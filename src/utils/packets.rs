use crate::{
    errors::AggregateErrors,
    utils::{crypt::CryptUtils, data::DataUtils, time::TimeUtils},
};
use magic_crypt::MagicCrypt256;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::tcp::{OwnedReadHalf, OwnedWriteHalf},
};

pub struct NetPacket {
    /// Packet data for this `NetPacket` instance.
    packet_data: Vec<u8>,

    /// Magic header value.
    magic_header: u32,
}

/// Packet types to identify and adjust receiver logic, based on what type
/// of packet it is.
///
/// For example, large packets (>40KB) will always be sent in chunks.
#[repr(u8)]
#[derive(serde::Serialize, serde::Deserialize, Clone, Copy, PartialEq, Eq)]
pub enum NetPacketType {
    /// Unfinished chunk; The client should keep on reading until `FinalChunk` is hit.
    UnfinishedChunk = 0,

    /// Final chunk; Merge the chunks together and proceed.
    FinalChunk = 1,

    /// Regular packet; All-in-one, no chunks.
    Regular = 2,
}

impl NetPacketType {
    /// Tries to get the `NetPacketType` from an `u8` value.
    pub fn try_from(value: u8) -> Result<Self, AggregateErrors> {
        match value {
            0 => Ok(Self::UnfinishedChunk),
            1 => Ok(Self::FinalChunk),
            2 => Ok(Self::Regular),
            _ => Err(AggregateErrors::ParseNetPacketType(value)),
        }
    }
}

/// NetPacket action received from reading information about a packet.
pub enum NetPacketAction {
    /// We received a NetPacket, check the type to see if it's
    /// ready to be unwrapped ASAP (`NetPacketType::Regular`),
    /// or if you need to continue reading as it's buffered.
    ///
    /// Parameters:
    /// 1. Wrapped packet data (w/encryption & compression);
    ///    can be split if not `NetPacketType::Regular`
    /// 2. Packet type
    /// 3. Packet signature
    ///    - If the packet is part of a collection of chunks,
    ///    - then this signature will inherit the signature of
    ///    - the packet that started the chunk, to allow you to
    ///    - easier stitch packets together.
    ReceivedPacket(Vec<u8>, NetPacketType, u128),

    /// The connection was closed.
    Disconnected,
}

impl NetPacket {
    /// Creates a new `NetPacket` instance out of the given packet data.
    pub fn new(packet_data: Vec<u8>, magic_header_value: u32) -> Self {
        Self {
            packet_data,
            magic_header: magic_header_value,
        }
    }

    /// Tries to wrap the current `NetPacket` and send it.
    pub async fn wrap_and_send(
        &self,
        crypt: &MagicCrypt256,
        stream_writer: &mut OwnedWriteHalf,
    ) -> Result<(), AggregateErrors> {
        // 40KB in binary.
        const MAX_CHUNK_SIZE: usize = 1024 * 40;

        // Compress -> Encrypt
        let wrapped_packet_bytes =
            CryptUtils::encrypt_bytes(crypt, &DataUtils::compress_bytes(&self.packet_data)?);

        let mut chunks = DataUtils::split_data_to_chunks(wrapped_packet_bytes, MAX_CHUNK_SIZE)?;
        let chunks_len = chunks.len();
        let send_as_chunks = chunks_len > 1;

        // Just use the unix timestamp as the signature, it'll always
        // be a new value.
        let packet_signature = TimeUtils::get_unix_millis_timestamp();

        for (i, chunk) in chunks.iter_mut().enumerate() {
            let packet_type = if !send_as_chunks {
                NetPacketType::Regular
            } else if i == chunks_len - 1 {
                NetPacketType::FinalChunk
            } else {
                NetPacketType::UnfinishedChunk
            };

            // Write a magic header with a dummy value to check for,
            // ensuring we're actually reading valid data later.
            stream_writer
                .write_u32(self.magic_header)
                .await
                .map_err(|error| AggregateErrors::Io("Failed writing magic header", error))?;

            // Write extra information about the packet, specifically how
            // to process it. Regular is just one-shot and do everything
            // immediately.
            //
            // UnfinishedChunk packets should be cached via their ID and
            // only processed once FinalChunk is hit.
            stream_writer
                .write_u8(packet_type as u8)
                .await
                .map_err(|error| AggregateErrors::Io("Failed writing packet type header", error))?;

            // Write the packet signature, this will remain the same if
            // the packet is sent as chunks, as chunks inherit the first
            // packets signature and it's by design to allow the receiver
            // to easily stitch content together based on it.
            stream_writer
                .write_u128(packet_signature)
                .await
                .map_err(|error| {
                    AggregateErrors::Io("Failed writing packet signature header", error)
                })?;

            // Write length header and then content as bytes.
            stream_writer
                .write_u32(chunk.len() as u32)
                .await
                .map_err(|error| {
                    AggregateErrors::Io("Failed writing packet length header", error)
                })?;
            stream_writer
                .write_all(chunk)
                .await
                .map_err(|error| AggregateErrors::Io("Failed writing packet data", error))?;

            // Try and force an immediate deallocation of the chunk.
            chunk.clear();
            chunk.shrink_to_fit();
            drop(std::mem::take(chunk));

            let _ = stream_writer.flush().await;
        }

        Ok(())
    }

    /// Tries to read incoming client packets from the provided `TcpStream`.
    pub async fn try_read_from_stream(
        magic_header_value: u32,
        stream_reader: &mut OwnedReadHalf,
        magic_header_buffer: &mut [u8; std::mem::size_of::<u32>()],
        packet_type_header_buffer: &mut [u8; std::mem::size_of::<u8>()],
        packet_signature_header_buffer: &mut [u8; std::mem::size_of::<u128>()],
        size_header_buffer: &mut [u8; std::mem::size_of::<u32>()],
    ) -> Result<NetPacketAction, AggregateErrors> {
        // Read the headers: Magic, packet type and packet length.
        if let Err(error) = Self::try_read_packet_headers(
            stream_reader,
            magic_header_buffer,
            packet_type_header_buffer,
            packet_signature_header_buffer,
            size_header_buffer,
        )
        .await
        {
            if let AggregateErrors::Io(_, ref error) = error
                && error.kind() == std::io::ErrorKind::UnexpectedEof
            {
                return Ok(NetPacketAction::Disconnected);
            }

            return Err(error);
        }

        let (packet_length, packet_type, packet_signature) = Self::read_and_validate_stream_data(
            magic_header_value,
            magic_header_buffer,
            packet_type_header_buffer,
            packet_signature_header_buffer,
            size_header_buffer,
        )
        .await?;

        // Read the wrapped content, this needs to be both decrypted and decompressed
        // before usage.
        let mut wrapped_packet_data = vec![0u8; packet_length as usize];
        stream_reader
            .read_exact(&mut wrapped_packet_data)
            .await
            .map_err(|error| AggregateErrors::Io("Failed reading packet data", error))?;

        if wrapped_packet_data.iter().all(|byte| *byte == 0) {
            return Err(AggregateErrors::PacketCorruption(
                "Packet is all null bytes!",
            ));
        }

        Ok(NetPacketAction::ReceivedPacket(
            wrapped_packet_data,
            packet_type,
            packet_signature,
        ))
    }

    /// Tries to unwrap the given packet data. The steps are as follow:
    ///
    /// 1. Decrypt the bytes
    /// 2. Decompress decrypted data
    /// 3. Return the unprocessed data
    pub fn try_unwrap_packet_data(
        crypt: &MagicCrypt256,
        processed_packet_data: Vec<u8>,
    ) -> Result<Vec<u8>, AggregateErrors> {
        let decrypted = CryptUtils::decrypt_bytes(crypt, &processed_packet_data)?;

        let mut output = Vec::new();
        DataUtils::decompress_bytes(decrypted, &mut output)?;
        Ok(output)
    }

    /// Tries to read the packet headers and output them into
    /// their respective buffers/parameters.
    async fn try_read_packet_headers(
        stream_reader: &mut OwnedReadHalf,
        magic_header_buffer: &mut [u8; std::mem::size_of::<u32>()],
        packet_type_header_buffer: &mut [u8; std::mem::size_of::<u8>()],
        packet_signature_header_buffer: &mut [u8; std::mem::size_of::<u128>()],
        size_header_buffer: &mut [u8; std::mem::size_of::<u32>()],
    ) -> Result<(), AggregateErrors> {
        stream_reader
            .read_exact(magic_header_buffer)
            .await
            .map_err(|error| {
                AggregateErrors::Io("Failed reading magic header into buffer", error)
            })?;

        stream_reader
            .read_exact(packet_type_header_buffer)
            .await
            .map_err(|error| {
                AggregateErrors::Io("Failed reading packet type header into buffer", error)
            })?;

        stream_reader
            .read_exact(packet_signature_header_buffer)
            .await
            .map_err(|error| {
                AggregateErrors::Io("Failed reading packet signature header into buffer", error)
            })?;

        stream_reader
            .read_exact(size_header_buffer)
            .await
            .map_err(|error| {
                AggregateErrors::Io("Failed reading packet length header into buffer", error)
            })?;
        Ok(())
    }

    /// Read and validate the received stream data, if successful then
    /// the **packet size**, **packet type** and **packet signature**
    /// is returned.
    ///
    /// Otherwise an error is returned.
    async fn read_and_validate_stream_data(
        magic_header_value: u32,
        magic_header_buffer: &mut [u8; std::mem::size_of::<u32>()],
        packet_type_header_buffer: &mut [u8; std::mem::size_of::<u8>()],
        packet_signature_header_buffer: &mut [u8; std::mem::size_of::<u128>()],
        size_header_buffer: &mut [u8; std::mem::size_of::<u32>()],
    ) -> Result<(u32, NetPacketType, u128), AggregateErrors> {
        // 10MB limit.
        const MAX_PACKET_SIZE: u32 = (1024 * 1024) * 10;

        if (&magic_header_buffer[..])
            .read_u32()
            .await
            .map_err(|error| AggregateErrors::Io("Failed reading magic header as u32", error))?
            != magic_header_value
        {
            return Err(AggregateErrors::PacketCorruption(
                "Incorrect magic header value!",
            ));
        }

        let packet_type =
            NetPacketType::try_from((&packet_type_header_buffer[..]).read_u8().await.map_err(
                |error| AggregateErrors::Io("Failed reading packet type header as u8", error),
            )?)?;

        let packet_signature = (&packet_signature_header_buffer[..])
            .read_u128()
            .await
            .map_err(|error| {
                AggregateErrors::Io("Failed reading packet signature header as u32", error)
            })?;

        if packet_signature == 0 {
            return Err(AggregateErrors::PacketCorruption(
                "Packet had an invalid signature of 0!",
            ));
        }

        let packet_length = (&size_header_buffer[..])
            .read_u32()
            .await
            .map_err(|error| {
                AggregateErrors::Io("Failed reading packet length header as u32", error)
            })?;

        if packet_length == 0 {
            return Err(AggregateErrors::PacketCorruption(
                "Received packet length is 0!",
            ));
        }

        if packet_length > MAX_PACKET_SIZE {
            return Err(AggregateErrors::PacketCorruption(
                "Received packet length indicate an alarmingly large packet; or its corrupt!",
            ));
        }

        Ok((packet_length, packet_type, packet_signature))
    }
}
