use crate::{
    errors::AggregateErrors,
    utils::packets::{NetPacket, NetPacketAction, NetPacketType},
};
use dashmap::DashMap;
use magic_crypt::MagicCrypt256;
use std::net::SocketAddr;
use tokio::{
    net::{
        TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::Mutex,
};
use tokio_socks::tcp::Socks5Stream;

/// Packet header buffers.
#[derive(Default)]
struct HeaderBuffers {
    // Dedicated packet signature buffer for the client to reuse.
    packet_signature_header_buffer: [u8; std::mem::size_of::<u128>()],

    // Dedicated packet length header buffer for the client to always reuse.
    packet_length_header_buffer: [u8; std::mem::size_of::<u32>()],

    // Dedicated magic header buffer for the client to always reuse.
    magic_header_buffer: [u8; std::mem::size_of::<u32>()],

    // Dedicated packet type header output buffer.
    packet_type_header_buffer: [u8; std::mem::size_of::<u8>()],
}

/// Aggregate client struct, responsible for connecting
/// and interacting with other remote Aggregate TCP servers.
pub struct AggregateClient {
    /// Packet chunks to be stitched together once ready.
    ///
    /// Data stored:
    /// - Key: Packet signature
    /// - Value: Buffered processed (encrypted & compressed)
    ///   packets merged into one
    packet_chunks: DashMap<u128, Vec<u8>>,

    /// Client stream reader.
    stream_reader: Mutex<OwnedReadHalf>,

    /// Client stream writer.
    stream_writer: Mutex<OwnedWriteHalf>,

    /// Encryption/decryption instance.
    crypt: MagicCrypt256,

    // Header buffers for this client.
    header_buffers: Mutex<HeaderBuffers>,

    /// The chosen magic header value, used for basic integrity
    /// checks.
    magic_header_value: u32,
}

impl AggregateClient {
    /// Connects to a remote Aggregate TCP server.
    pub async fn connect(
        magic_header_value: u32,
        addr: SocketAddr,
        mut encryption_key: String,
    ) -> Result<Self, std::io::Error> {
        let crypt = magic_crypt::new_magic_crypt!(&encryption_key, 256);

        // Attempt to zero-out the memory at `encryption_key`.
        unsafe {
            encryption_key.as_mut_vec().fill(0);
            drop(encryption_key);
        }

        let (stream_reader, stream_writer) = TcpStream::connect(addr).await?.into_split();

        Ok(Self {
            magic_header_value,
            packet_chunks: DashMap::with_capacity(10),
            stream_reader: Mutex::new(stream_reader),
            stream_writer: Mutex::new(stream_writer),
            crypt,
            header_buffers: Mutex::new(HeaderBuffers {
                packet_type_header_buffer: (NetPacketType::Regular as u8).to_be_bytes(),
                ..Default::default()
            }),
        })
    }

    /// Connects to a remote Aggregate TCP server using a Socks5 proxy.
    pub async fn connect_with_proxy(
        magic_header_value: u32,
        addr: SocketAddr,
        proxy: SocketAddr,
        mut encryption_key: String,
    ) -> Result<Self, tokio_socks::Error> {
        let crypt = magic_crypt::new_magic_crypt!(&encryption_key, 256);

        // Attempt to zero-out the memory at `encryption_key`.
        unsafe {
            encryption_key.as_mut_vec().fill(0);
            drop(encryption_key);
        }

        let (stream_reader, stream_writer) = Socks5Stream::connect(proxy, addr)
            .await?
            .into_inner()
            .into_split();

        Ok(Self {
            magic_header_value,
            packet_chunks: DashMap::with_capacity(10),
            stream_reader: Mutex::new(stream_reader),
            stream_writer: Mutex::new(stream_writer),
            crypt,
            header_buffers: Mutex::new(HeaderBuffers {
                packet_type_header_buffer: (NetPacketType::Regular as u8).to_be_bytes(),
                ..Default::default()
            }),
        })
    }

    /// Gets the Mutex reference to the underlying stream reader.
    ///
    /// ## Safety
    /// This is only safe if you read all data properly and make sure
    /// you aren't having an ongoing send-or-recv call, as then it can
    /// deadlock upon accessing the actual reader.
    pub const unsafe fn get_stream_reader(&self) -> &Mutex<OwnedReadHalf> {
        &self.stream_reader
    }

    /// Gets the Mutex reference to the underlying stream writer.
    ///
    /// ## Safety
    /// This is only safe if you write all data properly and make sure
    /// you aren't having an ongoing send-or-recv call, as then it can
    /// deadlock upon accessing the actual writer.
    pub const unsafe fn get_stream_writer(&self) -> &Mutex<OwnedWriteHalf> {
        &self.stream_writer
    }

    /// Sends a packet to the server.
    pub async fn send_to_server(&self, packet_data: Vec<u8>) -> Result<(), AggregateErrors> {
        NetPacket::new(packet_data, self.magic_header_value)
            .wrap_and_send(
                &self.crypt,
                &mut *self
                    .stream_writer
                    .try_lock()
                    .map_err(|_| AggregateErrors::StreamWriterLocked)?,
            )
            .await
    }

    /// Tries to receive a packet from the server, returning
    /// the unwrapped bytes of it for you to process, like
    /// deserializing and such.
    pub async fn recv_packet(&self) -> Result<Vec<u8>, AggregateErrors> {
        let stream_reader = &mut *self
            .stream_reader
            .try_lock()
            .map_err(|_| AggregateErrors::StreamReaderLocked)?;

        let header_buffers = &mut *self
            .header_buffers
            .try_lock()
            .map_err(|_| AggregateErrors::StreamWriterLocked)?;

        loop {
            match NetPacket::try_read_from_stream(
                self.magic_header_value,
                stream_reader,
                &mut header_buffers.magic_header_buffer,
                &mut header_buffers.packet_type_header_buffer,
                &mut header_buffers.packet_signature_header_buffer,
                &mut header_buffers.packet_length_header_buffer,
            )
            .await?
            {
                NetPacketAction::ReceivedPacket(
                    wrapped_packet_data,
                    packet_type,
                    packet_signature,
                ) => match packet_type {
                    NetPacketType::Regular => {
                        let unwrapped_packet_data =
                            NetPacket::try_unwrap_packet_data(&self.crypt, wrapped_packet_data)?;
                        return Ok(unwrapped_packet_data);
                    }
                    NetPacketType::UnfinishedChunk => {
                        if let Some(mut existing_merged_chunks) =
                            self.packet_chunks.get_mut(&packet_signature)
                        {
                            existing_merged_chunks.extend_from_slice(&wrapped_packet_data);
                            continue;
                        }

                        self.packet_chunks
                            .insert(packet_signature, wrapped_packet_data);
                    }
                    NetPacketType::FinalChunk => {
                        let stitched_packet_data =
                            self.try_stitch_packet(wrapped_packet_data, packet_signature)?;
                        return Ok(stitched_packet_data);
                    }
                },
                NetPacketAction::Disconnected => return Err(AggregateErrors::ClientDisconnected),
            }
        }
    }

    /// Tries to stitch together a buffered packet from the given client,
    /// looked up via `packet_signature`.
    ///
    /// The `wrapped_packet_data` parameter should **always** be the final chunk of the
    /// buffered packet, with type `NetPacketType::FinalChunk`.
    fn try_stitch_packet(
        &self,
        wrapped_packet_data: Vec<u8>,
        packet_signature: u128,
    ) -> Result<Vec<u8>, AggregateErrors> {
        if !self.packet_chunks.contains_key(&packet_signature) {
            return Err(AggregateErrors::PacketNotBuffered(packet_signature));
        }

        let Some((_packet_signature, mut merged_chunks)) =
            self.packet_chunks.remove(&packet_signature)
        else {
            return Err(AggregateErrors::PacketNotBuffered(packet_signature));
        };

        merged_chunks.extend_from_slice(&wrapped_packet_data);
        NetPacket::try_unwrap_packet_data(&self.crypt, merged_chunks)
    }

    /// Disconnets the current client from the server.
    pub async fn disconnect(&self) {
        self.packet_chunks.clear();
        drop(self.stream_reader.lock());
        drop(self.stream_writer.lock());
    }
}
