use crate::{
    errors::AggregateErrors,
    utils::packets::{NetPacket, NetPacketAction, NetPacketType},
};
use dashmap::DashMap;
use magic_crypt::MagicCrypt256;
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::{
    io::AsyncWriteExt,
    net::{
        TcpListener,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::Mutex,
};

/// Holds information about an Aggregate client, stored on the server.
pub struct AGClientData {
    /// This clients stream writer part.
    stream_writer: Mutex<OwnedWriteHalf>,

    /// This clients stream reader part.
    stream_reader: Mutex<OwnedReadHalf>,

    /// Packet chunks to be stitched together once ready.
    ///
    /// Data stored:
    /// - Key: Packet signature
    /// - Value: Buffered processed (encrypted + compressed)
    ///   packets merged into one
    packet_chunks: DashMap<u128, Vec<u8>>,

    /// If `true` then the client loop is allowed to stay active.
    ///
    /// If `false` then it must exit on next call.
    stay_connected: AtomicBool,

    /// This clients `SocketAddr`.
    socket_addr: SocketAddr,
}

impl AGClientData {
    /// Inserts the into the authorized clients map on the server.
    pub fn authorize_client(self: &Arc<AGClientData>, server: &AggregateServer) {
        server
            .authorized_clients
            .insert(self.get_socket_addr(), Arc::clone(self));
    }

    /// Checks if the client has been authorized or not.
    pub fn is_authorized(&self, server: &AggregateServer) -> bool {
        server
            .get_authorized_clients()
            .contains_key(&self.get_socket_addr())
    }

    /// Gets the `SocketAddr` for the client.
    pub const fn get_socket_addr(&self) -> SocketAddr {
        self.socket_addr
    }

    /// Attempts to disconnect the client.
    pub async fn disconnect(&self, server: &AggregateServer) {
        server.disconnect_client(self).await;
    }
}

pub struct AggregateServer {
    /// Authorized and connected network clients.
    ///
    /// Manual authorization is the default, if a client
    /// isn't authorized then sender functions will refuse
    /// to function.
    ///
    /// Therefore the client should **always** send a packet
    /// upon connecting, for the server to then authorize it.
    authorized_clients: DashMap<SocketAddr, Arc<AGClientData>>,

    /// Encryption/decryption instance.
    crypt: MagicCrypt256,

    /// Server TCP Listener.
    listener: TcpListener,

    /// The chosen magic header value, used for basic integrity
    /// checks.
    magic_header_value: u32,
}

impl AggregateServer {
    /// Tries to start the server at `(ip):(port)`.
    ///
    /// To start accepting connections and packets, call
    /// `AggregateServer::start_listen_loop`.
    pub async fn start(
        magic_header_value: u32,
        ip: &str,
        port: u16,
        encryption_key: &str,
    ) -> std::io::Result<&'static Self> {
        let listener = TcpListener::bind(format!("{ip}:{port}")).await?;
        let instance: &'static Self = Box::leak(Box::new(Self {
            magic_header_value,
            authorized_clients: DashMap::with_capacity(10),
            crypt: magic_crypt::new_magic_crypt!(encryption_key, 256),
            listener,
        }));

        Ok(instance)
    }

    /// Tries to accept an incoming connection, stalling the calling task until one
    /// has been accepted, or an error is hit.
    pub async fn accept_connection(&self) -> Result<AGClientData, AggregateErrors> {
        let (stream, socket_addr) =
            self.listener.accept().await.map_err(|error| {
                AggregateErrors::Io("Failed accepting client connection", error)
            })?;
        let (stream_reader, stream_writer) = stream.into_split();
        let ag_client = AGClientData {
            stream_writer: Mutex::new(stream_writer),
            stream_reader: Mutex::new(stream_reader),
            packet_chunks: DashMap::new(),
            stay_connected: AtomicBool::new(true),
            socket_addr,
        };
        Ok(ag_client)
    }

    /// Tries to receive a packet from the given client, returning `Ok(Some(Vec<u8>))` if
    /// the packet is complete and ready.
    ///
    /// Returns `Ok(None)` if the packet is being buffered.
    ///
    /// Returns `Err(AggregateErrors)` if something went wrong.
    pub async fn try_recv_packet(
        &self,
        ag_client: &AGClientData,
    ) -> Result<Option<Vec<u8>>, AggregateErrors> {
        // Dedicated magic header buffer for the client to always reuse.
        let mut magic_header_buffer = [0u8; std::mem::size_of::<u32>()];

        // Dedicated packet type header output value.
        let mut packet_type_header: [u8; std::mem::size_of::<u8>()] =
            (NetPacketType::Regular as u8).to_be_bytes();

        // Dedicated packet signature buffer for the client to reuse.
        let mut packet_signature_header_buffer = [0u8; std::mem::size_of::<u128>()];

        // Dedicated size header buffer for the client to always reuse.
        let mut size_header_buffer = [0u8; std::mem::size_of::<u32>()];

        if !ag_client.stay_connected.load(Ordering::Relaxed) {
            return Err(AggregateErrors::ClientDisconnected);
        }

        let net_packet_action = NetPacket::try_read_from_stream(
            self.magic_header_value,
            &mut *ag_client
                .stream_reader
                .try_lock()
                .map_err(|_| AggregateErrors::StreamReaderLocked)?,
            &mut magic_header_buffer,
            &mut packet_type_header,
            &mut packet_signature_header_buffer,
            &mut size_header_buffer,
        )
        .await?;

        match net_packet_action {
            NetPacketAction::ReceivedPacket(wrapped_packet_data, packet_type, packet_signature) => {
                match packet_type {
                    NetPacketType::Regular => Ok(Some(NetPacket::try_unwrap_packet_data(
                        &self.crypt,
                        wrapped_packet_data,
                    )?)),
                    NetPacketType::UnfinishedChunk => {
                        if let Some(mut existing_merged_chunks) =
                            ag_client.packet_chunks.get_mut(&packet_signature)
                        {
                            existing_merged_chunks.extend_from_slice(&wrapped_packet_data);
                            return Ok(None);
                        }

                        ag_client
                            .packet_chunks
                            .insert(packet_signature, wrapped_packet_data);
                        Ok(None)
                    }
                    NetPacketType::FinalChunk => Ok(Some(self.try_stitch_packet(
                        ag_client,
                        wrapped_packet_data,
                        packet_signature,
                    )?)),
                }
            }
            NetPacketAction::Disconnected => Err(AggregateErrors::ClientDisconnected),
        }
    }

    /// Tries to stitch together a buffered packet from the given client,
    /// looked up via `packet_signature`.
    ///
    /// The `wrapped_packet_data` parameter should **always** be the final chunk of the
    /// buffered packet, with type `NetPacketType::FinalChunk`.
    fn try_stitch_packet(
        &self,
        ag_client: &AGClientData,
        wrapped_packet_data: Vec<u8>,
        packet_signature: u128,
    ) -> Result<Vec<u8>, AggregateErrors> {
        if !ag_client.packet_chunks.contains_key(&packet_signature) {
            return Err(AggregateErrors::PacketNotBuffered(packet_signature));
        }

        let Some((_packet_signature, mut merged_chunks)) =
            ag_client.packet_chunks.remove(&packet_signature)
        else {
            return Err(AggregateErrors::PacketNotBuffered(packet_signature));
        };

        merged_chunks.extend_from_slice(&wrapped_packet_data);
        NetPacket::try_unwrap_packet_data(&self.crypt, merged_chunks)
    }

    /// Gets a reference to the authorized clients map.
    pub const fn get_authorized_clients(&self) -> &DashMap<SocketAddr, Arc<AGClientData>> {
        &self.authorized_clients
    }

    /// Sends a packet to the specified client.
    ///
    /// If `allow_unauthorized` is `true`, then this will send packets to
    /// unauthorized clients, as well as authorized ones.
    pub async fn send_packet_to(
        &self,
        ag_client: Arc<AGClientData>,
        packet_data: Vec<u8>,
        allow_unauthorized: bool,
    ) -> Result<(), AggregateErrors> {
        if !ag_client.is_authorized(self) && !allow_unauthorized {
            return Err(AggregateErrors::ClientUnauthorized);
        }

        NetPacket::new(packet_data, self.magic_header_value)
            .wrap_and_send(&self.crypt, &mut *ag_client.stream_writer.lock().await)
            .await
    }

    /// Sends a packet to all connected clients.
    ///
    /// If `allow_unauthorized` is `true`, then this will send packets to
    /// unauthorized clients, as well as authorized ones.
    ///
    /// **Note**: Unlike `AggregateServer::send_packet_to`, this doesn't return
    /// any errors.
    ///
    /// Any errors encountered whilst sending will be ignored.
    pub async fn send_packet_to_all(&'static self, packet_data: Vec<u8>, allow_unauthorized: bool) {
        let packet = NetPacket::new(packet_data, self.magic_header_value);

        for kv in &self.authorized_clients {
            let (_socket_addr, ag_client) = kv.pair();
            if !ag_client.is_authorized(self) && !allow_unauthorized {
                continue;
            }

            let _ = packet
                .wrap_and_send(&self.crypt, &mut *ag_client.stream_writer.lock().await)
                .await;
        }
    }

    /// Attempts to disconnect the given client.
    pub async fn disconnect_client(&self, ag_client: &AGClientData) {
        ag_client.stay_connected.store(false, Ordering::Relaxed);
        let _ = ag_client.stream_writer.lock().await.shutdown().await;
        self.authorized_clients.remove(&ag_client.socket_addr);
    }
}
