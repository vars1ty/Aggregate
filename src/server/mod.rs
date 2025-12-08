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
    pub fn authorize_client(self: &Arc<AGClientData>, server: &'static AggregateServer) {
        server
            .authorized_clients
            .insert(self.get_socket_addr(), Arc::clone(self));
    }

    /// Checks if the client has been authorized or not.
    pub fn is_authorized(&self, server: &'static AggregateServer) -> bool {
        server
            .get_authorized_clients()
            .contains_key(&self.get_socket_addr())
    }

    /// Gets the `SocketAddr` for the client.
    pub const fn get_socket_addr(&self) -> SocketAddr {
        self.socket_addr
    }

    /// Attempts to disconnect the client.
    pub async fn disconnect(&self, server: &'static AggregateServer) {
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

    /// Starts the listening loop for the specified `TcpListener`, responsible for
    /// accepting incoming connections.
    ///
    /// **Note**: Blocks the calling task as it's an infinite loop.
    pub async fn start_listen_loop<
        P: Fn(&'static Self, Vec<u8>, Arc<AGClientData>) -> PFut + Send + Sync + Copy + 'static,
        PFut: Future<Output = ()> + Send,
        EFut: Future<Output = ()> + Send,
        E: Fn(&'static Self, AggregateErrors, Option<Arc<AGClientData>>) -> EFut
            + Send
            + Sync
            + Copy
            + 'static,
    >(
        &'static self,
        on_packet_received: P,
        on_error: E,
    ) {
        loop {
            let listener_accept_result = self.listener.accept().await;
            if let Err(error) = listener_accept_result {
                on_error(
                    self,
                    AggregateErrors::Io("Failed accepting incoming connection", error),
                    None,
                )
                .await;
                continue;
            }

            // Safety(unwrap): Tested for error, it's not possible to reach this code
            // if it wasn't Ok(..).
            let (stream, socket_addr) = listener_accept_result.unwrap();
            let _ = stream.set_nodelay(true);

            let (stream_reader, stream_writer) = stream.into_split();

            tokio::task::spawn(async move {
                self.start_client_loop(
                    on_packet_received,
                    on_error,
                    stream_reader,
                    stream_writer,
                    socket_addr,
                )
                .await;
            });
        }
    }

    /// Starts reading packets from the client.
    async fn start_client_loop<
        P: Fn(&'static Self, Vec<u8>, Arc<AGClientData>) -> PFut + Send + Sync + Clone + 'static,
        PFut: Future<Output = ()> + Send,
        EFut: Future<Output = ()> + Send,
        E: Fn(&'static Self, AggregateErrors, Option<Arc<AGClientData>>) -> EFut
            + Send
            + Sync
            + Clone
            + 'static,
    >(
        &'static self,
        on_packet_received: P,
        on_error: E,
        mut stream_reader: OwnedReadHalf,
        stream_writer: OwnedWriteHalf,
        socket_addr: SocketAddr,
    ) {
        let ag_client = Arc::new(AGClientData {
            stream_writer: Mutex::new(stream_writer),
            packet_chunks: DashMap::new(),
            stay_connected: AtomicBool::new(true),
            socket_addr,
        });

        // Dedicated magic header buffer for the client to always reuse.
        let mut magic_header_buffer = [0u8; std::mem::size_of::<u32>()];

        // Dedicated packet type header output value.
        let mut packet_type_header: [u8; std::mem::size_of::<u8>()] =
            (NetPacketType::Regular as u8).to_be_bytes();

        // Dedicated packet signature buffer for the client to reuse.
        let mut packet_signature_header_buffer = [0u8; std::mem::size_of::<u128>()];

        // Dedicated size header buffer for the client to always reuse.
        let mut size_header_buffer = [0u8; std::mem::size_of::<u32>()];

        loop {
            if !ag_client.stay_connected.load(Ordering::Relaxed) {
                break;
            }

            match NetPacket::try_read_from_stream(
                self.magic_header_value,
                &mut stream_reader,
                &mut magic_header_buffer,
                &mut packet_type_header,
                &mut packet_signature_header_buffer,
                &mut size_header_buffer,
            )
            .await
            {
                Ok(action) => match action {
                    NetPacketAction::ReceivedPacket(
                        wrapped_packet_data,
                        packet_type,
                        packet_signature,
                    ) => match packet_type {
                        NetPacketType::Regular => {
                            match NetPacket::try_unwrap_packet_data(
                                &self.crypt,
                                wrapped_packet_data,
                            ) {
                                Ok(packet_data) => {
                                    on_packet_received(self, packet_data, Arc::clone(&ag_client))
                                        .await;
                                }
                                Err(error) => {
                                    on_error(self, error, Some(Arc::clone(&ag_client))).await;
                                }
                            }
                        }
                        NetPacketType::UnfinishedChunk => {
                            if let Some(mut existing_merged_chunks) =
                                ag_client.packet_chunks.get_mut(&packet_signature)
                            {
                                existing_merged_chunks.extend_from_slice(&wrapped_packet_data);
                                continue;
                            }

                            ag_client
                                .packet_chunks
                                .insert(packet_signature, wrapped_packet_data);
                        }
                        NetPacketType::FinalChunk => {
                            match self
                                .try_stitch_packet(
                                    Arc::clone(&ag_client),
                                    wrapped_packet_data,
                                    packet_signature,
                                )
                                .await
                            {
                                Ok(packet_data) => {
                                    on_packet_received(self, packet_data, Arc::clone(&ag_client))
                                        .await;
                                }
                                Err(error) => {
                                    on_error(self, error, Some(Arc::clone(&ag_client))).await;
                                }
                            }
                        }
                    },
                    NetPacketAction::Disconnected => break,
                },
                Err(error) => {
                    on_error(self, error, Some(Arc::clone(&ag_client))).await;
                    break;
                }
            }
        }

        on_error(
            self,
            AggregateErrors::ClientDisconnected,
            Some(Arc::clone(&ag_client)),
        )
        .await;

        ag_client.disconnect(self).await;
    }

    /// Tries to stitch together a buffered packet from the given client,
    /// looked up via `packet_signature`.
    ///
    /// The `wrapped_packet_data` parameter should **always** be the final chunk of the
    /// buffered packet, with type `NetPacketType::FinalChunk`.
    async fn try_stitch_packet(
        &self,
        ag_client: Arc<AGClientData>,
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
    pub const fn get_authorized_clients(
        &'static self,
    ) -> &'static DashMap<SocketAddr, Arc<AGClientData>> {
        &self.authorized_clients
    }

    /// Sends a packet to the specified client.
    ///
    /// If `allow_unauthorized` is `true`, then this will send packets to
    /// unauthorized clients, as well as authorized ones.
    pub async fn send_packet_to(
        &'static self,
        ag_client: Arc<AGClientData>,
        packet_data: Vec<u8>,
        allow_unauthorized: bool,
    ) -> Result<(), AggregateErrors> {
        if !ag_client.is_authorized(self) && !allow_unauthorized {
            return Err(AggregateErrors::ClientUnauthorized);
        }

        NetPacket::new(packet_data)
            .serialize_and_send(
                self.magic_header_value,
                &self.crypt,
                &mut *ag_client.stream_writer.lock().await,
            )
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
        let packet = NetPacket::new(packet_data);

        for kv in &self.authorized_clients {
            let (_socket_addr, ag_client) = kv.pair();
            if !ag_client.is_authorized(self) && !allow_unauthorized {
                continue;
            }

            let _ = packet
                .serialize_and_send(
                    self.magic_header_value,
                    &self.crypt,
                    &mut *ag_client.stream_writer.lock().await,
                )
                .await;
        }
    }

    /// Attempts to disconnect the given client.
    pub async fn disconnect_client(&'static self, ag_client: &AGClientData) {
        ag_client.stay_connected.store(false, Ordering::Relaxed);
        let _ = ag_client.stream_writer.lock().await.shutdown().await;
        self.authorized_clients.remove(&ag_client.socket_addr);
    }
}
