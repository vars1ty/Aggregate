use aggregate::server::AggregateServer;

#[tokio::main]
async fn main() {
    let ag_server = AggregateServer::start(123456789, "0.0.0.0", 9458, "supersecretkey")
        .await
        .expect("Failed starting Aggregate Server!");
    println!("Server active at port 9458!");

    loop {
        let Ok(ag_client) = ag_server.accept_connection().await else {
            // Note: You should do proper error-handling.
            continue;
        };

        println!("Client accepted!");
        let Ok(packet_data) = ag_server.try_recv_packet(&ag_client).await else {
            // Note: You should do proper error-handling.
            continue;
        };

        // Ensure not a buffering packet.
        let Some(packet_data) = packet_data else {
            continue;
        };

        println!("Packet received, sz: {}", packet_data.len());
        // Exit
        break;
    }
}
