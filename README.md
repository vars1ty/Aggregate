# Aggregate
> [!NOTE]  
> Aggregate is very much a hobby-project and has rough edges, **use it at your own risk!**
##
*A Secure TCP Client & Server Framework*
## Features
- Asynchronous through `tokio`
- Encryption and decryption done via `magic-crypt` seamlessly for all data
- Zlib compression and decompression done via `flate2` seamlessly for all data
- Automatic buffering for all packets that exceed `40kb` in total size
- SOCKS5 Proxy Client connection support
- Automatic packet length header to treat TCP as a packet-based protocol (like UDP)
- Documented and easy-to-read codebase
## Packet processing
Packets are processed in several steps:

Headers:
1. `u32`: Magic - For basic integrity checks
2. `u8`: Packet Type - For determining the packet type, used with automatic buffering
3. `u128`: Packet Signature - For coupling together buffering packets, this is the unix timestamp and will be the same for all chunks in the same packet
3. `u32`: Packet Length - Ensuring the receiver reads the correct length; This is the length of the processed packet data

Data:
1. Compress packet data
2. Encrypt compressed data

After all steps have been processed in order, the packet is sent.
## Security
Aggregate offers some security through:
1. A magic header value, if it doesn't match on both the client and server, then the packet won't be processed
2. Encryption and compression, a custom encryption key is required
3. **Server**: Authorization checks

> [!IMPORTANT]  
> Aggregate's server **by default** doesn't trust any **AGClientData** instance when it comes to **sending** packets.

The client may send packets, but unless you call `authorize_client(aggregate_server_instance)` on the `AGClientData` instance, then the server won't send any to them.

The only exception to this rule is if you call a `send_packet*` function and set the `allow_unauthorized` parameter to `true`, which is not recommended for constant usage.

Instead you are supposed to send an authorization packet yourself and process data properly; not blindly trust everyone.
