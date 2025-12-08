use std::fmt::Display;

#[derive(Debug)]
pub enum AggregateErrors {
    PacketNotBuffered(u128),
    PacketCorruption(&'static str),
    ParseNetPacketType(u8),

    SplitInputIsEmpty,

    DecryptionFailure(magic_crypt::MagicCryptError),

    ClientDisconnected,
    ClientUnauthorized,

    Io(&'static str, std::io::Error),
    Json(&'static str, simd_json::Error),

    /// Only use for cases that should absolutely never
    /// happen and deserve no dedicated enum for it, as
    /// the fail-rate is so incredibly low.
    UnknownStr(&'static str),

    /// An error in just a `String`-repr, only intended
    /// for special edge-cases.
    String(String),
}

impl std::error::Error for AggregateErrors {}

impl Display for AggregateErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PacketNotBuffered(signature) => {
                write!(f, "Packet with signature {signature} hasn't been buffered!")
            }
            Self::PacketCorruption(msg) => {
                write!(
                    f,
                    "Encountered a corrupt (or tampered) packet, error: {msg}"
                )
            }
            Self::ParseNetPacketType(value) => {
                write!(f, "Failed parsing {value} as NetPacketType!")
            }
            Self::SplitInputIsEmpty => write!(f, "Split input is empty!"),
            Self::DecryptionFailure(error) => {
                write!(f, "Failed decrypting content, error: {error}")
            }
            Self::ClientDisconnected => {
                write!(f, "Client has been disconnected from the server!")
            }
            Self::ClientUnauthorized => write!(f, "Client hasn't been authorized!"),
            Self::Io(msg, error) => write!(f, "{msg}, error: {error}"),
            Self::Json(msg, error) => write!(f, "{msg}, error: {error}"),
            Self::UnknownStr(msg) => write!(f, "{msg}"),
            Self::String(msg) => write!(f, "{msg}"),
        }
    }
}
