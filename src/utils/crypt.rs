use crate::errors::AggregateErrors;
use magic_crypt::{MagicCrypt256, MagicCryptTrait};

/// Encryption / decryption utilities.
pub struct CryptUtils;

impl CryptUtils {
    /// Encrypts `bytes` and returns the result.
    pub fn encrypt_bytes(crypt: &MagicCrypt256, bytes: &[u8]) -> Vec<u8> {
        crypt.encrypt_bytes_to_bytes(bytes)
    }

    /// Attempts to decrypt `bytes` and returns the result.
    pub fn decrypt_bytes(crypt: &MagicCrypt256, bytes: &[u8]) -> Result<Vec<u8>, AggregateErrors> {
        crypt
            .decrypt_bytes_to_bytes(bytes)
            .map_err(AggregateErrors::DecryptionFailure)
    }
}
