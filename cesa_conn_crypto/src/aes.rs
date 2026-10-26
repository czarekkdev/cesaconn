use core::fmt;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};

use rand::TryRng;
use rand::rngs::SysRng;
use tracing::{error, trace};
use zeroize::Zeroizing;

/// Represents all possible errors that can occur during cryptographic operations
#[derive(Debug)]
pub enum AESError {
    /// Failed to generate a secure random nonce from the OS
    NonceFailed,
    /// AES-256-GCM encryption failed
    EncryptionFailed,
    /// AES-256-GCM decryption failed — data may have been tampered with
    DecryptionFailed,
}

impl fmt::Display for AESError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AESError::NonceFailed => write!(f, "Failed to generate secure random nonce"),
            AESError::EncryptionFailed => write!(f, "Encryption failed"),
            AESError::DecryptionFailed => {
                write!(f, "Decryption failed — data may be corrupted or tampered")
            }
        }
    }
}

/// Encrypts data using AES-256-GCM with a randomly generated nonce.
/// Returns the ciphertext and the nonce — both are required for decryption.
pub fn encrypt(key: &[u8; 32], data: &[u8]) -> Result<(Vec<u8>, [u8; 12]), AESError> {
    trace!(data_len = data.len(), "AES-256-GCM encrypt called");

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));

    // Generate a cryptographically secure random nonce using OS entropy source
    // Nonce MUST be unique for every encryption with the same key
    let mut nonce_bytes = [0u8; 12];
    let mut rng = SysRng::default();

    rng.try_fill_bytes(&mut nonce_bytes).map_err(|e| {
        error!(error = %e, "OS failed to generate random nonce for AES-256-GCM");
        AESError::NonceFailed
    })?;

    let nonce = Nonce::from(nonce_bytes);

    // AES-256-GCM provides both encryption and integrity verification (AEAD)
    let ciphertext = cipher.encrypt(&nonce, data).map_err(|e| {
        error!(error = %e, data_len = data.len(), "AES-256-GCM encryption failed");
        AESError::EncryptionFailed
    })?;

    trace!(
        data_len = data.len(),
        ciphertext_len = ciphertext.len(),
        "AES-256-GCM encryption successful"
    );
    Ok((ciphertext, nonce_bytes))
}

/// Decrypts AES-256-GCM encrypted data.
/// If the data was tampered with, GCM authentication will fail automatically.
/// Built-in integrity verification — no separate HMAC needed.
pub fn decrypt(
    key: &[u8; 32],
    ciphertext: &[u8],
    nonce_bytes: &[u8; 12],
) -> Result<Zeroizing<Vec<u8>>, AESError> {
    trace!(
        ciphertext_len = ciphertext.len(),
        "AES-256-GCM decrypt called"
    );

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));

    // Dereference nonce_bytes to get owned [u8; 12] for Nonce::from
    let nonce = Nonce::from(*nonce_bytes);

    // Decryption will fail if data was modified — GCM tag verification
    let plaintext = cipher.decrypt(&nonce, ciphertext)
    .map_err(|e| {
        error!(error = %e, ciphertext_len = ciphertext.len(), "AES-256-GCM decryption failed — GCM tag mismatch or wrong key");
        AESError::DecryptionFailed
    })?;

    trace!(
        ciphertext_len = ciphertext.len(),
        plaintext_len = plaintext.len(),
        "AES-256-GCM decryption successful"
    );
    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {

    use super::*;

    /// Test that encryption produces different output than input
    #[test]
    fn test_encrypt_changes_data() {
        let key = [0u8; 32];
        let data = b"Hello CesaSec!";

        let (ciphertext, _nonce) = encrypt(&key, data).unwrap();

        assert_ne!(ciphertext, data);
    }

    /// Test that decrypt(encrypt(data)) == data
    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0u8; 32];
        let data = b"Hello CesaSec!";

        let (ciphertext, nonce) = encrypt(&key, data).unwrap();
        let plaintext = decrypt(&key, &ciphertext, &nonce).unwrap();

        assert_eq!(plaintext.as_slice(), &data[..]);
    }

    /// Test that wrong key fails decryption
    #[test]
    fn test_wrong_key_fails() {
        let key = [0u8; 32];
        let wrong_key = [1u8; 32];
        let data = b"Hello CesaSec!";

        let (ciphertext, nonce) = encrypt(&key, data).unwrap();
        let result = decrypt(&wrong_key, &ciphertext, &nonce);

        assert!(result.is_err());
    }

    /// Test that tampered ciphertext fails decryption — GCM integrity check
    #[test]
    fn test_tampered_data_fails() {
        let key = [0u8; 32];
        let data = b"Hello CesaSec!";

        let (mut ciphertext, nonce) = encrypt(&key, data).unwrap();

        // Tamper with the ciphertext
        ciphertext[0] ^= 0xFF;

        let result = decrypt(&key, &ciphertext, &nonce);

        assert!(result.is_err());
    }

    /// Test that wrong nonce fails decryption
    #[test]
    fn test_wrong_nonce_fails() {
        let key = [0u8; 32];
        let wrong_nonce = [1u8; 12];
        let data = b"Hello CesaSec!";

        let (ciphertext, _nonce) = encrypt(&key, data).unwrap();
        let result = decrypt(&key, &ciphertext, &wrong_nonce);

        assert!(result.is_err());
    }

    /// Test that two encryptions of the same data produce different ciphertexts
    /// This verifies that nonce is random each time
    #[test]
    fn test_nonce_is_random() {
        let key = [0u8; 32];
        let data = b"Hello CesaSec!";

        let (ciphertext1, nonce1) = encrypt(&key, data).unwrap();
        let (ciphertext2, nonce2) = encrypt(&key, data).unwrap();

        // Same data, different nonce = different ciphertext
        assert_ne!(nonce1, nonce2);
        assert_ne!(ciphertext1, ciphertext2);
    }

    /// Test encryption of empty data
    #[test]
    fn test_empty_data() {
        let key = [0u8; 32];
        let data = b"";

        let (ciphertext, nonce) = encrypt(&key, data).unwrap();
        let plaintext = decrypt(&key, &ciphertext, &nonce).unwrap();

        assert_eq!(plaintext.as_slice(), &data[..]);
    }

    /// Test encryption of large data
    #[test]
    fn test_large_data() {
        let key = [0u8; 32];
        let data = vec![0u8; 1024 * 1024]; // 1MB

        let (ciphertext, nonce) = encrypt(&key, &data).unwrap();
        let plaintext = decrypt(&key, &ciphertext, &nonce).unwrap();

        assert_eq!(plaintext.as_slice(), &data[..]);
    }
}
