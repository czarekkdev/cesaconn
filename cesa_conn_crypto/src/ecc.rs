use core::fmt;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::{TryRng, rngs::SysRng};
use tracing::{error, trace};
use zeroize::Zeroizing;

/// Errors that can occur during ECC operations
#[derive(Debug)]
pub enum ECCErrors {
    /// OS failed to provide cryptographically secure random bytes
    FailedToGenerateSigningKey,
    /// Verifying key bytes are invalid or signature verification failed
    FailedToVerify,
}

impl fmt::Display for ECCErrors {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ECCErrors::FailedToGenerateSigningKey => write!(f, "Failed to generate signing key"),
            ECCErrors::FailedToVerify => {
                write!(f, "Failed to verify signature — key may be invalid")
            }
        }
    }
}

/// Generates a cryptographically secure Ed25519 signing key using OS entropy.
/// The key is returned in `Zeroizing`, so it is wiped from memory on drop.
pub fn generate_signing_key() -> Result<Zeroizing<[u8; 32]>, ECCErrors> {
    trace!("generating Ed25519 signing key from OS entropy");
    let mut signing_key_bytes = Zeroizing::new([0u8; 32]);
    let mut rng = SysRng::default();

    rng.try_fill_bytes(signing_key_bytes.as_mut_slice()).map_err(|e| {
        error!(error = %e, "OS failed to provide random bytes for Ed25519 signing key generation");
        ECCErrors::FailedToGenerateSigningKey
    })?;

    // SigningKey zeroizes itself on drop; the returned copy is wrapped in Zeroizing.
    let signing_key = SigningKey::from_bytes(&signing_key_bytes);
    trace!("Ed25519 signing key generated successfully");
    Ok(Zeroizing::new(signing_key.to_bytes()))
}

/// Derives the Ed25519 verifying (public) key from a signing key
pub fn calculate_verifying_key(signing_key: &[u8; 32]) -> [u8; 32] {
    let signing_key = SigningKey::from_bytes(signing_key);
    let veryfing_key = signing_key.verifying_key();

    veryfing_key.to_bytes()
}

/// Signs data using Ed25519 — returns a 64-byte signature
/// Signature should be verified by the receiver before trusting the data
pub fn sign(signing_key: &[u8; 32], data: &[u8]) -> [u8; 64] {
    trace!(data_len = data.len(), "signing data with Ed25519");
    let signing_key = SigningKey::from_bytes(signing_key);
    let signed_data = signing_key.sign(data);
    trace!(data_len = data.len(), "Ed25519 signing complete");
    signed_data.to_bytes()
}

/// Verifies an Ed25519 signature against data and a verifying key
/// Returns Ok(true) if valid, Ok(false) if invalid, Err if key is malformed
pub fn verify(
    verifying_key: &[u8; 32],
    data: &[u8],
    signature: &[u8; 64],
) -> Result<bool, ECCErrors> {
    trace!(data_len = data.len(), "verifying Ed25519 signature");
    let verifying_key = VerifyingKey::from_bytes(verifying_key).map_err(|e| {
        error!(error = %e, "Ed25519 verifying key bytes are malformed");
        ECCErrors::FailedToVerify
    })?;

    let signature = ed25519_dalek::Signature::from_bytes(signature);

    let valid = verifying_key.verify(data, &signature).is_ok();
    trace!(
        data_len = data.len(),
        valid, "Ed25519 signature verification complete"
    );
    Ok(valid)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that signing key generation succeeds
    #[test]
    fn test_generate_signing_key_success() {
        let result = generate_signing_key();
        assert!(result.is_ok());
    }

    /// Test that generated signing keys are unique
    #[test]
    fn test_signing_keys_unique() {
        let key1 = generate_signing_key().unwrap();
        let key2 = generate_signing_key().unwrap();
        assert_ne!(key1, key2);
    }

    /// Test that verifying key is deterministic from signing key
    #[test]
    fn test_verifying_key_deterministic() {
        let signing_key = generate_signing_key().unwrap();
        let verifying1 = calculate_verifying_key(&signing_key);
        let verifying2 = calculate_verifying_key(&signing_key);
        assert_eq!(verifying1, verifying2);
    }

    /// Test that different signing keys produce different verifying keys
    #[test]
    fn test_different_signing_keys_different_verifying_keys() {
        let signing1 = generate_signing_key().unwrap();
        let signing2 = generate_signing_key().unwrap();
        let verifying1 = calculate_verifying_key(&signing1);
        let verifying2 = calculate_verifying_key(&signing2);
        assert_ne!(verifying1, verifying2);
    }

    /// Test that valid signature verifies correctly
    #[test]
    fn test_sign_and_verify_success() {
        let signing_key = generate_signing_key().unwrap();
        let verifying_key = calculate_verifying_key(&signing_key);
        let data = b"Hello CesaSec!";

        let signature = sign(&signing_key, data);
        let result = verify(&verifying_key, data, &signature).unwrap();

        assert!(result);
    }

    /// Test that wrong key fails verification
    #[test]
    fn test_wrong_key_fails_verification() {
        let signing_key = generate_signing_key().unwrap();
        let wrong_signing_key = generate_signing_key().unwrap();
        let wrong_verifying_key = calculate_verifying_key(&wrong_signing_key);
        let data = b"Hello CesaSec!";

        let signature = sign(&signing_key, data);
        let result = verify(&wrong_verifying_key, data, &signature).unwrap();

        assert!(!result);
    }

    /// Test that tampered data fails verification
    #[test]
    fn test_tampered_data_fails_verification() {
        let signing_key = generate_signing_key().unwrap();
        let verifying_key = calculate_verifying_key(&signing_key);
        let data = b"Hello CesaSec!";
        let tampered = b"Hello CesaSec?"; // zmieniony znak

        let signature = sign(&signing_key, data);
        let result = verify(&verifying_key, tampered, &signature).unwrap();

        assert!(!result);
    }

    /// Test that tampered signature fails verification
    #[test]
    fn test_tampered_signature_fails_verification() {
        let signing_key = generate_signing_key().unwrap();
        let verifying_key = calculate_verifying_key(&signing_key);
        let data = b"Hello CesaSec!";

        let mut signature = sign(&signing_key, data);
        signature[0] ^= 0xFF; // zmodyfikuj podpis

        let result = verify(&verifying_key, data, &signature).unwrap();
        assert!(!result);
    }

    /// Test that signature is deterministic for same data and key
    #[test]
    fn test_signature_not_deterministic() {
        // Ed25519 używa losowego nonce — dwa podpisy tego samego
        // nie będą identyczne ale oba będą valid
        let signing_key = generate_signing_key().unwrap();
        let verifying_key = calculate_verifying_key(&signing_key);
        let data = b"Hello CesaSec!";

        let sig1 = sign(&signing_key, data);
        let sig2 = sign(&signing_key, data);

        // Oba podpisy są valid mimo że różne
        assert!(verify(&verifying_key, data, &sig1).unwrap());
        assert!(verify(&verifying_key, data, &sig2).unwrap());
    }
}
