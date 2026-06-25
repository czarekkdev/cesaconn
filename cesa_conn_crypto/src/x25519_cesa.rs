use sha2::{Digest, Sha256};
use tracing::trace;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub struct X25519KeyPair {
    pub public: Zeroizing<[u8; 32]>,
    pub private: Zeroizing<[u8; 32]>,
}

impl X25519KeyPair {
    pub fn new(pub_key: [u8; 32], priv_key: [u8; 32]) -> Self {
        Self {
            public: Zeroizing::new(pub_key),
            private: Zeroizing::new(priv_key),
        }
    }
}


/// Derives the X25519 public key from a private key
pub fn calculate_public_key(private_key: &[u8; 32]) -> [u8; 32] {
    trace!("deriving X25519 public key from private key");
    let private_key = StaticSecret::from(*private_key);
    let public_key = PublicKey::from(&private_key);
    *public_key.as_bytes()
}

// TODO: add check if was_contributory
/// Computes ECDH shared secret from private key and the other party's public key
/// The result should be hashed with SHA-256 before use as an AES-256 key
pub fn calculate_shared_key(private_key: &[u8; 32], their_public: &[u8; 32]) -> [u8; 32] {
    trace!("computing X25519 ECDH shared secret");
    let private_key = StaticSecret::from(*private_key);
    let their_public = PublicKey::from(*their_public);

    *private_key.diffie_hellman(&their_public).as_bytes()
}

/// Hashes the ECDH shared secret using SHA-256 to produce a secure AES-256 key.
/// Raw shared secret should never be used directly as an AES key — always hash first.
pub fn hash_key(shared_key: &[u8; 32]) -> [u8; 32] {
    trace!("hashing ECDH shared secret with SHA-256");
    Sha256::digest(*shared_key).into()
}

pub fn generate_new_key_pair(random_data: [u8; 32]) -> X25519KeyPair {
    let pub_key = Zeroizing::new(calculate_public_key(&random_data));

    X25519KeyPair::new(*pub_key, *&random_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that two parties derive the same shared secret
    #[test]
    fn test_shared_secret_matches() {
        let private_a = generate_private_key();
        let private_b = generate_private_key();

        let public_a = calculate_public_key(&private_a);
        let public_b = calculate_public_key(&private_b);

        let shared_a = calculate_shared_key(&private_a, &public_b);
        let shared_b = calculate_shared_key(&private_b, &public_a);

        assert_eq!(shared_a, shared_b); // magia ECDH ✅
    }

    /// Test that different key pairs produce different shared secrets
    #[test]
    fn test_different_keys_different_secrets() {
        let private_a = generate_private_key();
        let private_b = generate_private_key();
        let private_c = generate_private_key();

        let public_b = calculate_public_key(&private_b);
        let public_c = calculate_public_key(&private_c);

        let shared_ab = calculate_shared_key(&private_a, &public_b);
        let shared_ac = calculate_shared_key(&private_a, &public_c);

        assert_ne!(shared_ab, shared_ac);
    }

    /// Test that generated private keys are unique
    #[test]
    fn test_private_keys_unique() {
        let key1 = generate_private_key();
        let key2 = generate_private_key();
        assert_ne!(key1, key2);
    }

    /// Test that public key is deterministic from private key
    #[test]
    fn test_public_key_deterministic() {
        let private_key = generate_private_key();
        let public1 = calculate_public_key(&private_key);
        let public2 = calculate_public_key(&private_key);
        assert_eq!(public1, public2);
    }

    /// Test that hash_key produces consistent output for same input
    #[test]
    fn test_hash_key_deterministic() {
        let shared = calculate_shared_key(
            &generate_private_key(),
            &calculate_public_key(&generate_private_key()),
        );
        let hash1 = hash_key(&shared);
        let hash2 = hash_key(&shared);
        assert_eq!(hash1, hash2);
    }

    /// Test that hash_key output is not equal to input
    #[test]
    fn test_hash_key_changes_value() {
        let shared = [1u8; 32];
        let hashed = hash_key(&shared);
        assert_ne!(hashed, shared);
    }

    /// Test that different inputs produce different hashes
    #[test]
    fn test_hash_key_unique() {
        let shared_a = [1u8; 32];
        let shared_b = [2u8; 32];
        assert_ne!(hash_key(&shared_a), hash_key(&shared_b));
    }
}
