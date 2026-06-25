use sha2::{Digest, Sha256};
use tracing::trace;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// An X25519 key pair with both fields wrapped in [`Zeroizing`] so they are
/// scrubbed from memory on drop.
pub struct X25519KeyPair {
    pub public: Zeroizing<[u8; 32]>,
    pub private: Zeroizing<[u8; 32]>,
}

impl X25519KeyPair {
    /// Wraps raw public and private key bytes in [`Zeroizing`].
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

/// Generates an [`X25519KeyPair`] from 32 bytes of caller-supplied entropy.
/// The caller is responsible for ensuring `random_data` is cryptographically secure
/// (e.g. sourced from [`crate::crand::random_array`]).
pub fn generate_new_key_pair(random_data: [u8; 32]) -> X25519KeyPair {
    let pub_key = Zeroizing::new(calculate_public_key(&random_data));

    X25519KeyPair::new(*pub_key, *&random_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generates a random private key using OS entropy via `crand`.
    fn generate_private_key() -> [u8; 32] {
        *crate::crand::random_array::<32>().expect("OS RNG should succeed")
    }

    // -------------------------------------------------------------------------
    // calculate_shared_key / ECDH property tests
    // -------------------------------------------------------------------------

    /// Both parties must derive the same shared secret from their own private key
    /// and the other party's public key — the fundamental ECDH property.
    #[test]
    fn test_shared_secret_matches() {
        let private_a = generate_private_key();
        let private_b = generate_private_key();

        let public_a = calculate_public_key(&private_a);
        let public_b = calculate_public_key(&private_b);

        let shared_a = calculate_shared_key(&private_a, &public_b);
        let shared_b = calculate_shared_key(&private_b, &public_a);

        assert_eq!(shared_a, shared_b);
    }

    /// Two exchanges with different peer public keys must produce different shared secrets.
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

    // -------------------------------------------------------------------------
    // calculate_public_key tests
    // -------------------------------------------------------------------------

    /// `calculate_public_key` must be pure — same private key always yields same public key.
    #[test]
    fn test_public_key_deterministic() {
        let private_key = generate_private_key();
        let public1 = calculate_public_key(&private_key);
        let public2 = calculate_public_key(&private_key);
        assert_eq!(public1, public2);
    }

    /// Different private keys must produce different public keys.
    #[test]
    fn test_different_private_keys_different_public_keys() {
        let private_a = generate_private_key();
        let private_b = generate_private_key();
        assert_ne!(calculate_public_key(&private_a), calculate_public_key(&private_b));
    }

    // -------------------------------------------------------------------------
    // hash_key tests
    // -------------------------------------------------------------------------

    /// `hash_key` must be pure — same input always yields the same digest.
    #[test]
    fn test_hash_key_deterministic() {
        let shared = [0xABu8; 32];
        assert_eq!(hash_key(&shared), hash_key(&shared));
    }

    /// The SHA-256 digest of any non-trivial input must differ from the input itself.
    #[test]
    fn test_hash_key_changes_value() {
        let shared = [1u8; 32];
        let hashed = hash_key(&shared);
        assert_ne!(hashed, shared);
    }

    /// Different shared secrets must hash to different values.
    #[test]
    fn test_hash_key_unique() {
        assert_ne!(hash_key(&[1u8; 32]), hash_key(&[2u8; 32]));
    }

    // -------------------------------------------------------------------------
    // generate_new_key_pair tests
    // -------------------------------------------------------------------------

    /// The public key stored in the pair must match `calculate_public_key` for the same seed.
    #[test]
    fn test_generate_new_key_pair_public_key_correct() {
        let seed = generate_private_key();
        let pair = generate_new_key_pair(seed);
        assert_eq!(*pair.public, calculate_public_key(&seed));
    }

    /// The private field must be the raw seed bytes passed in.
    #[test]
    fn test_generate_new_key_pair_private_key_stored() {
        let seed = generate_private_key();
        let pair = generate_new_key_pair(seed);
        assert_eq!(*pair.private, seed);
    }

    /// A pair generated via `generate_new_key_pair` must satisfy the ECDH property
    /// when exchanged with a manually constructed peer.
    #[test]
    fn test_generate_new_key_pair_ecdh_property() {
        let seed_a = generate_private_key();
        let seed_b = generate_private_key();

        let pair_a = generate_new_key_pair(seed_a);
        let pair_b = generate_new_key_pair(seed_b);

        let shared_a = calculate_shared_key(&pair_a.private, &pair_b.public);
        let shared_b = calculate_shared_key(&pair_b.private, &pair_a.public);

        assert_eq!(shared_a, shared_b);
    }

    // -------------------------------------------------------------------------
    // X25519KeyPair::new tests
    // -------------------------------------------------------------------------

    /// Both fields must be stored verbatim inside their `Zeroizing` wrappers.
    #[test]
    fn test_key_pair_new_stores_both_fields() {
        let pub_bytes = [0xAAu8; 32];
        let priv_bytes = [0xBBu8; 32];
        let pair = X25519KeyPair::new(pub_bytes, priv_bytes);
        assert_eq!(*pair.public, pub_bytes);
        assert_eq!(*pair.private, priv_bytes);
    }

    /// Fields with identical values must not be deduplicated — they are independent.
    #[test]
    fn test_key_pair_new_same_values_independent() {
        let bytes = [0x42u8; 32];
        let pair = X25519KeyPair::new(bytes, bytes);
        assert_eq!(*pair.public, bytes);
        assert_eq!(*pair.private, bytes);
    }
}
