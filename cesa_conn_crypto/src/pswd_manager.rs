use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

use core::fmt;
use tracing::{debug, error};

/// Errors that can occur during password-based key derivation
#[derive(Debug)]
pub enum PswdMErrors {
    /// Argon2 hashing failed
    HashFailed,
}

impl fmt::Display for PswdMErrors {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PswdMErrors::HashFailed => write!(f, "Failed to derive key from password"),
        }
    }
}

/// Argon2id memory cost in KiB (64 MiB).
///
/// These parameters are part of the protocol: every device must use the same
/// ones, otherwise they derive different keys. Changing them changes all keys.
pub const ARGON2_M_COST: u32 = 64 * 1024;
/// Argon2id passes over memory.
pub const ARGON2_T_COST: u32 = 3;
/// Argon2id lanes.
pub const ARGON2_P_COST: u32 = 1;

/// Derives a 32-byte cryptographic key from a password and salt using Argon2id
/// (v0x13, [`ARGON2_M_COST`] / [`ARGON2_T_COST`] / [`ARGON2_P_COST`]).
/// The resulting key can be used directly as an AES-256 or X25519 key.
///
/// # Arguments
/// * `password` - Raw password bytes — never stored, only used for derivation
/// * `salt`     - 32-byte salt — must be unique per user/session
///
/// # Returns
/// * `Ok(Zeroizing<[u8; 32]>)` - Derived key, wiped from memory on drop
/// * `Err(PswdMErrors::HashFailed)` - Argon2 derivation failed
pub fn derive_key(password: &[u8], salt: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, PswdMErrors> {
    debug!(
        password_len = password.len(),
        "deriving AES-256 key from password using Argon2 (intentionally slow)"
    );
    let mut key = Zeroizing::new([0u8; 32]);

    // Argon2 is intentionally slow — makes brute force attacks impractical
    // explicit, not Argon2::default(): a changed library default would silently
    // give every device different keys
    let params =
        Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32)).map_err(|e| {
            error!(error = %e, "invalid Argon2 parameters");
            PswdMErrors::HashFailed
        })?;
    let cipher = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    cipher
        .hash_password_into(password, salt, key.as_mut_slice())
        .map_err(|e| {
            error!(error = %e, password_len = password.len(), "Argon2 key derivation failed");
            PswdMErrors::HashFailed
        })?;

    debug!("Argon2 key derivation successful");
    Ok(key)
}

#[cfg(test)]
mod tests {

    use super::*;

    /// Test that key derivation succeeds with valid input
    #[test]
    fn test_derive_key_success() {
        let password = b"test_password";
        let salt = [0u8; 32];

        let result = derive_key(password, &salt);
        assert!(result.is_ok());
    }

    /// Test that derived key is exactly 32 bytes
    #[test]
    fn test_derive_key_length() {
        let password = b"test_password";
        let salt = [0u8; 32];

        let key = derive_key(password, &salt).unwrap();
        assert_eq!(key.len(), 32);
    }

    /// Test that same password + same salt = same key (deterministic)
    #[test]
    fn test_derive_key_deterministic() {
        let password = b"test_password";
        let salt = [0u8; 32];

        let key1 = derive_key(password, &salt).unwrap();
        let key2 = derive_key(password, &salt).unwrap();

        assert_eq!(key1, key2);
    }

    /// Test that different passwords produce different keys
    #[test]
    fn test_different_passwords_different_keys() {
        let salt = [0u8; 32];

        let key1 = derive_key(b"password1", &salt).unwrap();
        let key2 = derive_key(b"password2", &salt).unwrap();

        assert_ne!(key1, key2);
    }

    /// Test that different salts produce different keys
    #[test]
    fn test_different_salts_different_keys() {
        let password = b"test_password";

        let key1 = derive_key(password, &[0u8; 32]).unwrap();
        let key2 = derive_key(password, &[1u8; 32]).unwrap();

        assert_ne!(key1, key2);
    }

    /// Test that derived key is not all zeros — sanity check
    #[test]
    fn test_key_not_empty() {
        let password = b"test_password";
        let salt = [0u8; 32];

        let key = derive_key(password, &salt).unwrap();
        assert_ne!(*key, [0u8; 32]);
    }

    /// Test that the parameters are pinned to Argon2id 64 MiB / 3 / 1 (known answer)
    #[test]
    fn test_derive_key_known_answer() {
        // reference value from the argon2 crate with the same parameters, so a
        // changed default or parameter shows up as a failing test
        let key = derive_key(b"password", &[0x02; 32]).unwrap();
        let params = Params::new(64 * 1024, 3, 1, Some(32)).unwrap();
        let mut expected = [0u8; 32];

        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(b"password", &[0x02; 32], &mut expected)
            .unwrap();
        assert_eq!(*key, expected);

        let mut default = [0u8; 32];
        Argon2::default()
            .hash_password_into(b"password", &[0x02; 32], &mut default)
            .unwrap();
        assert_ne!(*key, default);
    }

    /// Test with empty password
    #[test]
    fn test_empty_password() {
        let salt = [0u8; 32];
        let result = derive_key(b"", &salt);
        assert!(result.is_ok());
    }

    /// Test with maximum length password
    #[test]
    fn test_long_password() {
        let password = vec![b'a'; 1024];
        let salt = [0u8; 32];
        let result = derive_key(&password, &salt);
        assert!(result.is_ok());
    }
}
