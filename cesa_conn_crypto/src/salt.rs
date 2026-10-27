use core::fmt;
use rand::TryRng;
use rand::rngs::SysRng;
use tracing::{debug, error};

/// Errors that can occur during salt generation
#[derive(Debug)]
pub enum SaltError {
    /// OS failed to provide cryptographically secure random bytes
    FailedToGenerate,
}

impl fmt::Display for SaltError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SaltError::FailedToGenerate => write!(f, "Failed to generate salt"),
        }
    }
}

/// Generates a cryptographically secure random 32-byte salt.
/// Uses the OS entropy source (SysRng) — /dev/urandom on Linux.
/// Salt should be stored alongside the derived key for future use.
///
/// # Returns
/// * `Ok([u8; 32])` - Random salt ready for use with Argon2
/// * `Err(SaltError::FailedToGenerate)` - OS failed to generate random bytes
pub fn generate_salt() -> Result<[u8; 32], SaltError> {
    debug!("generating 32-byte cryptographic salt from OS entropy");
    let mut salt = [0u8; 32];

    // SysRng uses OS cryptographic random source
    // Most secure RNG available in software
    let mut rng = SysRng;

    rng.try_fill_bytes(&mut salt).map_err(|e| {
        error!(error = %e, "OS failed to provide random bytes for salt generation");
        SaltError::FailedToGenerate
    })?;

    debug!("32-byte salt generated successfully");
    Ok(salt)
}

#[cfg(test)]
mod tests {

    use super::*;

    /// Test that salt generation succeeds
    #[test]
    fn test_generate_salt_success() {
        let result = generate_salt();
        assert!(result.is_ok());
    }

    /// Test that generated salt is exactly 32 bytes
    #[test]
    fn test_generate_salt_length() {
        let salt = generate_salt().unwrap();
        assert_eq!(salt.len(), 32);
    }

    /// Test that generated salt is not all zeros — sanity check
    #[test]
    fn test_salt_not_empty() {
        let salt = generate_salt().unwrap();
        assert_ne!(salt, [0u8; 32]);
    }

    /// Test that two generated salts are different — verifies randomness
    #[test]
    fn test_salts_are_unique() {
        let salt1 = generate_salt().unwrap();
        let salt2 = generate_salt().unwrap();

        assert_ne!(salt1, salt2);
    }
}
