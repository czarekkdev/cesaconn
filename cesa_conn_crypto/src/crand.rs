use core::fmt;
use rand::{TryRng, rngs::SysRng};
use zeroize::Zeroizing;

/// Errors returned by the OS-RNG utilities in this module.
#[derive(Debug, PartialEq)]
pub enum CRandErrors {
    /// The OS RNG failed to supply entropy (e.g. `getrandom` syscall error).
    FailedToFillBuffer,
}

impl fmt::Display for CRandErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CRandErrors::FailedToFillBuffer => write!(f, "failed to fill buffer with random data"),
        }
    }
}

/// Returns cryptographically secure random bytes sourced directly from the OS.
///
/// The output is wrapped in [`Zeroizing`] so the buffer is scrubbed from memory on drop.
pub fn random_array<const SIZE: usize>() -> Result<Zeroizing<[u8; SIZE]>, CRandErrors> {
    let mut output = Zeroizing::new([0u8; SIZE]);

    SysRng
        .try_fill_bytes(output.as_mut_slice())
        .map_err(|_| CRandErrors::FailedToFillBuffer)?;

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// OS RNG must succeed and fill the buffer with at least some non-zero bytes.
    #[test]
    fn test_output_is_not_all_zeros() {
        let out = random_array::<32>().expect("OS RNG should succeed");
        assert_ne!(*out, [0u8; 32]);
    }

    /// Two consecutive calls must produce different output — collisions are cryptographically impossible.
    #[test]
    fn test_consecutive_calls_differ() {
        let a = random_array::<32>().expect("OS RNG should succeed");
        let b = random_array::<32>().expect("OS RNG should succeed");
        assert_ne!(*a, *b);
    }

    /// The const-generic SIZE parameter is respected — a 64-byte request must yield 64 bytes.
    #[test]
    fn test_size_64_succeeds() {
        let out = random_array::<64>().expect("OS RNG should succeed");
        assert_ne!(*out, [0u8; 64]);
    }

    /// `CRandErrors::FailedToFillBuffer` must produce a human-readable message.
    #[test]
    fn test_error_display() {
        assert_eq!(
            CRandErrors::FailedToFillBuffer.to_string(),
            "failed to fill buffer with random data"
        );
    }
}
