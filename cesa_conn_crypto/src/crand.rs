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

    #[test]
    fn output_is_not_all_zeros() {
        let out = random_array().expect("OS RNG should succeed");
        assert_ne!(*out, [0u8; 64]);
    }

    #[test]
    fn consecutive_calls_differ() {
        let a = random_array().expect("OS RNG should succeed");
        let b = random_array().expect("OS RNG should succeed");
        assert_ne!(*a, *b);
    }

    #[test]
    fn output_is_64_bytes() {
        let out = random_array().expect("OS RNG should succeed");
        assert_eq!(out.len(), 64);
    }
}
