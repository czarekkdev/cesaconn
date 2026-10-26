//! macOS code-signature check of the process at the other end of a local
//! socket. The daemon uses it on its UI clients, and the UI uses it on the
//! daemon before sending a password.
//!
//! The peer is identified by its audit token (pid + pid version), taken by
//! the kernel when the connection was made, so neither a recycled pid nor a
//! socket passed on to another process changes whose signature is checked.
//!
//! Other platforms have no OS code signing: a requirement is refused there,
//! so it can never look like protection that isn't there.

use core::fmt;

/// All errors of the code-signature check.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum CodeSignatureErrors {
    /// The requirement doesn't parse, or this platform has no code signing.
    InvalidRequirement,
    /// The peer's signature couldn't be checked or doesn't satisfy the requirement.
    Untrusted,
}

impl fmt::Display for CodeSignatureErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodeSignatureErrors::InvalidRequirement => {
                write!(f, "code requirement is invalid or unsupported here")
            }
            CodeSignatureErrors::Untrusted => {
                write!(f, "peer's code signature doesn't satisfy the requirement")
            }
        }
    }
}

/// Checks that `requirement` parses.
#[cfg(target_os = "macos")]
pub fn validate_requirement(requirement: &str) -> Result<(), CodeSignatureErrors> {
    use security_framework::os::macos::code_signing::SecRequirement;
    use std::str::FromStr;

    SecRequirement::from_str(requirement)
        .map(drop)
        .map_err(|_| CodeSignatureErrors::InvalidRequirement)
}

/// No code signing on this platform: every requirement is refused.
#[cfg(not(target_os = "macos"))]
pub fn validate_requirement(_requirement: &str) -> Result<(), CodeSignatureErrors> {
    Err(CodeSignatureErrors::InvalidRequirement)
}

/// Checks the code signature of the process at the other end of `stream`.
#[cfg(target_os = "macos")]
pub async fn verify_peer(
    stream: &tokio::net::UnixStream,
    requirement: &'static str,
) -> Result<(), CodeSignatureErrors> {
    use nix::sys::socket::{getsockopt, sockopt::LocalPeerToken};

    // the audit token identifies a process, it is not a secret
    let audit = getsockopt(stream, LocalPeerToken).map_err(|_| CodeSignatureErrors::Untrusted)?;
    let audit: Vec<u8> = audit.val.iter().flat_map(|v| v.to_ne_bytes()).collect();

    // the Security framework may touch the disk: off the async workers
    tokio::task::spawn_blocking(move || check_audit_token(&audit, requirement))
        .await
        .map_err(|_| CodeSignatureErrors::Untrusted)?
}

/// No code signing on this platform: fails closed.
#[cfg(all(unix, not(target_os = "macos")))]
pub async fn verify_peer(
    _stream: &tokio::net::UnixStream,
    _requirement: &'static str,
) -> Result<(), CodeSignatureErrors> {
    Err(CodeSignatureErrors::Untrusted)
}

/// Looks the audit token up as a guest of the kernel and validates it.
#[cfg(target_os = "macos")]
fn check_audit_token(audit: &[u8], requirement: &str) -> Result<(), CodeSignatureErrors> {
    use core_foundation::{base::TCFType, data::CFData};
    use security_framework::os::macos::code_signing::{
        Flags, GuestAttributes, SecCode, SecRequirement,
    };
    use std::str::FromStr;

    let audit = CFData::from_buffer(audit);
    let mut attributes = GuestAttributes::new();

    // the dictionary retains `audit`, which also outlives this call
    attributes.set_audit_token(audit.as_concrete_TypeRef());

    let code = SecCode::copy_guest_with_attribues(None, &attributes, Flags::NONE)
        .map_err(|_| CodeSignatureErrors::Untrusted)?;
    let requirement =
        SecRequirement::from_str(requirement).map_err(|_| CodeSignatureErrors::Untrusted)?;

    // dynamic check: the running code must still match its signature
    code.check_validity(Flags::NONE, &requirement)
        .map_err(|_| CodeSignatureErrors::Untrusted)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that an unparsable requirement is refused
    #[test]
    fn test_invalid_requirement_refused() {
        assert_eq!(
            validate_requirement("this is ( not a requirement"),
            Err(CodeSignatureErrors::InvalidRequirement)
        );
    }

    /// Test that a peer is checked against the requirement (the test binary
    /// is not Apple-signed): a requirement it misses fails, one it meets passes
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn test_verify_peer_against_requirement() {
        let (a, _b) = tokio::net::UnixStream::pair().unwrap();

        assert_eq!(
            verify_peer(&a, "anchor apple").await,
            Err(CodeSignatureErrors::Untrusted)
        );
        assert_eq!(verify_peer(&a, "! anchor apple").await, Ok(()));
        // unparsable at check time: fails closed
        assert_eq!(
            verify_peer(&a, "this is ( not a requirement").await,
            Err(CodeSignatureErrors::Untrusted)
        );
    }

    /// Test that without OS code signing every check fails closed
    #[cfg(all(unix, not(target_os = "macos")))]
    #[tokio::test]
    async fn test_no_code_signing_fails_closed() {
        let (a, _b) = tokio::net::UnixStream::pair().unwrap();
        assert_eq!(
            verify_peer(&a, "anything").await,
            Err(CodeSignatureErrors::Untrusted)
        );
    }
}
