//! Constant-time matching of a configured secret (the static bearer token)
//! against a value a client provides.

use std::fmt;

use myapp_core::secret::MASKED_VALUE;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// The SHA-256 digest of a configured secret, built once at startup.
///
/// [`SecretDigest::matches`] hashes the provided value and compares the two
/// 32-byte digests in constant time, so neither the comparison nor any branch
/// depends on the length of the provided value. A configured value that is
/// empty or whitespace-only never matches anything.
#[derive(Clone)]
pub struct SecretDigest {
    digest: [u8; 32],
    blank: bool,
}

impl SecretDigest {
    /// Digests `configured`, remembering whether it was empty or
    /// whitespace-only.
    pub fn new(configured: &str) -> Self {
        Self {
            digest: Sha256::digest(configured.as_bytes()).into(),
            blank: configured.trim().is_empty(),
        }
    }

    /// Whether `provided` equals the configured secret. Always false when
    /// the configured secret was empty or whitespace-only.
    pub fn matches(&self, provided: &str) -> bool {
        let provided: [u8; 32] = Sha256::digest(provided.as_bytes()).into();
        let equal: bool = self.digest.as_slice().ct_eq(provided.as_slice()).into();
        equal & !self.blank
    }
}

impl fmt::Debug for SecretDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretDigest({MASKED_VALUE})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_the_configured_value() {
        let digest = SecretDigest::new("correct-horse");
        assert!(digest.matches("correct-horse"));
        for provided in [
            "wrong-horse!!",
            "correct",
            "correct-horse-battery",
            "correct-horse ",
            "",
        ] {
            assert!(!digest.matches(provided), "{provided:?} must not match");
        }
    }

    #[test]
    fn blank_configured_value_never_matches() {
        for configured in ["", " ", "   ", "\n\t "] {
            let digest = SecretDigest::new(configured);
            for provided in ["", configured, " ", "anything"] {
                assert!(
                    !digest.matches(provided),
                    "configured {configured:?} must not match {provided:?}"
                );
            }
        }
    }

    #[test]
    fn debug_redacts_the_digest() {
        let digest = SecretDigest::new("correct-horse");
        let hex: String = digest
            .digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let debug = format!("{digest:?}");
        assert_eq!(debug, "SecretDigest(********)");
        assert!(!debug.contains(&hex));
        assert!(!debug.contains("correct-horse"));
    }
}
