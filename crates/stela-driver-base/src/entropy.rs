//! Owned cryptographic entropy supplied by the host platform.
use core::fmt;

/// Why the platform could not supply cryptographic random bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntropyError {
    /// No securely seeded source is available.
    Unavailable,
    /// The source failed while generating this request.
    Failed,
}

impl fmt::Display for EntropyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unavailable => "cryptographic entropy unavailable",
            Self::Failed => "cryptographic entropy generation failed",
        })
    }
}

impl core::error::Error for EntropyError {}

/// A platform source shared by drivers that need authentication nonces or
/// other cryptographic randomness. An owned handle keeps the source alive
/// after the probe that supplied it returns.
///
/// Implementations use a cryptographically secure generator seeded from
/// trusted entropy and serialize concurrent requests. On failure they leave
/// the whole output buffer unchanged.
pub trait Entropy: Send + Sync {
    fn fill(&self, output: &mut [u8]) -> Result<(), EntropyError>;
}
