//! Pointer-signing metadata shared by image fixups and execution providers.
use serde::Serialize;

/// The architectural key slot and pointer address domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Key {
    Ia,
    Ib,
    Da,
    Db,
}
impl Key {
    pub const fn index(self) -> usize {
        match self {
            Self::Ia => 0,
            Self::Ib => 1,
            Self::Da => 2,
            Self::Db => 3,
        }
    }
    pub const fn is_data(self) -> bool {
        matches!(self, Self::Da | Self::Db)
    }
    pub const fn is_b(self) -> bool {
        matches!(self, Self::Ib | Self::Db)
    }
}

/// A process-owned pointer-signing provider. Format readers own no keys.
pub trait Signer {
    type Error;
    fn address_space(&self) -> u64;
    fn profile_id(&self) -> &'static str;
    fn sign(&self, key: Key, pointer: u64, modifier: u64) -> Result<u64, Self::Error>;
}
