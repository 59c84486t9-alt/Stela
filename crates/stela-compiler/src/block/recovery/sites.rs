//! Orthogonal native fault sites, minted by the compiler's emission plan.
use super::{FaultRecoveryError, RecoveredPosition, RetirementPhase};

/// Portable classification tag. A decoded tag carries no guest-fault permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RecoverySiteKind {
    NativeInternal = 0,
    GuestAccess = 1,
    GuestCheck = 2,
    /// Deliberate translated-memory helper abandon at its exact return token.
    TranslatedHelper = 3,
}
impl TryFrom<u8> for RecoverySiteKind {
    type Error = FaultRecoveryError;
    fn try_from(tag: u8) -> Result<Self, Self::Error> {
        match tag {
            0 => Ok(Self::NativeInternal),
            1 => Ok(Self::GuestAccess),
            2 => Ok(Self::GuestCheck),
            3 => Ok(Self::TranslatedHelper),
            _ => Err(FaultRecoveryError::UnknownRecoverySite { tag }),
        }
    }
}

/// A site checked by matching admitted source, profile and native code/plan.
/// A source-word shape or portable kind alone cannot mint a guest site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoverySite {
    kind: RecoverySiteKind,
    translated: Option<TranslatedAccess>,
}

/// The compiler-emitted access descriptor at a checked helper return token.
/// No public constructor exists: portable tags and arbitrary byte pairs cannot
/// mint helper-failure permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TranslatedAccess {
    pub(super) bytes: u8,
    pub(super) flags: u8,
}
impl TranslatedAccess {
    pub const fn bytes(self) -> u8 {
        self.bytes
    }
    pub const fn write(self) -> bool {
        self.flags & 1 != 0
    }
    pub const fn unprivileged(self) -> bool {
        self.flags & 2 != 0
    }
    pub const fn atomic(self) -> bool {
        self.flags & 4 != 0
    }
}
impl RecoverySite {
    pub const fn native_internal() -> Self {
        Self {
            kind: RecoverySiteKind::NativeInternal,
            translated: None,
        }
    }
    pub const fn kind(self) -> RecoverySiteKind {
        self.kind
    }
    pub const fn translated_access(self) -> Option<TranslatedAccess> {
        self.translated
    }
    /// Back from [`super::PackedRecovery`], which holds only minted sites.
    pub(super) fn packed(kind: u8, translated: Option<(u8, u8)>) -> Self {
        Self {
            kind: RecoverySiteKind::try_from(kind).expect("packed by new"),
            translated: translated.map(|(bytes, flags)| TranslatedAccess { bytes, flags }),
        }
    }
    pub(crate) const fn guest_access() -> Self {
        Self {
            kind: RecoverySiteKind::GuestAccess,
            translated: None,
        }
    }
    pub(crate) const fn guest_check() -> Self {
        Self {
            kind: RecoverySiteKind::GuestCheck,
            translated: None,
        }
    }
    pub(crate) const fn translated_helper(bytes: u8, flags: u8) -> Self {
        Self {
            kind: RecoverySiteKind::TranslatedHelper,
            translated: Some(TranslatedAccess { bytes, flags }),
        }
    }
}

/// Validated architectural settlement and independent native fault semantics.
/// The native exception/vector must also be compatible with the site before a
/// caller projects a guest fault; an illegal host opcode is not a data abort.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoverySettlement {
    pub position: RecoveredPosition,
    pub site: RecoverySite,
    pub phase: RetirementPhase,
}

#[cfg(test)]
mod tests;
