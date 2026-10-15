//! Partial immutable named identification authority shared by MRS and qualifiers.
//! No control/cache/device state, default CPU, guessed absence or host inference.
mod qualifiers;

use super::identification::{Readback, Readbacks, Register};
use std::{fmt, sync::Arc};

const STATIC_ID_COUNT: usize = 20;
const STATIC_IDS: [Register; STATIC_ID_COUNT] = [
    Register::IdAa64Afr0El1,
    Register::IdAa64Afr1El1,
    Register::IdAa64Dfr0El1,
    Register::IdAa64Dfr1El1,
    Register::IdAa64Dfr2El1,
    Register::IdAa64Fpfr0El1,
    Register::IdAa64Isar0El1,
    Register::IdAa64Isar1El1,
    Register::IdAa64Isar2El1,
    Register::IdAa64Isar3El1,
    Register::IdAa64Mmfr0El1,
    Register::IdAa64Mmfr1El1,
    Register::IdAa64Mmfr2El1,
    Register::IdAa64Mmfr3El1,
    Register::IdAa64Mmfr4El1,
    Register::IdAa64Pfr0El1,
    Register::IdAa64Pfr1El1,
    Register::IdAa64Pfr2El1,
    Register::IdAa64Smfr0El1,
    Register::IdAa64Zfr0El1,
];
const DECLARATION_FORMAT: &[u8] = b"stela-partial-static-identification-v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    CapturedHardware,
    DeclaredGuest,
}

/// Evidence identity, not independent authentication of hardware. Captured input
/// is supplied by the trusted source owner after its acquisition verification.
/// Retained bytes and offsets let later evidence review verify exact readbacks.
pub struct Provenance {
    origin: Origin,
    source_identity: &'static str,
    input: Arc<[u8]>,
    input_sha256: String,
    captured_fields: Vec<(Register, usize)>,
}
impl Provenance {
    pub const fn origin(&self) -> Origin {
        self.origin
    }
    pub const fn source_identity(&self) -> &'static str {
        self.source_identity
    }
    pub fn input(&self) -> &[u8] {
        &self.input
    }
    pub fn input_sha256(&self) -> &str {
        &self.input_sha256
    }
    pub fn captured_fields(&self) -> &[(Register, usize)] {
        &self.captured_fields
    }
}
impl fmt::Debug for Provenance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Provenance")
            .field("origin", &self.origin)
            .field("source_identity", &self.source_identity)
            .field("input_sha256", &self.input_sha256)
            .field("input_bytes", &self.input.len())
            .finish_non_exhaustive()
    }
}

/// Non-Clone/non-Copy: consumers borrow this same immutable allocation. An Arc
/// may retain its lifetime; equality of raw values does not imply source identity.
#[derive(Debug)]
pub struct Snapshot {
    values: [Option<u64>; STATIC_ID_COUNT],
    provenance: Provenance,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitializationError {
    EmptyIdentity,
    EmbeddedIdentityNul,
    EmptyCapture,
    UnownedRegister(Register),
    DuplicateRegister(Register),
    CaptureBounds {
        register: Register,
        offset: usize,
        input_bytes: usize,
    },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unsupported {
    MissingRegister(Register),
    UnownedRegister(Register),
    Field {
        register: Register,
        field: &'static str,
        value: u8,
    },
    EntryProfile(super::profile::EntryProfileError),
    EntryProfileMismatch,
    PauthLrTuple {
        apa: u8,
        api: u8,
        apa3: u8,
    },
    BaseSpe(super::profile::UnsupportedSpe),
}
impl fmt::Display for Unsupported {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "unsupported identification requirement: {self:?}"
        )
    }
}
impl std::error::Error for Unsupported {}
impl fmt::Display for InitializationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid identification initialization: {self:?}")
    }
}
impl std::error::Error for InitializationError {}

fn index(register: Register) -> Option<usize> {
    STATIC_IDS
        .iter()
        .position(|candidate| *candidate == register)
}
fn insert(
    values: &mut [Option<u64>; STATIC_ID_COUNT],
    register: Register,
    value: u64,
) -> Result<(), InitializationError> {
    let slot = index(register).ok_or(InitializationError::UnownedRegister(register))?;
    if values[slot].replace(value).is_some() {
        return Err(InitializationError::DuplicateRegister(register));
    }
    Ok(())
}

impl Snapshot {
    /// An explicit software-machine declaration; every supplied value is retained.
    /// Missing IDs remain missing. Canonical declaration bytes bind the machine
    /// name and supplied values without implying hardware evidence or features.
    pub fn declared(
        machine_identity: &'static str,
        entries: &[(Register, u64)],
    ) -> Result<Self, InitializationError> {
        if machine_identity.is_empty() {
            return Err(InitializationError::EmptyIdentity);
        }
        if machine_identity.as_bytes().contains(&0) {
            return Err(InitializationError::EmbeddedIdentityNul);
        }
        let mut values = [None; STATIC_ID_COUNT];
        for &(register, value) in entries {
            insert(&mut values, register, value)?;
        }
        let mut input = DECLARATION_FORMAT.to_vec();
        input.extend(machine_identity.as_bytes());
        input.push(0);
        for (slot, register) in STATIC_IDS.iter().enumerate() {
            if let Some(value) = values[slot] {
                input.extend(register.encoding().selector().to_le_bytes());
                input.extend(value.to_le_bytes());
            }
        }
        let input_sha256 = stela_core::sha256(&input);
        Ok(Self {
            values,
            provenance: Provenance {
                origin: Origin::DeclaredGuest,
                source_identity: machine_identity,
                input: input.into(),
                input_sha256,
                captured_fields: Vec::new(),
            },
        })
    }

    /// Trusted acquisition adapter only: it supplies verified immutable input
    /// and source-format offsets. Values are extracted here, never independently
    /// supplied or normalized. This binding does not authenticate hardware; the
    /// actual acquisition/receipt owner remains responsible for that evidence.
    #[cfg(test)]
    pub(crate) fn captured(
        source_identity: &'static str,
        input: Arc<[u8]>,
        fields: &[(Register, usize)],
    ) -> Result<Self, InitializationError> {
        if source_identity.is_empty() {
            return Err(InitializationError::EmptyIdentity);
        }
        if source_identity.as_bytes().contains(&0) {
            return Err(InitializationError::EmbeddedIdentityNul);
        }
        if input.is_empty() {
            return Err(InitializationError::EmptyCapture);
        }
        let mut values = [None; STATIC_ID_COUNT];
        for &(register, offset) in fields {
            let end = offset
                .checked_add(std::mem::size_of::<u64>())
                .filter(|end| *end <= input.len())
                .ok_or(InitializationError::CaptureBounds {
                    register,
                    offset,
                    input_bytes: input.len(),
                })?;
            let value =
                u64::from_le_bytes(input[offset..end].try_into().expect("checked u64 readback"));
            insert(&mut values, register, value)?;
        }
        let input_sha256 = stela_core::sha256(&input);
        Ok(Self {
            values,
            provenance: Provenance {
                origin: Origin::CapturedHardware,
                source_identity,
                input,
                input_sha256,
                captured_fields: fields.to_vec(),
            },
        })
    }

    pub fn read(&self, register: Register) -> Result<u64, Unsupported> {
        let slot = index(register).ok_or(Unsupported::UnownedRegister(register))?;
        self.values[slot].ok_or(Unsupported::MissingRegister(register))
    }
    pub const fn provenance(&self) -> &Provenance {
        &self.provenance
    }
    pub fn same_snapshot(&self, other: &Self) -> bool {
        std::ptr::eq(self, other)
    }
}
impl Readbacks for Snapshot {
    fn readback(&self, readback: Readback) -> Option<u64> {
        match readback {
            Readback::Register(register) => self.read(register).ok(),
            _ => None,
        }
    }
    fn conditional_tid3(&self, _: Register) -> Option<bool> {
        None
    }
}

#[cfg(test)]
#[path = "identification_snapshot/tests.rs"]
mod tests;
