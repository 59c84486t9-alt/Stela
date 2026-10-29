//! An immutable set of identification-register values, shared by MRS and the
//! feature checks.
#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};
mod qualifiers;

use super::identification::Register;
use alloc::sync::Arc;
use core::fmt;

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

/// Where the snapshot came from. This identifies the input without
/// authenticating hardware; the bytes and offsets allow the readbacks
/// to be verified later.
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
/// may keep its lifetime; equality of raw values does not imply source identity.
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
impl core::error::Error for Unsupported {}
impl fmt::Display for InitializationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid identification initialization: {self:?}")
    }
}
impl core::error::Error for InitializationError {}

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
    /// Allocation capacities, including the containing Arc's two
    /// counters. Shared input is conservatively charged to each owner.
    pub(crate) fn retained_bytes(&self) -> usize {
        core::mem::size_of::<Self>()
            + 2 * core::mem::size_of::<usize>()
            + self
                .provenance
                .input
                .len()
                .next_multiple_of(core::mem::align_of::<usize>())
            + 2 * core::mem::size_of::<usize>()
            + self.provenance.input_sha256.capacity()
            + self.provenance.captured_fields.capacity() * core::mem::size_of::<(Register, usize)>()
    }

    /// A software-machine declaration. Every value is kept and missing IDs stay
    /// missing; the declaration bytes bind the machine name and the values.
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
        let input_sha256 = stela_formats::sha256(&input);
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

    /// Build a snapshot from verified captured input and its offsets; values
    /// are extracted here, not supplied separately.
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
                .checked_add(core::mem::size_of::<u64>())
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
        let input_sha256 = stela_formats::sha256(&input);
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
        core::ptr::eq(self, other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::profile::{EntryProfile, ScalableEntryAbsence, SystemEntryFeatures};

    const IDENTITY: &str = "declared-bounded-el01-auth2-test";
    const APA_SHIFT: u32 = 4;
    const API_SHIFT: u32 = 8;
    const APA3_SHIFT: u32 = 12;
    const APA_FAULTING_COMBINED: u64 = 5;
    const A64_EL0_EL1_NO_HIGHER_EL: u64 = 0x11;
    const FIELD_MAX: u64 = 0xf;
    const PFAR_SHIFT: u32 = 60;
    const REGISTER_VALUE_BYTES: usize = std::mem::size_of::<u64>();

    fn entries() -> Vec<(Register, u64)> {
        vec![
            (Register::IdAa64Isar1El1, APA_FAULTING_COMBINED << APA_SHIFT),
            (Register::IdAa64Isar2El1, 0),
            (Register::IdAa64Pfr0El1, A64_EL0_EL1_NO_HIGHER_EL),
            (Register::IdAa64Pfr1El1, 0),
            (Register::IdAa64Pfr2El1, 0),
            (Register::IdAa64Dfr0El1, 0),
            (Register::IdAa64Dfr1El1, 0),
            (Register::IdAa64Mmfr0El1, 0),
            (Register::IdAa64Mmfr1El1, 0),
            (Register::IdAa64Mmfr2El1, 0),
            (Register::IdAa64Mmfr3El1, 0),
        ]
    }
    fn replace(entries: &mut [(Register, u64)], register: Register, value: u64) {
        entries
            .iter_mut()
            .find(|(candidate, _)| *candidate == register)
            .unwrap()
            .1 = value;
    }

    #[test]
    fn partial_readbacks_are_exact_and_missing_never_becomes_zero() {
        let snapshot =
            Snapshot::declared(IDENTITY, &[(Register::IdAa64Isar1El1, u64::MAX)]).unwrap();
        assert_eq!(snapshot.read(Register::IdAa64Isar1El1), Ok(u64::MAX));
        assert_eq!(
            snapshot.read(Register::IdAa64Isar2El1),
            Err(Unsupported::MissingRegister(Register::IdAa64Isar2El1))
        );
        assert_eq!(snapshot.read(Register::IdAa64Isar1El1).ok(), Some(u64::MAX));
        assert_eq!(snapshot.read(Register::IdAa64Isar2El1).ok(), None);
        assert_eq!(snapshot.provenance().origin(), Origin::DeclaredGuest);
    }

    #[test]
    fn duplicate_dynamic_and_ambiguous_machine_identity_initialization_rejects() {
        assert!(matches!(
            Snapshot::declared(
                IDENTITY,
                &[(Register::IdAa64Pfr0El1, 0), (Register::IdAa64Pfr0El1, 1)]
            ),
            Err(InitializationError::DuplicateRegister(_))
        ));
        assert!(matches!(
            Snapshot::declared(IDENTITY, &[(Register::CsselrEl1, 0)]),
            Err(InitializationError::UnownedRegister(Register::CsselrEl1))
        ));
        assert!(matches!(
            Snapshot::declared("", &[]),
            Err(InitializationError::EmptyIdentity)
        ));
        assert!(matches!(
            Snapshot::declared("ambiguous\0machine", &[]),
            Err(InitializationError::EmbeddedIdentityNul)
        ));
    }

    #[test]
    fn declaration_digest_binds_named_values_and_identity_without_order_dependence() {
        let forward = entries();
        let mut reverse = forward.clone();
        reverse.reverse();
        let first = Snapshot::declared(IDENTITY, &forward).unwrap();
        let same_values = Snapshot::declared(IDENTITY, &reverse).unwrap();
        assert_eq!(
            first.provenance().input_sha256(),
            same_values.provenance().input_sha256()
        );
        assert!(!first.same_snapshot(&same_values));
        assert!(first.same_snapshot(&first));
        let other_machine = Snapshot::declared("another-declared-machine", &forward).unwrap();
        assert_ne!(
            first.provenance().input_sha256(),
            other_machine.provenance().input_sha256()
        );
        let mut changed = forward;
        replace(&mut changed, Register::IdAa64Isar2El1, 1);
        let changed = Snapshot::declared(IDENTITY, &changed).unwrap();
        assert_ne!(
            first.provenance().input_sha256(),
            changed.provenance().input_sha256()
        );
    }

    #[test]
    fn retained_arc_input_accounts_for_tail_padding() {
        let capture = |bytes| {
            Snapshot::captured(
                "snapshot-arc-padding-fixture",
                alloc::vec![0x5a; bytes].into(),
                &[(Register::IdAa64Isar1El1, 0)],
            )
            .unwrap()
        };
        // Arc's counters require the allocation to remain word-aligned even
        // when the byte slice ends earlier. These pairs share allocation size.
        let word = core::mem::size_of::<usize>();
        let first = capture(2 * word - 1);
        let aligned = capture(2 * word);
        let next = capture(2 * word + 1);
        let next_aligned = capture(3 * word);
        assert_eq!(first.retained_bytes(), aligned.retained_bytes());
        assert_eq!(next.retained_bytes(), next_aligned.retained_bytes());
        assert_eq!(next.retained_bytes() - first.retained_bytes(), word);
    }

    #[test]
    fn retained_snapshot_accounting_includes_arc_payload_and_all_allocation_capacities() {
        let input: Arc<[u8]> = alloc::vec![0x5a; 256].into();
        let snapshot = Snapshot::captured(
            "snapshot-retained-accounting-fixture",
            Arc::clone(&input),
            &[(Register::IdAa64Isar1El1, 0)],
        )
        .unwrap();
        let expected = core::mem::size_of::<Snapshot>()
            + 4 * core::mem::size_of::<usize>()
            + input.len()
            + snapshot.provenance.input_sha256.capacity()
            + snapshot.provenance.captured_fields.capacity()
                * core::mem::size_of::<(Register, usize)>();
        assert_eq!(snapshot.retained_bytes(), expected);
        assert!(snapshot.retained_bytes() > input.len());
    }

    #[test]
    fn captured_readbacks_are_extracted_from_and_retain_actual_immutable_input() {
        let mut bytes = Vec::new();
        bytes.extend(0x0123_4567_89ab_cdef_u64.to_le_bytes());
        bytes.extend(u64::MAX.to_le_bytes());
        let input: Arc<[u8]> = bytes.into();
        let fields = [
            (Register::IdAa64Isar1El1, 0),
            (Register::IdAa64Isar2El1, REGISTER_VALUE_BYTES),
        ];
        let snapshot = Snapshot::captured(
            "verified-acquisition-fixture-not-hardware-proof",
            Arc::clone(&input),
            &fields,
        )
        .unwrap();
        assert_eq!(
            snapshot.read(Register::IdAa64Isar1El1),
            Ok(0x0123_4567_89ab_cdef)
        );
        assert_eq!(snapshot.read(Register::IdAa64Isar2El1), Ok(u64::MAX));
        assert_eq!(snapshot.provenance().origin(), Origin::CapturedHardware);
        assert_eq!(snapshot.provenance().input(), input.as_ref());
        assert_eq!(
            snapshot.provenance().input_sha256(),
            stela_formats::sha256(&input)
        );
        assert_eq!(snapshot.provenance().captured_fields(), fields);
        assert!(Arc::ptr_eq(&input, &snapshot.provenance.input));
        assert!(matches!(
            Snapshot::captured(
                "fixture",
                Arc::clone(&input),
                &[(Register::IdAa64Isar1El1, usize::MAX)]
            ),
            Err(InitializationError::CaptureBounds { .. })
        ));
        assert!(matches!(
            Snapshot::captured(
                "fixture",
                input,
                &[
                    (Register::IdAa64Isar1El1, 0),
                    (Register::IdAa64Isar1El1, REGISTER_VALUE_BYTES)
                ]
            ),
            Err(InitializationError::DuplicateRegister(_))
        ));
    }

    #[test]
    fn entry_spe_and_regime_qualifiers_consume_the_same_explicit_named_readbacks() {
        let snapshot = Snapshot::declared(IDENTITY, &entries()).unwrap();
        let expected = EntryProfile::base(
            SystemEntryFeatures::declared_absent(),
            ScalableEntryAbsence::from_id_registers(A64_EL0_EL1_NO_HIGHER_EL, 0).unwrap(),
        )
        .unwrap();
        assert_eq!(snapshot.entry_profile(), Ok(expected));
        assert_eq!(snapshot.check_entry_profile(expected), Ok(()));
        assert!(snapshot.base_spe_absence().is_ok());
        assert_eq!(snapshot.check_base_el10_4k(), Ok(()));
        for missing in [
            Register::IdAa64Isar2El1,
            Register::IdAa64Pfr0El1,
            Register::IdAa64Dfr0El1,
        ] {
            let mut partial = entries();
            partial.retain(|(register, _)| *register != missing);
            assert_eq!(
                Snapshot::declared(IDENTITY, &partial)
                    .unwrap()
                    .entry_profile(),
                Err(Unsupported::MissingRegister(missing))
            );
        }
    }

    #[test]
    fn invalid_higher_el_granule_d128_and_spe_facts_never_mint_absence() {
        for (register, shift) in [
            (Register::IdAa64Pfr0El1, 8),
            (Register::IdAa64Pfr0El1, 12),
            (Register::IdAa64Mmfr0El1, 28),
            (Register::IdAa64Mmfr3El1, 32),
        ] {
            for value in 1..=FIELD_MAX {
                let mut raw = entries();
                let prior = raw
                    .iter()
                    .find(|(candidate, _)| *candidate == register)
                    .unwrap()
                    .1;
                replace(
                    &mut raw,
                    register,
                    (prior & !(FIELD_MAX << shift)) | (value << shift),
                );
                assert!(
                    Snapshot::declared(IDENTITY, &raw)
                        .unwrap()
                        .check_base_el10_4k()
                        .is_err()
                );
            }
        }
        for value in 1..=FIELD_MAX {
            let mut raw = entries();
            replace(&mut raw, Register::IdAa64Dfr0El1, value << 32);
            let snapshot = Snapshot::declared(IDENTITY, &raw).unwrap();
            assert!(snapshot.base_spe_absence().is_err());
            assert!(snapshot.entry_profile().is_err());
        }
        let mut raw = entries();
        replace(&mut raw, Register::IdAa64Pfr0El1, 0);
        assert!(
            Snapshot::declared(IDENTITY, &raw)
                .unwrap()
                .entry_profile()
                .is_err()
        );
    }

    #[test]
    fn doublefault_sve_sme_and_pauth_lr_are_not_inferred_from_unrelated_absences() {
        for (register, shift, value) in [
            (Register::IdAa64Pfr0El1, 28, 2),
            (Register::IdAa64Pfr0El1, 32, 1),
            (Register::IdAa64Pfr1El1, 24, 1),
            (Register::IdAa64Isar1El1, APA_SHIFT, 6),
            (Register::IdAa64Isar1El1, API_SHIFT, 1),
            (Register::IdAa64Isar2El1, APA3_SHIFT, 1),
        ] {
            let mut raw = entries();
            let prior = raw
                .iter()
                .find(|(candidate, _)| *candidate == register)
                .unwrap()
                .1;
            replace(
                &mut raw,
                register,
                (prior & !(FIELD_MAX << shift)) | (value << shift),
            );
            assert!(
                Snapshot::declared(IDENTITY, &raw)
                    .unwrap()
                    .entry_profile()
                    .is_err()
            );
        }
    }

    #[test]
    fn opaque_unrelated_fields_are_preserved_and_invalid_mte_fraction_not_interpreted() {
        let mut raw = entries();
        // Under primary MTE=0, MTE_frac/MTEX are invalid and not absence indicators.
        let opaque = (FIELD_MAX << 40) | (FIELD_MAX << 52);
        replace(&mut raw, Register::IdAa64Pfr1El1, opaque);
        let snapshot = Snapshot::declared(IDENTITY, &raw).unwrap();
        assert_eq!(snapshot.read(Register::IdAa64Pfr1El1), Ok(opaque));
        assert!(snapshot.entry_profile().is_ok());
    }

    #[test]
    fn pfar_absence_requires_a_named_readback_and_rejects_present_or_reserved_values() {
        let mut raw = entries();
        raw.retain(|(register, _)| *register != Register::IdAa64Pfr1El1);
        let missing = Snapshot::declared(IDENTITY, &raw).unwrap();
        assert_eq!(
            missing.entry_profile(),
            Err(Unsupported::MissingRegister(Register::IdAa64Pfr1El1))
        );
        assert_eq!(missing.read(Register::IdAa64Pfr1El1).ok(), None);

        let absent = Snapshot::declared(IDENTITY, &entries()).unwrap();
        let profile = absent.entry_profile().unwrap();
        assert_eq!(absent.check_entry_profile(profile), Ok(()));
        for value in 1..=FIELD_MAX {
            let mut raw = entries();
            let pfr1 = value << PFAR_SHIFT;
            replace(&mut raw, Register::IdAa64Pfr1El1, pfr1);
            let snapshot = Snapshot::declared(IDENTITY, &raw).unwrap();
            assert_eq!(snapshot.read(Register::IdAa64Pfr1El1), Ok(pfr1));
            assert_eq!(snapshot.read(Register::IdAa64Pfr1El1).ok(), Some(pfr1));
            let expected = Err(Unsupported::Field {
                register: Register::IdAa64Pfr1El1,
                field: "PFAR",
                value: value as u8,
            });
            assert_eq!(snapshot.entry_profile(), expected);
            assert_eq!(snapshot.check_entry_profile(profile), expected.map(|_| ()));
        }
    }

    #[test]
    fn classic_qarma5_tuple_preserves_the_bounded_entry_absence_contract() {
        const APA_QARMA5_CLASSIC: u64 = 1;
        let mut raw = entries();
        replace(
            &mut raw,
            Register::IdAa64Isar1El1,
            APA_QARMA5_CLASSIC << APA_SHIFT,
        );
        let classic = Snapshot::declared(IDENTITY, &raw).unwrap();
        assert_eq!(
            classic.entry_profile(),
            Snapshot::declared(IDENTITY, &entries())
                .unwrap()
                .entry_profile()
        );
        for (register, shift) in [
            (Register::IdAa64Isar1El1, API_SHIFT),
            (Register::IdAa64Isar2El1, APA3_SHIFT),
        ] {
            let mut invalid = raw.clone();
            let value = invalid
                .iter()
                .find(|(candidate, _)| *candidate == register)
                .unwrap()
                .1
                | (1 << shift);
            replace(&mut invalid, register, value);
            assert!(
                Snapshot::declared(IDENTITY, &invalid)
                    .unwrap()
                    .entry_profile()
                    .is_err()
            );
        }
    }
}
