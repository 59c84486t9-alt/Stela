//! M0 scalar and STP stores to physical RAM, in exact source widths.

use super::{PhysicalAddressSpace, PhysicalReadPlatformError};
use crate::platform::sync::MutexGuard;
use crate::{
    memory::domain::{
        MemoryExecutionLoan, PhysicalAccess, PublicationFault,
        m0_write::{M0WriteIntent, M0WriteMember},
    },
    system::translation_controls::m0_data::{M0ControlError, M0DataWriteLoan},
};
use alloc::vec::Vec;
use stela_compiler::{TargetCpu, context::memory::MemoryStatus};

/// A copied observation.
#[derive(Debug, Clone, Copy)]
pub(crate) struct M0RamWriteProgress {
    pub(crate) attempted: bool,
    pub(crate) completed_bytes: u64,
    pub(crate) publication_attempted: Option<M0WriteMember>,
    pub(crate) uncertain_member: Option<M0WriteMember>,
    pub(crate) modified_instruction_ram: bool,
}
impl M0RamWriteProgress {
    const fn unattempted() -> Self {
        Self {
            attempted: false,
            completed_bytes: 0,
            publication_attempted: None,
            uncertain_member: None,
            modified_instruction_ram: false,
        }
    }
}

pub(crate) enum M0RamWritePlatformError {
    SourceControl {
        error: M0ControlError,
        progress: M0RamWriteProgress,
    },
    Physical {
        error: PhysicalReadPlatformError,
        progress: M0RamWriteProgress,
    },
    DeviceOrdering(MemoryStatus),
    MissingMember {
        member: M0WriteMember,
        progress: M0RamWriteProgress,
    },
    Publication {
        fault: PublicationFault,
        progress: M0RamWriteProgress,
    },
    UnexpectedPublicationPrefix {
        fault: PublicationFault,
        progress: M0RamWriteProgress,
    },
    AlreadyAttempted(M0RamWriteProgress),
}

impl M0RamWritePlatformError {
    /// The write progress, for settlement diagnostics.
    pub(crate) fn progress(&self) -> M0RamWriteProgress {
        match self {
            Self::SourceControl { progress, .. }
            | Self::Physical { progress, .. }
            | Self::MissingMember { progress, .. }
            | Self::Publication { progress, .. }
            | Self::UnexpectedPublicationPrefix { progress, .. }
            | Self::AlreadyAttempted(progress) => *progress,
            // Ordering refusal occurs only in NO-WRITE preparation.
            Self::DeviceOrdering(_) => M0RamWriteProgress::unattempted(),
        }
    }
}

// Show the error and the reached prefix, including errors found during
// preparation.
impl core::fmt::Debug for M0RamWritePlatformError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SourceControl { error, .. } => f
                .debug_struct("SourceControl")
                .field("error", error)
                .field("progress", &self.progress())
                .finish(),
            Self::Physical { error, .. } => f
                .debug_struct("Physical")
                .field("error", error)
                .field("progress", &self.progress())
                .finish(),
            Self::DeviceOrdering(status) => f.debug_tuple("DeviceOrdering").field(status).finish(),
            Self::MissingMember { member, .. } => f
                .debug_struct("MissingMember")
                .field("member", member)
                .field("progress", &self.progress())
                .finish(),
            Self::Publication { fault, .. } => f
                .debug_struct("Publication")
                .field("fault", fault)
                .field("progress", &self.progress())
                .finish(),
            Self::UnexpectedPublicationPrefix { fault, .. } => f
                .debug_struct("UnexpectedPublicationPrefix")
                .field("fault", fault)
                .field("progress", &self.progress())
                .finish(),
            Self::AlreadyAttempted(_) => f
                .debug_tuple("AlreadyAttempted")
                .field(&self.progress())
                .finish(),
        }
    }
}

// Private physical pin; no standalone write capability escapes this module.
struct PhysicalRamWritePin<'loan> {
    physical: &'loan PhysicalAddressSpace,
    execution: &'loan MemoryExecutionLoan,
    reached: PhysicalAccess,
    bytes: usize,
}
impl PhysicalRamWritePin<'_> {
    fn check_current(&self) -> Result<(), PhysicalReadPlatformError> {
        self.physical.check_execution_loan(self.execution)?;
        self.physical.check_reached(&self.reached)
    }

    fn publish(
        &self,
        value: u64,
        receipts: &mut Vec<crate::memory::domain::SourceWriteReceipt>,
    ) -> Result<(), PublicationFault> {
        let first = self.reached.first();
        // SAFETY: the source borrow admitted this write, and the outer object
        // and order guard pin the physical rights and storage. Resolution
        // checked the naturally aligned source-width footprint and host
        // read-modify-write readability, and the staging is private stack
        // memory. Publication performs an exact-width XCHG and invalidates
        // reservations on every alias, even for same-value writes.
        unsafe {
            self.physical.domain.system.publish_tracked(
                first.view().backing(),
                first.backing_offset(),
                &value.to_le_bytes()[..self.bytes],
                Some(receipts),
            )
        }
    }
}

fn resolve_write_pin<'loan>(
    physical: &'loan PhysicalAddressSpace,
    execution: &'loan MemoryExecutionLoan,
    physical_address: u64,
    bytes: u8,
) -> Result<PhysicalRamWritePin<'loan>, PhysicalReadPlatformError> {
    use crate::memory::{access, backing::AccessKind};
    physical.check_execution_loan(execution)?;
    if !cfg!(target_arch = "x86_64") {
        return Err(PhysicalReadPlatformError::UnsupportedHost);
    }
    let bytes = usize::from(bytes);
    if !matches!(bytes, 1 | 2 | 4 | 8)
        || physical_address & (bytes as u64 - 1) != 0
        || physical_address.checked_add(bytes as u64).is_none()
    {
        return Err(PhysicalReadPlatformError::Alignment);
    }
    let reached = physical
        .domain
        .resolve_source_physical(execution, physical_address, bytes, AccessKind::Write)
        .map_err(PhysicalReadPlatformError::Domain)?;
    physical.check_reached(&reached)?;
    if core::iter::once(reached.first())
        .chain(reached._remaining.iter())
        .any(|span| {
            span.view().permissions().executable
                && span.view().backing().instruction_generation().is_none()
        })
    {
        return Err(PhysicalReadPlatformError::Unavailable);
    }
    let first = reached.first();
    let pointer = first.host_ptr().as_ptr();
    if pointer as usize & (bytes - 1) != 0 {
        return Err(PhysicalReadPlatformError::HostAlignment);
    }
    first
        .view()
        .backing()
        .host_pointer(first.backing_offset(), bytes, AccessKind::Read)
        .map_err(|_| PhysicalReadPlatformError::Unavailable)?;
    let (address, footprint) = access::read_footprint(pointer as usize, bytes, TargetCpu::Baseline)
        .map_err(|_| PhysicalReadPlatformError::UnsupportedHost)?;
    if address != pointer as usize || footprint != bytes {
        return Err(PhysicalReadPlatformError::UnsupportedHost);
    }
    Ok(PhysicalRamWritePin {
        physical,
        execution,
        reached,
        bytes,
    })
}

/// Created before any write and held by the failure guard through finalization
/// and the single base and PC settlement. Neither outcome releases its pins.
#[must_use]
pub(crate) struct M0RamWritePrepared<'loan, 'owner> {
    execution: &'loan MemoryExecutionLoan,
    source: &'loan M0DataWriteLoan<'owner>,
    first: PhysicalRamWritePin<'loan>,
    second: Option<PhysicalRamWritePin<'loan>>,
    _order: MutexGuard<'loan, ()>,
    progress: M0RamWriteProgress,
    receipts: Vec<crate::memory::domain::SourceWriteReceipt>,
}

impl M0RamWritePrepared<'_, '_> {
    pub(crate) fn validate_current(&self) -> Result<(), M0RamWritePlatformError> {
        self.source
            .validate_current_with_writes(self.execution, &self.receipts)
            .map_err(|error| M0RamWritePlatformError::SourceControl {
                error,
                progress: self.progress,
            })?;
        self.first
            .check_current()
            .map_err(|error| M0RamWritePlatformError::Physical {
                error,
                progress: self.progress,
            })?;
        if let Some(second) = &self.second {
            second
                .check_current()
                .map_err(|error| M0RamWritePlatformError::Physical {
                    error,
                    progress: self.progress,
                })?;
        }
        Ok(())
    }

    pub(crate) fn progress(&self) -> M0RamWriteProgress {
        self.progress
    }

    pub(crate) fn intent(&self) -> M0WriteIntent {
        self.source.intent()
    }

    fn record_publication(
        &mut self,
        result: Result<(), PublicationFault>,
    ) -> Result<(), M0RamWritePlatformError> {
        self.progress.modified_instruction_ram = !self.receipts.is_empty();
        match result {
            Ok(()) => {
                // Infallible primitive observations immediately follow the
                // The member published at its source width.
                self.progress.completed_bytes += u64::from(self.intent().member_bytes);
                self.progress.uncertain_member = None;
                Ok(())
            }
            Err(fault) => {
                // An aligned scalar is published in one part, so any reported
                // prefix is a terminal diagnostic: never clamped, completed
                // or retried.
                if fault.completed != 0 {
                    return Err(M0RamWritePlatformError::UnexpectedPublicationPrefix {
                        fault,
                        progress: self.progress,
                    });
                }
                Err(M0RamWritePlatformError::Publication {
                    fault,
                    progress: self.progress,
                })
            }
        }
    }

    /// At most one attempt, including pre-write refusal. A pair store is two
    /// ascending 8-byte writes without 16-byte atomicity; the second member is
    /// checked only after the first completes.
    pub(crate) fn attempt(&mut self) -> Result<(), M0RamWritePlatformError> {
        if self.progress.attempted {
            return Err(M0RamWritePlatformError::AlreadyAttempted(self.progress));
        }
        self.progress.attempted = true;
        self.validate_current()?;
        let (_, first) = self.source.intent().member(M0WriteMember::First).ok_or(
            M0RamWritePlatformError::MissingMember {
                member: M0WriteMember::First,
                progress: self.progress,
            },
        )?;
        self.progress.publication_attempted = Some(M0WriteMember::First);
        self.progress.uncertain_member = Some(M0WriteMember::First);
        let result = self.first.publish(first, &mut self.receipts);
        self.record_publication(result)?;
        self.validate_current()?;
        if let Some((_, value)) = self.source.intent().member(M0WriteMember::Second) {
            let translated = self
                .source
                .qualify_member_after_writes(self.execution, M0WriteMember::Second, &self.receipts)
                .map_err(|error| M0RamWritePlatformError::SourceControl {
                    error,
                    progress: self.progress,
                })?;
            let second = resolve_write_pin(
                self.source.physical_space(),
                self.execution,
                translated.physical_address(),
                self.intent().member_bytes,
            )
            .map_err(|error| M0RamWritePlatformError::Physical {
                error,
                progress: self.progress,
            })?;
            self.second = Some(second);
            self.validate_current()?;
            self.progress.publication_attempted = Some(M0WriteMember::Second);
            self.progress.uncertain_member = Some(M0WriteMember::Second);
            let result = self
                .second
                .as_ref()
                .expect("resolved reached second member")
                .publish(value, &mut self.receipts);
            self.record_publication(result)?;
        }
        // A failure after the effect reports the known prefix of 0, 8 or 16
        // bytes.
        self.validate_current()
    }
}

pub(crate) fn prepare_aligned_device_ram_scalar_or_pair<'loan, 'owner>(
    execution: &'loan MemoryExecutionLoan,
    source: &'loan M0DataWriteLoan<'owner>,
) -> Result<M0RamWritePrepared<'loan, 'owner>, M0RamWritePlatformError> {
    let progress = M0RamWriteProgress::unattempted();
    source
        .validate_current(execution)
        .map_err(|error| M0RamWritePlatformError::SourceControl { error, progress })?;
    let translated = source
        .qualify_member(execution, M0WriteMember::First)
        .map_err(|error| M0RamWritePlatformError::SourceControl { error, progress })?;
    let first = resolve_write_pin(
        source.physical_space(),
        execution,
        translated.physical_address(),
        source.intent().member_bytes,
    )
    .map_err(|error| M0RamWritePlatformError::Physical { error, progress })?;
    let order = execution
        .device_ram_order()
        .map_err(M0RamWritePlatformError::DeviceOrdering)?;
    let prepared = M0RamWritePrepared {
        execution,
        source,
        first,
        second: None,
        _order: order,
        progress,
        receipts: Vec::with_capacity(2),
    };
    prepared.validate_current()?;
    Ok(prepared)
}

#[cfg(all(
    test,
    target_arch = "x86_64",
    any(target_os = "macos", target_os = "linux")
))]
pub(crate) mod tests {
    //! M0 STP stores to fresh RAM.
    use crate::memory::{
        domain::m0_write::{M0WriteMembers, M0WriteSource},
        source_ram::{
            MaterializedSourceRam, OwnedRamExtent, PhysicalRamRange, SourceRamBuildError,
            SourceRamDeclaration, SourceRamPermissions, SourceRamSystemConfig, ZeroedRamExtent,
            materialize_source_ram_with_zeroed,
        },
    };
    use stela_compiler::{GuestAddress, GuestState, Lifter, TargetCpu, aarch64::Decoder};
    pub(crate) const SOURCE_PC: GuestAddress = GuestAddress(0x0010_0000);
    pub(crate) const DATA_PA: u64 = 0x0020_0000;
    pub(crate) const DATA_BYTES: usize = 32;
    pub(crate) const SP_EL0: u64 = 0x002e_0000;
    pub(crate) const SP_EL1: u64 = 0x002f_0000;
    pub(crate) const PSTATE_LOW32: u64 =
        0xa000_0000 | crate::system::state::PSTATE_EL1H | crate::system::pstate::DAIF_MASK;
    const WORD_BYTES: usize = size_of::<u64>();
    const BASE: usize = 20;
    const FIRST_DATA: usize = 2;
    const SECOND_DATA: usize = 3;
    const REGISTER_BASE_SHIFT: u32 = 5;
    const PAIR_SECOND_SHIFT: u32 = 10;
    const PAIR_IMMEDIATE_SHIFT: u32 = 15;
    const PRE_POST_WORD_DISPLACEMENT: u32 = 2;
    const A64_STR_X_UNSIGNED_OFFSET: u32 = 0xf900_0000;
    const A64_STP_X_OFFSET: u32 = 0xa900_0000;
    const A64_STP_X_PREINDEX: u32 = 0xa980_0000;
    const A64_STP_X_POSTINDEX: u32 = 0xa880_0000;
    const A64_NOP: u32 = 0xd503_201f;
    const FIRST_VALUE: u64 = 0x1020_3040_5060_7080;
    const SECOND_VALUE: u64 = 0x91a2_b3c4_d5e6_f708;
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum StoreShape {
        Scalar,
        PairOffset,
        PairPreIndex,
        PairPostIndex,
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum ReachedRefusal {
        ReadOnly,
        Hole,
        Alignment,
        ImmutableCode,
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum StoreOutcome {
        Complete,
        Refused { member: u8, reason: ReachedRefusal },
    }
    #[derive(Debug, Clone, Copy)]
    pub(crate) struct StoreCase {
        pub(crate) name: &'static str,
        pub(crate) shape: StoreShape,
        pub(crate) outcome: StoreOutcome,
        pub(crate) completed_bytes: u64,
    }
    pub(crate) fn cases() -> [StoreCase; 10] {
        use ReachedRefusal as R;
        use StoreOutcome as O;
        use StoreShape as S;
        [
            StoreCase::new("scalar8", S::Scalar, O::Complete, 8),
            StoreCase::new("pair16", S::PairOffset, O::Complete, 16),
            StoreCase::new("pair_preindex16", S::PairPreIndex, O::Complete, 16),
            StoreCase::new("pair_postindex16", S::PairPostIndex, O::Complete, 16),
            StoreCase::new(
                "first_readonly0",
                S::PairPreIndex,
                O::Refused {
                    member: 0,
                    reason: R::ReadOnly,
                },
                0,
            ),
            StoreCase::new(
                "first_hole0",
                S::PairPostIndex,
                O::Refused {
                    member: 0,
                    reason: R::Hole,
                },
                0,
            ),
            StoreCase::new(
                "second_readonly8",
                S::PairPreIndex,
                O::Refused {
                    member: 1,
                    reason: R::ReadOnly,
                },
                8,
            ),
            StoreCase::new(
                "second_hole8",
                S::PairPostIndex,
                O::Refused {
                    member: 1,
                    reason: R::Hole,
                },
                8,
            ),
            StoreCase::new(
                "unaligned0",
                S::PairOffset,
                O::Refused {
                    member: 0,
                    reason: R::Alignment,
                },
                0,
            ),
            StoreCase::new(
                "immutable_code0",
                S::Scalar,
                O::Refused {
                    member: 0,
                    reason: R::ImmutableCode,
                },
                0,
            ),
        ]
    }
    impl StoreCase {
        const fn new(
            name: &'static str,
            shape: StoreShape,
            outcome: StoreOutcome,
            completed_bytes: u64,
        ) -> Self {
            Self {
                name,
                shape,
                outcome,
                completed_bytes,
            }
        }
        pub(crate) fn source(self) -> [u8; 8] {
            let base = (BASE as u32) << REGISTER_BASE_SHIFT;
            let first = FIRST_DATA as u32;
            let pair = ((SECOND_DATA as u32) << PAIR_SECOND_SHIFT) | base | first;
            let displacement = PRE_POST_WORD_DISPLACEMENT << PAIR_IMMEDIATE_SHIFT;
            let word = match self.shape {
                StoreShape::Scalar => A64_STR_X_UNSIGNED_OFFSET | base | first,
                StoreShape::PairOffset => A64_STP_X_OFFSET | pair,
                StoreShape::PairPreIndex => A64_STP_X_PREINDEX | displacement | pair,
                StoreShape::PairPostIndex => A64_STP_X_POSTINDEX | displacement | pair,
            };
            let mut bytes = [0; 8];
            bytes[..4].copy_from_slice(&word.to_le_bytes());
            bytes[4..].copy_from_slice(&A64_NOP.to_le_bytes());
            bytes
        }
        pub(crate) fn before(self) -> GuestState {
            let mut state = GuestState {
                sp: SP_EL1,
                nzcv: 0xa000_0000,
                reserved: 0xdec0_de00,
                ..GuestState::default()
            };
            for (index, value) in state.x.iter_mut().enumerate() {
                *value = 0x1111_0000_0000_0000 | index as u64;
            }
            for (index, value) in state.v.iter_mut().enumerate() {
                *value = [
                    0x2222_0000_0000_0000 | index as u64,
                    0x3333_0000_0000_0000 | index as u64,
                ];
            }
            let target = match self.outcome {
                StoreOutcome::Refused {
                    reason: ReachedRefusal::Hole,
                    member: 0,
                } => DATA_PA - WORD_BYTES as u64,
                StoreOutcome::Refused {
                    reason: ReachedRefusal::Alignment,
                    ..
                } => DATA_PA + 1,
                StoreOutcome::Refused {
                    reason: ReachedRefusal::ImmutableCode,
                    ..
                } => SOURCE_PC.0,
                _ => DATA_PA,
            };
            state.x[BASE] = if self.shape == StoreShape::PairPreIndex {
                target - 16
            } else {
                target
            };
            state.x[FIRST_DATA] = FIRST_VALUE;
            state.x[SECOND_DATA] = SECOND_VALUE;
            state
        }
        pub(crate) fn expected_state(self) -> GuestState {
            let mut state = self.before();
            if self.outcome == StoreOutcome::Complete
                && matches!(
                    self.shape,
                    StoreShape::PairPreIndex | StoreShape::PairPostIndex
                )
            {
                state.x[BASE] += 16;
            }
            state
        }
        pub(crate) fn expected_pc(self) -> GuestAddress {
            if self.outcome == StoreOutcome::Complete {
                GuestAddress(SOURCE_PC.0 + 4)
            } else {
                SOURCE_PC
            }
        }
        pub(crate) fn observed_data_bytes(self) -> usize {
            if matches!(
                self.outcome,
                StoreOutcome::Refused {
                    member: 1,
                    reason: ReachedRefusal::Hole
                }
            ) {
                WORD_BYTES
            } else {
                DATA_BYTES
            }
        }
        pub(crate) fn expected_ram(self) -> Vec<u8> {
            let mut bytes = vec![0; self.observed_data_bytes()];
            if self.completed_bytes >= 8 {
                bytes[..WORD_BYTES].copy_from_slice(&self.before().x[FIRST_DATA].to_le_bytes());
            }
            if self.completed_bytes == 16 {
                bytes[WORD_BYTES..2 * WORD_BYTES]
                    .copy_from_slice(&self.before().x[SECOND_DATA].to_le_bytes());
            }
            bytes
        }
        pub(crate) fn materialize(
            self,
            address_space: u64,
        ) -> Result<MaterializedSourceRam, SourceRamBuildError> {
            let permissions = |writable, executable| SourceRamPermissions {
                readable: true,
                writable,
                executable,
            };
            let mut initialized = vec![OwnedRamExtent {
                source_pa: SOURCE_PC.0,
                bytes: self.source().to_vec(),
                permissions: permissions(false, true),
            }];
            let mut zeroed = Vec::new();
            match self.outcome {
                StoreOutcome::Refused {
                    member: 0,
                    reason: ReachedRefusal::ReadOnly,
                } => initialized.push(OwnedRamExtent {
                    source_pa: DATA_PA,
                    bytes: vec![0; DATA_BYTES],
                    permissions: permissions(false, false),
                }),
                StoreOutcome::Refused {
                    member: 1,
                    reason: ReachedRefusal::ReadOnly,
                } => {
                    zeroed.push(ZeroedRamExtent {
                        source_pa: DATA_PA,
                        bytes: WORD_BYTES as u64,
                        permissions: permissions(true, false),
                    });
                    initialized.push(OwnedRamExtent {
                        source_pa: DATA_PA + WORD_BYTES as u64,
                        bytes: vec![0; DATA_BYTES - WORD_BYTES],
                        permissions: permissions(false, false),
                    });
                }
                _ => zeroed.push(ZeroedRamExtent {
                    source_pa: DATA_PA,
                    bytes: self.observed_data_bytes() as u64,
                    permissions: permissions(true, false),
                }),
            }
            materialize_source_ram_with_zeroed(
                SourceRamDeclaration {
                    address_space,
                    target: TargetCpu::Baseline,
                    declared_capacity: vec![PhysicalRamRange {
                        source_pa: 0,
                        bytes: 0x0040_0000,
                    }],
                    initialized,
                },
                zeroed,
                SourceRamSystemConfig {
                    reservation_granule_bytes: 16,
                    reservation_stripe_count: 8,
                },
            )
        }
    }
    #[test]
    fn directed_models_match_actual_canonical_store_source_without_minting_a_loan() {
        for case in cases() {
            let source = case.source();
            let word = u32::from_le_bytes(source[..4].try_into().unwrap());
            let instruction = Decoder.lift(SOURCE_PC, word).unwrap();
            let descriptor = M0WriteSource::from_source(&instruction, word).unwrap();
            let intent = descriptor.intent(&case.before());
            assert_eq!(intent.source_pc, SOURCE_PC, "{}", case.name);
            assert_eq!(intent.source_word, word);
            assert_eq!(intent.next_pc, GuestAddress(SOURCE_PC.0 + 4));
            assert_eq!(
                intent.data,
                [
                    case.before().x[FIRST_DATA],
                    if case.shape == StoreShape::Scalar {
                        0
                    } else {
                        case.before().x[SECOND_DATA]
                    }
                ]
            );
            assert_eq!(
                intent.members == M0WriteMembers::Single,
                case.shape == StoreShape::Scalar
            );
            assert_eq!(
                case.expected_pc(),
                if case.outcome == StoreOutcome::Complete {
                    intent.next_pc
                } else {
                    intent.source_pc
                }
            );
            assert!(case.completed_bytes <= intent.bytes());
            assert_eq!(case.expected_ram().len(), case.observed_data_bytes());
            let writeback = intent.writeback;
            assert_eq!(
                writeback.is_some(),
                matches!(
                    case.shape,
                    StoreShape::PairPreIndex | StoreShape::PairPostIndex
                )
            );
            let mut expected = case.before();
            if case.outcome == StoreOutcome::Complete
                && let Some((base, value)) = writeback
            {
                let stela_compiler::aarch64::Register::X(base) = base else {
                    panic!("pair fixture must write back X base");
                };
                expected.x[usize::from(base)] = value;
            }
            assert_eq!(case.expected_state(), expected);
            assert_eq!(case.before().sp, SP_EL1);
            assert_eq!(PSTATE_LOW32 & 0xf000_0000, case.before().nzcv as u64);
            assert_ne!(SP_EL0, SP_EL1);
        }
    }
    #[test]
    fn directed_fixture_uses_real_backings_holes_and_permissions() {
        use crate::memory::{
            backing::AccessKind, domain::physical::PhysicalAddressSpace, stage1::PhysicalMemory,
        };
        for case in cases() {
            let ram = case.materialize(173).unwrap();
            let data = ram.test_view(DATA_PA).unwrap();
            assert_eq!(
                data.permissions().writable,
                !matches!(
                    case.outcome,
                    StoreOutcome::Refused {
                        member: 0,
                        reason: ReachedRefusal::ReadOnly
                    }
                )
            );
            if matches!(
                case.outcome,
                StoreOutcome::Refused {
                    member: 1,
                    reason: ReachedRefusal::ReadOnly
                }
            ) {
                let second = ram.test_view(DATA_PA + WORD_BYTES as u64).unwrap();
                assert!(!second.permissions().writable);
                assert!(
                    second
                        .resolve(DATA_PA + WORD_BYTES as u64, WORD_BYTES, AccessKind::Write)
                        .is_err()
                );
            }
            let (binding, code) = ram.into_parts();
            assert_eq!(code.len(), 1);
            let physical = PhysicalAddressSpace::from_materialized(binding).unwrap();
            assert_eq!(physical.read_descriptor(DATA_PA).unwrap(), 0);
            assert_eq!(
                physical.read_descriptor(SOURCE_PC.0).unwrap(),
                u64::from_le_bytes(case.source())
            );
            assert!(
                physical
                    .read_descriptor(DATA_PA - WORD_BYTES as u64)
                    .is_err()
            );
            assert!(
                physical
                    .read_descriptor(DATA_PA + case.observed_data_bytes() as u64)
                    .is_err()
            );
        }
    }
}
