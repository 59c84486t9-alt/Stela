//! Aligned two-element Device RAM reads for an M0 PE without FEAT_LSE2.

use crate::platform::sync::MutexGuard;

use super::pair::{M0ReadMember, M0ReadPairIntent};
use crate::{
    memory::domain::{
        MemoryExecutionLoan,
        physical::{PhysicalRamReadPin, PhysicalReadPlatformError},
    },
    system::translation_controls::m0_data::{M0ControlError, M0DataPairReadLoan},
};
use stela_compiler::context::memory::MemoryStatus;

const MEMBER_BYTES: u64 = size_of::<u64>() as u64;
const PAIR_BYTES: u64 = MEMBER_BYTES * 2;
const HOST_ALIGNMENT_MASK: usize = size_of::<u64>() - 1;

/// Read observations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct M0RamPairReadProgress {
    pub(crate) attempted: bool,
    pub(crate) completed_bytes: u64,
    pub(crate) read_attempted: Option<M0ReadMember>,
    pub(crate) uncertain_member: Option<M0ReadMember>,
}

impl M0RamPairReadProgress {
    const fn unattempted() -> Self {
        Self {
            attempted: false,
            completed_bytes: 0,
            read_attempted: None,
            uncertain_member: None,
        }
    }
}

/// Keeps the original errors and the reached prefix. Physical ownership
/// refusals are not reported as Arm external aborts, and translation errors
/// come only from the per-member control check.
pub(crate) enum M0RamPairReadPlatformError {
    SourceControl {
        error: M0ControlError,
        progress: M0RamPairReadProgress,
    },
    Physical {
        error: PhysicalReadPlatformError,
        progress: M0RamPairReadProgress,
    },
    DeviceOrdering(MemoryStatus),
    HostAlignment {
        member: M0ReadMember,
        progress: M0RamPairReadProgress,
    },
    UnsupportedHost,
    AlreadyAttempted(M0RamPairReadProgress),
}

// Format every diagnostic field explicitly.
impl core::fmt::Debug for M0RamPairReadPlatformError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SourceControl { error, progress } => f
                .debug_struct("SourceControl")
                .field("error", error)
                .field("progress", progress)
                .finish(),
            Self::Physical { error, progress } => f
                .debug_struct("Physical")
                .field("error", error)
                .field("progress", progress)
                .finish(),
            Self::DeviceOrdering(status) => f.debug_tuple("DeviceOrdering").field(status).finish(),
            Self::HostAlignment { member, progress } => f
                .debug_struct("HostAlignment")
                .field("member", member)
                .field("progress", progress)
                .finish(),
            Self::UnsupportedHost => f.write_str("UnsupportedHost"),
            Self::AlreadyAttempted(progress) => {
                f.debug_tuple("AlreadyAttempted").field(progress).finish()
            }
        }
    }
}

impl M0RamPairReadPlatformError {
    pub(crate) fn progress(&self) -> M0RamPairReadProgress {
        match self {
            Self::SourceControl { progress, .. }
            | Self::Physical { progress, .. }
            | Self::HostAlignment { progress, .. }
            | Self::AlreadyAttempted(progress) => *progress,
            Self::DeviceOrdering(_) | Self::UnsupportedHost => M0RamPairReadProgress::unattempted(),
        }
    }
}

/// Created before any read. The failure guard must own it before `read` and
/// keep it through finalization and settlement, so a failure or unwind marks
/// the PE failed before these borrows drop. No destination, base, SP, register
/// bank or PC is held or written.
#[must_use]
pub(crate) struct M0RamPairReadPrepared<'loan, 'owner> {
    execution: &'loan MemoryExecutionLoan,
    source: &'loan M0DataPairReadLoan<'owner>,
    first: PhysicalRamReadPin<'loan>,
    second: Option<PhysicalRamReadPin<'loan>>,
    _order: MutexGuard<'loan, ()>,
    progress: M0RamPairReadProgress,
}

impl M0RamPairReadPrepared<'_, '_> {
    pub(crate) fn progress(&self) -> M0RamPairReadProgress {
        self.progress
    }

    pub(crate) fn intent(&self) -> M0ReadPairIntent {
        self.source.intent()
    }

    pub(crate) fn validate_current(&self) -> Result<(), M0RamPairReadPlatformError> {
        self.source
            .validate_current(self.execution)
            .map_err(|error| M0RamPairReadPlatformError::SourceControl {
                error,
                progress: self.progress,
            })?;
        self.first
            .check_current()
            .map_err(|error| M0RamPairReadPlatformError::Physical {
                error,
                progress: self.progress,
            })?;
        if let Some(second) = &self.second {
            second
                .check_current()
                .map_err(|error| M0RamPairReadPlatformError::Physical {
                    error,
                    progress: self.progress,
                })?;
        }
        Ok(())
    }

    /// At most one attempt, including pre-read refusal. The first value remains
    /// private on every second-member failure. Even both completed reads do not
    /// expose values until current source/control/physical checks succeed.
    pub(crate) fn read(&mut self) -> Result<[u64; 2], M0RamPairReadPlatformError> {
        if self.progress.attempted {
            return Err(M0RamPairReadPlatformError::AlreadyAttempted(self.progress));
        }
        self.progress.attempted = true;
        self.validate_current()?;
        let first_pointer = self.first.pointer();
        self.check_alignment(first_pointer, M0ReadMember::First)?;
        #[cfg(target_arch = "x86_64")]
        {
            self.progress.read_attempted = Some(M0ReadMember::First);
            self.progress.uncertain_member = Some(M0ReadMember::First);
            // SAFETY: authentic no-LSE2 source/control qualification and exact
            // same-outer readable RAM pin/order retain this aligned8 quantity.
            // Reuse the scalar backend, with its full coherent-WB-RAM contract.
            let first_value = unsafe { super::ram::read_host_ram8(first_pointer) };
            // Infallible scalar observations immediately follow the real read.
            self.progress.completed_bytes = MEMBER_BYTES;
            self.progress.uncertain_member = None;
            self.validate_current()?;

            // No second target translation or physical resolution precedes the
            // completed first8. Canonical source priority remains in the producer.
            let translation = self
                .source
                .qualify_member(self.execution, M0ReadMember::Second)
                .map_err(|error| M0RamPairReadPlatformError::SourceControl {
                    error,
                    progress: self.progress,
                })?;
            let second = self
                .source
                .physical_space()
                .resolve_ram8(self.execution, translation.physical_address())
                .map_err(|error| M0RamPairReadPlatformError::Physical {
                    error,
                    progress: self.progress,
                })?;
            let second_pointer = second.pointer();
            self.second = Some(second);
            self.validate_current()?;
            // The pin stays held until settlement.
            self.check_alignment(second_pointer, M0ReadMember::Second)?;
            self.progress.read_attempted = Some(M0ReadMember::Second);
            self.progress.uncertain_member = Some(M0ReadMember::Second);
            // SAFETY: the member check, pin and order guard now cover this
            // second aligned 8-byte quantity of coherent host RAM.
            let second_value = unsafe { super::ram::read_host_ram8(second_pointer) };
            self.progress.completed_bytes = PAIR_BYTES;
            self.progress.uncertain_member = None;
            self.validate_current()?;
            Ok([first_value, second_value])
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = first_pointer;
            Err(M0RamPairReadPlatformError::UnsupportedHost)
        }
    }

    fn check_alignment(
        &self,
        pointer: *const u8,
        member: M0ReadMember,
    ) -> Result<(), M0RamPairReadPlatformError> {
        if pointer as usize & HOST_ALIGNMENT_MASK != 0 {
            return Err(M0RamPairReadPlatformError::HostAlignment {
                member,
                progress: self.progress,
            });
        }
        Ok(())
    }
}

/// Check the first member and take the system's order guard without reading.
/// Creating the source borrow must verify the instruction, operands and
/// overlap, source currency, EL1 little-endian M0 state, the absence of
/// FEAT_LSE2 and the physical owner. SP-based forms are refused. Device order
/// uses the coherent RAM profile without side effects: there is no MMIO,
/// watchpoint, speculation or host fault emulation.
pub(crate) fn prepare_aligned_device_ram8_pair<'loan, 'owner>(
    execution: &'loan MemoryExecutionLoan,
    source: &'loan M0DataPairReadLoan<'owner>,
) -> Result<M0RamPairReadPrepared<'loan, 'owner>, M0RamPairReadPlatformError> {
    if !cfg!(target_arch = "x86_64") {
        return Err(M0RamPairReadPlatformError::UnsupportedHost);
    }
    let progress = M0RamPairReadProgress::unattempted();
    source
        .validate_current(execution)
        .map_err(|error| M0RamPairReadPlatformError::SourceControl { error, progress })?;
    let translation = source
        .qualify_member(execution, M0ReadMember::First)
        .map_err(|error| M0RamPairReadPlatformError::SourceControl { error, progress })?;
    let first = source
        .physical_space()
        .resolve_ram8(execution, translation.physical_address())
        .map_err(|error| M0RamPairReadPlatformError::Physical { error, progress })?;
    let order = execution
        .device_ram_order()
        .map_err(M0RamPairReadPlatformError::DeviceOrdering)?;
    let prepared = M0RamPairReadPrepared {
        execution,
        source,
        first,
        second: None,
        _order: order,
        progress,
    };
    prepared.validate_current()?;
    prepared.check_alignment(prepared.first.pointer(), M0ReadMember::First)?;
    Ok(prepared)
}

#[cfg(all(test, target_arch = "x86_64"))]
pub(crate) mod tests {
    //! M0 pair reads.

    use crate::memory::domain::m0_read::pair::M0ReadPairSource;
    use stela_compiler::{
        GuestAddress, GuestState, Lifter,
        aarch64::{AddressMode, Decoder, MemoryTransfer, Operation, Register, Width},
    };

    pub(crate) const SOURCE_PC: GuestAddress = GuestAddress(0x0010_0000);
    pub(crate) const DATA_PA: u64 = 0x0020_0000;
    pub(crate) const SP_EL1: u64 = 0x002f_0000;
    pub(crate) const FIRST_VALUE: u64 = 0x1020_3040_5060_7080;
    pub(crate) const SECOND_VALUE: u64 = 0x91a2_b3c4_d5e6_f708;
    const MEMBER_BYTES: usize = size_of::<u64>();
    const BASE: usize = 20;
    const FIRST_DATA: usize = 2;
    const SECOND_DATA: usize = 3;
    const ZERO_REGISTER: u32 = 31;
    const BASE_SHIFT: u32 = 5;
    const SECOND_SHIFT: u32 = 10;
    const IMMEDIATE_SHIFT: u32 = 15;
    const IMMEDIATE_MASK: u32 = 0x7f;
    const A64_LDP_X_OFFSET: u32 = 0xa940_0000;
    const A64_LDP_X_PREINDEX: u32 = 0xa9c0_0000;
    const A64_LDP_X_POSTINDEX: u32 = 0xa8c0_0000;
    const A64_NOP: u32 = 0xd503_201f;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum ReadShape {
        Offset,
        PreIndex,
        PostIndex,
        NegativeOffset,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum ReadRefusal {
        Hole,
        ExecuteOnly,
        Alignment,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum ReadOutcome {
        Complete,
        Refused { member: u8, reason: ReadRefusal },
    }

    #[derive(Debug, Clone, Copy)]
    pub(crate) struct ReadCase {
        pub(crate) name: &'static str,
        pub(crate) shape: ReadShape,
        pub(crate) outcome: ReadOutcome,
        pub(crate) completed_bytes: u64,
        pub(crate) first_zero: bool,
        pub(crate) second_zero: bool,
        pub(crate) first_is_base: bool,
    }

    pub(crate) fn cases() -> [ReadCase; 12] {
        use ReadOutcome as O;
        use ReadRefusal as R;
        use ReadShape as S;
        [
            ReadCase::new("pair16", S::Offset, O::Complete, 16),
            ReadCase::new("pair_preindex16", S::PreIndex, O::Complete, 16),
            ReadCase::new("pair_postindex16", S::PostIndex, O::Complete, 16),
            ReadCase::new("pair_negative_offset16", S::NegativeOffset, O::Complete, 16),
            ReadCase {
                first_zero: true,
                ..ReadCase::new("first_zr_reads16", S::PostIndex, O::Complete, 16)
            },
            ReadCase {
                second_zero: true,
                ..ReadCase::new("second_zr_reads16", S::PreIndex, O::Complete, 16)
            },
            ReadCase {
                first_is_base: true,
                ..ReadCase::new(
                    "offset_base_destination_alias16",
                    S::Offset,
                    O::Complete,
                    16,
                )
            },
            ReadCase::new(
                "first_hole0",
                S::PostIndex,
                O::Refused {
                    member: 0,
                    reason: R::Hole,
                },
                0,
            ),
            ReadCase::new(
                "second_hole8",
                S::PreIndex,
                O::Refused {
                    member: 1,
                    reason: R::Hole,
                },
                8,
            ),
            ReadCase::new(
                "unaligned0",
                S::Offset,
                O::Refused {
                    member: 0,
                    reason: R::Alignment,
                },
                0,
            ),
            ReadCase::new(
                "first_executeonly0",
                S::PreIndex,
                O::Refused {
                    member: 0,
                    reason: R::ExecuteOnly,
                },
                0,
            ),
            ReadCase::new(
                "second_executeonly8",
                S::PostIndex,
                O::Refused {
                    member: 1,
                    reason: R::ExecuteOnly,
                },
                8,
            ),
        ]
    }

    impl ReadCase {
        const fn new(
            name: &'static str,
            shape: ReadShape,
            outcome: ReadOutcome,
            completed_bytes: u64,
        ) -> Self {
            Self {
                name,
                shape,
                outcome,
                completed_bytes,
                first_zero: false,
                second_zero: false,
                first_is_base: false,
            }
        }

        fn displacement(self) -> i32 {
            match self.shape {
                ReadShape::Offset => 0,
                ReadShape::PreIndex | ReadShape::PostIndex => 16,
                ReadShape::NegativeOffset => -16,
            }
        }

        pub(crate) fn source(self) -> [u8; 8] {
            let opcode = match self.shape {
                ReadShape::Offset | ReadShape::NegativeOffset => A64_LDP_X_OFFSET,
                ReadShape::PreIndex => A64_LDP_X_PREINDEX,
                ReadShape::PostIndex => A64_LDP_X_POSTINDEX,
            };
            let first = if self.first_zero {
                ZERO_REGISTER
            } else if self.first_is_base {
                BASE as u32
            } else {
                FIRST_DATA as u32
            };
            let second = if self.second_zero {
                ZERO_REGISTER
            } else {
                SECOND_DATA as u32
            };
            let immediate = ((self.displacement() / MEMBER_BYTES as i32) as u32) & IMMEDIATE_MASK;
            let word = opcode
                | (immediate << IMMEDIATE_SHIFT)
                | (second << SECOND_SHIFT)
                | ((BASE as u32) << BASE_SHIFT)
                | first;
            let mut source = [0; 8];
            source[..4].copy_from_slice(&word.to_le_bytes());
            source[4..].copy_from_slice(&A64_NOP.to_le_bytes());
            source
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
                ReadOutcome::Refused {
                    member: 0,
                    reason: ReadRefusal::Hole,
                } => DATA_PA - MEMBER_BYTES as u64,
                ReadOutcome::Refused {
                    reason: ReadRefusal::Alignment,
                    ..
                } => DATA_PA + 1,
                _ => DATA_PA,
            };
            state.x[BASE] = if self.shape == ReadShape::PostIndex {
                target
            } else {
                target.wrapping_add_signed(-i64::from(self.displacement()))
            };
            state
        }

        pub(crate) fn expected_state(self) -> GuestState {
            let mut state = self.before();
            if self.outcome == ReadOutcome::Complete {
                if !self.first_zero {
                    state.x[if self.first_is_base { BASE } else { FIRST_DATA }] = FIRST_VALUE;
                }
                if !self.second_zero {
                    state.x[SECOND_DATA] = SECOND_VALUE;
                }
                if matches!(self.shape, ReadShape::PreIndex | ReadShape::PostIndex) {
                    state.x[BASE] =
                        state.x[BASE].wrapping_add_signed(i64::from(self.displacement()));
                }
            }
            state
        }

        pub(crate) fn expected_pc(self) -> GuestAddress {
            if self.outcome == ReadOutcome::Complete {
                GuestAddress(SOURCE_PC.0 + 4)
            } else {
                SOURCE_PC
            }
        }
    }

    #[test]
    fn directed_pair_inputs_use_the_common_decoder_and_stage_whole_architectural_success() {
        for case in cases() {
            let bytes = case.source();
            let word = u32::from_le_bytes(bytes[..4].try_into().unwrap());
            let instruction = Decoder.lift(SOURCE_PC, word).unwrap();
            // The source metadata uses the same decoder.
            let source = M0ReadPairSource::from_source(&instruction, word).unwrap();
            let before = case.before();
            let intent = source.intent(&before);
            assert_eq!(intent.source_pc, SOURCE_PC, "{}", case.name);
            assert_eq!(intent.source_word, word, "{}", case.name);
            assert_eq!(
                intent.next_pc,
                GuestAddress(SOURCE_PC.0 + 4),
                "{}",
                case.name
            );
            assert_eq!(
                intent.raw_address,
                if case.shape == ReadShape::PostIndex {
                    before.x[BASE]
                } else {
                    before.x[BASE].wrapping_add_signed(i64::from(case.displacement()))
                },
                "{}",
                case.name
            );
            assert_eq!(
                intent.flags,
                stela_compiler::context::memory::flags::PAIR
                    | stela_compiler::context::memory::flags::TAG_CHECKED,
                "{}",
                case.name
            );
            assert_eq!(
                source.writeback(&before),
                if matches!(case.shape, ReadShape::PreIndex | ReadShape::PostIndex) {
                    Some((
                        BASE as u8,
                        before.x[BASE].wrapping_add_signed(i64::from(case.displacement())),
                    ))
                } else {
                    None
                },
                "{}",
                case.name
            );
            let expected_data = [
                if case.first_zero {
                    Register::Zero
                } else if case.first_is_base {
                    Register::X(BASE as u8)
                } else {
                    Register::X(FIRST_DATA as u8)
                },
                if case.second_zero {
                    Register::Zero
                } else {
                    Register::X(SECOND_DATA as u8)
                },
            ];
            assert_eq!(
                instruction.operation,
                Operation::MemoryPair {
                    transfer: MemoryTransfer::Load {
                        signed: false,
                        width: Width::X64
                    },
                    bytes: MEMBER_BYTES as u8,
                    data: expected_data,
                    base: Register::X(BASE as u8),
                    displacement: case.displacement(),
                    mode: match case.shape {
                        ReadShape::Offset | ReadShape::NegativeOffset => AddressMode::Offset,
                        ReadShape::PreIndex => AddressMode::PreIndex,
                        ReadShape::PostIndex => AddressMode::PostIndex,
                    },
                },
                "{}",
                case.name
            );
            if case.outcome != ReadOutcome::Complete {
                assert_eq!(case.expected_state(), case.before(), "{}", case.name);
                assert_eq!(case.expected_pc(), SOURCE_PC, "{}", case.name);
            }
            assert_eq!(case.expected_state().sp, SP_EL1);
            assert_eq!(case.expected_state().nzcv, case.before().nzcv);
            assert_eq!(case.expected_state().v, case.before().v);
            assert!(case.completed_bytes <= (2 * MEMBER_BYTES) as u64);
        }
    }

    /// Canonical consumers can use these unchanged source inputs to verify initial
    /// source-profile refusal. They are not requests that bypass source decoding.
    pub(crate) fn rejected_sources() -> [(&'static str, u32); 7] {
        const A64_LDNP_X_OFFSET: u32 = 0xa840_0000;
        const A64_LDP_W_OFFSET: u32 = 0x2940_0000;
        const A64_LDPSW_OFFSET: u32 = 0x6940_0000;
        const A64_LDR_X_UNSIGNED_OFFSET: u32 = 0xf940_0000;
        let data = ((SECOND_DATA as u32) << SECOND_SHIFT) | FIRST_DATA as u32;
        let base = (BASE as u32) << BASE_SHIFT;
        [
            (
                "sp_base_requires_original_sp_fault_owner",
                A64_LDP_X_OFFSET | (ZERO_REGISTER << BASE_SHIFT) | data,
            ),
            (
                "repeated_load_destination",
                A64_LDP_X_OFFSET | base | ((FIRST_DATA as u32) << SECOND_SHIFT) | FIRST_DATA as u32,
            ),
            (
                "postindex_base_destination_overlap",
                A64_LDP_X_POSTINDEX | base | ((SECOND_DATA as u32) << SECOND_SHIFT) | BASE as u32,
            ),
            ("non_temporal_pair", A64_LDNP_X_OFFSET | base | data),
            ("word_pair", A64_LDP_W_OFFSET | base | data),
            ("signed_word_pair", A64_LDPSW_OFFSET | base | data),
            (
                "scalar_load",
                A64_LDR_X_UNSIGNED_OFFSET | base | FIRST_DATA as u32,
            ),
        ]
    }

    #[test]
    fn actual_pair_metadata_declines_outside_source_scope_and_copied_instruction() {
        for (name, word) in rejected_sources() {
            // Constrained policy may give NOP or reject the encoding; neither lets
            // this producer reinterpret it.
            if let Ok(instruction) = Decoder.lift(SOURCE_PC, word) {
                assert!(
                    M0ReadPairSource::from_source(&instruction, word).is_err(),
                    "{name}"
                );
            }
        }
        let bytes = cases()[0].source();
        let word = u32::from_le_bytes(bytes[..4].try_into().unwrap());
        let mut fabricated = Decoder.lift(SOURCE_PC, word).unwrap();
        fabricated.operation = Operation::Nop;
        assert!(M0ReadPairSource::from_source(&fabricated, word).is_err());
        let no_continuation = Decoder.lift(GuestAddress(u64::MAX - 3), word).unwrap();
        assert!(M0ReadPairSource::from_source(&no_continuation, word).is_err());
    }
}
