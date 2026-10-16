//! Consolidated authored inputs for the actual retained pair-read consumer.
//! Models/materialized original RAM grant no source/control loan or execution.

use crate::memory::domain::m0_read::pair::M0ReadPairSource;
use crate::memory::source_ram::{
    MaterializedSourceRam, OwnedRamExtent, PhysicalRamRange, SourceRamBuildError,
    SourceRamDeclaration, SourceRamPermissions, SourceRamSystemConfig, SourceRamTestAlias,
    materialize_source_ram_with_test_aliases,
};
use stela_compiler::{
    GuestAddress, GuestState, Lifter, TargetCpu,
    aarch64::{AddressMode, Decoder, MemoryTransfer, Operation, Register, Width},
};

pub(crate) const SOURCE_PC: GuestAddress = GuestAddress(0x0010_0000);
pub(crate) const DATA_PA: u64 = 0x0020_0000;
pub(crate) const ALIAS_PA: u64 = 0x0030_0000;
pub(crate) const SP_EL0: u64 = 0x002e_0000;
pub(crate) const SP_EL1: u64 = 0x002f_0000;
pub(crate) const PSTATE_LOW32: u64 =
    0xa000_0000 | crate::system::state::PSTATE_EL1H | crate::system::pstate::DAIF_MASK;
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
    pub(crate) alias: bool,
    pub(crate) first_is_base: bool,
}

pub(crate) fn cases() -> [ReadCase; 13] {
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
            alias: true,
            ..ReadCase::new("same_backing_alias16", S::Offset, O::Complete, 16)
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
            alias: false,
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
            _ if self.alias => ALIAS_PA,
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
                state.x[BASE] = state.x[BASE].wrapping_add_signed(i64::from(self.displacement()));
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

    /// Same input bytes after success or refusal: these are reads, including ZR.
    pub(crate) fn expected_ram(self) -> Vec<u8> {
        let mut bytes = FIRST_VALUE.to_le_bytes().to_vec();
        if !matches!(
            self.outcome,
            ReadOutcome::Refused {
                member: 1,
                reason: ReadRefusal::Hole
            }
        ) {
            bytes.extend_from_slice(&SECOND_VALUE.to_le_bytes());
        }
        bytes
    }

    pub(crate) fn assert_progress(self, progress: super::M0RamPairReadProgress) {
        use super::M0ReadMember;
        assert_eq!(
            progress.completed_bytes, self.completed_bytes,
            "{}",
            self.name
        );
        assert_eq!(
            progress.attempted,
            self.completed_bytes != 0,
            "{}",
            self.name
        );
        assert_eq!(progress.uncertain_member, None, "{}", self.name);
        assert_eq!(
            progress.read_attempted,
            match self.completed_bytes {
                0 => None,
                8 => Some(M0ReadMember::First),
                16 => Some(M0ReadMember::Second),
                _ => panic!("fixture prefix"),
            },
            "{}",
            self.name
        );
    }

    pub(crate) fn materialize(
        self,
        address_space: u64,
    ) -> Result<MaterializedSourceRam, SourceRamBuildError> {
        let permissions = |readable, executable| SourceRamPermissions {
            readable,
            writable: false,
            executable,
        };
        let mut initialized = vec![OwnedRamExtent {
            source_pa: SOURCE_PC.0,
            bytes: self.source().to_vec(),
            permissions: permissions(true, true),
        }];
        let data = self.expected_ram();
        if let ReadOutcome::Refused {
            member,
            reason: ReadRefusal::ExecuteOnly,
        } = self.outcome
        {
            for (index, bytes) in data.as_chunks::<MEMBER_BYTES>().0.iter().enumerate() {
                let denied = index == usize::from(member);
                initialized.push(OwnedRamExtent {
                    source_pa: DATA_PA + (index * MEMBER_BYTES) as u64,
                    bytes: bytes.to_vec(),
                    permissions: permissions(!denied, denied),
                });
            }
        } else {
            initialized.push(OwnedRamExtent {
                source_pa: DATA_PA,
                bytes: data,
                permissions: permissions(true, false),
            });
        }
        let aliases = if self.alias {
            vec![SourceRamTestAlias {
                source_pa: ALIAS_PA,
                initialized_source_pa: DATA_PA,
                source_offset: 0,
                bytes: 2 * MEMBER_BYTES,
                permissions: permissions(true, false),
            }]
        } else {
            Vec::new()
        };
        materialize_source_ram_with_test_aliases(
            SourceRamDeclaration {
                address_space,
                target: TargetCpu::Baseline,
                declared_capacity: vec![PhysicalRamRange {
                    source_pa: 0,
                    bytes: 0x0040_0000,
                }],
                initialized,
            },
            SourceRamSystemConfig {
                reservation_granule_bytes: 16,
                reservation_stripe_count: 8,
            },
            &aliases,
        )
    }
}

#[test]
fn directed_pair_inputs_use_the_common_decoder_and_stage_whole_architectural_success() {
    for case in cases() {
        let bytes = case.source();
        let word = u32::from_le_bytes(bytes[..4].try_into().unwrap());
        let instruction = Decoder.lift(SOURCE_PC, word).unwrap();
        // The authentic source metadata reuses this SAME common decoder. This
        // typed descriptor is descriptive only; no source/control loan is minted.
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
        // Constrained policy may yield NOP or reject the original encoding.
        // Neither case authorizes this pair-read producer to reinterpret it.
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
