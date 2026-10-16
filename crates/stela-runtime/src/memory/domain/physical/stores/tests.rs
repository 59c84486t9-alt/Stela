//! Directed authored inputs/model for the canonical retained software engine.
//! Genuine fresh RAM and data only: no loan, executor or original oracle claim.
use crate::memory::{
    domain::m0_write::{M0WriteMembers, M0WriteSource},
    source_ram::{
        MaterializedSourceRam, OwnedRamExtent, PhysicalRamRange, SourceRamBuildError,
        SourceRamDeclaration, SourceRamPermissions, SourceRamSystemConfig, SourceRamTestAlias,
        ZeroedRamExtent, materialize_source_ram_with_zeroed_test_aliases,
    },
};
use stela_compiler::{GuestAddress, GuestState, Lifter, TargetCpu, aarch64::Decoder};
pub(crate) const SOURCE_PC: GuestAddress = GuestAddress(0x0010_0000);
pub(crate) const DATA_PA: u64 = 0x0020_0000;
pub(crate) const ALIAS_PA: u64 = 0x0030_0000;
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
    pub(crate) same_value: bool,
    pub(crate) alias: bool,
}
pub(crate) fn cases() -> [StoreCase; 11] {
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
        StoreCase {
            same_value: true,
            alias: true,
            ..StoreCase::new("same_value_alias16", S::PairOffset, O::Complete, 16)
        },
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
            same_value: false,
            alias: false,
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
        state.x[FIRST_DATA] = if self.same_value { 0 } else { FIRST_VALUE };
        state.x[SECOND_DATA] = if self.same_value { 0 } else { SECOND_VALUE };
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
    /// Compare only an observation returned by the actual retained session.
    /// First prepare refusals are unattempted; second-member refusal retains first8.
    pub(crate) fn assert_progress(self, progress: super::M0RamWriteProgress) {
        use crate::memory::domain::m0_write::M0WriteMember;
        let attempted = self.outcome == StoreOutcome::Complete || self.completed_bytes != 0;
        assert_eq!(progress.attempted, attempted, "{}", self.name);
        assert_eq!(
            progress.completed_bytes, self.completed_bytes,
            "{}",
            self.name
        );
        assert_eq!(progress.uncertain_member, None, "{}", self.name);
        let last = if !attempted {
            None
        } else if self.completed_bytes == 16 {
            Some(M0WriteMember::Second)
        } else {
            Some(M0WriteMember::First)
        };
        assert_eq!(progress.publication_attempted, last, "{}", self.name);
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
        let aliases = if self.alias {
            vec![SourceRamTestAlias {
                source_pa: ALIAS_PA,
                initialized_source_pa: DATA_PA,
                source_offset: 0,
                bytes: WORD_BYTES,
                permissions: permissions(true, false),
            }]
        } else {
            Vec::new()
        };
        materialize_source_ram_with_zeroed_test_aliases(
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
            &aliases,
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
        let writeback = descriptor.writeback(&case.before());
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
            expected.x[usize::from(base)] = value;
        }
        assert_eq!(case.expected_state(), expected);
        assert_eq!(case.before().sp, SP_EL1);
        assert_eq!(PSTATE_LOW32 & 0xf000_0000, case.before().nzcv as u64);
        assert_ne!(SP_EL0, SP_EL1);
    }
}
#[test]
fn directed_fixture_uses_real_backings_holes_permissions_and_alias_identity() {
    use crate::memory::{
        backing::AccessKind, domain::physical::PhysicalAddressSpace, stage1::PhysicalMemory,
    };
    use std::sync::Arc;
    for case in cases() {
        let ram = case.materialize(173).unwrap();
        let data = ram.test_view(DATA_PA).unwrap();
        if case.alias {
            let alias = ram.test_view(ALIAS_PA).unwrap();
            assert!(Arc::ptr_eq(data.backing(), alias.backing()));
            assert_eq!(data.backing_offset(), alias.backing_offset());
        }
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

/// Monitor-only test observation on the actual machine's first RAM word/alias.
/// The canonical session supplies its ORIGINAL outer and keeps it through this
/// witness. This creates no replacement execution loan, CPU or write permit.
pub(crate) struct AliasReservationWitness<'loan> {
    physical: &'loan super::super::PhysicalAddressSpace,
    original: &'loan crate::memory::domain::MemoryExecutionLoan,
    data: super::super::PhysicalRamReadPin<'loan>,
    alias: super::super::PhysicalRamReadPin<'loan>,
    access: crate::memory::monitor::Access<
        crate::memory::backing::MemoryBacking,
        crate::memory::backing::MemoryView,
        crate::memory::domain::MappingAttributes,
    >,
    thread: crate::memory::monitor::ThreadMonitor<
        crate::memory::backing::MemoryBacking,
        crate::memory::backing::MemoryView,
        crate::memory::domain::MappingAttributes,
    >,
}
impl<'loan> AliasReservationWitness<'loan> {
    pub(crate) fn reserve(
        physical: &'loan super::super::PhysicalAddressSpace,
        original: &'loan crate::memory::domain::MemoryExecutionLoan,
    ) -> Self {
        use crate::memory::monitor;
        use std::sync::Arc;
        let data = physical.resolve_ram8(original, DATA_PA).unwrap();
        let alias = physical.resolve_ram8(original, ALIAS_PA).unwrap();
        assert!(std::ptr::eq(data.execution, original));
        assert!(std::ptr::eq(alias.execution, original));
        let registered = physical.domain.registered_views();
        let mapping = |pin: &super::super::PhysicalRamReadPin<'_>| {
            registered
                .iter()
                .find(|registered| Arc::ptr_eq(&registered.view, pin.reached.first().view()))
                .unwrap()
        };
        let make_access = |pin: &super::super::PhysicalRamReadPin<'_>| {
            monitor::Access::new(
                Arc::clone(pin.reached.first().view().backing()),
                Arc::clone(&mapping(pin).monitor),
                pin.reached.first().backing_offset() as u64,
                WORD_BYTES as u8,
                monitor::Shape::Scalar,
            )
            .unwrap()
        };
        assert!(Arc::ptr_eq(
            data.reached.first().view().backing(),
            alias.reached.first().view().backing()
        ));
        assert_eq!(
            data.reached.first().backing_offset(),
            alias.reached.first().backing_offset()
        );
        let mut thread = physical.domain.system.reservations.thread();
        let data_access = make_access(&data);
        let access = make_access(&alias);
        let read = physical
            .domain
            .system
            .reservations
            .load(&mut thread, &data_access, || {
                data.check_current().unwrap();
                // SAFETY: actual original same-domain outer/current pin, aligned8
                // exact footprint and the original monitor load gate retain rights
                // and source storage; no Rust reference aliases shared RAM.
                unsafe {
                    crate::memory::access::read_part(
                        data.pointer(),
                        WORD_BYTES,
                        TargetCpu::Baseline,
                    )
                }
            })
            .unwrap();
        assert_eq!(read, 0);
        Self {
            physical,
            original,
            data,
            alias,
            access,
            thread,
        }
    }

    /// Call after the actual retained store, before its original outer releases.
    /// This monitor diagnostic never writes bytes or claims a guest STXR result.
    pub(crate) fn assert_invalidated(&mut self) {
        use crate::memory::monitor::ConditionalWrite;
        self.physical.check_execution_loan(self.original).unwrap();
        self.data.check_current().unwrap();
        self.alias.check_current().unwrap();
        let result = self
            .physical
            .domain
            .system
            .reservations
            .store(&mut self.thread, &self.access, || Ok::<(), ()>(()))
            .unwrap();
        assert_eq!(result, ConditionalWrite::Failed);
    }
}
