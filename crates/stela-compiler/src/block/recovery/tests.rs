//! Capture availability, exact retirement and atomic settlement validation.
use super::*;
use crate::{
    GuestState,
    aarch64::{Instruction, Operation},
};
use alloc::vec;

fn before(pc: u64, retired: u16) -> RetirementPoint {
    RetirementPoint::before(GuestAddress(pc), retired).unwrap()
}
fn row(bindings: alloc::vec::Vec<RecoveryBinding>) -> FaultRecovery {
    FaultRecovery {
        site: crate::block::RecoverySite::native_internal(),
        start: 2,
        end: 9,
        bindings,
        retirement: before(0x1000, 4),
    }
}

#[test]
fn spill_bank_has_only_explicitly_recorded_aligned_words() {
    for offset in [1, 7, 9, 127, 128, u16::MAX] {
        assert_eq!(
            SpillOffset::new(offset),
            Err(InvalidSpillOffset { bytes: offset })
        );
    }
    let mut bank = HostSpillSnapshot::new();
    for index in 0..NATIVE_SPILL_WORDS {
        let offset = SpillOffset::new(index as u16 * 8).unwrap();
        assert_eq!(bank.get(offset), None);
        bank.record(offset, 100 + index as u64);
        assert_eq!(bank.get(offset), Some(100 + index as u64));
    }
    bank.clear();
    for index in 0..NATIVE_SPILL_WORDS {
        assert_eq!(bank.get(SpillOffset::new(index as u16 * 8).unwrap()), None);
    }
}

#[test]
fn capture_requests_only_active_spill_locations() {
    let a = SpillOffset::new(16).unwrap();
    let b = SpillOffset::new(24).unwrap();
    let mut second = row(vec![RecoveryBinding::spill(1, b)]);
    second.start = 9;
    second.end = 12;
    let table = [
        row(vec![
            RecoveryBinding::gpr(0, 16),
            RecoveryBinding::spill(1, a),
        ]),
        second,
    ];
    assert_eq!(
        FaultRecovery::required_spills(&table, 1).collect::<alloc::vec::Vec<_>>(),
        []
    );
    assert_eq!(
        FaultRecovery::required_spills(&table, 2).collect::<alloc::vec::Vec<_>>(),
        [a]
    );
    assert_eq!(
        FaultRecovery::required_spills(&table, 9).collect::<alloc::vec::Vec<_>>(),
        [b]
    );
    assert_eq!(
        FaultRecovery::required_spills(&table, 12).collect::<alloc::vec::Vec<_>>(),
        []
    );
}

#[test]
fn missing_spill_refuses_values_and_position_atomically() {
    let offset = SpillOffset::new(16).unwrap();
    let table = [row(vec![
        RecoveryBinding::gpr(0, 16),
        RecoveryBinding::spill(1, offset),
    ])];
    let gprs = HostGprSnapshot::complete([55; 32]);
    let mut spills = HostSpillSnapshot::new();
    let mut state = GuestState {
        x: [0x1234; 31],
        ..GuestState::default()
    };
    let original = state.clone();
    assert_eq!(
        FaultRecovery::apply(
            &table,
            3,
            HostFaultSnapshot {
                gprs: &gprs,
                spills: &spills
            },
            &mut state
        ),
        Err(FaultRecoveryError::NativeSpillUnavailable { offset })
    );
    assert_eq!(state, original);
    spills.record(offset, 77);
    assert_eq!(
        FaultRecovery::apply(
            &table,
            3,
            HostFaultSnapshot {
                gprs: &gprs,
                spills: &spills
            },
            &mut state
        ),
        Ok(Some(RecoverySettlement {
            position: RecoveredPosition {
                pc: GuestAddress(0x1000),
                retired_instructions: 4
            },
            site: RecoverySite::native_internal(),
            phase: RetirementPhase::Before
        }))
    );
    assert_eq!((state.x[0], state.x[1]), (55, 77));
}

#[test]
fn retirement_is_explicit_and_branch_fallthrough_is_refused() {
    let instruction = Instruction {
        pc: GuestAddress(0x1000),
        operation: Operation::Nop,
    };
    let before = before(0x1000, 4);
    let after = RetirementPoint::after_fallthrough(&instruction, 4).unwrap();
    assert_eq!(before.phase(), RetirementPhase::Before);
    assert_eq!(after.phase(), RetirementPhase::AfterFallthrough);
    assert_eq!(
        before.position().unwrap(),
        RecoveredPosition {
            pc: GuestAddress(0x1000),
            retired_instructions: 4
        }
    );
    assert_eq!(
        after.position().unwrap(),
        RecoveredPosition {
            pc: GuestAddress(0x1004),
            retired_instructions: 5
        }
    );
    for operation in [
        Operation::Return,
        Operation::Branch {
            target: GuestAddress(0x2000),
        },
    ] {
        assert_eq!(
            RetirementPoint::after_fallthrough(
                &Instruction {
                    operation,
                    ..instruction.clone()
                },
                4
            ),
            Err(FaultRecoveryError::UnprovenFallthrough { pc: instruction.pc })
        );
    }
    assert!(RetirementPoint::before(GuestAddress(1), 0).is_err());
    assert!(
        RetirementPoint::after_fallthrough(
            &Instruction {
                pc: GuestAddress(u64::MAX - 3),
                ..instruction.clone()
            },
            0
        )
        .is_err()
    );
    assert!(RetirementPoint::after_fallthrough(&instruction, u16::MAX).is_err());
    assert!(
        RetirementPoint::before(instruction.pc, super::super::MAX_BLOCK_INSTRUCTIONS as u16)
            .unwrap()
            .rebased(1)
            .is_err()
    );
}

#[test]
fn overlapping_rows_cannot_partially_settle_disagreeing_guest_values_or_retirement() {
    let first = row(vec![RecoveryBinding::gpr(0, 0)]);
    let mut second = row(vec![RecoveryBinding::gpr(1, 1)]);
    second.retirement = before(0x1004, 5);
    let mut gprs = [55; 32];
    gprs[1] = 66;
    let gprs = HostGprSnapshot::complete(gprs);
    let spills = HostSpillSnapshot::new();
    let capture = HostFaultSnapshot {
        gprs: &gprs,
        spills: &spills,
    };
    let mut state = GuestState::default();
    assert_eq!(
        FaultRecovery::apply(&[first.clone(), second.clone()], 3, capture, &mut state),
        Err(FaultRecoveryError::InconsistentRetirement)
    );
    assert_eq!(state, GuestState::default());
    second.retirement = first.retirement;
    second.bindings = vec![RecoveryBinding::gpr(0, 1)];
    assert_eq!(
        FaultRecovery::apply(&[first, second], 3, capture, &mut state),
        Err(FaultRecoveryError::ConflictingGuestBinding { register: 0 })
    );
    assert_eq!(state, GuestState::default());
}

#[test]
fn relocated_and_persisted_points_keep_their_source_qualification() {
    let instruction = Instruction {
        pc: GuestAddress(0x1000),
        operation: Operation::Nop,
    };
    let point = RetirementPoint::after_fallthrough(&instruction, 3).unwrap();
    let moved = point.relocated(GuestAddress(0x2000)).unwrap();
    assert_eq!(moved.phase(), RetirementPhase::AfterFallthrough);
    assert_eq!(
        moved.position().unwrap(),
        RecoveredPosition {
            pc: GuestAddress(0x2004),
            retired_instructions: 4
        }
    );
    assert!(point.relocated(GuestAddress(0x2001)).is_err());
    assert!(point.relocated(GuestAddress(u64::MAX - 3)).is_err());
    let decoded =
        RetirementPoint::from_instruction(&instruction, point.retired_before(), point.phase())
            .unwrap();
    assert_eq!(decoded, point);
    let branch = Instruction {
        operation: Operation::Return,
        ..instruction
    };
    assert!(
        RetirementPoint::from_instruction(&branch, 3, RetirementPhase::AfterFallthrough).is_err()
    );
    assert_eq!(
        RetirementPoint::from_instruction(&branch, 3, RetirementPhase::Before)
            .unwrap()
            .position()
            .unwrap(),
        RecoveredPosition {
            pc: branch.pc,
            retired_instructions: 3
        }
    );
}

#[test]
fn scalar_load_shape_does_not_admit_writeback_or_store() {
    use crate::aarch64::{AddressMode, MemoryTransfer, Register, Width};
    let load = Instruction {
        pc: GuestAddress(0x2000),
        operation: Operation::Memory {
            transfer: MemoryTransfer::Load {
                signed: true,
                width: Width::X64,
            },
            bytes: 1,
            data: Register::X(1),
            base: Register::X(2),
            displacement: 16,
            mode: AddressMode::Offset,
        },
    };
    let point = RetirementPoint::after_fallthrough(&load, 7).unwrap();
    assert_eq!(
        point.position().unwrap(),
        RecoveredPosition {
            pc: GuestAddress(0x2004),
            retired_instructions: 8,
        }
    );
    assert_eq!(
        RetirementPoint::from_instruction(&load, 7, RetirementPhase::AfterFallthrough,).unwrap(),
        point
    );
    for (transfer, mode) in [
        (MemoryTransfer::Store, AddressMode::Offset),
        (
            MemoryTransfer::Load {
                signed: false,
                width: Width::X64,
            },
            AddressMode::PreIndex,
        ),
        (
            MemoryTransfer::Load {
                signed: false,
                width: Width::X64,
            },
            AddressMode::PostIndex,
        ),
    ] {
        let instruction = Instruction {
            operation: Operation::Memory {
                transfer,
                bytes: 8,
                data: Register::X(1),
                base: Register::X(2),
                displacement: 16,
                mode,
            },
            ..load.clone()
        };
        assert!(
            RetirementPoint::from_instruction(&instruction, 7, RetirementPhase::AfterFallthrough,)
                .is_err()
        );
    }
}

#[test]
fn guest_sites_require_before_and_conflicting_sites_cannot_publish_state() {
    let capture = HostGprSnapshot::legacy([77; 16]);
    let spills = HostSpillSnapshot::new();
    let mut row = row(alloc::vec![RecoveryBinding::gpr(0, 0)]);
    row.site = RecoverySite::guest_access();
    row.retirement = RetirementPoint::after_fallthrough(
        &Instruction {
            pc: GuestAddress(0x1000),
            operation: Operation::Nop,
        },
        4,
    )
    .unwrap();
    let mut state = GuestState::default();
    let original = state.clone();
    assert!(matches!(
        FaultRecovery::apply(
            &[row.clone()],
            3,
            HostFaultSnapshot {
                gprs: &capture,
                spills: &spills
            },
            &mut state
        ),
        Err(FaultRecoveryError::InvalidGuestSitePhase { .. })
    ));
    assert_eq!(state, original);
    row.retirement = before(0x1000, 4);
    let mut second = row.clone();
    second.site = RecoverySite::native_internal();
    assert_eq!(
        FaultRecovery::apply(
            &[row, second],
            3,
            HostFaultSnapshot {
                gprs: &capture,
                spills: &spills
            },
            &mut state
        ),
        Err(FaultRecoveryError::ConflictingRecoverySite)
    );
    assert_eq!(state, original);
    assert_eq!(
        RecoverySiteKind::try_from(4),
        Err(FaultRecoveryError::UnknownRecoverySite { tag: 4 })
    );
}

#[test]
fn absent_recovery_does_not_authorize_guest_fault_projection() {
    assert_eq!(
        FaultRecovery::site_at(&[], 0).unwrap().kind(),
        RecoverySiteKind::NativeInternal
    );
    let mut row = row(alloc::vec![]);
    row.site = RecoverySite::guest_access();
    assert_eq!(
        FaultRecovery::site_at(&[row.clone()], 3).unwrap().kind(),
        RecoverySiteKind::GuestAccess
    );
    assert_eq!(
        FaultRecovery::site_at(&[row], 99).unwrap().kind(),
        RecoverySiteKind::NativeInternal
    );
}
