//! Scalable-code entry with checked memory.
use super::*;
use crate::{
    memory::domain::{MemoryDomain, MemorySystem},
    system::state::{El1Registers, PSTATE_EL0T, PSTATE_IL_MASK},
};
use fixture::*;
use std::sync::Arc;
use stela_compiler::{TargetCpu, aarch64::scalable::ScalableMode, context::memory::MemoryStatus};

mod fixture;
mod retained;

#[test]
fn qualified_entry_owns_source_and_executes_same_snapshot_domain() {
    for (word, bytes, target, ram_base) in [
        (LD1B_Z1_P0_X5, 2, TargetCpu::Baseline, RAM),
        (LD1D_Z1_P0_X5, 8, wide_target(), RAM),
        (LD1B_Z1_P0_X5, 2, TargetCpu::Baseline, 0x800_1400_7400),
    ] {
        let mut f = Fixture::new_program_at(
            &[MOV_X3_SEVEN, word, RET_X30],
            PC,
            ram_base,
            VL,
            target,
            target,
            None,
            1,
            ScalableMode::new(true, true),
        );
        assert!(
            f.ids
                .same_snapshot(f.controls.identification_snapshot().unwrap())
        );
        assert_eq!(f.prepared.source_map()[0].0, GuestAddress(PC));
        assert_eq!(f.prepared.source_map()[1].0, GuestAddress(PC + 4));
        assert!(!f.prepared.identity().native_sha256.is_empty());
        let ram = f.storage.bytes();
        let mut expected = f.registers.clone();
        expected.x[3] = 7;
        let mut expected_scalable = f.scalable.clone();
        let mut output = [0; VL];
        output[..bytes].copy_from_slice(&ram[..bytes]);
        expected_scalable
            .write_z(&mut expected, 1, &output)
            .unwrap();
        assert_eq!(f.execute().unwrap(), ScalableLeafExit::Returned);
        assert_eq!(f.registers, expected);
        assert_eq!(
            banks(&f.registers, &f.scalable),
            banks(&expected, &expected_scalable)
        );
        assert_eq!(f.storage.bytes(), ram);
    }
    // Whole ZA-row and ZT0 transfers use their SME helpers even with SM = 0.
    for (word, bytes, lookup, write) in [
        (LDR_ZA_W12_X5, VL, false, false),
        (STR_ZA_W12_X5, VL, false, true),
        (
            LDR_ZT0_X5,
            stela_compiler::aarch64::scalable::LOOKUP_TABLE_BYTES,
            true,
            false,
        ),
        (
            STR_ZT0_X5,
            stela_compiler::aarch64::scalable::LOOKUP_TABLE_BYTES,
            true,
            true,
        ),
    ] {
        let mut f = Fixture::new_program_at(
            &[MOV_X3_SEVEN, word, RET_X30],
            PC,
            RAM,
            VL,
            TargetCpu::Baseline,
            TargetCpu::Baseline,
            None,
            1,
            ScalableMode::new(false, true),
        );
        let mut ram = f.storage.bytes();
        let mut expected = f.registers.clone();
        expected.x[3] = 7;
        let mut scalable = f.scalable.clone();
        if write {
            ram[..bytes].fill(if lookup { 0x35 } else { 0x6d });
        } else if lookup {
            scalable.write_zt0(0, &ram[..bytes]).unwrap();
        } else {
            scalable.write_za(0, &ram[..bytes]).unwrap();
        }
        assert_eq!(f.execute().unwrap(), ScalableLeafExit::Returned);
        assert_eq!(f.registers, expected);
        // With SM = 0, Z, P and FFR reads are unavailable, so Debug shows the
        // allocations without changing mode (re-enabling would zero ZA).
        assert_eq!(format!("{:?}", f.scalable), format!("{scalable:?}"));
        assert_eq!(f.storage.bytes(), ram);
    }
}

#[test]
fn same_domain_observation_excludes_scalable_entry_until_released() {
    let mut f = Fixture::new(
        LD1B_Z1_P0_X5,
        TargetCpu::Baseline,
        TargetCpu::Baseline,
        None,
    );
    let before = f.registers.clone();
    assert_ne!(before.x[3], 7);
    assert_eq!(&f.prepared.source()[..4], &MOV_X3_SEVEN.to_le_bytes());
    let state = banks(&f.registers, &f.scalable);
    let ram = f.storage.bytes();
    let generation = f.domain.generation().unwrap();
    // The observation holds the thread's domain service borrow, so admission
    // must refuse before any prefix or policy installation.
    let observation = f.memory.observation_loan().unwrap();
    assert!(matches!(
        f.execute(),
        Err(ScalableExecutionError::MemoryAuthority {
            cause: ProcessMemoryError::Memory(MemoryStatus::Domain),
            pc: GuestAddress(PC),
        })
    ));
    unchanged(&f, &before, &state, &ram);
    assert_eq!(f.domain.generation().unwrap(), generation);
    // Reuse the same prepared body, source witness, controls and state;
    // dropping a read-only borrow changes neither the mapping generation nor
    // the source.
    drop(observation);
    let mut expected = before;
    expected.x[3] = 7;
    let mut expected_scalable = f.scalable.clone();
    let mut output = [0; VL];
    output[..2].copy_from_slice(&ram[..2]);
    expected_scalable
        .write_z(&mut expected, 1, &output)
        .unwrap();
    assert_eq!(f.execute().unwrap(), ScalableLeafExit::Returned);
    assert_eq!(f.registers, expected);
    assert_eq!(
        banks(&f.registers, &f.scalable),
        banks(&expected, &expected_scalable)
    );
    assert_eq!(f.storage.bytes(), ram);
    assert_eq!(f.domain.generation().unwrap(), generation);
}

#[test]
fn distinct_snapshot_and_wrong_domain_decline_before_prefix() {
    let mut f = Fixture::new(
        LD1B_Z1_P0_X5,
        TargetCpu::Baseline,
        TargetCpu::Baseline,
        None,
    );
    let before = f.registers.clone();
    let state = banks(&f.registers, &f.scalable);
    let ram = f.storage.bytes();
    f.ids = snapshot(true, 1);
    assert!(matches!(
        f.execute(),
        Err(ScalableExecutionError::WrongIdentificationSnapshot {
            pc: GuestAddress(PC)
        })
    ));
    unchanged(&f, &before, &state, &ram);
    // Restore a single shared identification allocation, then use an empty
    // different domain solely for the negative identity control; no native
    // body is allowed to enter that owner.
    f.ids = snapshot(true, 1);
    f.controls = fixed(Arc::clone(&f.ids), &f.domain, true).unwrap();
    let wrong = MemoryDomain::new_for_address_space(
        7,
        MemorySystem::new(VL as u64, 4).unwrap(),
        Vec::new(),
        TargetCpu::Baseline,
    )
    .unwrap();
    f.memory = wrong.thread(*f.memory.policy_mut());
    assert!(matches!(
        f.execute(),
        Err(ScalableExecutionError::MemoryAuthority {
            cause: ProcessMemoryError::WrongMemoryDomain,
            ..
        })
    ));
    unchanged(&f, &before, &state, &ram);
}

#[test]
fn source_sca_and_lse2_requirements_decline_before_prefix() {
    let mut f = Fixture::new(
        LD1B_Z1_P0_X5,
        TargetCpu::Baseline,
        TargetCpu::Baseline,
        None,
    );
    let before = f.registers.clone();
    let state = banks(&f.registers, &f.scalable);
    let ram = f.storage.bytes();
    f.sca16 = false;
    assert!(matches!(
        f.execute(),
        Err(ScalableExecutionError::UnsupportedSourceAtomicity {
            actual: SourceAtomicity::Unspecified,
            ..
        })
    ));
    unchanged(&f, &before, &state, &ram);
    assert!(matches!(
        fixed(snapshot(false, 1), &f.domain, true),
        Err(ProcessMemoryError::UnsupportedFeature {
            register: "ID_AA64MMFR2_EL1",
            field: "AT",
            value: 0
        })
    ));
    unchanged(&f, &before, &state, &ram);
    for word in [LD1D_Z1_P0_X5, ST1Q_ZA_P0_X5] {
        let mut f = Fixture::new(word, wide_target(), TargetCpu::Baseline, None);
        let before = f.registers.clone();
        let state = banks(&f.registers, &f.scalable);
        let ram = f.storage.bytes();
        assert_eq!(
            f.execute().unwrap(),
            ScalableLeafExit::EntryDeclined(MemoryStatus::Unsupported)
        );
        unchanged(&f, &before, &state, &ram);
    }
}

#[test]
fn helper_za_sp_and_feature_failures_precede_prefix() {
    for cpacr in [
        ALL_ACCESS & !(3 << SMEN_SHIFT),
        ALL_ACCESS & !(3 << FPEN_SHIFT),
    ] {
        let mut f = Fixture::new(LD1Q_ZA_P0_X5, wide_target(), wide_target(), None);
        f.cpacr = cpacr;
        let before = f.registers.clone();
        let state = banks(&f.registers, &f.scalable);
        let ram = f.storage.bytes();
        assert!(matches!(
            f.execute(),
            Err(ScalableExecutionError::Control {
                cause: scalable_controls::Error::PreflightTrap(_),
                ..
            })
        ));
        unchanged(&f, &before, &state, &ram);
    }
    let mut f = Fixture::new(LD1Q_ZA_P0_X5, wide_target(), wide_target(), None);
    f.scalable
        .apply_mode(&mut f.registers, ScalableMode::new(true, false))
        .unwrap();
    let scalable_before = format!("{:?}", f.scalable);
    let before = f.registers.clone();
    let ram = f.storage.bytes();
    assert!(matches!(
        f.execute(),
        Err(ScalableExecutionError::Control {
            cause: scalable_controls::Error::PreflightTrap(_),
            ..
        })
    ));
    assert_eq!(f.registers, before);
    assert_eq!(format!("{:?}", f.scalable), scalable_before);
    assert_eq!(f.storage.bytes(), ram);
    let mut f = Fixture::new(
        LD1B_Z1_P0_SP,
        TargetCpu::Baseline,
        TargetCpu::Baseline,
        None,
    );
    f.controls = fixed(Arc::clone(&f.ids), &f.domain, false).unwrap();
    let before = f.registers.clone();
    let state = banks(&f.registers, &f.scalable);
    let ram = f.storage.bytes();
    assert_eq!(
        f.execute().unwrap(),
        ScalableLeafExit::EntryDeclined(MemoryStatus::Unsupported)
    );
    unchanged(&f, &before, &state, &ram);
    f.system = SystemState::new(
        PSTATE_EL0T | PSTATE_IL_MASK,
        0,
        El1Registers::new(0, 0, 0, 0, 0),
    )
    .unwrap();
    assert!(matches!(
        f.execute(),
        Err(ScalableExecutionError::MemoryAuthority {
            cause: ProcessMemoryError::IllegalExecutionState,
            ..
        })
    ));
    unchanged(&f, &before, &state, &ram);
}

#[test]
fn q16_native_aligned_residue8_and_other_residues() {
    for word in [LD1Q_ZA_P0_X5, ST1Q_ZA_P0_X5] {
        for residue in [0, 8, 1, 15] {
            let mut f = Fixture::new(word, wide_target(), wide_target(), None);
            f.registers.x[5] += residue as u64;
            let mut ram = f.storage.bytes();
            let mut expected = f.registers.clone();
            expected.x[3] = 7;
            let mut scalable = f.scalable.clone();
            if word == LD1Q_ZA_P0_X5 {
                scalable.write_za(0, &ram[residue..residue + VL]).unwrap();
            } else {
                ram[residue..residue + VL].fill(0x6d);
            }
            assert_eq!(f.execute().unwrap(), ScalableLeafExit::Returned);
            assert_eq!(f.registers, expected);
            assert_eq!(
                banks(&f.registers, &f.scalable),
                banks(&expected, &scalable)
            );
            assert_eq!(f.storage.bytes(), ram);
        }
    }
}

#[test]
fn qualified_q16_translation_permission_order_and_prefix() {
    // SME keeps its descriptor and uses byte parts when an unaligned quadword
    // crosses a 16-byte granule; permission and translation still fault at the
    // first inaccessible byte.
    for word in [LD1Q_ZA_P0_X5, ST1Q_ZA_P0_X5, ST2Q_Z1_P0_X5] {
        for translation in [false, true] {
            let mut f = if word == ST2Q_Z1_P0_X5 {
                Fixture::new_program(
                    &[MOV_X3_SEVEN, word, RET_X30],
                    PC,
                    VL,
                    wide_target(),
                    wide_target(),
                    Some((11, translation)),
                )
            } else {
                Fixture::new(word, wide_target(), wide_target(), Some((11, translation)))
            };
            f.registers.x[5] += 8;
            let mut ram = f.storage.bytes();
            let mut expected = f.registers.clone();
            expected.x[3] = 7;
            let state = banks(&expected, &f.scalable);
            if word == ST1Q_ZA_P0_X5 {
                ram[8..11].fill(0x6d);
            }
            assert_eq!(
                f.execute().unwrap(),
                ScalableLeafExit::MemoryFault(crate::scalable::leaf::MemoryFault {
                    status: if translation {
                        MemoryStatus::Translation
                    } else {
                        MemoryStatus::Permission
                    },
                    address: GuestAddress(RAM + if word == ST2Q_Z1_P0_X5 { 8 } else { 11 }),
                    pc: GuestAddress(PC + 4),
                    completed_bytes: if word == ST2Q_Z1_P0_X5 { 0 } else { 3 },
                })
            );
            assert_eq!(f.registers, expected);
            assert_eq!(banks(&f.registers, &f.scalable), state);
            assert_eq!(f.storage.bytes(), ram);
        }
    }
}

#[test]
fn qualified_callback_and_inactive_sp_faults_reset_next_entry() {
    for translation in [false, true] {
        let mut f = Fixture::new(
            LD1B_Z1_P0_X5,
            TargetCpu::Baseline,
            TargetCpu::Baseline,
            Some((1, translation)),
        );
        let ram = f.storage.bytes();
        let mut expected = f.registers.clone();
        expected.x[3] = 7;
        let state = banks(&expected, &f.scalable);
        assert_eq!(
            f.execute().unwrap(),
            ScalableLeafExit::MemoryFault(crate::scalable::leaf::MemoryFault {
                status: if translation {
                    MemoryStatus::Translation
                } else {
                    MemoryStatus::Permission
                },
                address: GuestAddress(RAM + 1),
                pc: GuestAddress(PC + 4),
                completed_bytes: 1,
            })
        );
        assert_eq!(f.registers, expected);
        assert_eq!(banks(&f.registers, &f.scalable), state);
        assert_eq!(f.storage.bytes(), ram);
    }
    let mut f = Fixture::new(
        LD1B_Z1_P0_SP,
        TargetCpu::Baseline,
        TargetCpu::Baseline,
        None,
    );
    f.scalable.write_predicate(0, &[0; VL / 8]).unwrap();
    f.registers.sp = RAM + 1;
    let ram = f.storage.bytes();
    let mut expected = f.registers.clone();
    expected.x[3] = 7;
    let mut scalable = f.scalable.clone();
    assert_eq!(
        f.execute().unwrap(),
        ScalableLeafExit::MemoryFault(crate::scalable::leaf::MemoryFault {
            status: MemoryStatus::StackAlignment,
            address: GuestAddress(RAM + 1),
            pc: GuestAddress(PC + 4),
            completed_bytes: 0,
        })
    );
    assert_eq!(f.registers, expected);
    assert_eq!(
        banks(&f.registers, &f.scalable),
        banks(&expected, &scalable)
    );
    assert_eq!(f.storage.bytes(), ram);
    f.registers.sp = RAM;
    expected.sp = RAM;
    scalable.write_z(&mut expected, 1, &[0; VL]).unwrap();
    assert_eq!(f.execute().unwrap(), ScalableLeafExit::Returned);
    assert_eq!(f.registers, expected);
    assert_eq!(
        banks(&f.registers, &f.scalable),
        banks(&expected, &scalable)
    );
    assert_eq!(f.storage.bytes(), ram);
}
