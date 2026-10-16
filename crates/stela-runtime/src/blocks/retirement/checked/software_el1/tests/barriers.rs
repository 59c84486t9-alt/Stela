//! DSB (including the nXS forms) and ISB after a RAM store on the platform PE.
use super::*;
use crate::system::{
    identification::Register,
    identification_snapshot::Snapshot,
    state::{El1Registers, PSTATE_EL1H},
};
use alloc::sync::Arc;
use stela_compiler::{GuestState, TargetCpu};

const SOURCE_PC: u64 = 0x4008_0000;
const DATA_PA: u64 = 0x4009_0000;
const CANARY_BYTES: usize = 32;
const CANARY: u8 = 0xa5;
const STP_X0_X1_X2: u32 = 0xa900_0440;
const DSB_SY: u32 = 0xd503_3f9f;
const DSB_NXS_BASE: u32 = 0xd503_323f;
const DSB_NXS_SCOPE_SHIFT: u32 = 10;
const ISB_BASE: u32 = 0xd503_30df;
const ISB_OPTION_SHIFT: u32 = 8;
const NOP: u32 = 0xd503_201f;
const XS_SHIFT: u32 = 56;
const ID_FIELD_MASK: u64 = 15;
const IDENTIFICATION: &[Register] = &[
    Register::IdAa64Pfr0El1,
    Register::IdAa64Pfr1El1,
    Register::IdAa64Pfr2El1,
    Register::IdAa64Dfr0El1,
    Register::IdAa64Dfr1El1,
    Register::IdAa64Mmfr0El1,
    Register::IdAa64Mmfr1El1,
    Register::IdAa64Mmfr2El1,
    Register::IdAa64Isar1El1,
    Register::IdAa64Isar2El1,
    Register::IdAa64Isar3El1,
];

fn source(barrier: u32) -> Vec<u8> {
    [STP_X0_X1_X2, barrier, NOP]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect()
}

fn config(cache: PathBuf, barrier: u32) -> SoftwareEl1Config {
    let mut registers = GuestState {
        sp: 0x1234_5000,
        nzcv: 0xa000_0000,
        reserved: 0xdec0_de00,
        ..Default::default()
    };
    for (index, value) in registers.x.iter_mut().enumerate() {
        *value = 0x1111_0000_0000_0000 | index as u64;
    }
    registers.x[2] = DATA_PA;
    SoftwareEl1Config {
        profile: SoftwareEl1Profile::PlatformV1,
        cache_directory: cache,
        ram: SourceRamDeclaration {
            address_space: 91,
            target: TargetCpu::Baseline,
            declared_capacity: vec![
                PhysicalRamRange {
                    source_pa: SOURCE_PC,
                    bytes: 0x1000,
                },
                PhysicalRamRange {
                    source_pa: DATA_PA,
                    bytes: CANARY_BYTES as u64,
                },
            ],
            initialized: vec![
                OwnedRamExtent {
                    source_pa: SOURCE_PC,
                    bytes: source(barrier),
                    permissions: SourceRamPermissions {
                        readable: true,
                        writable: false,
                        executable: true,
                    },
                },
                OwnedRamExtent {
                    source_pa: DATA_PA,
                    bytes: vec![CANARY; CANARY_BYTES],
                    permissions: SourceRamPermissions {
                        readable: true,
                        writable: true,
                        executable: false,
                    },
                },
            ],
        },
        thread: ThreadState {
            pc: GuestAddress(SOURCE_PC),
            registers,
        },
        system: SystemState::new(
            PSTATE_EL1H | crate::system::pstate::DAIF_MASK,
            0x9876_5000,
            El1Registers::new(1, 2, 3, 4, 0),
        )
        .unwrap(),
        translation: RegisterValues {
            sctlr_el1: 0,
            tcr_el1: 0,
            ttbr0_el1: 0,
            ttbr1_el1: 0,
            mair_el1: 0,
        },
    }
}

/// The base platform identification with ID_AA64ISAR1_EL1.XS replaced.
fn declaration_with_xs(xs: u64) -> SoftwareEl1Declaration {
    let base = El1PlatformControls::declared_base().unwrap();
    let fields: Vec<_> = IDENTIFICATION
        .iter()
        .map(|&register| {
            let value = base.identification().read(register).unwrap();
            if register == Register::IdAa64Isar1El1 {
                (
                    register,
                    (value & !(ID_FIELD_MASK << XS_SHIFT)) | (xs << XS_SHIFT),
                )
            } else {
                (register, value)
            }
        })
        .collect();
    let snapshot = Arc::new(Snapshot::declared("nxs-test", &fields).unwrap());
    SoftwareEl1Declaration::new(snapshot, SoftwareEl1Security::NonSecureOnly).unwrap()
}

fn run(machine: SoftwareEl1Machine) -> (SoftwareEl1Report, GuestState, SystemState) {
    let before = machine.thread.registers.clone();
    let system = machine.system.clone();
    let report = machine
        .run_to_shutdown(SoftwareEl1Request {
            stop_pc: Some(GuestAddress(SOURCE_PC + 2 * size_of::<u32>() as u64)),
            block_budget: 3,
        })
        .unwrap();
    (report, before, system)
}

/// The store completed and nothing else in RAM or the source changed.
fn assert_ram(report: &SoftwareEl1Report, before: &GuestState, barrier: u32) {
    let mut data = vec![CANARY; CANARY_BYTES];
    data[..8].copy_from_slice(&before.x[0].to_le_bytes());
    data[8..16].copy_from_slice(&before.x[1].to_le_bytes());
    let digest = |source_pa| {
        report
            .ram
            .iter()
            .find(|range| range.source_pa == source_pa)
            .unwrap()
            .sha256
            .clone()
    };
    assert_eq!(digest(DATA_PA), Ok(crate::sha256(&data)));
    assert_eq!(digest(SOURCE_PC), Ok(crate::sha256(&source(barrier))));
}

#[test]
fn dsb_nxs_scopes_complete_only_when_xs_is_implemented() {
    for (scope, xs) in [
        (Some(0), Some(1)),
        (Some(1), Some(1)),
        (Some(2), Some(1)),
        (Some(3), Some(1)),
        (None, None),
        (Some(3), Some(0)),
        (Some(3), Some(ID_FIELD_MASK)),
    ] {
        let cache = tempfile::tempdir().unwrap();
        let barrier = scope.map_or(DSB_SY, |scope| {
            DSB_NXS_BASE | (scope << DSB_NXS_SCOPE_SHIFT)
        });
        let config = config(cache.path().to_owned(), barrier);
        let machine = match xs {
            Some(xs) => {
                SoftwareEl1Machine::new_with_declaration(config, vec![], declaration_with_xs(xs))
            }
            None => SoftwareEl1Machine::new(config),
        }
        .unwrap();
        let (report, before, system) = run(machine);
        assert_eq!(report.thread.registers, before);
        assert_eq!(report.system, system);
        let observation = report.system_effect_observation.as_deref().unwrap();
        if xs.is_none_or(|value| value == 1) {
            assert_eq!(report.stop, "StopAddress", "{scope:?} {xs:?}");
            assert_eq!(report.accounting.blocks_executed, 2);
            assert_eq!(report.thread.pc, GuestAddress(SOURCE_PC + 8));
            assert!(observation.contains("Completed"), "{observation}");
        } else {
            assert_ne!(report.stop, "StopAddress", "{scope:?} {xs:?}");
            assert_eq!(report.accounting.blocks_executed, 1);
            assert_eq!(report.thread.pc, GuestAddress(SOURCE_PC + 4));
        }
        assert_ram(&report, &before, barrier);
    }
}

#[test]
fn every_isb_option_publishes_context_and_fetches_the_next_instruction() {
    for option in 0..16 {
        let cache = tempfile::tempdir().unwrap();
        let barrier = ISB_BASE | (option << ISB_OPTION_SHIFT);
        let machine = SoftwareEl1Machine::new(config(cache.path().to_owned(), barrier)).unwrap();
        let (report, before, system) = run(machine);
        assert_eq!(report.stop, "StopAddress", "option {option}");
        assert_eq!(report.accounting.blocks_executed, 2);
        assert_eq!(report.thread.pc, GuestAddress(SOURCE_PC + 8));
        assert_eq!(report.thread.registers, before);
        assert_eq!(report.system, system);
        let observation = report.context_observation.as_deref().unwrap();
        assert!(
            observation.contains(&format!(
                "InstructionSynchronization {{ option: {option} }}"
            )),
            "{observation}"
        );
        assert!(observation.contains("FetchRequired"), "{observation}");
        assert!(observation.contains("failure: None"), "{observation}");
        assert_ram(&report, &before, barrier);
    }
}
