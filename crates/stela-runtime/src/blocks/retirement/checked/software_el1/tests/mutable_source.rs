//! Authored full-state self-modification fixtures through the genuine machine.
//! They exercise the existing one-word EL1 lane, not a new dispatcher.
use super::*;
use crate::system::state::{El1Registers, PSTATE_EL1H};
use stela_compiler::{GuestState, TargetCpu};
fn assert_ram(report: &SoftwareEl1Report, index: usize, bytes: &[u8]) {
    assert_eq!(report.ram[index].sha256, Ok(stela_core::sha256(bytes)));
}
const BASE: u64 = 0x100000;
const STP_X0_X3_X1: u32 = 0xa9000c20;
const ADD_X2_1: u32 = 0x91000442;
const ADD_X2_7: u32 = 0x91001c42;
const NOP: u32 = 0xd503201f;
const B_BACK_12: u32 = 0x17fffffd;
fn config(cache: PathBuf, words: &[u32], target: u64) -> (SoftwareEl1Config, InitializedRamRegion) {
    let mut registers = GuestState {
        sp: BASE + 0x2000,
        nzcv: 0xa0000000,
        reserved: 0xabc12300,
        fpcr: 0,
        fpsr: 0,
        ..Default::default()
    };
    for (i, value) in registers.x.iter_mut().enumerate() {
        *value = 0x1122334400000000 | i as u64;
    }
    for (i, value) in registers.v.iter_mut().enumerate() {
        *value = [0x2233445500000000 | i as u64, 0x3344556600000000 | i as u64];
    }
    registers.x[0] = u64::from(ADD_X2_7) | u64::from(NOP) << 32;
    registers.x[1] = target;
    let prefix: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    (
        SoftwareEl1Config {
            profile: SoftwareEl1Profile::PlatformV1,
            cache_directory: cache,
            ram: SourceRamDeclaration {
                address_space: 702,
                target: TargetCpu::Baseline,
                declared_capacity: vec![PhysicalRamRange {
                    source_pa: BASE,
                    bytes: 64,
                }],
                initialized: Vec::new(),
            },
            thread: ThreadState {
                pc: GuestAddress(BASE),
                registers,
            },
            system: SystemState::new(
                PSTATE_EL1H | crate::system::pstate::DAIF_MASK,
                BASE + 0x1000,
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
        },
        InitializedRamRegion {
            range: PhysicalRamRange {
                source_pa: BASE,
                bytes: 64,
            },
            file_sha256: stela_core::sha256(&prefix),
            file_prefix: prefix,
            permissions: SourceRamPermissions {
                readable: true,
                writable: true,
                executable: true,
            },
        },
    )
}
#[test]
fn revisiting_modified_cached_source_rebinds_before_any_old_instruction_executes() {
    let cache = tempfile::tempdir().unwrap();
    let (mut config, region) = config(
        cache.path().to_owned(),
        &[ADD_X2_1, NOP, STP_X0_X3_X1, B_BACK_12],
        BASE,
    );
    // The second reached pair member overwrites its own STP/next branch with
    // identical words; both actual byte writes still advance source history.
    config.thread.registers.x[3] = u64::from(STP_X0_X3_X1) | u64::from(B_BACK_12) << 32;
    let mut expected = config.thread.registers.clone();
    expected.x[2] = expected.x[2].wrapping_add(8);
    let system = config.system.clone();
    let mut expected_ram = vec![0; 64];
    expected_ram[..16].copy_from_slice(&region.file_prefix);
    expected_ram[..8].copy_from_slice(&expected.x[0].to_le_bytes());
    expected_ram[8..16].copy_from_slice(&expected.x[3].to_le_bytes());
    let report = SoftwareEl1Machine::new_with_regions(config, Vec::new(), vec![region])
        .unwrap()
        .run_to_shutdown(SoftwareEl1Request {
            stop_pc: None,
            block_budget: 5,
        })
        .unwrap();
    assert_eq!(report.thread.registers, expected);
    assert_eq!(report.system, system);
    assert_eq!(report.thread.pc, GuestAddress(BASE + 4));
    assert_eq!(report.accounting.blocks_executed, 5);
    assert_ram(&report, 0, &expected_ram);
}
#[test]
fn overwrite_own_source_settles_once_using_exact_preeffect_pin_and_owned_write() {
    let cache = tempfile::tempdir().unwrap();
    let (mut config, region) = config(cache.path().to_owned(), &[STP_X0_X3_X1, ADD_X2_1], BASE);
    config.thread.registers.x[0] = u64::from(NOP) | u64::from(ADD_X2_7) << 32;
    let mut expected = config.thread.registers.clone();
    expected.x[2] = expected.x[2].wrapping_add(7);
    let system = config.system.clone();
    let mut expected_ram = vec![0; 64];
    expected_ram[..8].copy_from_slice(&expected.x[0].to_le_bytes());
    expected_ram[8..16].copy_from_slice(&expected.x[3].to_le_bytes());
    let report = SoftwareEl1Machine::new_with_regions(config, Vec::new(), vec![region])
        .unwrap()
        .run_to_shutdown(SoftwareEl1Request {
            stop_pc: Some(GuestAddress(BASE + 8)),
            block_budget: 3,
        })
        .unwrap();
    assert_eq!(report.stop, "StopAddress");
    assert_eq!(report.thread.registers, expected);
    assert_eq!(report.system, system);
    assert_eq!(report.thread.pc, GuestAddress(BASE + 8));
    assert_eq!(report.accounting.blocks_executed, 2);
    assert_ram(&report, 0, &expected_ram);
}
#[test]
fn declared_region_tail_is_real_data_but_outside_region_remains_a_reached_refusal() {
    for target in [BASE + 48, BASE + 64] {
        let cache = tempfile::tempdir().unwrap();
        let (config, region) = config(cache.path().to_owned(), &[STP_X0_X3_X1], target);
        let expected = config.thread.registers.clone();
        let system = config.system.clone();
        let report = SoftwareEl1Machine::new_with_regions(config, Vec::new(), vec![region])
            .unwrap()
            .run_to_shutdown(SoftwareEl1Request {
                stop_pc: Some(GuestAddress(BASE + 4)),
                block_budget: 2,
            })
            .unwrap();
        assert_eq!(report.thread.registers, expected);
        assert_eq!(report.system, system);
        if target == BASE + 48 {
            assert_eq!(report.stop, "StopAddress");
            assert_eq!(report.thread.pc, GuestAddress(BASE + 4));
            let mut ram = [0; 64];
            ram[..4].copy_from_slice(&STP_X0_X3_X1.to_le_bytes());
            ram[48..56].copy_from_slice(&expected.x[0].to_le_bytes());
            ram[56..64].copy_from_slice(&expected.x[3].to_le_bytes());
            assert_ram(&report, 0, &ram);
        } else {
            assert_ne!(report.stop, "StopAddress");
            assert_eq!(report.thread.pc, GuestAddress(BASE));
            assert_eq!(report.accounting.blocks_executed, 0);
        }
    }
}
#[test]
fn mutable_fetch_declines_actual_enabled_cache_controls_before_native_entry() {
    for bit in [1 << 2, 1 << 12] {
        let cache = tempfile::tempdir().unwrap();
        let (mut config, region) = config(cache.path().to_owned(), &[NOP], BASE);
        config.translation.sctlr_el1 = bit;
        assert!(SoftwareEl1Machine::new_with_regions(config, Vec::new(), vec![region]).is_err());
    }
}
#[test]
fn own_source_pair_prefix_survives_second_member_fault_without_writeback_or_retry() {
    const STP_X0_X2_X1_POST16: u32 = 0xa8810820;
    let cache = tempfile::tempdir().unwrap();
    let (config, mut region) = config(cache.path().to_owned(), &[STP_X0_X2_X1_POST16], BASE);
    region.range.bytes = 8; // explicit4B zero tail; remaining capacity stays absent
    let expected = config.thread.registers.clone();
    let system = config.system.clone();
    let report = SoftwareEl1Machine::new_with_regions(config, Vec::new(), vec![region])
        .unwrap()
        .run_to_shutdown(SoftwareEl1Request {
            stop_pc: None,
            block_budget: 2,
        })
        .unwrap();
    assert!(report.stop.starts_with("Indeterminate"));
    assert_eq!(report.thread.pc, GuestAddress(BASE));
    assert_eq!(report.thread.registers, expected); // includes original X1 base
    assert_eq!(report.system, system);
    assert_eq!(report.accounting.blocks_executed, 0);
    assert_ram(&report, 0, &expected.x[0].to_le_bytes());
}
