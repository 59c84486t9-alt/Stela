//! Authored generic scalar-store fixtures through the original software PE.
//! Complete bank and exact RAM comparisons; no direct native entry or fake loan.
use super::*;
use crate::system::state::{El1Registers, PSTATE_EL1H};
use stela_compiler::{GuestState, TargetCpu};
const CODE: u64 = 0x100000;
const DATA: u64 = CODE + 0x100;
fn config(cache: PathBuf, word: u32, data: Option<Vec<u8>>) -> SoftwareEl1Config {
    let mut registers = GuestState {
        sp: DATA,
        nzcv: 0xa0000000,
        reserved: 0xabc12000,
        ..Default::default()
    };
    for (index, value) in registers.x.iter_mut().enumerate() {
        *value = 0x1234567800000000 | index as u64;
    }
    for (index, value) in registers.v.iter_mut().enumerate() {
        *value = [
            0x2233445500000000 | index as u64,
            0x3344556600000000 | index as u64,
        ];
    }
    registers.x[1] = DATA;
    registers.x[0] = 0x8899aabbccddeeff;
    let mut initialized = vec![OwnedRamExtent {
        source_pa: CODE,
        bytes: word.to_le_bytes().to_vec(),
        permissions: SourceRamPermissions {
            readable: true,
            writable: false,
            executable: true,
        },
    }];
    if let Some(bytes) = data {
        initialized.push(OwnedRamExtent {
            source_pa: DATA,
            bytes,
            permissions: SourceRamPermissions {
                readable: true,
                writable: true,
                executable: false,
            },
        });
    }
    SoftwareEl1Config {
        profile: SoftwareEl1Profile::PlatformV1,
        cache_directory: cache,
        ram: SourceRamDeclaration {
            address_space: 719,
            target: TargetCpu::Baseline,
            declared_capacity: vec![PhysicalRamRange {
                source_pa: CODE,
                bytes: 0x1000,
            }],
            initialized,
        },
        thread: ThreadState {
            pc: GuestAddress(CODE),
            registers,
        },
        system: SystemState::new(
            PSTATE_EL1H | crate::system::pstate::DAIF_MASK,
            0x2f0000,
            El1Registers::new(CODE, 0x3c5, 0, 0, 0),
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
fn run(config: SoftwareEl1Config) -> SoftwareEl1Report {
    SoftwareEl1Machine::new(config)
        .unwrap()
        .run_to_shutdown(SoftwareEl1Request {
            stop_pc: Some(GuestAddress(CODE + 4)),
            block_budget: 2,
        })
        .unwrap()
}
#[test]
fn all_store_widths_and_zr_publish_only_exact_extent_and_preserve_complete_banks() {
    for (word, bytes) in [
        (0x39000020_u32, 1),
        (0x79000020, 2),
        (0xb9000020, 4),
        (0xf9000020, 8),
    ] {
        for zero in [false, true] {
            let cache = tempfile::tempdir().unwrap();
            let config = config(
                cache.path().join("cache"),
                if zero { word | 31 } else { word },
                Some(vec![0xa5; bytes]),
            );
            let expected = config.thread.registers.clone();
            let system = config.system.clone();
            let value = if zero { 0_u64 } else { expected.x[0] };
            let report = run(config);
            assert_eq!(report.stop, "StopAddress");
            assert_eq!(report.thread.pc, GuestAddress(CODE + 4));
            assert_eq!(report.thread.registers, expected);
            assert_eq!(report.system, system);
            assert_eq!(report.accounting.blocks_executed, 1);
            assert_eq!(
                report.ram[1].sha256,
                Ok(crate::sha256(&value.to_le_bytes()[..bytes]))
            );
            assert_eq!(report.ram[1].bytes, bytes as u64);
        }
    }
}
#[test]
fn store_address_extensions_and_writeback_use_original_source_and_address_banks() {
    for (word, base, index, writeback) in [
        (0xb9000420_u32, DATA - 4, 0, None),
        (0xb81fc020, DATA + 4, 0, None),
        (0xf8008420, DATA, 0, Some(DATA + 8)),
        (0xf8008c20, DATA - 8, 0, Some(DATA)),
        (0xf8226820, DATA - 8, 8, None),
        (0xf8225820, DATA - 8, 0x1234567800000001, None),
        (0xf822d820, DATA + 8, 0x12345678ffffffff, None),
        (0xf8227820, DATA - 8, 1, None),
        (0xf822f820, DATA + 8, u64::MAX, None),
        (0xf83f6820, DATA, 0, None),
    ] {
        let cache = tempfile::tempdir().unwrap();
        let mut config = config(cache.path().join("cache"), word, Some(vec![0xa5; 8]));
        config.thread.registers.x[1] = base;
        config.thread.registers.x[2] = index;
        let mut expected = config.thread.registers.clone();
        let value = expected.x[0];
        if let Some(base) = writeback {
            expected.x[1] = base;
        }
        let system = config.system.clone();
        let report = run(config);
        assert_eq!(report.stop, "StopAddress", "{word:#x}");
        assert_eq!(report.thread.registers, expected, "{word:#x}");
        assert_eq!(report.system, system);
        let bytes = if matches!(word, 0xb9000420 | 0xb81fc020) {
            4
        } else {
            8
        };
        let mut expected_ram = vec![0xa5; 8];
        expected_ram[..bytes].copy_from_slice(&value.to_le_bytes()[..bytes]);
        assert_eq!(report.ram[1].sha256, Ok(crate::sha256(&expected_ram)));
    }
}
#[test]
fn data_base_index_aliases_snapshot_source_before_effects_and_preserve_flags() {
    for (word, source, base, index) in [
        (0xb9000021_u32, 1, DATA, 8),
        (0xf8226822, 2, DATA - 8, 8),
        (0xf8226821, 1, DATA - 8, 8),
        (0xf90003ff, 31, DATA, 8),
    ] {
        let cache = tempfile::tempdir().unwrap();
        let mut config = config(cache.path().join("cache"), word, Some(vec![0xa5; 8]));
        config.thread.registers.x[1] = base;
        config.thread.registers.x[2] = index;
        let expected = config.thread.registers.clone();
        let system = config.system.clone();
        let value = if source == 31 { 0 } else { expected.x[source] };
        let bytes = if word == 0xb9000021 { 4 } else { 8 };
        let mut expected_ram = vec![0xa5; 8];
        expected_ram[..bytes].copy_from_slice(&value.to_le_bytes()[..bytes]);
        let report = run(config);
        assert_eq!(report.stop, "StopAddress");
        assert_eq!(report.thread.registers, expected);
        assert_eq!(report.system, system);
        assert_eq!(report.ram[1].sha256, Ok(crate::sha256(&expected_ram)));
    }
}
#[test]
fn actual_sp_alignment_precedes_store_target_and_only_success_commits_sp_writeback() {
    for sa in [false, true] {
        let cache = tempfile::tempdir().unwrap();
        let mut config = config(cache.path().join("cache"), 0xf8004fe0, Some(vec![0x5a; 8]));
        config.thread.registers.sp = DATA - 4;
        config.translation.sctlr_el1 = if sa { 1 << 3 } else { 0 };
        let mut expected = config.thread.registers.clone();
        let system = config.system.clone();
        let value = expected.x[0];
        let report = run(config);
        if sa {
            assert_ne!(report.stop, "StopAddress");
            let diagnostic = report.memory_write_observation.as_ref().unwrap();
            assert!(diagnostic.contains("StackAlignment"));
            assert!(diagnostic.contains(&format!("original_sp: {}", DATA - 4)));
            assert_eq!(report.thread.pc, GuestAddress(CODE));
            assert_eq!(report.accounting.blocks_executed, 0);
            assert_eq!(report.ram[1].sha256, Ok(crate::sha256(&[0x5a; 8])));
        } else {
            expected.sp = DATA;
            assert_eq!(report.stop, "StopAddress");
            assert_eq!(report.accounting.blocks_executed, 1);
            assert_eq!(
                report.ram[1].sha256,
                Ok(crate::sha256(&value.to_le_bytes()))
            );
        }
        assert_eq!(report.thread.registers, expected);
        assert_eq!(report.system, system);
    }
}
#[test]
fn missing_readonly_and_misaligned_ram_refuse_before_writeback_or_any_ram_effect() {
    for kind in 0..3 {
        let cache = tempfile::tempdir().unwrap();
        let mut config = config(
            cache.path().join("cache"),
            0xf8008420,
            if kind == 0 { None } else { Some(vec![0xa5; 8]) },
        );
        if kind == 1 {
            config.ram.initialized[1].permissions.writable = false;
        }
        if kind == 2 {
            config.thread.registers.x[1] = DATA + 1;
        }
        let expected = config.thread.registers.clone();
        let system = config.system.clone();
        let report = run(config);
        assert_ne!(report.stop, "StopAddress");
        assert_eq!(report.thread.pc, GuestAddress(CODE));
        assert_eq!(report.thread.registers, expected);
        assert_eq!(report.system, system);
        assert_eq!(report.accounting.blocks_executed, 0);
        if kind != 0 {
            assert_eq!(report.ram[1].sha256, Ok(crate::sha256(&[0xa5; 8])));
        }
    }
    for word in [0xb8000820_u32, 0xf8008c00, 0xf8008400] {
        let cache = tempfile::tempdir().unwrap();
        let config = config(cache.path().join("cache"), word, Some(vec![0xa5; 8]));
        assert!(SoftwareEl1Machine::new(config).is_err());
    }
}
#[test]
fn every_scalar_width_retires_cached_source_before_revisit_with_exact_owned_receipt() {
    for (word, bytes) in [
        (0x39000022_u32, 1),
        (0x79000022, 2),
        (0xb9000022, 4),
        (0xf9000022, 8),
    ] {
        let cache = tempfile::tempdir().unwrap();
        let mut config = config(cache.path().join("cache"), word, None);
        config.ram.initialized.clear();
        config.thread.registers.x[0] = 0;
        config.thread.registers.x[1] = CODE + 16 + if bytes == 1 { 1 } else { 0 };
        config.thread.registers.x[2] = match bytes {
            1 => 0x1c,
            2 | 4 => 0x91001c00,
            8 => (0x17fffffc_u64 << 32) | 0x91001c00,
            _ => unreachable!(),
        };
        let mut expected = config.thread.registers.clone();
        expected.x[0] = 8;
        let system = config.system.clone();
        let words = [
            0x14000004_u32,
            word,
            0x14000002,
            0xd503201f,
            0x91000400,
            0x17fffffc,
        ];
        let prefix = words
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        let mut expected_ram = prefix.clone();
        expected_ram.resize(64, 0);
        let region = InitializedRamRegion {
            range: PhysicalRamRange {
                source_pa: CODE,
                bytes: 64,
            },
            file_sha256: crate::sha256(&prefix),
            file_prefix: prefix,
            permissions: SourceRamPermissions {
                readable: true,
                writable: true,
                executable: true,
            },
        };
        let machine = SoftwareEl1Machine::new_with_regions(config, vec![], vec![region]).unwrap();
        let report = machine
            .run_to_shutdown(SoftwareEl1Request {
                stop_pc: None,
                block_budget: 6,
            })
            .unwrap();
        assert_eq!(report.accounting.blocks_executed, 6);
        assert_eq!(report.thread.pc, GuestAddress(CODE + 20));
        assert_eq!(report.thread.registers, expected);
        assert_eq!(report.system, system);
        expected_ram[16..20].copy_from_slice(&0x91001c00_u32.to_le_bytes());
        assert_eq!(report.ram[0].sha256, Ok(crate::sha256(&expected_ram)));
        assert!(
            report
                .memory_write_observation
                .as_ref()
                .unwrap()
                .contains("modified_instruction_ram: true")
        );
    }
}
#[test]
fn scalar_self_overwrite_settles_using_original_pin_before_source_rebind() {
    let cache = tempfile::tempdir().unwrap();
    let mut config = config(cache.path().join("cache"), 0xb9000022, None);
    config.ram.initialized.clear();
    config.thread.registers.x[0] = 0;
    config.thread.registers.x[1] = CODE;
    config.thread.registers.x[2] = 0x91001c00;
    let mut expected = config.thread.registers.clone();
    expected.x[0] = 7;
    let system = config.system.clone();
    let prefix = [0xb9000022_u32, 0x17ffffff]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect::<Vec<_>>();
    let mut expected_ram = prefix.clone();
    expected_ram.resize(64, 0);
    let region = InitializedRamRegion {
        range: PhysicalRamRange {
            source_pa: CODE,
            bytes: 64,
        },
        file_sha256: crate::sha256(&prefix),
        file_prefix: prefix,
        permissions: SourceRamPermissions {
            readable: true,
            writable: true,
            executable: true,
        },
    };
    let machine = SoftwareEl1Machine::new_with_regions(config, vec![], vec![region]).unwrap();
    let report = machine
        .run_to_shutdown(SoftwareEl1Request {
            stop_pc: None,
            block_budget: 3,
        })
        .unwrap();
    assert_eq!(report.accounting.blocks_executed, 3);
    assert_eq!(report.thread.pc, GuestAddress(CODE + 4));
    assert_eq!(report.thread.registers, expected);
    assert_eq!(report.system, system);
    expected_ram[..4].copy_from_slice(&0x91001c00_u32.to_le_bytes());
    assert_eq!(report.ram[0].sha256, Ok(crate::sha256(&expected_ram)));
}
