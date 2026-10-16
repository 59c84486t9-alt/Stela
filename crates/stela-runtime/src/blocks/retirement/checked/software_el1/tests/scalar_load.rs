//! Scalar loads on the software EL1 PE, checked against full register banks and RAM.
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
fn widths_extensions_literals_and_zero_discard_preserve_complete_banks_and_exact_ram() {
    // Concrete authored source words, not an encoding or decoder model.
    for (word, bytes, value) in [
        (0x39400020_u32, 1, 0x80_u64),
        (0x79400020, 2, 0x8080),
        (0xb9400020, 4, 0x80808080),
        (0xf9400020, 8, 0x8080808080808080),
        (0x39c00020, 1, 0xffffff80),
        (0x39800020, 1, 0xffffffffffffff80),
        (0x79c00020, 2, 0xffff8080),
        (0x79800020, 2, 0xffffffffffff8080),
        (0xb9800020, 4, 0xffffffff80808080),
        (0x18000800, 4, 0x80808080),
        (0x58000800, 8, 0x8080808080808080),
        (0x98000800, 4, 0xffffffff80808080),
        (0xb940003f, 4, 0),
    ] {
        let cache = tempfile::tempdir().unwrap();
        let data = vec![0x80; bytes];
        let config = config(cache.path().to_owned(), word, Some(data.clone()));
        let mut expected = config.thread.registers.clone();
        if word != 0xb940003f {
            expected.x[0] = value;
        }
        let system = config.system.clone();
        let report = run(config);
        assert_eq!(report.stop, "StopAddress", "{word:#x}");
        assert_eq!(report.thread.pc, GuestAddress(CODE + 4));
        assert_eq!(report.thread.registers, expected, "{word:#x}");
        assert_eq!(report.system, system);
        assert_eq!(report.accounting.blocks_executed, 1);
        assert_eq!(report.ram[1].sha256, Ok(stela_core::sha256(&data)));
    }
}
#[test]
fn immediate_register_extensions_and_pending_writeback_use_original_banks() {
    for (word, base, index, writeback) in [
        (0xb9400420_u32, DATA - 4, 0, None),   // unsigned scaled #4
        (0xb85fc020, DATA + 4, 0, None),       // LDUR W0,[X1,#-4]
        (0xf8408420, DATA, 0, Some(DATA + 8)), // post
        (0xf8408c20, DATA - 8, 0, Some(DATA)), // pre
        (0xf8626820, DATA - 8, 8, None),       // X offset
        (0xf8625820, DATA - 8, 0x1234567800000001, None), // UXTW #3
        (0xf862d820, DATA + 8, 0x12345678ffffffff, None), // SXTW #3
        (0xf8627820, DATA - 8, 1, None),
        (0xf862f820, DATA + 8, u64::MAX, None),
        (0xf87f6820, DATA, 0xdeadbeef, None), // LSL #3
    ] {
        let cache = tempfile::tempdir().unwrap();
        let mut config = config(cache.path().to_owned(), word, Some(vec![0xa5; 8]));
        config.thread.registers.x[1] = base;
        config.thread.registers.x[2] = index;
        let mut expected = config.thread.registers.clone();
        expected.x[0] = if matches!(word, 0xb85fc020 | 0xb9400420) {
            0xa5a5a5a5
        } else {
            0xa5a5a5a5a5a5a5a5
        };
        if let Some(base) = writeback {
            expected.x[1] = base;
        }
        let system = config.system.clone();
        let report = run(config);
        assert_eq!(report.stop, "StopAddress", "{word:#x}");
        assert_eq!(report.thread.registers, expected, "{word:#x}");
        assert_eq!(report.system, system);
        assert_eq!(report.accounting.blocks_executed, 1);
    }
}
#[test]
fn actual_sp_alignment_policy_precedes_offset_access_and_preserves_failed_writeback() {
    for sa in [false, true] {
        let cache = tempfile::tempdir().unwrap();
        let mut config = config(cache.path().to_owned(), 0xf8404fe0, Some(vec![0x5a; 8]));
        config.thread.registers.sp = DATA - 4;
        config.translation.sctlr_el1 = if sa { 1 << 3 } else { 0 };
        let mut expected = config.thread.registers.clone();
        let system = config.system.clone();
        let report = run(config);
        if sa {
            assert!(
                report
                    .stop
                    .contains("M0 source/control fault remains blocked")
            );
            let diagnostic = report.memory_observation.as_ref().unwrap();
            assert!(diagnostic.contains("StackAlignment"));
            assert!(diagnostic.contains(&format!("source_pc: {}", CODE)));
            assert!(diagnostic.contains(&format!("original_sp: {}", DATA - 4)));
            assert_eq!(report.thread.pc, GuestAddress(CODE));
            assert_eq!(report.accounting.blocks_executed, 0);
        } else {
            expected.sp = DATA;
            expected.x[0] = 0x5a5a5a5a5a5a5a5a;
            assert_eq!(report.stop, "StopAddress");
            assert_eq!(report.accounting.blocks_executed, 1);
        }
        assert_eq!(report.thread.registers, expected);
        assert_eq!(report.system, system);
    }
}
#[test]
fn reached_missing_ram_and_zr_load_refuse_without_destination_writeback_or_pc() {
    for word in [0xf8408420_u32, 0xb940003f] {
        let cache = tempfile::tempdir().unwrap();
        let config = config(cache.path().to_owned(), word, None);
        let before = config.thread.registers.clone();
        let system = config.system.clone();
        let report = run(config);
        assert_ne!(report.stop, "StopAddress");
        assert_eq!(report.thread.pc, GuestAddress(CODE));
        assert_eq!(report.thread.registers, before);
        assert_eq!(report.system, system);
        assert_eq!(report.accounting.blocks_executed, 0);
    }
}

#[test]
fn aligned_sp_and_offset_destination_alias_commit_only_the_typed_register() {
    for word in [0xf94003e0_u32, 0xb9400021] {
        let cache = tempfile::tempdir().unwrap();
        let mut config = config(cache.path().to_owned(), word, Some(vec![0x3c; 8]));
        config.translation.sctlr_el1 = 1 << 3;
        let mut expected = config.thread.registers.clone();
        if word == 0xf94003e0 {
            expected.x[0] = 0x3c3c3c3c3c3c3c3c;
        } else {
            expected.x[1] = 0x3c3c3c3c;
        }
        let system = config.system.clone();
        let report = run(config);
        assert_eq!(report.stop, "StopAddress");
        assert_eq!(report.thread.registers, expected);
        assert_eq!(report.system, system);
        assert_eq!(report.accounting.blocks_executed, 1);
    }
}
#[test]
fn device_alignment_and_unprivileged_or_constrained_shapes_decline_before_commit() {
    for word in [0xb8400820_u32, 0xf8408421] {
        let cache = tempfile::tempdir().unwrap();
        let config = config(cache.path().to_owned(), word, Some(vec![0x6b; 8]));
        assert!(SoftwareEl1Machine::new(config).is_err(), "{word:#x}");
    }
    {
        let cache = tempfile::tempdir().unwrap();
        let mut config = config(cache.path().to_owned(), 0xb9400020, Some(vec![0x6b; 8]));
        config.thread.registers.x[1] = DATA + 1;
        let before = config.thread.registers.clone();
        let system = config.system.clone();
        let report = run(config);
        assert_ne!(report.stop, "StopAddress");
        assert_eq!(report.thread.pc, GuestAddress(CODE));
        assert_eq!(report.thread.registers, before);
        assert_eq!(report.system, system);
        assert_eq!(report.accounting.blocks_executed, 0);
    }
}
