//! Actual consuming RAM-store -> DSB fixture. No original ARM oracle claim.
//! Complete current state/RAM and real reached fence receipt are saved first.
use super::*;
use crate::memory::domain::physical::completion::RamCompletionProgress;
use crate::system::state::{El1Registers, PSTATE_EL1H};
use std::path::Path;
use stela_compiler::{GuestState, TargetCpu};

const SOURCE_PC: u64 = 0x4008_0000;
const DATA_PA: u64 = 0x4009_0000;
const ADDRESS_SPACE: u64 = 91;
const CANARY_BYTES: usize = 32;
const CANARY: u8 = 0xa5;
const STACK_VALUE: u64 = 0x1234_5000;
const INACTIVE_STACK: u64 = 0x9876_5000;
const STP_X0_X1_X2: u32 = 0xa900_0440;
const DSB_BASE: u32 = 0xd503_309f;
const DSB_OPTION_SHIFT: u32 = 8;
const DSB_SY: u8 = 15;
const DSB_ISH: u8 = 11;
const DSB_ISHLD: u8 = 9;
const DSB_ISHST: u8 = 10;
const NOP: u32 = 0xd503_201f;

fn state_bytes(state: &GuestState) -> &[u8] {
    // SAFETY: GuestState is the same fixed all-integer 784-byte native frame;
    // this reads the original fully initialized object for retained evidence.
    unsafe { std::slice::from_raw_parts(std::ptr::from_ref(state).cast(), size_of::<GuestState>()) }
}
fn machine(cache: PathBuf, dsb: u32) -> SoftwareEl1Machine {
    let mut registers = GuestState {
        sp: STACK_VALUE,
        nzcv: 0xa000_0000,
        reserved: 0xdec0_de00,
        ..Default::default()
    };
    for (index, value) in registers.x.iter_mut().enumerate() {
        *value = 0x1111_0000_0000_0000 | index as u64;
    }
    for (index, value) in registers.v.iter_mut().enumerate() {
        *value = [
            0x2222_0000_0000_0000 | index as u64,
            0x3333_0000_0000_0000 | index as u64,
        ];
    }
    registers.x[2] = DATA_PA;
    SoftwareEl1Machine::new(SoftwareEl1Config {
        profile: SoftwareEl1Profile::PlatformV1,
        cache_directory: cache,
        ram: SourceRamDeclaration {
            address_space: ADDRESS_SPACE,
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
                    bytes: [STP_X0_X1_X2, dsb, NOP]
                        .into_iter()
                        .flat_map(u32::to_le_bytes)
                        .collect(),
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
            INACTIVE_STACK,
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
    })
    .unwrap()
}
fn save(output: &Path, report: &SoftwareEl1Report) {
    std::fs::write(
        output.join("after-state.bin"),
        state_bytes(&report.thread.registers),
    )
    .unwrap();
    std::fs::write(
        output.join("after-system.txt"),
        format!("{:#?}", report.system),
    )
    .unwrap();
    std::fs::write(
        output.join("actual-observation.txt"),
        format!(
            "stop={}\npc={:x}\nblocks={}\nwrite={:?}\ncompletion={:?}\ntranslation_before={:?}\ntranslation_after={:?}\ncompiler={}\n",
            report.stop,
            report.thread.pc.0,
            report.accounting.blocks_executed,
            report.memory_write_observation,
            report.system_effect_fixture_observation,
            report.translation_before,
            report.translation,
            report.compiler_source_sha256
        ),
    )
    .unwrap();
    for range in &report.ram {
        match &range.captured_bytes {
            Ok(bytes) => std::fs::write(
                output.join(format!("actual-ram-{:x}.bin", range.source_pa)),
                bytes,
            )
            .unwrap(),
            Err(error) => std::fs::write(
                output.join(format!("actual-ram-{:x}.error", range.source_pa)),
                error,
            )
            .unwrap(),
        }
    }
}
#[test]
#[ignore = "requires current qualified x86 owner and explicit evidence output"]
fn actual_store_and_dsb_keep_original_state_ram_and_reached_completion() {
    let output = PathBuf::from(
        std::env::var_os("STELA_DSB_OUTPUT").expect("fresh evidence output required"),
    );
    assert!(!output.exists(), "preserve previous evidence");
    std::fs::create_dir_all(&output).unwrap();
    for (name, option) in [
        ("sy", DSB_SY),
        ("ish", DSB_ISH),
        ("ishld", DSB_ISHLD),
        ("ishst", DSB_ISHST),
    ] {
        let case = output.join(name);
        std::fs::create_dir(&case).unwrap();
        let dsb = DSB_BASE | (u32::from(option) << DSB_OPTION_SHIFT);
        let machine = machine(case.join("cache"), dsb);
        let before = machine.thread.registers.clone();
        let system = machine.system.clone();
        std::fs::write(case.join("before-state.bin"), state_bytes(&before)).unwrap();
        std::fs::write(case.join("before-system.txt"), format!("{system:#?}")).unwrap();
        let source: Vec<u8> = [STP_X0_X1_X2, dsb, NOP]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        std::fs::write(case.join("source.bin"), &source).unwrap();
        let (actual_source_before, actual_data_before) = {
            let memory = machine.memory.observation_loan().unwrap();
            (
                memory.snapshot(SOURCE_PC, source.len()).unwrap(),
                memory.snapshot(DATA_PA, CANARY_BYTES).unwrap(),
            )
        };
        std::fs::write(case.join("before-source.bin"), &actual_source_before).unwrap();
        std::fs::write(case.join("before-ram.bin"), &actual_data_before).unwrap();
        let report = machine
            .run_to_shutdown(SoftwareEl1Request {
                stop_pc: Some(GuestAddress(SOURCE_PC + 2 * size_of::<u32>() as u64)),
                block_budget: 3,
            })
            .unwrap();
        save(&case, &report);
        assert_eq!(report.stop, "StopAddress");
        assert_eq!(report.accounting.blocks_executed, 2);
        assert_eq!(report.thread.registers, before);
        assert_eq!(report.system, system);
        assert_eq!(actual_source_before, source);
        assert_eq!(actual_data_before, vec![CANARY; CANARY_BYTES]);
        assert_eq!(
            report.translation_before.as_ref().unwrap(),
            report.translation.as_ref().unwrap()
        );
        let observed = report
            .system_effect_fixture_observation
            .as_ref()
            .expect("actual DSB observation absent");
        let completion = observed
            .completion
            .as_ref()
            .expect("actual DSB effect not reached")
            .as_ref()
            .expect("actual DSB failed");
        assert_eq!(completion.progress, RamCompletionProgress::Completed);
        assert_eq!(completion.requirement.option(), option);
        assert_eq!(observed.actual_continuation, Some(report.thread.pc));
        assert!(observed.native.invoked && observed.native.failure.is_none());
        let mut expected = vec![CANARY; CANARY_BYTES];
        expected[..8].copy_from_slice(&before.x[0].to_le_bytes());
        expected[8..16].copy_from_slice(&before.x[1].to_le_bytes());
        let data = report
            .ram
            .iter()
            .find(|ram| ram.source_pa == DATA_PA)
            .unwrap();
        assert_eq!(data.captured_bytes.as_ref().unwrap(), &expected);
        let code = report
            .ram
            .iter()
            .find(|ram| ram.source_pa == SOURCE_PC)
            .unwrap();
        assert_eq!(code.captured_bytes.as_ref().unwrap(), &source);
    }
}
