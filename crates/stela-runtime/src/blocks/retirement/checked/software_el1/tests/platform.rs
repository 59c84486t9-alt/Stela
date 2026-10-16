use super::*;
use crate::system::state::{El1Registers, PSTATE_EL1H};
const SOURCE_PA: u64 = 0x100000;
const VECTOR_BASE: u64 = 0x8000;
const NOP: u32 = 0xd503201f;
fn machine(cache: PathBuf, words: &[u32], vector_base: u64) -> SoftwareEl1Machine {
    let mut registers = stela_compiler::GuestState {
        sp: 0x2f0000,
        nzcv: 0xa0000000,
        reserved: 0xdec0de00,
        ..Default::default()
    };
    for (i, value) in registers.x.iter_mut().enumerate() {
        *value = 0x1111000000000000 | i as u64;
    }
    registers.x[10] = vector_base;
    for (i, value) in registers.v.iter_mut().enumerate() {
        *value = [0x2222000000000000 | i as u64, 0x3333000000000000 | i as u64];
    }
    SoftwareEl1Machine::new(SoftwareEl1Config {
        profile: SoftwareEl1Profile::PlatformV1,
        cache_directory: cache,
        ram: SourceRamDeclaration {
            address_space: 91,
            target: stela_compiler::TargetCpu::Baseline,
            declared_capacity: vec![PhysicalRamRange {
                source_pa: SOURCE_PA,
                bytes: 0x10000,
            }],
            initialized: vec![OwnedRamExtent {
                source_pa: SOURCE_PA,
                bytes: words.iter().flat_map(|word| word.to_le_bytes()).collect(),
                permissions: SourceRamPermissions {
                    readable: true,
                    writable: false,
                    executable: true,
                },
            }],
        },
        thread: ThreadState {
            pc: GuestAddress(SOURCE_PA),
            registers,
        },
        system: SystemState::new(
            PSTATE_EL1H | crate::system::pstate::DAIF_MASK,
            0x2e0000,
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
#[test]
fn context_publication_rejects_other_same_profile_cache_before_fetch() {
    let machine = machine(PathBuf::new(), &[NOP], VECTOR_BASE);
    let memory = machine.memory;
    let system = machine.system;
    let InstalledSource::El1(installed) = machine.installed else {
        panic!("actual platform owner absent")
    };
    // Moving the installed owner retains its original cache allocation.
    installed
        .into_executable_scope(&ConsumerKey(()), |runtime, sources, controls| {
            let outer = memory.execution_loan().unwrap();
            let mut other = BlockRuntime::new_for_target(
                runtime.address_space(),
                PathBuf::new(),
                runtime.profile(),
                runtime.target_cpu(),
            );
            let before = controls.snapshot().unwrap();
            let registered = runtime.regions.len();
            let error = sources
                .publication_scope(&mut other, controls, &system, &outer)
                .err()
                .unwrap();
            assert_eq!(
                error,
                "publication runtime is not the original installed source cache"
            );
            assert!(other.regions.is_empty() && other.loaded.is_empty());
            assert_eq!(runtime.regions.len(), registered);
            let after = controls.snapshot().unwrap();
            assert_eq!(before.generation(), after.generation());
            assert!(before.same_pe(&after));
            let _scope = sources
                .publication_scope(runtime, controls, &system, &outer)
                .unwrap();
        })
        .unwrap();
}
