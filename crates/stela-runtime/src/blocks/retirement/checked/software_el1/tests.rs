use super::*;
use crate::system::state::{El1Registers, PSTATE_EL1H};
use stela_compiler::{GuestState, TargetCpu};

#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
mod barriers;
#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
mod hosted;
#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
mod mutable_source;
#[cfg(target_arch = "x86_64")]
mod platform;
#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
mod scalar_load;
#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
mod scalar_store;

#[test]
fn full_pacm_storage_is_refused_before_ram_materialization() {
    let config = SoftwareEl1Config {
        profile: SoftwareEl1Profile::IntegerV1,
        cache_directory: PathBuf::new(),
        // Deliberately invalid RAM must not reach materialization.
        ram: SourceRamDeclaration {
            address_space: 0,
            target: TargetCpu::Baseline,
            declared_capacity: Vec::new(),
            initialized: Vec::new(),
        },
        thread: ThreadState {
            registers: GuestState::default(),
            pc: GuestAddress(0),
        },
        system: SystemState::new_with_pacm(
            PSTATE_EL1H,
            0,
            El1Registers::new(0, 0, 0, 0, 0),
            PacmStateFeature::Full,
        )
        .unwrap(),
        translation: RegisterValues {
            sctlr_el1: 0,
            tcr_el1: 0,
            ttbr0_el1: 0,
            ttbr1_el1: 0,
            mair_el1: 0,
        },
    };
    let error = SoftwareEl1Machine::new(config).err().unwrap();
    assert_eq!(
        error.to_string(),
        "software EL1 foundation requires PACM-absent storage"
    );
}
