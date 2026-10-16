use super::*;
use crate::system::state::{El1Registers, PSTATE_EL0T, PSTATE_EL1H};

fn actual_system() -> SystemState {
    SystemState::new(PSTATE_EL1H, 0, El1Registers::new(0, 0, 0, 0, 0)).unwrap()
}

// These are genuinely initialized immutable test declarations, never a
// changed live PE or copied mutable control bank. No execution authority.
fn declared_pair_profile(mmfr2: Option<u64>) -> El1PlatformControls {
    let base = El1PlatformControls::declared_base().unwrap();
    let mut fields = [
        Register::IdAa64Pfr0El1,
        Register::IdAa64Pfr1El1,
        Register::IdAa64Pfr2El1,
        Register::IdAa64Dfr0El1,
        Register::IdAa64Dfr1El1,
        Register::IdAa64Mmfr0El1,
        Register::IdAa64Mmfr1El1,
        Register::IdAa64Isar1El1,
        Register::IdAa64Isar2El1,
        Register::IdAa64Isar3El1,
    ]
    .into_iter()
    .map(|register| (register, base.identification.read(register).unwrap()))
    .collect::<Vec<_>>();
    if let Some(value) = mmfr2 {
        fields.push((Register::IdAa64Mmfr2El1, value));
    }
    El1PlatformControls {
        identification: Snapshot::declared("authored-pair-read-negative-identification", &fields)
            .unwrap(),
        security: SecurityImplementation::NonSecureOnly,
        // Descriptive original absence tuple is not a substitute for the
        // actual Snapshot: context() must independently recheck it.
        entry: base.entry,
    }
}

#[test]
fn actual_retained_pair_profile_requires_positive_lse2_absence() {
    let system = actual_system();
    let base = El1PlatformControls::declared_base().unwrap();
    base.check_pair_read_profile(&system).unwrap();
    let present = declared_pair_profile(Some(1_u64 << LSE2_SHIFT));
    present.context(&system).unwrap();
    let error = present.check_pair_read_profile(&system).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("positively observed LSE2 absence")
    );
    let missing = declared_pair_profile(None);
    let error = missing.check_pair_read_profile(&system).unwrap_err();
    assert!(error.to_string().contains("IdAa64Mmfr2El1"));
    assert_eq!(system, actual_system());
}

#[test]
fn actual_pair_profile_rechecks_original_el_and_il() {
    let platform = El1PlatformControls::declared_base().unwrap();
    for pstate in [PSTATE_EL0T, PSTATE_EL1H | PSTATE_IL_MASK] {
        let system = SystemState::new(pstate, 0, El1Registers::new(0, 0, 0, 0, 0)).unwrap();
        let before = system.clone();
        assert!(platform.check_pair_read_profile(&system).is_err());
        assert_eq!(system, before);
    }
}
