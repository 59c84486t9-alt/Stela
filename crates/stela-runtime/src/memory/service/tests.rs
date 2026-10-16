use crate::memory::{
    binding::tests::{config, owned},
    domain::MemorySystem,
    policy::{LowerAddressProfile, MemoryControls, TagCheckFaultMode},
};

#[test]
fn actual_guard_poison_invalidates_health_and_preflight_without_owner_flag() {
    let (mut owner, base) = owned();
    // SAFETY: new anonymous storage with every software writer.
    let domain =
        unsafe { owner.bind_shared_memory(config(MemorySystem::new(16, 8).unwrap(), 76), &mut []) }
            .unwrap();
    let mut thread = domain.thread(MemoryControls::new(
        LowerAddressProfile::new(47, false).unwrap(),
        false,
        false,
        false,
        TagCheckFaultMode::Ignore,
        false,
    ));
    {
        let mut service = owner.service_memory(&mut thread).unwrap();
        assert!(service.is_usable());
        service.service.poison();
        assert!(service.owner.is_usable());
        assert!(!service.is_usable());
        assert!(service.validate_write(base, 1).is_err());
        assert!(service.validate_write(base, 0).is_err());
        assert!(service.read_snapshot(base, 1).is_err());
        assert!(service.write(base, &[1]).is_err());
    }
    assert!(owner.is_usable());
    assert!(domain.execution_loan().is_err());
    assert!(owner.service_memory(&mut thread).is_err());
}
