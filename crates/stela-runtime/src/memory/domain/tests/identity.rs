use super::*;

#[test]
fn generic_data_and_tag_entries_refuse_every_separately_owned_m0_identity() {
    let backing = backing();
    let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, RIGHTS)]);
    let controls = crate::memory::policy::MemoryControls::new(
        crate::memory::policy::LowerAddressProfile::new(48, false).unwrap(),
        false,
        false,
        false,
        crate::memory::policy::TagCheckFaultMode::Ignore,
        false,
    );
    let mut thread = domain.thread(controls);
    let ordinary = MemoryRequirements {
        required_profile: profile_requirements::NATIVE_ACCESS,
        ..Default::default()
    };
    assert!(thread.prepare(ordinary).is_ok());
    assert!(thread.prepare_tag(ordinary, false).is_ok());
    let before = snapshot(&backing, STORAGE_BYTES);
    for dedicated in [
        profile_requirements::M0_DEVICE_RAM_READ64,
        profile_requirements::M0_DEVICE_RAM_WRITE8_OR_PAIR,
        profile_requirements::M0_DEVICE_RAM_READ64_PAIR_NO_LSE2,
        profile_requirements::M0_DEVICE_RAM_SCALAR_LOAD,
    ] {
        for generic in [0, profile_requirements::NATIVE_ACCESS] {
            let requirements = MemoryRequirements {
                required_profile: dedicated | generic,
                ..Default::default()
            };
            assert_eq!(
                thread.prepare(requirements).err(),
                Some(MemoryStatus::Unsupported)
            );
            assert_eq!(
                thread.prepare_tag(requirements, false).err(),
                Some(MemoryStatus::Unsupported)
            );
        }
    }
    assert_eq!(snapshot(&backing, STORAGE_BYTES), before);
    assert!(thread.prepare(ordinary).is_ok());
    assert!(thread.prepare_tag(ordinary, false).is_ok());
}
