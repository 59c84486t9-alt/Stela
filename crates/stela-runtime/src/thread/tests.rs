use super::*;

#[test]
fn explicit_guest_maximum_sanitizes_only_values_strictly_above_it() -> Result<()> {
    for maximum in [1, 0x12345, DIRECT_RAM_USER_END] {
        let profile = VmMaximum::new(maximum)?;
        for address in [0, 1, maximum - 1, maximum] {
            assert_eq!(profile.sanitize_thread_specific_data(address), address);
        }
        for address in [maximum + 1, u64::MAX] {
            assert_eq!(profile.sanitize_thread_specific_data(address), 0);
        }
    }
    assert!(VmMaximum::new(0).is_err());
    assert!(VmMaximum::new(DIRECT_RAM_USER_END + 1).is_err());
    Ok(())
}
