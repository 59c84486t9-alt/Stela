use super::*;

#[test]
fn arm64_page_sizes_are_explicit_owned_and_readonly() -> Result<()> {
    let _guard = crate::clock::TEST_CONTEXT_LOCK.lock().unwrap();
    for kernel in [KernelPageSize::FourKiB, KernelPageSize::SixteenKiB] {
        let mut context = Context::new(71, kernel)?;
        assert_eq!(context.address_space(), 71);
        assert_eq!(context.profile_id(), PROFILE_ID);
        let region = context.region();
        assert_eq!(region.guest_address, GUEST_BASE);
        assert_eq!(region.virtual_bytes, GUEST_BYTES as u64);
        assert!(region.readable && !region.writable && !region.executable);
        let fields = context.supported_fields();
        assert_eq!(fields[0].value, 14);
        assert_eq!(fields[1].value, kernel.shift());
        let bytes = context.snapshot_bytes()?;
        for field in fields {
            assert_eq!(field.bytes, 1);
            assert_eq!(bytes[(field.address - GUEST_BASE) as usize], field.value);
        }
        assert!(context.memory.write(GUEST_BASE + 0x25, &[12]).is_err());
        assert!(Context::new(72, kernel).is_err());
        assert_eq!(context.snapshot_bytes()?, bytes);
        // Dropping this owner releases the fixed address for the next profile.
    }
    Ok(())
}
