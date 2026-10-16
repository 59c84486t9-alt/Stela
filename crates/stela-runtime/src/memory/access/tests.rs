use super::*;

#[repr(align(16))]
struct Quantity([u8; SCA_BYTES]);

#[test]
fn footprints_decline_unsupported_widths_crossings_and_capabilities() {
    for bytes in [0, 3, 5, 9, 17, usize::MAX] {
        assert_eq!(
            read_footprint(0, bytes, TargetCpu::Baseline),
            Err(AccessError::InvalidWidth)
        );
    }
    assert_eq!(
        read_footprint(SCA_BYTES - 1, HALFWORD_BYTES, TargetCpu::AtomicLoad16),
        Err(AccessError::CrossesScaQuantity)
    );
    assert_eq!(
        read_footprint(DOUBLEWORD_BYTES - 1, HALFWORD_BYTES, TargetCpu::Cx16),
        Err(AccessError::MissingAtomicLoad16)
    );
    assert_eq!(
        read_footprint(0, QUADWORD_BYTES, TargetCpu::AtomicLoad16),
        Ok((0, SCA_BYTES))
    );
    // Declines occur before touching a deliberately inaccessible pointer.
    assert_eq!(
        unsafe {
            write_part(
                std::ptr::null_mut(),
                QUADWORD_BYTES,
                0,
                TargetCpu::AtomicLoad16,
            )
        },
        Err(AccessError::MissingCx16)
    );
}

#[test]
fn all_valid_offsets_preserve_neighbors_and_zero_extend_reads() {
    let target = TargetCpu::detect();
    let original = std::array::from_fn(|index| index as u8 * 13);
    let value = 0xfedc_ba98_7654_3210_1234_5678_9abc_def0u128;
    for bytes in [
        BYTE_BYTES,
        HALFWORD_BYTES,
        WORD_BYTES,
        DOUBLEWORD_BYTES,
        QUADWORD_BYTES,
    ] {
        for offset in 0..=SCA_BYTES - bytes {
            let mut memory = Quantity(original);
            let pointer = memory.0.as_mut_ptr().wrapping_add(offset);
            let footprint = read_footprint(pointer as usize, bytes, target);
            if footprint.is_ok() {
                let mut expected = [0u8; QUADWORD_BYTES];
                expected[..bytes].copy_from_slice(&original[offset..offset + bytes]);
                assert_eq!(
                    unsafe { read_part(pointer, bytes, target) }.unwrap(),
                    u128::from_le_bytes(expected)
                );
            } else {
                assert_eq!(footprint, Err(AccessError::MissingAtomicLoad16));
            }
            if bytes == QUADWORD_BYTES && !target.supports(TargetCpu::Cx16) {
                continue;
            }
            unsafe { write_part(pointer, bytes, value, target) }.unwrap();
            let mut expected = original;
            expected[offset..offset + bytes].copy_from_slice(&value.to_le_bytes()[..bytes]);
            assert_eq!(memory.0, expected, "width={bytes} offset={offset}");
            if footprint.is_ok() {
                let mask = u128::MAX >> ((QUADWORD_BYTES - bytes) * BITS_PER_BYTE);
                assert_eq!(
                    unsafe { read_part(pointer, bytes, target) }.unwrap(),
                    value & mask
                );
            }
        }
    }
}
#[test]
fn scalar_exchange_declines_invalid_widths_and_sca_crossings_before_access() {
    for bytes in [0, 3, 5, QUADWORD_BYTES, usize::MAX] {
        // Invalid shape must decline without reaching native memory.
        assert_eq!(
            unsafe { exchange_part(std::ptr::null_mut(), bytes, 0) },
            Err(AccessError::InvalidWidth)
        );
    }
    assert_eq!(
        unsafe { exchange_part((SCA_BYTES - 1) as *mut u8, HALFWORD_BYTES, 0) },
        Err(AccessError::CrossesScaQuantity)
    );
}

#[test]
fn scalar_exchange_returns_normalized_old_and_preserves_neighbors() {
    let original = std::array::from_fn(|index| u8::MAX - index as u8);
    let replacement = 0xfedc_ba98_7654_3210_1234_5678_9abc_def0_u128;
    for (bytes, offset) in [
        (BYTE_BYTES, DOUBLEWORD_BYTES - 1),
        (HALFWORD_BYTES, DOUBLEWORD_BYTES - 1),
        (WORD_BYTES, DOUBLEWORD_BYTES - 1),
        (DOUBLEWORD_BYTES, DOUBLEWORD_BYTES - 1),
    ] {
        let mut memory = Quantity(original);
        let pointer = memory.0.as_mut_ptr().wrapping_add(offset);
        let mut expected_old = [0_u8; QUADWORD_BYTES];
        expected_old[..bytes].copy_from_slice(&original[offset..offset + bytes]);
        // SAFETY: exact private live storage, no simultaneous aliases or
        // observers; the scalar part stays within one aligned SCA quantity.
        let old = unsafe { exchange_part(pointer, bytes, replacement) }.unwrap();
        assert_eq!(old, u128::from_le_bytes(expected_old));
        let mut expected = original;
        expected[offset..offset + bytes].copy_from_slice(&replacement.to_le_bytes()[..bytes]);
        assert_eq!(memory.0, expected, "width={bytes} offset={offset}");
    }
}
