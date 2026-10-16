use super::*;

fn command() -> Vec<u8> {
    let mut raw = vec![0; UNIX_THREAD_COMMAND_BYTES];
    for (offset, value) in [
        (COMMAND_ID_OFFSET, macho::LC_UNIXTHREAD),
        (COMMAND_SIZE_OFFSET, UNIX_THREAD_COMMAND_BYTES as u32),
        (FLAVOR_OFFSET, ARM_THREAD_STATE64_FLAVOR),
        (COUNT_OFFSET, ARM_THREAD_STATE64_WORDS),
    ] {
        raw[offset..offset + WORD_BYTES].copy_from_slice(&value.to_le_bytes());
    }
    for index in 0..ARM64_GPR_COUNT {
        let value = 0xfedc_ba98_7654_3210u64.rotate_left(index as u32);
        let offset = STATE_OFFSET + index * REGISTER_BYTES;
        raw[offset..offset + REGISTER_BYTES].copy_from_slice(&value.to_le_bytes());
    }
    raw[SP_OFFSET..SP_OFFSET + REGISTER_BYTES].copy_from_slice(&(u64::MAX - 7).to_le_bytes());
    raw[PC_OFFSET..PC_OFFSET + REGISTER_BYTES]
        .copy_from_slice(&0xffff_fe00_09eb_4480u64.to_le_bytes());
    raw[CPSR_OFFSET..CPSR_OFFSET + WORD_BYTES].copy_from_slice(&0xf123_4567u32.to_le_bytes());
    raw[PAD_OFFSET..PAD_OFFSET + WORD_BYTES].copy_from_slice(&0x89ab_cdefu32.to_le_bytes());
    raw
}

#[test]
fn preserves_original_fields_raw_identity_and_process_type_path() -> Result<()> {
    let raw = command();
    let thread: crate::load_plan::Arm64UnixThread = unix_thread(&raw)?;
    for index in 0..ARM64_GPR_COUNT {
        assert_eq!(
            thread.x[index],
            0xfedc_ba98_7654_3210u64.rotate_left(index as u32)
        );
    }
    assert_eq!(thread.sp, u64::MAX - 7);
    assert_eq!(thread.pc, 0xffff_fe00_09eb_4480);
    assert_eq!(thread.cpsr, 0xf123_4567);
    assert_eq!(thread.pad, 0x89ab_cdef);
    assert_eq!(thread.raw_command_sha256, sha256(&raw));
    assert_eq!(thread.raw_command_hex, hex::encode(&raw));
    Ok(())
}

#[test]
fn rejects_truncation_trailing_and_unreviewed_descriptors() {
    let raw = command();
    assert_eq!(
        unix_thread(&raw[..UNIX_THREAD_COMMAND_BYTES - 1])
            .unwrap_err()
            .to_string(),
        "LC_UNIXTHREAD requires exactly 288 bytes"
    );
    for length in 0..UNIX_THREAD_COMMAND_BYTES {
        assert!(unix_thread(&raw[..length]).is_err(), "length {length}");
    }
    let mut trailing = raw.clone();
    trailing.extend_from_slice(&[0; WORD_BYTES]);
    assert!(unix_thread(&trailing).is_err());
    for (offset, value) in [
        (COMMAND_ID_OFFSET, macho::LC_THREAD),
        (
            COMMAND_SIZE_OFFSET,
            (UNIX_THREAD_COMMAND_BYTES - WORD_BYTES) as u32,
        ),
        (FLAVOR_OFFSET, ARM_THREAD_STATE64_FLAVOR + 1),
        (COUNT_OFFSET, ARM_THREAD_STATE64_WORDS - 1),
    ] {
        let mut bad = raw.clone();
        bad[offset..offset + WORD_BYTES].copy_from_slice(&value.to_le_bytes());
        assert!(unix_thread(&bad).is_err());
    }
    let mut wrong_flavor = raw;
    wrong_flavor[FLAVOR_OFFSET..FLAVOR_OFFSET + WORD_BYTES]
        .copy_from_slice(&(ARM_THREAD_STATE64_FLAVOR + 1).to_le_bytes());
    assert_eq!(
        unix_thread(&wrong_flavor).unwrap_err().to_string(),
        "LC_UNIXTHREAD requires ARM_THREAD_STATE64 flavor 6/count 68"
    );
}
