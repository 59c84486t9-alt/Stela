//! Mach-O ARM thread-state load commands.
use crate::Result;
use alloc::string::String;
use object::macho;
use serde::Serialize;
use stela_contracts::require;
use stela_formats::sha256;

const WORD_BYTES: usize = core::mem::size_of::<u32>();
const REGISTER_BYTES: usize = core::mem::size_of::<u64>();
const ARM64_GPR_COUNT: usize = 31;
const ARM_THREAD_STATE64_FLAVOR: u32 = 6;
const ARM_THREAD_STATE64_WORDS: u32 = 68;
const COMMAND_ID_OFFSET: usize = 0;
const COMMAND_SIZE_OFFSET: usize = WORD_BYTES;
const FLAVOR_OFFSET: usize = COMMAND_SIZE_OFFSET + WORD_BYTES;
const COUNT_OFFSET: usize = FLAVOR_OFFSET + WORD_BYTES;
const STATE_OFFSET: usize = COUNT_OFFSET + WORD_BYTES;
const SP_OFFSET: usize = STATE_OFFSET + ARM64_GPR_COUNT * REGISTER_BYTES;
const PC_OFFSET: usize = SP_OFFSET + REGISTER_BYTES;
const CPSR_OFFSET: usize = PC_OFFSET + REGISTER_BYTES;
const PAD_OFFSET: usize = CPSR_OFFSET + WORD_BYTES;
const UNIX_THREAD_COMMAND_BYTES: usize =
    STATE_OFFSET + ARM_THREAD_STATE64_WORDS as usize * WORD_BYTES;

/// Original ARM_THREAD_STATE64 descriptor, not a live execution context.
/// PC keeps its image-linked virtual address. Serialized x0, SP and CPSR do
/// not establish process arguments, a physical entry address or firmware state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Arm64UnixThread {
    pub x: [u64; ARM64_GPR_COUNT],
    pub sp: u64,
    pub pc: u64,
    pub cpsr: u32,
    pub pad: u32,
    pub flavor: u32,
    pub count: u32,
    pub raw_command_sha256: String,
    pub raw_command_hex: String,
}

pub(super) fn unix_thread(raw: &[u8]) -> Result<Arm64UnixThread> {
    require!(
        raw.len() == UNIX_THREAD_COMMAND_BYTES,
        "LC_UNIXTHREAD requires exactly {UNIX_THREAD_COMMAND_BYTES} bytes",
        UNIX_THREAD_COMMAND_BYTES
    );
    // The exact command extent above covers every fixed ABI offset below.
    let word = |offset| u32::from_le_bytes(raw[offset..offset + WORD_BYTES].try_into().unwrap());
    require!(
        word(COMMAND_ID_OFFSET) == macho::LC_UNIXTHREAD,
        "expected LC_UNIXTHREAD"
    );
    require!(
        word(COMMAND_SIZE_OFFSET) as usize == UNIX_THREAD_COMMAND_BYTES,
        "LC_UNIXTHREAD command size disagrees with its byte extent"
    );
    let flavor = word(FLAVOR_OFFSET);
    let count = word(COUNT_OFFSET);
    require!(
        flavor == ARM_THREAD_STATE64_FLAVOR && count == ARM_THREAD_STATE64_WORDS,
        "LC_UNIXTHREAD requires ARM_THREAD_STATE64 flavor {ARM_THREAD_STATE64_FLAVOR}/count {ARM_THREAD_STATE64_WORDS}",
        ARM_THREAD_STATE64_FLAVOR,
        ARM_THREAD_STATE64_WORDS
    );
    let register =
        |offset| u64::from_le_bytes(raw[offset..offset + REGISTER_BYTES].try_into().unwrap());
    Ok(Arm64UnixThread {
        x: core::array::from_fn(|index| register(STATE_OFFSET + index * REGISTER_BYTES)),
        sp: register(SP_OFFSET),
        pc: register(PC_OFFSET),
        cpsr: word(CPSR_OFFSET),
        pad: word(PAD_OFFSET),
        flavor,
        count,
        raw_command_sha256: sha256(raw),
        raw_command_hex: hex::encode(raw),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

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
}
