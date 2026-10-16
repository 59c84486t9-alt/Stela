//! Original Mach-O ARM thread descriptors, without process or firmware policy.
use anyhow::{Result, ensure};
use object::macho;
use serde::Serialize;
use stela_core::sha256;

const WORD_BYTES: usize = std::mem::size_of::<u32>();
const REGISTER_BYTES: usize = std::mem::size_of::<u64>();
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
/// PC retains its image-linked virtual address. Serialized x0, SP and CPSR do
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
    ensure!(
        raw.len() == UNIX_THREAD_COMMAND_BYTES,
        "LC_UNIXTHREAD requires exactly {UNIX_THREAD_COMMAND_BYTES} bytes"
    );
    // The exact command extent above covers every fixed ABI offset below.
    let word = |offset| u32::from_le_bytes(raw[offset..offset + WORD_BYTES].try_into().unwrap());
    ensure!(
        word(COMMAND_ID_OFFSET) == macho::LC_UNIXTHREAD,
        "expected LC_UNIXTHREAD"
    );
    ensure!(
        word(COMMAND_SIZE_OFFSET) as usize == UNIX_THREAD_COMMAND_BYTES,
        "LC_UNIXTHREAD command size disagrees with its byte extent"
    );
    let flavor = word(FLAVOR_OFFSET);
    let count = word(COUNT_OFFSET);
    ensure!(
        flavor == ARM_THREAD_STATE64_FLAVOR && count == ARM_THREAD_STATE64_WORDS,
        "LC_UNIXTHREAD requires ARM_THREAD_STATE64 flavor {ARM_THREAD_STATE64_FLAVOR}/count {ARM_THREAD_STATE64_WORDS}"
    );
    let register =
        |offset| u64::from_le_bytes(raw[offset..offset + REGISTER_BYTES].try_into().unwrap());
    Ok(Arm64UnixThread {
        x: std::array::from_fn(|index| register(STATE_OFFSET + index * REGISTER_BYTES)),
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
mod tests;
