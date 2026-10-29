//! Immutable CPU implementation register offsets; no lock ownership.
pub const BYTES: u64 = 16;
pub const WORD_BYTES: u64 = 8;
pub const CPU_PIO_TRACE_CORE_CFG: u64 = 1 << 54;
const RVBAR: u64 = 0;
pub const CPU_STS: u64 = 0x100;
pub const CORE_THRTL_CFG2: u64 = 0x218;
pub const PE_WORDS: [u64; 3] = [RVBAR, CPU_STS, CORE_THRTL_CFG2];
pub const CPU_STS_RUNNING: u64 = 1;
