//! Guest register state, shared by hosted and freestanding execution.

/// Native code requires the direct ordinary-RAM profile documented in compiler.md.
pub const NATIVE_ABI: &str = "x86_64-sysv-guest-state-v3-direct-ram";

/// Native ABI v3: System V x86-64 `void function(GuestState *state)`. Registers
/// enter and leave native code in this layout. Only NZCV bits 31:28 of PSTATE
/// are held here. V registers are little-endian pairs of 64-bit halves.
/// Arithmetic preserves unrelated FPCR/FPSR bits, and register accesses apply
/// the declared field masks; saturating integer SIMD sets QC and floating-point
/// arithmetic accumulates exception flags.
#[repr(C)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GuestState {
    pub x: [u64; 31],
    pub sp: u64,
    pub nzcv: u32,
    pub reserved: u32,
    pub v: [[u64; 2]; 32],
    pub fpcr: u32,
    pub fpsr: u32,
}

#[cfg(test)]
mod tests;
