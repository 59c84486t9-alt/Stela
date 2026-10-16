//! Guest register state shared by hosted and freestanding execution.
#![no_std]

/// Native code requires the direct ordinary-RAM profile documented in compiler.md.
pub const NATIVE_ABI: &str = "x86_64-sysv-guest-state-v3-direct-ram";

/// Native ABI v3: System V x86-64 `void function(GuestState *state)`.
/// Registers enter and leave native calls in this canonical memory layout.
/// Only NZCV bits 31:28 are modeled, not the complete PSTATE register.
/// V registers are little-endian low/high 64-bit limbs. Arithmetic preserves
/// unrelated FPCR/FPSR bits; architectural register accesses apply the declared
/// field masks. Saturating integer SIMD updates QC and numerical FP accumulates
/// exception status. The state layout itself grants no instruction support.
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
