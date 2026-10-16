//! Apple AMX matrix-coprocessor instructions, M2 generation (Avalanche/Blizzard,
//! T8112).
//!
//! AMX is undocumented. The semantics follow the hardware-tested emulator of
//! [corsix/amx](https://github.com/corsix/amx/tree/483714bb051da088d08a66724b22dd08a5db3c99)
//! with `AMX_VER == AMX_VER_M2`, ported in [`model`] under its MIT license
//! (`LICENSES/corsix-amx.txt`). M1-only behavior and the M3/M4 changes
//! (non-consecutive loads, `matint` mode 12 widening, aligned X/Y offsets) are
//! not part of this generation. The research record is `docs/research/amx.md`.
//!
//! Instructions occupy the reserved A64 space `0x00201000 + (operation << 5) +
//! operand`. Operation 17 takes a five-bit immediate (`set` 0, `clr` 1); every
//! other operation reads a 64-bit operand from a general-purpose register, with
//! X31 reading zero. No AMX instruction writes a general-purpose register,
//! NZCV, FPCR or FPSR.
pub mod decode;
pub mod model;
pub mod state;

pub use decode::{AmxInstruction, AmxOperand, AmxOperation, decode};
pub use state::AmxRegisters;

/// The AMX generation of a declared CPU profile. Only M2 is implemented.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Generation {
    M2,
}
