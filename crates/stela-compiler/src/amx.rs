//! Apple AMX matrix-coprocessor instructions, M1 and M2 generations.
//!
//! AMX is undocumented. The semantics follow the hardware-tested emulator of
//! [corsix/amx](https://github.com/corsix/amx/tree/483714bb051da088d08a66724b22dd08a5db3c99)
//! with `AMX_VER_M1` or `AMX_VER_M2`, ported in [`model`] under its MIT license
//! (`LICENSES/corsix-amx.txt`). The M3/M4 changes
//! (non-consecutive loads, `matint` mode 12 widening, aligned X/Y offsets) are
//! not part of these generations. The research record is `docs/research/amx.md`.
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

/// A source-qualified AMX semantic generation. Later generations are not
/// representable: no generation-label fallback to M2 is authorized.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Generation {
    M1,
    M2,
}

impl Generation {
    /// The pinned reference's generation selector, not a hardware ID register.
    pub const fn reference_version(self) -> u32 {
        match self {
            Self::M1 => 1,
            Self::M2 => 2,
        }
    }

    /// The complete M2 additions qualified by the pinned reference model.
    pub(crate) const fn m2_extensions(self) -> bool {
        matches!(self, Self::M2)
    }
}
