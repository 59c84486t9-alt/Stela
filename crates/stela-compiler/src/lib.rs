//! Ahead-of-time native translation of supported Apple-silicon ARM64 semantics.
//! Unsupported instructions are errors; no interpreter fallback is emitted.

pub mod aarch64;
pub mod block;
pub mod x86_64;

use serde::{Deserialize, Serialize};

/// Bind cached code and evidence to compiler implementation and dependencies.
pub const SOURCE_FINGERPRINT_MATERIAL: &str = concat!(
    include_str!("lib.rs"),
    include_str!("aarch64.rs"),
    include_str!("x86_64.rs"),
    include_str!("block.rs"),
    include_str!("x86_64/block.rs"),
    include_str!("aarch64/conditional_select.rs"),
    include_str!("x86_64/conditional_select.rs"),
    include_str!("aarch64/multiply.rs"),
    include_str!("x86_64/multiply.rs"),
    include_str!("aarch64/register_offset.rs"),
    include_str!("x86_64/register_offset.rs"),
    include_str!("../Cargo.toml"),
    include_str!("../../../Cargo.lock"),
);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestAddress(pub u64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnsupportedReason {
    Instruction {
        address: GuestAddress,
        encoding: u32,
    },
    PrivilegedOperation {
        address: GuestAddress,
    },
    PointerAuthentication {
        address: GuestAddress,
    },
    UnresolvedIndirectTarget {
        address: GuestAddress,
    },
    UnresolvedDirectTarget {
        address: GuestAddress,
        target: GuestAddress,
    },
    RuntimeGeneratedCode,
}

/// A lifted instruction must describe architectural effects, not just syntax.
pub trait Lifter {
    type Instruction;
    fn lift(&self, pc: GuestAddress, encoding: u32)
    -> Result<Self::Instruction, UnsupportedReason>;
}

/// Emission must retain guest addresses for faults, debugging and evidence.
#[derive(Debug, Serialize, Deserialize)]
pub struct NativeBlock {
    pub x86_64_code: Vec<u8>,
    pub source_map: Vec<(GuestAddress, usize)>,
}

/// Native code requires the direct ordinary-RAM profile documented in compiler.md.
pub const NATIVE_ABI: &str = "x86_64-sysv-guest-state-v2-direct-ram";

/// Native ABI v2: System V x86-64 `void function(GuestState *state)`.
/// Registers are initially memory-backed; register allocation is future work.
/// Only NZCV bits 31:28 are modeled, not the complete PSTATE register.
#[repr(C)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GuestState {
    pub x: [u64; 31],
    pub sp: u64,
    pub nzcv: u32,
    pub reserved: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileError(pub String);

impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for CompileError {}

/// Compile one raw ARM64 leaf region ending in RET X30.
/// Input addresses are retained in the output map. No Mach-O loading, external
/// calls, PAC, privileged operations, or arbitrary RET targets.
pub fn compile(code: &[u8], base: GuestAddress) -> Result<NativeBlock, CompileError> {
    if code.is_empty() || !code.len().is_multiple_of(4) || !base.0.is_multiple_of(4) {
        return Err(CompileError(
            "input and guest base must be nonempty/aligned to 4 bytes".into(),
        ));
    }
    let mut instructions = vec![];
    for (index, bytes) in code.as_chunks::<4>().0.iter().enumerate() {
        let pc = GuestAddress(
            base.0
                .checked_add((index as u64) * 4)
                .ok_or_else(|| CompileError("guest address overflow".into()))?,
        );
        let encoding = u32::from_le_bytes(*bytes);
        let instruction = aarch64::Decoder
            .lift(pc, encoding)
            .map_err(|e| CompileError(format!("unsupported ARM64 semantics: {e:?}")))?;
        instructions.push(instruction);
    }
    if !matches!(
        instructions.last().unwrap().operation,
        aarch64::Operation::Return
    ) {
        return Err(CompileError("leaf region must end in RET X30".into()));
    }
    x86_64::Emitter
        .emit(&instructions)
        .map_err(|e| CompileError(format!("x86 emission failed: {e:?}")))
}

pub trait Backend<I> {
    fn emit(&self, instructions: &[I]) -> Result<NativeBlock, UnsupportedReason>;
}

/// Platform adaptation is separate from instruction translation.
pub mod platform {
    #[derive(Debug)]
    pub enum Requirement {
        MachTraps,
        BsdSyscalls,
        ThreadState,
        ExceptionDelivery,
        VirtualMemory,
        DynamicLinking,
        KernelBoot,
        Interrupts,
        Graphics,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn guest_state_layout_is_the_native_abi() {
        assert_eq!(std::mem::size_of::<GuestState>(), 264);
        assert_eq!(std::mem::offset_of!(GuestState, sp), 248);
        assert_eq!(std::mem::offset_of!(GuestState, nzcv), 256);
    }
    #[test]
    fn rejects_unknown_instructions_bad_boundaries_and_address_overflow() {
        for words in [
            vec![],
            vec![0xd503201fu32],
            vec![0x14000002, 0xd65f03c0], // branch falls outside the region
            vec![0xf9800000, 0xd65f03c0], // PRFM is not a data load
            vec![0xd65f0000],
        ] {
            let bytes: Vec<_> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
            assert!(compile(&bytes, GuestAddress(0)).is_err());
        }
        assert!(compile(&[0, 0, 0], GuestAddress(0)).is_err());
        assert!(compile(&0xd65f03c0u32.to_le_bytes(), GuestAddress(1)).is_err());
        let code: Vec<_> = [0xd503201fu32, 0xd65f03c0]
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        assert!(compile(&code, GuestAddress(u64::MAX - 3)).is_err());
    }
}
