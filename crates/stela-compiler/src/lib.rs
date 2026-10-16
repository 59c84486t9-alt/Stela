//! Ahead-of-time native translation of supported Apple-silicon ARM64 semantics.
//! Unsupported instructions are errors; no interpreter fallback is emitted.
#![no_std]

extern crate alloc;
#[cfg(any(feature = "std", test))]
extern crate std;

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
pub mod aarch64;
pub mod block;
pub mod context;
pub mod extended;
mod target;
pub mod x86_64;

pub use stela_state::{GuestState, NATIVE_ABI};
pub use target::TargetCpu;

use serde::{Deserialize, Serialize};

/// SHA-256 of the compiler and guest-state sources; binds cached native code.
pub const SOURCE_SHA256: &str = env!("STELA_COMPILER_SOURCE_SHA256");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestAddress(pub u64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnsupportedReason {
    HostCapabilityRequired {
        address: GuestAddress,
        required: TargetCpu,
    },
    NumericalRuntimeRequired {
        address: GuestAddress,
    },
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileError(pub String);

impl core::fmt::Display for CompileError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}
impl core::error::Error for CompileError {}

/// Compile one raw ARM64 leaf region ending in RET X30.
/// Input addresses are retained in the output map. No Mach-O loading, external
/// calls, PAC, privileged operations, or arbitrary RET targets.
pub fn compile(code: &[u8], base: GuestAddress) -> Result<NativeBlock, CompileError> {
    compile_for_target(code, base, TargetCpu::Baseline)
}
pub fn compile_for_target(
    code: &[u8],
    base: GuestAddress,
    target: TargetCpu,
) -> Result<NativeBlock, CompileError> {
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
        .emit_for_target(&instructions, target)
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
mod tests;
