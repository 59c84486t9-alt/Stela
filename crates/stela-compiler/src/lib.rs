//! Compiler contracts. No ARM instruction is claimed translated yet.
//! Keep unsupported semantics explicit instead of silently emitting NOPs.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    RuntimeGeneratedCode,
}

/// A lifted instruction must describe architectural effects, not just syntax.
pub trait Lifter {
    type Instruction;
    fn lift(&self, pc: GuestAddress, encoding: u32)
    -> Result<Self::Instruction, UnsupportedReason>;
}

/// Emission must retain guest addresses for faults, debugging and evidence.
pub struct NativeBlock {
    pub x86_64_code: Vec<u8>,
    pub source_map: Vec<(GuestAddress, usize)>,
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
