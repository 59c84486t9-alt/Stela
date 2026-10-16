//! Run outcomes: why execution stopped and the service events it produced.
use crate::{memory, system};
#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};
use serde::Serialize;
use stela_compiler::{
    GuestAddress, GuestState,
    block::{
        ClockInstruction, PointerAuthentication, PointerAuthenticationKey, SynchronousTrap,
        SystemInstruction, ThreadRegisterInstruction,
    },
};

#[derive(Debug, Clone)]
pub struct ThreadState {
    pub registers: GuestState,
    pub pc: GuestAddress,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StopReason {
    Halted {
        instruction_pc: GuestAddress,
    },
    StopAddress,
    BudgetExhausted,
    UnmappedTarget,
    UnalignedTarget,
    TruncatedInstruction,
    NoncanonicalInstructionTarget {
        address: GuestAddress,
    },
    Unsupported {
        detail: String,
    },
    FloatingPointUnsupported {
        instruction_pc: GuestAddress,
        fpcr: u32,
        enabled_exceptions: u32,
    },
    SynchronousTrap {
        trap: SynchronousTrap,
    },
    PointerAuthenticationRequired {
        instruction: PointerAuthentication,
    },
    PointerAuthenticationUnsupported {
        instruction: PointerAuthentication,
        detail: String,
    },
    PointerAuthenticationKeyUnavailable {
        instruction: PointerAuthentication,
        key: PointerAuthenticationKey,
    },
    PointerAuthenticationGenericKeyUnavailable {
        instruction: PointerAuthentication,
    },
    /// FPAC/FPACCOMBINE raised an authentication failure before committing
    /// destinations or the link register. Exception delivery belongs to the CPU owner.
    PointerAuthenticationFailure {
        instruction: PointerAuthentication,
        code: u8,
    },
    PointerAuthenticationLoadUndefined {
        instruction: PointerAuthentication,
    },
    PointerAuthenticationStackAlignment {
        instruction: PointerAuthentication,
        stack_pointer: u64,
    },
    PointerAuthenticationMemoryRequired {
        instruction: PointerAuthentication,
    },
    PointerAuthenticationMemoryFault {
        instruction: PointerAuthentication,
        fault: memory::domain::MemoryFault,
    },
    /// A nonfaulting PAuth check produced an invalid return target. No target instruction executed;
    /// guest instruction-fetch exception delivery remains the caller's work.
    PointerAuthenticationPoisonedReturn {
        instruction: PointerAuthentication,
        poisoned_target: GuestAddress,
    },
    /// A nonfaulting PAuth check produced an invalid branch/call target before fetch.
    PointerAuthenticationPoisonedBranch {
        instruction: PointerAuthentication,
        poisoned_target: GuestAddress,
    },
    ThreadRegisterRequired {
        instruction: ThreadRegisterInstruction,
    },
    SystemContextRequired {
        instruction_pc: GuestAddress,
    },
    SystemEntryFailure {
        instruction_pc: GuestAddress,
        word: u32,
        failure: system::execution::Failure,
    },
    SystemFailure {
        instruction: SystemInstruction,
        failure: system::execution::Failure,
    },
    ClockRequired {
        instruction: ClockInstruction,
    },
    ClockUnavailable {
        instruction: ClockInstruction,
        detail: String,
    },
}

#[derive(Debug, Serialize)]
pub struct PointerAuthenticationEvent {
    pub instruction: PointerAuthentication,
    pub next_pc: GuestAddress,
    /// None for signing; AUT and RET report whether authentication succeeded.
    pub authenticated: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct ClockEvent {
    pub instruction: ClockInstruction,
    pub next_pc: GuestAddress,
    /// ISB does not consume a clock sample. MRS XZR still reads/publishes one.
    pub counter: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct ThreadRegisterEvent {
    pub instruction: ThreadRegisterInstruction,
    pub next_pc: GuestAddress,
    pub value: u64,
}

#[derive(Debug, Serialize)]
pub struct RunOutcome {
    pub reason: StopReason,
    /// Completed blocks, including iterations of resident loops.
    pub blocks_executed: usize,
    pub compiled_blocks: usize,
    pub disk_cache_hits: usize,
    pub memory_cache_hits: usize,
    pub last_exit: Option<(u64, u64)>,
    /// Successful numerical slowpath completions; no per-instruction event allocation.
    pub floating_point_helpers: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub pointer_authentication_events: Vec<PointerAuthenticationEvent>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub clock_events: Vec<ClockEvent>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub thread_register_events: Vec<ThreadRegisterEvent>,
}
