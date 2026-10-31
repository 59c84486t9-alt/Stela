//! Startup validation of this private host's real context entry/recovery.
//! The translated GPR/faulting-service source and deliberate native UD2 fixture
//! test host ABI ownership only; they do not admit guest SMP or RAM mappings.
use crate::Result;
use core::{arch::naked_asm, ptr};
use stela_compiler::{
    GuestAddress, GuestState, TargetCpu,
    block::{BlockProfile, CheckedMemoryProfile, CompilationPlan, ExitKind},
    context::{
        ExecutionContext,
        memory::{
            MEMORY_CONTEXT_BYTES, MEMORY_CONTEXT_VERSION, MemoryContextView, MemoryRequest,
            MemoryStatus,
        },
    },
};
use stela_contracts::refuse;
use stela_engine::machine::FaultCause;
use stela_engine::machine::Host;
use stela_engine::machine::NativeExit;

const BASE: u64 = 0x4000;
const ADD_X0: u32 = 0x9100_0400;
const ADD_X2: u32 = 0x9100_0442;
const LOAD_X1: u32 = 0xf940_0001;
const RET: u32 = 0xd65f_03c0;
const UD2: [u8; 2] = [0x0f, 0x0b];

unsafe extern "sysv64" fn reject(
    context: *mut MemoryContextView,
    request: *const MemoryRequest,
) -> u32 {
    // SAFETY: check() exclusively pins this private view/request/counter through
    // the native call. No guest-memory reference or success is exposed.
    unsafe {
        let context = &mut *context;
        let request = &*request;
        *context.opaque.cast::<u64>() += 1;
        context.record(MemoryStatus::Unsupported, request.address, request.pc, 0);
    }
    MemoryStatus::Unsupported as u32
}

// Check the ABI entry stack before a Rust prologue changes it. The tail
// jump preserves the exact context/request arguments and normal return address.
#[unsafe(naked)]
unsafe extern "sysv64" fn aligned_reject(
    _: *mut MemoryContextView,
    _: *const MemoryRequest,
) -> u32 {
    naked_asm!(
        "mov rax, rsp",
        "and eax, 15",
        "cmp eax, 8",
        "jne 2f",
        "jmp {reject}",
        "2: mov eax, {domain}",
        "ret",
        reject = sym reject,
        domain = const MemoryStatus::Domain as u32,
    );
}

fn compile(words: &[u32]) -> Result<stela_compiler::block::CompiledBlock> {
    let source: alloc::vec::Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    let plan = CompilationPlan::new(
        &source,
        GuestAddress(BASE),
        &stela_compiler::Options::new(
            BlockProfile::ORDINARY.with_checked_memory(CheckedMemoryProfile::SpAlignmentDisabled),
            TargetCpu::Baseline,
        ),
    )
    .map_err(|_| refuse!("native context fixture source refused"))?;
    if plan.source_bytes() != source.len() {
        return Err(refuse!("native context fixture trailing source"));
    }
    plan.compile()
        .map_err(|_| refuse!("native context fixture emission refused"))
}

/// Run before any artifact/guest loan is published on this private Host.
/// All private frames/views/code remain alive until true fault/return checks;
/// installed fixtures are discarded only after their last use.
pub(super) fn check(host: &mut dyn Host) -> Result<()> {
    let mut state = GuestState {
        x: core::array::from_fn(|i| 0x100 + i as u64),
        sp: 0x8000,
        nzcv: 0xa000_0000,
        exclusive_bytes: 0x1234,
        exclusive_address: 0,
        exclusive_value: 0,
        daif: 0,
        pending: 0,
        v: core::array::from_fn(|i| [i as u64, !(i as u64)]),
        fpcr: 0x400000,
        fpsr: 0x8000000,
    };
    state.x[30] = 0x9000;
    let before = state.clone();
    let mut calls = 0u64;
    let mut view = MemoryContextView {
        version: MEMORY_CONTEXT_VERSION,
        bytes: MEMORY_CONTEXT_BYTES,
        callback: aligned_reject,
        opaque: ptr::from_mut(&mut calls).cast(),
        fault_kind: 0,
        fault_access: 0,
        fault_address: 0,
        fault_pc: 0,
        completed_bytes: 0,
        reserved_tail: 0,
    };
    let mut context = ExecutionContext {
        memory: ptr::from_mut(&mut view).cast(),
        ..ExecutionContext::default()
    };
    let body = compile(&[ADD_X0, RET])?;
    let code = host
        .install(&body.native.x86_64_code)
        .map_err(|_| refuse!("native context arena full"))?;
    // SAFETY: exact compiler-derived context-block ABI/target, pinned private
    // state/context/service owners and this same physical Host throughout.
    let result = unsafe { host.execute_context(code, &mut state, &mut context) };
    let mut expected = before;
    expected.x[0] += 1;
    if result
        != Some(NativeExit::Exit {
            next_pc: expected.x[30],
            kind: ExitKind::Return as u64,
        })
        || state != expected
        || calls != 0
        || view.fault_kind != 0
    {
        return Err(refuse!("native context register return differs"));
    }
    let faulting = compile(&[ADD_X2, LOAD_X1, RET])?;
    let faulting_code = host
        .install(&faulting.native.x86_64_code)
        .map_err(|_| refuse!("native context arena full"))?;
    // SAFETY: same exact compiler ABI; the only callback explicitly refuses.
    let result = unsafe { host.execute_context(faulting_code, &mut state, &mut context) };
    expected.x[2] += 1;
    // On service failure the checked ABI returns the status in RAX; RDX
    // has no architectural exit-kind meaning until the fault view is settled.
    if !matches!(result, Some(NativeExit::Exit { next_pc, .. }) if next_pc == MemoryStatus::Unsupported as u64)
        || state != expected
        || calls != 1
        || view.fault_kind != MemoryStatus::Unsupported as u32
        || view.fault_pc != BASE + 4
        || view.fault_address != expected.x[0]
        || view.fault_access != 0
        || view.completed_bytes != 0
        || !view.has_supported_header()
    {
        return Err(refuse!(
            "native context service stack or precise refusal differs"
        ));
    }
    // This deliberate x86 hardware-fault fixture accepts the same two input
    // arguments and never returns normally. It is not a translated ARM opcode,
    // cached artifact or a production NativeFrame constructor.
    let trap = host
        .install(&UD2)
        .map_err(|_| refuse!("native context arena full"))?;
    let state_pointer = ptr::from_mut(&mut state) as u64;
    let context_pointer = ptr::from_mut(&mut context) as u64;
    // SAFETY: private installed fault-only context fixture, valid pinned inputs;
    // this Host's native recovery path is the expected outcome.
    let result = unsafe { host.execute_context(trap, &mut state, &mut context) };
    if !matches!(result, Some(NativeExit::Fault(fault)) if fault.offset == 0
        && fault.cause == FaultCause::InvalidOpcode && !fault.write && fault.address == 0
        && fault.registers.get(7) == Some(state_pointer) && fault.registers.get(6) == Some(context_pointer))
        || state != expected
    {
        return Err(refuse!("native context hardware recovery differs"));
    }
    view.record(MemoryStatus::Success, 0, 0, 0);
    // SAFETY: same artifact/frame; proves recovery did not lose the
    // owner-local stack or leave a stale native-fault observation behind.
    let result = unsafe { host.execute_context(code, &mut state, &mut context) };
    expected.x[0] += 1;
    if result
        != Some(NativeExit::Exit {
            next_pc: expected.x[30],
            kind: ExitKind::Return as u64,
        })
        || state != expected
        || calls != 1
    {
        return Err(refuse!("native context reentry after fault differs"));
    }
    host.discard_code();
    Ok(())
}
