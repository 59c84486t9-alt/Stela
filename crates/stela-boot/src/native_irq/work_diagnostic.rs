//! Opt-in EDU MSI → preallocated queue → owned BSP work stack.
//! Device/config/Executor ownership stays !Send on the BSP. The ISR receives
//! only the existing bounded IRQ register access plus Send+Sync queue/events.
//! No production OSL/SCI/provider capability is installed.
use super::diagnostic::{self, Edu, EduSource};
use crate::Result;
use alloc::{boxed::Box, format, rc::Rc, string::String, sync::Arc, vec::Vec};
use core::{
    alloc::{GlobalAlloc, Layout},
    arch::{asm, naked_asm},
    ffi::c_void,
    ops::Range,
    sync::atomic::{AtomicPtr, AtomicU64, AtomicUsize, Ordering},
};
use stela_contracts::refuse;
use stela_drivers::{
    Clock,
    bus::{
        irq::{Disposition, Handler, IrqError, Platform, Route, RouteRequest, Source},
        pci::{Function as PciFunction, owned::OwnedConfig},
    },
    platform::work::{Cpu, Executor, Kind, Queue, WorkError},
};
const IF: u64 = 1 << 9;
const TIMEOUT_US: u64 = 2_000_000;
const BAD_ISR_ID: u64 = 1;
const BAD_INTERRUPTED_SP: u64 = 2;
const BAD_ISR_SP: u64 = 4;
const BAD_ADMISSION: u64 = 8;
const BAD_INLINE: u64 = 16;
const BAD_WORKER: u64 = 32;
const BAD_ASYNC_STATE: u64 = 64;
const BAD_IRQ_HEAP: u64 = 128;
struct BspCpu;
// SAFETY: source-bound one-BSP fixture. Registered dispatch
// brackets depth from unchanged IDT entry, including its real saved Frame.rsp.
// Only that ISR and kept owned process callbacks receive this adapter.
// This does not check other CPU entry paths or production ISR FP preservation.
unsafe impl Cpu for BspCpu {
    fn check_cpu(&self) -> Result<(), WorkError> {
        super::NativePlatform(())
            .check_cpu()
            .map_err(|_| WorkError::WrongCpu)
    }
    fn in_interrupt(&self) -> bool {
        super::current_context().map_or(true, |c| c.is_some())
    }
    fn save_disable(&self) -> Result<u64, WorkError> {
        self.check_cpu()?;
        let flags;
        // SAFETY: saves RFLAGS and masks interrupts on this CPU; `restore` undoes it.
        unsafe {
            asm!("pushfq", "pop {}", "cli", out(reg) flags);
        }
        Ok(flags)
    }
    unsafe fn restore(&self, flags: u64) {
        // SAFETY: the caller passes flags `save_disable` read on this CPU.
        unsafe {
            asm!("push {}", "popfq", in(reg) flags);
        }
    }
    fn ticks(&self) -> u64 {
        crate::apic::rdtsc()
    }
    fn fatal(&self, error: WorkError) -> ! {
        crate::output::arguments(format_args!("NATIVE IRQ WORK FATAL {error:?}\n"));
        crate::output::fatal("native IRQ work retained after context failure")
    }
}
struct Events {
    // This is a nonowning pointer to a Send+Sync queue, never a !Send device or
    // Runtime. The executor/source/IRQ handle keep its Arc throughout
    // every admitted callback, retirement, and uncertain quarantine.
    queue: AtomicPtr<Queue<16>>,
    edu: Arc<Edu>,
    spans: Vec<Range<usize>>,
    deadline: AtomicU64,
    delivered: AtomicU64,
    worker: AtomicU64,
    foreground: AtomicU64,
    worker_id: AtomicU64,
    worker_rsp: AtomicUsize,
    interrupted_rsp: AtomicUsize,
    isr_rsp: AtomicUsize,
    errors: AtomicU64,
    async_observation: [AtomicU64; 4],
}
impl Events {
    unsafe fn queue(&self) -> &Queue<16> {
        // SAFETY: callers run only while the published queue is held by its executor and
        // handler.
        unsafe { &*self.queue.load(Ordering::Acquire) }
    }
    fn bad(&self, bits: u64) {
        self.errors.fetch_or(bits, Ordering::Relaxed);
    }
}
struct WorkHandler {
    queue: Arc<Queue<16>>,
    events: Arc<Events>,
}
impl Handler for WorkHandler {
    fn handle(&self) -> Disposition {
        // Asynchronous IRQ mutation: the common entry, not a promise
        // about inspected Rust code avoiding SIMD, must restore the caller.
        // SAFETY: the IRQ entry saved the interrupted FP state and restores it on return.
        unsafe { poison_irq_fp() };
        // Reuse the existing cause/W1C/readback handler. Registry emits
        // EOI after this whole callback and its context scope finish.
        let disposition = self.events.edu.handle();
        if !heap_probe(0) {
            self.events.bad(BAD_IRQ_HEAP);
        }
        if self.queue.current_id() != Err(WorkError::InterruptContext) {
            self.events.bad(BAD_ISR_ID);
        }
        match super::current_context() {
            Ok(Some(frame)) if frame.depth == 1 => {
                let sp = frame.interrupted_rsp.unwrap_or(0);
                self.events.interrupted_rsp.store(sp, Ordering::Relaxed);
                if !self.events.spans[0].contains(&sp) {
                    self.events.bad(BAD_INTERRUPTED_SP);
                }
            }
            _ => self.events.bad(BAD_INTERRUPTED_SP),
        }
        let sp = stack_pointer();
        self.events.isr_rsp.store(sp, Ordering::Relaxed);
        if self.events.spans.iter().any(|s| s.contains(&sp)) {
            self.events.bad(BAD_ISR_SP);
        }
        let before = self.events.worker.load(Ordering::Acquire);
        // SAFETY: queue/provider and callback context are held;
        // only a bounded event is submitted, with no CPU-affine owner erasure.
        if unsafe {
            self.queue.execute(
                Kind::General,
                deferred,
                Arc::as_ptr(&self.events) as *mut c_void,
            )
        }
        .is_err()
        {
            self.events.bad(BAD_ADMISSION);
        }
        if self.events.worker.load(Ordering::Acquire) != before {
            self.events.bad(BAD_INLINE);
        }
        self.events.delivered.fetch_add(1, Ordering::Release);
        disposition
    }
}
// Rc<Executor> makes the config/device/work owner !Send. It
// is held in the checked BSP registry; no unsafe Send/Sync implementation.
struct WorkSource {
    inner: EduSource,
    executor: Rc<Executor<16>>,
    events: Arc<Events>,
    clock: Clock,
}
// SAFETY: exact stopped EDU grant inherited after real DMA/IOTLB/TEoff ACK.
// Both quiescence phases keep the device and executor while draining;
// failed hardware/work/metadata checks leave the complete registration kept.
unsafe impl Source for WorkSource {
    fn mask(&mut self) -> Result<(), IrqError> {
        self.inner.mask()
    }
    fn route(&self) -> RouteRequest {
        self.inner.route()
    }
    unsafe fn program(&mut self, route: Route) -> Result<(), IrqError> {
        // SAFETY: forwards the registry's own call under the same contract.
        unsafe { self.inner.program(route) }
    }
    unsafe fn unmask(&mut self) -> Result<(), IrqError> {
        // SAFETY: forwards the registry's own call under the same contract.
        unsafe { self.inner.unmask() }
    }
    fn quiesce(&mut self) -> Result<(), IrqError> {
        self.inner.quiesce()?;
        if self.events.errors.load(Ordering::Acquire) != 0 {
            return Err(IrqError::Quiesce);
        }
        self.executor
            .runtime()
            .drain(deadline(self.clock).map_err(|_| IrqError::Drain)?)
            .map_err(|_| IrqError::Drain)
    }
    unsafe fn synchronize(&mut self) -> Result<(), IrqError> {
        // SAFETY: forwards the registry's own call under the same contract.
        unsafe { self.inner.synchronize() }?;
        self.executor
            .runtime()
            .queue()
            .close()
            .map_err(|_| IrqError::Drain)?;
        self.executor
            .runtime()
            .drain(deadline(self.clock).map_err(|_| IrqError::Drain)?)
            .map_err(|_| IrqError::Drain)?;
        // SAFETY: registry established real source stop, IRR/ISR and inflight
        // drain before calling synchronize; this final closed drain completed.
        unsafe { self.executor.runtime().retire() }.map_err(|_| IrqError::Drain)
    }
}
fn deadline(clock: Clock) -> Result<u64> {
    clock
        .ticks_per_microsecond
        .checked_mul(TIMEOUT_US)
        .and_then(|n| crate::apic::rdtsc().checked_add(n))
        .ok_or_else(|| refuse!("IRQ work deadline overflow"))
}
fn stack_pointer() -> usize {
    let sp;
    // SAFETY: reads RSP and changes nothing.
    unsafe {
        asm!("mov {}, rsp",out(reg) sp, options(nomem,nostack,preserves_flags));
    }
    sp
}
fn interrupt_flags() -> u64 {
    let flags;
    // SAFETY: reads RFLAGS through the stack and changes nothing.
    unsafe {
        asm!("pushfq", "pop {}", out(reg) flags, options(preserves_flags));
    }
    flags
}

// Exercise both free-list and small-cache allocations in the real ISR and
// foreground. No infallible allocation, formatting or failure report runs here.
// Volatile accesses require the memory work even in optimized EFI builds.
fn heap_probe(expected_if: u64) -> bool {
    if interrupt_flags() & IF != expected_if {
        return false;
    }
    for (size, alignment) in [(257, 64), (31, 16)] {
        let Ok(layout) = Layout::from_size_align(size, alignment) else {
            return false;
        };
        let before = crate::ALLOCATOR.usage().live;
        // SAFETY: valid nonzero layout; this function keeps exclusive
        // ownership of the allocation until its matching deallocation.
        let block = unsafe { crate::ALLOCATOR.alloc_zeroed(layout) };
        if block.is_null() {
            return false;
        }
        let mut valid =
            (block as usize).is_multiple_of(alignment) && interrupt_flags() & IF == expected_if;
        for offset in 0..size {
            // SAFETY: `block` is this function's live allocation of `size` bytes and `offset` is
            // below `size`.
            unsafe {
                valid &= block.add(offset).read_volatile() == 0;
                block.add(offset).write_volatile(0xa5);
            }
        }
        for offset in 0..size {
            // SAFETY: `block` is this function's live allocation of `size` bytes and `offset` is
            // below `size`.
            valid &= unsafe { block.add(offset).read_volatile() } == 0xa5;
        }
        // SAFETY: `block` came from `alloc_zeroed` with this layout and is freed once.
        unsafe { crate::ALLOCATOR.dealloc(block, layout) };
        valid &= crate::ALLOCATOR.usage().live == before && interrupt_flags() & IF == expected_if;
        if !valid {
            return false;
        }
    }
    true
}
unsafe fn events<'a>(ctx: *mut c_void) -> &'a Events {
    // SAFETY: callers pass the `Events` context they queued, which outlives every job.
    unsafe { &*ctx.cast::<Events>() }
}
unsafe extern "C" fn deferred(ctx: *mut c_void) {
    // SAFETY: `ctx` is the `Events` context this job was queued with.
    let state = unsafe { events(ctx) };
    // SAFETY: the queue stays held while any job it admitted runs.
    let queue = unsafe { state.queue() };
    let sp = stack_pointer();
    match queue.current_id() {
        Ok(id)
            if id.get() != state.foreground.load(Ordering::Acquire)
                && state.spans[2..].iter().any(|r| r.contains(&sp))
                && matches!(super::current_context(), Ok(None)) =>
        {
            state.worker_id.store(id.get(), Ordering::Relaxed);
            state.worker_rsp.store(sp, Ordering::Relaxed);
        }
        _ => state.bad(BAD_WORKER),
    }
    if state.edu.read(0x24) != 0 || state.edu.bad_ack() != 0 {
        state.bad(BAD_WORKER);
    }
    state.worker.fetch_add(1, Ordering::Release);
}
#[repr(C)]
struct AsyncCall {
    delivered: *const AtomicU64,
    trigger: *mut u32,
    deadline: u64,
    result: u64,
    preflight: [u64; 3],
}
const _: () = {
    assert!(size_of::<AsyncCall>() == 56);
    assert!(core::mem::offset_of!(AsyncCall, trigger) == 8);
    assert!(core::mem::offset_of!(AsyncCall, deadline) == 16);
    assert!(core::mem::offset_of!(AsyncCall, result) == 24);
    assert!(core::mem::offset_of!(AsyncCall, preflight) == 32);
};
unsafe extern "C" fn foreground(ctx: *mut c_void) {
    // SAFETY: `ctx` is the `Events` context this job was queued with.
    let state = unsafe { events(ctx) };
    if !heap_probe(IF) {
        state.bad(BAD_IRQ_HEAP);
    }
    // SAFETY: the queue stays held while any job it admitted runs.
    match unsafe { state.queue() }.current_id() {
        Ok(id) => state.foreground.store(id.get(), Ordering::Release),
        Err(_) => {
            state.bad(BAD_WORKER);
            return;
        }
    }
    // The MMIO address is the existing bounded EDU IRQ access, not an
    // invented mapping/claim. This local borrow never escapes into a job.
    let mut call = AsyncCall {
        delivered: &state.delivered,
        trigger: state.edu.interrupt_trigger(),
        deadline: state.deadline.load(Ordering::Acquire),
        result: u64::MAX,
        preflight: [0; 3],
    };
    // SAFETY: `call` lives on this stack for the whole call, and its trigger is the EDU's mapped
    // interrupt register.
    unsafe { msi_with_fp_sentinel(&mut call) };
    for (destination, value) in state.async_observation.iter().zip([
        call.result,
        call.preflight[0],
        call.preflight[1],
        call.preflight[2],
    ]) {
        destination.store(value, Ordering::Release);
    }
    if call.result != 0 {
        state.bad(BAD_ASYNC_STATE);
    }
    if state.worker.load(Ordering::Acquire) != 0 {
        state.bad(BAD_INLINE);
    }
}

/// Execute only after the original fixture acknowledged IOTLB/TEoff teardown.
pub(crate) fn run(
    function: Function,
    base: u64,
    clock: Clock,
    prepared: crate::native_work_check::Prepared,
) -> Result<String> {
    let batch = prepared.into_irq_stacks()?;
    let parts = diagnostic::prepare_source(function, base, clock)?;
    let cpu = Arc::new(BspCpu);
    let events = Arc::new(Events {
        queue: AtomicPtr::new(core::ptr::null_mut()),
        edu: parts.edu.clone(),
        spans: batch.spans,
        deadline: AtomicU64::new(deadline(clock)?),
        delivered: AtomicU64::new(0),
        worker: AtomicU64::new(0),
        foreground: AtomicU64::new(0),
        worker_id: AtomicU64::new(0),
        worker_rsp: AtomicUsize::new(0),
        interrupted_rsp: AtomicUsize::new(0),
        isr_rsp: AtomicUsize::new(0),
        errors: AtomicU64::new(0),
        async_observation: [const { AtomicU64::new(0) }; 4],
    });
    // SAFETY: provider/code/root/event owner; only the owned
    // native handler and BSP callbacks can submit or execute this work.
    let queue = unsafe { Queue::<16>::new(cpu, events.clone()) }
        .map_err(|e| refuse!("IRQ queue: {e}", ?e))?;
    events
        .queue
        .store(Arc::as_ptr(&queue).cast_mut(), Ordering::Release);
    let executor = Rc::new(
        Executor::new(queue.clone(), batch.stacks).map_err(|e| refuse!("IRQ executor: {e}", ?e))?,
    );
    let handler = Arc::new(WorkHandler {
        queue: queue.clone(),
        events: events.clone(),
    });
    let source = Box::new(WorkSource {
        inner: parts.source,
        executor: executor.clone(),
        events: events.clone(),
        clock,
    });
    let mut registration = super::CONTROLLER
        .request_owned(*source, handler.clone())
        .map_err(|e| refuse!("IRQ work request: {e}", ?e))?;
    let vector = registration.vector();
    // Dispatcher permits MSI progress. All callbacks run
    // on kept real task stacks; no resource/queue lock spans this window.
    // SAFETY: the handler is registered and the runtime's stacks are owned; interrupts are masked
    // again right after.
    unsafe {
        asm!("sti", options(nostack));
    }
    // SAFETY: `foreground` and `events` stay held until the call completes or times out.
    let result = unsafe {
        executor.runtime().call_foreground(
            foreground,
            Arc::as_ptr(&events) as *mut c_void,
            events.deadline.load(Ordering::Acquire),
        )
    };
    // SAFETY: masks interrupts on this CPU.
    unsafe {
        asm!("cli", options(nostack));
    }
    if result.is_err()
        || events.errors.load(Ordering::Acquire) != 0
        || events.delivered.load(Ordering::Acquire) != 1
        || events.worker.load(Ordering::Acquire) != 0
        || parts.edu.received() != 1
        || parts.edu.observed() != 1
        || registration.handled() != Ok(1)
    {
        // Run the real stop attempt before reporting retention. Any uncertain
        // source/work/metadata failure keeps Source+Rc<Executor> in its slot.
        drop(registration);
        return Err(refuse!(
            "IRQ work observation failed result={result} errors={errors:#x} delivered={delivered} \
             worker={worker} quarantine={quarantine} retained_BSP_owner={retained} \
             released_stack_leases={released} async_result={async_result} \
             fcw_fsw_ftw_fop={fpu_control:#x} fip={fip:#x} fdp={fdp:#x}",
            ?result,
            errors = events.errors.load(Ordering::Acquire),
            delivered = events.delivered.load(Ordering::Acquire),
            worker = events.worker.load(Ordering::Acquire),
            quarantine = super::CONTROLLER.quarantine_count(),
            retained = Rc::strong_count(&executor) >= 2,
            released = batch.releases.released(),
            async_result = events.async_observation[0].load(Ordering::Acquire),
            fpu_control = events.async_observation[1].load(Ordering::Acquire),
            fip = events.async_observation[2].load(Ordering::Acquire),
            fdp = events.async_observation[3].load(Ordering::Acquire)
        ));
    }
    // This exercises the source's two real quiescence/drain phases. The queued
    // job is pending here and cannot release device/context resources early.
    let retired = registration
        .retire()
        .map_err(|e| refuse!("IRQ work mask/synchronize/drain: {e}", ?e))?;
    // SAFETY: route+callback+work drain just completed on this BSP;
    // keep returned callback while consuming its original concrete source.
    let (source, returned_handler, _route) = unsafe { retired.into_parts() };
    let WorkSource {
        inner,
        executor: source_executor,
        ..
    } = *source;
    crate::native_dma::diagnostic::retire_function(inner.function)?;
    drop(source_executor);
    drop(returned_handler);
    if events.worker.load(Ordering::Acquire) != 1
        || events.errors.load(Ordering::Acquire) != 0
        || Arc::strong_count(&handler) != 1
        || !matches!(queue.current_id(), Err(WorkError::Closed))
    {
        return Err(refuse!("IRQ work callback/owner retirement failed"));
    }
    // Late device cause must not submit into the now closed queue.
    parts.edu.write(0x60, 2);
    // SAFETY: the handler is registered and the runtime's stacks are owned; interrupts are masked
    // again right after.
    unsafe {
        asm!("sti", options(nostack));
    }
    let late = clock.wait(1_000, || events.delivered.load(Ordering::Acquire) != 1);
    // SAFETY: masks interrupts on this CPU.
    unsafe {
        asm!("cli", options(nostack));
    }
    parts.edu.write(0x64, u32::MAX);
    if late || parts.edu.read(0x24) != 0 {
        return Err(refuse!("IRQ work survived source retirement"));
    }
    drop(registration);
    drop(executor);
    if batch.releases.released() != 4 {
        return Err(refuse!(
            "IRQ worker stack leases did not release after synchronization"
        ));
    }
    Ok(format!(
        "EDU vector={vector:#x} actual_cause=0x1 IRQ_depth=real interrupted_SP=owned-foreground ISR_SP=separate-IST current_id=IRQ-refused enqueue=owned/noninline worker=owned-distinct-context async_FXSAVE=IRQ-poison-restored async_GPR+RSP+DF=restored heap=aligned-zeroed-read-write-reclaimed heap_IF=off/on-preserved mask+hardware+IRR/ISR+inflight+work=drained late_delivery=absent stack_leases=4-released BSP_device_owner=!Send interrupted_rsp={:#x} isr_rsp={:#x} worker_rsp={:#x}",
        events.interrupted_rsp.load(Ordering::Acquire),
        events.isr_rsp.load(Ordering::Acquire),
        events.worker_rsp.load(Ordering::Acquire)
    ))
}

/// Deliberate caller-saved data mutation in the fixture ISR. The
/// entry's default controls are held; all XMM lanes and x87 data change.
/// Only the separate opt-in EDU fixture calls this diagnostic helper.
#[unsafe(naked)]
unsafe extern "sysv64" fn poison_irq_fp() {
    naked_asm!(
        "fninit",
        "fldz",
        "pxor xmm0, xmm0",
        "pxor xmm1, xmm1",
        "pxor xmm2, xmm2",
        "pxor xmm3, xmm3",
        "pxor xmm4, xmm4",
        "pxor xmm5, xmm5",
        "pxor xmm6, xmm6",
        "pxor xmm7, xmm7",
        "pxor xmm8, xmm8",
        "pxor xmm9, xmm9",
        "pxor xmm10, xmm10",
        "pxor xmm11, xmm11",
        "pxor xmm12, xmm12",
        "pxor xmm13, xmm13",
        "pxor xmm14, xmm14",
        "pxor xmm15, xmm15",
        "ret",
    );
}

/// Synchronous owned-stack probe; no pointer to this local frame
/// escapes. Before/after snapshots cover all16 XMM registers and x87/MXCSR
/// state across the real asynchronous MSI, then restore the caller fully.
#[unsafe(naked)]
unsafe extern "C" fn msi_with_fp_sentinel(_: *mut AsyncCall) {
    naked_asm!(
        "push rbx",
        "push rbp",
        "push rdi",
        "push rsi",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "sub rsp, 1592",
        "mov rbx, rcx",
        "fxsave64 [rsp+32]",
        "xor eax, eax",
        "lea rdi, [rsp+544]",
        "mov ecx, 128",
        "rep stosq",
        "mov rax, 0x6162636465666700",
        "mov [rsp+1568], rax",
        "mov rax, 0x7172737475767700",
        "mov [rsp+1576], rax",
        "movdqu xmm0, [rsp+1568]",
        "mov rax, 0x6162636465666701",
        "mov [rsp+1568], rax",
        "mov rax, 0x7172737475767701",
        "mov [rsp+1576], rax",
        "movdqu xmm1, [rsp+1568]",
        "mov rax, 0x6162636465666702",
        "mov [rsp+1568], rax",
        "mov rax, 0x7172737475767702",
        "mov [rsp+1576], rax",
        "movdqu xmm2, [rsp+1568]",
        "mov rax, 0x6162636465666703",
        "mov [rsp+1568], rax",
        "mov rax, 0x7172737475767703",
        "mov [rsp+1576], rax",
        "movdqu xmm3, [rsp+1568]",
        "mov rax, 0x6162636465666704",
        "mov [rsp+1568], rax",
        "mov rax, 0x7172737475767704",
        "mov [rsp+1576], rax",
        "movdqu xmm4, [rsp+1568]",
        "mov rax, 0x6162636465666705",
        "mov [rsp+1568], rax",
        "mov rax, 0x7172737475767705",
        "mov [rsp+1576], rax",
        "movdqu xmm5, [rsp+1568]",
        "mov rax, 0x6162636465666706",
        "mov [rsp+1568], rax",
        "mov rax, 0x7172737475767706",
        "mov [rsp+1576], rax",
        "movdqu xmm6, [rsp+1568]",
        "mov rax, 0x6162636465666707",
        "mov [rsp+1568], rax",
        "mov rax, 0x7172737475767707",
        "mov [rsp+1576], rax",
        "movdqu xmm7, [rsp+1568]",
        "mov rax, 0x6162636465666708",
        "mov [rsp+1568], rax",
        "mov rax, 0x7172737475767708",
        "mov [rsp+1576], rax",
        "movdqu xmm8, [rsp+1568]",
        "mov rax, 0x6162636465666709",
        "mov [rsp+1568], rax",
        "mov rax, 0x7172737475767709",
        "mov [rsp+1576], rax",
        "movdqu xmm9, [rsp+1568]",
        "mov rax, 0x616263646566670a",
        "mov [rsp+1568], rax",
        "mov rax, 0x717273747576770a",
        "mov [rsp+1576], rax",
        "movdqu xmm10, [rsp+1568]",
        "mov rax, 0x616263646566670b",
        "mov [rsp+1568], rax",
        "mov rax, 0x717273747576770b",
        "mov [rsp+1576], rax",
        "movdqu xmm11, [rsp+1568]",
        "mov rax, 0x616263646566670c",
        "mov [rsp+1568], rax",
        "mov rax, 0x717273747576770c",
        "mov [rsp+1576], rax",
        "movdqu xmm12, [rsp+1568]",
        "mov rax, 0x616263646566670d",
        "mov [rsp+1568], rax",
        "mov rax, 0x717273747576770d",
        "mov [rsp+1576], rax",
        "movdqu xmm13, [rsp+1568]",
        "mov rax, 0x616263646566670e",
        "mov [rsp+1568], rax",
        "mov rax, 0x717273747576770e",
        "mov [rsp+1576], rax",
        "movdqu xmm14, [rsp+1568]",
        "mov rax, 0x616263646566670f",
        "mov [rsp+1568], rax",
        "mov rax, 0x717273747576770f",
        "mov [rsp+1576], rax",
        "movdqu xmm15, [rsp+1568]",
        "fninit",
        "fld1",
        "fldpi",
        // Safely masked pending invalid-operation status (0/0). Modern Intel
        // need not update FOP for a masked divide; seed pointer/opcode
        // registers below through FXRSTOR, then immediately reobserve them.
        // No FWAIT may expose an unmasked x87 exception in this diagnostic.
        "mov rax, 0x3ff0000000000000",
        "mov [rsp+1568], rax",
        "fld qword ptr [rsp+1568]",
        "fldz",
        "fldz",
        "8:",
        "fdivp st(1), st(0)",
        "mov dword ptr [rsp+1568], 0x7fa1",
        "ldmxcsr [rsp+1568]",
        "mov word ptr [rsp+1568], 0x0b7f",
        "fldcw [rsp+1568]",
        "fxsave64 [rsp+544]",
        // This owned image is an input register setup, never rewritten failed
        // evidence. Only the immediate FXSAVE observation is held.
        // DE F9 at label8 has architectural FOP0x6f9; FDP is the owned slot
        // used by the preceding source memory load.
        "mov word ptr [rsp+550], 0x6f9",
        "lea rax, [rip+8b]",
        "mov [rsp+552], rax",
        "lea rax, [rsp+1568]",
        "mov [rsp+560], rax",
        "fxrstor64 [rsp+544]",
        "fxsave64 [rsp+544]",
        // Preserve preflight bytes for a failed diagnostic, including
        // an oracle that cannot produce meaningful x87 pointer/opcode state.
        "mov rax, [rsp+544]",
        "mov [rbx+32], rax",
        "mov rax, [rsp+552]",
        "mov [rbx+40], rax",
        "mov rax, [rsp+560]",
        "mov [rbx+48], rax",
        "test word ptr [rsp+546], 1",
        "jz 4f",
        "test word ptr [rsp+546], 0x80",
        "jnz 4f",
        "movzx eax, word ptr [rsp+550]",
        "and eax, 0x7ff",
        "cmp eax, 0x6f9",
        "jne 4f",
        "lea rax, [rip+8b]",
        "cmp [rsp+552], rax",
        "jne 4f",
        "lea rax, [rsp+1568]",
        "cmp [rsp+560], rax",
        "jne 4f",
        "pushfq",
        "pop rax",
        "test eax, {interrupt_flag}",
        "jz 4f",
        "mov [rsp+1584], rsp",
        "mov rbp, 0x1828384858687888",
        "mov rsi, 0x1929394959697989",
        "mov rdi, 0x1a2a3a4a5a6a7a8a",
        "mov r8, 0x1b2b3b4b5b6b7b8b",
        "mov r9, 0x1c2c3c4c5c6c7c8c",
        "mov r10, 0x1d2d3d4d5d6d7d8d",
        "mov r11, 0x1e2e3e4e5e6e7e8e",
        "mov r12, 0x1f2f3f4f5f6f7f8f",
        "mov r13, 0x2030405060708090",
        "mov r14, 0x2131415161718191",
        "mov r15, 0x2232425262728292",
        "std",
        "mov rax, [rbx+8]",
        "mov dword ptr [rax], 1",
        "2:",
        "mov rax, [rbx]",
        "cmp qword ptr [rax], 0",
        "jne 3f",
        "rdtsc",
        "shl rdx, 32",
        "or rax, rdx",
        "cmp rax, [rbx+16]",
        "jae 5f",
        "pause",
        "jmp 2b",
        "3:",
        "pushfq",
        "pop rax",
        "test eax, 0x400",
        "jz 6f",
        "test eax, {interrupt_flag}",
        "jz 6f",
        "cld",
        "cmp rsp, [rsp+1584]",
        "jne 6f",
        "mov rax, 0x1828384858687888",
        "cmp rbp, rax",
        "jne 6f",
        "mov rax, 0x1929394959697989",
        "cmp rsi, rax",
        "jne 6f",
        "mov rax, 0x1a2a3a4a5a6a7a8a",
        "cmp rdi, rax",
        "jne 6f",
        "mov rax, 0x1b2b3b4b5b6b7b8b",
        "cmp r8, rax",
        "jne 6f",
        "mov rax, 0x1c2c3c4c5c6c7c8c",
        "cmp r9, rax",
        "jne 6f",
        "mov rax, 0x1d2d3d4d5d6d7d8d",
        "cmp r10, rax",
        "jne 6f",
        "mov rax, 0x1e2e3e4e5e6e7e8e",
        "cmp r11, rax",
        "jne 6f",
        "mov rax, 0x1f2f3f4f5f6f7f8f",
        "cmp r12, rax",
        "jne 6f",
        "mov rax, 0x2030405060708090",
        "cmp r13, rax",
        "jne 6f",
        "mov rax, 0x2131415161718191",
        "cmp r14, rax",
        "jne 6f",
        "mov rax, 0x2232425262728292",
        "cmp r15, rax",
        "jne 6f",
        "fxsave64 [rsp+1056]",
        "lea rdi, [rsp+544]",
        "lea rsi, [rsp+1056]",
        "mov ecx, 64",
        "repe cmpsq",
        "jne 6f",
        "mov qword ptr [rbx+24], 0",
        "jmp 7f",
        "4:",
        "mov qword ptr [rbx+24], 3",
        "jmp 7f",
        "5:",
        "mov qword ptr [rbx+24], 1",
        "jmp 7f",
        "6:",
        "mov qword ptr [rbx+24], 2",
        "7:",
        "cld",
        "fxrstor64 [rsp+32]",
        "add rsp, 1592",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rsi",
        "pop rdi",
        "pop rbp",
        "pop rbx",
        "ret",
        interrupt_flag = const IF,
    );
}

type Function = PciFunction<OwnedConfig>;
