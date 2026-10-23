//! Opt-in actual EDU MSI → preallocated queue → owned BSP work stack.
//! Device/config/Executor ownership stays !Send on the BSP. The ISR receives
//! only the existing bounded IRQ register access plus Send+Sync queue/events.
//! No production OSL/SCI/provider capability is installed.
use super::diagnostic::{self, Edu, EduSource};
use alloc::{boxed::Box, format, rc::Rc, string::String, sync::Arc, vec::Vec};
use core::{
    alloc::{GlobalAlloc, Layout},
    arch::{asm, naked_asm},
    ffi::c_void,
    ops::Range,
    sync::atomic::{AtomicPtr, AtomicU64, AtomicUsize, Ordering},
};
use stela_drivers::{
    Clock,
    bus::{
        irq::{Disposition, Handler, IrqError, Platform, Route, RouteRequest, Source},
        pci::Function,
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
// SAFETY: actual source-bound one-BSP fixture. Genuine registered dispatch
// brackets depth from unchanged IDT entry, including its real saved Frame.rsp.
// Only that ISR and retained owned process callbacks receive this adapter.
// This does not qualify other CPU entry paths or production ISR FP preservation.
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
        unsafe {
            asm!("pushfq", "pop {}", "cli", out(reg) flags);
        }
        Ok(flags)
    }
    unsafe fn restore(&self, flags: u64) {
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
    // Runtime. The actual executor/source/IRQ handle retain its Arc throughout
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
}
impl Events {
    unsafe fn queue(&self) -> &Queue<16> {
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
        // Reuse the existing actual cause/W1C/readback handler. Registry emits
        // EOI after this whole callback and its genuine context scope finish.
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
        // SAFETY: queue/provider and callback context are genuinely retained;
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
// Rc<Executor> makes the actual config/device/work owner genuinely !Send. It
// is retained in the checked BSP registry; no unsafe Send/Sync implementation.
struct WorkSource {
    inner: EduSource,
    executor: Rc<Executor<16>>,
    events: Arc<Events>,
    clock: Clock,
}
// SAFETY: exact stopped EDU grant inherited after real DMA/IOTLB/TEoff ACK.
// Both quiescence phases retain the actual device and executor while draining;
// failed hardware/work/metadata checks leave the complete registration retained.
unsafe impl Source for WorkSource {
    fn mask(&mut self) -> Result<(), IrqError> {
        self.inner.mask()
    }
    fn route(&self) -> RouteRequest {
        self.inner.route()
    }
    unsafe fn program(&mut self, route: Route) -> Result<(), IrqError> {
        unsafe { self.inner.program(route) }
    }
    unsafe fn unmask(&mut self) -> Result<(), IrqError> {
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
fn deadline(clock: Clock) -> Result<u64, String> {
    clock
        .ticks_per_microsecond
        .checked_mul(TIMEOUT_US)
        .and_then(|n| crate::apic::rdtsc().checked_add(n))
        .ok_or_else(|| String::from("IRQ work deadline overflow"))
}
fn stack_pointer() -> usize {
    let sp;
    unsafe {
        asm!("mov {}, rsp",out(reg) sp, options(nomem,nostack,preserves_flags));
    }
    sp
}
fn interrupt_flags() -> u64 {
    let flags;
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
        // SAFETY: valid nonzero layout; this function retains exclusive
        // ownership of the allocation until its matching deallocation.
        let block = unsafe { crate::ALLOCATOR.alloc_zeroed(layout) };
        if block.is_null() {
            return false;
        }
        let mut valid =
            (block as usize).is_multiple_of(alignment) && interrupt_flags() & IF == expected_if;
        for offset in 0..size {
            unsafe {
                valid &= block.add(offset).read_volatile() == 0;
                block.add(offset).write_volatile(0xa5);
            }
        }
        for offset in 0..size {
            valid &= unsafe { block.add(offset).read_volatile() } == 0xa5;
        }
        unsafe { crate::ALLOCATOR.dealloc(block, layout) };
        valid &= crate::ALLOCATOR.usage().live == before && interrupt_flags() & IF == expected_if;
        if !valid {
            return false;
        }
    }
    true
}
unsafe fn events<'a>(ctx: *mut c_void) -> &'a Events {
    unsafe { &*ctx.cast::<Events>() }
}
unsafe extern "C" fn deferred(ctx: *mut c_void) {
    let state = unsafe { events(ctx) };
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
}
const _: () = {
    assert!(size_of::<AsyncCall>() == 32);
    assert!(core::mem::offset_of!(AsyncCall, trigger) == 8);
    assert!(core::mem::offset_of!(AsyncCall, deadline) == 16);
    assert!(core::mem::offset_of!(AsyncCall, result) == 24);
};
unsafe extern "C" fn foreground(ctx: *mut c_void) {
    let state = unsafe { events(ctx) };
    if !heap_probe(IF) {
        state.bad(BAD_IRQ_HEAP);
    }
    match unsafe { state.queue() }.current_id() {
        Ok(id) => state.foreground.store(id.get(), Ordering::Release),
        Err(_) => {
            state.bad(BAD_WORKER);
            return;
        }
    }
    // The MMIO address is the existing actual bounded EDU IRQ access, not a
    // fabricated mapping/claim. This local borrow never escapes into a job.
    let mut call = AsyncCall {
        delivered: &state.delivered,
        trigger: state.edu.interrupt_trigger(),
        deadline: state.deadline.load(Ordering::Acquire),
        result: u64::MAX,
    };
    unsafe { msi_with_fp_sentinel(&mut call) };
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
) -> Result<String, String> {
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
    });
    // SAFETY: actual retained provider/code/root/event owner; only the owned
    // native handler and actual BSP callbacks can submit or execute this work.
    let queue = unsafe { Queue::<16>::new(cpu, events.clone()) }
        .map_err(|e| format!("IRQ queue: {e:?}"))?;
    events
        .queue
        .store(Arc::as_ptr(&queue).cast_mut(), Ordering::Release);
    let executor = Rc::new(
        Executor::new(queue.clone(), batch.stacks).map_err(|e| format!("IRQ executor: {e:?}"))?,
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
    let mut registration = super::service()
        .map_err(|e| format!("IRQ service: {e:?}"))?
        .request(source, handler.clone())
        .map_err(|e| format!("IRQ work request: {e:?}"))?;
    let vector = registration.vector();
    // Dispatcher deliberately permits actual MSI progress. All callbacks run
    // on retained real task stacks; no resource/queue lock spans this window.
    unsafe {
        asm!("sti", options(nostack));
    }
    let result = unsafe {
        executor.runtime().call_foreground(
            foreground,
            Arc::as_ptr(&events) as *mut c_void,
            events.deadline.load(Ordering::Acquire),
        )
    };
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
        return Err(format!(
            "IRQ work observation failed result={result:?} errors={:#x} delivered={} worker={} quarantine={} retained_BSP_owner={} released_stack_leases={}",
            events.errors.load(Ordering::Acquire),
            events.delivered.load(Ordering::Acquire),
            events.worker.load(Ordering::Acquire),
            super::CONTROLLER.quarantine_count(),
            Rc::strong_count(&executor) >= 2,
            batch.releases.released()
        ));
    }
    // This exercises the source's two real quiescence/drain phases. The queued
    // job is pending here and cannot release device/context resources early.
    registration
        .retire()
        .map_err(|e| format!("IRQ work mask/synchronize/drain: {e:?}"))?;
    if events.worker.load(Ordering::Acquire) != 1
        || events.errors.load(Ordering::Acquire) != 0
        || Arc::strong_count(&handler) != 1
        || !matches!(queue.current_id(), Err(WorkError::Closed))
    {
        return Err(String::from("IRQ work callback/owner retirement failed"));
    }
    // Actual late device cause must not submit into the now closed queue.
    parts.edu.write(0x60, 2);
    unsafe {
        asm!("sti", options(nostack));
    }
    let late = clock.wait(1_000, || events.delivered.load(Ordering::Acquire) != 1);
    unsafe {
        asm!("cli", options(nostack));
    }
    parts.edu.write(0x64, u32::MAX);
    if late || parts.edu.read(0x24) != 0 {
        return Err(String::from("IRQ work survived source retirement"));
    }
    drop(registration);
    drop(executor);
    if batch.releases.released() != 4 {
        return Err(String::from(
            "IRQ worker stack leases did not release after synchronization",
        ));
    }
    Ok(format!(
        "EDU vector={vector:#x} actual_cause=0x1 IRQ_depth=real interrupted_SP=owned-foreground ISR_SP=separate-IST current_id=IRQ-refused enqueue=owned/noninline worker=owned-distinct-context async_FXSAVE=unchanged heap=aligned-zeroed-read-write-reclaimed heap_IF=off/on-preserved mask+hardware+IRR/ISR+inflight+work=drained late_delivery=absent stack_leases=4-released BSP_device_owner=!Send interrupted_rsp={:#x} isr_rsp={:#x} worker_rsp={:#x}",
        events.interrupted_rsp.load(Ordering::Acquire),
        events.isr_rsp.load(Ordering::Acquire),
        events.worker_rsp.load(Ordering::Acquire)
    ))
}

/// Synchronous actual owned-stack probe; no pointer to this local frame
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
        "mov dword ptr [rsp+1568], 0x7fa1",
        "ldmxcsr [rsp+1568]",
        "mov word ptr [rsp+1568], 0x0b7f",
        "fldcw [rsp+1568]",
        "fxsave64 [rsp+544]",
        "pushfq",
        "pop rax",
        "test eax, {interrupt_flag}",
        "jz 4f",
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
