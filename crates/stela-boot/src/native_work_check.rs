//! Opt-in native work execution proof, never an installed ACPICA provider.
//! Uses genuine reserved LoaderData stack pages and the host-check's retained
//! BSP/root/IDT ownership. No interpreter, AP bootstrap, or mapper is invented.
use crate::{
    apic,
    paging::{NX, PAGE, PRESENT, Tables, WRITABLE},
};
use alloc::{boxed::Box, format, string::String, sync::Arc, vec::Vec};
use core::{
    arch::{asm, naked_asm},
    ffi::c_void,
    ops::Range,
    pin::Pin,
    ptr::NonNull,
    sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};
use sha2::{Digest, Sha256};
use stela_drivers::{
    Clock,
    platform::work::{
        self, Callback, Cpu, Executor, Kind, Queue, Runtime, Stack, StackBacking, WorkError,
    },
};
use stela_runtime::{freestanding::BootArena, pc::acpi};
mod fixture;
// Reuse the actual read-only native PAT/MTRR/translation qualifier unchanged.
use crate::native_memory::cache;
const CHUNK: usize = 2 * 1024 * 1024;
const STACK_BYTES: usize = 128 * 1024;
const STACK_COUNT: usize = 8;
const TIMEOUT_US: u64 = 2_000_000;
const IF: u64 = 1 << 9;

struct Reservation {
    original: Range<usize>,
    arena: usize,
    released: AtomicU64,
}
pub(crate) struct Prepared {
    reservation: Arc<Reservation>,
    clock: Clock,
    madt: &'static [u8],
    madt_hash: [u8; 32],
}
struct Backing {
    reservation: Arc<Reservation>,
    bounds: Range<usize>,
}
// SAFETY: exact current root has these independently owned LoaderData pages
// RW+NX/WB, preceding guard is genuinely absent. The source reservation and
// root stay retained for the complete bounded BSP fixture, including failures.
// LoaderData reservation remains owned until VM stop; this proof does not
// claim a dynamic physical page allocator or live all-root unmap capability.
unsafe impl StackBacking for Backing {
    fn bounds(&self) -> Range<usize> {
        self.bounds.clone()
    }
    fn guard(&self) -> Range<usize> {
        self.bounds.start - PAGE..self.bounds.start
    }
}
impl Drop for Backing {
    fn drop(&mut self) {
        self.reservation.released.fetch_add(1, Ordering::Relaxed);
    }
}
fn bounds(base: usize, i: usize) -> Range<usize> {
    let guard = base + i * (STACK_BYTES + PAGE);
    guard + PAGE..guard + PAGE + STACK_BYTES
}
impl Prepared {
    pub(crate) fn prepare(clock: Clock) -> Result<Self, &'static str> {
        let hv = core::arch::x86_64::__cpuid(0x4000_0000);
        if [
            hv.ebx.to_le_bytes(),
            hv.ecx.to_le_bytes(),
            hv.edx.to_le_bytes(),
        ]
        .concat()
            != b"TCGTCGTCGTCG"
        {
            return Err("native work proof requires one QEMU TCG BSP");
        }
        let rsdp = crate::storage::rsdp().ok_or("native work fixture RSDP missing")?;
        // SAFETY: actual firmware tables are mapped and retained before EBS.
        let madt = unsafe { acpi::find(rsdp, b"APIC") }.map_err(|_| "work MADT unavailable")?;
        fixture::one_processor(madt, apic_id())?;
        let start = crate::firmware::pages(2 * CHUNK / PAGE)?;
        let base = start.next_multiple_of(CHUNK);
        if STACK_COUNT * (STACK_BYTES + PAGE) > CHUNK {
            return Err("work stacks exceed reserved arena");
        }
        Ok(Self {
            reservation: Arc::new(Reservation {
                original: start..start + 2 * CHUNK,
                arena: base,
                released: AtomicU64::new(0),
            }),
            clock,
            madt,
            madt_hash: Sha256::digest(madt).into(),
        })
    }
    pub(crate) fn arena(&self) -> BootArena {
        BootArena {
            base: NonNull::new(self.reservation.arena as *mut u8).expect("reserved arena"),
            pages: CHUNK / PAGE,
        }
    }
    pub(crate) fn map(&self, tables: &mut Tables) -> Result<(), &'static str> {
        for i in 0..STACK_COUNT {
            for page in bounds(self.reservation.arena, i).step_by(PAGE) {
                tables.page(page, PRESENT | WRITABLE | NX)?;
            }
        }
        Ok(())
    }
    pub(crate) fn run(self) -> Result<String, String> {
        if Sha256::digest(self.madt).as_slice() != self.madt_hash {
            return Err(String::from("work MADT changed before execution"));
        }
        fixture::one_processor(self.madt, apic_id()).map_err(String::from)?;
        let madt_hex: String = self.madt.iter().map(|b| format!("{b:02x}")).collect();
        crate::output::arguments(format_args!("NATIVE WORK MADT {madt_hex}\n"));
        if flags() & IF != 0 {
            return Err(String::from("work entry requires IRQs off"));
        }
        for i in 0..STACK_COUNT {
            let span = bounds(self.reservation.arena, i);
            cache::verify_writeback(span.start as u64, span.start as u64, span.len(), 0)
                .map_err(|e| format!("work stack WB mapping: {e:?}"))?;
            if leaf(span.start - PAGE).is_some() {
                return Err(String::from("work stack guard is present"));
            }
            for page in span.step_by(PAGE) {
                let entry = leaf(page).ok_or_else(|| String::from("stack missing"))?;
                if entry & (WRITABLE | NX) != (WRITABLE | NX) {
                    return Err(String::from("stack lacks actual RW+NX"));
                }
            }
        }
        let cpu = Arc::new(NativeCpu { apic_id: apic_id() });
        let state = Arc::new(Probe {
            runtime: AtomicUsize::new(0),
            events: core::array::from_fn(|_| AtomicU64::new(0)),
            rsp: core::array::from_fn(|_| AtomicUsize::new(0)),
            observed_flags: core::array::from_fn(|_| AtomicU64::new(0)),
            next: AtomicUsize::new(0),
            phase: AtomicU64::new(0),
            deadline: AtomicU64::new(0),
            released: AtomicBool::new(false),
            cpu: cpu.clone(),
            baseline: controls(),
        });
        // SAFETY: genuine provider state/code/root retained by this queue;
        // only this BSP and retained proof callbacks produce work.
        let queue = unsafe { Queue::<16>::new(cpu.clone(), state.clone()) }.map_err(error)?;
        let make_stacks = |first| -> Result<Vec<Stack>, String> {
            (first..first + 4)
                .map(|i| {
                    Stack::new(Box::new(Backing {
                        reservation: self.reservation.clone(),
                        bounds: bounds(self.reservation.arena, i),
                    }))
                    .map_err(error)
                })
                .collect()
        };
        let executor = Executor::new(queue, make_stacks(0)?).map_err(error)?;
        let runtime = executor.runtime();
        state
            .runtime
            .store(runtime.get_ref() as *const _ as usize, Ordering::Release);
        if runtime.current_id() != Err(WorkError::Unavailable) {
            return Err(String::from("dispatcher invented a thread ID"));
        }
        let apic = apic::Apic::new(apic::base_msr(), apic::base_msr() & apic::BASE_ADDRESS);
        apic.start(
            crate::engine::interrupts::SPURIOUS_VECTOR,
            crate::engine::interrupts::TIMER_VECTOR,
            self.clock
                .ticks_per_microsecond
                .checked_mul(1_000_000)
                .ok_or_else(|| String::from("APIC deadline overflow"))?,
        );
        let original = flags();
        for phase in 0..2 {
            state.phase.store(phase, Ordering::Release);
            state.next.store(0, Ordering::Release);
            let deadline = next_deadline(self.clock, TIMEOUT_US)?;
            state.deadline.store(deadline, Ordering::Release);
            if phase == 1 {
                unsafe {
                    asm!("sti", options(nostack));
                }
            }
            let expected = flags();
            unsafe { abi_probe_dispatch(Arc::as_ptr(&state) as *mut c_void) };
            if flags() & IF != expected & IF {
                return Err(String::from("dispatcher IF changed across real contexts"));
            }
            unsafe { cpu.restore(original) };
            verify(&state, self.reservation.arena, phase)?;
        }
        state.next.store(0, Ordering::Release);
        let deadline = next_deadline(self.clock, TIMEOUT_US)?;
        state.deadline.store(deadline, Ordering::Release);
        let context = Arc::as_ptr(&state) as *mut c_void;
        for (kind, callback) in [
            (Kind::Notify, serial_drain as Callback),
            (Kind::General, cyclic_drain),
            (Kind::General, cyclic_drain),
        ] {
            unsafe { runtime.queue().execute(kind, callback, context) }.map_err(error)?;
        }
        runtime.drain(deadline).map_err(error)?;
        for event in [50, 60, 61] {
            if !(0..state.next.load(Ordering::Acquire))
                .any(|i| state.events[i].load(Ordering::Acquire) >> 32 == event)
            {
                return Err(format!("actual drain-cycle result {event} missing"));
            }
        }
        // SAFETY: all actual proof callbacks finished, no real source exists;
        // this fixture has no producer/work/reset path that can restart them.
        unsafe { runtime.retire() }.map_err(error)?;
        drop(executor);
        if self.reservation.released.load(Ordering::Acquire) != 4 {
            return Err(String::from("idle stack leases not released"));
        }
        // Timeout leaves a genuine foreground continuation on the other four
        // owned stacks. Abandonment must retain the entire runtime allocation.
        let queue = unsafe { Queue::<16>::new(cpu.clone(), state.clone()) }.map_err(error)?;
        let executor = Executor::new(queue, make_stacks(4)?).map_err(error)?;
        let runtime = executor.runtime();
        let raw = runtime.get_ref() as *const Runtime<16>;
        state.runtime.store(raw as usize, Ordering::Release);
        let deadline = next_deadline(self.clock, 1000)?;
        if unsafe {
            runtime.call_foreground(suspended, Arc::as_ptr(&state) as *mut c_void, deadline)
        } != Err(WorkError::TimedOut)
            || unsafe { runtime.retire() } != Err(WorkError::Pending)
        {
            return Err(String::from("suspended work falsely retired"));
        }
        let quarantined = work::quarantined_owners();
        drop(executor);
        if self.reservation.released.load(Ordering::Acquire) != 4
            || work::quarantined_owners() <= quarantined
            || unsafe { Pin::new_unchecked(&*raw) }.step() != Err(WorkError::Closed)
        {
            return Err(String::from("pending runtime/stack quarantine failed"));
        }
        let queue = unsafe { Queue::<2>::new(cpu, state.clone()) }.map_err(error)?;
        unsafe { queue.execute(Kind::General, no_op, core::ptr::null_mut()) }.map_err(error)?;
        unsafe { queue.execute(Kind::General, no_op, core::ptr::null_mut()) }.map_err(error)?;
        if unsafe { queue.execute(Kind::General, no_op, core::ptr::null_mut()) }
            != Err(WorkError::Full)
        {
            return Err(String::from("overflow was accepted"));
        }
        queue.close().map_err(error)?;
        if unsafe { queue.execute(Kind::Notify, no_op, core::ptr::null_mut()) }
            != Err(WorkError::Closed)
        {
            return Err(String::from("close admitted new work"));
        }
        drop(queue);
        Ok(format!(
            "BSP native contexts=4 foreground=owned-stack ids=distinct/stable execute=deferred Notify=FIFO general=yield/resume Win64-shadow+all-GPR+XMM6-15=task+dispatcher-verified MXCSR+x87=preserved IF=off/on/clear-yield/exact guards=8-absent RW+NX+WB=verified idle_stack_leases=4-released pending_runtime+stacks=quarantined overflow+close=refused drain_cycles=refused source_IRQ_enqueue=not-qualified arena={:#x} reservation={:#x}..{:#x}",
            self.reservation.arena, self.reservation.original.start, self.reservation.original.end
        ))
    }
}
fn next_deadline(clock: Clock, microseconds: u64) -> Result<u64, String> {
    clock
        .ticks_per_microsecond
        .checked_mul(microseconds)
        .and_then(|delta| apic::rdtsc().checked_add(delta))
        .ok_or_else(|| String::from("native work deadline overflow"))
}
fn error(e: WorkError) -> String {
    format!("native work: {e:?}")
}
fn flags() -> u64 {
    let f: u64;
    unsafe {
        asm!("pushfq","pop {}",out(reg)f,options(preserves_flags));
    }
    f
}
fn apic_id() -> u32 {
    let max = core::arch::x86_64::__cpuid(0).eax;
    if max >= 0xb {
        let p = core::arch::x86_64::__cpuid_count(0xb, 0);
        if p.ebx != 0 {
            return p.edx;
        }
    }
    core::arch::x86_64::__cpuid(1).ebx >> 24
}
struct NativeCpu {
    apic_id: u32,
}
// SAFETY: only this actual source-bound QEMU BSP executes this bounded proof;
// actual CLI/POPFQ and TSC are used. No autonomous/IRQ OSL provider is installed.
// All current callers are retained process callbacks. No IRQ producer invokes
// this adapter yet; actual source IRQ metadata/delivery remains unqualified.
unsafe impl Cpu for NativeCpu {
    fn check_cpu(&self) -> Result<(), WorkError> {
        if apic_id() == self.apic_id {
            Ok(())
        } else {
            Err(WorkError::WrongCpu)
        }
    }
    fn in_interrupt(&self) -> bool {
        // Restricted fixture call graph: neither this private adapter nor its
        // queue/runtime is published to any ISR. All actual callers are the
        // retained dispatcher/process callbacks. This is not IRQ metadata and
        // must never be installed as a production/IRQ-reachable Cpu adapter.
        false
    }
    fn save_disable(&self) -> Result<u64, WorkError> {
        self.check_cpu()?;
        let f: u64;
        unsafe {
            asm!("pushfq","pop {}","cli",out(reg)f);
        }
        Ok(f)
    }
    unsafe fn restore(&self, f: u64) {
        unsafe {
            asm!("push {}","popfq",in(reg)f);
        }
    }
    fn ticks(&self) -> u64 {
        apic::rdtsc()
    }
    fn fatal(&self, e: WorkError) -> ! {
        crate::output::arguments(format_args!("NATIVE WORK FATAL {e:?}\n"));
        crate::output::fatal("native work failed; retained owners required")
    }
}
fn leaf(address: usize) -> Option<u64> {
    let root: u64;
    let cr4: u64;
    unsafe {
        asm!("mov {}, cr3",out(reg)root,options(nomem,nostack,preserves_flags));
        asm!("mov {}, cr4",out(reg)cr4,options(nomem,nostack,preserves_flags));
    }
    let mut table = root & 0x000f_ffff_ffff_f000;
    let levels = if cr4 & (1 << 12) != 0 { 5 } else { 4 };
    for level in (0..levels).rev() {
        let index = (address >> (12 + level * 9)) & 511;
        let value = unsafe { ((table as *const u64).add(index)).read_volatile() };
        if value & 1 == 0 {
            return None;
        }
        if level == 0 || value & (1 << 7) != 0 {
            return Some(value);
        }
        table = value & 0x000f_ffff_ffff_f000;
    }
    None
}
struct Probe {
    runtime: AtomicUsize,
    events: [AtomicU64; 32],
    rsp: [AtomicUsize; 32],
    observed_flags: [AtomicU64; 32],
    next: AtomicUsize,
    phase: AtomicU64,
    deadline: AtomicU64,
    released: AtomicBool,
    cpu: Arc<NativeCpu>,
    baseline: (u32, u16),
}
impl Probe {
    unsafe fn runtime(&self) -> Pin<&Runtime<16>> {
        unsafe {
            Pin::new_unchecked(&*(self.runtime.load(Ordering::Acquire) as *const Runtime<16>))
        }
    }
    fn require<T>(&self, r: Result<T, WorkError>) -> T {
        match r {
            Ok(v) => v,
            Err(e) => self.cpu.fatal(e),
        }
    }
    fn event(&self, n: u64) {
        let r = unsafe { self.runtime() };
        let id = self.require(r.current_id());
        let i = self.next.fetch_add(1, Ordering::AcqRel);
        if i >= 32 {
            self.cpu.fatal(WorkError::Full);
        }
        let rsp: usize;
        unsafe {
            asm!("mov {}, rsp",out(reg)rsp,options(nomem,nostack,preserves_flags));
        }
        self.events[i].store(n << 32 | id.get(), Ordering::Release);
        self.rsp[i].store(rsp, Ordering::Release);
        self.observed_flags[i].store(flags(), Ordering::Release);
    }
}
unsafe fn probe<'a>(p: *mut c_void) -> &'a Probe {
    unsafe { &*p.cast::<Probe>() }
}
unsafe extern "C" fn abi_dispatch_body(p: *mut c_void) {
    let f = unsafe { probe(p) };
    f.require(unsafe {
        f.runtime()
            .call_foreground(foreground, p, f.deadline.load(Ordering::Acquire))
    });
}
unsafe extern "C" fn foreground(p: *mut c_void) {
    let f = unsafe { probe(p) };
    f.event(10);
    let r = unsafe { f.runtime() };
    for (kind, callback) in [
        (Kind::Notify, notify_one as Callback),
        (Kind::Notify, notify_two),
        (Kind::General, abi_probe),
        (Kind::General, abi_probe_b),
    ] {
        f.require(unsafe { r.queue().execute(kind, callback, p) });
    }
    if f.next.load(Ordering::Acquire) != 1 {
        f.cpu.fatal(WorkError::CorruptContext);
    }
    f.require(r.drain(f.deadline.load(Ordering::Acquire)));
    f.event(11);
}
unsafe extern "C" fn notify_one(p: *mut c_void) {
    let f = unsafe { probe(p) };
    f.event(20);
    f.require(unsafe { f.runtime() }.yield_now());
    f.event(21);
}
unsafe extern "C" fn notify_two(p: *mut c_void) {
    unsafe { probe(p) }.event(22);
}
unsafe extern "C" fn abi_yield_b(p: *mut c_void) {
    let f = unsafe { probe(p) };
    if controls() != f.baseline {
        f.cpu.fatal(WorkError::CorruptContext);
    }
    f.event(40);
    f.require(unsafe { f.runtime() }.yield_now());
    if controls() != f.baseline {
        f.cpu.fatal(WorkError::CorruptContext);
    }
    f.event(41);
}
unsafe extern "C" fn abi_yield(p: *mut c_void) {
    let f = unsafe { probe(p) };
    f.event(30);
    let (mxcsr, fcw) = controls();
    let changed_mx = (mxcsr & !(3 << 13)) | 2 << 13;
    let changed_cw = (fcw & !(3 << 10)) | 2 << 10;
    unsafe {
        asm!("ldmxcsr [{}]",in(reg)&changed_mx,options(nostack));
        asm!("fldcw [{}]",in(reg)&changed_cw,options(nostack));
    }
    // This continuation deliberately differs from the dispatcher's incoming
    // IF state in phase 1. Resumption must restore the task's saved IF=0;
    // another task may still execute with IF=1 in between.
    let saved_flags = f.require(f.cpu.save_disable());
    f.require(unsafe { f.runtime() }.yield_now());
    if flags() & IF != 0 {
        f.cpu.fatal(WorkError::CorruptContext);
    }
    unsafe { f.cpu.restore(saved_flags) };
    if controls() != (changed_mx, changed_cw) {
        f.cpu.fatal(WorkError::CorruptContext);
    }
    unsafe {
        asm!("ldmxcsr [{}]",in(reg)&mxcsr,options(nostack));
        asm!("fldcw [{}]",in(reg)&fcw,options(nostack));
    }
    f.event(31);
}
fn controls() -> (u32, u16) {
    let mut mxcsr = 0;
    let mut fcw = 0;
    unsafe {
        asm!("stmxcsr [{}]",in(reg)&mut mxcsr,options(nostack,preserves_flags));
        asm!("fnstcw [{}]",in(reg)&mut fcw,options(nostack,preserves_flags));
    }
    (mxcsr, fcw)
}
/// Actual Win64 callback: touch all four caller-provided home slots, preserve
/// all nonvolatile registers it changes, and check them across a yielding C
/// helper (which crosses the explicit SysV context-switch boundary).
macro_rules! abi_callback {
    ($name:ident, $body:ident, $seed:expr) => {
        #[unsafe(naked)]
        unsafe extern "C" fn $name(_: *mut c_void) {
            naked_asm!(
                "mov rax, rsp",
                "and eax, 15",
                "cmp eax, 8",
                "jne 2f",
                "mov rax, {seed}",
                "mov [rsp+8], rax",
                "mov [rsp+16], rax",
                "mov [rsp+24], rax",
                "mov [rsp+32], rax",
                "push rbx",
                "push rbp",
                "push rdi",
                "push rsi",
                "push r12",
                "push r13",
                "push r14",
                "push r15",
                "sub rsp, 200",
                "movdqu [rsp+32], xmm6",
                "mov rax, {seed}",
                "add rax, 6",
                "movq xmm6, rax",
                "mov rax, {seed}",
                "add rax, 262",
                "movq xmm0, rax",
                "punpcklqdq xmm6, xmm0",
                "movdqu [rsp+48], xmm7",
                "mov rax, {seed}",
                "add rax, 7",
                "movq xmm7, rax",
                "mov rax, {seed}",
                "add rax, 263",
                "movq xmm0, rax",
                "punpcklqdq xmm7, xmm0",
                "movdqu [rsp+64], xmm8",
                "mov rax, {seed}",
                "add rax, 8",
                "movq xmm8, rax",
                "mov rax, {seed}",
                "add rax, 264",
                "movq xmm0, rax",
                "punpcklqdq xmm8, xmm0",
                "movdqu [rsp+80], xmm9",
                "mov rax, {seed}",
                "add rax, 9",
                "movq xmm9, rax",
                "mov rax, {seed}",
                "add rax, 265",
                "movq xmm0, rax",
                "punpcklqdq xmm9, xmm0",
                "movdqu [rsp+96], xmm10",
                "mov rax, {seed}",
                "add rax, 10",
                "movq xmm10, rax",
                "mov rax, {seed}",
                "add rax, 266",
                "movq xmm0, rax",
                "punpcklqdq xmm10, xmm0",
                "movdqu [rsp+112], xmm11",
                "mov rax, {seed}",
                "add rax, 11",
                "movq xmm11, rax",
                "mov rax, {seed}",
                "add rax, 267",
                "movq xmm0, rax",
                "punpcklqdq xmm11, xmm0",
                "movdqu [rsp+128], xmm12",
                "mov rax, {seed}",
                "add rax, 12",
                "movq xmm12, rax",
                "mov rax, {seed}",
                "add rax, 268",
                "movq xmm0, rax",
                "punpcklqdq xmm12, xmm0",
                "movdqu [rsp+144], xmm13",
                "mov rax, {seed}",
                "add rax, 13",
                "movq xmm13, rax",
                "mov rax, {seed}",
                "add rax, 269",
                "movq xmm0, rax",
                "punpcklqdq xmm13, xmm0",
                "movdqu [rsp+160], xmm14",
                "mov rax, {seed}",
                "add rax, 14",
                "movq xmm14, rax",
                "mov rax, {seed}",
                "add rax, 270",
                "movq xmm0, rax",
                "punpcklqdq xmm14, xmm0",
                "movdqu [rsp+176], xmm15",
                "mov rax, {seed}",
                "add rax, 15",
                "movq xmm15, rax",
                "mov rax, {seed}",
                "add rax, 271",
                "movq xmm0, rax",
                "punpcklqdq xmm15, xmm0",
                "mov rbx, {seed}",
                "add rbx, 1",
                "mov rbp, {seed}",
                "add rbp, 2",
                "mov rdi, {seed}",
                "add rdi, 3",
                "mov rsi, {seed}",
                "add rsi, 4",
                "mov r12, {seed}",
                "add r12, 5",
                "mov r13, {seed}",
                "add r13, 6",
                "mov r14, {seed}",
                "add r14, 7",
                "mov r15, {seed}",
                "add r15, 8",
                "call {body}",
                "mov rax, {seed}",
                "add rax, 1",
                "cmp rbx, rax",
                "jne 2f",
                "mov rax, {seed}",
                "add rax, 2",
                "cmp rbp, rax",
                "jne 2f",
                "mov rax, {seed}",
                "add rax, 3",
                "cmp rdi, rax",
                "jne 2f",
                "mov rax, {seed}",
                "add rax, 4",
                "cmp rsi, rax",
                "jne 2f",
                "mov rax, {seed}",
                "add rax, 5",
                "cmp r12, rax",
                "jne 2f",
                "mov rax, {seed}",
                "add rax, 6",
                "cmp r13, rax",
                "jne 2f",
                "mov rax, {seed}",
                "add rax, 7",
                "cmp r14, rax",
                "jne 2f",
                "mov rax, {seed}",
                "add rax, 8",
                "cmp r15, rax",
                "jne 2f",
                "movq rax, xmm6",
                "mov rdx, {seed}",
                "add rdx, 6",
                "cmp rax, rdx",
                "jne 2f",
                "movdqa xmm0, xmm6",
                "psrldq xmm0, 8",
                "movq rax, xmm0",
                "add rdx, 256",
                "cmp rax, rdx",
                "jne 2f",
                "movq rax, xmm7",
                "mov rdx, {seed}",
                "add rdx, 7",
                "cmp rax, rdx",
                "jne 2f",
                "movdqa xmm0, xmm7",
                "psrldq xmm0, 8",
                "movq rax, xmm0",
                "add rdx, 256",
                "cmp rax, rdx",
                "jne 2f",
                "movq rax, xmm8",
                "mov rdx, {seed}",
                "add rdx, 8",
                "cmp rax, rdx",
                "jne 2f",
                "movdqa xmm0, xmm8",
                "psrldq xmm0, 8",
                "movq rax, xmm0",
                "add rdx, 256",
                "cmp rax, rdx",
                "jne 2f",
                "movq rax, xmm9",
                "mov rdx, {seed}",
                "add rdx, 9",
                "cmp rax, rdx",
                "jne 2f",
                "movdqa xmm0, xmm9",
                "psrldq xmm0, 8",
                "movq rax, xmm0",
                "add rdx, 256",
                "cmp rax, rdx",
                "jne 2f",
                "movq rax, xmm10",
                "mov rdx, {seed}",
                "add rdx, 10",
                "cmp rax, rdx",
                "jne 2f",
                "movdqa xmm0, xmm10",
                "psrldq xmm0, 8",
                "movq rax, xmm0",
                "add rdx, 256",
                "cmp rax, rdx",
                "jne 2f",
                "movq rax, xmm11",
                "mov rdx, {seed}",
                "add rdx, 11",
                "cmp rax, rdx",
                "jne 2f",
                "movdqa xmm0, xmm11",
                "psrldq xmm0, 8",
                "movq rax, xmm0",
                "add rdx, 256",
                "cmp rax, rdx",
                "jne 2f",
                "movq rax, xmm12",
                "mov rdx, {seed}",
                "add rdx, 12",
                "cmp rax, rdx",
                "jne 2f",
                "movdqa xmm0, xmm12",
                "psrldq xmm0, 8",
                "movq rax, xmm0",
                "add rdx, 256",
                "cmp rax, rdx",
                "jne 2f",
                "movq rax, xmm13",
                "mov rdx, {seed}",
                "add rdx, 13",
                "cmp rax, rdx",
                "jne 2f",
                "movdqa xmm0, xmm13",
                "psrldq xmm0, 8",
                "movq rax, xmm0",
                "add rdx, 256",
                "cmp rax, rdx",
                "jne 2f",
                "movq rax, xmm14",
                "mov rdx, {seed}",
                "add rdx, 14",
                "cmp rax, rdx",
                "jne 2f",
                "movdqa xmm0, xmm14",
                "psrldq xmm0, 8",
                "movq rax, xmm0",
                "add rdx, 256",
                "cmp rax, rdx",
                "jne 2f",
                "movq rax, xmm15",
                "mov rdx, {seed}",
                "add rdx, 15",
                "cmp rax, rdx",
                "jne 2f",
                "movdqa xmm0, xmm15",
                "psrldq xmm0, 8",
                "movq rax, xmm0",
                "add rdx, 256",
                "cmp rax, rdx",
                "jne 2f",
                "movdqu xmm6, [rsp+32]",
                "movdqu xmm7, [rsp+48]",
                "movdqu xmm8, [rsp+64]",
                "movdqu xmm9, [rsp+80]",
                "movdqu xmm10, [rsp+96]",
                "movdqu xmm11, [rsp+112]",
                "movdqu xmm12, [rsp+128]",
                "movdqu xmm13, [rsp+144]",
                "movdqu xmm14, [rsp+160]",
                "movdqu xmm15, [rsp+176]",
                "add rsp, 200",
                "pop r15",
                "pop r14",
                "pop r13",
                "pop r12",
                "pop rsi",
                "pop rdi",
                "pop rbp",
                "pop rbx",
                "ret",
                "2:",
                "ud2",
                body=sym $body, seed=const $seed
            );
        }
    }
}
abi_callback!(abi_probe, abi_yield, 0x3132333435363738u64);
abi_callback!(abi_probe_b, abi_yield_b, 0x4142434445464748u64);
abi_callback!(abi_probe_dispatch, abi_dispatch_body, 0x5152535455565758u64);
unsafe extern "C" fn serial_drain(p: *mut c_void) {
    let f = unsafe { probe(p) };
    let r = unsafe { f.runtime() };
    f.require(unsafe { r.queue().execute(Kind::Notify, notify_two, p) });
    if r.drain(f.deadline.load(Ordering::Acquire)) != Err(WorkError::WouldDeadlock) {
        f.cpu.fatal(WorkError::CorruptContext);
    }
    f.event(50);
}
unsafe extern "C" fn cyclic_drain(p: *mut c_void) {
    let f = unsafe { probe(p) };
    match unsafe { f.runtime() }.drain(f.deadline.load(Ordering::Acquire)) {
        Ok(()) => f.event(60),
        Err(WorkError::WouldDeadlock) => f.event(61),
        Err(e) => f.cpu.fatal(e),
    }
}
unsafe extern "C" fn suspended(p: *mut c_void) {
    let f = unsafe { probe(p) };
    while !f.released.load(Ordering::Acquire) {
        f.require(unsafe { f.runtime() }.yield_now());
    }
}
unsafe extern "C" fn no_op(_: *mut c_void) {}
fn verify(f: &Probe, base: usize, phase: u64) -> Result<(), String> {
    let count = f.next.load(Ordering::Acquire);
    let events: Vec<_> = (0..count)
        .map(|i| f.events[i].load(Ordering::Acquire))
        .collect();
    let pos = |event| {
        events
            .iter()
            .position(|v| v >> 32 == event)
            .ok_or_else(|| format!("missing event {event}"))
    };
    if !(pos(20)? < pos(21)? && pos(21)? < pos(22)? && pos(30)? < pos(40)? && pos(40)? < pos(31)?) {
        return Err(format!("work ordering differs: {events:?}"));
    }
    let mut ids: Vec<_> = events.iter().map(|e| e & u64::from(u32::MAX)).collect();
    ids.sort_unstable();
    ids.dedup();
    if ids.len() != 4 {
        return Err(String::from("task contexts did not have distinct IDs"));
    }
    if events[pos(10)?] as u32 != events[pos(11)?] as u32
        || events[pos(20)?] as u32 != events[pos(22)?] as u32
    {
        return Err(String::from("resumed task identity changed"));
    }
    for i in 0..count {
        let rsp = f.rsp[i].load(Ordering::Acquire);
        if !(0..4).any(|j| bounds(base, j).contains(&rsp)) {
            return Err(String::from("callback ran on unowned dispatcher stack"));
        }
        if (f.observed_flags[i].load(Ordering::Acquire) & IF != 0) != (phase == 1) {
            return Err(String::from("callback IF changed across context switch"));
        }
    }
    Ok(())
}
