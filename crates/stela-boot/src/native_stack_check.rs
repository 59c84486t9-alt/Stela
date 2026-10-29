//! Finite actual WB stack/PTE/root/continuation diagnostic. Preparation only.
//! This consumes real RootPublication and Cpu capabilities; no time or Linux
//! owner/Task/NativeDomain substitutes are installed by this caller. Cpu is a
//! genuinely installed timing-capable Clock Cpu, never a time-free fake Cpu.
use crate::{native_mmio::RootPublication, native_stacks::Source};
use alloc::{sync::Arc, vec::Vec};
use core::{
    ffi::c_void,
    ops::Range,
    pin::Pin,
    ptr,
    sync::atomic::{AtomicPtr, AtomicUsize, Ordering},
};
use stela_drivers::platform::work::{Cpu, Executor, Kind, Queue, Runtime, WorkError};

const JOBS: usize = 8;
pub(crate) struct Observation {
    pub(crate) rsp: [usize; 2],
}
struct Probe {
    _source: Arc<Source>,
    cpu: Arc<dyn Cpu>,
    runtime: AtomicPtr<Runtime<JOBS>>,
    stacks: [Range<usize>; 4],
    rsp: [AtomicUsize; 2],
    resumed: [AtomicUsize; 2],
}
impl Probe {
    fn exercise(&self, index: usize) {
        self.cpu.check_cpu().unwrap_or_else(|e| self.cpu.fatal(e));
        let pointer = self.runtime.load(Ordering::Acquire);
        if pointer.is_null() {
            self.cpu.fatal(WorkError::CorruptContext);
        }
        // SAFETY: the pinned real Executor allocation is retained until both
        // actual jobs complete, then this pointer is cleared before final Drop.
        let runtime = unsafe { Pin::new_unchecked(&*pointer) };
        let mut local = [0_u64; 16];
        let mut first = 0;
        for turn in 0..3 {
            let rsp: usize;
            // SAFETY: bounded architectural read on actual owned callback stack.
            unsafe {
                core::arch::asm!("mov {}, rsp",out(reg) rsp,options(nomem,nostack,preserves_flags));
            }
            let Some(range) = self.stacks.iter().find(|r| r.contains(&rsp)) else {
                self.cpu.fatal(WorkError::InvalidStack)
            };
            if turn == 0 {
                first = range.start;
                self.rsp[index].store(rsp, Ordering::Release);
            }
            if range.start != first {
                self.cpu.fatal(WorkError::CorruptContext);
            }
            // Real volatile frame storage survives TWO genuine stack switches.
            // Guard/root authority comes from Source, not these observations.
            for (at, value) in local.iter_mut().enumerate() {
                if turn != 0
                    && unsafe { ptr::read_volatile(value) } != (index * 100 + at + turn - 1) as u64
                {
                    self.cpu.fatal(WorkError::CorruptContext);
                }
                unsafe { ptr::write_volatile(value, (index * 100 + at + turn) as u64) };
            }
            if turn != 2 {
                runtime.yield_now().unwrap_or_else(|e| self.cpu.fatal(e));
            }
        }
        self.resumed[index].store(2, Ordering::Release);
    }
}
unsafe extern "C" fn first(opaque: *mut c_void) {
    unsafe { &*opaque.cast::<Probe>() }.exercise(0);
}
unsafe extern "C" fn second(opaque: *mut c_void) {
    unsafe { &*opaque.cast::<Probe>() }.exercise(1);
}

/// Exercise finite actual stack lifecycle through the existing generic Runtime.
/// # Safety
/// Publication comes from genuine RootContext/RootExecution. Cpu comes from
/// an actually installed and qualified Clock bound to that SAME root; retain
/// Installed/DriverExecution, native memory/heap generation and image/code
/// through ALL queue/runtime/frame/source/publication final Drops. Time-free
/// RootContext supplies no fake work::Cpu::ticks implementation.
/// No NativeMemory retarget/reset or root/cache change may occur while any
/// frame/pin/alias exists. Call on that actual process CPU, outside interrupts.
/// On uncertain failure, retained publication/pins block root retirement; caller
/// must preserve that real root/HostOwner and stop/report, never force closure.
/// Every CPU-checking final Drop below precedes external RootContext or any
/// installed Clock retirement. This diagnostic does not call Clock/Idle or
/// ExecutionClock, but the Cpu trait's timing contract remains fully genuine.
pub(crate) unsafe fn run(
    publication: RootPublication,
    cpu: Arc<dyn Cpu>,
) -> Result<Observation, WorkError> {
    cpu.check_cpu()?;
    if cpu.in_interrupt() {
        return Err(WorkError::InterruptContext);
    }
    let source = Source::new(publication, 4)?;
    let result = run_stacks(source.clone(), cpu);
    // run_stacks returns only after actual successful retirement, or after its
    // uncertain Executor quarantines full storage. Live slots then make source
    // retirement refuse, preserving actual tables/pins/root scope.
    source.retire()?;
    drop(source); // Complete parent clear/CR3 acknowledgement BEFORE root ends.
    result
}
fn run_stacks(source: Arc<Source>, cpu: Arc<dyn Cpu>) -> Result<Observation, WorkError> {
    let mut stacks = Vec::new();
    stacks.try_reserve_exact(4).map_err(|_| WorkError::Full)?;
    for _ in 0..4 {
        stacks.push(source.allocate()?);
    }
    let ranges = core::array::from_fn(|i| stacks[i].bounds());
    let probe = Arc::new(Probe {
        _source: source,
        cpu: cpu.clone(),
        runtime: AtomicPtr::new(ptr::null_mut()),
        stacks: ranges,
        rsp: core::array::from_fn(|_| AtomicUsize::new(0)),
        resumed: core::array::from_fn(|_| AtomicUsize::new(0)),
    });
    let queue = unsafe { Queue::<JOBS>::new(cpu, probe.clone()) }?;
    let executor = Executor::new(queue.clone(), stacks)?;
    let runtime = executor.runtime();
    probe.runtime.store(
        runtime.get_ref() as *const Runtime<JOBS> as *mut Runtime<JOBS>,
        Ordering::Release,
    );
    let opaque = Arc::as_ptr(&probe).cast_mut().cast();
    let jobs =
        [first, second].map(|callback| unsafe { queue.execute(Kind::General, callback, opaque) });
    let [a, b] = jobs;
    let tickets = [a?, b?];
    let mut steps = 0;
    while tickets
        .iter()
        .any(|t| !queue.completed(*t).unwrap_or_else(|e| probe.cpu.fatal(e)))
    {
        if steps >= 16 || !runtime.step()? {
            return Err(WorkError::Pending);
        }
        steps += 1;
    }
    let rsp = core::array::from_fn(|i| probe.rsp[i].load(Ordering::Acquire));
    if rsp[0] == rsp[1]
        || rsp.contains(&0)
        || probe.resumed.iter().any(|v| v.load(Ordering::Acquire) != 2)
    {
        return Err(WorkError::CorruptContext);
    }
    let observed = Observation { rsp };
    queue.close()?;
    // SAFETY: both actual jobs returned; there are no external handles/bindings,
    // callbacks, services or IRQ producers in this finite generic diagnostic.
    unsafe {
        runtime.retire()?;
    }
    probe.runtime.store(ptr::null_mut(), Ordering::Release);
    drop(executor); // Actual frames gone, all four Backings clear leaf PTE/TLB.
    drop(queue); // Final Queue CPU validation while root still live.
    drop(probe); // Last retained Source clone; no callback data can outlive it.
    Ok(observed)
}
