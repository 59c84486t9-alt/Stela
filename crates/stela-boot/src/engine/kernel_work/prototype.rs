//! Bounded optional mixed32 owner proof. Small callbacks only record their
//! actual context/RSP; they do not enter Linux, AML, Clock or a driver service.
use super::*;
use core::{
    mem::{ManuallyDrop, MaybeUninit},
    pin::Pin,
    sync::atomic::AtomicU32,
};
struct Case {
    runtime: usize,
    kernel: bool,
    completed: AtomicBool,
    error: AtomicU32,
    observed: UnsafeCell<MaybeUninit<work::TaskContext>>,
}
unsafe extern "C" fn record(context: *mut c_void) {
    // SAFETY: the diagnostic retains its stable preallocated Case vector and
    // actual Runtime through every accepted ticket or permanent quarantine.
    let case = unsafe { &*context.cast::<Case>() };
    // SAFETY: pointer is the same retained pinned Runtime, on its qualified
    // actual callback stack. It is never used as a cross-CPU execution grant.
    let runtime = unsafe { Pin::new_unchecked(&*(case.runtime as *const work::Runtime<SLOTS>)) };
    let result = (|| {
        let view = runtime.current_context()?;
        let rsp: usize;
        // SAFETY: read-only observation on this real owned continuation.
        unsafe {
            asm!("mov {}, rsp",out(reg)rsp,options(nomem,nostack,preserves_flags));
        }
        let (bytes, alignment) = if case.kernel {
            (16 * 1024, 16 * 1024)
        } else {
            (128 * 1024, 4096)
        };
        if view.context_id == 0
            || view.sequence == 0
            || view.stack_end.checked_sub(view.stack_start) != Some(bytes)
            || !view.stack_start.is_multiple_of(alignment)
            || !(view.stack_start..view.stack_end).contains(&rsp)
            || view.guard_end != view.stack_start
            || view.guard_end.checked_sub(view.guard_start) != Some(4096)
        {
            return Err(WorkError::CorruptContext);
        }
        // SAFETY: this accepted one-shot Case has exactly one writer; completion
        // is published only after the full copied context is initialized.
        unsafe { (*case.observed.get()).write(view) };
        Ok(())
    })();
    if result.is_err() {
        case.error.store(1, Ordering::Relaxed);
    }
    case.completed.store(true, Ordering::Release);
}
/// # Safety
/// Explicit original UP native-MMIO diagnostic, before any driver/IRQ/guest
/// producer. Actual sealed loader raw allocation and all-root/cache owners
/// stay pinned. No C entry, KernelTask, hardware Clock or service is published.
pub(in crate::engine) unsafe fn check(
    handoff: &'static Handoff,
    owner: &mut HostOwner,
) -> Result<(), Error> {
    if handoff.native_resources.cores != 1 {
        return Err(Error::WrongCpu);
    }
    // Deliberately corrupt layout DATA while retaining the genuine original
    // handoff. Validation must reject before a root/stack publication or claim.
    let mut wrong = Plan::prototype(handoff)?;
    if let Plan::Mixed { raw, .. } = &mut wrong {
        raw.bytes -= 4096;
    } else {
        return Err(Error::Geometry);
    }
    // SAFETY: actual handoff/owner remain genuine; the bad Plan supplies no
    // authority and must fail their pre-effect exact-inventory comparison.
    if !matches!(
        unsafe { KernelWork::prepare_plan(handoff, owner, wrong) },
        Err(Error::Inventory)
    ) || handoff
        .native_task_allocations
        .claim_state(native_smp::resources::TaskPool::Prototype)
        != Ok(false)
    {
        return Err(Error::Qualification);
    }
    // A real fallible metadata capacity refusal must also occur before claim;
    // this is allocation-overflow coverage, not a claim of firmware OOM testing.
    let mut impossible = Vec::<Case>::new();
    if impossible.try_reserve_exact(usize::MAX).is_ok()
        || handoff
            .native_task_allocations
            .claim_state(native_smp::resources::TaskPool::Prototype)
            != Ok(false)
    {
        return Err(Error::Qualification);
    }
    let mut cases = Vec::new();
    cases.try_reserve_exact(32).map_err(|_| Error::Allocation)?;
    for index in 0..32 {
        cases.push(Case {
            runtime: 0,
            kernel: index == 2 || (8..28).contains(&index),
            completed: AtomicBool::new(false),
            error: AtomicU32::new(0),
            observed: UnsafeCell::new(MaybeUninit::uninit()),
        });
    }
    // SAFETY: this is the separately selected genuine raw reservation, never
    // a reinterpretation of production's16-stack pool or unowned metadata.
    let work = unsafe { KernelWork::prepare_plan(handoff, owner, Plan::prototype(handoff)?) }?;
    let stack_pages = work.task_pages()?;
    let described = stack_pages.count();
    if described != cases.iter().filter(|case| case.kernel).count() {
        return Err(Error::Qualification);
    }
    // SAFETY: original UP process-only diagnostic, before producers, with
    // immutable actual heap/slot allocations and all-root WB mappings retained.
    let mut catalog = unsafe { stack_pages.register() }?;
    catalog.verify().map_err(Error::Pages)?;
    catalog.try_retire().map_err(Error::Pages)?;
    crate::output::arguments(format_args!(
        "CHECK native-stack-inventory PASS slots={described} catalog=retired backing=firmware-owned; no C stack or current grant\n"
    ));
    let retained = work._cpu.reservation.clone();
    let pointer = work.executor.runtime().get_ref() as *const _ as usize;
    for case in &mut cases {
        case.runtime = pointer;
    }
    // If a callback/ticket becomes uncertain, retaining the complete vector is
    // mandatory. Runtime Drop likewise quarantines every paused stack owner.
    let cases = ManuallyDrop::new(cases);
    work._cpu
        .reservation
        .identity
        .check_dispatch()
        .map_err(Error::Work)?;
    // SAFETY: the same actual root/CPU owns all32 validated mappings and frames;
    // acquire the non-reentrant host/root guard once around actual switching.
    let root = unsafe { RestoreRoot::enter(handoff.root) };
    let runtime = work.executor.runtime();
    let context = |index: usize| {
        core::ptr::from_ref(&cases[index])
            .cast_mut()
            .cast::<c_void>()
    };
    let kernel = stela_drivers::gpu::linux::task::stack_requirement().map_err(Error::Work)?;
    // SAFETY: fixed finite callbacks fit their real stack class and every Case,
    // Runtime/code/root remains retained until complete retirement/quarantine.
    unsafe {
        runtime
            .start_service(record, context(2))
            .map_err(Error::Work)?;
        runtime
            .start_firmware(record, context(3))
            .map_err(Error::Work)?;
        runtime
            .queue()
            .execute_gpe(record, context(4))
            .map_err(Error::Work)?;
        for index in [1, 5] {
            runtime
                .queue()
                .execute(work::Kind::Notify, record, context(index))
                .map_err(Error::Work)?;
        }
        for index in [6, 7] {
            runtime
                .queue()
                .execute_portal(record, context(index))
                .map_err(Error::Work)?;
        }
        for index in 8..28 {
            runtime
                .queue()
                .execute_general_with_requirement(kernel, record, context(index))
                .map_err(Error::Work)?;
        }
        for index in 28..32 {
            runtime
                .queue()
                .execute(work::Kind::General, record, context(index))
                .map_err(Error::Work)?;
        }
        let deadline = work
            ._cpu
            .ticks()
            .checked_add(2_000_000)
            .ok_or(Error::Clock)?;
        runtime
            .call_foreground(record, context(0), deadline)
            .map_err(Error::Work)?;
    }
    // Fixed finite step count: no stopped bootstrap counter can make this
    // diagnostic wait forever. These one-shot callbacks never park or loop.
    for _ in 0..64 {
        if !runtime.step().map_err(Error::Work)? {
            break;
        }
    }
    let mut ids = [0u64; 32];
    for (index, case) in cases.iter().enumerate() {
        if !case.completed.load(Ordering::Acquire) || case.error.load(Ordering::Relaxed) != 0 {
            return Err(Error::Qualification);
        }
        // SAFETY: actual callback finished and release-published its full view.
        ids[index] = unsafe { (*case.observed.get()).assume_init_ref() }.context_id;
    }
    ids.sort_unstable();
    if ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(Error::Qualification);
    }
    // SAFETY: every finite accepted job returned, no binding/producer exists,
    // the taskless dispatcher owns this original CPU/root with IRQs excluded.
    unsafe { runtime.retire() }.map_err(Error::Work)?;
    drop(root);
    drop(work);
    if retained.released_stack_views.load(Ordering::Acquire) != 32 {
        return Err(Error::Qualification);
    }
    let raw = retained.allocation.region();
    drop(retained);
    drop(ManuallyDrop::into_inner(cases));
    crate::output::arguments(format_args!(
        "CHECK native-mixed32 PASS contexts=32 kernel=21 rust=11 raw_bytes={} payload_bytes=1785856 alignment_padding=12288 guards=all-roots holes=absent cache=WB retire=32-views raw=whole-boot-owned refusals=wrong-inventory+allocation-capacity; no C-current, Clock or provider grant\n",
        raw.bytes
    ));
    Ok(())
}
