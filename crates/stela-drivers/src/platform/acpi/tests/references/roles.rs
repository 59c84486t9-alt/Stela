//! ACPICA Wait/Signal on hosted role stacks; no native grant.
use super::*;
use crate::platform::work::{
    self, ContextId, FirmwareRole, ParkOutcome, SwitchBinding, TaskContext, WakeHandle, WorkError,
};
use core::pin::Pin;
use core::sync::atomic::{AtomicU32, AtomicU64};
use std::{sync::Mutex, time::Instant};
static CURRENT: AtomicUsize = AtomicUsize::new(0);
static SEMAPHORES: AtomicUsize = AtomicUsize::new(0);
struct Sem {
    max: u32,
    units: AtomicU32,
}
struct Binding {
    id: AtomicU64,
    semaphore: AtomicUsize,
    units: AtomicU32,
}
impl Binding {
    fn verify(&self, view: &TaskContext, active: bool) {
        assert_eq!(self.id.load(Ordering::Acquire), view.context_id);
        let local = 0u8;
        let rsp = core::ptr::addr_of!(local) as usize;
        assert_eq!((view.stack_start..view.stack_end).contains(&rsp), active);
    }
}
// SAFETY: this fixture has real kept same-thread stacks and atomics only.
// Hooks never switch, allocate or drop a resource; semaphore allocations remain
// live until all waiting frames join and the Session tears down.
unsafe impl SwitchBinding for Binding {
    unsafe fn attach(&self, v: &TaskContext) -> Result<(), WorkError> {
        self.id.store(v.context_id, Ordering::Release);
        self.verify(v, true);
        Ok(())
    }
    unsafe fn still_blocked(&self, v: &TaskContext) -> Result<bool, WorkError> {
        self.verify(v, true);
        let pointer = self.semaphore.load(Ordering::Acquire);
        if pointer == 0 {
            return Ok(false);
        }
        // SAFETY: wait publishes a live Sem pointer before parking; Core never
        // deletes it with a pending waiter, and the fixture keeps the Session.
        Ok(unsafe { &*(pointer as *const Sem) }
            .units
            .load(Ordering::Acquire)
            < self.units.load(Ordering::Acquire))
    }
    unsafe fn leave(&self, v: &TaskContext, _: work::LeaveReason) -> Result<(), WorkError> {
        self.verify(v, true);
        Ok(())
    }
    unsafe fn arrive(&self, v: &TaskContext, _: bool) -> Result<(), WorkError> {
        self.verify(v, true);
        Ok(())
    }
    unsafe fn complete(&self, v: &TaskContext) -> Result<(), WorkError> {
        self.verify(v, true);
        assert_eq!(self.semaphore.load(Ordering::Acquire), 0);
        Ok(())
    }
    unsafe fn detach(&self, v: &TaskContext) -> Result<(), WorkError> {
        self.verify(v, false);
        Ok(())
    }
}
struct Scene {
    runtime: AtomicU64,
    session: AtomicUsize,
    bindings: Mutex<Vec<(ContextId, Arc<Binding>)>>,
    wakes: Mutex<Vec<(usize, u64, WakeHandle<32>)>>,
    events: Mutex<Vec<u8>>,
    general: Box<Sem>,
}
impl Scene {
    fn runtime(&self) -> Pin<&work::Runtime<32>> {
        // SAFETY: the enclosing fixture publishes a pinned executor, keeps it
        // through all callbacks, and clears CURRENT before its successful drop.
        unsafe {
            Pin::new_unchecked(&*(self.runtime.load(Ordering::Acquire) as *const work::Runtime<32>))
        }
    }
    fn session(&self) -> &Session {
        self.runtime().current_id().unwrap();
        // SAFETY: a heap-stable ManuallyDrop Session is held until every
        // admitted callback joins. On failure it is quarantined.
        unsafe { &*(self.session.load(Ordering::Acquire) as *const Session) }
    }
    fn bind(&self) -> Arc<Binding> {
        let r = self.runtime();
        let id = r.current_id().unwrap().get();
        if let Some(binding) = self
            .bindings
            .lock()
            .unwrap()
            .iter()
            .find(|(context, _)| context.get() == id)
        {
            return binding.1.clone();
        }
        let binding = Arc::new(Binding {
            id: AtomicU64::new(0),
            semaphore: AtomicUsize::new(0),
            units: AtomicU32::new(0),
        });
        r.bind_current(binding.clone()).unwrap();
        self.bindings
            .lock()
            .unwrap()
            .push((r.current_id().unwrap(), binding.clone()));
        binding
    }
    fn invoke(&self, method: &str, start: u8, finish: u8) {
        self.bind();
        self.events.lock().unwrap().push(start);
        self.session().root().invoke(Some(method), &[]).unwrap();
        self.events.lock().unwrap().push(finish);
    }
}
fn current() -> Option<&'static Scene> {
    let pointer = CURRENT.load(Ordering::Acquire);
    if pointer == 0 {
        return None;
    }
    // SAFETY: TEST_SERIAL excludes other Sessions. The fixture keeps the Arc
    // until all callbacks/quiescence and resets CURRENT before releasing it.
    Some(unsafe { &*(pointer as *const Scene) })
}
unsafe extern "C" fn create(
    _: *mut c_void,
    max: u32,
    initial: u32,
    out: *mut *mut c_void,
) -> Status {
    if out.is_null() || initial > max {
        return BAD_PARAMETER.0;
    }
    SEMAPHORES.fetch_add(1, Ordering::Relaxed);
    // SAFETY: ACPICA supplied its writable output; this allocation is freed
    // exactly by the matching delete callback after every waiter is gone.
    unsafe {
        out.write(
            Box::into_raw(Box::new(Sem {
                max,
                units: AtomicU32::new(initial),
            }))
            .cast(),
        )
    };
    0
}
unsafe extern "C" fn delete(_: *mut c_void, p: *mut c_void) -> Status {
    // SAFETY: ACPICA passes the live unique allocation created above, once.
    drop(unsafe { Box::from_raw(p.cast::<Sem>()) });
    SEMAPHORES.fetch_sub(1, Ordering::Relaxed);
    0
}
unsafe extern "C" fn wait(_: *mut c_void, p: *mut c_void, units: u32, timeout: u16) -> Status {
    // SAFETY: the active ACPICA semaphore outlives this complete wait frame.
    let sem = unsafe { &*p.cast::<Sem>() };
    if units == 0 || units > sem.max {
        return BAD_PARAMETER.0;
    }
    let take = || {
        sem.units
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                n.checked_sub(units)
            })
            .is_ok()
    };
    if take() {
        return 0;
    }
    if timeout == 0 {
        return 0x11;
    }
    let Some(scene) = current() else { return 0x11 };
    let r = scene.runtime();
    if r.current_id().is_err() {
        return 0x11;
    }
    let binding = scene.bind();
    let id = r.current_id().unwrap().get();
    let wake = r.wake_handle().unwrap();
    scene.wakes.lock().unwrap().push((p as usize, id, wake));
    binding.units.store(units, Ordering::Release);
    binding.semaphore.store(p as usize, Ordering::Release);
    let start = Instant::now();
    let result = loop {
        if take() {
            break 0;
        }
        if timeout != 0xffff && start.elapsed().as_millis() >= u128::from(timeout) {
            break 0x11;
        }
        if timeout == 0xffff {
            assert!(matches!(
                r.park_if_blocked().unwrap(),
                ParkOutcome::Skipped | ParkOutcome::Resumed
            ));
        } else {
            r.yield_now().unwrap();
        }
    };
    binding.semaphore.store(0, Ordering::Release);
    scene
        .wakes
        .lock()
        .unwrap()
        .retain(|(s, t, _)| *s != p as usize || *t != id);
    result
}
unsafe extern "C" fn signal(_: *mut c_void, p: *mut c_void, units: u32) -> Status {
    // SAFETY: ACPICA keeps this semaphore until matching deletion after quiescence.
    let sem = unsafe { &*p.cast::<Sem>() };
    if units == 0 {
        return BAD_PARAMETER.0;
    }
    if sem
        .units
        .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
            n.checked_add(units).filter(|v| *v <= sem.max)
        })
        .is_err()
    {
        return LIMIT.0;
    }
    if let Some(scene) = current() {
        for (s, _, wake) in &*scene.wakes.lock().unwrap() {
            if *s == p as usize {
                wake.wake().unwrap();
            }
        }
    }
    0
}
unsafe extern "C" fn thread(_: *mut c_void) -> u64 {
    current()
        .and_then(|s| s.runtime().current_id().ok())
        .map_or(1, |id| id.get().checked_add(1).unwrap())
}
unsafe extern "C" fn portal_wait(p: *mut c_void) {
    // SAFETY: queue keeps this exact Scene through callback completion.
    let scene = unsafe { &*p.cast::<Scene>() };
    assert_eq!(
        scene.runtime().firmware_role_current(),
        Ok(Some(FirmwareRole::PortalAml))
    );
    scene.invoke("WAIT", 1, 3);
}
unsafe extern "C" fn portal_signal(p: *mut c_void) {
    // SAFETY: queue keeps this exact Scene through callback completion.
    let scene = unsafe { &*p.cast::<Scene>() };
    assert_eq!(
        scene.runtime().firmware_role_current(),
        Ok(Some(FirmwareRole::PortalAml))
    );
    scene.invoke("SIGN", 2, 4);
}
unsafe extern "C" fn notify_wait(p: *mut c_void) {
    // SAFETY: queue keeps this exact Scene through callback completion.
    let scene = unsafe { &*p.cast::<Scene>() };
    assert_eq!(
        scene.runtime().firmware_role_current(),
        Ok(Some(FirmwareRole::Notify))
    );
    scene.invoke("WAIT", 5, 7);
}
unsafe extern "C" fn notify_signal(p: *mut c_void) {
    // SAFETY: queue keeps this exact Scene through callback completion.
    let scene = unsafe { &*p.cast::<Scene>() };
    assert_eq!(
        scene.runtime().firmware_role_current(),
        Ok(Some(FirmwareRole::Notify))
    );
    scene.invoke("SIGN", 6, 8);
}
unsafe extern "C" fn gpe_signal(p: *mut c_void) {
    // SAFETY: queue keeps this exact Scene through callback completion.
    let scene = unsafe { &*p.cast::<Scene>() };
    assert_eq!(
        scene.runtime().firmware_role_current(),
        Ok(Some(FirmwareRole::Gpe))
    );
    scene.invoke("SIGN", 9, 10);
}
unsafe extern "C" fn general_wait(p: *mut c_void) {
    // SAFETY: queue keeps Scene and its separate semaphore through join.
    let scene = unsafe { &*p.cast::<Scene>() };
    assert_eq!(scene.runtime().firmware_role_current(), Ok(None));
    scene.bind();
    assert_eq!(
        // SAFETY: this fixture semaphore is owned by Scene through all waits.
        unsafe {
            wait(
                ptr::null_mut(),
                (&*scene.general as *const Sem).cast_mut().cast(),
                1,
                0xffff,
            )
        },
        0
    );
}
fn aml() -> Vec<u8> {
    let mut dsdt = table(b"DSDT", 36, 2);
    dsdt.extend_from_slice(&[
        0x5b, 0x02, b'E', b'V', b'0', b'0', 0x08, b'C', b'N', b'T', b'0', 0,
    ]);
    dsdt.extend_from_slice(&[
        0x14, 26, b'W', b'A', b'I', b'T', 0, 0x5b, 0x25, b'E', b'V', b'0', b'0', 0x0b, 0xff, 0xff,
        0x70, 1, b'C', b'N', b'T', b'0', 0xa4, b'C', b'N', b'T', b'0',
    ]);
    dsdt.extend_from_slice(&[
        0x14, 14, b'S', b'I', b'G', b'N', 0, 0x5b, 0x24, b'E', b'V', b'0', b'0', 0xa4, 1,
    ]);
    let length = dsdt.len() as u32;
    dsdt[4..8].copy_from_slice(&length.to_le_bytes());
    checksum(&mut dsdt, 9);
    dsdt
}
fn run_wait_signal(policy: work::ReservationPolicy) {
    let _serial = TEST_SERIAL.lock().unwrap();
    assert_eq!(CURRENT.load(Ordering::Acquire), 0);
    SEMAPHORES.store(0, Ordering::Release);
    let (mut services, counts) = fixture_dsdt(aml());
    services.create_semaphore = create;
    services.delete_semaphore = delete;
    services.wait_semaphore = wait;
    services.signal_semaphore = signal;
    services.thread_id = thread;
    // SAFETY: serialized real ACPICA fixture. Keep the heap Session
    // quarantined on any failure until no frame can reference it.
    let mut session = core::mem::ManuallyDrop::new(Box::new(
        // SAFETY: TEST_SERIAL excludes every other Session and fixture services
        // keep their table/allocation state through Session teardown.
        unsafe { Session::start(services, Mode::InterpreterOnly) }.unwrap(),
    ));
    let scene = Arc::new(Scene {
        runtime: AtomicU64::new(0),
        session: AtomicUsize::new((&**session as *const Session) as usize),
        bindings: Mutex::new(Vec::new()),
        wakes: Mutex::new(Vec::new()),
        events: Mutex::new(Vec::new()),
        general: Box::new(Sem {
            max: 8,
            units: AtomicU32::new(0),
        }),
    });
    let (executor, cpu, dropped) =
        work::test_support::executor_with_policy::<32>(scene.clone(), policy);
    let r = executor.runtime();
    scene.runtime.store(
        r.get_ref() as *const work::Runtime<32> as u64,
        Ordering::Release,
    );
    CURRENT.store(Arc::as_ptr(&scene) as usize, Ordering::Release);
    let p = Arc::as_ptr(&scene) as *mut c_void;
    for _ in 0..8 {
        // SAFETY: Scene owns all callback state and the enclosing real Session
        // remains heap-stable through all admitted jobs and retirement.
        unsafe { r.queue().execute(work::Kind::General, general_wait, p) }.unwrap();
        assert_eq!(r.step(), Ok(true));
    }
    // SAFETY: two distinct portal stacks keep both AML frames.
    unsafe { r.queue().execute_portal(portal_wait, p) }.unwrap();
    // SAFETY: this matching Scene and Session outlive the signaler's callback.
    unsafe { r.queue().execute_portal(portal_signal, p) }.unwrap();
    let deadline = work::Cpu::ticks(&*cpu) + 1_000_000_000;
    assert_eq!(r.drain(deadline), Err(WorkError::Pending));
    assert_eq!(*scene.events.lock().unwrap(), vec![1, 2, 4, 3]);
    // SAFETY: FIFO-start Notify callbacks keep independent real stacks.
    unsafe { r.queue().execute(work::Kind::Notify, notify_wait, p) }.unwrap();
    // SAFETY: the second Notify worker signals after the first parks.
    unsafe { r.queue().execute(work::Kind::Notify, notify_signal, p) }.unwrap();
    assert_eq!(
        r.drain(work::Cpu::ticks(&*cpu) + 1_000_000_000),
        Err(WorkError::Pending)
    );
    assert_eq!(*scene.events.lock().unwrap(), vec![1, 2, 4, 3, 5, 6, 8, 7]);
    // SAFETY: portal waits while a separately reserved GPE-role continuation
    // executes Signal AML. Triggering the role here models GPE dispatch;
    // this test does not claim a physical SCI/GPE interrupt source.
    unsafe { r.queue().execute_portal(portal_wait, p) }.unwrap();
    assert_eq!(r.step(), Ok(true));
    // SAFETY: GPE callback's Scene/Session remain held through completion.
    unsafe { r.queue().execute_gpe(gpe_signal, p) }.unwrap();
    assert_eq!(
        r.drain(work::Cpu::ticks(&*cpu) + 1_000_000_000),
        Err(WorkError::Pending)
    );
    assert_eq!(&scene.events.lock().unwrap()[8..], &[1, 9, 10, 3]);
    assert_eq!(
        // SAFETY: Scene owns this separate fixture semaphore and its eight waiters.
        unsafe {
            signal(
                ptr::null_mut(),
                (&*scene.general as *const Sem).cast_mut().cast(),
                8,
            )
        },
        0
    );
    r.queue().close().unwrap();
    r.drain(work::Cpu::ticks(&*cpu) + 1_000_000_000).unwrap();
    assert!(scene.wakes.lock().unwrap().is_empty());
    for (id, binding) in core::mem::take(&mut *scene.bindings.lock().unwrap()) {
        // SAFETY: every real AML/general frame joined; no external producer or
        // C namespace frame keeps a binding, and its allocation remains live.
        drop(unsafe { r.detach_binding(id) }.unwrap());
        drop(binding);
    }
    // SAFETY: all admitted callbacks completed and every binding detached.
    unsafe { r.retire() }.unwrap();
    CURRENT.store(0, Ordering::Release);
    drop(executor);
    assert_eq!(dropped.load(Ordering::Relaxed), 16);
    assert_eq!(cpu.flags(), 0x202);
    // SAFETY: the Session has no live queued/parked frames or producer;
    // release only after proved executor retirement, otherwise keep quarantine.
    unsafe { core::mem::ManuallyDrop::drop(&mut session) };
    assert_eq!(SEMAPHORES.load(Ordering::Acquire), 0);
    assert!(counts.destroyed.load(Ordering::SeqCst));
    assert_eq!(counts.allocations.load(Ordering::SeqCst), 0);
    assert_eq!(counts.mappings.load(Ordering::SeqCst), 0);
}

#[test]
fn actual_aml_wait_signal_keeps_portal_notify_and_gpe_progress_with_general_parked() {
    run_wait_signal(work::ReservationPolicy::NativeFirmware16);
}
#[test]
fn protected_gpe_policy_keeps_actual_aml_wait_signal_progress_with_general_parked() {
    run_wait_signal(work::ReservationPolicy::NativeFirmware16Protected {
        gpe: work::GpeQueueBudget::QUALIFICATION,
    });
}
