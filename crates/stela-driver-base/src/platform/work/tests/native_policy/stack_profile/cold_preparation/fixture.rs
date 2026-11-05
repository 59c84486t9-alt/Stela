//! Owned hosted fixtures for cold stack preparation.
use super::*;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Mode {
    Bytes,
    Hot,
    Park,
    Denied,
    RestoreRefusal,
    Closed,
    Drop,
    Stale,
    Forget,
}
pub(super) struct ModelCpu {
    pub(super) model: Arc<test_support::CpuModel>,
    pub(super) dropped: Arc<AtomicUsize>,
    pub(super) mode: Mode,
    pub(super) watch: AtomicU64,
    pub(super) watch_state: AtomicU64,
    pub(super) restored: AtomicBool,
}
// SAFETY: same-host-thread flags only. The bounded watch observes an
// exclusively kept unstarted fixture backing; it never calls Runtime,
// allocates, switches or grants a native CPU/root/provider capability.
unsafe impl Cpu for ModelCpu {
    fn check_cpu(&self) -> Result<(), WorkError> {
        self.model.check_cpu()
    }
    fn in_interrupt(&self) -> bool {
        self.model.in_interrupt()
    }
    fn save_disable(&self) -> Result<u64, WorkError> {
        self.model.save_disable()
    }
    unsafe fn restore(&self, flags: u64) {
        if flags & 0x200 != 0 {
            let address = self.watch.load(Ordering::Acquire);
            let state = self.watch_state.load(Ordering::Acquire);
            // SAFETY: an armed watch keeps this exact excluded Task field on
            // the model's same OS thread. Earlier checks may restore flags, but
            // only the Preparing transfer makes this the zeroing boundary.
            let preparing = address != 0
                && unsafe { (state as *const TaskState).read() } == TaskState::Preparing;
            if preparing {
                self.watch.store(0, Ordering::Release);
                assert_eq!(
                    // SAFETY: creator armed the exact owned cold usable base
                    // after poisoning it; backing stays held through this read.
                    unsafe { (address as *const u8).read_volatile() },
                    0xa7
                );
                self.restored.store(true, Ordering::Release);
            }
        }
        // SAFETY: flags are this same model's enclosing save_disable.
        unsafe { self.model.restore(flags) }
    }
    fn ticks(&self) -> u64 {
        self.model.ticks()
    }
    fn fatal(&self, error: WorkError) -> ! {
        if matches!(self.mode, Mode::Drop | Mode::Stale | Mode::Forget) {
            assert_eq!(
                error,
                if self.mode == Mode::Forget {
                    WorkError::Pending
                } else {
                    WorkError::Closed
                }
            );
            assert_eq!(self.dropped.load(Ordering::Relaxed), 0);
            println!("STELA_COLD_FATAL_RETAINED {:?}", self.mode);
            std::process::exit(93);
        }
        panic!("unexpected cold fixture fatal {error:?}")
    }
}
pub(super) struct Authority {
    pub(super) cpu: Arc<ModelCpu>,
    pub(super) active: Cell<bool>,
}
impl Authority {
    pub(super) fn new(cpu: &Arc<ModelCpu>) -> Self {
        Self {
            cpu: cpu.clone(),
            active: Cell::new(true),
        }
    }
}
// SAFETY: hosted callback model checks its OS thread and active borrowed
// segment without allocation/wait, including IF0. Native DriverExecution and
// Guest park/reentry remain separate production validation requirements.
unsafe impl EnteredProcess for Authority {
    fn check(&self) -> Result<(), WorkError> {
        self.cpu.check_cpu()?;
        if self.active.get()
            && !(self.cpu.mode == Mode::RestoreRefusal && self.cpu.restored.load(Ordering::Acquire))
        {
            Ok(())
        } else {
            Err(WorkError::Unavailable)
        }
    }
}
pub(super) struct Scene {
    pub(super) runtime: AtomicU64,
    pub(super) cpu: Arc<ModelCpu>,
    pub(super) mode: Mode,
    pub(super) marked: AtomicUsize,
    pub(super) hot: Mutex<Option<ContextId>>,
    pub(super) binding: Mutex<Option<(Arc<Binding>, WakeHandle<64>)>>,
}
impl Scene {
    pub(super) fn runtime(&self) -> Pin<&Runtime<64>> {
        // SAFETY: exact pinned executor is held through every fixture use;
        // fatal paths keep the complete allocation before any destruction.
        unsafe {
            Pin::new_unchecked(&*(self.runtime.load(Ordering::Acquire) as *const Runtime<64>))
        }
    }
    pub(super) fn reserved(&self) -> (usize, core::ops::Range<usize>) {
        let r = self.runtime();
        let flags = self.cpu.save_disable().unwrap();
        // SAFETY: creator/dispatcher fixture holds IF0 and all peers are
        // stopped. These reads inspect immutable kept geometry/history only.
        let found = unsafe {
            (&*r.tasks.get())
                .iter()
                .enumerate()
                .find(|(_, t)| t.state == TaskState::Escrow)
                .map(|(i, t)| (i, t.stack.bounds.clone()))
        }
        .unwrap();
        // SAFETY: enclosing model flags, no task borrow survives restore.
        unsafe { self.cpu.restore(flags) };
        found
    }
}
pub(super) unsafe extern "C" fn marker(pointer: *mut c_void) {
    // SAFETY: Scene/code remain queue-owned through completion/quarantine.
    let f = unsafe { &*pointer.cast::<Scene>() };
    let r = f.runtime();
    f.marked.fetch_add(1, Ordering::Relaxed);
    if f.mode == Mode::Hot {
        *f.hot.lock().unwrap() = Some(r.current_id().unwrap());
    }
    if f.mode == Mode::Park {
        assert_eq!(r.owned_escrows.get(), 1);
        let (binding, wake) = f.binding.lock().unwrap().as_ref().unwrap().clone();
        binding.blocked.store(false, Ordering::Release);
        wake.wake().unwrap();
    }
}
pub(super) fn take_prepared<'a>(
    owner: OwnedGeneralEscrow<'a, 64>,
    authority: &dyn EnteredProcess,
) -> GeneralStackPreparation<'a, 64> {
    // SAFETY: fixture callers retain the unbound frame with no C or alias user.
    match unsafe { owner.prepare_stack(authority) } {
        Ok(cold) => cold,
        Err((owner, error)) => {
            // SAFETY: preparation refused before creating a source user.
            unsafe { owner.cancel(authority) }.unwrap();
            panic!("cold precheck failed {error:?}")
        }
    }
}
