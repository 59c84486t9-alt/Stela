//! Real mmap allocation owners kept by opaque pins; PA labels are hosted
//! model metadata only and never check native physical/cache/device access.
use super::*;
use crate::bus::dma::memory::{CacheAttribute, CpuMapping, MemoryError, PageBacking, PinnedPages};
use core::{ops::Range, ptr::NonNull};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Case {
    Good,
    HeldView,
    Missing,
    Oom,
    Logical,
    Subset,
    Other,
    Granule,
    Denied,
    Closed,
    PostStale,
    Park,
    Drop,
    Stale,
    Forget,
}
struct PinScene {
    runtime: AtomicU64,
    cpu: Arc<ModelCpu>,
    case: Case,
    active: AtomicBool,
    entered: AtomicUsize,
    exports: AtomicUsize,
    pins_dropped: Arc<AtomicUsize>,
    marked: AtomicUsize,
    binding: Mutex<Option<(Arc<Binding>, WakeHandle<64>)>>,
    held_view: Mutex<Option<CpuMapping>>,
}
impl PinScene {
    fn runtime(&self) -> Pin<&Runtime<64>> {
        // SAFETY: setup keeps this exact pinned Executor until every callback
        // joins or the observed fatal path keeps all ownership.
        unsafe {
            Pin::new_unchecked(&*(self.runtime.load(Ordering::Acquire) as *const Runtime<64>))
        }
    }
    fn authority(&self) -> PinAuthority<'_> {
        assert_eq!(self.entered.fetch_add(1, Ordering::AcqRel), 0);
        PinAuthority(self)
    }
}
struct PinAuthority<'a>(&'a PinScene);
impl Drop for PinAuthority<'_> {
    fn drop(&mut self) {
        assert_eq!(self.0.entered.fetch_sub(1, Ordering::AcqRel), 1);
    }
}
// SAFETY: hosted same-thread borrowed-segment model only. Checks never allocate
// or wait, including at IF0; no native DriverExecution/CPU capability is claimed.
unsafe impl EnteredProcess for PinAuthority<'_> {
    fn check(&self) -> Result<(), WorkError> {
        self.0.cpu.check_cpu()?;
        if self.0.active.load(Ordering::Acquire) && self.0.entered.load(Ordering::Acquire) == 1 {
            Ok(())
        } else {
            Err(WorkError::Unavailable)
        }
    }
}
struct Source {
    actual: Arc<Box<dyn StackBacking>>,
    other: Option<Arc<Box<dyn StackBacking>>>,
    scene: Arc<PinScene>,
    index: usize,
    last_epoch: AtomicU64,
    active_epoch: Arc<AtomicU64>,
}
// SAFETY: this wrapper owns the original mmap object, not just bounds
// or a lifetime token. Its Arc keeps both real PROT_NONE guards and RAM alive.
// Exported page views share THAT allocation owner until exact release.
unsafe impl StackBacking for Source {
    fn bounds(&self) -> Range<usize> {
        self.actual.bounds()
    }
    fn guard(&self) -> Range<usize> {
        self.actual.guard()
    }
    unsafe fn pin_prepared_pages(&self, epoch: u64) -> Result<PinnedPages, MemoryError> {
        assert!(epoch != 0);
        self.scene.exports.fetch_add(1, Ordering::Relaxed);
        assert_eq!(self.scene.cpu.model.flags(), 0x202);
        assert_eq!(self.scene.entered.load(Ordering::Acquire), 1);
        let range = self.actual.bounds();
        assert!(
            // SAFETY: the cold caller holds the never-entered mapping in
            // Preparing and has zeroed its usable bytes. This reads only them.
            unsafe { core::slice::from_raw_parts(range.start as *const u8, range.len()) }
                .iter()
                .all(|byte| *byte == 0)
        );
        if self.scene.case == Case::Oom {
            return Err(MemoryError::OutOfMemory);
        }
        assert!(epoch > self.last_epoch.load(Ordering::Acquire));
        if self
            .active_epoch
            .compare_exchange(0, epoch, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(MemoryError::Unavailable);
        }
        let lease = EpochLease {
            active: self.active_epoch.clone(),
            epoch,
        };
        let actual = self.other.as_ref().unwrap_or(&self.actual).clone();
        let range = actual.bounds();
        let bytes = if self.scene.case == Case::Subset {
            range.len() / 2
        } else {
            range.len()
        };
        let shift = if self.scene.case == Case::Granule {
            14
        } else {
            12
        };
        // These independent symbolic PFNs model allocation granules; actual
        // CPU storage/ownership are real, but this is not native PA evidence.
        let physical = (0..(bytes >> shift))
            .map(|i| 0x6000_0000 + self.index as u64 * 0x10_0000 + ((i as u64) << shift))
            .collect();
        let view = View {
            actual,
            start: range.start,
            physical,
            shift,
            dropped: self.scene.pins_dropped.clone(),
            _epoch: lease,
        };
        let logical = if self.scene.case == Case::Logical {
            bytes - 1
        } else {
            bytes
        };
        let pin = PinnedPages::new(Box::new(view), logical, 1 << shift)?;
        self.last_epoch.store(epoch, Ordering::Release);
        if self.scene.case == Case::HeldView {
            *self.scene.held_view.lock().unwrap() =
                Some(pin.cpu_mapping(CacheAttribute::WriteBack)?);
        }
        if self.scene.case == Case::PostStale {
            self.scene.active.store(false, Ordering::Release);
        }
        Ok(pin)
    }
}
struct EpochLease {
    active: Arc<AtomicU64>,
    epoch: u64,
}
impl Drop for EpochLease {
    fn drop(&mut self) {
        assert_eq!(
            self.active
                .compare_exchange(self.epoch, 0, Ordering::AcqRel, Ordering::Acquire),
            Ok(self.epoch)
        );
    }
}
struct View {
    actual: Arc<Box<dyn StackBacking>>,
    start: usize,
    physical: Vec<u64>,
    shift: u8,
    dropped: Arc<AtomicUsize>,
    _epoch: EpochLease,
}
impl Drop for View {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }
}
// SAFETY: CPU-model view keeps the SAME real exclusively owned mmap object;
// its usable bytes are mapped/zeroed and guards excluded. Immutable PA
// labels/granule metadata are symbolic and never used for DMA/native evidence.
// Dropping the view cannot munmap while Runtime still holds the real owner.
unsafe impl PageBacking for View {
    fn cpu_base(&self) -> NonNull<u8> {
        assert!(self.actual.bounds().contains(&self.start));
        NonNull::new(self.start as *mut u8).unwrap()
    }
    fn physical_pages(&self) -> &[u64] {
        &self.physical
    }
    fn page_shift(&self) -> u8 {
        self.shift
    }
    fn cache_attribute(&self) -> CacheAttribute {
        CacheAttribute::WriteBack
    }
}
fn mappings(f: &Arc<PinScene>, dropped: &Arc<AtomicUsize>) -> Vec<Stack> {
    let other = if f.case == Case::Other {
        let Stack { backing, .. } = support::mapped(kernel(), 0, dropped);
        Some(Arc::new(backing))
    } else {
        None
    };
    support::stacks(dropped, 20)
        .into_iter()
        .enumerate()
        .map(|(index, stack)| {
            if f.case == Case::Missing {
                return stack;
            }
            let Stack { backing, .. } = stack;
            Stack::new(Box::new(Source {
                actual: Arc::new(backing),
                other: other.clone(),
                scene: f.clone(),
                index,
                last_epoch: AtomicU64::new(0),
                active_epoch: Arc::new(AtomicU64::new(0)),
            }))
            .unwrap()
        })
        .collect()
}
unsafe extern "C" fn marker(pointer: *mut c_void) {
    // SAFETY: queue keeps this exact Scene/code until real completion.
    let f = unsafe { &*pointer.cast::<PinScene>() };
    f.marked.fetch_add(1, Ordering::Relaxed);
    if f.case == Case::Park {
        assert_eq!(f.entered.load(Ordering::Acquire), 0);
        let (binding, wake) = f.binding.lock().unwrap().as_ref().unwrap().clone();
        binding.blocked.store(false, Ordering::Release);
        wake.wake().unwrap();
    }
}
unsafe extern "C" fn creator(pointer: *mut c_void) {
    // SAFETY: Scene, Foreground frame and all owners survive join.
    let f = unsafe { &*pointer.cast::<PinScene>() };
    let r = f.runtime();
    let authority = f.authority();
    let owner = r
        .reserve_unstarted_general(&authority, kernel())
        .unwrap()
        .into_owned()
        .unwrap();
    let cold = take_prepared(owner, &authority);
    if f.case == Case::Denied {
        f.active.store(false, Ordering::Release);
    }
    if f.case == Case::Closed {
        r.queue.close().unwrap();
    }
    let pinned = match cold.pin(&authority) {
        Ok(pin) => pin,
        Err((cold, error)) => {
            let expected = match f.case {
                Case::Missing => StackPinError::Memory(MemoryError::Unavailable),
                Case::Oom => StackPinError::Memory(MemoryError::OutOfMemory),
                Case::Logical => StackPinError::Memory(MemoryError::InvalidSize),
                Case::Subset | Case::Granule => StackPinError::Memory(MemoryError::InvalidPageList),
                Case::Other => StackPinError::Memory(MemoryError::OutsideReservation),
                Case::Denied | Case::PostStale => StackPinError::Work(WorkError::Unavailable),
                Case::Closed => StackPinError::Work(WorkError::Closed),
                _ => panic!("unexpected pin refusal {error:?}"),
            };
            assert_eq!(error, expected);
            assert_eq!(f.pins_dropped.load(Ordering::Relaxed), 0);
            assert_eq!(r.owned_escrows.get(), 1);
            f.active.store(true, Ordering::Release);
            drop(authority);
            let fresh = f.authority();
            let acquired = matches!(
                f.case,
                Case::Logical | Case::Subset | Case::Granule | Case::Other | Case::PostStale
            );
            let cold = if acquired {
                match cold.pin(&fresh) {
                    Err((cold, error)) => {
                        assert_eq!(error, StackPinError::Work(WorkError::Busy));
                        cold
                    }
                    Ok(_) => panic!("retry accumulated another actual pin"),
                }
            } else {
                cold
            };
            unsafe { cold.cancel(&fresh) }.unwrap();
            assert_eq!(
                f.pins_dropped.load(Ordering::Relaxed),
                usize::from(acquired)
            );
            return;
        }
    };
    assert_eq!(f.exports.load(Ordering::Relaxed), 1);
    assert_eq!(f.pins_dropped.load(Ordering::Relaxed), 0);
    assert_eq!(r.owned_escrows.get(), 1);
    match f.case {
        Case::Drop => {
            drop(pinned);
        }
        Case::Stale => {
            f.active.store(false, Ordering::Release);
            assert_eq!(
                cancellation_error(unsafe { pinned.cancel(&authority) }),
                WorkError::Unavailable
            );
        }
        Case::Forget => {
            core::mem::forget(pinned);
        }
        Case::Park => {
            let binding = Arc::new(Binding {
                id: AtomicU64::new(0),
                blocked: AtomicBool::new(true),
            });
            let wake = r.bind_current(binding.clone()).unwrap();
            *f.binding.lock().unwrap() = Some((binding, wake));
            f.active.store(false, Ordering::Release);
            drop(authority);
            assert_eq!(r.park_if_blocked().unwrap(), ParkOutcome::Resumed);
            f.active.store(true, Ordering::Release);
            unsafe { pinned.cancel(&f.authority()) }.unwrap();
        }
        _ => {
            unsafe { pinned.cancel(&authority) }.unwrap();
        }
    }
    if matches!(f.case, Case::Drop | Case::Stale | Case::Forget) {
        assert_eq!(f.pins_dropped.load(Ordering::Relaxed), 0);
        println!("STELA_COLD_PIN_OWNER_RETAINED {:?}", f.case);
        return;
    }
    assert_eq!(r.owned_escrows.get(), 0);
    assert_eq!(f.pins_dropped.load(Ordering::Relaxed), 1);
    if f.case == Case::Good {
        // SAFETY: original cold frame was reseeded/cancelled; this
        // finite marker fits the real kernel-sized owned worker and stays held.
        unsafe {
            r.queue
                .execute_general_with_requirement(kernel(), marker, pointer)
        }
        .unwrap();
    }
}
fn run(case: Case) {
    let dropped = Arc::new(AtomicUsize::new(0));
    let cpu = Arc::new(ModelCpu {
        model: test_support::CpuModel::new(),
        dropped: dropped.clone(),
        mode: match case {
            Case::Drop => Mode::Drop,
            Case::Stale => Mode::Stale,
            Case::Forget => Mode::Forget,
            _ => Mode::Bytes,
        },
        watch: AtomicU64::new(0),
        watch_state: AtomicU64::new(0),
        restored: AtomicBool::new(false),
    });
    let f = Arc::new(PinScene {
        runtime: AtomicU64::new(0),
        cpu: cpu.clone(),
        case,
        active: AtomicBool::new(true),
        entered: AtomicUsize::new(0),
        exports: AtomicUsize::new(0),
        pins_dropped: Arc::new(AtomicUsize::new(0)),
        marked: AtomicUsize::new(0),
        binding: Mutex::new(None),
        held_view: Mutex::new(None),
    });
    // SAFETY: same-thread fixture, code and real mmap owners remain held.
    let queue = unsafe { Queue::<64>::new(cpu.clone(), f.clone()) }.unwrap();
    let executor =
        Executor::new_hosted_profile_for_test(queue, mappings(&f, &dropped), policy(), profile())
            .unwrap();
    let r = executor.runtime();
    f.runtime
        .store(r.get_ref() as *const Runtime<64> as u64, Ordering::Release);
    let pointer = Arc::as_ptr(&f).cast_mut().cast();
    if case == Case::Park {
        // SAFETY: queue-kept ordinary peer wakes only the bound creator.
        unsafe { r.queue.execute(Kind::General, marker, pointer) }.unwrap();
    }
    // SAFETY: exact Foreground callback and all mapping owners survive join.
    unsafe { r.call_foreground(creator, pointer, cpu.ticks() + 1_000_000_000) }.unwrap();
    r.drain(cpu.ticks() + 1_000_000_000).unwrap();
    assert_eq!(f.entered.load(Ordering::Acquire), 0);
    if let Some((binding, wake)) = f.binding.lock().unwrap().take() {
        // SAFETY: callbacks completed; all external fixture producers stopped.
        drop(unsafe { r.detach_binding(wake.context_id()) }.unwrap());
        drop(binding);
        drop(wake);
    }
    assert_eq!(dropped.load(Ordering::Relaxed), 0);
    assert_eq!(
        f.marked.load(Ordering::Relaxed),
        usize::from(matches!(case, Case::Good | Case::Park))
    );
    assert_eq!(
        f.exports.load(Ordering::Relaxed),
        usize::from(!matches!(case, Case::Missing | Case::Denied | Case::Closed))
    );
    r.queue.close().unwrap();
    // SAFETY: no device/IRQ/other producer exists, frames joined and binding detached;
    // pin release completed under fresh permission. Backing is still valid.
    unsafe { r.retire() }.unwrap();
    drop(executor);
    assert_eq!(
        dropped.load(Ordering::Relaxed),
        if case == Case::Other { 33 } else { 32 }
    );
}
#[test]
fn pin_cancel_restores_entry() {
    run(Case::Good);
}
#[test]
fn pin_refusal_keeps_owner() {
    for case in [
        Case::Missing,
        Case::Oom,
        Case::Logical,
        Case::Subset,
        Case::Other,
        Case::Granule,
        Case::Denied,
        Case::Closed,
        Case::PostStale,
    ] {
        run(case);
    }
}
#[test]
fn pin_survives_creator_park() {
    run(Case::Park);
}
#[test]
fn pin_abandonment_keeps_owner() {
    if let Ok(case) = std::env::var("STELA_COLD_PIN_MODE") {
        run(match case.as_str() {
            "drop" => Case::Drop,
            "stale" => Case::Stale,
            "forget" => Case::Forget,
            _ => panic!("unknown pin fatal mode"),
        });
        unreachable!();
    }
    let test = format!(
        "{}::pin_abandonment_keeps_owner",
        module_path!().split_once("::").unwrap().1
    );
    for case in ["drop", "stale", "forget"] {
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &test, "--nocapture", "--test-threads=1"])
            .env("STELA_COLD_PIN_MODE", case)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(93),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("STELA_COLD_PIN_OWNER_RETAINED"));
        assert!(stdout.contains("STELA_COLD_FATAL_RETAINED"));
    }
}

mod publication;
