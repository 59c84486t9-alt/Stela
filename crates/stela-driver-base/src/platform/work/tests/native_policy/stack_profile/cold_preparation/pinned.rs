//! Real mmap allocation owners kept by opaque pins; PA labels are hosted
//! model metadata only and never check native physical/cache/device access.
use super::*;
use crate::bus::dma::memory::{CacheAttribute, CpuMapping, MemoryError, PageBacking, PinnedPages};
use crate::platform::work::tests::cancellation_error;
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
mod memory;
use memory::mappings;
mod callbacks;
use callbacks::{creator, marker};

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
