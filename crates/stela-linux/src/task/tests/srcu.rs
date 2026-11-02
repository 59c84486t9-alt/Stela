//! Canonical SRCU on existing real guarded stacks and work Runtime. Each mode
//! gets a fresh process because kernel bootstrap/global ownership is irreversible.
use super::*;
use crate::{
    kernel::KernelOwner,
    srcu::{Bootstrap, Error, Ready},
};
use core::mem::ManuallyDrop;

unsafe extern "C" {
    fn stela_linux_srcu_test(control: *const Control);
    fn stela_linux_srcu_early_test();
    fn stela_linux_srcu_joined_admission_test(expected: bool);
}
#[repr(C)]
struct Control {
    context: *const Machine,
    workers: unsafe extern "C" fn(*const Machine, bool),
}
unsafe extern "C" fn allow_workers(context: *const Machine, refuse: bool) {
    // SAFETY: C's bounded control call borrows the actual retained platform.
    unsafe { &*context }
        .refuse_workers
        .store(refuse, Ordering::Release);
}
struct Harness {
    executor: ManuallyDrop<Executor<16>>,
    cpu: Arc<CpuModel>,
    kernel: Arc<KernelOwner<Machine, 16>>,
    dropped: Arc<AtomicU64>,
}
impl Harness {
    fn new(refuse: bool) -> Self {
        // SAFETY: fresh isolated process, same real canonical allocator.
        assert!(unsafe { crate::heap::register(try_allocate) }.is_ok());
        let cpu = CpuModel::new();
        let f = Fixture::new(cpu.clone());
        // SAFETY: this test owns the hosted queue and is its sole producer.
        let queue = unsafe { Queue::<16>::new(cpu.clone(), f) }.unwrap();
        let dropped = Arc::new(AtomicU64::new(0));
        let executor = ManuallyDrop::new(
            Executor::new_hosted_service_for_test(queue, stacks_count(&dropped, 16 * 1024, 16))
                .unwrap(),
        );
        let clock: Arc<dyn service::Clock> = Arc::new(ServiceClock {
            cpu: cpu.clone(),
            reads: Arc::new(AtomicU64::new(0)),
            start: std::time::Instant::now(),
        });
        let idle = Arc::new(ServiceIdle {
            clock: clock.clone(),
            owner: thread::current(),
            waits: AtomicU64::new(0),
        });
        let domain = service::Domain::new(clock.clone(), idle).unwrap();
        let machine = Machine {
            clock: Some(clock),
            refuse_workers: AtomicBool::new(refuse),
            ..Machine::default()
        };
        // SAFETY: before any task/WQ/entry activity. This isolated kernel and
        // actual executor/service/code roots remain retained until process exit.
        let kernel = Arc::new(
            unsafe { KernelOwner::new(machine, executor.runtime(), domain) }
                .unwrap_or_else(|failure| panic!("{}", failure.error)),
        );
        kernel.platform().environment.store(
            ptr::from_ref(kernel.environment().get_ref()).cast_mut(),
            Ordering::Release,
        );
        kernel.environment().start().unwrap();
        Self {
            executor,
            cpu,
            kernel,
            dropped,
        }
    }
    fn runtime(&self) -> Pin<&Runtime<16>> {
        self.executor.runtime()
    }
    fn start(&self) -> Bootstrap<Machine, 16> {
        // SAFETY: actual hosted dispatcher with no Linux/native callback scope;
        // this harness keeps all runtime/platform/code roots for kernel life.
        unsafe { Bootstrap::start(self.kernel.clone()) }
            .unwrap_or_else(|failure| panic!("{}", failure.error))
    }
    fn drive_bootstrap(&self, bootstrap: &Bootstrap<Machine, 16>) {
        let mut steps = 0;
        while bootstrap.status().unwrap().is_none() {
            assert!(steps < 100_000, "SRCU bootstrap did not return");
            self.runtime().step_or_idle().unwrap();
            steps += 1;
        }
    }
    fn ready(&self) -> Ready<Machine, 16> {
        let bootstrap = self.start();
        assert_eq!(bootstrap.status().unwrap(), None, "no inline bootstrap");
        self.drive_bootstrap(&bootstrap);
        bootstrap
            .join()
            .unwrap_or_else(|failure| panic!("{}", failure.error))
    }
    fn kept(&self) {
        assert_eq!(self.kernel.environment().stop(), Err(WorkError::Busy));
        // SAFETY: negative control refuses before any domain/binding retirement.
        assert_eq!(
            unsafe { self.kernel.environment().retire() },
            Err(WorkError::Busy)
        );
        assert_eq!(self.dropped.load(Ordering::Acquire), 0);
    }
}
struct TestJob {
    kernel: Arc<KernelOwner<Machine, 16>>,
    early: bool,
}
unsafe extern "C" fn body(context: *mut c_void) {
    // SAFETY: the harness retains this owned box through exact ticket completion.
    let job = unsafe { &*context.cast::<TestJob>() };
    // SAFETY: actual retained task of this exact canonical environment.
    let _entered = unsafe { crate::owner::Entered::new(job.kernel.raw()) };
    if job.early {
        // SAFETY: entered canonical task; original boot-domain storage is static.
        unsafe { stela_linux_srcu_early_test() };
    } else {
        let control = Control {
            context: ptr::from_ref(job.kernel.platform()),
            workers: allow_workers,
        };
        // SAFETY: actual retained task; C keeps this stack/control until all its
        // dynamic domains, callback frames and queued work have really joined.
        unsafe { stela_linux_srcu_test(&control) };
    }
}
fn publish(
    h: &Harness,
    early: bool,
) -> (
    ManuallyDrop<Box<TestJob>>,
    stela_driver_base::platform::work::Ticket,
) {
    let mut job = ManuallyDrop::new(Box::new(TestJob {
        kernel: h.kernel.clone(),
        early,
    }));
    let context = ptr::from_mut(&mut **job).cast();
    // SAFETY: owned job remains immovable and retained through exact completion
    // or caught-unwind/abandonment; Runtime binds the real task before body.
    let ticket = unsafe { h.kernel.environment().spawn(body, context) }.unwrap();
    (job, ticket)
}
fn join_job(
    h: &Harness,
    mut job: ManuallyDrop<Box<TestJob>>,
    ticket: stela_driver_base::platform::work::Ticket,
) {
    let mut steps = 0;
    while !h.runtime().queue().completed(ticket).unwrap() {
        assert!(steps < 100_000, "SRCU domain fixture did not join");
        h.runtime().step_or_idle().unwrap();
        steps += 1;
    }
    // SAFETY: exact callback/owner tail completed before releasing its context.
    drop(unsafe { ManuallyDrop::take(&mut job) });
}
fn normal() {
    let h = Harness::new(false);
    let ready = h.ready();
    assert!(Arc::ptr_eq(ready.kernel(), &h.kernel));
    let (job, ticket) = publish(&h, false);
    join_job(&h, job, ticket);
    let duplicate = h.start();
    let address = ptr::from_ref(&duplicate) as usize;
    // No dispatcher step occurs concurrently: this diagnostic thread checks
    // context before any affine state/result or C owner access.
    let wrong = thread::spawn(move || {
        // SAFETY: parent keeps exact object immutable until this thread joins;
        // status must refuse at real CPU check before touching Cell metadata.
        unsafe { &*(address as *const Bootstrap<Machine, 16>) }.status()
    })
    .join()
    .unwrap();
    assert_eq!(wrong, Err(WorkError::WrongCpu));
    h.drive_bootstrap(&duplicate);
    let failure = duplicate
        .join()
        .err()
        .expect("duplicate activation refused");
    assert_eq!(failure.error, Error::Native(-114));
    h.kept();
}
fn early() {
    let h = Harness::new(false);
    let bootstrap = h.start();
    let (job, ticket) = publish(&h, true);
    h.drive_bootstrap(&bootstrap);
    assert!(bootstrap.join().is_ok());
    join_job(&h, job, ticket);
    h.kept();
}
fn refusal() {
    let h = Harness::new(true);
    let bootstrap = h.start();
    h.drive_bootstrap(&bootstrap);
    let failure = bootstrap
        .join()
        .err()
        .expect("real worker refusal observed");
    assert_eq!(failure.error, Error::Native(-110));
    assert!(h.kernel.platform().worker_attempts[1].load(Ordering::Acquire) > 0);
    assert!(h.kernel.platform().worker_attempts[2].load(Ordering::Acquire) > 0);
    h.kept();
    h.kernel
        .platform()
        .refuse_workers
        .store(false, Ordering::Release);
    let _ready = h.ready();
    // Old completed/refused bootstrap never becomes a successful new attempt.
    assert!(!matches!(failure.bootstrap.status(), Ok(Some(Ok(())))));
    h.kept();
}
fn replacement_refusal() {
    let h = Harness::new(false);
    h.kernel.platform().worker_limits[1].store(1, Ordering::Release);
    h.kernel.platform().worker_limits[2].store(1, Ordering::Release);
    let bootstrap = h.start();
    h.drive_bootstrap(&bootstrap);
    let failure = bootstrap
        .join()
        .err()
        .expect("replacement readiness refused");
    assert_eq!(failure.error, Error::Native(-11));
    assert!(h.kernel.platform().worker_attempts[1].load(Ordering::Acquire) >= 2);
    assert!(h.kernel.platform().worker_attempts[2].load(Ordering::Acquire) >= 2);
    h.kept();
    h.kernel.platform().worker_limits[1].store(0, Ordering::Release);
    h.kernel.platform().worker_limits[2].store(0, Ordering::Release);
    let _ready = h.ready();
    assert!(!matches!(failure.bootstrap.status(), Ok(Some(Ok(())))));
    h.kept();
}
fn abandon() {
    let h = Harness::new(false);
    let original = Arc::strong_count(&h.kernel);
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let bootstrap = h.start();
        assert_eq!(bootstrap.status().unwrap(), None);
        assert_eq!(Arc::strong_count(&h.kernel), original + 1);
        panic!("abandon published SRCU bootstrap");
    }));
    assert!(caught.is_err());
    assert_eq!(Arc::strong_count(&h.kernel), original + 1);
    for _ in 0..100_000 {
        if h.kernel.platform().worker_attempts[1].load(Ordering::Acquire) >= 2
            && h.kernel.platform().worker_attempts[2].load(Ordering::Acquire) >= 2
        {
            break;
        }
        h.runtime().step_or_idle().unwrap();
    }
    assert!(h.kernel.platform().worker_attempts[1].load(Ordering::Acquire) >= 2);
    assert!(h.kernel.platform().worker_attempts[2].load(Ordering::Acquire) >= 2);
    // Run available tails only; no fixed elapsed time is a completion receipt.
    for _ in 0..32 {
        if !h.runtime().step().unwrap() {
            break;
        }
    }
    assert_eq!(Arc::strong_count(&h.kernel), original + 1);
    h.kept();
}
#[derive(Clone)]
pub(super) struct PublicationObserver {
    queue: alloc::sync::Weak<Queue<16>>,
    baseline: usize,
    armed: Arc<AtomicBool>,
    observed: Arc<AtomicBool>,
}
impl PublicationObserver {
    pub(super) fn after_restore(&self, flags: u64) {
        // Inner queue guards restore IF0; target only the actual outer
        // restoration of the caller's enabled flags after publication.
        if flags & 0x200 == 0 || !self.armed.swap(false, Ordering::AcqRel) {
            return;
        }
        let published = self
            .queue
            .upgrade()
            .unwrap()
            .published_jobs_for_test()
            .unwrap();
        if published > self.baseline {
            self.observed.store(true, Ordering::Release);
            panic!("restore after actual callback publication");
        }
        self.armed.store(true, Ordering::Release);
    }
}
fn publication_unwind() {
    let h = Harness::new(false);
    let observed = Arc::new(AtomicBool::new(false));
    let baseline = h.runtime().queue().published_jobs_for_test().unwrap();
    *h.cpu.publication_probe.lock().unwrap() = Some(PublicationObserver {
        queue: Arc::downgrade(h.runtime().queue()),
        baseline,
        armed: Arc::new(AtomicBool::new(true)),
        observed: observed.clone(),
    });
    let original = Arc::strong_count(&h.kernel);
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _bootstrap = h.start();
        panic!("publisher did not inject the requested failure");
    }));
    assert!(caught.is_err() && observed.load(Ordering::Acquire));
    assert_eq!(h.cpu.flags.load(Ordering::Acquire), 0x202);
    h.cpu.publication_probe.lock().unwrap().take();
    assert_eq!(Arc::strong_count(&h.kernel), original + 1);
    // No Bootstrap handle returned. Actual publication is independently visible
    // and its queued callback can still execute against the retained job.
    for _ in 0..100_000 {
        if h.kernel.platform().worker_attempts[1].load(Ordering::Acquire) >= 2
            && h.kernel.platform().worker_attempts[2].load(Ordering::Acquire) >= 2
        {
            break;
        }
        h.runtime().step_or_idle().unwrap();
    }
    assert!(h.kernel.platform().worker_attempts[1].load(Ordering::Acquire) >= 2);
    assert!(h.kernel.platform().worker_attempts[2].load(Ordering::Acquire) >= 2);
    assert_eq!(Arc::strong_count(&h.kernel), original + 1);
    h.kept();
}
#[test]
#[ignore = "isolation: canonical kernel/SRCU globals retained for process life"]
fn srcu_child() {
    match std::env::var("STELA_SRCU_SCENARIO").unwrap().as_str() {
        "normal" => normal(),
        "early" => early(),
        "refusal" => refusal(),
        "abandon" => abandon(),
        "publication-unwind" => publication_unwind(),
        "replacement-refusal" => replacement_refusal(),
        "joined-boundary" => joined_boundary(),
        mode => panic!("unknown SRCU mode {mode}"),
    }
}
pub(super) fn run_child() {
    let selector = "task::tests::srcu::srcu_child";
    for mode in [
        "normal",
        "early",
        "refusal",
        "abandon",
        "publication-unwind",
        "replacement-refusal",
        "joined-boundary",
    ] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .env("STELA_SRCU_SCENARIO", mode)
            .args([
                "--exact",
                selector,
                "--ignored",
                "--test-threads=1",
                "--nocapture",
                "--format=pretty",
                "--color=never",
            ])
            .output()
            .unwrap();
        let stdout = std::string::String::from_utf8_lossy(&output.stdout);
        let stderr = std::string::String::from_utf8_lossy(&output.stderr);
        let named = stdout
            .lines()
            .any(|line| line == std::format!("test {selector} ... ok"));
        let one = stdout
            .lines()
            .any(|line| line.starts_with("test result: ok. 1 passed; 0 failed; 0 ignored;"));
        assert!(
            output.status.success() && named && one,
            "SRCU {mode} child did not execute/pass once ({}):\n{}{}",
            output.status,
            stdout,
            stderr
        );
    }
}

struct JoinedCheck {
    kernel: Arc<KernelOwner<Machine, 16>>,
    expected: bool,
}
unsafe extern "C" fn joined_check(pointer: *mut c_void) {
    // SAFETY: same retained immutable job/kernel until its exact native join.
    let job = unsafe { &*pointer.cast::<JoinedCheck>() };
    // SAFETY: actual canonical Runtime-bound task, no borrowed native permit.
    let _entered = unsafe { crate::owner::Entered::new(job.kernel.raw()) };
    // SAFETY: ordinary current task queries only the actual joined source state.
    unsafe { stela_linux_srcu_joined_admission_test(job.expected) };
}
fn check_joined_admission(h: &Harness, expected: bool) {
    let mut job = ManuallyDrop::new(Box::new(JoinedCheck {
        kernel: h.kernel.clone(),
        expected,
    }));
    let pointer = ptr::from_mut(&mut **job).cast();
    // SAFETY: pinned owned box/root lives until exact callback and exit tail.
    let ticket = unsafe { h.kernel.environment().spawn(joined_check, pointer) }.unwrap();
    let mut steps = 0;
    while !h.runtime().queue().completed(ticket).unwrap() {
        assert!(steps < 100_000, "joined SRCU query task did not complete");
        h.runtime().step_or_idle().unwrap();
        steps += 1;
    }
    // SAFETY: actual callback/owner tail and native task ticket completed above.
    drop(unsafe { ManuallyDrop::take(&mut job) });
}
fn joined_boundary() {
    let h = Harness::new(false);
    let bootstrap = h.start();
    h.drive_bootstrap(&bootstrap);
    assert_eq!(bootstrap.status().unwrap(), Some(Ok(())));
    // Original work/timer probes completed, but the exact owned native
    // Bootstrap has not yet been consumed/joined: consumer admission refuses.
    check_joined_admission(&h, false);
    let ready = bootstrap
        .join()
        .unwrap_or_else(|failure| panic!("{}", failure.error));
    assert!(Arc::ptr_eq(ready.kernel(), &h.kernel));
    check_joined_admission(&h, true);
    h.kept();
}
