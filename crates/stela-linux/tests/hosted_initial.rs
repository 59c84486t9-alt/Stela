#![cfg(all(
    feature = "hosted-runtime",
    target_os = "linux",
    target_arch = "x86_64"
))]

use std::{
    cell::RefCell,
    ffi::{CStr, c_void},
    io::Read,
    num::NonZeroU64,
    ops::Range,
    pin::Pin,
    process::{self, Command},
    ptr,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};
use stela_driver_base::platform::work::{
    WorkError,
    kernel_domain::{
        DomainRaised, HostedClock, HostedDeadlines, HostedDomain, HostedExecution, HostedExecutor,
        HostedIdle, HostedQueue, HostedRuntime,
    },
};
use stela_driver_base::{
    entropy::{Entropy, EntropyError},
    platform::image::NativeReadOnlyImage,
};
use stela_linux::{
    owner::{
        Entered, Errno, IrqEnableError, MinimumDeadline, Platform, RawOwner, RealtimeOrigin,
        RealtimeRead,
    },
    task::{
        HostedTaskBinding, ResourceBootstrapError, initialize_hosted_resources,
        reserve_hosted_child_stack, start_hosted_threads, step_hosted,
    },
};

struct Host {
    clock: Arc<HostedClock>,
    boot_origin_ns: u64,
    timer: DomainRaised<HostedDomain>,
    tsc_hz: NonZeroU64,
    realtime: RealtimeOrigin,
    random: RefCell<stela_linux::random::Seeded>,
}

struct HostEntropy;

impl Entropy for HostEntropy {
    fn fill(&self, output: &mut [u8]) -> Result<(), EntropyError> {
        std::fs::File::open("/dev/urandom")
            .and_then(|mut source| source.read_exact(output))
            .map_err(|_| EntropyError::Failed)
    }
}

struct ProcessImage {
    read_only: Vec<Range<usize>>,
}

impl ProcessImage {
    fn current() -> Self {
        let path = std::env::current_exe().unwrap();
        let path = path.to_str().unwrap();
        let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
        let read_only: Vec<_> = maps
            .lines()
            .filter_map(|line| {
                let fields = line.strip_suffix(path)?;
                if !fields.ends_with(' ') {
                    return None;
                }
                let mut fields = fields.split_whitespace();
                let (start, end) = fields.next()?.split_once('-')?;
                (fields.next()? == "r--p").then(|| {
                    usize::from_str_radix(start, 16).unwrap()
                        ..usize::from_str_radix(end, 16).unwrap()
                })
            })
            .collect();
        assert!(!read_only.is_empty());
        Self { read_only }
    }
}

// SAFETY: only actual non-executable, read-only mappings of this statically
// resident program are recognized. This isolated process keeps the original
// image and has no permission change, reload, writable alias or unload path.
unsafe impl NativeReadOnlyImage for ProcessImage {
    fn contains(&self, address: usize) -> bool {
        self.read_only.iter().any(|range| range.contains(&address))
    }
}

fn host_boottime() -> Result<u64, WorkError> {
    let mut sample = std::mem::MaybeUninit::<libc::timespec>::uninit();
    // SAFETY: CLOCK_BOOTTIME initializes the exact output on success.
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, sample.as_mut_ptr()) } != 0 {
        return Err(WorkError::Unavailable);
    }
    // SAFETY: the successful host call wrote both fields.
    let sample = unsafe { sample.assume_init() };
    let seconds = u64::try_from(sample.tv_sec).map_err(|_| WorkError::CorruptContext)?;
    let nanos = u64::try_from(sample.tv_nsec).map_err(|_| WorkError::CorruptContext)?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|base| base.checked_add(nanos))
        .ok_or(WorkError::Exhausted)
}

impl Platform for Host {
    fn now_ns(&self) -> i64 {
        self.clock.now_ns().unwrap().try_into().unwrap()
    }
    fn boottime_ns(&self) -> Result<u64, WorkError> {
        host_boottime()?
            .checked_sub(self.boot_origin_ns)
            .ok_or(WorkError::CorruptContext)
    }
    fn calibrated_tsc_hz(&self) -> Option<NonZeroU64> {
        Some(self.tsc_hz)
    }
    fn realtime_at(&self, now: i64, read: RealtimeRead) -> Option<(i64, u32)> {
        self.realtime.read(now, read)
    }
    fn minimum_delay_us(&self, _: u64) -> Result<(), WorkError> {
        Err(WorkError::Unavailable)
    }
    fn minimum_deadline_us(&self, _: u64) -> Result<Box<dyn MinimumDeadline>, WorkError> {
        Err(WorkError::Unavailable)
    }
    fn timer_changed(&self) -> Result<(), WorkError> {
        self.timer.raise()
    }
    fn log(&self, _: i32, message: &CStr) {
        eprintln!("{message:?}");
    }
    fn warn(&self, file: &CStr, line: i32, condition: Option<&CStr>) {
        panic!("Linux warning at {file:?}:{line} {condition:?}");
    }
    fn unsupported(&self, operation: &CStr) {
        panic!("Linux reported {operation:?}");
    }
    fn random_bytes(&self, bytes: &mut [u8]) {
        self.random.borrow_mut().fill(bytes);
    }
    fn mix_random(&self, bytes: &[u8]) -> bool {
        let Ok(ticks) = self.clock.now_ns() else {
            return false;
        };
        self.random.borrow_mut().mix(ticks, bytes);
        true
    }
    fn shutdown(&self, _: bool) {
        process::abort()
    }
    fn map_device(&self, _: u64, _: usize, _: bool) -> Option<*mut c_void> {
        None
    }
    unsafe fn unmap_device(&self, _: *mut c_void) {
        process::abort()
    }
    fn map_pages(&self, _: &[u64]) -> Option<*mut c_void> {
        None
    }
    unsafe fn unmap_pages(&self, _: *mut c_void, _: usize) {
        process::abort()
    }
    fn irq_enable(&self, _: u32) -> Result<(), IrqEnableError> {
        Err(IrqEnableError::retained(-95))
    }
    fn irq_disable(&self, _: u32) -> Result<(), Errno> {
        Err(-95)
    }
    fn irq_retire(&self, _: u32) -> Result<(), Errno> {
        Err(-95)
    }
    unsafe fn copy_from_user(&self, _: *mut u8, _: *const u8, size: usize) -> usize {
        size
    }
    unsafe fn copy_to_user(&self, _: *mut u8, _: *const u8, size: usize) -> usize {
        size
    }
    fn map_user(&self, _: *mut c_void, _: u64, _: u64, _: u64) -> Result<(), Errno> {
        Err(-95)
    }
    fn unmap_user(&self, _: *mut c_void, _: u64, _: usize) -> Result<(), Errno> {
        Err(-95)
    }
}

unsafe extern "C" {
    static init_task: u8;
    static jiffies_64: u64;
    static system_wq: *const c_void;
    static kthreadd_task: *const c_void;
    static sighand_cachep: *const c_void;
    fn stela_linux_current() -> *const u8;
    fn task_sched_runtime(task: *const u8) -> u64;
    fn stela_linux_require_current(owner: *const RawOwner) -> i32;
    fn stela_linux_device_publish_allowed(device: *const c_void) -> bool;
    fn stela_linux_page_catalog_register_extents_v2(
        extents: *const c_void,
        count: usize,
        ops: *const c_void,
        context: *mut c_void,
    ) -> i32;
    fn get_free_pages_noprof(gfp: u32, order: u32) -> usize;
    fn free_pages(address: usize, order: u32);
    fn stela_linux_virt_to_page(address: usize) -> *const c_void;
    fn stela_linux_page_to_virt(page: *const c_void) -> *const c_void;
    fn page_to_pfn(page: *const c_void) -> usize;
    fn pfn_to_page(frame: usize) -> *const c_void;
    fn stela_linux_page_dma_pin(physical: u64) -> *const c_void;
    fn dma_map_phys(
        device: *const c_void,
        physical: u64,
        size: usize,
        direction: i32,
        attrs: usize,
    ) -> u64;
    fn stela_linux_pages_finish();
    fn stela_linux_available_page_frames(out: *mut usize) -> i32;
    fn stela_linux_task_resource_roots_complete(owner: *const RawOwner) -> bool;
}

const MODEL_PAGES: usize = 16;

unsafe extern "C" fn check_initial(owner: *const RawOwner, context: *mut c_void) -> ! {
    // SAFETY: this callback runs in the exact kept original Initial scope.
    let _entered = unsafe { Entered::new(owner) };
    // SAFETY: the actual current binding and exact owner are live.
    unsafe {
        assert_eq!(stela_linux_require_current(owner), 0);
        assert_eq!(stela_linux_current(), &raw const init_task);
        assert!(!stela_linux_device_publish_allowed(ptr::null()));
        assert_eq!(
            stela_linux_page_catalog_register_extents_v2(
                ptr::null(),
                0,
                ptr::null(),
                ptr::null_mut()
            ),
            -1,
        );
    }
    // SAFETY: actual entered original Initial owns this task pointer.
    let initial_time = unsafe { task_sched_runtime(&raw const init_task) };
    let spin = Instant::now();
    while spin.elapsed() < Duration::from_millis(1) {
        std::hint::spin_loop();
    }
    // SAFETY: the same original task and source scope remained current.
    let after_spin = unsafe { task_sched_runtime(&raw const init_task) };
    assert!(after_spin > initial_time);
    assert_eq!(
        stela_linux::threads::initial_root_levels(),
        Err(WorkError::Unavailable)
    );
    // SAFETY: the stopped dispatcher keeps the exact pinned runtime handle.
    let runtime = unsafe { *context.cast::<Pin<&HostedRuntime<8>>>() };
    // SAFETY: C checks the owner before using it. A refusal must release the worker.
    let refused = unsafe { reserve_hosted_child_stack(runtime, ptr::null()) };
    assert!(matches!(refused, Err(ResourceBootstrapError::Native(-1))));
    // SAFETY: this is the entered creator on the actual mounted runtime.
    let child = unsafe { reserve_hosted_child_stack(runtime, owner) }.unwrap();
    let stack = child.stack();
    // SAFETY: the original creator is still entered and owns the only worker reservation.
    let second = unsafe { reserve_hosted_child_stack(runtime, owner) };
    assert!(matches!(
        second,
        Err(ResourceBootstrapError::Work(WorkError::Full))
    ));
    // SAFETY: actual current owns the fresh 16-page inventory. Use the original
    // C allocation and release calls with the exact order and live address.
    unsafe {
        let order = MODEL_PAGES.ilog2();
        let bytes = MODEL_PAGES * 4096;
        let address = get_free_pages_noprof(0, order);
        assert_ne!(address, 0);
        assert_eq!(address % bytes, 0);
        assert_eq!(get_free_pages_noprof(0, 0), 0);
        (address as *mut u8).add(bytes - 1).write(0x96);
        assert_eq!((address as *const u8).add(bytes - 1).read(), 0x96);
        let last = stela_linux_virt_to_page(address + bytes - 1);
        let model_frame = page_to_pfn(last);
        assert_eq!(pfn_to_page(model_frame), last);
        assert_eq!(
            stela_linux_page_to_virt(last).addr(),
            address + bytes - 4096
        );
        let colliding_physical = (model_frame as u64) << 12;
        assert!(stela_linux_page_dma_pin(colliding_physical).is_null());
        assert_eq!(
            dma_map_phys(ptr::null(), colliding_physical, 4096, 0, 0),
            u64::MAX
        );
        free_pages(address, order);
        stela_linux_pages_finish();
        let mut free = 0;
        assert_eq!(stela_linux_available_page_frames(&mut free), 0);
        assert_eq!(free, MODEL_PAGES);
        let reused = get_free_pages_noprof(0, order);
        assert_eq!(reused, address);
        free_pages(reused, order);
        stela_linux_pages_finish();
    }
    // SAFETY: no source child has borrowed or published this reservation.
    unsafe { child.cancel() }.unwrap_or_else(|(_, error)| panic!("{error:?}"));
    // SAFETY: this is still the original entered creator.
    let reused = unsafe { reserve_hosted_child_stack(runtime, owner) }.unwrap();
    assert!(reused.stack().same_allocation(&stack));
    // SAFETY: the second reservation was also kept unpublished and unused.
    unsafe { reused.cancel() }.unwrap_or_else(|(_, error)| panic!("{error:?}"));
    println!("original hosted Initial attached");
    process::exit(0);
}

unsafe extern "C" fn check_resources(owner: *const RawOwner, _: *mut c_void) -> ! {
    // SAFETY: this is the exact mounted Initial and its original source lease.
    let _entered = unsafe { Entered::new(owner) };
    // SAFETY: all model roots are kept by the mount. Run the actual source
    // bootstrap once, on its original current and without a queue loan.
    unsafe {
        assert!(!stela_linux_task_resource_roots_complete(owner));
        assert!(system_wq.is_null());
        assert!(sighand_cachep.is_null());
        assert_eq!(initialize_hosted_resources(owner), Ok(()));
        assert!(stela_linux_task_resource_roots_complete(owner));
        assert!(!system_wq.is_null());
        assert!(!sighand_cachep.is_null());
        assert_eq!(
            initialize_hosted_resources(owner),
            Err(ResourceBootstrapError::Native(-114))
        );
    }
    println!("original hosted resource bootstrap returned");
    process::exit(0);
}

#[test]
fn hosted_initial_enters_the_original_task_without_native_admission() {
    in_fresh_process(
        "hosted_initial_enters_the_original_task_without_native_admission",
        "original hosted Initial attached",
        MODEL_PAGES,
        1,
        check_initial,
        run_once,
    );
}

#[test]
fn hosted_initial_bootstraps_original_resource_roots() {
    in_fresh_process(
        "hosted_initial_bootstraps_original_resource_roots",
        "original hosted resource bootstrap returned",
        16 * 1024,
        1,
        check_resources,
        run_once,
    );
}

#[test]
fn hosted_initial_services_original_timers_after_a_park() {
    in_fresh_process(
        "hosted_initial_services_original_timers_after_a_park",
        "original hosted timer service resumed",
        16 * 1024,
        1,
        start_timer_service,
        drive_timer_service,
    );
}

#[test]
fn hosted_initial_publishes_original_pid1_and_kthreadd() {
    in_fresh_process(
        "hosted_initial_publishes_original_pid1_and_kthreadd",
        "original hosted kernel children dispatched",
        16 * 1024,
        2,
        check_threads_published,
        drive_first_children,
    );
}

#[test]
fn hosted_original_fork_returns_enomem_without_an_unowned_stack() {
    in_fresh_process(
        "hosted_original_fork_returns_enomem_without_an_unowned_stack",
        "original hosted fork exhausted its worker inventory",
        16 * 1024,
        1,
        check_threads_exhausted,
        run_once,
    );
}

unsafe extern "C" fn check_threads_exhausted(owner: *const RawOwner, context: *mut c_void) -> ! {
    // SAFETY: the stopped dispatcher keeps the exact pinned runtime handle.
    let runtime = unsafe { *context.cast::<Pin<&HostedRuntime<8>>>() };
    // SAFETY: the mounted Initial is the real entered source creator.
    let _entered = unsafe { Entered::new(owner) };
    // SAFETY: the permanent model inventory and clock are retained.
    unsafe { initialize_hosted_resources(owner) }.unwrap();
    // SAFETY: exact entered Initial after original resource initialization.
    let result = unsafe { start_hosted_threads(owner, runtime) };
    assert_eq!(result, Err(ResourceBootstrapError::Native(-12)));
    // SAFETY: the failed startup never published a kthreadd task.
    assert!(unsafe { kthreadd_task }.is_null());
    println!("original hosted fork exhausted its worker inventory");
    process::exit(0);
}

unsafe extern "C" fn check_threads_published(owner: *const RawOwner, context: *mut c_void) -> ! {
    // SAFETY: exact retained original owner/current and dispatcher runtime handle.
    let (owner, runtime) = unsafe { (&*owner, *context.cast::<Pin<&HostedRuntime<8>>>()) };
    {
        // SAFETY: the mounted Initial is the real entered source creator.
        let _entered = unsafe { Entered::new(owner) };
        // SAFETY: the permanent model inventory and clock are retained.
        unsafe { initialize_hosted_resources(owner) }.unwrap();
        // SAFETY: exact entered Initial after original resource initialization.
        unsafe { start_hosted_threads(owner, runtime) }.unwrap();
        // SAFETY: original publication retains this genuine kthreadd task.
        assert!(!unsafe { kthreadd_task }.is_null());
        // SAFETY: both real children still own the reserved stacks.
        let extra = unsafe { reserve_hosted_child_stack(runtime, owner) };
        assert!(matches!(
            extra,
            Err(ResourceBootstrapError::Work(WorkError::Full))
        ));
    }
    // SAFETY: mounted Initial's exact scope with the original resources kept.
    unsafe { stela_linux::service::run_hosted_service(owner, runtime) }
}

fn drive_first_children(runtime: Pin<&HostedRuntime<8>>, _: &HostedClock) {
    assert!(step_hosted(runtime, false).unwrap()); // Initial parks
    assert!(step_hosted(runtime, false).unwrap()); // PID1 waits for kthreadd
    assert!(step_hosted(runtime, false).unwrap()); // kthreadd enters and parks
    println!("original hosted kernel children dispatched");
    process::exit(0);
}

unsafe extern "C" fn start_timer_service(owner: *const RawOwner, context: *mut c_void) -> ! {
    // SAFETY: exact retained original owner/current and dispatcher runtime handle.
    let (owner, runtime) = unsafe { (&*owner, *context.cast::<Pin<&HostedRuntime<8>>>()) };
    {
        // SAFETY: this is the exact original Initial, before the C loop enters it.
        let _entered = unsafe { Entered::new(owner) };
        // SAFETY: entered original Initial with its model roots and clock kept.
        unsafe { initialize_hosted_resources(owner) }.unwrap();
    }
    // SAFETY: original resources initialized and the previous guard has left.
    unsafe { stela_linux::service::run_hosted_service(owner, runtime) }
}

fn run_once(runtime: Pin<&HostedRuntime<8>>, _: &HostedClock) {
    runtime.step().unwrap();
}

fn drive_timer_service(runtime: Pin<&HostedRuntime<8>>, clock: &HostedClock) {
    let raised = runtime.service_raised_work().unwrap();
    raised.raise().unwrap();
    assert!(runtime.step().unwrap());
    assert!(
        !runtime.step().unwrap(),
        "original service should be parked"
    );
    // SAFETY: all original continuations are stopped on this dispatcher.
    let initial = unsafe { ptr::read_volatile(&raw const jiffies_64) };
    let deadline = clock.now_ns().unwrap() + 30_000_000;
    runtime.set_service_timer(Some(deadline)).unwrap();
    while !runtime.step_or_idle().unwrap() {}
    assert!(clock.now_ns().unwrap() >= deadline);
    // SAFETY: the original timer phases returned and Initial parked again.
    let resumed = unsafe { ptr::read_volatile(&raw const jiffies_64) };
    assert!(
        resumed.wrapping_sub(initial) > 0,
        "original jiffy clock did not advance"
    );
    assert!(!runtime.step().unwrap());
    println!("original hosted timer service resumed");
    process::exit(0);
}

fn in_fresh_process(
    test: &str,
    witness: &str,
    page_count: usize,
    general_stacks: usize,
    body: unsafe extern "C" fn(*const RawOwner, *mut c_void) -> !,
    drive: fn(Pin<&HostedRuntime<8>>, &HostedClock),
) {
    const CHILD: &str = "STELA_HOSTED_INITIAL_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let result = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--nocapture"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&result.stdout);
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(result.status.success(), "{stdout}\n{stderr}");
        assert!(stdout.contains(witness), "{stdout}");
        return;
    }
    // SAFETY: this isolated process has no other alarm or host signal user.
    unsafe { libc::alarm(10) };
    // SAFETY: all C names in the fixture come from this resident executable
    // or the original owned name allocator. The process preserves the maps.
    assert!(unsafe { stela_linux::image::register(Arc::new(ProcessImage::current())) }.is_ok());
    let execution = HostedExecution::new();
    let clock = HostedClock::new(&execution).unwrap();
    let idle = HostedIdle::new(&clock).unwrap();
    let deadlines = HostedDeadlines::new(&clock, &idle).unwrap();
    let queue = HostedQueue::<8>::new(execution, Arc::new(())).unwrap();
    let stack = stela_linux::task::stack_requirement().unwrap();
    // SAFETY: this fresh process retains its only executor through exit.
    let executor = unsafe {
        HostedExecutor::new_with_persistent_service_stacks(
            queue.clone(),
            stack,
            general_stacks,
            deadlines,
        )
    }
    .unwrap();
    let runtime = executor.runtime();
    let start = Instant::now();
    // SAFETY: reading the userspace x86-64 TSC supplies a measured fixture rate.
    let first = unsafe { std::arch::x86_64::_rdtsc() };
    while start.elapsed() < Duration::from_millis(10) {
        std::hint::spin_loop();
    }
    // SAFETY: the same host thread samples the same architectural counter.
    let last = unsafe { std::arch::x86_64::_rdtsc() };
    let hz =
        u128::from(last.checked_sub(first).unwrap()) * 1_000_000_000 / start.elapsed().as_nanos();
    let utc = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap();
    let realtime = RealtimeOrigin::new(
        clock.now_ns().unwrap().try_into().unwrap(),
        utc.as_secs().try_into().unwrap(),
        utc.subsec_nanos(),
    )
    .unwrap();
    let platform = Host {
        clock: clock.clone(),
        boot_origin_ns: host_boottime().unwrap(),
        timer: runtime.service_raised_work().unwrap(),
        tsc_hz: NonZeroU64::new(hz.try_into().unwrap()).unwrap(),
        realtime,
        random: RefCell::new(stela_linux::random::Seeded::from_entropy(&HostEntropy).unwrap()),
    };
    let context = ptr::from_ref(&runtime).cast_mut().cast();
    // SAFETY: the exact static archive, dispatcher and local runtime handle
    // remain live through the source check, which exits this process.
    let ticket =
        unsafe { HostedTaskBinding::start_initial(runtime, platform, page_count, body, context) }
            .unwrap();
    assert_eq!(queue.completed(ticket), Ok(false));
    drive(runtime, &clock);
    panic!("the original Initial check returned to its dispatcher");
}
