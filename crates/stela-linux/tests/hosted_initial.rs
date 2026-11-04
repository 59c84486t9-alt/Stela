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
use stela_driver_base::platform::image::NativeReadOnlyImage;
use stela_driver_base::platform::work::{
    WorkError,
    kernel_domain::{
        DomainRaised, HostedClock, HostedDeadlines, HostedDomain, HostedExecution, HostedExecutor,
        HostedIdle, HostedQueue, HostedRuntime,
    },
};
use stela_linux::{
    owner::{
        Entered, Errno, IrqEnableError, MinimumDeadline, Platform, RawOwner, RealtimeOrigin,
        RealtimeRead,
    },
    task::{
        HostedTaskBinding, ResourceBootstrapError, initialize_hosted_resources,
        reserve_hosted_child_stack,
    },
};

struct Host {
    clock: Arc<HostedClock>,
    timer: DomainRaised<HostedDomain>,
    tsc_hz: NonZeroU64,
    realtime: RealtimeOrigin,
    random: RefCell<stela_crypto::random::Generator>,
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

impl Platform for Host {
    fn now_ns(&self) -> i64 {
        self.clock.now_ns().unwrap().try_into().unwrap()
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
    static system_wq: *const c_void;
    static sighand_cachep: *const c_void;
    fn stela_linux_current() -> *const u8;
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
    assert_eq!(
        stela_linux::threads::initial_root_levels(),
        Err(WorkError::Unavailable)
    );
    // SAFETY: the stopped dispatcher keeps the exact pinned runtime handle.
    let runtime = unsafe { *context.cast::<Pin<&HostedRuntime<4>>>() };
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
        check_initial,
    );
}

#[test]
fn hosted_initial_bootstraps_original_resource_roots() {
    in_fresh_process(
        "hosted_initial_bootstraps_original_resource_roots",
        "original hosted resource bootstrap returned",
        16 * 1024,
        check_resources,
    );
}

fn in_fresh_process(
    test: &str,
    witness: &str,
    page_count: usize,
    body: unsafe extern "C" fn(*const RawOwner, *mut c_void) -> !,
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
    let queue = HostedQueue::<4>::new(execution, Arc::new(())).unwrap();
    let stack = stela_linux::task::stack_requirement().unwrap();
    // SAFETY: this fresh process retains its only executor through exit.
    let executor = unsafe {
        HostedExecutor::new_with_persistent_service_stacks(queue.clone(), stack, 1, deadlines)
    }
    .unwrap();
    let runtime = executor.runtime();
    runtime.enable_ranked_scheduling().unwrap();
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
    let mut seed = [0; 32];
    std::fs::File::open("/dev/urandom")
        .unwrap()
        .read_exact(&mut seed)
        .unwrap();
    let platform = Host {
        clock,
        timer: runtime.service_raised_work().unwrap(),
        tsc_hz: NonZeroU64::new(hz.try_into().unwrap()).unwrap(),
        realtime,
        random: RefCell::new(stela_crypto::random::Generator::from_seed(seed)),
    };
    let context = ptr::from_ref(&runtime).cast_mut().cast();
    // SAFETY: the exact static archive, dispatcher and local runtime handle
    // remain live through the source check, which exits this process.
    let ticket =
        unsafe { HostedTaskBinding::start_initial(runtime, platform, page_count, body, context) }
            .unwrap();
    assert_eq!(queue.completed(ticket), Ok(false));
    runtime.step().unwrap();
    panic!("the original Initial returned to its dispatcher");
}
