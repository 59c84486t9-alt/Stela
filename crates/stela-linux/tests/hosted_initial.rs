#![cfg(all(
    feature = "hosted-runtime",
    target_os = "linux",
    target_arch = "x86_64"
))]

use std::{
    ffi::{CStr, c_void},
    process::{self, Command},
    ptr,
    sync::Arc,
};
use stela_driver_base::platform::work::{
    WorkError,
    kernel_domain::{
        HostedClock, HostedDeadlines, HostedExecution, HostedExecutor, HostedIdle, HostedQueue,
    },
};
use stela_linux::{
    owner::{Entered, Errno, IrqEnableError, MinimumDeadline, Platform, RawOwner},
    task::HostedTaskBinding,
};

struct Host;
impl Platform for Host {
    fn now_ns(&self) -> i64 {
        process::abort()
    }
    fn minimum_delay_us(&self, _: u64) -> Result<(), WorkError> {
        Err(WorkError::Unavailable)
    }
    fn minimum_deadline_us(&self, _: u64) -> Result<Box<dyn MinimumDeadline>, WorkError> {
        Err(WorkError::Unavailable)
    }
    fn timer_changed(&self) -> Result<(), WorkError> {
        Err(WorkError::Unavailable)
    }
    fn log(&self, _: i32, _: &CStr) {
        process::abort()
    }
    fn warn(&self, _: &CStr, _: i32, _: Option<&CStr>) {
        process::abort()
    }
    fn unsupported(&self, _: &CStr) {
        process::abort()
    }
    fn random_bytes(&self, _: &mut [u8]) {
        process::abort()
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
}

const MODEL_PAGES: usize = 16;

unsafe extern "C" fn check_initial(owner: *const RawOwner, _: *mut c_void) -> ! {
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
    println!("original hosted Initial attached");
    process::exit(0);
}

#[test]
fn hosted_initial_enters_the_original_task_without_native_admission() {
    const CHILD: &str = "STELA_HOSTED_INITIAL_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let result = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "hosted_initial_enters_the_original_task_without_native_admission",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&result.stdout);
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(result.status.success(), "{stdout}\n{stderr}");
        assert!(
            stdout.contains("original hosted Initial attached"),
            "{stdout}"
        );
        return;
    }
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
    // SAFETY: this exact static archive and the only dispatcher are retained
    // for the lifetime of this process. The source check does not return.
    let ticket = unsafe {
        HostedTaskBinding::start_initial(runtime, Host, MODEL_PAGES, check_initial, ptr::null_mut())
    }
    .unwrap();
    assert_eq!(queue.completed(ticket), Ok(false));
    runtime.step().unwrap();
    panic!("the original Initial returned to its dispatcher");
}
