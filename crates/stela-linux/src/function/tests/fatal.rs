//! Actual C callback terminal behavior after domain invalidation uncertainty.
use super::*;
use crate::owner::{self, Owner, Platform};
use core::ffi::CStr;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;

struct Reporter {
    path: PathBuf,
    expected: &'static str,
    drops: Arc<AtomicUsize>,
    domain: Arc<Identity>,
    map_failure: bool,
}
impl Platform for Reporter {
    fn now_ns(&self) -> i64 {
        unreachable!()
    }
    fn delay_us(&self, _: u64, _: u64, _: bool) {
        unreachable!()
    }
    fn firmware(&self, _: &CStr) -> Result<&[u8], Errno> {
        unreachable!()
    }
    fn log(&self, level: i32, message: &CStr) {
        assert_eq!(level, 0);
        assert_eq!(message.to_str().unwrap(), self.expected);
        assert_eq!(self.drops.load(Ordering::Relaxed), 0);
        assert_eq!(dma_quarantine_status().mappings, 1);
        assert_eq!(dma_quarantine_status().bytes, 0x3000);
        if self.map_failure {
            assert_eq!(Arc::strong_count(&self.domain), 4);
        } else {
            assert_eq!(self.domain.unmapped.load(Ordering::Relaxed), 1);
        }
        std::fs::write(&self.path, self.expected).unwrap();
    }
    fn warn(&self, _: &CStr, _: i32, _: Option<&CStr>) {
        unreachable!()
    }
    fn unsupported(&self, _: &CStr) {
        unreachable!()
    }
    fn random_bytes(&self, _: &mut [u8]) {
        unreachable!()
    }
    fn start_worker(&self, _: crate::owner::WorkerKind) -> Result<(), Errno> {
        unreachable!()
    }
    fn shutdown(&self, _: bool) {
        unreachable!()
    }
    fn map_device(&self, _: u64, _: usize, _: bool) -> Option<*mut c_void> {
        unreachable!()
    }
    unsafe fn unmap_device(&self, _: *mut c_void) {
        unreachable!()
    }
    fn map_pages(&self, _: &[u64]) -> Option<*mut c_void> {
        unreachable!()
    }
    unsafe fn unmap_pages(&self, _: *mut c_void, _: usize) {
        unreachable!()
    }
    fn irq_enable(&self, _: u32) -> Result<(), Errno> {
        unreachable!()
    }
    fn irq_disable(&self, _: u32) {
        unreachable!()
    }
    unsafe fn copy_from_user(&self, _: *mut u8, _: *const u8, _: usize) -> usize {
        unreachable!()
    }
    unsafe fn copy_to_user(&self, _: *mut u8, _: *const u8, _: usize) -> usize {
        unreachable!()
    }
    fn map_user(&self, _: *mut c_void, _: u64, _: u64, _: u64) -> Result<(), Errno> {
        unreachable!()
    }
    fn unmap_user(&self, _: *mut c_void, _: u64, _: usize) {
        unreachable!()
    }
}
struct HostConfig(Config);
impl Host for HostConfig {
    type Config = Config;
    fn config(&mut self) -> &mut Config {
        &mut self.0
    }
    fn enable_msi(&mut self) -> Result<(), Errno> {
        unreachable!()
    }
    fn disable_msi(&mut self) {
        unreachable!()
    }
}
fn terminal(test: &str, map_failure: bool) {
    let expected = if map_failure {
        "DMA map failed without proven retirement"
    } else {
        "DMA unmap failed without proven retirement"
    };
    let Some(path) = std::env::var_os("STELA_DMA_FATAL_WITNESS") else {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("fatal.txt");
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--test-threads=1", "--nocapture"])
            .env("STELA_DMA_FATAL_WITNESS", &path)
            .output()
            .unwrap();
        assert_eq!(output.status.signal(), Some(libc::SIGILL), "{output:?}");
        assert_eq!(std::fs::read_to_string(path).unwrap(), expected);
        return;
    };
    let mut fixture = Fixture::new();
    fixture.entered.take();
    let domain = Arc::new(Identity::default());
    let mut state = State {
        host: HostConfig(Config([0; 256])),
        mappings: mappings(&domain),
    };
    let owner = Owner::new(Reporter {
        path: PathBuf::from(&path),
        expected,
        drops: fixture.drops.clone(),
        domain: domain.clone(),
        map_failure,
    });
    // SAFETY: this isolated subprocess runs no other task; the owner stays
    // live through the callback and its terminal emergency report.
    let _entered = unsafe { owner::Entered::new(owner.raw()) };
    let context = (&raw mut state).cast();
    if map_failure {
        domain.fail_map.store(true, Ordering::Relaxed);
        // SAFETY: exact live state, entered isolated owner and live model pages.
        unsafe { dma_map::<HostConfig>(context, 0x5010, 0x2000, 1) };
    } else {
        // SAFETY: exact live state, entered isolated owner and live model pages.
        let address = unsafe { dma_map::<HostConfig>(context, 0x5010, 0x2000, 1) };
        assert_ne!(address, MAPPING_ERROR);
        domain.fail_unmap.store(true, Ordering::Relaxed);
        // SAFETY: exact callback context and live quiescent model mapping.
        unsafe { dma_unmap::<HostConfig>(context, address, 0x2000, 1) };
    }
    // Any return would let C reuse even an object slot in the pinned page.
    std::fs::write(path, "callback returned and caller reused backing").unwrap();
    std::process::exit(99);
}
#[test]
fn map_failure_stops_before_caller_can_reuse_memory() {
    terminal(
        "function::tests::fatal::map_failure_stops_before_caller_can_reuse_memory",
        true,
    );
}
#[test]
fn unmap_failure_stops_before_caller_can_reuse_memory() {
    terminal(
        "function::tests::fatal::unmap_failure_stops_before_caller_can_reuse_memory",
        false,
    );
}
