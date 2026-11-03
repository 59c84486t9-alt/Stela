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
    configuration: bool,
    irq_failure: bool,
    enable_failure: bool,
    irq_calls: Arc<AtomicUsize>,
}
impl Platform for Reporter {
    fn now_ns(&self) -> i64 {
        unreachable!()
    }
    fn minimum_delay_us(&self, _: u64) -> Result<(), stela_driver_base::platform::work::WorkError> {
        unreachable!("non-time fatal fixture")
    }
    fn minimum_deadline_us(
        &self,
        _: u64,
    ) -> Result<Box<dyn owner::MinimumDeadline>, stela_driver_base::platform::work::WorkError> {
        unreachable!("non-time fatal fixture")
    }
    fn timer_changed(&self) -> Result<(), stela_driver_base::platform::work::WorkError> {
        unreachable!("non-timer fatal fixture")
    }
    fn log(&self, level: i32, message: &CStr) {
        assert_eq!(level, 0);
        assert_eq!(message.to_str().unwrap(), self.expected);
        assert_eq!(self.drops.load(Ordering::Relaxed), 0);
        if self.expected == "physical minimum without actual original current" {
            // Negative admission needs no fabricated hosted Initial/root.
            // The original Bare owner/fixture must remain retained before any
            // minimum provider, clock, timer allocation or caller reuse.
            std::fs::write(&self.path, self.expected).unwrap();
            return;
        }
        if self.irq_failure {
            unsafe extern "C" {
                fn stela_linux_irq_actions_joined(irq: u32) -> bool;
            }
            // SAFETY: fatal report remains on the actual entered C free_irq
            // stack; its closing request must still exist with joined work.
            if self.enable_failure {
                // SAFETY: exact entered action list remains on this C stack.
                assert!(!unsafe { stela_linux_irq_actions_joined(7) });
                assert_eq!(self.irq_calls.load(Ordering::Relaxed), 1);
                unsafe extern "C" {
                    fn stela_linux_irq_run(irq: u32);
                }
                // SAFETY: exact bounded C action remains linked on this
                // non-returning enable-failure stack with live dev_id storage.
                unsafe { stela_linux_irq_run(7) };
                assert_eq!(self.irq_calls.load(Ordering::Relaxed), 2);
            } else {
                // SAFETY: exact entered closing request remains linked.
                assert!(unsafe { stela_linux_irq_actions_joined(7) });
            }
            std::fs::write(&self.path, self.expected).unwrap();
            return;
        }
        if self.configuration {
            assert_eq!(dma_quarantine_status().mappings, 0);
            std::fs::write(&self.path, self.expected).unwrap();
            return;
        }
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
    fn irq_enable(&self, irq: u32) -> Result<(), crate::owner::IrqEnableError> {
        assert!(self.irq_failure && irq == 7);
        if self.enable_failure {
            unsafe extern "C" {
                fn stela_linux_irq_run(irq: u32);
            }
            // SAFETY: real bounded synchronous C primary, whose fully linked
            // action must already exist before this enable hook can deliver.
            unsafe { stela_linux_irq_run(7) };
            return Err(crate::owner::IrqEnableError::retained(-95));
        }
        Ok(())
    }
    fn irq_disable(&self, irq: u32) -> Result<(), Errno> {
        assert!(self.irq_failure && irq == 7);
        Ok(())
    }
    fn irq_retire(&self, irq: u32) -> Result<(), Errno> {
        assert!(self.irq_failure && irq == 7);
        Err(-95)
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
    fn enable_msi(&mut self) -> Result<(), MsiError> {
        unreachable!()
    }
    fn disable_msi(&mut self) -> Result<(), MsiError> {
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
        enrollment: None,
        configuration: ConfigurationStatus::default(),
        host: HostConfig(Config([0; 256])),
        mappings: mappings(&domain),
    };
    let owner = Owner::new(Reporter {
        path: PathBuf::from(&path),
        expected,
        drops: fixture.drops.clone(),
        domain: domain.clone(),
        map_failure,
        configuration: false,
        irq_failure: false,
        enable_failure: false,
        irq_calls: Arc::new(AtomicUsize::new(0)),
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

#[cfg(all(
    feature = "hosted-test-support",
    target_arch = "x86_64",
    any(target_os = "linux", target_os = "macos")
))]
struct IrqAttempt<'a> {
    path: &'a std::ffi::OsStr,
    dev_id: *mut c_void,
    primary: unsafe extern "C" fn(core::ffi::c_int, *mut c_void) -> core::ffi::c_int,
    enable_failure: bool,
}
#[cfg(all(
    feature = "hosted-test-support",
    target_arch = "x86_64",
    any(target_os = "linux", target_os = "macos")
))]
unsafe extern "C" fn quiet_primary(_: core::ffi::c_int, _: *mut c_void) -> core::ffi::c_int {
    1
}
#[cfg(all(
    feature = "hosted-test-support",
    target_arch = "x86_64",
    any(target_os = "linux", target_os = "macos")
))]
unsafe extern "C" fn counted_primary(_: core::ffi::c_int, dev: *mut c_void) -> core::ffi::c_int {
    // SAFETY: the suspended caller retains this exact fixture AtomicUsize dev_id.
    unsafe { &*dev.cast::<AtomicUsize>() }.fetch_add(1, Ordering::Relaxed);
    1
}
#[cfg(all(
    feature = "hosted-test-support",
    target_arch = "x86_64",
    any(target_os = "linux", target_os = "macos")
))]
unsafe extern "C" fn irq_attempt(context: *mut c_void) {
    // SAFETY: the hosted foreground helper keeps this exact attempt and original
    // source/dev_id/owner graph through its real TaskBinding/current and trap.
    let attempt = unsafe { &*context.cast::<IrqAttempt<'_>>() };
    unsafe extern "C" {
        fn request_threaded_irq(
            irq: u32,
            primary: Option<
                unsafe extern "C" fn(core::ffi::c_int, *mut c_void) -> core::ffi::c_int,
            >,
            thread: Option<unsafe extern "C" fn(core::ffi::c_int, *mut c_void) -> core::ffi::c_int>,
            flags: core::ffi::c_ulong,
            name: *const core::ffi::c_char,
            dev_id: *mut c_void,
        ) -> core::ffi::c_int;
        fn free_irq(irq: u32, dev_id: *mut c_void) -> *const core::ffi::c_void;
    }
    // SAFETY: actual bound task and SAME entered Reporter owner, with exact live
    // primary/dev_id. No native IRQ or physical/root capability is installed.
    let result = unsafe {
        request_threaded_irq(
            7,
            Some(attempt.primary),
            None,
            0,
            if attempt.enable_failure {
                c"enable-visible"
            } else {
                c"retained-action"
            }
            .as_ptr(),
            attempt.dev_id,
        )
    };
    if !attempt.enable_failure {
        assert_eq!(result, 0);
        // SAFETY: exact registered action on its original task stack; refusal
        // must trap before unlink/free or returning dev_id to this caller.
        unsafe { free_irq(7, attempt.dev_id) };
    }
    let returned = if attempt.enable_failure {
        "enable failure returned and caller reclaimed dev_id"
    } else {
        "free_irq returned and caller reclaimed dev_id"
    };
    std::fs::write(attempt.path, returned).unwrap();
    std::process::exit(99);
}

#[cfg(all(
    feature = "hosted-test-support",
    target_arch = "x86_64",
    any(target_os = "linux", target_os = "macos")
))]
#[test]
fn irq_retirement_refusal_never_reclaims_request_or_returns_to_free_dev_id() {
    const TEST: &str = "function::tests::fatal::irq_retirement_refusal_never_reclaims_request_or_returns_to_free_dev_id";
    const EXPECTED: &str = "IRQ action retirement unavailable; request retained";
    let Some(path) = std::env::var_os("STELA_IRQ_FATAL_WITNESS") else {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("irq-fatal.txt");
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--test-threads=1", "--nocapture"])
            .env("STELA_IRQ_FATAL_WITNESS", &path)
            .output()
            .unwrap();
        assert_eq!(output.status.signal(), Some(libc::SIGILL), "{output:?}");
        assert_eq!(std::fs::read_to_string(path).unwrap(), EXPECTED);
        return;
    };
    let mut fixture = Fixture::new();
    fixture.entered.take();
    let owner = Owner::new(Reporter {
        path: PathBuf::from(&path),
        expected: EXPECTED,
        drops: fixture.drops.clone(),
        domain: Arc::new(Identity::default()),
        map_failure: false,
        configuration: false,
        irq_failure: true,
        enable_failure: false,
        irq_calls: Arc::new(AtomicUsize::new(0)),
    });
    let mut attempt = IrqAttempt {
        path: &path,
        dev_id: Arc::as_ptr(&fixture.drops).cast_mut().cast(),
        primary: quiet_primary,
        enable_failure: false,
    };
    // SAFETY: this isolated caller retains owner, pages and exact action dev_id
    // while a real hosted Runtime/TaskBinding enters SAME Reporter on its stack.
    // The body never returns: expected C trap or explicit false-return witness.
    unsafe {
        crate::task::tests::terminal_foreground(owner.raw(), irq_attempt, (&raw mut attempt).cast())
    }
}

#[cfg(all(
    feature = "hosted-test-support",
    target_arch = "x86_64",
    any(target_os = "linux", target_os = "macos")
))]
#[test]
fn synchronous_enable_delivery_then_error_retains_linked_action_before_trap() {
    const TEST: &str = "function::tests::fatal::synchronous_enable_delivery_then_error_retains_linked_action_before_trap";
    const EXPECTED: &str = "IRQ enable uncertain; published request retained";
    let Some(path) = std::env::var_os("STELA_IRQ_ENABLE_FATAL_WITNESS") else {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("irq-enable-fatal.txt");
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--test-threads=1", "--nocapture"])
            .env("STELA_IRQ_ENABLE_FATAL_WITNESS", &path)
            .output()
            .unwrap();
        assert_eq!(output.status.signal(), Some(libc::SIGILL), "{output:?}");
        assert_eq!(std::fs::read_to_string(path).unwrap(), EXPECTED);
        return;
    };
    let mut fixture = Fixture::new();
    fixture.entered.take();
    let calls = Arc::new(AtomicUsize::new(0));
    let owner = Owner::new(Reporter {
        path: PathBuf::from(&path),
        expected: EXPECTED,
        drops: fixture.drops.clone(),
        domain: Arc::new(Identity::default()),
        map_failure: false,
        configuration: false,
        irq_failure: true,
        enable_failure: true,
        irq_calls: calls.clone(),
    });
    let mut attempt = IrqAttempt {
        path: &path,
        dev_id: Arc::as_ptr(&calls).cast_mut().cast(),
        primary: counted_primary,
        enable_failure: true,
    };
    // SAFETY: same retained bounded owner/source/dev_id graph through actual
    // TaskBinding/current. Synchronous delivery proves publication before the
    // retained-enable fatal report; the body cannot return/reclaim this storage.
    unsafe {
        crate::task::tests::terminal_foreground(owner.raw(), irq_attempt, (&raw mut attempt).cast())
    }
}

fn configuration_terminal(test: &str, operation: u8) {
    use super::configuration::{FaultConfig, TestHost};
    let expected = if operation == 1 {
        "MSI disable failed without proven retirement"
    } else {
        "PCI configuration write failed without acknowledgement"
    };
    let Some(path) = std::env::var_os("STELA_PCI_FATAL_WITNESS") else {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("fatal.txt");
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--test-threads=1", "--nocapture"])
            .env("STELA_PCI_FATAL_WITNESS", &path)
            .output()
            .unwrap();
        assert_eq!(output.status.signal(), Some(libc::SIGILL), "{output:?}");
        assert_eq!(std::fs::read_to_string(path).unwrap(), expected);
        return;
    };
    let mut fixture = Fixture::new();
    fixture.entered.take();
    let domain = Arc::new(Identity::default());
    let owner = Owner::new(Reporter {
        path: PathBuf::from(&path),
        expected,
        drops: fixture.drops.clone(),
        domain: domain.clone(),
        map_failure: false,
        configuration: true,
        irq_failure: false,
        enable_failure: false,
        irq_calls: Arc::new(AtomicUsize::new(0)),
    });
    let error = ConfigError::write_may_have_applied(4, 4, ConfigFailure::ForeignGrant);
    let mut config = FaultConfig::new(0);
    config.write_error = Some((1, error));
    let mut state = State {
        enrollment: None,
        configuration: ConfigurationStatus::default(),
        host: TestHost {
            config,
            msi: Err(MsiError::Native(-16)),
            drops: Arc::new(AtomicUsize::new(0)),
        },
        mappings: mappings(&domain),
    };
    // SAFETY: isolated subprocess, actual retained entered owner and exact State.
    let _entered = unsafe { owner::Entered::new(owner.raw()) };
    let context = (&raw mut state).cast();
    if operation == 1 {
        // SAFETY: exact callback State; its typed host refuses real completion.
        unsafe { disable_msi::<TestHost>(context) };
    } else if operation == 2 {
        state.configuration.first = Some(error);
        state.configuration.uncertain = Some(error);
        let context = Box::into_raw(Box::new(state)).cast();
        // SAFETY: exact unique Box, original final C release. It must retain
        // State and never return to the caller that would free C host metadata.
        unsafe { release_context::<TestHost>(context) };
    } else {
        // SAFETY: exact callback State; injected post-write uncertainty must trap.
        unsafe { write_config::<TestHost>(context, 4, 4, 7) };
    }
    panic!("terminal original C callback returned");
}
#[test]
fn configuration_write_uncertainty_never_returns_to_c() {
    configuration_terminal(
        "function::tests::fatal::configuration_write_uncertainty_never_returns_to_c",
        0,
    );
}
#[test]
fn refused_msi_disable_never_reports_void_completion() {
    configuration_terminal(
        "function::tests::fatal::refused_msi_disable_never_reports_void_completion",
        1,
    );
}

#[test]
fn terminal_context_release_keeps_outer_c_host_allocation() {
    configuration_terminal(
        "function::tests::fatal::terminal_context_release_keeps_outer_c_host_allocation",
        2,
    );
}

mod minimum;
