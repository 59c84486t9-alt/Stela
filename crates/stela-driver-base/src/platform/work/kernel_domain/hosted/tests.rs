//! Actual hosted resources only; never an Original Initial/kernel fixture.
use super::*;
#[cfg(target_os = "linux")]
use crate::{
    bus::dma::memory::MemoryError,
    platform::work::kernel_domain::{HostedDomain, StorageView},
};
#[test]
fn owner_checks_actual_os_thread_without_native_cpu_permission() {
    let owner = HostedExecution::new();
    owner.check_current().unwrap();
    let other = HostedExecution::new();
    assert!(!owner.same_owner(&other));
    let foreign = owner.clone();
    thread::spawn(move || {
        assert_eq!(foreign.check_current(), Err(WorkError::WrongCpu));
        foreign.check_process().unwrap();
    })
    .join()
    .unwrap();
    owner.check_current().unwrap();
}
#[cfg(target_os = "linux")]
#[test]
fn real_mapping_guard_alignment_clone_and_model_namespace() {
    let owner = HostedExecution::new();
    let pages = HostedPages::allocate(&owner, 4, 16 * 1024, 1).unwrap();
    let other_owner = HostedExecution::new();
    let other = HostedPages::allocate(&other_owner, 1, 4096, 0).unwrap();
    // Numeric collision is intentional: exact owners remain distinct, and
    // neither model ID can be exported as native PFN/DMA/mapping authority.
    assert_eq!(pages.model_frames()[0], other.model_frames()[0]);
    assert!(!pages.owner().same_owner(other.owner()));
    let base = pages.cpu_address(0, pages.bytes()).unwrap();
    assert_eq!(base.as_ptr() as usize % (16 * 1024), 0);
    assert_eq!(pages.guard().end, base.as_ptr() as usize);
    assert_eq!(pages.guard().len(), 4096);
    // SAFETY: the actual fresh mmap is readable and kept by pages for this read.
    assert_eq!(unsafe { base.as_ptr().read_volatile() }, 0);
    let retained = pages.clone();
    assert!(pages.has_other_views());
    assert!(pages.same_allocation(&retained));
    drop(pages);
    assert!(!retained.has_other_views());
    let view = StorageView::<HostedDomain>::borrow_hosted(&retained);
    let span = view.cpu_span(0, retained.bytes()).unwrap();
    assert_eq!(span.address(), base);
    assert_eq!(
        view.cpu_span(retained.bytes(), 1).err().unwrap(),
        MemoryError::InvalidSize
    );
    assert_eq!(
        view.cpu_span(usize::MAX, 2).err().unwrap(),
        MemoryError::InvalidSize
    );
    // SAFETY: this exact allocation is private, mapped writable and still held.
    unsafe { span.address().as_ptr().write_volatile(0xa7) };
    assert_eq!(
        // SAFETY: retained keeps the same live mapping throughout this read.
        unsafe { retained.cpu_address(0, 1).unwrap().as_ptr().read_volatile() },
        0xa7
    );
}
#[cfg(target_os = "linux")]
#[test]
fn refusal_precedes_host_allocation_and_frame_counter_never_wraps() {
    let owner = HostedExecution::new();
    assert_eq!(
        HostedPages::allocate(&owner, 0, 4096, 0).err(),
        Some(MemoryError::InvalidSize)
    );
    assert_eq!(
        HostedPages::allocate(&owner, 1, 8193, 0).err(),
        Some(MemoryError::InvalidAlignment)
    );
    owner.next_frame.store(u64::MAX, Ordering::Release);
    assert_eq!(
        HostedPages::allocate(&owner, 1, 4096, 0).err(),
        Some(MemoryError::Unavailable)
    );
    assert_eq!(owner.next_frame.load(Ordering::Acquire), u64::MAX);
}
#[test]
fn notify_before_wait_and_closed_handle_cannot_reopen() {
    let owner = HostedExecution::new();
    let clock = HostedClock::new(&owner).unwrap();
    let idle = HostedIdle::new(&clock).unwrap();
    let reason = HostedReason::new(&idle).unwrap();
    let raised = reason.raised();
    // This is deliberately notify BEFORE wait: the real pending check returns
    // early. The separate check-to-park control exercises actual OS unpark.
    // Scoped borrowing avoids foreign Drop or inline callback delivery.
    thread::scope(|scope| {
        scope.spawn(|| raised.raise().unwrap());
    });
    idle.wait_until_ns(None).unwrap();
    assert_eq!(reason.observed_epoch().unwrap(), 1);
    let before = clock.now_ns().unwrap();
    idle.wait_until_ns(Some(before)).unwrap();
    assert!(clock.now_ns().unwrap() >= before);
    reason.close().unwrap();
    assert_eq!(raised.raise(), Err(WorkError::Closed));
    assert_eq!(reason.observed_epoch().unwrap(), 1);
}

#[cfg(target_os = "linux")]
#[test]
fn actual_guard_fault_targets_a_fresh_child_mapping() {
    use std::{io::Write, os::unix::process::ExitStatusExt, process::Command};
    const KEY: &str = "STELA_HOST_STORAGE_GUARD_CHILD";
    if std::env::var_os(KEY).is_some() {
        let owner = HostedExecution::new();
        owner.check_current().unwrap();
        let pages = HostedPages::allocate(&owner, 1, 4096, 1).unwrap();
        let guard = pages.guard();
        assert_eq!(guard.len(), 4096);
        std::println!("STELA_FRESH_HOST_GUARD_LOAD");
        std::io::stdout().flush().unwrap();
        // SAFETY: isolated fault control deliberately executes this exact load
        // against a freshly mprotected guard. No typed Rust value is accessed;
        // the parent requires SIGSEGV after the specific target witness.
        unsafe {
            core::arch::asm!("mov al, byte ptr [{address}]",address=in(reg)guard.start,out("al")_,options(nostack,readonly))
        };
        std::process::abort();
    }
    let name = std::format!(
        "{}::actual_guard_fault_targets_a_fresh_child_mapping",
        module_path!().split_once("::").unwrap().1
    );
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &name, "--nocapture", "--test-threads=1"])
        .env(KEY, "1")
        .output()
        .unwrap();
    assert!(
        output
            .stdout
            .windows(b"STELA_FRESH_HOST_GUARD_LOAD".len())
            .any(|bytes| bytes == b"STELA_FRESH_HOST_GUARD_LOAD")
    );
    assert_eq!(output.status.signal(), Some(11));
}

#[test]
fn notify_in_actual_check_to_park_gap_is_not_lost() {
    use core::sync::atomic::AtomicBool;
    use std::{
        io::Write,
        process::Command,
        time::{Duration, Instant},
    };
    const KEY: &str = "STELA_HOST_CHECK_TO_PARK_CHILD";
    const ENTER: &str = "STELA_ACTUAL_HOST_PENDING_CHECK_FALSE";
    const NOTIFIED: &str = "STELA_ACTUAL_HOST_NOTIFY_RETURNED";
    const POSTWAIT: &str = "STELA_ACTUAL_HOST_ORIGINAL_WAIT_RETURNED";
    const JOINED: &str = "STELA_ACTUAL_HOST_PARK_AND_PUBLISHER_JOINED";
    if std::env::var_os(KEY).is_some() {
        struct Gates {
            checked: AtomicBool,
            published: AtomicBool,
            wait_returned: AtomicBool,
        }
        let owner = HostedExecution::new();
        let clock = HostedClock::new(&owner).unwrap();
        let idle = HostedIdle::new(&clock).unwrap();
        let reason = HostedReason::new(&idle).unwrap();
        let raised = Arc::new(reason.raised());
        let actual = Arc::downgrade(&idle);
        let origin_pid = std::process::id();
        let origin_thread = thread::current().id();
        let gates = Arc::new(Gates {
            checked: AtomicBool::new(false),
            published: AtomicBool::new(false),
            wait_returned: AtomicBool::new(false),
        });
        let observer = gates.clone();
        idle.observe_before_park(alloc::boxed::Box::new(move |observed| {
            // Actual wait authenticates current PID/thread immediately before
            // its false pending check. Capture this exact whole instance; the
            // owner keeps strong roots/gates across the observer's later Drop.
            assert!(core::ptr::eq(observed, actual.as_ptr()));
            observer.checked.store(true, Ordering::Release);
            while !observer.published.load(Ordering::Acquire) {
                core::hint::spin_loop();
                thread::yield_now();
            }
            // Only atomics/pointer checks/spin/yield in this critical window:
            // no channels, stdout, join, allocation, extra park or Drop.
        }));
        let publisher = gates.clone();
        let publish = raised.clone();
        let producer = thread::spawn(move || {
            while !publisher.checked.load(Ordering::Acquire) {
                core::hint::spin_loop();
                thread::yield_now();
            }
            std::println!("{ENTER}");
            std::io::stdout().flush().unwrap();
            publish.raise().unwrap();
            std::println!("{NOTIFIED}");
            std::io::stdout().flush().unwrap();
            publisher.published.store(true, Ordering::Release);
            // Thread completion can itself wake its joiner. Keep it alive until
            // the owner records that the SAME actual original wait returned.
            while !publisher.wait_returned.load(Ordering::Acquire) {
                core::hint::spin_loop();
                thread::yield_now();
            }
        });
        owner.check_current().unwrap();
        assert_eq!(std::process::id(), origin_pid);
        assert_eq!(thread::current().id(), origin_thread);
        // Drain an older binary Thread token BEFORE allowing publication:
        // producer cannot notify or finish until the actual false-check gate.
        // No owner channel/scoped-thread completion follows this drain.
        thread::park_timeout(Duration::ZERO);
        idle.wait_until_ns(None).unwrap();
        std::println!("{POSTWAIT}");
        std::io::stdout().flush().unwrap();
        gates.wait_returned.store(true, Ordering::Release);
        producer.join().unwrap();
        owner.check_current().unwrap();
        assert_eq!(std::process::id(), origin_pid);
        assert_eq!(thread::current().id(), origin_thread);
        assert_eq!(reason.observed_epoch().unwrap(), 1);
        reason.close().unwrap();
        assert_eq!(raised.raise(), Err(WorkError::Closed));
        std::println!("{JOINED}");
        std::io::stdout().flush().unwrap();
        return;
    }
    let name = std::format!(
        "{}::notify_in_actual_check_to_park_gap_is_not_lost",
        module_path!().split_once("::").unwrap().1
    );
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &name, "--nocapture", "--test-threads=1"])
        .env(KEY, "1")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let limit = Instant::now() + Duration::from_secs(8);
    let timed_out = loop {
        if child.try_wait().unwrap().is_some() {
            break false;
        }
        if Instant::now() >= limit {
            child.kill().unwrap();
            break true;
        }
        thread::sleep(Duration::from_millis(2));
    };
    let output = child.wait_with_output().unwrap();
    let text = std::string::String::from_utf8_lossy(&output.stdout);
    assert!(
        text.contains(ENTER),
        "actual false-pending checkpoint was not reached: {text}"
    );
    assert!(
        text.contains(NOTIFIED),
        "actual notify did not return: {text}"
    );
    if timed_out {
        assert!(
            !text.contains(POSTWAIT) && !text.contains(JOINED),
            "timeout followed unexpected progress: {text}"
        );
        panic!("STELA_HOST_PARK_WATCHDOG_AFTER_CHECK_AND_NOTIFY: {text}");
    }
    assert!(
        output.status.success(),
        "{}",
        std::string::String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        text.contains(POSTWAIT),
        "original wait return witness missing: {text}"
    );
    assert!(
        text.contains(JOINED),
        "actual publisher join witness missing: {text}"
    );
}
