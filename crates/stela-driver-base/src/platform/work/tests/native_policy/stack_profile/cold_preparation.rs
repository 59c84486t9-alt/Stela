//! Real cold backing initialization/reseed, with modeled process permission only.
use super::*;
use crate::platform::work::tests::cancellation_error;
use core::cell::Cell;
use std::{println, process::Command, string::String};
mod fixture;
use fixture::{Authority, Mode, ModelCpu, Scene, marker, take_prepared};
mod callbacks;
use callbacks::creator;

fn run(mode: Mode) {
    let dropped = Arc::new(AtomicUsize::new(0));
    let cpu = Arc::new(ModelCpu {
        model: test_support::CpuModel::new(),
        dropped: dropped.clone(),
        mode,
        watch: AtomicU64::new(0),
        watch_state: AtomicU64::new(0),
        restored: AtomicBool::new(false),
    });
    let f = Arc::new(Scene {
        runtime: AtomicU64::new(0),
        cpu: cpu.clone(),
        mode,
        marked: AtomicUsize::new(0),
        hot: Mutex::new(None),
        binding: Mutex::new(None),
    });
    // SAFETY: same-thread model and Scene remain held through join/quarantine.
    let q = unsafe { Queue::<64>::new(cpu.clone(), f.clone()) }.unwrap();
    let executor = Executor::new_hosted_profile_for_test(
        q,
        support::stacks(&dropped, 20),
        policy(),
        profile(),
    )
    .unwrap();
    let r = executor.runtime();
    f.runtime
        .store(r.get_ref() as *const Runtime<64> as u64, Ordering::Release);
    let pointer = Arc::as_ptr(&f) as *mut c_void;
    if mode == Mode::Hot {
        // SAFETY: exact kernel-size marker enters one worker.
        unsafe {
            r.queue
                .execute_general_with_requirement(kernel(), marker, pointer)
        }
        .unwrap();
        r.drain(cpu.ticks() + 1_000_000_000).unwrap();
    }
    if mode == Mode::Park {
        // SAFETY: ordinary wake peer cannot run inline and owns no cold bytes.
        unsafe { r.queue.execute(Kind::General, marker, pointer) }.unwrap();
    }
    // SAFETY: real Foreground callback/context and all mappings survive joins.
    unsafe { r.call_foreground(creator, pointer, cpu.ticks() + 1_000_000_000) }.unwrap();
    r.drain(cpu.ticks() + 1_000_000_000).unwrap();
    if let Some((binding, wake)) = f.binding.lock().unwrap().take() {
        // SAFETY: callback/wake peer completed; all external fixture producers stopped.
        drop(unsafe { r.detach_binding(wake.context_id()) }.unwrap());
        drop(binding);
        drop(wake);
    }
    assert_eq!(
        f.marked.load(Ordering::Relaxed),
        match mode {
            Mode::Bytes | Mode::Park => 1,
            Mode::Hot => 2,
            _ => 0,
        }
    );
    r.queue.close().unwrap();
    // SAFETY: no external producer can enqueue/resume; CPU/backing kept.
    unsafe { r.retire() }.unwrap();
    drop(executor);
    assert_eq!(dropped.load(Ordering::Relaxed), 32);
}
#[test]
fn cold_usable_bytes_zero_after_if_restore_and_frame_reseed_runs() {
    run(Mode::Bytes);
}
#[test]
fn hot_idle_frame_is_rejected_while_real_unstarted_selection_finds_cold_peer() {
    run(Mode::Hot);
}
#[test]
fn cold_owner_survives_real_park_until_fresh_creator_permission_reseeds() {
    run(Mode::Park);
}
#[test]
fn denied_and_closed_prechecks_return_original_owned_exclusion() {
    run(Mode::Denied);
    run(Mode::Closed);
}
fn isolated(mode: &str) {
    let test = format!(
        "{}::stale_dropped_and_forgotten_cold_values_never_reseed_or_free",
        module_path!().split_once("::").unwrap().1
    );
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &test, "--nocapture", "--test-threads=1"])
        .env("STELA_COLD_TEST_MODE", mode)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(93),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("STELA_COLD_FATAL_RETAINED"));
}
#[test]
fn stale_dropped_and_forgotten_cold_values_never_reseed_or_free() {
    if let Ok(mode) = std::env::var("STELA_COLD_TEST_MODE") {
        run(match mode.as_str() {
            "stale" => Mode::Stale,
            "drop" => Mode::Drop,
            "forget" => Mode::Forget,
            _ => panic!("wrong fixture mode"),
        });
        unreachable!();
    }
    for mode in ["stale", "drop", "forget"] {
        isolated(mode);
    }
}

mod pinned;

#[test]
fn outer_restore_scope_loss_retains_unzeroed_preparation_until_fresh_cancel() {
    run(Mode::RestoreRefusal);
}
