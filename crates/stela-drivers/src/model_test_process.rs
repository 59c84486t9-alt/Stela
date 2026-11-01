//! Test-only process isolation for driver models that deliberately retain an
//! unfinished DMA/IRQ epoch. Process exit reclaims synthetic host RAM; it is
//! never a driver retirement receipt or a production ownership exception.
extern crate std;

use std::{env, ffi::OsStr, process::Command, sync::Mutex, thread};

const CHILD: &str = "STELA_DRIVERS_ISOLATED_MODEL_TEST";
const ENTRY: &str = "STELA_DRIVERS_MODEL_BODY_ENTRY:";
static SERIAL: Mutex<()> = Mutex::new(());

/// Execute the current original test exactly once in an isolated libtest child.
/// True means the parent verified that execution and must skip its duplicate
/// body. False means this is the exact child, which runs every original assertion.
pub(crate) fn isolate() -> bool {
    let current = thread::current();
    let name = current
        .name()
        .expect("libtest model thread has its exact selector");
    let marker = env::var_os(CHILD);
    if marker.as_deref() == Some(OsStr::new(name)) {
        std::eprintln!("{ENTRY}{name}");
        return false;
    }
    assert!(
        marker.is_none(),
        "foreign isolated model selector for {name}"
    );

    // Keep the cohort bounded even when the outer harness uses many threads.
    // A previous failing child must not prevent other original tests running.
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let output = Command::new(env::current_exe().expect("current libtest executable"))
        .args([
            "--exact",
            name,
            "--include-ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, name)
        .output()
        .expect("spawn exact isolated driver model test");
    let stdout = std::string::String::from_utf8_lossy(&output.stdout);
    let stderr = std::string::String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "isolated model {name} failed: {}\n{stdout}\n{stderr}",
        output.status
    );
    let witness = alloc::format!("{ENTRY}{name}");
    assert_eq!(
        stderr.lines().filter(|line| *line == witness).count(),
        1,
        "exactly one original model body must execute for {name}\n{stdout}\n{stderr}"
    );
    true
}
