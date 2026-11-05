//! Exact-selector process isolation for retained synthetic native graphs.
extern crate std;

/// Keep deliberately quarantined synthetic native graphs local to one process.
/// Parent return skips only its duplicate body; the exact child executes every
/// original assertion, including all negative retention and receipt checks.
pub(crate) fn isolate_model() -> bool {
    const CHILD: &str = "STELA_NET_MODEL_CHILD";
    let thread = std::thread::current();
    let name = thread.name().expect("libtest exact test thread name");
    let witness = std::format!("STELA_NET_MODEL_BODY:{name}");
    if let Some(selected) = std::env::var_os(CHILD) {
        assert_eq!(selected.as_os_str(), std::ffi::OsStr::new(name));
        std::eprintln!("{witness}");
        return false;
    }
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = LOCK.lock().unwrap_or_else(|poison| poison.into_inner());

    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            name,
            "--include-ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, name)
        .output()
        .expect("spawn exact synthetic native model test");
    let stdout = std::string::String::from_utf8_lossy(&output.stdout);
    let stderr = std::string::String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "isolated model {name} failed: {}\n{stdout}\n{stderr}",
        output.status
    );
    assert_eq!(
        stderr
            .lines()
            .filter(|line| *line == witness.as_str())
            .count(),
        1,
        "exact model body must execute once: {name}\n{stdout}\n{stderr}"
    );
    true
}
