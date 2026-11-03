// SPDX-License-Identifier: MIT
//! Actual C negative admission controls, never a hosted native-root substitute.
use super::*;
#[test]
fn bare_owner_cannot_authorize_physical_minimum_or_reuse_its_owners() {
    const TEST: &str = "function::tests::fatal::minimum::bare_owner_cannot_authorize_physical_minimum_or_reuse_its_owners";
    const EXPECTED: &str = "physical minimum without actual original current";
    let Some(path) = std::env::var_os("STELA_TIME_NEGATIVE_WITNESS") else {
        for kind in ["atomic", "sleep"] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("minimum-fatal.txt");
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--test-threads=1", "--nocapture"])
                .env("STELA_TIME_NEGATIVE_WITNESS", &path)
                .env("STELA_TIME_NEGATIVE_KIND", kind)
                .output()
                .unwrap();
            assert_eq!(output.status.signal(), Some(libc::SIGILL), "{output:?}");
            assert_eq!(std::fs::read_to_string(path).unwrap(), EXPECTED);
        }
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
        irq_failure: false,
        enable_failure: false,
        irq_calls: Arc::new(AtomicUsize::new(0)),
    });
    // SAFETY: isolated original Bare owner/frame stays held on the terminal
    // C stack. No Initial/Managed root or native clock grant is fabricated.
    let _entered = unsafe { owner::Entered::new(owner.raw()) };
    unsafe extern "C" {
        fn __udelay(us: core::ffi::c_ulong);
        fn msleep(ms: core::ffi::c_uint);
    }
    if std::env::var("STELA_TIME_NEGATIVE_KIND").unwrap() == "atomic" {
        // SAFETY: entered C negative-control invocation; must fail before the
        // Reporter's unreachable minimum provider could ever run.
        unsafe { __udelay(1) };
    } else {
        unsafe { msleep(1) };
    }
    std::fs::write(path, "minimum returned and caller reused original owners").unwrap();
    std::process::exit(99);
}
