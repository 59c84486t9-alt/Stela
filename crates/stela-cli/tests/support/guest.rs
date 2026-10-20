//! The 26A434 guest roots the tests that read or run guest programs use,
//! shared by the integration tests and the crate's unit tests: the guest
//! system files (`.stela/process-work/guest-os`, which `stela
//! extract-guest-files` made with the tools the hosted comparisons run)
//! and the shared cache (`.stela/26A434-shared-cache`) of the main
//! checkout, or `STELA_TEST_GUEST_ROOTS`, colon-separated, system files
//! first. Without them a test says so and checks nothing.
use std::path::PathBuf;
use std::process::Command;

const ROOTS: [&str; 2] = [".stela/process-work/guest-os", ".stela/26A434-shared-cache"];

/// The guest roots, system files first, when they are present.
pub fn guest_roots() -> Option<Vec<PathBuf>> {
    if let Some(list) = std::env::var_os("STELA_TEST_GUEST_ROOTS") {
        return Some(std::env::split_paths(&list).collect());
    }
    let common = Command::new("git")
        .args(["rev-parse", "--path-format=absolute", "--git-common-dir"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .ok()?;
    let checkout = PathBuf::from(String::from_utf8(common.stdout).ok()?.trim())
        .parent()?
        .to_owned();
    let roots: Vec<PathBuf> = ROOTS.iter().map(|root| checkout.join(root)).collect();
    roots
        .iter()
        .all(|root| root.join("receipt.json").is_file())
        .then_some(roots)
}
