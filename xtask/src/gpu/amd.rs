//! Run the native AMD probe admission, IP discovery and BAR adapter tests.
use super::support::capture;
use crate::tools;
use std::process::Command;

#[test]
fn probe_admission_discovery_and_bar_adapters_pass() {
    run(&["check", "test"]);
}

fn run(targets: &[&str]) {
    let directory = tempfile::tempdir().unwrap();
    let source = tools::root().join("crates/stela-drivers/src/gpu/amd/stela/Makefile");
    let mut command = Command::new(tools::which("make").unwrap());
    command
        .current_dir(tools::root())
        .env_remove("MAKEFLAGS")
        .arg("-f")
        .arg(source)
        .arg(format!("BUILD={}", directory.path().display()))
        .arg(format!(
            "HOST_CC={}",
            tools::which("clang").unwrap().display()
        ))
        .arg("SANITIZE=")
        .args(targets);
    capture(&mut command).unwrap();
}
