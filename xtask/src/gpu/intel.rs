//! Run the native Xe firmware, WOPCM, GSM, PAT and GuC reset adapter tests.
use super::support::capture;
use crate::tools;
use std::process::Command;

#[test]
fn firmware_wopcm_gsm_pat_and_guc_reset_adapters_pass() {
    run(&[
        "test-firmware",
        "test-huc-firmware",
        "test-wopcm",
        "test-wopcm-owned",
        "test-ggtt-probe",
        "test-pat",
        "test-guc-reset",
    ]);
}

fn run(targets: &[&str]) {
    let directory = tempfile::tempdir().unwrap();
    let source = tools::root().join("crates/stela-drivers/src/gpu/intel/stela/Makefile");
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
