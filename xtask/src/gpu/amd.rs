//! CPU acquisition checks compile the actual retained AMD refresh function.
use super::support::capture;
use crate::tools;
use std::process::Command;

#[test]
fn discovery_refresh_bounds_actual_driver_reads_and_preserves_failed_output() {
    run("discovery-refresh-test");
}

#[test]
fn mm_index_reads_preserve_original_order_and_refuse_before_access() {
    run("vram-mm-test");
}

#[test]
fn tmr_query_preserves_original_selection_order_and_failures() {
    run("tmr-test");
}

#[test]
fn pci_admission_and_sources_preserve_original_matching_and_callers() {
    run("pci-test");
}

#[test]
fn hardware_ip_walk_preserves_original_packed_data_and_atomic_refusals() {
    run("ip-test");
}

#[test]
fn selected_discovery_file_preserves_original_validation_and_release_order() {
    run("file-test");
}

#[test]
fn discovery_information_preserves_original_harvest_and_schema_results() {
    run("info-test");
    run("info-isp-test");
}

fn run(target: &str) {
    let directory = tempfile::tempdir().unwrap();
    let source = tools::root().join("crates/stela-drivers/src/gpu/amd/stela/Makefile");
    let compiler = tools::which("clang").unwrap();
    let mut command = Command::new(tools::which("make").unwrap());
    command
        .current_dir(tools::root())
        .env_remove("MAKEFLAGS")
        .arg("-f")
        .arg(source)
        .arg(format!("OUT_DIR={}", directory.path().display()))
        .arg(format!("CC={}", compiler.display()))
        .arg(target);
    capture(&mut command).unwrap();
}
