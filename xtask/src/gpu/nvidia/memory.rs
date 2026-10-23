//! Exercise the actual C adapter's allocator-refusal ABI in a separate process.
#[cfg(test)]
use super::capture;
use super::{Sources, lut, tools};
use anyhow::Result;
use serde_json::json;
#[cfg(test)]
use std::process::Command;
use std::{fs, path::Path};

#[cfg(test)]
#[test]
fn nvlink_preserves_full_lengths_and_refuses_common_heap_failures() {
    let output = tempfile::tempdir().unwrap();
    let source = Sources::new();
    let binary = output.path().join("nvlink-memory");
    let mut compiler = Command::new(tools::which("clang").unwrap());
    compiler.args(["-std=gnu11", "-DNV_BSD", "-Wall", "-Wextra", "-Werror"]);
    for include in [
        "stela",
        "src/common/nvlink/interface",
        "src/common/sdk/nvidia/inc",
        "src/common/inc",
    ] {
        compiler.arg("-I").arg(source.join(include));
    }
    super::freebsd_headers(&mut compiler, &source);
    compiler
        .arg(source.join("stela/stela_nvlink_memory.c"))
        .arg(source.join("stela/tests/nvlink_memory.c"))
        .arg("-o")
        .arg(&binary);
    capture(&mut compiler).unwrap();
    capture(&mut Command::new(binary)).unwrap();
}

/// Replay the original realloc and real common-heap failure boundary separately
/// from the test runner's allocator. No fixture provider enters native archives.
pub(super) fn verify(clang: &Path, source: &Sources, output: &Path) -> Result<()> {
    fs::create_dir_all(output)?;
    let flags = lut::flags(clang, source, output)?;
    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    let cpu = Some(lut::cpu_model(
        clang,
        source,
        output,
        &flags,
        &[
            ("stela/tests/nvkms_memory.c", &[]),
            (
                "stela/stela_nvkms_memory.c",
                &[
                    "-Dstela_nvidia_alloc=stela_nvkms_model_alloc",
                    "-Dstela_nvidia_free=stela_nvkms_model_free",
                    "-Dnvkms_memset=stela_nvkms_model_zero",
                ],
            ),
            ("stela/stela_nvkms_primitives.c", &[]),
        ],
    )?);
    #[cfg(not(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux"))))]
    let cpu: Option<serde_json::Value> = None;
    fs::write(
        output.join("receipt.json"),
        serde_json::to_vec_pretty(&json!({
            "scope":"Actual metadata backend, original sized-prefix/realloc and common heap in a separate CPU process; no production context, final driver link or GPU execution",
            "task":tools::binding(&tools::root().join(file!()))?,
            "original_utils":tools::binding(&source.join("src/nvidia-modeset/src/nvkms-utils.c"))?,
            "makefile":tools::binding(&source.join("src/nvidia-modeset/Makefile"))?,
            "common_flags":flags.common,"c_flags":flags.c,
            "hosted_CPU_access":cpu,
        }))?,
    )?;
    Ok(())
}

#[cfg(test)]
#[test]
fn nvkms_original_realloc_preserves_ownership_on_heap_denial() {
    let output = tempfile::tempdir().unwrap();
    verify(
        &tools::which("clang").unwrap(),
        &Sources::new(),
        output.path(),
    )
    .unwrap();
}
