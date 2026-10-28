//! Original CPU wrappers and separate full-width observation providers.
use super::{Sources, capture, tools};
use anyhow::Result;
use serde_json::json;
use std::{fs, path::Path, process::Command};

pub(super) fn verify(clang: &Path, source: &Sources, output: &Path) -> Result<()> {
    fs::create_dir_all(output)?;
    let adapter = source.join("port/stela_nvswitch_primitives.c");
    let fixture = source.join("port/tests/nvswitch_primitives.c");
    let mut models = Vec::new();
    for sanitize in [false, true] {
        for forward in [false, true] {
            let name = format!(
                "{}-{}",
                if sanitize { "sanitized" } else { "normal" },
                if forward { "forward" } else { "bytes" }
            );
            let mut objects = Vec::new();
            let mut commands = Vec::new();
            for (index, input) in [&adapter, &fixture].iter().enumerate() {
                let artifact = output.join(format!("{name}-{index}.o"));
                let mut command = Command::new(clang);
                command.args([
                    "-DNV_BSD",
                    "-ffreestanding",
                    "-fno-builtin",
                    "-std=c11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-Wmissing-prototypes",
                    "-O2",
                ]);
                for include in [
                    "port",
                    "src/common/sdk/nvidia/inc",
                    "src/nvidia/arch/nvalloc/unix/include",
                    "src/nvidia/inc/kernel",
                    "src/common/inc",
                    "src/common/nvlink/interface",
                    "src/common/nvswitch/interface",
                    "src/common/unix/common/inc",
                ] {
                    command.arg("-I").arg(source.join(include));
                }
                super::freebsd_headers(&mut command);
                if sanitize {
                    command.args(["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]);
                }
                if forward {
                    if index == 0 {
                        // Only the adapter object observes providers; these
                        // symbols never enter any production archive.
                        command.args([
                            "-Dmemcpy=stela_nvswitch_test_memcpy",
                            "-Dmemset=stela_nvswitch_test_memset",
                            "-Dstrlen=stela_nvswitch_test_strlen",
                        ]);
                    } else {
                        command.arg("-DSTELA_NVSWITCH_FORWARD_TEST");
                    }
                }
                command.arg("-c").arg(input).arg("-o").arg(&artifact);
                capture(&mut command)?;
                commands.push(format!("{command:?}"));
                objects.push(artifact);
            }
            let binary = output.join(&name);
            let mut link = Command::new(clang);
            link.args(&objects).arg("-o").arg(&binary);
            if sanitize {
                link.args(["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]);
            }
            capture(&mut link)?;
            commands.push(format!("{link:?}"));
            let log = output.join(format!("{name}.log"));
            fs::write(&log, capture(&mut Command::new(&binary))?)?;
            models.push(json!({"sanitized":sanitize,"forwarding_only":forward,"commands":commands,"binary":tools::binding(&binary)?,"output":tools::binding(&log)?}));
        }
    }
    fs::write(
        output.join("receipt.json"),
        serde_json::to_vec_pretty(&json!({
            "scope":"Actual original wrappers in four hosted CPU byte/forwarding processes; no native EFI/GPU execution or production observer provider",
            "task":tools::binding(&tools::root().join(file!()))?,"adapter":tools::binding(&adapter)?,"fixture":tools::binding(&fixture)?,
            "original_header":tools::binding(&source.join("src/common/nvswitch/interface/export_nvswitch.h"))?,"models":models,
        }))?,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg_attr(
        not(feature = "fetched-sources"),
        ignore = "reads the sources `cargo xtask gpu fetch` checks out"
    )]
    #[test]
    fn original_nvswitch_wrappers_keep_bytes_and_full_native_lengths() {
        let output = tempfile::tempdir().unwrap();
        verify(
            &tools::which("clang").unwrap(),
            &Sources::new(),
            output.path(),
        )
        .unwrap();
    }
}
