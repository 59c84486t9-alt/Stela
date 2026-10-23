//! Compare actual compiled vendor records across the core and OS-hook ABIs.
use super::{NATIVE_TARGET, Sources, capture, tools};
use anyhow::{Context, Result, ensure};
use object::{Architecture, Object, ObjectSection, ObjectSymbol};
use serde_json::json;
use std::{fs, path::Path, process::Command};

pub(super) fn constants(object: &object::File<'_>, name: &str, count: usize) -> Result<Vec<u64>> {
    let symbol = object
        .symbols()
        .find(|s| {
            s.name()
                .is_ok_and(|n| n == name || n.strip_prefix('_') == Some(name))
        })
        .with_context(|| format!("missing compiled layout symbol {name}"))?;
    let section =
        object.section_by_index(symbol.section_index().context("layout has no section")?)?;
    let bytes = section
        .data_range(
            symbol.address(),
            u64::try_from(count.checked_mul(8).context("layout size overflow")?)?,
        )?
        .context("truncated compiled layout array")?;
    Ok(bytes
        .as_chunks::<8>()
        .0
        .iter()
        .map(|bytes| u64::from_le_bytes(*bytes))
        .collect())
}

pub(super) fn verify(clang: &Path, source: &Sources, output: &Path) -> Result<()> {
    fs::create_dir_all(output)?;
    let fixture = source.join("port/tests/record_layout.c");
    let text = fs::read_to_string(&fixture)?;
    let labels: Vec<_> = text
        .lines()
        .filter_map(|line| {
            line.trim()
                .strip_prefix("M(\"")
                .and_then(|rest| rest.split_once('"'))
                .map(|(label, _)| label)
        })
        .collect();
    ensure!(!labels.is_empty(), "empty NVIDIA record fixture");
    let makefile = fs::read_to_string(source.join("src/nvidia/Makefile"))?;
    let core_defines: Vec<_> = makefile
        .lines()
        .filter_map(|line| line.strip_prefix("CFLAGS += -DPORT_"))
        .map(|suffix| format!("-DPORT_{suffix}"))
        .collect();
    ensure!(
        !core_defines.is_empty()
            && core_defines
                .iter()
                .all(|s| !s.chars().any(char::is_whitespace)),
        "unrecognized core NvPort definitions"
    );
    let mut baseline = None;
    let mut profiles = Vec::new();
    for (profile, target, kernel_interface) in [
        ("core", NATIVE_TARGET, false),
        ("shim", NATIVE_TARGET, true),
        ("shim-host-darwin", "x86_64-apple-macosx", true),
    ] {
        let artifact = output.join(format!("{profile}.o"));
        let mut command = Command::new(clang);
        command.args([
            "-target",
            target,
            "-DNV_BSD",
            "-DNVRM",
            "-ffreestanding",
            "-fno-stack-protector",
            "-mno-red-zone",
            "-mgeneral-regs-only",
            "-std=gnu11",
            "-Werror",
        ]);
        if kernel_interface {
            command.arg("-DNV_KERNEL_INTERFACE_LAYER");
        } else {
            command.args(&core_defines);
        }
        for include in [
            "port",
            "src/common/sdk/nvidia/inc",
            "src/nvidia/arch/nvalloc/unix/include",
            "src/nvidia/arch/nvalloc/common/inc",
            "src/nvidia/inc/kernel",
            "src/nvidia/inc/libraries",
            "src/common/inc",
            "src/common/uproc/os/common/include",
        ] {
            command.arg("-I").arg(source.join(include));
        }
        super::freebsd_headers(&mut command);
        command.arg("-c").arg(&fixture).arg("-o").arg(&artifact);
        capture(&mut command)?;
        let bytes = fs::read(&artifact)?;
        let object = object::File::parse(bytes.as_slice())?;
        ensure!(
            object.architecture() == Architecture::X86_64 && object.is_little_endian(),
            "wrong layout target"
        );
        let count = constants(&object, "stela_nvidia_record_layout_count", 1)?[0];
        ensure!(count == labels.len() as u64, "layout label/count mismatch");
        let values = constants(&object, "stela_nvidia_record_layout_values", labels.len())?;
        if let Some(base) = &baseline {
            for ((label, expected), actual) in labels.iter().zip(base).zip(&values) {
                ensure!(
                    expected == actual,
                    "{profile}: {label}: core={expected}, actual={actual}"
                );
            }
        } else {
            baseline = Some(values.clone());
        }
        let platform_long = constants(&object, "stela_nvidia_platform_long", 2)?;
        ensure!(
            platform_long == [8, 8],
            "{profile} is not LP64, as NVIDIA's Unix resource manager assumes"
        );
        profiles.push(
            json!({"profile":profile,"target":target,"command":format!("{command:?}"),
            "artifact":tools::binding(&artifact)?,"values":values,"platform_long":platform_long}),
        );
    }
    fs::write(
        output.join("receipt.json"),
        serde_json::to_vec_pretty(&json!({
            "schema":1,"scope":"Exact compiled record compatibility; no execution or full driver link",
            "fixture":tools::binding(&fixture)?,"makefile":tools::binding(&source.join("src/nvidia/Makefile"))?,
            "task":tools::binding(&tools::root().join(file!()))?,
            "labels":labels,"core_defines":core_defines,"profiles":profiles
        }))?,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_core_and_os_hook_records_match_on_all_build_abis() {
        let compiler = tools::which("clang").unwrap();
        let source = Sources::new();
        let directory = tempfile::tempdir().unwrap();
        verify(&compiler, &source, directory.path()).unwrap();
    }
}
