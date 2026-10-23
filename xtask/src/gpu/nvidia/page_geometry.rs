//! Original RM page accessors over the actual one-time native publisher.
use super::{Sources, capture, tools};
use anyhow::{Context, Result, ensure};
use serde_json::json;
use std::{fs, path::Path, process::Command};

pub(super) fn verify(clang: &Path, source: &Sources, output: &Path) -> Result<()> {
    fs::create_dir_all(output)?;
    let original = source.join("src/nvidia/arch/nvalloc/unix/src/os.c");
    let text = fs::read_to_string(&original)?;
    let declarations = source.join("src/nvidia/generated/g_os_nvoc.h");
    let declarations_text = fs::read_to_string(&declarations)?;
    let mut accessors = text
        .split_once("#include")
        .context("missing original OS source notices")?
        .0
        .to_owned();
    for (result, name) in [
        ("NvU64", "osGetPageSize"),
        ("NvU64", "osGetSupportedSysmemPageSizeMask"),
        ("NvU8", "osGetPageShift"),
    ] {
        let signature = format!("{name}(void);");
        let prototypes: Vec<_> = declarations_text
            .lines()
            .filter(|line| line.split_whitespace().eq([result, signature.as_str()]))
            .collect();
        ensure!(prototypes.len() == 1, "changed original {name} declaration");
        accessors.push_str(prototypes[0]);
        accessors.push('\n');
        let marker = format!("{result}\n{name}(void)\n{{\n");
        ensure!(
            text.matches(&marker).count() == 1,
            "changed original {name}"
        );
        let start = text.find(&marker).unwrap();
        let end = text[start..]
            .find("\n}\n")
            .context("missing original accessor body")?;
        accessors.push_str(&text[start..start + end + 3]);
        accessors.push('\n');
    }
    let header = output.join("page_geometry_accessors.h");
    fs::write(&header, accessors)?;
    let adapter = source.join("stela/stela_page_geometry.c");
    let fixture = source.join("stela/tests/page_geometry.c");
    let mut processes = Vec::new();
    for sanitized in [false, true] {
        let binary = output.join(if sanitized { "sanitized" } else { "normal" });
        let mut compiler = Command::new(clang);
        compiler.args([
            "-DNV_BSD",
            "-std=c11",
            "-ffreestanding",
            "-fno-builtin",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wmissing-prototypes",
            "-O2",
        ]);
        for include in [
            "stela",
            "src/common/sdk/nvidia/inc",
            "src/nvidia/arch/nvalloc/unix/include",
            "src/nvidia/inc/kernel",
            "src/common/inc",
            "src/common/unix/common/inc",
        ] {
            compiler.arg("-I").arg(source.join(include));
        }
        super::freebsd_headers(&mut compiler, source);
        if sanitized {
            compiler.args(["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]);
        }
        compiler
            .arg("-I")
            .arg(output)
            .arg(&adapter)
            .arg(&fixture)
            .arg("-o")
            .arg(&binary);
        capture(&mut compiler)?;
        for (base, max) in [(12, 12), (14, 14), (12, 14), (12, 21), (62, 62)] {
            let mut command = Command::new(&binary);
            command.args([base.to_string(), max.to_string()]);
            let log = output.join(format!("{sanitized}-{base}-{max}.log"));
            fs::write(&log, capture(&mut command)?)?;
            processes.push(json!({
                "sanitized":sanitized,"base_shift":base,"max_shift":max,
                "compiler":format!("{compiler:?}"),"command":format!("{command:?}"),
                "binary":tools::binding(&binary)?,"output":tools::binding(&log)?,
            }));
        }
    }
    fs::write(
        output.join("receipt.json"),
        serde_json::to_vec_pretty(&json!({
            "scope":"Ten hosted original accessor/publisher processes; broad granules refused before publication; no physical RAM support or RM activation",
            "task":tools::binding(&tools::root().join(file!()))?,
            "original":tools::binding(&original)?,"accessors":tools::binding(&header)?,
        "original_declarations":tools::binding(&declarations)?,
            "adapter":tools::binding(&adapter)?,"fixture":tools::binding(&fixture)?,
            "processes":processes,
        }))?,
    )?;
    Ok(())
}

#[cfg(test)]
#[test]
fn original_page_accessors_publish_only_supported_native_geometry() {
    let output = tempfile::tempdir().unwrap();
    verify(
        &tools::which("clang").unwrap(),
        &Sources::new(),
        output.path(),
    )
    .unwrap();
}
