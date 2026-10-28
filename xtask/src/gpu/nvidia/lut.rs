//! NVKMS types and upstream CPU upload over the common heap.
use super::{NATIVE_TARGET, Sources, capture, layout, tools};
use anyhow::{Context, Result, ensure};
use object::{Architecture, Object};
use serde_json::json;
use std::{fs, path::Path, process::Command};

pub(super) struct Flags {
    pub(super) common: Vec<String>,
    pub(super) c: Vec<String>,
    cxx: Vec<String>,
}

pub(super) fn flags(clang: &Path, source: &Sources, output: &Path) -> Result<Flags> {
    let makefile = output.join("flags.mk");
    // Let the retained Makefile and its ordinary shell expand each argument.
    // No second flag parser or copied vendor build configuration is needed.
    fs::write(
        &makefile,
        ".PHONY: stela-lut-flags\nstela-lut-flags:\n\t@printf '%s\\n' STELA_COMMON $(CFLAGS) STELA_C $(CC_ONLY_CFLAGS) STELA_CXX $(CXX_ONLY_CFLAGS)\n",
    )?;
    let mut make = Command::new(tools::which("make").context("install make")?);
    make.current_dir(source.join("src/nvidia-modeset"))
        .args(["-s", "-f", "Makefile", "-f"])
        .arg(makefile)
        .args(["stela-lut-flags", "TARGET_OS=FreeBSD", "TARGET_ARCH=x86_64"])
        .arg(format!("CC={}", clang.display()))
        .arg(format!("OUTPUTDIR={}", output.join("flags").display()))
        .arg(format!(
            "OUTPUTDIR_ABSOLUTE={}",
            output.join("flags").display()
        ));
    for name in ["CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS", "MAKEFLAGS"] {
        make.env_remove(name);
    }
    let text = capture(&mut make)?;
    let mut sections: [Vec<String>; 3] = Default::default();
    let mut section = None;
    for line in text.lines() {
        match line {
            "STELA_COMMON" => section = Some(0),
            "STELA_C" => section = Some(1),
            "STELA_CXX" => section = Some(2),
            _ => sections[section.context("unexpected Make flag output")?].push(line.to_owned()),
        }
    }
    let [mut common, c, cxx] = sections;
    ensure!(
        section == Some(2) && !common.is_empty() && !c.is_empty() && !cxx.is_empty(),
        "incomplete NVKMS flags"
    );
    // Only the probe's object format changes. Full production builds retain
    // their original machine-model and external return-thunk options.
    common.retain(|flag| !flag.starts_with("--target="));
    Ok(Flags { common, c, cxx })
}

pub(super) fn verify(clang: &Path, source: &Sources, output: &Path) -> Result<()> {
    fs::create_dir_all(output)?;
    let flags = flags(clang, source, output)?;
    let fixture = source.join("port/tests/lut_layout.c");
    let mut profiles = Vec::new();
    for (profile, target, linux) in [
        ("native", NATIVE_TARGET, false),
        ("host-darwin", "x86_64-apple-macosx", false),
        ("linux", "x86_64-unknown-linux-gnu", true),
    ] {
        for (language, suffix) in [("c", &flags.c), ("c++", &flags.cxx)] {
            let artifact = output.join(format!("{profile}-{language}.o"));
            let mut command = Command::new(clang);
            command.current_dir(source.join("src/nvidia-modeset"));
            for flag in &flags.common {
                command.arg(if linux && flag == "-DNV_BSD" {
                    "-DNV_LINUX"
                } else {
                    flag
                });
            }
            command
                .args(suffix)
                .arg(format!("--target={target}"))
                .args(["-x", language, "-c"])
                .arg(&fixture)
                .arg("-o")
                .arg(&artifact);
            capture(&mut command)?;
            let bytes = fs::read(&artifact)?;
            let object = object::File::parse(bytes.as_slice())?;
            ensure!(
                object.architecture() == Architecture::X86_64 && object.is_little_endian(),
                "wrong LUT object ABI"
            );
            let count = layout::constants(&object, "stela_nvkms_lut_layout_count", 1)?;
            ensure!(count == [8], "changed LUT fixture inventory");
            let values = layout::constants(&object, "stela_nvkms_lut_layout", 8)?;
            ensure!(
                values == [8, 2, 16896, 256, 0, 8448, 8232, 8232],
                "changed LUT byte layout or CPU alignment"
            );
            profiles.push(json!({"profile":profile,"target":target,"language":language,
                "command":format!("{command:?}"),"artifact":tools::binding(&artifact)?,"values":values}));
        }
    }
    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    let cpu = Some(cpu_model(CpuModelOptions {
        clang,
        source,
        output,
        flags: &flags,
        sources: &[
            ("port/tests/lut_access.c", &[]),
            ("src/nvidia-modeset/src/nvkms-lut.c", &[]),
            ("port/stela_nvkms_primitives.c", &[]),
        ],
    })?);
    #[cfg(not(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux"))))]
    let cpu: Option<serde_json::Value> = None;
    fs::write(
        output.join("receipt.json"),
        serde_json::to_vec_pretty(&json!({
            "scope":"Actual C/C++ object layouts and separate hosted common-heap/original-upload fixture; no production context qualification or GPU execution",
            "task":tools::binding(&tools::root().join(file!()))?,"fixture":tools::binding(&fixture)?,
            "header":tools::binding(&source.join("src/nvidia-modeset/include/nvkms-types.h"))?,
            "makefile":tools::binding(&source.join("src/nvidia-modeset/Makefile"))?,
            "common_flags":flags.common,"c_flags":flags.c,"cxx_flags":flags.cxx,
            "profiles":profiles,"hosted_CPU_access":cpu,
        }))?,
    )?;
    Ok(())
}

#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
/// Vendor CPU fixture sources, compiler flags and output location.
pub(super) struct CpuModelOptions<'a> {
    pub(super) clang: &'a Path,
    pub(super) source: &'a Sources,
    pub(super) output: &'a Path,
    pub(super) flags: &'a Flags,
    pub(super) sources: &'a [(&'a str, &'a [&'a str])],
}

pub(super) fn cpu_model(options: CpuModelOptions<'_>) -> Result<serde_json::Value> {
    let CpuModelOptions {
        clang,
        source,
        output,
        flags,
        sources,
    } = options;
    // This executable models ordinary host OS-hook calls. These full-core
    // options belong to the separately built kernel archives, not this process.
    let excluded = [
        "-mfunction-return=thunk-extern",
        "-mcmodel=kernel",
        "-fno-pic",
        "-msoft-float",
        "-mno-mmx",
        "-mno-sse",
        "-mno-sse2",
        "-mno-3dnow",
    ];
    let mut objects = Vec::new();
    let mut commands = Vec::new();
    for (index, (file, extra)) in sources.iter().enumerate() {
        let artifact = output.join(format!("cpu-{index}.o"));
        let mut command = Command::new(clang);
        command
            .current_dir(source.join("src/nvidia-modeset"))
            .args(
                flags
                    .common
                    .iter()
                    .filter(|f| !excluded.contains(&f.as_str())),
            )
            .args(&flags.c)
            .args([
                "-mgeneral-regs-only",
                "-ffunction-sections",
                "-fdata-sections",
                "-fno-inline",
                "-I",
            ])
            .arg(source.join("port"))
            .arg("-idirafter")
            .arg(super::gpu().join("compat/freebsd"))
            // The fixtures include the original NVKMS sources they model.
            .arg("-iquote")
            .arg(source.join("src/nvidia-modeset/src"))
            .args(*extra)
            .arg("-c")
            .arg(source.join(file))
            .arg("-o")
            .arg(&artifact);
        capture(&mut command)?;
        commands.push(format!("{command:?}"));
        objects.push(artifact);
    }
    let heap = output.join("libactual-heap.a");
    let mut rust = Command::new(tools::which("rustc").context("install rustc")?);
    rust.args([
        "--edition=2024",
        "--crate-name=stela_nvkms_lut_heap",
        "--crate-type=staticlib",
        "-C",
        "panic=abort",
        "-C",
        "opt-level=2",
    ])
    .arg(source.join("port/tests/lut_heap.rs"))
    .arg("-o")
    .arg(&heap);
    capture(&mut rust)?;
    commands.push(format!("{rust:?}"));
    let binary = output.join("cpu-model");
    let mut link = Command::new(clang);
    link.args(&objects)
        .arg(&heap)
        .arg(if cfg!(target_os = "macos") {
            "-Wl,-dead_strip"
        } else {
            "-Wl,--gc-sections"
        })
        .arg("-o")
        .arg(&binary);
    capture(&mut link)?;
    commands.push(format!("{link:?}"));
    capture(&mut Command::new(&binary))?;
    Ok(
        json!({"binary":tools::binding(&binary)?,"heap":tools::binding(&heap)?,
        "shared_heap_source":tools::binding(&tools::root().join("crates/stela-boot/src/heap.rs"))?,
        "metadata_adapter":tools::binding(&source.port.join("memory.rs"))?,
        "fixture_sources":sources.iter().map(|(file,_)| tools::binding(&source.join(file))).collect::<Result<Vec<_>>>()?,
        "excluded_only_for_host_CPU_fixture":excluded,"commands":commands,"executed":true}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg_attr(not(feature = "fetched-sources"), ignore = "feature: fetched-sources")]
    #[test]
    fn lut_upload_uses_header_prefix_and_common_heap() {
        let output = tempfile::tempdir().unwrap();
        verify(
            &tools::which("clang").unwrap(),
            &Sources::new(),
            output.path(),
        )
        .unwrap();
    }
}
