//! Inspect the upstream ordering hook's machine code without executing it.
use super::{NATIVE_TARGET, Sources, capture, tools};
use anyhow::{Context, Result, ensure};
use object::{Architecture, Object, ObjectSection, ObjectSymbol};
use serde_json::json;
use std::{fs, path::Path, process::Command};

pub(super) fn verify(clang: &Path, source: &Sources, output: &Path) -> Result<()> {
    fs::create_dir_all(output)?;
    let objdump = tools::which("llvm-objdump")
        .or_else(tools::toolchain_objdump)
        .context("original ordering inspection requires llvm-objdump")?;
    let fixture = source.join("port/tests/ordering.c");
    let mut profiles = Vec::new();
    for target in [NATIVE_TARGET, "x86_64-apple-macosx"] {
        let artifact = output.join(format!("{target}.o"));
        let mut command = Command::new(clang);
        command.args([
            "-target",
            target,
            "-DNV_BSD",
            "-DNV_KERNEL_INTERFACE_LAYER",
            "-ffreestanding",
            "-fno-stack-protector",
            "-fomit-frame-pointer",
            "-mno-red-zone",
            "-mgeneral-regs-only",
            "-std=gnu11",
            "-O2",
            "-Werror",
        ]);
        for include in [
            "port",
            "src/common/sdk/nvidia/inc",
            "src/nvidia/arch/nvalloc/unix/include",
            "src/common/inc",
            "src/nvidia/inc/kernel",
            "src/common/unix/common/inc",
        ] {
            command.arg("-I").arg(source.join(include));
        }
        super::freebsd_headers(&mut command);
        let ir = output.join(format!("{target}.ll"));
        let mut ir_command = Command::new(clang);
        ir_command
            .args(command.get_args())
            .arg(&fixture)
            .args(["-S", "-emit-llvm", "-o"])
            .arg(&ir);
        command.arg(&fixture).arg("-c").arg("-o").arg(&artifact);
        capture(&mut command)?;
        let bytes = fs::read(&artifact)?;
        let object = object::File::parse(bytes.as_slice())?;
        ensure!(
            object.architecture() == Architecture::X86_64,
            "wrong ordering ABI"
        );
        ensure!(
            !object
                .symbols()
                .any(|s| s.is_undefined() && s.name().is_ok_and(|n| !n.is_empty())),
            "ordering hook has unresolved imports"
        );
        let hook = object
            .symbols()
            .find(|s| {
                s.name()
                    .is_ok_and(|n| n.trim_start_matches('_') == "os_flush_cpu_write_combine_buffer")
            })
            .context("missing actual ordering hook")?;
        let text =
            object.section_by_index(hook.section_index().context("ordering hook section")?)?;
        ensure!(
            text.data_range(hook.address(), 4)? == Some(&[0x0f, 0xae, 0xf8, 0xc3]),
            "ordering hook is not exactly SFENCE and return"
        );
        let disassembly = capture(Command::new(&objdump).arg("-d").arg(&artifact))?;
        ensure!(
            disassembly
                .lines()
                .filter(|l| l.contains("\tsfence"))
                .count()
                == 2,
            "hook/probe must each contain one SFENCE"
        );
        ensure!(
            !disassembly
                .split_whitespace()
                .any(|t| ["%xmm", "%ymm", "%zmm"].iter().any(|r| t.starts_with(r))),
            "ordering hook/probe uses SIMD registers"
        );
        let dump = output.join(format!("{target}.disassembly"));
        fs::write(&dump, disassembly)?;
        capture(&mut ir_command)?;
        let text = fs::read_to_string(&ir)?;
        ensure!(
            text.lines()
                .filter(|l| l.contains("asm sideeffect \"sfence\"") && l.contains("~{memory}"))
                .count()
                == 2,
            "original volatile SFENCE memory clobber was lost"
        );
        profiles.push(json!({"target":target,"command":format!("{command:?}"),"ir_command":format!("{ir_command:?}"),
            "object":tools::binding(&artifact)?,"disassembly":tools::binding(&dump)?,"ir":tools::binding(&ir)?}));
    }
    fs::write(
        output.join("receipt.json"),
        serde_json::to_vec_pretty(&json!({
            "scope":"Three ABI compile/IR/actual emitted-binary inspection only; no hardware or fence execution",
            "adapter":tools::binding(&source.join("port/stela_ordering.c"))?,
            "fixture":tools::binding(&fixture)?,"objdump":tools::binding(&objdump)?,"profiles":profiles,
        }))?,
    )?;
    Ok(())
}

#[cfg_attr(not(feature = "fetched-sources"), ignore = "feature: fetched-sources")]
#[test]
fn ordering_hook_preserves_fences_across_native_abis() {
    let output = tempfile::tempdir().unwrap();
    verify(
        &tools::which("clang").unwrap(),
        &Sources::new(),
        output.path(),
    )
    .unwrap();
}
