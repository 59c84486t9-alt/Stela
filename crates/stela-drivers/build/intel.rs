//! Source list for the native Intel support library; the caller owns target,
//! compiler, archiver, freestanding flags, and the final library name. Dispatch
//! headers use Mesa's original XML generator and a selected Python interpreter.
pub fn configure(build: &mut cc::Build) {
    use std::{env, path::PathBuf};

    let source = "src/gpu/intel";
    let linux = "src/gpu/common/linux/include";
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo supplies OUT_DIR"));
    // Unchanged Linux sources build in Stela's Linux environment, with Kbuild's
    // definition and forced includes, from system directories so upstream code
    // keeps Linux's warning profile rather than Stela's. compat/overlay.yaml
    // puts each shadow in place of the upstream header it replaces, however a
    // source names it. compat/ itself comes last and only adds the asm/ and
    // generated/ headers that Linux's arch tree and build supply.
    let overlay = format!("{source}/stela/compat/overlay.yaml");
    println!("cargo:rerun-if-changed={source}/stela/compat");
    build
        .flag("-ivfsoverlay")
        .flag(&overlay)
        .define("__KERNEL__", None)
        .flag("-include")
        .flag(format!("{linux}/linux/kconfig.h"))
        .flag("-include")
        .flag(format!("{linux}/linux/compiler_types.h"))
        .flag("-isystem")
        .flag(output.join("intel-generated"));
    for directory in [
        format!("{source}/xe"),
        format!("{source}/i915"),
        linux.into(),
        format!("{linux}/uapi"),
        format!("{source}/stela/compat"),
    ] {
        build.flag("-isystem").flag(directory);
    }
    build
        .file(format!("{source}/xe/xe_pt_walk.c"))
        .file(format!("{source}/stela/pt_walk.c"))
        .file(format!("{source}/stela/commands.c"))
        .file(format!("{source}/stela/ct.c"))
        .file(format!("{source}/stela/activation.c"))
        .file(format!("{source}/stela/guc_reset.c"))
        .file(format!("{source}/stela/firmware.c"))
        .file(format!("{source}/stela/wopcm.c"))
        .file(format!("{source}/stela/ggtt_probe.c"))
        .file(format!("{source}/stela/pat.c"))
        .file(format!("{source}/stela/i915_commands.c"));
    for path in [
        "stela",
        "xe/xe_pt_walk.h",
        "xe/xe_ring_emit.h",
        "xe/instructions",
        "xe/xe_guc_ct_message.h",
        "xe/abi",
        "xe/regs/xe_guc_ct_regs.h",
        "xe/xe_pci_device_info.h",
        "xe/xe_pci_runtime.h",
        "xe/xe_pci_types.h",
        "xe/xe_platform_types.h",
        "xe/xe_engine_ids.h",
        "xe/xe_gt_type.h",
        "xe/xe_cache_level.h",
        "xe/xe_pat.h",
        "xe/xe_uc_fw_types.h",
        "xe/xe_wopcm.h",
        "xe/xe_uc_fw.h",
        "xe/xe_macros.h",
        "xe/xe_ggtt_probe_core.h",
        "xe/regs/xe_gtt_defs.h",
        "xe/xe_wopcm_types.h",
        "xe/xe_huc_role.h",
        "xe/regs/xe_guc_regs.h",
        "xe/xe_force_wake_core.h",
        "xe/xe_force_wake_gt.h",
        "xe/xe_force_wake_domain_types.h",
        "xe/xe_mmio_poll.h",
        "xe/xe_guc_reset_core.h",
        "xe/xe_gen_wa_oob.c",
        "xe/xe_wa_oob.rules",
        "xe/regs/xe_gt_regs.h",
        "xe/regs/xe_regs.h",
        "xe/regs/xe_reg_defs.h",
        "xe/regs/xe_reg_type.h",
        "i915/gt/intel_gpu_commands.h",
        "i915/gt/intel_batch_emit.h",
    ] {
        println!("cargo:rerun-if-changed={source}/{path}");
    }
    for header in [
        "linux/kconfig.h",
        "linux/cleanup.h",
        "linux/compiler_attributes.h",
        "linux/align.h",
        "linux/array_size.h",
        "linux/container_of.h",
        "linux/err.h",
        "linux/errno.h",
        "linux/sizes.h",
        "linux/stringify.h",
        "kunit/static_stub.h",
        "uapi/asm-generic/errno.h",
        "uapi/asm-generic/errno-base.h",
        "uapi/asm-generic/ioctl.h",
        "uapi/drm/drm.h",
        "uapi/drm/xe_drm.h",
    ] {
        println!("cargo:rerun-if-changed={linux}/{header}");
    }
    println!("cargo:rerun-if-changed=src/gpu/common/linux/include/drm/intel/pciids.h");
    println!("cargo:rerun-if-changed=src/gpu/common/linux/include/vdso/align.h");
    println!("cargo:rerun-if-changed=src/gpu/common/linux/include/vdso/const.h");
    println!("cargo:rerun-if-env-changed=STELA_GPU_PYTHON");
    let python = PathBuf::from(env::var_os("STELA_GPU_PYTHON").unwrap_or_else(|| "python3".into()));
    configure_ggtt(build, &output);
    configure_guc_reset(build, &output);
    configure_dispatch(build, &output, &python);
}

/// Use the unchanged original host generator and its complete rule input.
/// The native reset TU verifies that this actual WA excludes its admitted GTs.
fn configure_guc_reset(build: &mut cc::Build, output: &std::path::Path) {
    use std::{env, fs, process::Command};
    let source = "src/gpu/intel/xe";
    // The unchanged xe_pat.c includes the header as <generated/xe_wa_oob.h>.
    let generated = output.join("intel-generated/generated");
    fs::create_dir_all(&generated).expect("create the generated Xe header directory");
    let upstream_header = generated.join("xe_wa_oob.h");
    let output = output.join("intel-guc-reset");
    fs::create_dir_all(&output).expect("create GuC reset generation directory");
    let host = env::var("HOST").expect("Cargo supplies host triple");
    let generator = output.join(if host.contains("windows") {
        "xe_gen_wa_oob.exe"
    } else {
        "xe_gen_wa_oob"
    });
    let compiler = cc::Build::new()
        .host(&host)
        .target(&host)
        .cargo_metadata(false)
        .get_compiler();
    let result = compiler
        .to_command()
        .args(["-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror"])
        .arg(format!("{source}/xe_gen_wa_oob.c"))
        .arg("-o")
        .arg(&generator)
        .output()
        .expect("compile original GuC WA generator");
    assert!(
        result.status.success(),
        "original GuC WA generator compilation failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let generated = output.join("xe_wa_oob.c");
    let result = Command::new(&generator)
        .arg(format!("{source}/xe_wa_oob.rules"))
        .arg(&generated)
        .arg(upstream_header)
        .output()
        .expect("run original GuC WA generator");
    assert!(
        result.status.success(),
        "original GuC WA generation failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let contents = fs::read_to_string(generated).expect("read original GuC WA output");
    let start = "{ XE_RTP_NAME(\"14025883347\"),";
    assert_eq!(
        contents.matches(start).count(),
        1,
        "changed original GuC reset WA entry"
    );
    let (_, entry) = contents.split_once(start).expect("original reset WA entry");
    let (entry, _) = entry
        .split_once(") },")
        .expect("original reset WA terminator");
    fs::write(
        output.join("guc_reset_wa.inc"),
        format!("{start}{entry}) }},\n"),
    )
    .expect("write original reset WA entry");
    build.flag("-isystem").flag(output);
}

fn configure_dispatch(build: &mut cc::Build, output: &std::path::Path, python: &std::path::Path) {
    use std::{fs, process::Command};

    let genxml = "src/gpu/common/mesa/src/intel/genxml";
    let output = output.join("intel-dispatch");
    fs::create_dir_all(&output).expect("cannot create Intel packet generation directory");
    const LEGACY: &str = "GPGPU_WALKER,MEDIA_STATE_FLUSH";
    const COMPUTE: &str = "COMPUTE_WALKER,COMPUTE_WALKER_BODY,INTERFACE_DESCRIPTOR_DATA,POSTSYNC_DATA,PREF_SLM_ALLOCATION_SIZE";
    for (generation, xml, family, unit, symbols) in [
        (70, "gen70", "dispatch", "gen", LEGACY),
        (75, "gen75", "dispatch", "gen", LEGACY),
        (80, "gen80", "dispatch", "gen", LEGACY),
        (90, "gen90", "dispatch", "gen", LEGACY),
        (110, "gen110", "dispatch", "gen", LEGACY),
        (120, "gen120", "dispatch", "gen", LEGACY),
        (125, "gen125", "compute", "compute", COMPUTE),
        (200, "xe2", "compute", "compute", COMPUTE),
        (300, "xe3", "compute", "compute", COMPUTE),
        (350, "xe3p", "compute", "compute", COMPUTE),
    ] {
        let generated = output.join(format!("gen{generation}_{family}_pack.h"));
        let result = Command::new(python)
            .arg(format!("{genxml}/gen_pack_header.py"))
            .arg(format!("{genxml}/{xml}.xml"))
            .args([
                "--include-symbols",
                symbols,
                "--helpers-include",
                "genxml_native.h",
            ])
            .output()
            .expect("Mesa Intel XML generation requires Python 3; select STELA_GPU_PYTHON");
        assert!(
            result.status.success(),
            "Intel Gen{generation} packet generation failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        fs::write(generated, result.stdout).expect("cannot write generated Intel packet header");
        build.file(format!("src/gpu/intel/stela/dispatch/{unit}{generation}.c"));
    }
    build
        .file("src/gpu/intel/stela/dispatch.c")
        .file("src/gpu/intel/stela/compute_dispatch.c")
        .include(output)
        .include("src/gpu/intel/stela")
        .include("src/gpu/common/mesa/src")
        .include(genxml);
    println!("cargo:rerun-if-changed={genxml}");
    println!("cargo:rerun-if-changed=src/gpu/common/mesa/src/util/bitpack_uint.h");
}

/// Copy only the nine original scalar definitions needed by the native probe.
/// The full headers require Linux services; no hardware values are mirrored.
fn configure_ggtt(build: &mut cc::Build, output: &std::path::Path) {
    use std::fs;
    let original = "src/gpu/common/linux/include/drm/intel/i915_drm.h";
    let drm = fs::read_to_string(original).expect("read original Intel GMCH definitions");
    let mut header = drm
        .split_once("#ifndef _I915_DRM_H_")
        .expect("original Intel header guard")
        .0
        .to_owned();
    for (path, names) in [
        (
            original,
            ["SNB_GMCH_CTRL", "BDW_GMCH_GGMS_SHIFT", "BDW_GMCH_GGMS_MASK"],
        ),
        (
            "src/gpu/intel/xe/xe_bo.h",
            ["XE_PTE_SHIFT", "XE_PAGE_SIZE", "XE_PTE_MASK"],
        ),
        (
            "src/gpu/common/linux/include/linux/sizes.h",
            ["SZ_1M", "SZ_8M", "SZ_2M"],
        ),
    ] {
        println!("cargo:rerun-if-changed={path}");
        let source = fs::read_to_string(path).expect("read original GGTT scalar header");
        for name in names {
            let mut lines = source.lines().filter(|line| {
                let mut words = line.split_whitespace();
                words.next() == Some("#define") && words.next() == Some(name)
            });
            header.push_str(lines.next().expect("missing original GGTT scalar define"));
            header.push('\n');
            assert!(
                lines.next().is_none(),
                "duplicate original GGTT define {name}"
            );
        }
    }
    let output = output.join("intel-ggtt");
    fs::create_dir_all(&output).expect("create GGTT scalar output directory");
    fs::write(output.join("ggtt_probe_defs.h"), header).expect("write original GGTT scalar header");
    build.flag("-isystem").flag(output);
}
