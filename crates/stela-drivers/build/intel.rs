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
    // The overlay hides shadows from dependency tracking, so the whole Linux
    // environment and the upstream trees it builds from are inputs.
    for path in ["stela", "xe", "i915/gt", "../common/linux/include"] {
        println!("cargo:rerun-if-changed={source}/{path}");
    }
    println!("cargo:rerun-if-env-changed=STELA_GPU_PYTHON");
    let python = PathBuf::from(env::var_os("STELA_GPU_PYTHON").unwrap_or_else(|| "python3".into()));
    generate_workarounds(&output);
    configure_dispatch(build, &output, &python);
}

/// Xe's workaround table, generated as Kbuild does by Linux's unchanged
/// generator from its rules, as <generated/xe_wa_oob.h>.
fn generate_workarounds(output: &std::path::Path) {
    use std::{env, fs, process::Command};
    let source = "src/gpu/intel/xe";
    let generated = output.join("intel-generated/generated");
    fs::create_dir_all(&generated).expect("create the generated Xe header directory");
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
        .expect("compile Xe's workaround generator");
    assert!(
        result.status.success(),
        "Xe workaround generator compilation failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let result = Command::new(&generator)
        .arg(format!("{source}/xe_wa_oob.rules"))
        .arg(output.join("xe_wa_oob.c"))
        .arg(generated.join("xe_wa_oob.h"))
        .output()
        .expect("run Xe's workaround generator");
    assert!(
        result.status.success(),
        "Xe workaround generation failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
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
