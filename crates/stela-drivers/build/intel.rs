//! Source list for the native Intel support library; the caller owns target,
//! compiler, archiver, freestanding flags, and the final library name. Dispatch
//! headers use Mesa's original XML generator and a selected Python interpreter.
pub fn configure(build: &mut cc::Build) {
    use std::{env, path::PathBuf};

    let source = "src/gpu/intel";
    build
        .define("STELA_NATIVE", None)
        .include(format!("{source}/xe"))
        .file(format!("{source}/xe/xe_pt_walk.c"))
        .file(format!("{source}/stela/pt_walk.c"))
        .file(format!("{source}/stela/commands.c"))
        .file(format!("{source}/stela/ct.c"))
        .file(format!("{source}/stela/i915_commands.c"));
    for path in [
        "stela",
        "xe/xe_pt_walk.h",
        "xe/xe_ring_emit.h",
        "xe/instructions",
        "xe/xe_guc_ct_message.h",
        "xe/abi",
        "xe/regs/xe_guc_ct_regs.h",
        "i915/gt/intel_gpu_commands.h",
        "i915/gt/intel_batch_emit.h",
    ] {
        println!("cargo:rerun-if-changed={source}/{path}");
    }
    println!("cargo:rerun-if-env-changed=STELA_GPU_PYTHON");
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo supplies OUT_DIR"));
    let python = PathBuf::from(env::var_os("STELA_GPU_PYTHON").unwrap_or_else(|| "python3".into()));
    configure_dispatch(build, &output, &python);
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
