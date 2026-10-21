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
    for generation in [70, 75, 80, 90, 110, 120] {
        let generated = output.join(format!("gen{generation}_dispatch_pack.h"));
        let result = Command::new(python)
            .arg(format!("{genxml}/gen_pack_header.py"))
            .arg(format!("{genxml}/gen{generation}.xml"))
            .args([
                "--include-symbols",
                "GPGPU_WALKER,MEDIA_STATE_FLUSH",
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
        build.file(format!("src/gpu/intel/stela/dispatch/gen{generation}.c"));
    }
    build
        .file("src/gpu/intel/stela/dispatch.c")
        .include(output)
        .include("src/gpu/intel/stela")
        .include("src/gpu/common/mesa/src")
        .include(genxml);
    println!("cargo:rerun-if-changed={genxml}");
    println!("cargo:rerun-if-changed=src/gpu/common/mesa/src/util/bitpack_uint.h");
}
