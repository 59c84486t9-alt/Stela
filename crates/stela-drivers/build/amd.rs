//! Build only the native AMD command encoder with Mesa's original Meson targets
//! and generators. No prebuilt archive, compiler backend, Vulkan runtime, kernel
//! device initialization or network download is used by this hook.
use std::{env, ffi::OsString, path::PathBuf, process::Command};

pub fn build() {
    let target = env::var("TARGET").expect("Cargo supplies TARGET");
    let host = env::var("HOST").expect("Cargo supplies HOST");
    assert_eq!(
        host, target,
        "AMD command encoding currently requires a native hosted build"
    );
    assert_eq!(env::var("CARGO_CFG_TARGET_ARCH").as_deref(), Ok("x86_64"));
    assert!(
        matches!(
            env::var("CARGO_CFG_TARGET_OS").as_deref(),
            Ok("macos" | "linux")
        ),
        "AMD PM4's hosted C runtime dependencies are not ported to the freestanding target"
    );
    let manifest =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("Cargo supplies manifest"));
    let source = manifest.join("src/gpu/common/mesa");
    assert!(
        source.join("meson.build").is_file(),
        "the upstream GPU sources are missing; run `cargo xtask gpu fetch`"
    );
    let build = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo supplies OUT_DIR"))
        .join("mesa-amd-commands");
    let local = manifest.join("../../.tools/gpu/generators/bin");
    let mut paths = env::split_paths(&env::var_os("PATH").unwrap_or_default()).collect::<Vec<_>>();
    if local.is_dir() {
        paths.push(local);
    }
    let path = env::join_paths(&paths).expect("native tool paths must form a valid PATH");
    let meson = tool("STELA_MESON", "meson", &paths);
    let ninja = tool("STELA_NINJA", "ninja", &paths);
    let mut setup = Command::new(meson);
    setup
        .arg("setup")
        .env("NINJA", &ninja)
        .env("PATH", &path)
        .env("PYTHONDONTWRITEBYTECODE", "1");
    if build.join("meson-private/coredata.dat").is_file() {
        // Cargo reruns this hook only for changed inputs. Reconfigure alone
        // does not adopt changed CC/CFLAGS in Meson's cached machine state.
        setup.arg("--wipe");
    }
    setup.args([
        "--wrap-mode=nodownload",
        "-Dstela-compilers=amd",
        "-Dplatforms=[]",
        "-Dgallium-drivers=[]",
        "-Dvulkan-drivers=[]",
        "-Dopengl=false",
        "-Dgles1=disabled",
        "-Dgles2=disabled",
        "-Degl=disabled",
        "-Dgbm=disabled",
        "-Dglx=disabled",
        "-Dllvm=disabled",
        "-Dvideo-codecs=",
        "-Dbuild-tests=false",
        "-Dbuildtype=debugoptimized",
        "-Db_ndebug=false",
        "-Db_lto=false",
        "-Db_sanitize=none",
    ]);
    setup.arg(&build).arg(&source);
    run(&mut setup);
    let mut compile = Command::new(ninja);
    compile
        .env("PATH", &path)
        .env("PYTHONDONTWRITEBYTECODE", "1");
    compile.arg("-C").arg(&build).args([
        "src/stela/libstela_amd_commands.a",
        "src/amd/common/libamd_common.a",
    ]);
    if let Some(jobs) = env::var_os("NUM_JOBS") {
        compile.arg("-j").arg(jobs);
    }
    run(&mut compile);
    println!(
        "cargo:rustc-link-search=native={}",
        build.join("src/stela").display()
    );
    println!(
        "cargo:rustc-link-search=native={}",
        build.join("src/amd/common").display()
    );
    println!("cargo:rustc-link-lib=static=stela_amd_commands");
    // Mesa's whole common archive: the linker keeps only the command encoders
    // and drops its unused device-query code, whose libdrm calls never link.
    println!("cargo:rustc-link-lib=static=amd_common");
    // The command tests' immutable radeon_info fixture; only cfg(test) links it.
    cc::Build::new()
        .file(manifest.join("src/gpu/amd/tests/commands_fixture.c"))
        .include(source.join("include"))
        .include(source.join("src"))
        .include(build.join("src"))
        .include(build.join("src/amd/common"))
        .std("c11")
        .warnings_into_errors(true)
        .cargo_metadata(false)
        .compile("stela-amd-commands-test");
    println!(
        "cargo:rustc-link-search=native={}",
        env::var("OUT_DIR").expect("Cargo supplies OUT_DIR")
    );
    println!("cargo:rerun-if-changed=src/gpu/amd/tests/commands_fixture.c");
    println!("cargo:rerun-if-changed={}", source.display());
    for name in [
        "CC", "CXX", "AR", "CFLAGS", "CPPFLAGS", "CXXFLAGS", "LDFLAGS", "PATH",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }
}

fn tool(variable: &str, default: &str, paths: &[PathBuf]) -> OsString {
    println!("cargo:rerun-if-env-changed={variable}");
    env::var_os(variable).unwrap_or_else(|| {
        paths
            .iter()
            .map(|directory| directory.join(default))
            .find(|candidate| candidate.is_file())
            .map(PathBuf::into_os_string)
            .unwrap_or_else(|| default.into())
    })
}

fn run(command: &mut Command) {
    let result = command.output().unwrap_or_else(|error| {
        panic!("cannot execute {command:?}: {error}; install Mesa's documented build tools")
    });
    assert!(
        result.status.success(),
        "{command:?} failed ({}):\n{}\n{}",
        result.status,
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}
