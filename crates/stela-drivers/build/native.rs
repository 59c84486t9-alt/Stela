//! Native C for the physical GPU ports: target and tool selection, Stela's
//! Linux environment for unchanged Linux sources, and the hosted C test
//! programs that `cargo test` runs when Cargo builds for this machine.
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

/// LP64 COFF with the Win64 calling convention; see `configure`.
pub const NATIVE_TARGET: &str = "x86_64-pc-cygwin";

/// Stela's own C is held to these as errors. Upstream code builds from system
/// include directories and keeps its own warning profile.
const WARNINGS: [&str; 4] = ["-Wall", "-Wextra", "-Wconversion", "-Wsign-conversion"];

/// Upstream GPU sources are linked into `src/gpu` by `cargo xtask gpu fetch`.
pub fn require_sources() {
    assert!(
        Path::new("src/gpu/common/linux/include").is_dir(),
        "the upstream GPU sources are missing; run `cargo xtask gpu fetch`"
    );
}

/// The port's sources compiled for Cargo's target, freestanding as the mount
/// runs them.
pub fn configure() -> cc::Build {
    require_sources();
    assert_eq!(
        env::var("CARGO_CFG_TARGET_ARCH").as_deref(),
        Ok("x86_64"),
        "the native physical GPU backends currently target x86-64"
    );
    let mut build = cc::Build::new();
    common(&mut build);
    build
        .flag("-ffreestanding")
        .flag("-fno-stack-protector")
        .flag("-mno-red-zone")
        .flag("-mgeneral-regs-only");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("uefi") {
        // Upstream GPU code assumes LP64, as on Linux. Cygwin's target keeps
        // that data model while emitting COFF with the UEFI Win64 C ABI;
        // clang uses this last target over the one cc derives. Its large
        // frames must not call Cygwin's ___chkstk_ms, which the mount lacks,
        // and its objects carry no incremental-linker timestamps.
        build
            .flag(format!("--target={NATIVE_TARGET}"))
            .flag("-mno-stack-arg-probe")
            .flag("-mno-incremental-linker-compatible");
        if !selected("CC") {
            build.compiler("clang");
        }
        if !selected("AR") {
            build.archiver(rust_archiver());
        }
    }
    build
}

/// The same sources compiled for this machine with sanitizers, for the C test
/// programs. `None` when Cargo cross-compiles: the programs cannot run then.
pub fn hosted() -> Option<cc::Build> {
    if env::var("TARGET").ok() != env::var("HOST").ok() {
        return None;
    }
    let mut build = cc::Build::new();
    common(&mut build);
    // Optimized as the mount's release build: the adapters still name upstream
    // services that only dead code calls, and they do not link without it.
    build
        .cargo_metadata(false)
        .opt_level(2)
        .debug(true)
        .flag("-fsanitize=address,undefined")
        .flag("-fno-sanitize-recover=all")
        .flag("-fno-omit-frame-pointer");
    Some(build)
}

fn common(build: &mut cc::Build) {
    build.std("gnu11").warnings_into_errors(true);
    for warning in WARNINGS {
        build.flag(warning);
    }
}

/// Whether the caller chose a tool through cc's standard environment.
fn selected(tool: &str) -> bool {
    let target = env::var("TARGET").expect("Cargo supplies TARGET");
    let names = [
        format!("{tool}_{target}"),
        format!("{tool}_{}", target.replace('-', "_")),
        format!("TARGET_{tool}"),
        tool.into(),
    ];
    for name in &names {
        println!("cargo:rerun-if-env-changed={name}");
    }
    names.iter().any(|name| env::var_os(name).is_some())
}

/// Apple's ar produces a BSD archive even for COFF inputs; the active Rust
/// toolchain's LLVM archiver does not.
fn rust_archiver() -> PathBuf {
    let output = Command::new(env::var_os("RUSTC").expect("Cargo supplies RUSTC"))
        .args(["--print", "sysroot"])
        .output()
        .expect("cannot locate the active Rust sysroot");
    assert!(output.status.success(), "rustc --print sysroot failed");
    let sysroot = String::from_utf8(output.stdout).expect("Rust sysroot is not UTF-8");
    let host = env::var("HOST").expect("Cargo supplies HOST");
    let archiver = PathBuf::from(sysroot.trim())
        .join("lib/rustlib")
        .join(host)
        .join(format!("bin/llvm-ar{}", env::consts::EXE_SUFFIX));
    assert!(
        archiver.is_file(),
        "install llvm-tools-preview for the active Rust toolchain"
    );
    archiver
}

/// Stela's Linux environment for unchanged Linux sources: Kbuild's definition
/// and forced includes, and system include directories so upstream code keeps
/// Linux's warning profile rather than Stela's. `compat/overlay.yaml` puts each
/// shadow in place of the upstream header it replaces, however a source names
/// it. `generated` holds headers Linux's build generates, `drivers` the
/// upstream driver directories. `compat/` follows Linux's include trees for the
/// asm/ and generated/ headers that Linux's arch tree and build supply, then
/// the x86 uapi headers.
pub fn linux_environment(build: &mut cc::Build, generated: Option<&Path>, drivers: &[&str]) {
    let gpu = "src/gpu";
    let linux = format!("{gpu}/common/linux/include");
    build
        .flag("-ivfsoverlay")
        .flag(format!("{gpu}/compat/overlay.yaml"))
        .define("__KERNEL__", None)
        .flag("-include")
        .flag(format!("{linux}/linux/kconfig.h"))
        .flag("-include")
        .flag(format!("{linux}/linux/compiler_types.h"));
    if let Some(generated) = generated {
        build.flag("-isystem").flag(generated);
    }
    let directories = drivers.iter().map(|driver| format!("{gpu}/{driver}"));
    for directory in directories.chain([
        linux.clone(),
        format!("{linux}/uapi"),
        format!("{gpu}/compat"),
        format!("{gpu}/common/linux/arch/x86/include/uapi"),
    ]) {
        build.flag("-isystem").flag(directory);
    }
    // The overlay hides shadows from dependency tracking, so the whole
    // environment and the upstream trees it builds from are inputs.
    for path in [format!("{gpu}/compat"), linux] {
        println!("cargo:rerun-if-changed={path}");
    }
    for driver in drivers {
        println!("cargo:rerun-if-changed={gpu}/{driver}");
    }
}

/// Clang reports nothing from system headers, not even a call to a service no
/// header declares, so check each adapter for those before it links.
pub fn check_declarations(build: &cc::Build, sources: &[PathBuf]) {
    for source in sources {
        run(build
            .get_compiler()
            .to_command()
            .args(["-Wsystem-headers", "-Wno-everything"])
            .args([
                "-Werror=implicit-function-declaration",
                "-Werror=implicit-int",
            ])
            .arg("-fsyntax-only")
            .arg(source));
    }
}

/// The C files directly in `directory`, in a stable order.
pub fn sources(directory: &str) -> Vec<PathBuf> {
    let mut sources = fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("cannot read {directory}: {error}"))
        .map(|entry| entry.expect("readable directory entry").path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "c"))
        .collect::<Vec<_>>();
    sources.sort();
    println!("cargo:rerun-if-changed={directory}");
    sources
}

/// Hosted C test programs, each run by its own Rust test.
#[derive(Default)]
pub struct Tests(Vec<(String, PathBuf)>);

impl Tests {
    /// Link `source` with `archives` into a program named `name`. A source may
    /// include the adapter it tests; the archives supply the others it calls.
    pub fn add(&mut self, build: &cc::Build, name: &str, source: &str, archives: &[&Path]) {
        let program = out_dir().join(format!("c-test-{name}"));
        let mut command = build.get_compiler().to_command();
        command.arg(source).args(archives).arg("-o").arg(&program);
        run(command.args(["-lpthread", "-lm"]));
        println!("cargo:rerun-if-changed={source}");
        self.0.push((name.replace('-', "_"), program));
    }

    /// The Rust tests `src/gpu.rs` includes, one per program.
    pub fn write(&self) {
        let tests = self
            .0
            .iter()
            .map(|(name, program)| {
                format!("#[test]\nfn {name}() {{\n    run({:?});\n}}\n", program)
            })
            .collect::<String>();
        fs::write(out_dir().join("c_tests.rs"), tests).expect("write the C test list");
    }
}

/// Compile `sources` with `build` into an archive outside Cargo's link line.
pub fn archive(build: &cc::Build, name: &str, sources: &[PathBuf]) -> PathBuf {
    build.clone().files(sources).compile(name);
    out_dir().join(format!("lib{name}.a"))
}

pub fn out_dir() -> PathBuf {
    PathBuf::from(env::var_os("OUT_DIR").expect("Cargo supplies OUT_DIR"))
}

pub fn run(command: &mut Command) {
    let line = std::iter::once(command.get_program())
        .chain(command.get_args())
        .map(|part| part.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ");
    let output = command
        .output()
        .unwrap_or_else(|error| panic!("cannot run {line}: {error}"));
    assert!(
        output.status.success(),
        "{line} failed ({}):\n{}{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
