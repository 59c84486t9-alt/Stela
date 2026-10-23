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

/// The upstream sources: submodules that `cargo xtask gpu fetch` checks out.
#[cfg(feature = "linux-kernel")]
pub const LINUX: &str = "../../third_party/linux";
#[cfg(feature = "intel-port")]
pub const MESA: &str = "../../third_party/mesa";
#[cfg(feature = "nvidia-port")]
pub const NVIDIA: &str = "../../third_party/nvidia";

pub fn require_sources() {
    for source in [
        #[cfg(feature = "linux-kernel")]
        LINUX,
        #[cfg(feature = "intel-port")]
        MESA,
        #[cfg(feature = "nvidia-port")]
        NVIDIA,
    ] {
        assert!(
            Path::new(source).join(".git").exists(),
            "{source} is missing; run `cargo xtask gpu fetch`"
        );
    }
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
    build
        .cargo_metadata(false)
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

/// A Linux module, as Kbuild names it to the sources it builds.
pub struct Module {
    pub name: &'static str,
    /// The module's path in Linux's tree, without its extension.
    pub file: &'static str,
}

/// Stela's Linux environment for unchanged Linux sources, and the kernel-API
/// in `compat/linux/kernel` that they call, built once for every port.
pub struct Linux {
    /// Kbuild's generated asm wrappers, in `asm/` and `uapi/asm/`.
    wrappers: PathBuf,
    /// What hosted programs running Linux code link: the kernel-API and the
    /// host's platform services.
    pub hosted: Vec<PathBuf>,
}

const DRM: &str = "../../third_party/linux/drivers/gpu/drm";
const COMPAT: &str = "src/gpu/compat/linux";
const INCLUDE: &str = "../../third_party/linux/include";
const X86_UAPI: &str = "../../third_party/linux/arch/x86/include/uapi";

impl Linux {
    pub fn new() -> Self {
        require_sources();
        additions(Path::new(COMPAT));
        let wrappers = out_dir().join("linux-asm");
        // As Kbuild does, each mandatory asm header that the arch does not
        // provide wraps asm-generic's. Stela's arch headers are compat's.
        for (list, arch, directory) in [
            ("asm-generic/Kbuild", format!("{COMPAT}/asm"), "asm"),
            (
                "uapi/asm-generic/Kbuild",
                format!("{X86_UAPI}/asm"),
                "uapi/asm",
            ),
        ] {
            let output = wrappers.join(directory);
            fs::create_dir_all(&output).expect("create the asm wrapper directory");
            let list = fs::read_to_string(format!("{INCLUDE}/{list}"))
                .unwrap_or_else(|error| panic!("{list}: {error}"));
            for header in list
                .lines()
                .filter_map(|line| line.strip_prefix("mandatory-y += "))
                .filter(|header| !Path::new(&arch).join(header).exists())
            {
                let wrapper = format!("#include <asm-generic/{header}>\n");
                fs::write(output.join(header), wrapper).expect("write an asm wrapper");
            }
        }
        let mut linux = Self {
            wrappers,
            hosted: Vec::new(),
        };
        let kernel = sources(&format!("{COMPAT}/kernel"));
        // Unchanged shared helpers use Linux's arithmetic types. Stela's
        // extra conversion diagnostics remain confined to its own source.
        let upstream = [
            PathBuf::from(format!("{DRM}/drm_fourcc.c")),
            PathBuf::from(format!("{LINUX}/lib/scatterlist.c")),
        ];
        for source in &upstream {
            println!("cargo:rerun-if-changed={}", source.display());
        }
        let mut build = configure();
        linux.apply(&mut build, None, &[], None);
        linux_archive(&build, "stela-linux", &kernel, &upstream);
        if let Some(host) = hosted() {
            let services = [PathBuf::from(format!("{COMPAT}/stela/test.c"))];
            let services = archive(&host, "linux-host", &services);
            let mut kernel_build = host;
            linux.apply(&mut kernel_build, None, &[], None);
            linux.hosted = vec![
                linux_archive(&kernel_build, "linux-hosted", &kernel, &upstream),
                services,
            ];
        }
        linux
    }

    pub fn tests(&self, tests: &mut Tests) {
        let Some(mut build) = hosted() else {
            return;
        };
        self.apply(&mut build, None, &[], None);
        let archives = self.hosted.iter().map(PathBuf::as_path).collect::<Vec<_>>();
        for (name, source, define) in [
            ("linux_drm_formats", "drm.c", "STELA_LINUX_DRM_FORMAT_TEST"),
            ("linux_rcu", "rcu.c", "STELA_LINUX_RCU_TEST"),
            ("linux_pages", "page.c", "STELA_LINUX_PAGE_TEST"),
        ] {
            let mut build = build.clone();
            build.define(define, None);
            tests.add(
                &build,
                name,
                &format!("{COMPAT}/kernel/{source}"),
                &archives,
            );
        }
    }

    /// Kbuild's definitions, flags and forced includes, and system include
    /// directories so upstream code keeps Linux's warning profile rather than
    /// Stela's. `generated` holds headers a driver's build generates and
    /// `drivers` its directories below Linux's `drivers/gpu/drm`. Stela's
    /// arch headers in `compat/linux/asm` and the generated wrappers stand for
    /// Linux's arch tree ahead of its `include` tree, and the x86 uapi
    /// headers and their wrappers ahead of `include/uapi`.
    pub fn apply(
        &self,
        build: &mut cc::Build,
        generated: Option<&Path>,
        drivers: &[&str],
        module: Option<&Module>,
    ) {
        // As Kbuild builds, no headers outside Linux's trees: neither the
        // host's C library nor the compiler's own. Stela's C code gets the C
        // headers it uses from `compat`, over Linux's types.
        build
            .flag("-nostdinc")
            .define("__KERNEL__", None)
            // Linux explicitly supports static reuse without its ELF module
            // export records (also used by its own UEFI stub).
            .define("__DISABLE_EXPORTS", None);
        for flag in [
            "-fms-extensions",
            "-fno-strict-aliasing",
            "-fno-common",
            "-fno-strict-overflow",
            "-fno-delete-null-pointer-checks",
            "-funsigned-char",
        ] {
            build.flag(flag);
        }
        for header in [
            format!("{INCLUDE}/linux/kconfig.h"),
            format!("{INCLUDE}/linux/compiler_types.h"),
            format!("{COMPAT}/stela/compiler.h"),
        ] {
            build.flag("-include").flag(header);
        }
        if let Some(module) = module {
            build
                .define("KBUILD_MODNAME", format!("\"{}\"", module.name).as_str())
                .define("KBUILD_MODFILE", format!("\"{}\"", module.file).as_str());
        }
        let drivers = drivers
            .iter()
            .map(|driver| PathBuf::from(format!("{DRM}/{driver}")))
            .collect::<Vec<_>>();
        // Cargo sees no included header, so every source tree the
        // environment builds from is an input.
        for directory in drivers.iter().map(|path| path.as_path()).chain([
            Path::new(COMPAT),
            Path::new(INCLUDE),
            Path::new(X86_UAPI),
        ]) {
            println!("cargo:rerun-if-changed={}", directory.display());
        }
        for directory in generated
            .map(Path::to_path_buf)
            .into_iter()
            .chain(drivers)
            .chain([
                COMPAT.into(),
                self.wrappers.clone(),
                INCLUDE.into(),
                X86_UAPI.into(),
                self.wrappers.join("uapi"),
                format!("{INCLUDE}/uapi").into(),
            ])
        {
            build.flag("-isystem").flag(directory);
        }
    }
}

/// Compile unchanged helpers with the common ABI and baseline diagnostics,
/// then archive them with the strictly checked owned objects. One archive
/// preserves dependency resolution between Linux helpers and host services.
fn linux_archive(
    build: &cc::Build,
    name: &str,
    kernel: &[PathBuf],
    upstream: &[PathBuf],
) -> PathBuf {
    check_declarations(build, kernel);
    check_declarations(build, upstream);
    let mut upstream_build = build.clone();
    upstream_build
        .remove_flag("-Wconversion")
        .remove_flag("-Wsign-conversion")
        .files(upstream);
    let objects = upstream_build.compile_intermediates();
    let mut combined = build.clone();
    combined.objects(&objects);
    archive(&combined, name, kernel)
}

/// Every header in `compat` adds to Linux's: none stands in for one of
/// `include/` by sharing its path, so upstream code always compiles against
/// Linux's own headers. Its `asm/` is Stela's arch, which stands in for x86's.
fn additions(directory: &Path) {
    for entry in fs::read_dir(directory).expect("read the kernel-API directory") {
        let path = entry.expect("readable directory entry").path();
        let header = path.strip_prefix(COMPAT).expect("a kernel-API path");
        if path.is_dir() {
            if header != Path::new("asm") {
                additions(&path);
            }
            continue;
        }
        for tree in [INCLUDE, &format!("{INCLUDE}/uapi")] {
            assert!(
                !Path::new(tree).join(header).exists(),
                "{COMPAT}/{} would replace Linux's in {tree}",
                header.display()
            );
        }
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
