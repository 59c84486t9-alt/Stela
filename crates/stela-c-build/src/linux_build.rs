//! Shared Linux archive diagnostics, build outputs and hosted fixture programs.
use std::{
    env, fs,
    path::{Path, PathBuf},
};

/// Compile unchanged helpers with the common ABI and baseline diagnostics,
/// then archive them with the strictly checked owned objects. One archive
/// preserves dependency resolution between Linux helpers and host services.
pub fn linux_archive(
    build: &cc::Build,
    name: &str,
    kernel: &[PathBuf],
    upstream: &[PathBuf],
    compat: &Path,
) -> PathBuf {
    check_declarations(build, kernel);
    let mut upstream_build = upstream_build(build, compat);
    check_declarations(&upstream_build, upstream);
    upstream_warnings(&mut upstream_build);
    upstream_build.files(upstream);
    let objects = upstream_build.compile_intermediates();
    let mut combined = build.clone();
    combined.objects(&objects);
    archive(&combined, name, kernel)
}

/// `build` for unchanged Linux sources.
pub fn upstream_build(build: &cc::Build, compat: &Path) -> cc::Build {
    let mut build = build.clone();
    // The scheduler's shared units include its internal header as "sched.h";
    // Stela's scheduler supplies what they take from it. As Kbuild builds
    // every profile: Linux relies on the optimizer to drop the calls its
    // configuration disables.
    build
        .flag(format!("-iquote{}/kernel/sched", compat.display()))
        .opt_level(2);
    build
}

/// Linux's own warning profile for unchanged sources, in place of Stela's.
pub fn upstream_warnings(build: &mut cc::Build) {
    build
        .remove_flag("-Wconversion")
        .remove_flag("-Wsign-conversion")
        // Linux scripts/Makefile.warn disables these outside W=3. Unchanged
        // helpers compare signed counts and keep unused public parameters.
        .flag("-Wno-sign-compare")
        .flag("-Wno-unused-parameter")
        // Linux's top-level Makefile builds every file with -Wno-pointer-sign:
        // mutex.c passes its unsigned owner word to the long atomic helpers.
        .flag("-Wno-pointer-sign");
    // The rest of scripts/Makefile.warn's default (no W=) clang profile.
    for warning in [
        "format-security",
        "trigraphs",
        "frame-address",
        "address-of-packed-member",
        "type-limits",
        "unused-but-set-variable",
        "unused-const-variable",
        "initializer-overrides",
        "pointer-to-enum-cast",
        "tautological-constant-out-of-range-compare",
        "unaligned-access",
        "enum-compare-conditional",
        "missing-field-initializers",
        "shift-negative-value",
        "enum-enum-conversion",
    ] {
        build.flag(format!("-Wno-{warning}"));
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
pub struct Tests {
    programs: Vec<(String, PathBuf)>,
    rust: Vec<(&'static str, &'static str)>,
}

impl Tests {
    /// Link `source` with `archives` into a program named `name`. A source may
    /// include the adapter it tests; the archives supply the others it calls.
    pub fn add(&mut self, build: &cc::Build, name: &str, source: &str, archives: &[&Path]) {
        let program = out_dir().join(format!("c-test-{name}"));
        let mut command = build.get_compiler().to_command();
        command.arg(source).args(archives).arg("-o").arg(&program);
        run(command.args(["-lpthread", "-lm"]));
        println!("cargo:rerun-if-changed={source}");
        self.programs.push((name.replace('-', "_"), program));
    }

    /// The Rust-hosted fixtures, each with its own exact child selector.
    pub fn rust_children(&mut self) {
        self.rust.extend([
            ("linux_trees", "crate::task::tests::run_trees_child()"),
            ("linux_mutex_wait", "crate::task::tests::run_mutex_child()"),
        ]);
    }

    /// The Rust tests `src/lib.rs` includes, one per program/child wrapper.
    pub fn write(&self) {
        let mut tests = self
            .programs
            .iter()
            .map(|(name, program)| {
                format!("#[test]\nfn {name}() {{\n    run({:?});\n}}\n", program)
            })
            .collect::<String>();
        for (name, body) in &self.rust {
            tests.push_str(&format!("#[test]\nfn {name}() {{\n    {body};\n}}\n"));
        }
        fs::write(out_dir().join("c_tests.rs"), tests).expect("write the C test list");
    }
}

/// Compile `sources` with `build` into an archive outside Cargo's link line.
pub fn archive(build: &cc::Build, name: &str, sources: &[PathBuf]) -> PathBuf {
    build.clone().files(sources).compile(name);
    out_dir().join(format!("lib{name}.a"))
}

/// Rebuild when `path` changes.
pub fn rerun_on(path: &Path) {
    println!("cargo:rerun-if-changed={}", path.display());
}

pub fn out_dir() -> PathBuf {
    PathBuf::from(env::var_os("OUT_DIR").expect("Cargo supplies OUT_DIR"))
}

pub fn run(command: &mut std::process::Command) {
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
