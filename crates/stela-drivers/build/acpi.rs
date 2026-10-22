//! Build the pinned freestanding ACPICA implementation only when requested.
use std::{env, fs, path::PathBuf, process::Command};

fn run(command: &mut Command) {
    let status = command.status().expect("execute ACPICA tool");
    assert!(status.success(), "ACPICA tool failed: {command:?}");
}

pub fn build() {
    println!("cargo:rerun-if-env-changed=CC");
    println!("cargo:rerun-if-env-changed=AR");
    println!("cargo:rerun-if-env-changed=STELA_ACPI_SANITIZE");
    println!("cargo:rerun-if-env-changed=MACOSX_DEPLOYMENT_TARGET");
    if env::var_os("CARGO_FEATURE_NATIVE_ACPI").is_none() {
        return;
    }
    let base = PathBuf::from("src/platform/acpi");
    for name in ["vendor", "bridge.c", "bridge.h", "libc.c"] {
        println!("cargo:rerun-if-changed={}", base.join(name).display());
    }
    let target = env::var("TARGET").unwrap();
    assert!(target.starts_with("x86_64-"), "native ACPI requires x86-64");
    let coff = target == "x86_64-unknown-uefi";
    let sanitize = env::var_os("STELA_ACPI_SANITIZE").is_some();
    assert!(!sanitize || !coff, "sanitizers are hosted test tools");
    let c_target = if coff {
        "x86_64-pc-windows-msvc"
    } else {
        &target
    };
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let compiler = env::var_os("CC").unwrap_or_else(|| "clang".into());
    let archiver = env::var_os("AR").unwrap_or_else(|| {
        let output = Command::new(env::var_os("RUSTC").unwrap())
            .args(["--print", "sysroot"])
            .output()
            .expect("find Rust toolchain archiver");
        assert!(output.status.success());
        PathBuf::from(String::from_utf8(output.stdout).unwrap().trim())
            .join("lib/rustlib")
            .join(env::var("HOST").unwrap())
            .join("bin/llvm-ar")
            .into_os_string()
    });
    let mut sources: Vec<_> = fs::read_dir(base.join("vendor/core"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "c"))
        .filter(|path| {
            let name = path.file_name().unwrap().to_str().unwrap();
            !name.starts_with("db") && name != "rsdump.c"
        })
        .collect();
    sources.sort();
    sources.push(base.join("bridge.c"));
    sources.push(base.join("libc.c"));
    let mut objects = Vec::new();
    for source in sources {
        let object = out
            .join(source.file_stem().unwrap())
            .with_extension(if coff { "obj" } else { "o" });
        let mut command = Command::new(&compiler);
        command
            .args([
                "-target",
                c_target,
                "-std=c11",
                "-O2",
                "-ffreestanding",
                "-fno-builtin",
                "-fno-strict-aliasing",
                "-fwrapv",
                "-fno-stack-protector",
                "-fno-asynchronous-unwind-tables",
                "-fno-unwind-tables",
                "-mno-red-zone",
                "-mno-sse",
                "-mno-sse2",
                "-mno-mmx",
                "-DSTELA_ACPI",
                "-DACPI_PCI_CONFIGURED",
                "-Werror=implicit-function-declaration",
            ])
            .arg("-I")
            .arg(base.join("vendor/include"))
            .arg("-I")
            .arg(base.join("vendor/core"))
            .arg("-I")
            .arg(&base);
        if target == "x86_64-apple-darwin" {
            command.arg(format!(
                "-mmacosx-version-min={}",
                env::var("MACOSX_DEPLOYMENT_TARGET").unwrap_or_else(|_| "10.12".into())
            ));
        }
        if sanitize {
            command.args([
                "-fsanitize=address,undefined",
                "-fno-sanitize-recover=all",
                "-fno-omit-frame-pointer",
            ]);
        }
        if coff {
            command.args(["-mno-stack-arg-probe", "-mno-incremental-linker-compatible"]);
        }
        command.arg("-c").arg(&source).arg("-o").arg(&object);
        run(&mut command);
        objects.push(object);
    }
    let archive = out.join("libstela_acpica.a");
    let _ = fs::remove_file(&archive);
    run(Command::new(archiver)
        .arg("crs")
        .arg(&archive)
        .args(&objects));
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=stela_acpica");
    if sanitize {
        // Rust links with -nodefaultlibs. Select this compiler's runtime explicitly
        // instead of accidentally mixing a different linker driver's sanitizer.
        let runtime = if target == "x86_64-apple-darwin" {
            let output = Command::new(&compiler)
                .arg("--print-resource-dir")
                .output()
                .unwrap();
            assert!(output.status.success());
            PathBuf::from(String::from_utf8(output.stdout).unwrap().trim())
                .join("lib/darwin/libclang_rt.asan_osx_dynamic.dylib")
        } else {
            let output = Command::new(&compiler)
                .arg("--print-file-name=libclang_rt.asan-x86_64.so")
                .output()
                .unwrap();
            assert!(output.status.success());
            PathBuf::from(String::from_utf8(output.stdout).unwrap().trim())
        };
        assert!(
            runtime.is_file(),
            "clang sanitizer runtime unavailable: {}",
            runtime.display()
        );
        println!("cargo:rustc-link-arg={}", runtime.display());
        println!(
            "cargo:rustc-link-arg=-Wl,-rpath,{}",
            runtime.parent().unwrap().display()
        );
    }
}
