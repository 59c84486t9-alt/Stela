//! Explicit hosted tests of the bounded nouveau parser/size helpers.
//! Preparation is fresh and source-bound; no complete driver is compiled here.
use std::{env, path::PathBuf};

#[cfg(feature = "linux-kernel")]
use super::native::{self, LINUX, Linux, Tests, check_declarations, run};
#[cfg(feature = "linux-kernel")]
use std::{
    process::{self, Command},
    time::{SystemTime, UNIX_EPOCH},
};
#[cfg(feature = "linux-kernel")]
use stela_c_build::linux::Module;
#[cfg(feature = "linux-kernel")]
use stela_c_build::native::hosted;

const SELECTOR: &str = "STELA_NOUVEAU_FIRMWARE_TESTS";
const BOOTLOADER: &str = "STELA_NOUVEAU_FIRMWARE_BOOTLOADER";

/// Validate even when Linux is disabled, before any other build preparation.
pub fn validate() {
    println!("cargo:rerun-if-env-changed={SELECTOR}");
    println!("cargo:rerun-if-env-changed={BOOTLOADER}");
    if request().is_some() {
        #[cfg(not(feature = "linux-kernel"))]
        panic!("{SELECTOR} requires the linux-kernel feature");
        #[cfg(feature = "linux-kernel")]
        assert_eq!(
            env::var("TARGET").expect("Cargo supplies TARGET"),
            env::var("HOST").expect("Cargo supplies HOST"),
            "{SELECTOR} requires TARGET=HOST; focused tests cannot run when cross-compiling"
        );
    }
}

fn request() -> Option<(bool, Option<PathBuf>)> {
    let bootloader = env::var_os(BOOTLOADER).map(PathBuf::from);
    let Some(selection) = env::var_os(SELECTOR) else {
        assert!(
            bootloader.is_none(),
            "{BOOTLOADER} requires {SELECTOR}=retained"
        );
        return None;
    };
    let retained = match selection.to_str() {
        Some("authored") => false,
        Some("retained") => true,
        _ => panic!("{SELECTOR} must be authored or retained, got {selection:?}"),
    };
    assert!(
        retained == bootloader.is_some(),
        "{BOOTLOADER} is required only with {SELECTOR}=retained"
    );
    if let Some(path) = &bootloader {
        assert!(
            !path.as_os_str().is_empty(),
            "{BOOTLOADER} must name an explicit input file"
        );
    }
    Some((retained, bootloader))
}

#[cfg(feature = "linux-kernel")]
pub fn tests(linux: &Linux, tests: &mut Tests) {
    let Some((retained, bootloader)) = request() else {
        return;
    };
    let mut build = hosted().expect("focused nouveau tests require TARGET=HOST");
    let manifest =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("Cargo supplies manifest"));
    let repository = manifest
        .join("../..")
        .canonicalize()
        .expect("locate repository");
    let source = manifest
        .join(LINUX)
        .canonicalize()
        .expect("locate actual Linux source");
    let generator = manifest.join("tests/reference/nouveau_firmware_bounds.py");
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("host clock precedes epoch")
        .as_nanos();
    let mode = if retained { "retained" } else { "authored" };
    let generated = repository
        .join(".stela/gpu/evidence")
        .join(format!("{stamp}-nouveau-firmware-{mode}-{}", process::id()));
    println!("cargo:rerun-if-env-changed=STELA_GPU_PYTHON");
    let python = env::var_os("STELA_GPU_PYTHON").unwrap_or_else(|| "python3".into());
    let mut prepare = Command::new(python);
    prepare
        .arg(&generator)
        .arg("--linux-source")
        .arg(&source)
        .arg("--patched-source")
        .arg(&source)
        .arg("--output")
        .arg(&generated)
        .env("PYTHONDONTWRITEBYTECODE", "1");
    if let Some(path) = bootloader {
        let path = path
            .canonicalize()
            .expect("locate explicitly selected nouveau bootloader");
        assert!(path.is_file(), "{BOOTLOADER} must name a file");
        println!("cargo:rerun-if-changed={}", path.display());
        prepare.arg("--bootloader").arg(path);
    }
    println!("cargo:rerun-if-changed={}", generator.display());
    for file in ["firmware.c", "firmware_retained.c"] {
        println!("cargo:rerun-if-changed=tests/reference/nouveau/{file}");
    }
    run(&mut prepare);
    for file in ["nouveau_firmware_helpers.inc", "source-receipt.json"] {
        println!("cargo:rerun-if-changed={}", generated.join(file).display());
    }
    linux.environment.apply(
        &mut build,
        Some(&generated),
        &native::drm_includes(&[
            "nouveau/include",
            "nouveau/include/nvkm",
            "nouveau/nvkm",
            "nouveau/nvkm/subdev/gsp",
            "nouveau",
        ]),
        Some(&Module {
            name: "nouveau",
            file: "drivers/gpu/drm/nouveau/nouveau",
        }),
    );
    let archives = linux
        .hosted
        .iter()
        .map(PathBuf::as_path)
        .collect::<Vec<_>>();
    let authored = "tests/reference/nouveau/firmware.c";
    check_declarations(&build, &[PathBuf::from(authored)]);
    tests.add(&build, "nouveau_firmware_authored", authored, &archives);
    if retained {
        println!(
            "cargo:rerun-if-changed={}",
            generated.join("nouveau_firmware_real_boot.inc").display()
        );
        let source = "tests/reference/nouveau/firmware_retained.c";
        check_declarations(&build, &[PathBuf::from(source)]);
        tests.add(&build, "nouveau_firmware_retained", source, &archives);
    }
}
