//! The ARM64e macOS components Stela installs in the guest, built with the
//! host's clang against xnu's open-source headers: no macOS SDK.
//!
//! The StelaGPU kext compiles to relocatable objects beside its
//! `Info.plist` in `target/guest/StelaGPU.kext`, whose final link is against
//! one boot kernel collection. The Metal plugin links here, into
//! `target/guest/StelaGPU.bundle`. No released `ld64.lld` links arm64e's
//! authenticated pointers, so `stela-loader` links both.
use crate::tools::{self, exec};
use anyhow::{Context, Result, ensure};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

pub mod sdk;
pub mod wire;

/// The macOS the guest components target, as clang's `-target` names it.
const TARGET: &str = "arm64e-apple-macos27.0";
/// What the Metal plugin's `Info.plist` and signature identify it as.
const BUNDLE_IDENTIFIER: &str = "com.stela.StelaGPU.Metal";
/// The Metal plugin's slices: Metal loads it into processes of either.
const BUNDLE_TARGETS: [(&str, &str); 2] = [("arm64", "arm64-apple-macos27.0"), ("arm64e", TARGET)];

/// Builds every guest component.
pub fn run() -> Result<()> {
    let root = tools::root();
    let xnu = root.join("third_party/xnu");
    let output = root.join("target/guest");
    let include = output.join("include");
    sdk::generate(&xnu, &include)?;
    wire::generate(&root.join("crates/stela-driver-gpu/src/metal"), &include)?;
    let component = root.join("guest/stela-gpu");
    let kext = build_kext(&component, &output, &xnu, &include)?;
    embed_kext(&kext, &output.join("StelaGPU.kext.rs"))?;
    println!("StelaGPU kext: {}", kext.display());
    let bundle = build_bundle(&component, &output, &include)?;
    println!("StelaGPU bundle: {}", bundle.display());
    Ok(())
}

/// Compiles each source of `<component>/bundle` once per slice, under
/// `<output>/StelaGPU.objects`, and links the slices into
/// `<output>/StelaGPU.bundle`.
fn build_bundle(component: &Path, output: &Path, include: &Path) -> Result<PathBuf> {
    let source = component.join("bundle");
    let objects = output.join("StelaGPU.objects");
    let bundle = output.join("StelaGPU.bundle");
    for directory in [&objects, &bundle] {
        if directory.exists() {
            fs::remove_dir_all(directory)?;
        }
    }
    let clang = tools::which("clang").context("install clang 21 or newer")?;
    let resources = Command::new(&clang).arg("-print-resource-dir").output()?;
    ensure!(
        resources.status.success(),
        "clang names no resource directory"
    );
    let resources = PathBuf::from(String::from_utf8(resources.stdout)?.trim());
    let mut sources = Vec::new();
    for entry in fs::read_dir(&source)? {
        let path = entry?.path();
        if path.extension().is_some_and(|extension| extension == "m") {
            sources.push(path);
        }
    }
    sources.sort();
    let mut slices = Vec::new();
    for (architecture, target) in BUNDLE_TARGETS {
        let directory = objects.join(architecture);
        fs::create_dir_all(&directory)?;
        let mut compiled = Vec::with_capacity(sources.len());
        for path in &sources {
            let object = directory
                .join(path.file_stem().unwrap())
                .with_extension("o");
            let mut command = Command::new(&clang);
            command
                .args(BUNDLE_FLAGS)
                .arg(format!("--target={target}"))
                .arg("-isystem")
                .arg(resources.join("include"))
                .arg("-I")
                .arg(&source)
                .arg("-I")
                .arg(component.join("include"))
                .arg("-I")
                .arg(include);
            exec(command.arg("-c").arg(path).arg("-o").arg(&object))?;
            compiled.push(fs::read(&object)?);
        }
        slices.push(compiled);
    }
    let slices: Vec<Vec<&[u8]>> = slices
        .iter()
        .map(|slice| slice.iter().map(Vec::as_slice).collect())
        .collect();
    let executable = stela_loader::plugin::link(BUNDLE_IDENTIFIER, &slices)?;
    let contents = bundle.join("Contents");
    fs::create_dir_all(contents.join("MacOS"))?;
    fs::copy(source.join("Info.plist"), contents.join("Info.plist"))?;
    fs::write(contents.join("MacOS/StelaGPU"), executable)?;
    Ok(bundle)
}

/// Objective-C against the bundle's own declarations of macOS: no SDK.
const BUNDLE_FLAGS: &[&str] = &[
    "-xobjective-c",
    "-std=gnu17",
    "-O2",
    "-Wall",
    "-Wextra",
    "-Werror",
    "-Wno-unused-parameter",
    "-Wno-objc-protocol-method-implementation",
    "-fobjc-arc",
    "-fblocks",
    "-fobjc-runtime=macosx-27.0",
    "-fno-common",
    "-fno-unwind-tables",
    "-fno-asynchronous-unwind-tables",
    "-nostdinc",
];

/// Compiles each source of `<component>/kext` into `<output>/StelaGPU.kext`
/// beside its `Info.plist`.
fn build_kext(component: &Path, output: &Path, xnu: &Path, include: &Path) -> Result<PathBuf> {
    let source = component.join("kext");
    let bundle = output.join("StelaGPU.kext");
    if bundle.exists() {
        fs::remove_dir_all(&bundle)?;
    }
    fs::create_dir_all(&bundle)?;
    let info = fs::read_to_string(source.join("Info.plist"))?;
    let (identifier, version) = identity(&info)?;
    fs::write(bundle.join("Info.plist"), &info)?;
    let clang = tools::which("clang++").context("install clang 21 or newer")?;
    for entry in fs::read_dir(&source)? {
        let path = entry?.path();
        if path.extension().is_none_or(|extension| extension != "cpp") {
            continue;
        }
        let object = bundle.join(path.file_stem().unwrap()).with_extension("o");
        let mut command = Command::new(&clang);
        command
            .args(KEXT_FLAGS)
            .arg(format!("--target={TARGET}"))
            .arg(format!("-DSTELA_KEXT_IDENTIFIER=\"{identifier}\""))
            .arg(format!("-DSTELA_KEXT_VERSION=\"{version}\""))
            .arg("-I")
            .arg(component.join("include"));
        for headers in XNU_HEADERS {
            command.arg("-isystem").arg(xnu.join(headers));
        }
        command.arg("-isystem").arg(include);
        exec(command.arg("-c").arg(&path).arg("-o").arg(&object))?;
    }
    Ok(bundle)
}

/// Writes the Rust `stela.efi` includes for `kext`'s `INFO` and `OBJECTS`, as
/// it links them against each boot's own kernel.
fn embed_kext(kext: &Path, source: &Path) -> Result<()> {
    let mut objects: Vec<_> = fs::read_dir(kext)?
        .map(|entry| Ok(entry?.path()))
        .collect::<Result<_>>()?;
    objects.retain(|path| path.extension().is_some_and(|extension| extension == "o"));
    objects.sort();
    let includes: String = objects
        .iter()
        .map(|path| format!("    include_bytes!({:?}),\n", path.display().to_string()))
        .collect();
    let info = kext.join("Info.plist");
    fs::write(
        source,
        format!(
            "pub static INFO: &[u8] = include_bytes!({:?});\n\
             pub static OBJECTS: &[&[u8]] = &[\n{includes}];\n",
            info.display().to_string()
        ),
    )?;
    Ok(())
}

/// A kext's code generation: Apple clang's `-mkernel` set, which upstream
/// clang leaves to the build, and Apple clang's name for its
/// pointer-authentication intrinsics, which xnu's `ptrauth.h` tests.
const KEXT_FLAGS: &[&str] = &[
    "-std=gnu++20",
    "-O2",
    "-Wall",
    "-Wextra",
    "-Werror",
    "-mkernel",
    "-fapple-kext",
    "-fno-rtti",
    "-fno-exceptions",
    "-fno-builtin",
    "-fno-common",
    "-fno-stack-protector",
    "-nostdinc",
    "-nostdinc++",
    "-DKERNEL",
    "-D__PTRAUTH_INTRINSICS__=1",
];

/// xnu's header roots, in the precedence the kernel SDK's flat tree has.
const XNU_HEADERS: [&str; 6] = [
    "EXTERNAL_HEADERS",
    "bsd",
    "osfmk",
    "iokit",
    "libkern",
    "pexpert",
];

/// The `CFBundleIdentifier` and `CFBundleVersion` of an `Info.plist`, which
/// the kext's `kmod_info` repeats.
fn identity(info: &str) -> Result<(String, String)> {
    let plist: plist::Value = plist::from_bytes(info.as_bytes())?;
    let dictionary = plist
        .as_dictionary()
        .context("Info.plist is not a dictionary")?;
    let [identifier, version] = ["CFBundleIdentifier", "CFBundleVersion"].map(|key| {
        let value = dictionary
            .get(key)
            .and_then(plist::Value::as_string)
            .with_context(|| format!("Info.plist has no {key}"))?;
        ensure!(
            value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b".-".contains(&byte)),
            "{key} {value:?} is not a kext's"
        );
        Ok(value.to_owned())
    });
    Ok((identifier?, version?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_identity_comes_from_the_info_plist() {
        let info = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.stela.Test</string>
<key>CFBundleVersion</key><string>1.2.3</string>
</dict></plist>"#;
        let identity = identity(info).unwrap();
        assert_eq!(identity, ("com.stela.Test".into(), "1.2.3".into()));
        assert!(super::identity(&info.replace("1.2.3", "1\"2")).is_err());
    }
}
