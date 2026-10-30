//! The ARM64e macOS components Stela installs in the guest, built with the
//! host's clang against xnu's open-source headers: no macOS SDK.
//!
//! The StelaGPU kext compiles to relocatable objects beside its
//! `Info.plist` in `target/guest/StelaGPU.kext`. No released `ld64.lld`
//! links arm64e's authenticated pointers, and a kext's final link is
//! against one boot kernel collection anyway, so `stela-loader`'s auxiliary
//! collection linker takes the objects from there.
use crate::tools::{self, exec};
use anyhow::{Context, Result, ensure};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

pub mod sdk;

/// The macOS the guest components target, as clang's `-target` names it.
const TARGET: &str = "arm64e-apple-macos27.0";

/// Builds every guest component.
pub fn run() -> Result<()> {
    let root = tools::root();
    let xnu = root.join("third_party/xnu");
    let output = root.join("target/guest");
    let include = output.join("include");
    sdk::generate(&xnu, &include)?;
    let component = root.join("guest/stela-gpu");
    let kext = build_kext(&component, &output, &xnu, &include)?;
    println!("StelaGPU kext: {}", kext.display());
    Ok(())
}

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
