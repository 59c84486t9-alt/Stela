//! One launcher bundle: the original app's name, icon, document and URL
//! types around `stela-launcher`, which runs the original under `stela run`.
//! It is built beside its place, signed ad hoc, renamed into place and
//! registered with LaunchServices. Its `Info.plist` carries the
//! `StelaLauncher` marker that every later change and removal checks.
use super::Environment;
use crate::bundle::AppBundle;
use crate::restore::payload::file_sha256;
use anyhow::{Context, Result, ensure};
use plist::{Dictionary, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The `Info.plist` key that marks a launcher, and its fields.
const MARKER: &str = "StelaLauncher";
const MARKER_TARGET: &str = "Target";
const MARKER_STELA: &str = "Stela";
const MARKER_VERSION: &str = "Version";
/// The launcher layout's version; a change rebuilds every launcher.
const LAUNCHER_VERSION: u64 = 1;
/// The launchers' bundle identifiers: this prefix and the original's.
const IDENTIFIER_PREFIX: &str = "local.stela.launcher.";
/// Keys copied from the original's `Info.plist` unchanged.
const COPIED_KEYS: [&str; 9] = [
    "CFBundleName",
    "CFBundleDisplayName",
    "CFBundleShortVersionString",
    "CFBundleVersion",
    "CFBundleDevelopmentRegion",
    "CFBundleURLTypes",
    "NSHumanReadableCopyright",
    "LSApplicationCategoryType",
    "NSHighResolutionCapable",
];
const ICON_FILE: &str = "CFBundleIconFile";
const ICON_NAME: &str = "CFBundleIconName";
const DOCUMENT_TYPES: &str = "CFBundleDocumentTypes";
/// The asset catalog an icon name refers to.
const ASSET_CATALOG: &str = "Assets.car";
/// LaunchServices' rank for an app that opens a type but never claims it.
const ALTERNATE: &str = "Alternate";
const CODESIGN: &str = "/usr/bin/codesign";
const LSREGISTER: &str = "/System/Library/Frameworks/CoreServices.framework/Versions/A/\
                          Frameworks/LaunchServices.framework/Versions/A/Support/lsregister";

/// The launcher program's SHA-256; it must exist.
pub(super) fn program_digest(environment: &Environment) -> Result<String> {
    let program = &environment.launcher_program;
    ensure!(
        program.is_file(),
        "{} is missing beside stela; build it with `cargo build --release -p stela-cli`",
        program.display()
    );
    Ok(file_sha256(program)?.1)
}

/// What a launcher for `bundle` is made from.
pub(super) fn fingerprint(
    environment: &Environment,
    bundle: &AppBundle,
    program_digest: &str,
) -> Result<String> {
    let mut hash = Sha256::new();
    hash.update(LAUNCHER_VERSION.to_le_bytes());
    hash.update(fs::read(bundle.info_path())?);
    hash.update(environment.stela.as_os_str().as_encoded_bytes());
    hash.update([0]);
    hash.update(program_digest.as_bytes());
    Ok(hex::encode(hash.finalize()))
}

/// `identifier` with only the characters a bundle identifier may hold.
fn identifier(bundle: &AppBundle) -> String {
    let original = bundle
        .identifier()
        .map(str::to_owned)
        .unwrap_or_else(|| bundle.name());
    let clean: String = original
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    format!("{IDENTIFIER_PREFIX}{clean}")
}

/// The original's icon file in its resources, as `CFBundleIconFile` names
/// it with or without its extension.
fn icon_file(bundle: &AppBundle) -> Option<PathBuf> {
    let name = bundle.string(ICON_FILE)?;
    let resources = bundle.path.join("Contents/Resources");
    [resources.join(name), resources.join(format!("{name}.icns"))]
        .into_iter()
        .find(|path| path.is_file() && path.parent() == Some(resources.as_path()))
}

/// The launcher's `Info.plist`.
fn info(environment: &Environment, bundle: &AppBundle, executable: &str) -> Dictionary {
    let mut info = Dictionary::new();
    for key in COPIED_KEYS {
        if let Some(value) = bundle.info.get(key) {
            info.insert(key.into(), value.clone());
        }
    }
    if let Some(icon) = icon_file(bundle) {
        let name = icon.file_name().unwrap().to_string_lossy().into_owned();
        info.insert(ICON_FILE.into(), name.into());
    }
    if let Some(name) = bundle.string(ICON_NAME)
        && bundle
            .path
            .join("Contents/Resources")
            .join(ASSET_CATALOG)
            .is_file()
    {
        info.insert(ICON_NAME.into(), name.into());
    }
    if let Some(types) = bundle.info.get(DOCUMENT_TYPES).and_then(Value::as_array) {
        let types = types
            .iter()
            .filter_map(Value::as_dictionary)
            .map(|kind| {
                let mut kind = kind.clone();
                kind.insert("LSHandlerRank".into(), ALTERNATE.into());
                kind.remove("CFBundleTypeIconFile");
                kind.remove("NSDocumentClass");
                Value::Dictionary(kind)
            })
            .collect();
        info.insert(DOCUMENT_TYPES.into(), Value::Array(types));
    }
    for (key, value) in [
        ("CFBundleExecutable", executable),
        ("CFBundleIdentifier", &identifier(bundle)),
        ("CFBundlePackageType", "APPL"),
        ("CFBundleInfoDictionaryVersion", "6.0"),
        ("NSPrincipalClass", "NSApplication"),
    ] {
        info.insert(key.into(), value.into());
    }
    if !info.contains_key("CFBundleName") {
        info.insert("CFBundleName".into(), bundle.name().into());
    }
    let mut marker = Dictionary::new();
    marker.insert(
        MARKER_TARGET.into(),
        bundle.path.to_string_lossy().into_owned().into(),
    );
    marker.insert(
        MARKER_STELA.into(),
        environment.stela.to_string_lossy().into_owned().into(),
    );
    marker.insert(
        MARKER_VERSION.into(),
        Value::Integer(LAUNCHER_VERSION.into()),
    );
    info.insert(MARKER.into(), Value::Dictionary(marker));
    info
}

/// The `StelaLauncher` marker of the bundle at `path`.
fn marker(path: &Path) -> Option<Dictionary> {
    Value::from_file(path.join("Contents/Info.plist"))
        .ok()?
        .into_dictionary()?
        .remove(MARKER)?
        .into_dictionary()
}

/// Whether `path` is Stela's launcher for `target`.
pub(super) fn is_ours(path: &Path, target: &Path) -> bool {
    marker(path).is_some_and(|marker| {
        marker.get(MARKER_TARGET).and_then(Value::as_string) == target.to_str()
    })
}

/// Build the launcher for `bundle` at `path`, replacing an earlier
/// launcher of Stela's there.
pub(super) fn create(environment: &Environment, bundle: &AppBundle, path: &Path) -> Result<()> {
    ensure!(
        !path.exists() || marker(path).is_some(),
        "{} is not Stela's launcher",
        path.display()
    );
    let folder = path.parent().context("launcher has no folder")?;
    fs::create_dir_all(folder)?;
    let name = path.file_name().context("launcher has no name")?;
    let staging = folder.join(format!(".{}.partial", name.to_string_lossy()));
    if staging.exists() {
        fs::remove_dir_all(&staging)?;
    }
    if let Err(error) = build(environment, bundle, &staging) {
        let _ = fs::remove_dir_all(&staging);
        return Err(error);
    }
    if path.exists() {
        fs::remove_dir_all(path)?;
    }
    fs::rename(&staging, path)?;
    if environment.register {
        run(Command::new(LSREGISTER).arg("-f").arg(path))
            .context("cannot register the launcher with LaunchServices")?;
    }
    Ok(())
}

/// The launcher's files at `staging`, signed.
fn build(environment: &Environment, bundle: &AppBundle, staging: &Path) -> Result<()> {
    let contents = staging.join("Contents");
    let executables = contents.join("MacOS");
    let resources = contents.join("Resources");
    fs::create_dir_all(&executables)?;
    fs::create_dir_all(&resources)?;
    let original = bundle.executable()?;
    let executable = original
        .file_name()
        .context("the app's executable has no name")?
        .to_string_lossy()
        .into_owned();
    let program = executables.join(&executable);
    fs::copy(&environment.launcher_program, &program)
        .with_context(|| format!("cannot copy {}", environment.launcher_program.display()))?;
    fs::set_permissions(&program, fs::Permissions::from_mode(0o755))?;
    if let Some(icon) = icon_file(bundle) {
        fs::copy(&icon, resources.join(icon.file_name().unwrap()))?;
    }
    let catalog = bundle.path.join("Contents/Resources").join(ASSET_CATALOG);
    if bundle.string(ICON_NAME).is_some() && catalog.is_file() {
        fs::copy(&catalog, resources.join(ASSET_CATALOG))?;
    }
    Value::Dictionary(info(environment, bundle, &executable))
        .to_file_xml(contents.join("Info.plist"))?;
    fs::write(contents.join("PkgInfo"), b"APPL????")?;
    run(Command::new(CODESIGN)
        .args(["--force", "--sign", "-", "--timestamp=none"])
        .arg(staging))
    .context("cannot sign the launcher ad hoc")
}

/// Remove Stela's launcher at `path` and its LaunchServices registration.
pub(super) fn remove(environment: &Environment, path: &Path) -> Result<()> {
    ensure!(
        marker(path).is_some(),
        "{} is not Stela's launcher",
        path.display()
    );
    if environment.register {
        // A launcher LaunchServices never registered has nothing to undo.
        let _ = run(Command::new(LSREGISTER).arg("-u").arg(path));
    }
    fs::remove_dir_all(path).with_context(|| format!("cannot remove {}", path.display()))
}

/// Run a host tool, failing with its standard error.
fn run(command: &mut Command) -> Result<()> {
    let output = command
        .output()
        .with_context(|| format!("cannot run {:?}", command.get_program()))?;
    ensure!(
        output.status.success(),
        "{:?} failed: {}",
        command.get_program(),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::tests::{ARM64, app, environment};
    use super::*;

    #[test]
    fn a_launcher_carries_the_app_s_name_icon_and_types_and_is_signed() -> Result<()> {
        let work = tempfile::tempdir()?;
        let original = app(work.path(), "Arm", ARM64)?;
        let before = fs::read(original.join("Contents/Info.plist"))?;
        let environment = environment(work.path());
        let bundle = AppBundle::open(&original)?;
        let path = environment.launchers.join("Arm.app");
        create(&environment, &bundle, &path)?;
        assert!(is_ours(&path, &original));
        assert!(!is_ours(&path, &work.path().join("Other.app")));
        let launcher = AppBundle::open(&path)?;
        assert_eq!(
            launcher.identifier(),
            Some("local.stela.launcher.com.example.Arm")
        );
        assert_eq!(launcher.string("CFBundleName"), Some("Arm"));
        assert_eq!(launcher.string(ICON_FILE), Some("AppIcon.icns"));
        assert_eq!(
            fs::read(path.join("Contents/Resources/AppIcon.icns"))?,
            b"icns"
        );
        let types = launcher.info[DOCUMENT_TYPES].as_array().unwrap();
        let rank = types[0].as_dictionary().unwrap()["LSHandlerRank"].as_string();
        assert_eq!(rank, Some(ALTERNATE));
        let marker = marker(&path).unwrap();
        assert_eq!(
            marker[MARKER_STELA].as_string(),
            Some("/usr/local/bin/stela")
        );
        assert_eq!(launcher.executable()?, path.join("Contents/MacOS/Arm"));
        let verified = Command::new(CODESIGN)
            .args(["--verify", "--strict"])
            .arg(&path)
            .status()?;
        assert!(verified.success(), "the launcher verifies as signed");
        assert_eq!(
            fs::read(original.join("Contents/Info.plist"))?,
            before,
            "the original is only read"
        );
        // Rebuilding replaces it in place; removal checks the marker.
        create(&environment, &bundle, &path)?;
        remove(&environment, &path)?;
        assert!(!path.exists());
        fs::create_dir_all(path.join("Contents"))?;
        assert!(remove(&environment, &path).is_err());
        // Nor is a launcher built over a bundle that is not Stela's, and
        // nothing is left beside it.
        assert!(create(&environment, &bundle, &path).is_err());
        let left: Vec<_> = fs::read_dir(&environment.launchers)?.collect();
        assert_eq!(left.len(), 1, "{left:?}");
        Ok(())
    }

    #[test]
    fn identifiers_keep_only_bundle_identifier_characters() -> Result<()> {
        let work = tempfile::tempdir()?;
        let original = app(work.path(), "Arm", ARM64)?;
        let mut bundle = AppBundle::open(&original)?;
        bundle
            .info
            .insert("CFBundleIdentifier".into(), "com.example/odd id".into());
        assert_eq!(
            identifier(&bundle),
            "local.stela.launcher.com.example-odd-id"
        );
        Ok(())
    }
}
