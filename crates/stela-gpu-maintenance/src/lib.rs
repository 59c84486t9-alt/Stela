//! GPU maintenance payload validation, shared by its producer and installer.
use anyhow::{Context, Result, ensure};
use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Component, Path, PathBuf},
};
use stela_loader::aux_kc::Kext;

#[cfg(any(target_os = "macos", test))]
mod executable;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(any(target_os = "macos", test))]
mod policy;
#[cfg(any(target_os = "macos", all(test, unix)))]
mod publication;

pub const MANIFEST: &str = "gpu-install.json";
pub const KEXT: &str = "StelaGPU.kext";
pub const PLUGIN: &str = "StelaGPU.bundle";
pub const BUNDLE_PATH: &str = "/Library/Extensions/StelaGPU.kext";

#[derive(Parser)]
#[command(
    name = "stela-gpu-maintenance",
    version,
    about = "Install GPU components from macOS maintenance",
    arg_required_else_help = true
)]
pub struct Gpu {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Validate an installation payload without changing a disk.
    Check { payload: PathBuf },
    /// Run as root in macOS maintenance; uses macOS's APFS and trust APIs.
    Install(Install),
}

#[derive(Args)]
struct Install {
    /// The complete target/guest directory from cargo xtask guest.
    #[arg(long)]
    payload: PathBuf,
    /// Mounted writable Data volume of the system being installed.
    #[arg(long)]
    data_volume: PathBuf,
    /// Mounted Preboot volume, containing the volume group's directory.
    #[arg(long)]
    preboot: PathBuf,
    #[arg(long, value_parser = parse_uuid)]
    volume_group: [u8; 16],
    /// The installed system's next-stage IM4M under this Preboot group.
    #[arg(long)]
    manifest: PathBuf,
    /// The installed system's splat manifest, when present.
    #[arg(long)]
    splat: Option<PathBuf>,
    /// Apple's native linker, required for the on-disk arm64e kext.
    #[arg(long, default_value = "/usr/bin/ld")]
    linker: PathBuf,
}

impl Gpu {
    pub fn run(self) -> Result<()> {
        match self.command {
            Command::Check { payload } => {
                let manifest = Payload::load(&payload)?;
                println!(
                    "GPU payload verified: {} files, kext UUID {}",
                    manifest.files.len(),
                    manifest.kext_uuid
                );
                Ok(())
            }
            Command::Install(options) => {
                #[cfg(target_os = "macos")]
                {
                    macos::install(options)
                }
                #[cfg(not(target_os = "macos"))]
                {
                    let _ = options;
                    anyhow::bail!(
                        "GPU installation requires a macOS maintenance boot; build and payload checking work on this host"
                    )
                }
            }
        }
    }
}

fn parse_uuid(text: &str) -> Result<[u8; 16], String> {
    let bytes = text.as_bytes();
    if bytes.len() != 36 || [8, 13, 18, 23].iter().any(|&at| bytes[at] != b'-') {
        return Err("expected a hyphenated volume-group UUID".into());
    }
    let digits: String = text.chars().filter(|&ch| ch != '-').collect();
    let mut uuid = [0; 16];
    hex::decode_to_slice(digits, &mut uuid).map_err(|error| error.to_string())?;
    if uuid == [0; 16] {
        return Err("volume-group UUID is zero".into());
    }
    Ok(uuid)
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Payload {
    format: u32,
    pub kext_uuid: String,
    /// Each relative regular file and its SHA-256, in bytewise path order.
    pub files: BTreeMap<String, String>,
}

impl Payload {
    /// Seal only the two installable components. Build intermediates stay out.
    pub fn write(root: &Path) -> Result<()> {
        let files = inventory(root)?;
        let mut payload = Self {
            format: 1,
            kext_uuid: String::new(),
            files,
        };
        payload.kext_uuid = hex::encode(payload.source_uuid(root)?);
        fs::write(root.join(MANIFEST), serde_json::to_vec_pretty(&payload)?)?;
        Ok(())
    }

    pub fn load(root: &Path) -> Result<Self> {
        let payload: Self = serde_json::from_slice(&fs::read(root.join(MANIFEST))?)?;
        ensure!(
            payload.format == 1,
            "unsupported GPU payload format {}",
            payload.format
        );
        for (path, hash) in &payload.files {
            ensure!(
                safe_relative(path) && hash.len() == 64 && hex::decode(hash).is_ok(),
                "invalid GPU payload entry {path}"
            );
        }
        ensure!(
            payload.files == inventory(root)?,
            "GPU payload file inventory or SHA-256 differs from its manifest"
        );
        ensure!(
            payload.kext_uuid == hex::encode(payload.source_uuid(root)?),
            "GPU payload source UUID differs from its kext objects"
        );
        let executable = fs::read(root.join(PLUGIN).join("Contents/MacOS/StelaGPU"))?;
        let mut actual = stela_loader::plugin::code_hashes(&executable)?;
        let mut listed = stela_loader::trust_cache::code_hashes(&fs::read(
            root.join(KEXT)
                .join(stela_loader::aux_kc::TRUSTED_CODE_FILE),
        )?)?;
        actual.sort_unstable();
        listed.sort_unstable();
        ensure!(
            actual == listed,
            "GPU payload code hashes differ from its Metal executable"
        );
        Ok(payload)
    }

    pub fn source_uuid(&self, root: &Path) -> Result<[u8; 16]> {
        let info = fs::read(root.join(KEXT).join("Info.plist"))?;
        let objects = self
            .files
            .keys()
            .filter(|name| name.starts_with(&format!("{KEXT}/")) && name.ends_with(".o"))
            .map(|name| fs::read(root.join(name)))
            .collect::<std::io::Result<Vec<_>>>()?;
        ensure!(!objects.is_empty(), "GPU payload has no kext objects");
        let properties = plist::Value::from_reader_xml(&info[..])?;
        ensure!(
            properties
                .as_dictionary()
                .and_then(|dict| dict.get("CFBundleIdentifier"))
                .and_then(plist::Value::as_string)
                == Some("com.stela.StelaGPU"),
            "GPU payload has another kext identifier"
        );
        Ok(Kext {
            info: &info,
            objects: objects.iter().map(Vec::as_slice).collect(),
            bundle_path: BUNDLE_PATH.into(),
            trusted_code: vec![],
        }
        .uuid())
    }
}

fn safe_relative(path: &str) -> bool {
    !path.contains(['\\', ':'])
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
        && Path::new(path)
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
}

fn inventory(root: &Path) -> Result<BTreeMap<String, String>> {
    fn walk(root: &Path, relative: &Path, files: &mut BTreeMap<String, String>) -> Result<()> {
        let path = root.join(relative);
        let metadata =
            fs::symlink_metadata(&path).with_context(|| format!("reading {}", path.display()))?;
        ensure!(
            !metadata.file_type().is_symlink(),
            "GPU payload contains a symlink: {}",
            path.display()
        );
        if metadata.is_dir() {
            for child in fs::read_dir(&path)? {
                walk(root, &relative.join(child?.file_name()), files)?;
            }
        } else {
            ensure!(
                metadata.is_file() && metadata.len() <= 512 * 1024 * 1024,
                "GPU payload is not a bounded regular file: {}",
                path.display()
            );
            let name = relative
                .to_str()
                .context("GPU payload path is not UTF-8")?
                .replace('\\', "/");
            ensure!(safe_relative(&name), "invalid GPU payload path {name}");
            files.insert(name, stela_formats::sha256(&fs::read(&path)?));
        }
        Ok(())
    }
    let mut files = BTreeMap::new();
    for component in [KEXT, PLUGIN] {
        walk(root, Path::new(component), &mut files)?;
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_and_volume_groups_cannot_escape_the_target() {
        for path in ["/a", "../a", "a/../b", "a\\b", "C:/a", "a//b", "a/./b"] {
            assert!(!safe_relative(path), "{path}");
        }
        assert!(safe_relative("StelaGPU.bundle/Contents/MacOS/StelaGPU"));
        assert_eq!(
            parse_uuid("ABCDEF01-2345-6789-ABCD-EF0123456789").unwrap()[0],
            0xab
        );
        assert!(parse_uuid("00000000-0000-0000-0000-000000000000").is_err());
        assert!(parse_uuid("ABCDEF0123456789ABCDEF0123456789").is_err());
    }

    #[test]
    fn maintenance_command_requires_explicit_target_mounts_and_group() {
        use clap::Parser;
        assert!(
            Gpu::try_parse_from([
                "stela-gpu-maintenance",
                "install",
                "--payload",
                "guest",
                "--data-volume",
                "/Volumes/Data",
                "--preboot",
                "/Volumes/Preboot",
                "--volume-group",
                "ABCDEF01-2345-6789-ABCD-EF0123456789",
                "--manifest",
                "/Volumes/Preboot/group/boot/apticket.im4m",
            ])
            .is_ok()
        );
        assert!(
            Gpu::try_parse_from(["stela-gpu-maintenance", "install", "--payload", "guest"])
                .is_err()
        );
    }

    #[test]
    fn inventory_detects_modified_and_extra_files() -> Result<()> {
        let root = tempfile::tempdir()?;
        for directory in [KEXT, PLUGIN] {
            fs::create_dir(root.path().join(directory))?;
        }
        let path = root.path().join(KEXT).join("unit.o");
        fs::write(&path, b"first")?;
        let before = inventory(root.path())?;
        fs::write(&path, b"other")?;
        assert_ne!(before, inventory(root.path())?);
        fs::write(root.path().join(PLUGIN).join("extra"), b"extra")?;
        assert_eq!(inventory(root.path())?.len(), 2);
        Ok(())
    }

    #[test]
    #[cfg(unix)]
    fn payload_symlinks_are_refused_before_following_their_targets() -> Result<()> {
        let root = tempfile::tempdir()?;
        fs::create_dir(root.path().join(KEXT))?;
        fs::create_dir(root.path().join(PLUGIN))?;
        std::os::unix::fs::symlink("/etc/passwd", root.path().join(KEXT).join("outside"))?;
        assert!(
            inventory(root.path())
                .unwrap_err()
                .to_string()
                .contains("symlink")
        );
        Ok(())
    }
}
