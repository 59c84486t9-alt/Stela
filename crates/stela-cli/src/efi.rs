//! Add the UEFI mount to an existing OpenCore EFI as one boot picker entry.
//!
//! `install` copies `stela.efi` to `EFI/OC/Tools/Stela.efi`, writes the
//! mount's `EFI/stela/stela.cfg` and `EFI/stela/source.bin`, and adds one
//! `Misc.Tools` entry to `EFI/OC/config.plist`. The configuration from before
//! the first install is kept as `EFI/stela/config.plist.backup`; a reinstall
//! leaves that backup alone. Every other key keeps its value
//! and order; only the XML layout is rewritten. `uninstall` removes the entry
//! and those files.
//!
//! With `--ipsw`, `install` also writes a restore payload for `stela.efi`
//! under `EFI/stela/images/<build>/` on the ESP or another volume of the
//! same USB: FAT32-safe slices of the model's members, or the whole IPSW,
//! and `payload.json` with every member's SHA-256 and the public AEA key
//! responses. `uninstall` leaves payloads alone.
pub use crate::restore::payload::{
    PayloadLayout, SYNTHETIC_BUILD, SYNTHETIC_MODEL, WriteOptions as PayloadOptions,
    synthetic_ipsw, write as write_payload,
};
use anyhow::{Context, Result, bail, ensure};
use clap::{Args, Subcommand};
use plist::{Dictionary, Value};
use serde_json::json;
use std::{
    fs,
    io::{Cursor, Write},
    path::{Path, PathBuf},
};
use stela_runtime::payload::MAX_SLICE_BYTES;

/// The tool's file name under `EFI/OC/Tools`, which identifies the entry.
pub const TOOL: &str = "Stela.efi";
/// The picker label.
pub const NAME: &str = "macOS (Stela)";
const CONFIG: &str = "EFI/OC/config.plist";
const TOOLS: &str = "EFI/OC/Tools";
const MOUNT: &str = "EFI/stela";
const OPTIONS: &str = "EFI/stela/stela.cfg";
const SOURCE: &str = "EFI/stela/source.bin";
const BACKUP: &str = "EFI/stela/config.plist.backup";

#[derive(Subcommand)]
pub(crate) enum EfiCommand {
    /// Add `stela.efi` to an OpenCore EFI as the "macOS (Stela)" tool entry.
    Install(Install),
    /// Remove everything `install` added.
    Uninstall(Uninstall),
}

impl EfiCommand {
    pub(crate) fn run(self) -> Result<()> {
        let report = match self {
            Self::Install(command) => install(&command)?,
            Self::Uninstall(command) => uninstall(&command.esp)?,
        };
        println!("{report:#}");
        Ok(())
    }
}

#[derive(Args)]
pub struct Install {
    /// The EFI system partition root, which holds `EFI/OC/config.plist`.
    #[arg(long)]
    pub esp: PathBuf,
    /// The mount application, `stela.efi`.
    #[arg(long)]
    pub image: PathBuf,
    /// Original ARM bytes; omit to keep the installed `source.bin`.
    #[arg(long)]
    pub source: Option<PathBuf>,
    /// Mount options for `stela.cfg`; omit to keep the installed file.
    #[arg(long, allow_hyphen_values = true)]
    pub options: Option<String>,
    /// Write this IPSW's restore payload as well.
    #[arg(long)]
    pub ipsw: Option<PathBuf>,
    /// The Mac model whose identities the payload carries.
    #[arg(long, default_value = "Mac14,3", requires = "ipsw")]
    pub model: String,
    /// The volume root for the payload; defaults to `--esp`.
    #[arg(long, requires = "ipsw")]
    pub payload_root: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = PayloadLayout::Split, requires = "ipsw")]
    pub payload_layout: PayloadLayout,
    /// Largest slice of a split payload; FAT32 allows 4 GiB - 1.
    #[arg(long, default_value_t = MAX_SLICE_BYTES, hide = true)]
    pub slice_bytes: u64,
    /// Leave out the public AEA keys; the restore then needs the network.
    #[arg(long, requires = "ipsw")]
    pub no_aea_keys: bool,
}

#[derive(Args)]
pub(crate) struct Uninstall {
    /// The EFI system partition root, which holds `EFI/OC/config.plist`.
    #[arg(long)]
    esp: PathBuf,
}

/// The `Misc.Tools` entry. OpenCore starts a tool from a memory buffer
/// unless `RealPath` is set, and the mount then has no boot volume to read.
fn entry() -> Value {
    let mut entry = Dictionary::new();
    entry.insert("Arguments".into(), "".into());
    entry.insert("Auxiliary".into(), false.into());
    entry.insert("Comment".into(), "Stela ARM macOS mount".into());
    entry.insert("Enabled".into(), true.into());
    entry.insert("Flavour".into(), "Auto".into());
    entry.insert("FullNvramAccess".into(), false.into());
    entry.insert("Name".into(), NAME.into());
    entry.insert("Path".into(), TOOL.into());
    entry.insert("RealPath".into(), true.into());
    entry.insert("TextMode".into(), false.into());
    entry.into()
}

fn is_stela(entry: &Value) -> bool {
    entry
        .as_dictionary()
        .and_then(|entry| entry.get("Path"))
        .and_then(Value::as_string)
        .is_some_and(|path| path.eq_ignore_ascii_case(TOOL))
}

/// A parsed `config.plist` with its original bytes.
struct Config {
    path: PathBuf,
    bytes: Vec<u8>,
    root: Value,
}

impl Config {
    fn read(esp: &Path) -> Result<Self> {
        let path = esp.join(CONFIG);
        let bytes = fs::read(&path).with_context(|| format!("cannot read {}", path.display()))?;
        let root = Value::from_reader(Cursor::new(&bytes))
            .with_context(|| format!("{} is not a property list", path.display()))?;
        let config = Self { path, bytes, root };
        // A vault signs config.plist; an edit would stop OpenCore booting.
        let vault = config
            .misc()?
            .get("Security")
            .and_then(Value::as_dictionary)
            .and_then(|security| security.get("Vault"))
            .and_then(Value::as_string)
            .unwrap_or("Optional");
        ensure!(
            vault == "Optional",
            "Misc.Security.Vault is {vault}; changing config.plist would break the vault, so \
             set Vault to Optional or regenerate the vault after installing"
        );
        Ok(config)
    }

    fn misc(&self) -> Result<&Dictionary> {
        self.root
            .as_dictionary()
            .and_then(|root| root.get("Misc"))
            .and_then(Value::as_dictionary)
            .with_context(|| format!("{} has no Misc dictionary", self.path.display()))
    }

    fn tools(&mut self) -> Result<&mut Vec<Value>> {
        let path = &self.path;
        self.root
            .as_dictionary_mut()
            .and_then(|root| root.get_mut("Misc"))
            .and_then(Value::as_dictionary_mut)
            .and_then(|misc| misc.get_mut("Tools"))
            .and_then(Value::as_array_mut)
            .with_context(|| format!("{} has no Misc.Tools array", path.display()))
    }

    /// Remove every Stela entry; return how many there were and where the
    /// first one was.
    fn remove_stela(&mut self) -> Result<(usize, Option<usize>)> {
        let tools = self.tools()?;
        let first = tools.iter().position(is_stela);
        let before = tools.len();
        tools.retain(|entry| !is_stela(entry));
        Ok((before - tools.len(), first))
    }

    /// Replace the file through a sibling temporary, so a failed write leaves
    /// the old configuration in place.
    fn write(&self) -> Result<()> {
        let mut xml = Vec::new();
        self.root.to_writer_xml(&mut xml)?;
        xml.push(b'\n');
        self.restore(&xml)
    }

    fn restore(&self, bytes: &[u8]) -> Result<()> {
        let parent = self.path.parent().expect("config.plist has a parent");
        let mut file = tempfile::NamedTempFile::new_in(parent)?;
        file.write_all(bytes)?;
        file.as_file().sync_all()?;
        file.persist(&self.path).map_err(|error| error.error)?;
        Ok(())
    }
}

/// Install or replace the mount, and return a report of what changed.
pub fn install(command: &Install) -> Result<serde_json::Value> {
    let esp = &command.esp;
    let source = match &command.source {
        Some(source) => {
            Some(fs::read(source).with_context(|| format!("cannot read {}", source.display()))?)
        }
        None if esp.join(SOURCE).is_file() => None,
        None => bail!("pass --source: {} has no {SOURCE}", esp.display()),
    };
    // Check the configuration before writing the payload.
    Config::read(esp)?;
    // The payload goes before the entry, so OpenCore never lists Stela with
    // a half-written payload.
    let payload = match &command.ipsw {
        Some(ipsw) => Some(crate::restore::payload::write(
            &crate::restore::payload::WriteOptions {
                image: ipsw,
                model: &command.model,
                root: command.payload_root.as_deref().unwrap_or(esp),
                layout: command.payload_layout,
                slice_bytes: command.slice_bytes,
                fetch_keys: !command.no_aea_keys,
            },
        )?),
        None => None,
    };
    let mut report = add_mount(
        esp,
        &command.image,
        source.as_deref(),
        command.options.as_deref(),
    )?;
    report["payload"] = json!(payload);
    Ok(report)
}

/// Copy the tool, the ARM source when given and the options, then add the
/// entry. `stela setup` uses this without a source: install mode runs none.
pub(crate) fn add_mount(
    esp: &Path,
    image_path: &Path,
    source: Option<&[u8]>,
    options: Option<&str>,
) -> Result<serde_json::Value> {
    let mut config = Config::read(esp)?;
    let image =
        fs::read(image_path).with_context(|| format!("cannot read {}", image_path.display()))?;
    ensure!(
        image.starts_with(b"MZ"),
        "{} is not a PE image",
        image_path.display()
    );
    let (replaced, first) = config.remove_stela()?;
    let index = first.unwrap_or(0);
    config.tools()?.insert(index, entry());

    fs::create_dir_all(esp.join(MOUNT))?;
    fs::create_dir_all(esp.join(TOOLS))?;
    // Keep the configuration from before Stela, not a previous install's.
    if !esp.join(BACKUP).is_file() {
        fs::write(esp.join(BACKUP), &config.bytes)?;
    }
    fs::write(esp.join(TOOLS).join(TOOL), &image)?;
    if let Some(source) = source {
        fs::write(esp.join(SOURCE), source)?;
    }
    if let Some(options) = options {
        fs::write(esp.join(OPTIONS), options)?;
    }
    // The entry goes in last, so OpenCore never lists a missing tool.
    config.write()?;
    Ok(json!({
        "config": config.path,
        "backup": esp.join(BACKUP),
        "entry": index,
        "replaced": replaced,
        "tool": esp.join(TOOLS).join(TOOL),
        "source": esp.join(SOURCE).is_file().then(|| esp.join(SOURCE)),
        "options": esp.join(OPTIONS).is_file().then(|| esp.join(OPTIONS)),
    }))
}

/// Paths relative to the ESP that `install` writes, for reports.
pub(crate) const INSTALLED: [&str; 4] = ["EFI/OC/Tools/Stela.efi", OPTIONS, SOURCE, BACKUP];

/// Check that `uninstall` would understand this ESP, without changing it.
pub(crate) fn check_config(esp: &Path) -> Result<()> {
    Config::read(esp).map(|_| ())
}

/// Remove the entry and the files `install` wrote, and return a report.
pub fn uninstall(esp: &Path) -> Result<serde_json::Value> {
    let mut config = Config::read(esp)?;
    let (removed, _) = config.remove_stela()?;
    // When the entry was the only change, the backup's own bytes go back.
    let backup = fs::read(esp.join(BACKUP)).ok().filter(|bytes| {
        Value::from_reader(Cursor::new(bytes)).is_ok_and(|backup| backup == config.root)
    });
    match backup {
        Some(bytes) if bytes != config.bytes => config.restore(&bytes)?,
        Some(_) => {}
        None if removed > 0 => config.write()?,
        None => {}
    }
    let mut files = Vec::new();
    for file in [
        esp.join(TOOLS).join(TOOL),
        esp.join(OPTIONS),
        esp.join(SOURCE),
        esp.join(BACKUP),
    ] {
        if file.is_file() {
            fs::remove_file(&file)?;
            files.push(file);
        }
    }
    // Directories go only when nothing else is left in them.
    for directory in [esp.join(MOUNT), esp.join(TOOLS)] {
        if fs::read_dir(&directory).is_ok_and(|mut entries| entries.next().is_none()) {
            fs::remove_dir(&directory)?;
        }
    }
    Ok(json!({ "config": config.path, "entries": removed, "files": files }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool(path: &str) -> Value {
        let mut entry = Dictionary::new();
        entry.insert("Path".into(), path.into());
        entry.into()
    }

    #[test]
    fn stela_entries_match_the_tool_path_in_any_case() {
        assert!(is_stela(&tool("Stela.efi")));
        assert!(is_stela(&tool("STELA.EFI")));
        assert!(!is_stela(&tool("OpenShell.efi")));
        assert!(!is_stela(&tool("Stela.efi.bak")));
        assert!(!is_stela(&Value::from("Stela.efi")));
    }

    #[test]
    fn the_entry_starts_from_the_real_path() {
        let entry = entry();
        let entry = entry.as_dictionary().unwrap();
        assert_eq!(entry.get("RealPath"), Some(&Value::Boolean(true)));
        assert_eq!(entry.get("Auxiliary"), Some(&Value::Boolean(false)));
        assert_eq!(entry.get("Name").and_then(Value::as_string), Some(NAME));
        let keys: Vec<&str> = entry.keys().map(String::as_str).collect();
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        assert_eq!(keys, sorted, "OpenCore's sample orders keys alphabetically");
    }
}
