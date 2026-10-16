//! Add the UEFI mount to an existing OpenCore EFI as one boot picker entry.
//!
//! `install` copies `stela.efi` to `EFI/OC/Tools/Stela.efi`, writes the
//! mount's `EFI/stela/stela.cfg` and `EFI/stela/source.bin`, and adds one
//! `Misc.Tools` entry to `EFI/OC/config.plist`. The previous configuration is
//! kept as `EFI/stela/config.plist.backup`. Every other key keeps its value
//! and order; only the XML layout is rewritten. `uninstall` removes the entry
//! and those files.
use anyhow::{Context, Result, bail, ensure};
use clap::{Args, Subcommand};
use plist::{Dictionary, Value};
use serde_json::json;
use std::{
    fs,
    io::{Cursor, Write},
    path::{Path, PathBuf},
};

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
        let parent = self.path.parent().expect("config.plist has a parent");
        let mut file = tempfile::NamedTempFile::new_in(parent)?;
        file.write_all(&xml)?;
        file.as_file().sync_all()?;
        file.persist(&self.path).map_err(|error| error.error)?;
        Ok(())
    }
}

/// Install or replace the mount, and return a report of what changed.
pub fn install(command: &Install) -> Result<serde_json::Value> {
    let esp = &command.esp;
    let mut config = Config::read(esp)?;
    let image = fs::read(&command.image)
        .with_context(|| format!("cannot read {}", command.image.display()))?;
    ensure!(
        image.starts_with(b"MZ"),
        "{} is not a PE image",
        command.image.display()
    );
    let source = match &command.source {
        Some(source) => {
            Some(fs::read(source).with_context(|| format!("cannot read {}", source.display()))?)
        }
        None if esp.join(SOURCE).is_file() => None,
        None => bail!("pass --source: {} has no {SOURCE}", esp.display()),
    };

    let (replaced, first) = config.remove_stela()?;
    let index = first.unwrap_or(0);
    config.tools()?.insert(index, entry());

    fs::create_dir_all(esp.join(MOUNT))?;
    fs::create_dir_all(esp.join(TOOLS))?;
    fs::write(esp.join(BACKUP), &config.bytes)?;
    fs::write(esp.join(TOOLS).join(TOOL), &image)?;
    if let Some(source) = &source {
        fs::write(esp.join(SOURCE), source)?;
    }
    if let Some(options) = &command.options {
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
        "source": esp.join(SOURCE),
        "options": esp.join(OPTIONS).is_file().then(|| esp.join(OPTIONS)),
    }))
}

/// Remove the entry and the files `install` wrote, and return a report.
pub fn uninstall(esp: &Path) -> Result<serde_json::Value> {
    let mut config = Config::read(esp)?;
    let (removed, _) = config.remove_stela()?;
    if removed > 0 {
        config.write()?;
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
