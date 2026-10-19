//! Add the UEFI mount to an existing OpenCore EFI as one boot picker entry.
//!
//! `install` copies `stela.efi` to `EFI/OC/Tools/Stela.efi`, writes the
//! mount's `EFI/stela/stela.cfg` and `EFI/stela/source.bin`, and adds one
//! `Misc.Tools` entry to `EFI/OC/config.plist`. That entry is the only change
//! to the configuration: it is inserted into the file's text (see
//! [`config`]), so every other byte stays as it was, and nothing outside
//! `Misc.Tools` (`ACPI`, `Kernel`, `NVRAM`, `PlatformInfo`, `UEFI` and the
//! rest) is touched. The configuration is validated first and refused with a
//! reason, never echoed, when it cannot be edited exactly. Files are replaced
//! atomically. The configuration from before the first install is kept as
//! `EFI/stela/config.plist.backup`; a reinstall leaves that backup alone.
//! `uninstall` removes the entry and those files and restores the
//! configuration byte for byte.
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

mod config;
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

/// A value of the `Misc.Tools` entry.
enum Field {
    Text(&'static str),
    Flag(bool),
}

/// The `Misc.Tools` entry, its keys in alphabetical order as in OpenCore's
/// sample. OpenCore starts a tool from a memory buffer unless `RealPath` is
/// set, and the mount then has no boot volume to read.
const ENTRY: [(&str, Field); 10] = [
    ("Arguments", Field::Text("")),
    ("Auxiliary", Field::Flag(false)),
    ("Comment", Field::Text("Stela ARM macOS mount")),
    ("Enabled", Field::Flag(true)),
    ("Flavour", Field::Text("Auto")),
    ("FullNvramAccess", Field::Flag(false)),
    ("Name", Field::Text(NAME)),
    ("Path", Field::Text(TOOL)),
    ("RealPath", Field::Flag(true)),
    ("TextMode", Field::Flag(false)),
];

fn entry() -> Value {
    let mut entry = Dictionary::new();
    for (key, field) in &ENTRY {
        let value = match field {
            Field::Text(text) => Value::from(*text),
            Field::Flag(flag) => Value::from(*flag),
        };
        entry.insert((*key).into(), value);
    }
    entry.into()
}

/// The entry as XML lines at `indent`, each ending in `newline`. None of its
/// strings needs escaping.
fn entry_text(indent: &str, unit: &str, newline: &str) -> String {
    let mut text = format!("{indent}<dict>{newline}");
    for (key, field) in &ENTRY {
        let value = match field {
            Field::Text(value) => format!("<string>{value}</string>"),
            Field::Flag(true) => "<true/>".into(),
            Field::Flag(false) => "<false/>".into(),
        };
        text.push_str(&format!(
            "{indent}{unit}<key>{key}</key>{newline}{indent}{unit}{value}{newline}"
        ));
    }
    text.push_str(&format!("{indent}</dict>{newline}"));
    text
}

fn is_stela(entry: &Value) -> bool {
    entry
        .as_dictionary()
        .and_then(|entry| entry.get("Path"))
        .and_then(Value::as_string)
        .is_some_and(|path| path.eq_ignore_ascii_case(TOOL))
}

/// Replace `path` through a sibling temporary file, so a failed write leaves
/// the old file in place; with `fresh`, only when nothing is there yet.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8], fresh: bool) -> Result<()> {
    let parent = path.parent().context("a file without a parent directory")?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    match fresh {
        true => file.persist_noclobber(path).map_err(|error| error.error)?,
        false => file.persist(path).map_err(|error| error.error)?,
    };
    // FAT may refuse to sync a directory; the file itself is already synced.
    let _ = fs::File::open(parent).and_then(|directory| directory.sync_all());
    Ok(())
}

/// `config.plist`: its bytes, its text and its parsed value.
struct Config {
    path: PathBuf,
    bytes: Vec<u8>,
    text: String,
    root: Value,
}

impl Config {
    /// Read and validate the configuration; the reasons never quote it.
    fn read(esp: &Path) -> Result<Self> {
        let path = esp.join(CONFIG);
        let bytes = fs::read(&path).with_context(|| format!("cannot read {}", path.display()))?;
        let refuse =
            |reason: &str| anyhow::anyhow!("{} cannot be changed safely: {reason}", path.display());
        if bytes.starts_with(b"bplist") {
            return Err(refuse("it is a binary property list; OpenCore reads XML"));
        }
        let text = String::from_utf8(bytes.clone()).map_err(|_| refuse("it is not UTF-8 text"))?;
        let root = Value::from_reader(Cursor::new(&bytes))
            .map_err(|_| refuse("it is not a valid property list"))?;
        let misc = root
            .as_dictionary()
            .and_then(|root| root.get("Misc"))
            .and_then(Value::as_dictionary)
            .ok_or_else(|| refuse("it has no Misc dictionary"))?;
        if !misc
            .get("Tools")
            .is_some_and(|tools| tools.as_array().is_some())
        {
            return Err(refuse("it has no Misc.Tools array"));
        }
        // A vault signs config.plist; an edit would stop OpenCore booting.
        let vault = misc
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
        config::tools(&text)
            .map_err(|error| refuse(&format!("its XML cannot be edited exactly ({error})")))?;
        Ok(Self {
            path,
            bytes,
            text,
            root,
        })
    }

    /// The parsed configuration with the Stela entries removed, and with
    /// `entry()` inserted at `insert` when given.
    fn expected(&self, insert: Option<usize>) -> Value {
        let mut root = self.root.clone();
        let tools = root
            .as_dictionary_mut()
            .and_then(|root| root.get_mut("Misc"))
            .and_then(Value::as_dictionary_mut)
            .and_then(|misc| misc.get_mut("Tools"))
            .and_then(Value::as_array_mut)
            .expect("checked when read");
        tools.retain(|entry| !is_stela(entry));
        if let Some(index) = insert {
            tools.insert(index, entry());
        }
        root
    }

    /// Indices of the Stela entries in `Misc.Tools`.
    fn stela_entries(&self, tools: &config::Tools) -> Result<Vec<usize>> {
        let mut found = Vec::new();
        for (index, child) in tools.array.children.iter().enumerate() {
            if child.name == "dict"
                && config::string(&self.text, child, "Path")?
                    .is_some_and(|path| path.eq_ignore_ascii_case(TOOL))
            {
                found.push(index);
            }
        }
        Ok(found)
    }

    /// Check an edited text against the structure it must have.
    fn checked(&self, text: String, expected: &Value) -> Result<Vec<u8>> {
        let edited = Value::from_reader(Cursor::new(text.as_bytes()))
            .context("the edited config.plist does not parse; nothing was written")?;
        ensure!(
            &edited == expected,
            "the edit would change more than the Stela entry; nothing was written"
        );
        Ok(text.into_bytes())
    }

    /// The text with one Stela entry: an existing one replaced in place and
    /// any others removed, or a new one first in the array. Returns the new
    /// bytes, the entry's index and how many entries it replaced.
    fn with_entry(&self) -> Result<(Vec<u8>, usize, usize)> {
        let tools = config::tools(&self.text)?;
        let stela = self.stela_entries(&tools)?;
        let newline = config::newline(&self.text);
        let block = entry_text(&tools.entry_indent, &tools.unit, newline);
        let mut text = self.text.clone();
        let index = match stela.first() {
            Some(&first) => {
                for &index in stela.iter().rev() {
                    let range = config::lines(&self.text, &tools.array.children[index]);
                    let replacement = if index == first { block.as_str() } else { "" };
                    text.replace_range(range, replacement);
                }
                first
            }
            None if tools.array.content.is_empty() => {
                // `<array/>` or `<array></array>`: open it onto its own lines.
                let outer = tools
                    .entry_indent
                    .strip_suffix(tools.unit.as_str())
                    .unwrap_or_default();
                text.replace_range(
                    tools.array.start..tools.array.end,
                    &format!("<array>{newline}{block}{outer}</array>"),
                );
                0
            }
            None => {
                let mut at = tools.array.content.start;
                if self.text[at..].starts_with(newline) {
                    at += newline.len();
                    text.insert_str(at, &block);
                } else {
                    text.insert_str(at, &format!("{newline}{block}"));
                }
                0
            }
        };
        let bytes = self.checked(text, &self.expected(Some(index)))?;
        Ok((bytes, index, stela.len()))
    }

    /// The text without any Stela entry, and how many there were.
    fn without_entries(&self) -> Result<(Vec<u8>, usize)> {
        let tools = config::tools(&self.text)?;
        let stela = self.stela_entries(&tools)?;
        let mut text = self.text.clone();
        for &index in stela.iter().rev() {
            text.replace_range(config::lines(&self.text, &tools.array.children[index]), "");
        }
        Ok((self.checked(text, &self.expected(None))?, stela.len()))
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
    let config = Config::read(esp)?;
    let image =
        fs::read(image_path).with_context(|| format!("cannot read {}", image_path.display()))?;
    ensure!(
        image.starts_with(b"MZ"),
        "{} is not a PE image",
        image_path.display()
    );
    // Prepare and check the edit before anything is written.
    let (edited, index, replaced) = config.with_entry()?;

    fs::create_dir_all(esp.join(MOUNT))?;
    fs::create_dir_all(esp.join(TOOLS))?;
    // Keep the configuration from before Stela, not a previous install's.
    if !esp.join(BACKUP).is_file() && replaced == 0 {
        write_atomic(&esp.join(BACKUP), &config.bytes, true)?;
    }
    write_atomic(&esp.join(TOOLS).join(TOOL), &image, false)?;
    if let Some(source) = source {
        write_atomic(&esp.join(SOURCE), source, false)?;
    }
    if let Some(options) = options {
        write_atomic(&esp.join(OPTIONS), options.as_bytes(), false)?;
    }
    // The entry goes in last, so OpenCore never lists a missing tool.
    if edited != config.bytes {
        write_atomic(&config.path, &edited, false)?;
    }
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

/// Whether `config.plist` holds Stela's entry exactly once, as `add_mount`
/// writes it.
pub(crate) fn entry_installed(esp: &Path) -> Result<bool> {
    let config = Config::read(esp)?;
    let (edited, _, replaced) = config.with_entry()?;
    Ok(replaced == 1 && edited == config.bytes)
}

/// Check that `uninstall` would understand this ESP, without changing it.
pub(crate) fn check_config(esp: &Path) -> Result<()> {
    Config::read(esp).map(|_| ())
}

/// Remove the entry and the files `install` wrote, and return a report.
pub fn uninstall(esp: &Path) -> Result<serde_json::Value> {
    let config = Config::read(esp)?;
    let (without, removed) = config.without_entries()?;
    // When the entry is the only change since the first install, the
    // backup's own bytes go back; otherwise only the entry's lines leave and
    // the backup stays for the user.
    let backup = fs::read(esp.join(BACKUP)).ok();
    let restores = backup.as_ref().is_some_and(|bytes| {
        Value::from_reader(Cursor::new(bytes)).is_ok_and(|backup| backup == config.expected(None))
    });
    let restored = match (&backup, restores) {
        (Some(bytes), true) => bytes.clone(),
        _ => without,
    };
    if restored != config.bytes {
        write_atomic(&config.path, &restored, false)?;
    }
    let kept_backup = backup.is_some() && !restores;
    let mut files = Vec::new();
    let mut remove = vec![
        esp.join(TOOLS).join(TOOL),
        esp.join(OPTIONS),
        esp.join(SOURCE),
    ];
    if !kept_backup {
        remove.push(esp.join(BACKUP));
    }
    for file in remove {
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
    Ok(json!({
        "config": config.path,
        "entries": removed,
        "restored_backup": restores,
        "kept_backup": kept_backup.then(|| esp.join(BACKUP)),
        "files": files,
    }))
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
