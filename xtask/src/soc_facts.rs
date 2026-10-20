//! `cargo xtask soc-facts`: the per-SoC facts of a universal macOS IPSW,
//! derived from the AP-side SPTM, TXM, kernelcache and DeviceTree builds its
//! BuildManifest names, so `machine::soc`'s rows cite reproducible evidence
//! rather than one board's reading.
//!
//! The task walks the manifest once per build: each SPTM (one per SoC
//! family, `Firmware/sptm.<soc>.release.im4p`) for its CPU implementation
//! block fields, accesses and lockdown pairs ([`sptm`]); each SPTM, TXM and
//! kernelcache for its IMPLEMENTATION DEFINED System register census
//! ([`sysreg`]); each kernelcache for the SoC drivers it links; and each
//! board's DeviceTree for its SoC name, CPU topology, AIC, PMGR and NVRAM
//! slot ([`board`]). Every row carries its member, the decoded payload's
//! SHA-256 and the offset of its evidence; no Apple bytes are written. From
//! the census it also generates `machine::impdef`'s per-chip census
//! ([`impdef`]). `--system-extensions` adds the kexts of the installed
//! system's `/System/Library/Extensions` (from the decrypted OS image), which
//! macOS 27 links into its system kext collection on the machine itself and
//! loads on every chip after boot; without it the checked-in collection rows
//! are kept. `--check` fails when either
//! checked-in output differs from a fresh pass.
//! A later pass adds a fact by adding an analysis to the matching loop.
use crate::tools::root;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};
use stela_cli::restore::{archive, manifest::Identity};
use stela_runtime::sha256;

mod a64;
mod board;
mod impdef;
mod macho;
mod sptm;
mod sysreg;

const OUTPUT: &str = "isa/apple-soc-facts.json";
const SCHEMA_VERSION: u32 = 1;
/// The identity whose components a board's facts come from; the restore
/// identities of 26A434 name the same SPTM, TXM and DeviceTree members.
const VARIANT: &str = "Customer Erase Install (IPSW)";
const SPTM: &str = "Ap,SecurePageTableMonitor";
const TXM: &str = "Ap,TrustedExecutionMonitor";
const KERNEL: &str = "KernelCache";
const DEVICE_TREE: &str = "DeviceTree";
/// Member and decoded size limits (the kernelcaches decode to about 125 MB).
const MEMBER_LIMIT: u64 = 64 << 20;
const DECODED_LIMIT: u64 = 512 << 20;
/// The size limit of one kext binary.
const KEXT_LIMIT: u64 = 256 << 20;
const FAT_MAGIC: u32 = 0xcafe_babe;
const MH_MAGIC_64: u32 = 0xfeed_facf;
const CPU_TYPE_ARM64: u32 = 0x0100_000c;
const CPU_SUBTYPE_ARM64E: u32 = 2;
const CPU_SUBTYPE_MASK: u32 = 0xff;
/// Fileset entries whose names identify the SoC's AIC and PMGR drivers.
const DRIVER_PREFIXES: [&str; 2] = [
    "com.apple.driver.AppleInterruptController",
    "com.apple.driver.AppleT",
];

#[derive(clap::Args)]
pub struct SocFacts {
    /// The universal macOS restore IPSW.
    #[arg(long)]
    ipsw: PathBuf,
    /// The OS image's `/System/Library/Extensions`, such as a read-only
    /// mount of the decrypted image.
    #[arg(long)]
    system_extensions: Option<PathBuf>,
    /// Fail instead of writing when the checked-in facts differ.
    #[arg(long)]
    check: bool,
}

/// One decoded member and its provenance.
struct Decoded {
    member: String,
    bytes: Vec<u8>,
    sha256: String,
}

impl Decoded {
    fn read(ipsw: &std::path::Path, member: &str) -> Result<Self> {
        let container = archive::read_member(ipsw, member, MEMBER_LIMIT)
            .with_context(|| format!("cannot read {member}"))?;
        let (bytes, _) = stela_loader::im4p::decode(&container, DECODED_LIMIT)
            .with_context(|| format!("cannot decode {member}"))?;
        let sha256 = sha256(&bytes);
        Ok(Self {
            member: member.into(),
            bytes,
            sha256,
        })
    }

    fn source(&self) -> Value {
        json!({ "member": self.member, "decoded_sha256": self.sha256 })
    }
}

fn component<'a>(identity: &'a Identity, name: &str) -> Option<&'a str> {
    identity
        .components
        .get(name)
        .map(|component| component.path.as_str())
}

/// The boards (one identity each) grouped under every member they share.
fn group<'a>(identities: &[&'a Identity], name: &str) -> BTreeMap<&'a str, Vec<&'a Identity>> {
    let mut groups: BTreeMap<&str, Vec<&Identity>> = BTreeMap::new();
    for identity in identities {
        if let Some(member) = component(identity, name) {
            groups.entry(member).or_default().push(identity);
        }
    }
    groups
}

fn chip_ids(identities: &[&Identity]) -> Vec<String> {
    identities
        .iter()
        .filter_map(|identity| identity.ap_chip_id.clone())
        .map(|id| id.to_ascii_lowercase())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn device_classes(identities: &[&Identity]) -> Vec<String> {
    identities
        .iter()
        .map(|identity| identity.device_class.clone())
        .collect()
}

fn census(data: &[u8]) -> Result<Value> {
    let image = macho::parse(data, 0)?;
    Ok(sysreg::json(&sysreg::census(&image, data)))
}

/// The SoC drivers a kernelcache links, by fileset entry.
/// The prefix of XNU's `version[]`, which `kern.version` reports.
const KERNEL_VERSION_PREFIX: &[u8] = b"Darwin Kernel Version ";

/// The kernelcache's XNU `version[]` string. The kernel keeps copies of it;
/// they must agree.
fn kernel_version(data: &[u8]) -> Result<String> {
    let mut found = BTreeSet::new();
    let mut rest = data;
    while let Some(start) = rest
        .windows(KERNEL_VERSION_PREFIX.len())
        .position(|window| window == KERNEL_VERSION_PREFIX)
    {
        let tail = &rest[start..];
        let end = tail
            .iter()
            .position(|&byte| byte == 0)
            .context("unterminated kernel version")?;
        found.insert(String::from_utf8(tail[..end].to_vec()).context("kernel version")?);
        rest = &tail[end..];
    }
    ensure!(
        found.len() == 1,
        "the kernelcache has {} kernel versions",
        found.len()
    );
    Ok(found.pop_first().expect("one version"))
}

fn drivers(data: &[u8]) -> Result<Vec<String>> {
    let image = macho::parse(data, 0)?;
    Ok(image
        .entries
        .iter()
        .map(|entry| entry.name.clone())
        .filter(|name| {
            DRIVER_PREFIXES
                .iter()
                .any(|prefix| name.starts_with(prefix))
                && (name.contains("InterruptController") || name.ends_with("PMGR"))
        })
        .collect())
}

/// Every arm64 Mach-O file under `directory`, by path relative to it, in
/// path order. Symbolic links are not followed.
fn binaries(directory: &Path) -> Result<Vec<(String, PathBuf)>> {
    let mut found = Vec::new();
    let mut pending = vec![directory.to_path_buf()];
    while let Some(path) = pending.pop() {
        for entry in
            std::fs::read_dir(&path).with_context(|| format!("cannot list {}", path.display()))?
        {
            let entry = entry?;
            let kind = entry.file_type()?;
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() {
                let mut magic = [0; 4];
                let mut file = std::fs::File::open(entry.path())?;
                if std::io::Read::read_exact(&mut file, &mut magic).is_ok()
                    && (u32::from_le_bytes(magic) == MH_MAGIC_64
                        || u32::from_be_bytes(magic) == FAT_MAGIC)
                {
                    let relative = entry.path().strip_prefix(directory)?.to_path_buf();
                    found.push((relative.to_string_lossy().into_owned(), entry.path()));
                }
            }
        }
    }
    found.sort();
    Ok(found)
}

/// The arm64e slice of a thin or universal Mach-O, else its arm64 one.
fn arm64_slice(data: &[u8]) -> Result<Option<&[u8]>> {
    let word = |at: usize| -> Result<u32> {
        let bytes = data.get(at..at + 4).context("truncated fat header")?;
        Ok(u32::from_be_bytes(bytes.try_into()?))
    };
    if data.get(..4) != Some(&FAT_MAGIC.to_be_bytes()) {
        let cpu = u32::from_le_bytes(data.get(4..8).context("truncated header")?.try_into()?);
        return Ok((cpu == CPU_TYPE_ARM64).then_some(data));
    }
    let mut best: Option<(bool, usize, usize)> = None;
    for index in 0..word(4)? as usize {
        let at = 8 + index * 20;
        if word(at)? != CPU_TYPE_ARM64 {
            continue;
        }
        let arm64e = word(at + 4)? & CPU_SUBTYPE_MASK == CPU_SUBTYPE_ARM64E;
        let (offset, size) = (word(at + 8)? as usize, word(at + 12)? as usize);
        if best.is_none_or(|(chosen, ..)| arm64e && !chosen) {
            best = Some((arm64e, offset, size));
        }
    }
    best.map(|(_, offset, size)| {
        data.get(offset..offset + size)
            .context("fat slice outside the file")
    })
    .transpose()
}

/// IMPLEMENTATION DEFINED accesses by encoding and direction.
type Census = BTreeMap<(sysreg::Encoding, sysreg::Direction), sysreg::Row>;

/// The census of every kext binary under `directory`, merged: a row counts
/// all sites and names the first file, in path order, that has one. The
/// source digest covers each file's path and SHA-256.
fn extensions(directory: &Path) -> Result<(Value, Census)> {
    let mut rows = Census::new();
    let mut listing = String::new();
    let mut files = 0;
    for (relative, path) in binaries(directory)? {
        let bytes = std::fs::read(&path)?;
        ensure!(
            bytes.len() as u64 <= KEXT_LIMIT,
            "{relative} exceeds the kext limit"
        );
        listing.push_str(&format!(
            "{relative} {}
",
            sha256(&bytes)
        ));
        let Some(slice) = arm64_slice(&bytes)? else {
            continue;
        };
        let image = macho::parse(slice, 0).with_context(|| format!("{relative}: Mach-O"))?;
        files += 1;
        for (key, row) in sysreg::census(&image, slice) {
            rows.entry(key)
                .and_modify(|merged| merged.count += row.count)
                .or_insert(sysreg::Row {
                    entry: Some(relative.clone()),
                    ..row
                });
        }
    }
    ensure!(files > 0, "{} holds no arm64 kexts", directory.display());
    let source = json!({
        "directory": "/System/Library/Extensions",
        "arm64_files": files,
        "listing_sha256": sha256(listing.as_bytes()),
    });
    Ok((source, rows))
}

/// The checked-in facts, or `null` before the first pass.
fn checked_in() -> Result<Value> {
    match std::fs::read_to_string(root().join(OUTPUT)) {
        Ok(text) => serde_json::from_str(&text).with_context(|| format!("{OUTPUT} is not JSON")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Value::Null),
        Err(error) => Err(error).with_context(|| format!("cannot read {OUTPUT}")),
    }
}

/// The widest line [`render`] keeps a value on.
const LINE: usize = 100;
const INDENT: usize = 2;

/// `value` on one line, with a space after each comma and colon.
fn inline(value: &Value) -> String {
    match value {
        Value::Array(items) => {
            let items: Vec<String> = items.iter().map(inline).collect();
            format!("[{}]", items.join(", "))
        }
        Value::Object(fields) => {
            let fields: Vec<String> = fields
                .iter()
                .map(|(key, item)| format!("{}: {}", Value::from(key.as_str()), inline(item)))
                .collect();
            format!("{{{}}}", fields.join(", "))
        }
        scalar => scalar.to_string(),
    }
}

/// Pretty JSON that keeps a value on one line when it fits in [`LINE`]
/// columns, so the census and access rows stay one per line.
fn render(value: &Value, indent: usize) -> String {
    let inline = inline(value);
    if indent + inline.len() <= LINE || !(value.is_array() || value.is_object()) {
        return inline;
    }
    let pad = " ".repeat(indent + INDENT);
    let close = " ".repeat(indent);
    match value {
        Value::Array(items) => {
            let lines: Vec<String> = items
                .iter()
                .map(|item| format!("{pad}{}", render(item, indent + INDENT)))
                .collect();
            format!("[\n{}\n{close}]", lines.join(",\n"))
        }
        Value::Object(fields) => {
            let lines: Vec<String> = fields
                .iter()
                .map(|(key, item)| {
                    let key = Value::from(key.as_str());
                    format!("{pad}{key}: {}", render(item, indent + INDENT))
                })
                .collect();
            format!("{{\n{}\n{close}}}", lines.join(",\n"))
        }
        _ => unreachable!("scalars return inline"),
    }
}

impl SocFacts {
    pub fn run(&self) -> Result<()> {
        let report = archive::manifest(&self.ipsw, None, false)?;
        let mut seen = BTreeSet::new();
        let boards: Vec<&Identity> = report
            .identities
            .iter()
            .filter(|identity| identity.variant == VARIANT)
            .filter(|identity| component(identity, SPTM).is_some())
            .filter(|identity| seen.insert(identity.device_class.clone()))
            .collect();
        ensure!(
            !boards.is_empty(),
            "the IPSW names no SPTM board identities"
        );

        let mut socs = Vec::new();
        for (member, group) in group(&boards, SPTM) {
            let decoded = Decoded::read(&self.ipsw, member)?;
            println!("{member}: {} boards", group.len());
            let mut facts =
                sptm::facts(&decoded.bytes).with_context(|| format!("{member}: SPTM facts"))?;
            facts["source"] = decoded.source();
            facts["chip_ids"] = json!(chip_ids(&group));
            facts["boards"] = json!(device_classes(&group));
            facts["impdef"] = census(&decoded.bytes)?;
            socs.push(facts);
        }

        let mut monitors = Vec::new();
        for (member, group) in group(&boards, TXM) {
            let decoded = Decoded::read(&self.ipsw, member)?;
            println!("{member}: {} boards", group.len());
            monitors.push(json!({
                "source": decoded.source(),
                "chip_ids": chip_ids(&group),
                "impdef": census(&decoded.bytes)?,
            }));
        }

        let mut kernels = Vec::new();
        for (member, group) in group(&boards, KERNEL) {
            let decoded = Decoded::read(&self.ipsw, member)?;
            println!("{member}: {} boards", group.len());
            kernels.push(json!({
                "source": decoded.source(),
                "chip_ids": chip_ids(&group),
                "boards": device_classes(&group),
                "version": kernel_version(&decoded.bytes)?,
                "drivers": drivers(&decoded.bytes)?,
                "impdef": census(&decoded.bytes)?,
            }));
        }

        let all_chips = chip_ids(&boards);
        let collections = match &self.system_extensions {
            Some(directory) => {
                let (source, rows) = extensions(directory)?;
                println!("{}: every chip", directory.display());
                vec![json!({
                    "source": source,
                    "chip_ids": all_chips,
                    "impdef": sysreg::json(&rows),
                })]
            }
            None => checked_in()?["collections"]
                .as_array()
                .cloned()
                .unwrap_or_default(),
        };

        let mut trees = Vec::new();
        for identity in &boards {
            let member = component(identity, DEVICE_TREE).context("a board has no DeviceTree")?;
            let decoded = Decoded::read(&self.ipsw, member)?;
            let mut facts = board::facts(&decoded.bytes)
                .with_context(|| format!("{member}: DeviceTree facts"))?;
            facts["source"] = decoded.source();
            facts["device_class"] = json!(identity.device_class);
            facts["product_type"] = json!(identity.product_type);
            facts["chip_id"] = json!(identity.ap_chip_id.as_deref().map(str::to_ascii_lowercase));
            facts["board_id"] = json!(identity.ap_board_id);
            facts["sptm"] = json!(component(identity, SPTM));
            facts["kernelcache"] = json!(component(identity, KERNEL));
            trees.push(facts);
        }

        let facts = json!({
            "schema_version": SCHEMA_VERSION,
            "generator": "cargo xtask soc-facts --ipsw IPSW",
            "impdef_columns": sysreg::COLUMNS,
            "source": {
                "ipsw": self.ipsw.file_name().map(|name| name.to_string_lossy()),
                "product_version": report.product_version,
                "product_build": report.product_build,
                "manifest_sha256": report.manifest_sha256,
            },
            "socs": socs,
            "monitors": monitors,
            "kernels": kernels,
            "collections": collections,
            "boards": trees,
        });
        self.update(OUTPUT, render(&facts, 0) + "\n")?;
        self.update(impdef::OUTPUT, impdef::rust(&facts)?)
    }

    /// Write `text` to the repository's `output`, or with `--check` fail
    /// when it differs.
    fn update(&self, output: &str, text: String) -> Result<()> {
        let path = root().join(output);
        let current = std::fs::read_to_string(&path).unwrap_or_default();
        if current == text {
            println!("{output}: up to date");
        } else if self.check {
            anyhow::bail!("{output} differs from the IPSW's facts; rerun without --check");
        } else {
            std::fs::write(&path, text)
                .with_context(|| format!("cannot write {}", path.display()))?;
            println!("{output}: written");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_kernel_version_is_its_one_version_string() {
        let version = b"Darwin Kernel Version 27.0.0: Tue Aug 11; root:xnu~1/RELEASE_ARM64_T8112";
        let mut data = vec![0u8; 8];
        for _ in 0..2 {
            data.extend_from_slice(version);
            data.extend_from_slice(&[0, 1, 2]);
        }
        assert_eq!(
            kernel_version(&data).unwrap().as_bytes(),
            version.as_slice()
        );
        data.extend_from_slice(b"Darwin Kernel Version 26\0");
        data.push(0);
        assert!(kernel_version(&data).is_err());
        assert!(kernel_version(b"none").is_err());
    }

    #[test]
    fn a_universal_kext_gives_its_arm64e_slice_and_a_thin_one_itself() {
        let mut fat = FAT_MAGIC.to_be_bytes().to_vec();
        fat.extend(3u32.to_be_bytes());
        // x86_64, arm64, arm64e: (cputype, subtype, offset, size, align).
        for (cpu, subtype, offset) in [
            (0x0100_0007u32, 3u32, 68u32),
            (CPU_TYPE_ARM64, 0, 72),
            (CPU_TYPE_ARM64, 0x8000_0002, 76),
        ] {
            for value in [cpu, subtype, offset, 4, 0] {
                fat.extend(value.to_be_bytes());
            }
        }
        fat.extend(b"x86_a64_a64e");
        assert_eq!(arm64_slice(&fat).unwrap(), Some(&b"a64e"[..]));
        let mut thin = MH_MAGIC_64.to_le_bytes().to_vec();
        thin.extend(CPU_TYPE_ARM64.to_le_bytes());
        assert_eq!(arm64_slice(&thin).unwrap(), Some(&thin[..]));
        thin[4] = 7;
        assert_eq!(arm64_slice(&thin).unwrap(), None);
    }

    #[test]
    fn short_values_stay_on_one_line_and_long_ones_break() {
        let row = json!(["S3_0_C15_C1_2", "read", 3]);
        assert_eq!(render(&row, 0), r#"["S3_0_C15_C1_2", "read", 3]"#);
        let long = json!({ "rows": vec![row.clone(); 4] });
        let line = r#"    ["S3_0_C15_C1_2", "read", 3]"#;
        let expected = format!("{{\n  \"rows\": [\n{}\n  ]\n}}", [line; 4].join(",\n"));
        assert_eq!(render(&long, 0), expected);
    }
}
