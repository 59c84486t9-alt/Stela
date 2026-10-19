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
//! ([`impdef`]). `--check` fails when either checked-in output differs from a
//! fresh pass.
//! A later pass adds a fact by adding an analysis to the matching loop.
use crate::tools::root;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
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
                "drivers": drivers(&decoded.bytes)?,
                "impdef": census(&decoded.bytes)?,
            }));
        }

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
    fn short_values_stay_on_one_line_and_long_ones_break() {
        let row = json!(["S3_0_C15_C1_2", "read", 3]);
        assert_eq!(render(&row, 0), r#"["S3_0_C15_C1_2", "read", 3]"#);
        let long = json!({ "rows": vec![row.clone(); 4] });
        let line = r#"    ["S3_0_C15_C1_2", "read", 3]"#;
        let expected = format!("{{\n  \"rows\": [\n{}\n  ]\n}}", [line; 4].join(",\n"));
        assert_eq!(render(&long, 0), expected);
    }
}
