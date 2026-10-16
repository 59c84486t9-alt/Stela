//! Build-pinned inventories and evidence-based translation progress.
use crate::sha256;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs::File, io::Write, path::Path};

/// Write `value` as pretty JSON, replacing `path` atomically. Readers see the
/// old or the new file; durability across power loss is not promised.
pub fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    tmp.write_all(&bytes)?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    /// Identity includes path, fat-slice offset, and exact source hash.
    pub id: String,
    pub path: String,
    pub sha256: String,
    pub architecture: String,
    pub slice_offset: u64,
    pub text_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanIssue {
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inventory {
    pub schema_version: u32,
    pub build: String,
    pub root: String,
    pub artifacts: Vec<Artifact>,
    pub issues: Vec<ScanIssue>,
    pub excluded_containers: Vec<ScanIssue>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Inventoried,
    Lifted,
    Emitted,
    Verified,
}

impl std::str::FromStr for Stage {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "lifted" => Ok(Self::Lifted),
            "emitted" => Ok(Self::Emitted),
            "verified" => Ok(Self::Verified),
            _ => anyhow::bail!("stage must be lifted, emitted, or verified"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub stage: Stage,
    pub file: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Progress {
    pub schema_version: u32,
    pub inventory_sha256: String,
    pub inventory: Inventory,
    pub evidence: BTreeMap<String, Vec<Evidence>>,
}

impl Progress {
    pub fn new(inventory: Inventory, inventory_bytes: &[u8]) -> Result<Self> {
        ensure!(
            inventory.schema_version == 1,
            "unsupported inventory schema"
        );
        ensure!(
            !inventory.build.trim().is_empty(),
            "build must not be empty"
        );
        let mut ids = std::collections::BTreeSet::new();
        for artifact in &inventory.artifacts {
            ensure!(ids.insert(&artifact.id), "duplicate artifact ID");
        }
        Ok(Self {
            schema_version: 1,
            inventory_sha256: sha256(inventory_bytes),
            inventory,
            evidence: BTreeMap::new(),
        })
    }

    pub fn record(&mut self, id: &str, stage: Stage, evidence_path: &Path) -> Result<()> {
        ensure!(self.schema_version == 1, "unsupported progress schema");
        let artifact = self
            .inventory
            .artifacts
            .iter()
            .find(|a| a.id == id)
            .context("unknown artifact ID")?;
        ensure!(
            matches!(artifact.architecture.as_str(), "arm64" | "arm64e"),
            "only ARM64 slices need translation"
        );
        let records = self.evidence.entry(id.into()).or_default();
        let previous = records
            .last()
            .map(|e| e.stage)
            .unwrap_or(Stage::Inventoried);
        let next = match previous {
            Stage::Inventoried => Stage::Lifted,
            Stage::Lifted => Stage::Emitted,
            Stage::Emitted => Stage::Verified,
            Stage::Verified => anyhow::bail!("artifact already verified"),
        };
        ensure!(
            stage == next,
            "next stage is {next:?}; stages cannot be skipped"
        );
        let bytes = std::fs::read(evidence_path).context("read evidence")?;
        ensure!(!bytes.is_empty(), "evidence must not be empty");
        records.push(Evidence {
            stage,
            file: evidence_path.canonicalize()?.display().to_string(),
            sha256: sha256(&bytes),
        });
        Ok(())
    }

    pub fn report(&self) -> Result<serde_json::Value> {
        ensure!(self.schema_version == 1, "unsupported progress schema");
        // Fail closed when a recorded test result or compiler artifact changes.
        for records in self.evidence.values() {
            for evidence in records {
                let bytes = std::fs::read(&evidence.file)
                    .with_context(|| format!("missing evidence: {}", evidence.file))?;
                ensure!(
                    sha256(&bytes) == evidence.sha256,
                    "evidence changed: {}",
                    evidence.file
                );
            }
        }
        let arms: Vec<_> = self
            .inventory
            .artifacts
            .iter()
            .filter(|a| matches!(a.architecture.as_str(), "arm64" | "arm64e"))
            .collect();
        let mut stages = BTreeMap::new();
        for stage in [Stage::Lifted, Stage::Emitted, Stage::Verified] {
            let count = arms
                .iter()
                .filter(|a| {
                    self.evidence
                        .get(&a.id)
                        .and_then(|e| e.last())
                        .is_some_and(|e| e.stage >= stage)
                })
                .count();
            stages.insert(format!("{stage:?}").to_lowercase(), count);
        }
        Ok(serde_json::json!({
            "build": self.inventory.build,
            "scope": "inventoried standalone Mach-O ARM64 slices only",
            "arm64_slices": arms.len(),
            "arm64_text_bytes": arms.iter().map(|a| a.text_bytes).sum::<u64>(),
            "stages": stages,
            "scan_errors": self.inventory.issues.len(),
            "excluded_containers": self.inventory.excluded_containers.len(),
            "whole_os_coverage": null,
            "note": "Evidence is recorded by the operator; this ledger does not prove semantic equivalence. Whole-OS coverage is unknown."
        }))
    }
}

pub fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    serde_json::from_reader(File::open(path)?).context("read JSON")
}

#[cfg(test)]
mod tests;
