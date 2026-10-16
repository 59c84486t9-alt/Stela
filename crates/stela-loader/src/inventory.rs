//! Build inventories and per-artifact translation progress.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path};
use stela_runtime::sha256;

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

#[cfg(test)]
mod tests {
    use super::*;
    fn inventory() -> Inventory {
        Inventory {
            schema_version: 1,
            build: "fixture".into(),
            root: ".".into(),
            artifacts: vec![Artifact {
                id: "a".into(),
                path: "a".into(),
                sha256: "hash".into(),
                architecture: "arm64".into(),
                slice_offset: 0,
                text_bytes: 4,
            }],
            issues: vec![],
            excluded_containers: vec![],
        }
    }
    #[test]
    fn rejects_skipped_stages_and_changed_evidence() -> Result<()> {
        let mut p = Progress::new(inventory(), b"inventory")?;
        let file = tempfile::NamedTempFile::new()?;
        std::fs::write(file.path(), "compiler report")?;
        assert!(p.record("a", Stage::Verified, file.path()).is_err());
        p.record("a", Stage::Lifted, file.path())?;
        assert_eq!(p.report()?["stages"]["lifted"], 1);
        assert!(p.report()?["whole_os_coverage"].is_null());
        std::fs::write(file.path(), "different report")?;
        assert!(p.report().is_err());
        Ok(())
    }
}
