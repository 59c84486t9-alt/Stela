//! Complete bounded patchbay updates supplied by a selected boot-policy owner.
//!
//! A provenance claim is retained, not automatically certified. This byte-level
//! operation does not qualify policy values, entropy, vendor trust or RUN.
use super::{Plan, Staged, digest, label, macho::file_bytes};
use alloc::{collections::BTreeSet, string::String, vec::Vec};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use stela_runtime::sha256;

pub mod entropy;
pub mod native;

#[derive(Debug, Clone, Serialize)]
pub struct Provenance {
    pub input_sha256: String,
    pub coordinates: String,
    pub span_sha256: String,
}
impl Provenance {
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            digest(&self.input_sha256) && digest(&self.span_sha256) && label(&self.coordinates),
            "invalid coprocessor policy provenance"
        );
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize)]
pub struct Record {
    pub tag: u32,
    pub source_file_offset: u64,
    pub image_offset: u64,
    pub bytes: u32,
    pub source_sha256: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct Patchbay {
    pub source_file_offset: u64,
    pub bytes: u64,
    pub source_sha256: String,
    pub records: Vec<Record>,
}
pub(super) fn source_record(staged: &Staged, tag: u32) -> Result<(&Record, &[u8])> {
    let bay = staged
        .plan()
        .patchbay
        .as_ref()
        .context("native policy requires an original patchbay")?;
    let record = bay
        .records
        .iter()
        .find(|r| r.tag == tag)
        .context("native policy requires an original patchbay tag")?;
    let at = usize::try_from(record.image_offset)?;
    let raw = staged
        .bytes()
        .get(at..)
        .and_then(|tail| tail.get(..record.bytes as usize))
        .context("native policy record exceeds owned source bytes")?;
    ensure!(
        sha256(raw) == record.source_sha256,
        "native policy record differs from original source"
    );
    Ok((record, raw))
}
pub(super) fn parse(data: &[u8], plan: &Plan) -> Result<Option<Patchbay>> {
    let mut matches = plan.sections.iter().filter(|s| s.name == "_rtk_patchbay");
    let Some(section) = matches.next() else {
        return Ok(None);
    };
    ensure!(
        matches.next().is_none(),
        "duplicate firmware patchbay section"
    );
    ensure!(
        section.flags & 0xff == 0,
        "firmware patchbay must be an original regular file-backed section"
    );
    let raw = file_bytes(data, section.file_offset, section.bytes)?;
    let mut at = 0usize;
    let mut records = Vec::new();
    let mut tags = BTreeSet::new();
    while at < raw.len() {
        let header = raw
            .get(at..)
            .and_then(|tail| tail.get(..8))
            .context("truncated firmware patchbay record header")?;
        let tag = u32::from_le_bytes(header[..4].try_into()?);
        let bytes = u32::from_le_bytes(header[4..].try_into()?);
        ensure!(
            records.len() < 4096 && tags.insert(tag),
            "invalid or repeated firmware patchbay tag"
        );
        let start = at.checked_add(8).context("patchbay header overflows")?;
        let end = start
            .checked_add(bytes as usize)
            .context("patchbay value overflows")?;
        let value = raw
            .get(start..end)
            .context("firmware patchbay value exceeds its section")?;
        records.push(Record {
            tag,
            source_file_offset: section.file_offset + start as u64,
            image_offset: section.virtual_address - plan.vm_base + start as u64,
            bytes,
            source_sha256: sha256(value),
        });
        at = end;
    }
    Ok(Some(Patchbay {
        source_file_offset: section.file_offset,
        bytes: section.bytes,
        source_sha256: sha256(raw),
        records,
    }))
}
/// Every original record receives an explicit decision. Missing decisions never
/// mean preserve, and an unknown field cannot silently disappear.
pub enum Action {
    Preserve,
    Replace(Vec<u8>),
}
pub struct Field {
    pub tag: u32,
    pub action: Action,
    pub provenance: Provenance,
}
pub struct Policy {
    pub owner: String,
    pub product_build: String,
    pub hardware_role: String,
    pub compatible: String,
    pub decoded_sha256: String,
    pub patchbay_sha256: String,
    pub fields: Vec<Field>,
}
#[derive(Debug, Clone, Copy, Serialize)]
pub enum Decision {
    Preserve,
    Replace,
}
#[derive(Debug, Clone, Serialize)]
pub struct AppliedField {
    pub tag: u32,
    pub source_file_offset: u64,
    pub image_offset: u64,
    pub bytes: u32,
    pub decision: Decision,
    pub changed: bool,
    pub source_sha256: String,
    pub configured_sha256: String,
    pub provenance: Provenance,
}
#[derive(Debug, Clone, Serialize)]
pub struct Receipt {
    pub owner: String,
    pub source: crate::boot_bundle::Source,
    pub product_build: String,
    pub hardware: super::HardwareIdentity,
    pub uuid: Option<String>,
    pub original_staged_sha256: String,
    pub patchbay_sha256: String,
    pub fields: Vec<AppliedField>,
    /// Present only when the independent native version5 bootstrap header and
    /// matching SLID patch have been applied together. This remains byte policy.
    pub cold_slide: Option<native::ColdSlideProposal>,
    pub configured_sha256: String,
}
/// Encoded cold image after a complete caller-supplied patch policy. It has no
/// relocation method: original cold bootstrap still owns all encoded chains.
pub struct Configured {
    pub(super) staged: Staged,
    receipt: Receipt,
}
impl Staged {
    pub fn configure(mut self, policy: Policy) -> Result<Configured> {
        let plan = self.plan();
        let bay = plan
            .patchbay
            .as_ref()
            .context("firmware image has no qualified patchbay")?;
        ensure!(
            label(&policy.owner)
                && policy.product_build == plan.product_build
                && policy.hardware_role == plan.hardware.role
                && policy.compatible == plan.hardware.compatible
                && policy.decoded_sha256 == plan.source.decoded_sha256
                && policy.patchbay_sha256 == bay.source_sha256,
            "firmware configuration policy is not bound to this source/build/hardware"
        );
        ensure!(
            policy.fields.len() == bay.records.len(),
            "firmware policy does not cover the complete patchbay"
        );
        let mut tags = BTreeSet::new();
        let mut fields = Vec::new();
        let mut changes = Vec::new();
        for field in policy.fields {
            field.provenance.validate()?;
            ensure!(tags.insert(field.tag), "duplicate firmware policy decision");
            let record = bay
                .records
                .iter()
                .find(|r| r.tag == field.tag)
                .context("firmware policy names absent tag")?;
            let decision = if matches!(field.action, Action::Replace(_)) {
                Decision::Replace
            } else {
                Decision::Preserve
            };
            let hash = match field.action {
                Action::Preserve => record.source_sha256.clone(),
                Action::Replace(value) => {
                    ensure!(
                        value.len() == record.bytes as usize,
                        "firmware patch width disagrees with original record"
                    );
                    let start = record.image_offset;
                    let end = start + u64::from(record.bytes);
                    ensure!(
                        record.bytes == 0
                            || !plan
                                .chains
                                .pointers
                                .iter()
                                .any(|p| p.image_offset < end && start < p.image_offset + 8),
                        "firmware configuration must preserve encoded chained pointers"
                    );
                    let hash = sha256(&value);
                    changes.push((record.image_offset, value));
                    hash
                }
            };
            fields.push(AppliedField {
                tag: record.tag,
                source_file_offset: record.source_file_offset,
                image_offset: record.image_offset,
                bytes: record.bytes,
                decision,
                changed: hash != record.source_sha256,
                source_sha256: record.source_sha256.clone(),
                configured_sha256: hash,
                provenance: field.provenance,
            });
        }
        fields.sort_by_key(|f| f.source_file_offset);
        let mut receipt = Receipt {
            owner: policy.owner,
            source: plan.source.clone(),
            product_build: plan.product_build.clone(),
            hardware: plan.hardware.clone(),
            uuid: plan.uuid.clone(),
            original_staged_sha256: self.placement().staged_sha256.clone(),
            patchbay_sha256: bay.source_sha256.clone(),
            fields,
            cold_slide: None,
            configured_sha256: String::new(),
        };
        // No bytes change until every original field and every source claim has
        // passed validation. Keys stay in owned image bytes, not in the receipt.
        for (offset, value) in changes {
            self.bytes[offset as usize..offset as usize + value.len()].copy_from_slice(&value);
        }
        receipt.configured_sha256 = sha256(&self.bytes);
        Ok(Configured {
            staged: self,
            receipt,
        })
    }
}
impl Configured {
    pub fn plan(&self) -> &Plan {
        self.staged.plan()
    }
    pub fn placement(&self) -> &super::Placement {
        self.staged.placement()
    }
    pub fn bytes(&self) -> &[u8] {
        self.staged.bytes()
    }
    pub fn receipt(&self) -> &Receipt {
        &self.receipt
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::coprocessor::{
        self as configuration_root,
        tests::{fixture, prepare, w32, w64},
    };
    use alloc::vec;
    use configuration_root::configuration;

    pub(in crate::coprocessor) fn config_policy(plan: &Plan) -> configuration::Policy {
        configuration::Policy {
            owner: "synthetic boot policy".into(),
            product_build: plan.product_build.clone(),
            hardware_role: plan.hardware.role.clone(),
            compatible: plan.hardware.compatible.clone(),
            decoded_sha256: plan.source.decoded_sha256.clone(),
            patchbay_sha256: plan.patchbay.as_ref().unwrap().source_sha256.clone(),
            fields: plan
                .patchbay
                .as_ref()
                .unwrap()
                .records
                .iter()
                .map(|r| configuration::Field {
                    tag: r.tag,
                    action: configuration::Action::Preserve,
                    provenance: provenance(),
                })
                .collect(),
        }
    }

    pub(in crate::coprocessor) fn provenance() -> configuration::Provenance {
        configuration::Provenance {
            input_sha256: "1".repeat(64),
            coordinates: "synthetic policy source span".into(),
            span_sha256: "2".repeat(64),
        }
    }

    pub(in crate::coprocessor) fn configured() -> Result<configuration::Configured> {
        let p = prepare(&fixture())?;
        let policy = config_policy(p.plan());
        p.stage(0x800000, 0x3000)?.configure(policy)
    }

    #[test]
    fn complete_configuration_preserves_source_and_encoded_cold_chains() -> Result<()> {
        let p = prepare(&fixture())?;
        let original = p.plan().source.decoded_sha256.clone();
        let bay = p.plan().patchbay.as_ref().unwrap();
        assert_eq!(bay.records.len(), 3);
        assert_eq!(bay.records[2].bytes, 5); // Packed records do not imply alignment.
        let mut policy = config_policy(p.plan());
        policy.fields[0].action = configuration::Action::Replace(123u64.to_le_bytes().to_vec());
        let s = p.stage(0x800000, 0x3000)?;
        let encoded = s.bytes()[0x2000..0x2010].to_vec();
        let c = s.configure(policy)?;
        assert_eq!(c.plan().source.decoded_sha256, original);
        assert_eq!(&c.bytes()[0x2000..0x2010], &encoded);
        assert_eq!(&c.bytes()[0x208..0x210], &123u64.to_le_bytes());
        assert_eq!(c.receipt().fields.iter().filter(|f| f.changed).count(), 1);
        assert_ne!(c.receipt().configured_sha256, c.placement().staged_sha256);
        assert_eq!(
            configured()?.receipt().configured_sha256,
            configured()?.placement().staged_sha256
        );
        Ok(())
    }

    #[test]
    fn configuration_rejects_incomplete_stale_or_malformed_policy() -> Result<()> {
        for case in 0..7 {
            let p = prepare(&fixture())?;
            let mut policy = config_policy(p.plan());
            match case {
                0 => {
                    policy.fields.pop();
                }
                1 => {
                    policy.fields[1].tag = policy.fields[0].tag;
                }
                2 => policy.fields[0].action = configuration::Action::Replace(vec![0; 4]),
                3 => policy.fields[0].tag = 0,
                4 => policy.decoded_sha256 = "3".repeat(64),
                5 => policy.fields[0].provenance.coordinates.clear(),
                _ => policy.hardware_role = "another owner".into(),
            }
            assert!(p.stage(0x800000, 0x3000)?.configure(policy).is_err());
        }
        let mut malformed = fixture();
        w32(&mut malformed, 0x1204, 0x10000);
        assert!(prepare(&malformed).is_err());
        let mut repeated = fixture();
        w32(&mut repeated, 0x1210, 0x50414345);
        assert!(prepare(&repeated).is_err());
        Ok(())
    }

    #[test]
    fn configuration_cannot_replace_original_encoded_fixup_slots() -> Result<()> {
        let mut raw = fixture();
        w32(&mut raw, 0x1108, 0x208);
        w64(&mut raw, 0x1208, (1u64 << 63) | (2u64 << 49));
        let p = prepare(&raw)?;
        let mut policy = config_policy(p.plan());
        policy.fields[0].action = configuration::Action::Replace(vec![0; 8]);
        assert!(p.stage(0x800000, 0x3000)?.configure(policy).is_err());
        Ok(())
    }

    #[test]
    fn packed_zero_width_records_are_explicit_and_never_advance_by_alignment() -> Result<()> {
        let mut raw = fixture();
        w32(&mut raw, 0x1220, 0);
        w64(&mut raw, 32 + 232 + 40, 36);
        let p = prepare(&raw)?;
        let mut policy = config_policy(p.plan());
        assert_eq!(p.plan().patchbay.as_ref().unwrap().records[2].bytes, 0);
        policy.fields[2].action = configuration::Action::Replace(vec![]);
        let c = p.stage(0x800000, 0x3000)?.configure(policy)?;
        assert_eq!(c.receipt().fields[2].bytes, 0);
        assert!(!c.receipt().fields[2].changed);
        Ok(())
    }
}
