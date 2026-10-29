//! Native format1 UUID-header/dseg finalization after map selection.
//!
//! These are original image metadata effects. Proposed mappings and provenance
//! remain claims until the parent keeps allocation/mapping/fetch owners.
use super::{Configured, Provenance};
use crate::coprocessor::publication;
use alloc::{collections::BTreeSet, string::String, vec::Vec};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use stela_formats::sha256;

const DSEG: u32 = u32::from_le_bytes(*b"dseg");
const RECORD_BYTES: usize = 16;
const ENTRY_BYTES: usize = 32;

pub struct Input {
    /// Selected descriptor+0x265; bit2 skips native finalization. Other
    /// bits keep their independent native effects with the parent owners.
    pub descriptor_flags: u8,
    pub provenance: Provenance,
}

#[derive(Debug, Clone, Serialize)]
pub struct Write {
    pub image_offset: u64,
    pub source_file_offset: u64,
    pub before: u64,
    pub after: u64,
}
#[derive(Debug, Clone, Serialize)]
pub struct Receipt {
    pub descriptor_flags: u8,
    pub provenance: Provenance,
    pub mapping_snapshot_sha256: String,
    pub writes: Vec<Write>,
    pub original_configured_sha256: String,
    pub configured_sha256: String,
    pub metadata_records: Vec<u64>,
}

fn u32_at(bytes: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes
            .get(at..)
            .and_then(|b| b.get(..4))
            .context("truncated native finalization u32")?
            .try_into()?,
    ))
}
fn u64_at(bytes: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        bytes
            .get(at..)
            .and_then(|b| b.get(..8))
            .context("truncated native finalization u64")?
            .try_into()?,
    ))
}
fn snapshot(proposal: &publication::Proposal) -> Result<String> {
    // The complete selected geometry/flags/provenance and omitted family stay
    // bound to this pass. Do not hash its old configured-image identity here.
    Ok(sha256(&serde_json::to_vec(&(
        &proposal.allocation_owner,
        &proposal.mapping_owner,
        &proposal.records,
        &proposal.omitted,
    ))?))
}
fn moved(
    segment: Option<&publication::SegmentRecord>,
    text: Option<&publication::SegmentRecord>,
) -> u64 {
    let (Some(segment), Some(text)) = (segment, text) else {
        return 0;
    };
    let linked = segment.linked_virtual.overflowing_sub(text.linked_virtual);
    let remap = segment.iop_remap.overflowing_sub(text.iop_remap);
    if linked != remap {
        segment.iop_remap
    } else {
        0
    }
}

impl Configured {
    fn file_backed(&self, at: u64, bytes: usize) -> Result<u64> {
        let linked = self
            .plan()
            .vm_base
            .checked_add(at)
            .context("native metadata linked address overflows")?;
        let end = linked
            .checked_add(bytes as u64)
            .context("native metadata extent overflows")?;
        let segment = self
            .plan()
            .segments
            .iter()
            .find(|s| {
                linked >= s.segment.vm_address && end <= s.segment.vm_address + s.segment.file_size
            })
            .context("native metadata is not wholly file-backed")?;
        Ok(segment.segment.file_offset + linked - segment.segment.vm_address)
    }
    fn native_bytes(&self, at: u64, bytes: usize) -> Result<&[u8]> {
        self.file_backed(at, bytes)?;
        self.bytes()
            .get(usize::try_from(at)?..)
            .and_then(|b| b.get(..bytes))
            .context("native metadata exceeds owned bytes")
    }
    fn final_write(&self, writes: &mut Vec<Write>, at: u64, value: u64) -> Result<()> {
        let old = u64_at(self.native_bytes(at, 8)?, 0)?;
        ensure!(
            old == 0 || old == value,
            "native metadata write conflicts with an existing value"
        );
        ensure!(
            !self
                .plan()
                .chains
                .pointers
                .iter()
                .any(|p| p.image_offset < at + 8 && at < p.image_offset + 8),
            "native metadata write overlaps an encoded cold chain"
        );
        if let Some(bay) = &self.plan().patchbay {
            ensure!(
                bay.records
                    .iter()
                    .all(|r| at + 8 <= r.image_offset.saturating_sub(8)
                        || at >= r.image_offset + u64::from(r.bytes)),
                "native metadata write overlaps patchbay"
            );
        }
        if let Some(tuning) = &self.receipt.tuning {
            ensure!(
                at + 8 <= tuning.target_image_offset
                    || at >= tuning.target_image_offset + u64::from(tuning.target_bytes),
                "native metadata write overlaps tuning target"
            );
        }
        if let Some(prior) = writes
            .iter()
            .find(|w| w.image_offset < at + 8 && at < w.image_offset + 8)
        {
            ensure!(
                prior.image_offset == at && prior.after == value,
                "native metadata writes overlap or disagree"
            );
            return Ok(());
        }
        if old != value {
            writes.push(Write {
                image_offset: at,
                source_file_offset: self.file_backed(at, 8)?,
                before: old,
                after: value,
            });
        }
        Ok(())
    }

    /// Native10f4d0 finalizes after patch callbacks.10f958 compares linked and
    /// remap subtraction results *including carry*.10f9c4 permits only zero or
    /// an already equal value. dseg v1 shared entries also match exact nonzero
    /// extent. All writes are preflighted before this owned image changes.
    pub fn finalize_cold_mappings(
        mut self,
        mut policy: publication::Policy,
        input: Input,
    ) -> Result<(Self, publication::Policy)> {
        input.provenance.validate()?;
        ensure!(
            self.receipt.finalization.is_none(),
            "native metadata was already finalized"
        );
        let header = self
            .receipt
            .cold_slide
            .as_ref()
            .context("native finalization requires qualified cold bootstrap header")?
            .header_image_offset();
        let proposal = self.publication_preview(policy.clone())?;
        let mapping_snapshot_sha256 = snapshot(&proposal)?;
        let mut writes = Vec::new();
        let mut metadata_records = Vec::new();
        if input.descriptor_flags & 4 == 0 {
            let find = |name: &str| proposal.records.iter().find(|s| s.name == name);
            let text = find("__TEXT");
            let data = moved(find("__DATA"), text);
            if data != 0 {
                self.final_write(&mut writes, header + 0x38, data)?;
            }
            let first = u32_at(self.native_bytes(header, 0x40)?, 0x34)?;
            let mut next = first;
            let mut seen = BTreeSet::new();
            while next != 0 {
                ensure!(
                    seen.len() < 4096 && seen.insert(next),
                    "native metadata list cycles or exceeds its bound"
                );
                let at = header
                    .checked_add(u64::from(next))
                    .context("native metadata relative offset overflows")?;
                let record = self.native_bytes(at, RECORD_BYTES)?;
                metadata_records.push(at);
                if u32_at(record, 0)? == DSEG && u32_at(record, 4)? == 1 {
                    let count = u32_at(record, 12)? as usize;
                    let extent = count
                        .checked_mul(ENTRY_BYTES)
                        .and_then(|n| n.checked_add(RECORD_BYTES))
                        .context("native dseg extent overflows")?;
                    let entries = self.native_bytes(at, extent)?;
                    let ro = find("__DATA_SHARED_RO");
                    let rw = find("__DATA_SHARED_RW");
                    let ro_moved = moved(ro, text);
                    let rw_moved = moved(rw, text);
                    let required = usize::from(ro_moved != 0) + usize::from(rw_moved != 0);
                    ensure!(
                        count >= required,
                        "native dseg has fewer entries than moved shared segments"
                    );
                    for (segment, value) in [(ro, ro_moved), (rw, rw_moved)] {
                        if value == 0 {
                            continue;
                        }
                        let segment = segment.context("native moved shared segment is absent")?;
                        for index in 0..count {
                            let offset = RECORD_BYTES + index * ENTRY_BYTES;
                            if u64_at(entries, offset + 8)? == segment.linked_virtual
                                && u64_at(entries, offset + 16)? != 0
                                && u64_at(entries, offset + 16)? == u64::from(segment.bytes)
                            {
                                self.final_write(&mut writes, at + offset as u64, value)?;
                            }
                        }
                    }
                    break; // Native uses the first matching version1 record.
                }
                next = u32_at(record, 8)?;
            }
        }
        let before = self.receipt.configured_sha256.clone();
        for write in &writes {
            let at = usize::try_from(write.image_offset)?;
            self.staged.bytes[at..at + 8].copy_from_slice(&write.after.to_le_bytes());
        }
        let after = sha256(self.bytes());
        self.receipt.finalization = Some(Receipt {
            descriptor_flags: input.descriptor_flags,
            provenance: input.provenance,
            mapping_snapshot_sha256,
            writes,
            original_configured_sha256: before,
            configured_sha256: after.clone(),
            metadata_records,
        });
        self.receipt.configured_sha256 = after.clone();
        policy.configured_sha256 = after;
        Ok((self, policy))
    }

    pub(in crate::coprocessor) fn validate_finalization(
        &self,
        proposal: &publication::Proposal,
    ) -> Result<()> {
        if self.receipt.cold_slide.is_none() {
            return Ok(());
        }
        let receipt = self
            .receipt
            .finalization
            .as_ref()
            .context("cold native metadata must be finalized before publication")?;
        ensure!(
            snapshot(proposal)? == receipt.mapping_snapshot_sha256,
            "publication maps differ from finalized native metadata"
        );
        ensure!(
            sha256(self.bytes()) == receipt.configured_sha256,
            "cold native bytes changed after metadata finalization"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coprocessor::{
        configuration::{
            native::tests::{slide_fixture, slide_input},
            tests::{config_policy, provenance},
        },
        tests::{name, prepare, w32, w64},
    };

    fn configured(mut raw: Vec<u8>, shared: bool) -> Result<Configured> {
        if shared {
            raw.resize(0x2300, 0);
            w32(&mut raw, 16, 6);
            w32(&mut raw, 20, 840);
            for (at, segment_name, vm, file) in [
                (728, "__DATA_SHARED_RO", 0x1000, 0x2100),
                (800, "__DATA_SHARED_RW", 0x1100, 0x2200),
            ] {
                w32(&mut raw, at, 0x19);
                w32(&mut raw, at + 4, 72);
                name(&mut raw, at + 8, segment_name);
                for (o, v) in [(24, vm), (32, 0x100), (40, file), (48, 0x100)] {
                    w64(&mut raw, at + o, v);
                }
                w32(&mut raw, at + 56, 3);
                w32(&mut raw, at + 60, 3);
            }
        }
        let p = prepare(&raw)?;
        let mut policy = config_policy(p.plan());
        let s = p.stage(0x800000, 0x3000)?;
        let slide = s.cold_slide_proposal(slide_input(0x40, 0))?;
        *policy
            .fields
            .iter_mut()
            .find(|f| f.tag == u32::from_be_bytes(*b"SLID"))
            .unwrap() = slide.field(provenance())?;
        s.configure_cold(policy, slide)
    }
    fn policy(c: &Configured, data_remap: u64) -> publication::Policy {
        publication::Policy {
            allocation_owner: "synthetic allocation".into(),
            mapping_owner: "synthetic map".into(),
            configured_sha256: c.receipt().configured_sha256.clone(),
            segments: c
                .plan()
                .segments
                .iter()
                .map(|s| publication::SegmentPolicy {
                    name: s.segment.name.clone(),
                    action: publication::Action::Publish {
                        iop_remap: match s.segment.name.as_str() {
                            "__TEXT" => 0,
                            "__DATA" => data_remap,
                            "__DATA_SHARED_RO" => 0x4000,
                            _ => 0x5000,
                        },
                        raw_flags: 0,
                    },
                    provenance: provenance(),
                })
                .collect(),
        }
    }
    fn input(flags: u8) -> Input {
        Input {
            descriptor_flags: flags,
            provenance: provenance(),
        }
    }

    #[test]
    fn uniform_maps_retain_header_and_nonuniform_maps_install_data_remap_base() -> Result<()> {
        for (remap, expected) in [(0x2000, 0), (0x8000, 0x8000)] {
            let c = configured(slide_fixture(), false)?;
            let p = policy(&c, remap);
            assert!(c.publication_proposal(p.clone()).is_err());
            let (c, p) = c.finalize_cold_mappings(p, input(0))?;
            assert_eq!(u64_at(c.bytes(), 0x58)?, expected);
            assert_eq!(p.configured_sha256, sha256(c.bytes()));
            c.publication_proposal(p)?;
        }
        Ok(())
    }
    #[test]
    fn dseg_updates_both_exact_shared_entries_and_preserves_rest() -> Result<()> {
        let mut raw = slide_fixture();
        w32(&mut raw, 0x1054, 0x7e0);
        for (at, value) in [(0x1800, DSEG), (0x1804, 1), (0x180c, 2)] {
            w32(&mut raw, at, value);
        }
        for (at, linked) in [(0x1810, 0x1000), (0x1830, 0x1100)] {
            w64(&mut raw, at + 8, linked);
            w64(&mut raw, at + 16, 0x100);
        }
        let c = configured(raw, true)?;
        let before = c.bytes().to_vec();
        let p = policy(&c, 0x2000);
        let (c, p) = c.finalize_cold_mappings(p, input(0))?;
        assert_eq!(u64_at(c.bytes(), 0x810)?, 0x4000);
        assert_eq!(u64_at(c.bytes(), 0x830)?, 0x5000);
        assert_eq!(&c.bytes()[0x818..0x830], &before[0x818..0x830]);
        assert_eq!(c.receipt().finalization.as_ref().unwrap().writes.len(), 2);
        c.publication_proposal(p)?;
        Ok(())
    }
    #[test]
    fn cycles_conflicting_words_and_short_dseg_fail_before_publication() -> Result<()> {
        for case in 0..3 {
            let mut raw = slide_fixture();
            if case == 0 {
                w64(&mut raw, 0x1058, 0x1234);
            } else {
                w32(&mut raw, 0x1054, 0x7e0);
                if case == 1 {
                    w32(&mut raw, 0x1808, 0x7e0);
                } else {
                    w32(&mut raw, 0x1800, DSEG);
                    w32(&mut raw, 0x1804, 1);
                    w32(&mut raw, 0x180c, 1);
                }
            }
            let c = configured(raw, case == 2)?;
            let p = policy(&c, 0x8000);
            assert!(
                c.finalize_cold_mappings(p, input(0)).is_err(),
                "case {case}"
            );
        }
        Ok(())
    }
    #[test]
    fn actual_skip_flag_and_mapping_receipt_remain_bound() -> Result<()> {
        let mut raw = slide_fixture();
        w64(&mut raw, 0x1058, 0x1234);
        let c = configured(raw, false)?;
        let p = policy(&c, 0x8000);
        let (c, mut p) = c.finalize_cold_mappings(p, input(4))?;
        assert_eq!(u64_at(c.bytes(), 0x58)?, 0x1234);
        c.publication_proposal(p.clone())?;
        p.mapping_owner = "other actual map".into();
        assert!(c.publication_proposal(p).is_err());
        Ok(())
    }
    #[test]
    fn moved_comparison_preserves_unsigned_subtraction_carry() {
        let segment = |linked_virtual, iop_remap| publication::SegmentRecord {
            original_index: 0,
            name: "synthetic".into(),
            physical: 0x800000,
            linked_virtual,
            iop_remap,
            bytes: 8,
            raw_flags: 0,
            provenance: provenance(),
        };
        assert_eq!(moved(Some(&segment(0, 0)), Some(&segment(4, 4))), 0);
        assert_eq!(
            moved(Some(&segment(4, 0)), Some(&segment(0, u64::MAX - 3))),
            0
        ); // remap zero remains native no-write.
        assert_eq!(moved(Some(&segment(4, 8)), Some(&segment(0, 4))), 0);
        assert_eq!(moved(Some(&segment(4, 8)), Some(&segment(0, 0))), 8);
        assert_eq!(
            moved(Some(&segment(0, u64::MAX - 3)), Some(&segment(4, 0))),
            u64::MAX - 3
        );
        assert_eq!(moved(None, Some(&segment(0, 0))), 0);
    }
}
