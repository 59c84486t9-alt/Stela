//! Exact original segment publication ABI, as an uninstalled parent proposal.
//!
//! AppleA7IOP and RTBuddy consume PA/linked-VA/remap separately. An encoded
//! proposal and ownership identifiers do not establish live allocation/mapping
//! ownership, vendor policy, an initial entry word, or permission to RUN.
use super::{
    Plan,
    configuration::{Configured, Provenance},
    label,
    macho::end,
};
use alloc::{collections::BTreeSet, string::String, vec::Vec};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use stela_runtime::sha256;

pub enum Action {
    /// Deliberate policy decision retained in the proposal, never an implicit
    /// effect of a zero VM size or an unfamiliar segment name.
    Omit,
    Publish {
        iop_remap: u64,
        raw_flags: u32,
    },
}
pub struct SegmentPolicy {
    pub name: String,
    pub action: Action,
    pub provenance: Provenance,
}
pub struct Policy {
    pub allocation_owner: String,
    pub mapping_owner: String,
    pub configured_sha256: String,
    pub segments: Vec<SegmentPolicy>,
}
#[derive(Debug, Clone, Serialize)]
pub struct SegmentRecord {
    pub original_index: usize,
    pub name: String,
    pub physical: u64,
    pub linked_virtual: u64,
    pub iop_remap: u64,
    pub bytes: u32,
    /// bit0 read-only, bit1 omit-DART, bit2 backup, bit3 kernel, bit4 restricted.
    pub raw_flags: u32,
    pub provenance: Provenance,
}
#[derive(Debug, Clone, Serialize)]
pub struct Omitted {
    pub original_index: usize,
    pub name: String,
    pub virtual_bytes: u64,
    pub provenance: Provenance,
}
/// Geometry for a proposed mapping join. This cannot construct EntryHandoff:
/// the parent must establish both real owners and the successful translation.
/// In particular remap address zero is not an authorization derived from PC0.
#[derive(Debug, Clone, Serialize)]
pub struct MappedEntryPlan {
    pub allocation_owner: String,
    pub mapping_owner: String,
    pub original_segment: usize,
    pub linked_virtual: u64,
    pub physical: u64,
    pub iop_remap: u64,
    pub mapped_physical_base: u64,
    pub mapped_iop_base: u64,
    pub mapped_bytes: u32,
    pub raw_flags: u32,
}
#[derive(Debug, Clone, Serialize)]
pub struct Proposal {
    pub allocation_owner: String,
    pub mapping_owner: String,
    pub source: crate::boot_bundle::Source,
    pub product_build: String,
    pub hardware: super::HardwareIdentity,
    pub uuid: Option<String>,
    pub configuration_receipt_sha256: String,
    pub configured_sha256: String,
    pub records: Vec<SegmentRecord>,
    pub omitted: Vec<Omitted>,
    pub entry: MappedEntryPlan,
    /// Actual OSData wire bytes, for both the ASC and nub provider views.
    pub segment_ranges: Vec<u8>,
    /// RTBuddy's semicolon-delimited buffer. No unused trailing name remains.
    pub segment_names: Vec<u8>,
    pub ranges_sha256: String,
    pub names_sha256: String,
}
fn same_entry_segment(plan: &Plan, index: usize) -> bool {
    let s = &plan.segments[index].segment;
    plan.thread.pc >= s.vm_address && plan.thread.pc < s.vm_end()
}
impl Configured {
    /// Build exact property bytes only after explicit policy for every original
    /// segment. No default flags, PA==DVA assumption, or empty-segment policy.
    pub fn publication_proposal(&self, policy: Policy) -> Result<Proposal> {
        let plan = self.plan();
        ensure!(
            label(&policy.allocation_owner)
                && label(&policy.mapping_owner)
                && policy.configured_sha256 == self.receipt().configured_sha256,
            "coprocessor publication lacks source-bound allocation/mapping identity"
        );
        ensure!(
            policy.segments.len() == plan.segments.len(),
            "publication policy does not cover every original segment"
        );
        let mut seen = BTreeSet::new();
        let mut records: Vec<SegmentRecord> = Vec::new();
        let mut omitted = Vec::new();
        let mut entry = None;
        for decision in policy.segments {
            decision.provenance.validate()?;
            ensure!(
                seen.insert(decision.name.clone()),
                "repeated coprocessor publication decision"
            );
            let (index, map) = plan
                .segments
                .iter()
                .enumerate()
                .find(|(_, s)| s.segment.name == decision.name)
                .context("publication policy names an absent segment")?;
            let segment = &map.segment;
            match decision.action {
                Action::Omit => {
                    ensure!(
                        !same_entry_segment(plan, index),
                        "cannot omit the coprocessor entry segment"
                    );
                    omitted.push(Omitted {
                        original_index: index,
                        name: decision.name,
                        virtual_bytes: segment.vm_size,
                        provenance: decision.provenance,
                    });
                }
                Action::Publish {
                    iop_remap,
                    raw_flags,
                } => {
                    ensure!(
                        segment.vm_size != 0,
                        "empty-segment publication semantics are not qualified"
                    );
                    ensure!(
                        raw_flags & !0x1f == 0,
                        "unknown original segment publication flags"
                    );
                    ensure!(
                        !decision.name.is_empty()
                            && !decision.name.bytes().any(|b| b == 0 || b == b';'),
                        "segment name cannot be encoded in original publication ABI"
                    );
                    let bytes = u32::try_from(segment.vm_size)
                        .context("segment size exceeds publication ABI")?;
                    let remap_end = end(iop_remap, segment.vm_size)?;
                    for r in &records {
                        ensure!(
                            iop_remap >= end(r.iop_remap, u64::from(r.bytes))?
                                || r.iop_remap >= remap_end,
                            "overlapping coprocessor publication remap ranges"
                        );
                    }
                    let physical =
                        self.placement().physical_base + (segment.vm_address - plan.vm_base);
                    if same_entry_segment(plan, index) {
                        let offset = plan.thread.pc - segment.vm_address;
                        entry = Some(MappedEntryPlan {
                            allocation_owner: policy.allocation_owner.clone(),
                            mapping_owner: policy.mapping_owner.clone(),
                            original_segment: index,
                            linked_virtual: plan.thread.pc,
                            physical: physical + offset,
                            iop_remap: end(iop_remap, offset)?,
                            mapped_physical_base: physical,
                            mapped_iop_base: iop_remap,
                            mapped_bytes: bytes,
                            raw_flags,
                        });
                    }
                    records.push(SegmentRecord {
                        original_index: index,
                        name: decision.name,
                        physical,
                        linked_virtual: segment.vm_address,
                        iop_remap,
                        bytes,
                        raw_flags,
                        provenance: decision.provenance,
                    });
                }
            }
        }
        records.sort_by_key(|r| r.original_index);
        omitted.sort_by_key(|r| r.original_index);
        let entry = entry.context("publication has no mapped entry instruction")?;
        let mut segment_ranges = Vec::new();
        let mut segment_names = Vec::new();
        for r in &records {
            for v in [r.physical, r.linked_virtual, r.iop_remap] {
                segment_ranges.extend(v.to_le_bytes());
            }
            segment_ranges.extend(r.bytes.to_le_bytes());
            segment_ranges.extend(r.raw_flags.to_le_bytes());
            segment_names.extend(r.name.as_bytes());
            segment_names.push(b';');
        }
        Ok(Proposal {
            allocation_owner: policy.allocation_owner,
            mapping_owner: policy.mapping_owner,
            source: plan.source.clone(),
            product_build: plan.product_build.clone(),
            hardware: plan.hardware.clone(),
            uuid: plan.uuid.clone(),
            configuration_receipt_sha256: sha256(&serde_json::to_vec(self.receipt())?),
            configured_sha256: self.receipt().configured_sha256.clone(),
            ranges_sha256: sha256(&segment_ranges),
            names_sha256: sha256(&segment_names),
            records,
            omitted,
            entry,
            segment_ranges,
            segment_names,
        })
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::coprocessor::{
        self as publication_root,
        tests::{fixture, name, prepare, w32, w64},
    };
    use configuration::tests::{config_policy, configured, provenance};
    use publication_root::{configuration, publication};

    pub(in crate::coprocessor) fn publication_policy(
        c: &configuration::Configured,
    ) -> publication::Policy {
        publication::Policy {
            allocation_owner: "allocation fixture1".into(),
            mapping_owner: "DART fixture1".into(),
            configured_sha256: c.receipt().configured_sha256.clone(),
            segments: vec![
                publication::SegmentPolicy {
                    name: "__TEXT".into(),
                    action: publication::Action::Publish {
                        iop_remap: 0x100000,
                        raw_flags: 1,
                    },
                    provenance: provenance(),
                },
                publication::SegmentPolicy {
                    name: "__DATA".into(),
                    action: publication::Action::Publish {
                        iop_remap: 0x200000,
                        raw_flags: 4,
                    },
                    provenance: provenance(),
                },
            ],
        }
    }

    #[test]
    fn publication_keeps_three_domains_and_exact_complete_wire_records() -> Result<()> {
        let c = configured()?;
        let proposal = c.publication_proposal(publication_policy(&c))?;
        assert_eq!(proposal.segment_ranges.len(), 64);
        assert_eq!(proposal.segment_names, b"__TEXT;__DATA;");
        let q = |at| u64::from_le_bytes(proposal.segment_ranges[at..at + 8].try_into().unwrap());
        assert_eq!((q(0), q(8), q(16)), (0x800000, 0, 0x100000));
        assert_eq!(
            (
                proposal.entry.linked_virtual,
                proposal.entry.physical,
                proposal.entry.iop_remap
            ),
            (0, 0x800000, 0x100000)
        );
        assert_eq!(
            (
                proposal.records[1].physical,
                proposal.records[1].linked_virtual,
                proposal.records[1].iop_remap
            ),
            (0x802000, 0x2000, 0x200000)
        );
        let mut policy = publication_policy(&c);
        policy.segments[0].action = publication::Action::Publish {
            iop_remap: 0,
            raw_flags: 1,
        };
        let zero = c.publication_proposal(policy)?;
        assert_eq!(zero.entry.iop_remap, 0);
        assert_ne!(zero.entry.physical, 0); // Proposal only, never an ASC authorization.
        Ok(())
    }

    #[test]
    fn publication_refuses_implicit_or_overlapping_owner_policy() -> Result<()> {
        let c = configured()?;
        for case in 0..7 {
            let mut policy = publication_policy(&c);
            match case {
                0 => {
                    policy.segments.pop();
                }
                1 => policy.segments[0].action = publication::Action::Omit,
                2 => {
                    policy.segments[1].action = publication::Action::Publish {
                        iop_remap: 0x100800,
                        raw_flags: 4,
                    }
                }
                3 => {
                    policy.segments[0].action = publication::Action::Publish {
                        iop_remap: u64::MAX,
                        raw_flags: 1,
                    }
                }
                4 => {
                    policy.segments[0].action = publication::Action::Publish {
                        iop_remap: 0x100000,
                        raw_flags: 0x20,
                    }
                }
                5 => policy.mapping_owner.clear(),
                _ => policy.configured_sha256 = "3".repeat(64),
            }
            assert!(c.publication_proposal(policy).is_err());
        }
        let mut policy = publication_policy(&c);
        policy.segments[1].action = publication::Action::Omit;
        let omitted = c.publication_proposal(policy)?;
        assert_eq!(omitted.omitted.len(), 1);
        assert_eq!(omitted.omitted[0].virtual_bytes, 0x100);
        Ok(())
    }

    #[test]
    fn empty_segment_decision_is_explicit_and_publication_stays_unqualified() -> Result<()> {
        let mut raw = fixture();
        w32(&mut raw, 16, 5);
        w32(&mut raw, 20, 768);
        let at = 728;
        w32(&mut raw, at, 0x19);
        w32(&mut raw, at + 4, 72);
        name(&mut raw, at + 8, "__EMPTY");
        w64(&mut raw, at + 24, 0x2100);
        w64(&mut raw, at + 40, 0x2010);
        w32(&mut raw, at + 56, 3);
        w32(&mut raw, at + 60, 3);
        let p = prepare(&raw)?;
        let policy = config_policy(p.plan());
        let c = p.stage(0x800000, 0x3000)?.configure(policy)?;
        assert!(c.publication_proposal(publication_policy(&c)).is_err());
        let mut policy = publication_policy(&c);
        policy.segments.push(publication::SegmentPolicy {
            name: "__EMPTY".into(),
            action: publication::Action::Omit,
            provenance: provenance(),
        });
        let proposal = c.publication_proposal(policy)?;
        assert_eq!(proposal.omitted[0].name, "__EMPTY");
        let mut policy = publication_policy(&c);
        policy.segments.push(publication::SegmentPolicy {
            name: "__EMPTY".into(),
            action: publication::Action::Publish {
                iop_remap: 0x300000,
                raw_flags: 0,
            },
            provenance: provenance(),
        });
        assert!(c.publication_proposal(policy).is_err());
        Ok(())
    }
}
