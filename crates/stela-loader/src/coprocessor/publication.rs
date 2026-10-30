//! Original segment publication ABI, as an uninstalled parent proposal.
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
use crate::Result;
use alloc::{collections::BTreeSet, string::String, vec::Vec};
use serde::Serialize;
use stela_contracts::{refuse, require};
use stela_formats::sha256;

/// Selected native policy inputs, before packing the wire flag word.
/// These internal flags are not Mach-O protections. Their other allocation,
/// isolation and lifecycle effects remain with the corresponding parent owners.
pub struct NativeFlagsInput {
    pub internal_segment_flags: u32,
    pub kernel: bool,
    pub per_firmware_isolation: u64,
    pub telemetry_handoff_restricted: u64,
    pub segment_provenance: Provenance,
    pub kernel_provenance: Provenance,
    pub isolation_provenance: Provenance,
    pub telemetry_provenance: Provenance,
}

/// A kept derivation, not certification of the caller's selected policy.
#[derive(Debug, Clone, Serialize)]
pub struct NativeFlags {
    raw_flags: u32,
    internal_segment_flags: u32,
    kernel: bool,
    per_firmware_isolation: u64,
    telemetry_handoff_restricted: u64,
    segment_provenance: Provenance,
    kernel_provenance: Provenance,
    isolation_provenance: Provenance,
    telemetry_provenance: Provenance,
}
impl NativeFlags {
    /// iBoot1505e8..1506c0. In particular read-only suppresses backup, and
    /// isolation values compare exactly to one rather than testing nonzero.
    pub fn derive(input: NativeFlagsInput) -> Result<Self> {
        for provenance in [
            &input.segment_provenance,
            &input.kernel_provenance,
            &input.isolation_provenance,
            &input.telemetry_provenance,
        ] {
            provenance.validate()?;
        }
        let s = input.internal_segment_flags;
        let read_only = (s >> 1) & 1;
        let backup = if read_only != 0 { 0 } else { (s >> 4) & 4 };
        let restricted = s & (1 << 12) != 0
            && (s & (1 << 13) != 0
                || input.per_firmware_isolation == 1
                || input.telemetry_handoff_restricted == 1);
        Ok(Self {
            raw_flags: read_only
                | ((s >> 4) & 2)
                | backup
                | (u32::from(input.kernel) << 3)
                | (u32::from(restricted) << 4),
            internal_segment_flags: s,
            kernel: input.kernel,
            per_firmware_isolation: input.per_firmware_isolation,
            telemetry_handoff_restricted: input.telemetry_handoff_restricted,
            segment_provenance: input.segment_provenance,
            kernel_provenance: input.kernel_provenance,
            isolation_provenance: input.isolation_provenance,
            telemetry_provenance: input.telemetry_provenance,
        })
    }
    pub fn raw_flags(&self) -> u32 {
        self.raw_flags
    }
}

#[derive(Clone)]
pub enum Action {
    /// Deliberate policy decision kept in the proposal, never an implicit
    /// effect of a zero VM size or an unfamiliar segment name.
    Omit,
    Publish {
        iop_remap: u64,
        raw_flags: u32,
    },
}
#[derive(Clone)]
pub struct SegmentPolicy {
    pub name: String,
    pub action: Action,
    pub provenance: Provenance,
}
#[derive(Clone)]
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
    /// OSData wire bytes, for both the ASC and nub provider views.
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
        let proposal = self.publication_preview(policy)?;
        self.validate_finalization(&proposal)?;
        Ok(proposal)
    }

    pub(in crate::coprocessor) fn publication_preview(&self, policy: Policy) -> Result<Proposal> {
        self.validate_tuning()?;
        let plan = self.plan();
        require!(
            label(&policy.allocation_owner)
                && label(&policy.mapping_owner)
                && policy.configured_sha256 == self.receipt().configured_sha256,
            "coprocessor publication lacks source-bound allocation/mapping identity"
        );
        require!(
            policy.segments.len() == plan.segments.len(),
            "publication policy does not cover every original segment"
        );
        let mut seen = BTreeSet::new();
        let mut records: Vec<SegmentRecord> = Vec::new();
        let mut omitted = Vec::new();
        let mut entry = None;
        for decision in policy.segments {
            decision.provenance.validate()?;
            require!(
                seen.insert(decision.name.clone()),
                "repeated coprocessor publication decision"
            );
            let (index, map) = plan
                .segments
                .iter()
                .enumerate()
                .find(|(_, s)| s.segment.name == decision.name)
                .ok_or(refuse!("publication policy names an absent segment"))?;
            let segment = &map.segment;
            match decision.action {
                Action::Omit => {
                    require!(
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
                    require!(
                        segment.vm_size != 0,
                        "empty-segment publication semantics are not qualified"
                    );
                    require!(
                        raw_flags & !0x1f == 0,
                        "unknown original segment publication flags"
                    );
                    require!(
                        !decision.name.is_empty()
                            && !decision.name.bytes().any(|b| b == 0 || b == b';'),
                        "segment name cannot be encoded in original publication ABI"
                    );
                    let bytes = u32::try_from(segment.vm_size)
                        .map_err(|_| refuse!("segment size exceeds publication ABI"))?;
                    let remap_end = end(iop_remap, segment.vm_size)?;
                    for r in &records {
                        require!(
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
        let entry = entry.ok_or(refuse!("publication has no mapped entry instruction"))?;
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
    use anyhow::Result;
    use configuration::tests::{config_policy, configured, provenance};
    use publication_root::{configuration, publication};

    fn native_flags(s: u32, isolation: u64, telemetry: u64, kernel: bool) -> NativeFlagsInput {
        NativeFlagsInput {
            internal_segment_flags: s,
            kernel,
            per_firmware_isolation: isolation,
            telemetry_handoff_restricted: telemetry,
            segment_provenance: provenance(),
            kernel_provenance: provenance(),
            isolation_provenance: provenance(),
            telemetry_provenance: provenance(),
        }
    }

    #[test]
    fn native_flags_preserve_independent_omit_backup_and_exact_isolation_conditions() -> Result<()>
    {
        // The default native OS_LOG descriptor604 converts to internal121.
        assert_eq!(
            NativeFlags::derive(native_flags(0x121, 0, 0, false))?.raw_flags(),
            2
        );
        assert_eq!(
            NativeFlags::derive(native_flags(0x60, 0, 0, false))?.raw_flags(),
            6
        );
        assert_eq!(
            NativeFlags::derive(native_flags(0x62, 0, 0, false))?.raw_flags(),
            3
        );
        for (s, isolation, telemetry, expected) in [
            (0, 1, 1, 0),
            (0x1000, 0, 0, 0),
            (0x1000, 2, u64::MAX, 0),
            (0x1000, 1, 0, 16),
            (0x1000, 0, 1, 16),
            (0x3000, 0, 0, 16),
        ] {
            assert_eq!(
                NativeFlags::derive(native_flags(s, isolation, telemetry, false))?.raw_flags(),
                expected
            );
        }
        let all = NativeFlags::derive(native_flags(u32::MAX, 2, 2, true))?;
        assert_eq!(all.raw_flags(), 0x1b);
        let receipt = serde_json::to_value(all)?;
        assert_eq!(receipt["internal_segment_flags"], u32::MAX);
        assert_eq!(receipt["per_firmware_isolation"], 2);
        let mut unknown = native_flags(0x121, 0, 0, false);
        unknown.isolation_provenance.coordinates.clear();
        assert!(NativeFlags::derive(unknown).is_err());
        Ok(())
    }

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
