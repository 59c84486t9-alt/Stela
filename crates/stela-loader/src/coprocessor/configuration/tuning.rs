//! Native bounded TUNS/TUNZ mutation, separate from patchbay scalar decisions.
//!
//! Selected original source tables remain input data. Preparation neither
//! executes their register writes nor establishes backing, mappings or entry.
use super::{Configured, Provenance, source_record};
use crate::coprocessor::Staged;
use alloc::vec::Vec;
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use stela_runtime::sha256;

pub mod source;

const ADDRESS: u32 = u32::from_be_bytes(*b"TUNS");
const LENGTH: u32 = u32::from_be_bytes(*b"TUNZ");
const OFFSET_MASK: u32 = 0x07ff_ffff;
const HEADER_BYTES: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Width {
    Bits32,
    Bits64,
}
impl Width {
    fn bytes(self) -> usize {
        match self {
            Self::Bits32 => 12,
            Self::Bits64 => 20,
        }
    }
}

/// One selected, sentinel-terminated native table. Constructors verify bounds
/// and source hashes; the parent still owns hardware/revision selection inputs.
pub struct Table {
    width: Width,
    records: Vec<u8>,
    source: source::Selection,
}

/// The original compiled provider returns no override. A required dynamic
/// provider is refused until its distinct format and selection are qualified.
/// Absence must be explicitly established by the actual provider.
pub enum Override {
    Absent(Provenance),
    Required(Provenance),
}
pub struct Phase {
    /// None is permitted only for a source-qualified empty provider, whose
    /// output is independent of its runtime phase bit.
    pub enabled: Option<bool>,
    pub provenance: Provenance,
    pub table: Option<Table>,
}
pub struct Tables {
    pub provenance: Provenance,
    pub primary: Option<Table>,
    pub additional: [Phase; 2],
}
pub struct Input {
    pub native_override: Override,
    pub compiled: Tables,
}

#[derive(Debug, Clone, Serialize)]
pub struct Receipt {
    pub source: crate::boot_bundle::Source,
    pub product_build: alloc::string::String,
    pub hardware: crate::coprocessor::HardwareIdentity,
    pub uuid: Option<alloc::string::String>,
    pub original_staged_sha256: alloc::string::String,
    pub target_linked: u64,
    pub target_image_offset: u64,
    pub target_source_file_offset: u64,
    pub target_bytes: u32,
    pub original_target_sha256: alloc::string::String,
    pub configured_target_sha256: alloc::string::String,
    pub kind: u8,
    pub width: Width,
    pub capacity: u8,
    pub entries: u8,
    pub absent_override: Provenance,
    pub provider_provenance: Provenance,
    pub selected_sources: Vec<source::Selection>,
    pub phases: [Provenance; 2],
    pub enabled_phases: [Option<bool>; 2],
}
/// Owned byte proposal bound to the original image and both patchbay scalars.
pub struct Proposal {
    receipt: Receipt,
    bytes: Vec<u8>,
    address_source_sha256: alloc::string::String,
    length_source_sha256: alloc::string::String,
}
impl Proposal {
    pub fn receipt(&self) -> &Receipt {
        &self.receipt
    }
}

impl Staged {
    /// iBoot 0x113954 copies the entire TUNS range, runs 0x1133a8 and copies back.
    /// Its parser preserves the header/capacity and untouched tail, clears the
    /// upper five source offset bits, and stores the actual count at header +3.
    /// Unknown kinds/flags and capacity overflow are explicit unsupported cases.
    pub fn tuning_proposal(&self, input: Input) -> Result<Proposal> {
        let (address_record, address) = source_record(self, ADDRESS)?;
        let (length_record, length) = source_record(self, LENGTH)?;
        ensure!(
            address.len() == 8 && length.len() == 4,
            "native tuning scalar widths disagree"
        );
        let linked = u64::from_le_bytes(address.try_into()?);
        let length = u32::from_le_bytes(length.try_into()?);
        ensure!(
            linked != 0 && length != 0,
            "absent/empty native tuning family is not qualified"
        );
        let offset = linked
            .checked_sub(self.plan().vm_base)
            .context("native tuning precedes image")?;
        let end = offset
            .checked_add(u64::from(length))
            .context("native tuning range overflows")?;
        let at = usize::try_from(offset)?;
        let raw = self
            .bytes()
            .get(at..)
            .and_then(|b| b.get(..length as usize))
            .context("native tuning exceeds image")?;
        ensure!(raw.len() >= HEADER_BYTES, "truncated native tuning header");
        ensure!(
            [1, 3].contains(&raw[0]),
            "native tuning kind is not qualified"
        );
        ensure!(raw[1] & !1 == 2, "native tuning flags are not qualified");
        let width = if raw[1] & 1 != 0 {
            Width::Bits64
        } else {
            Width::Bits32
        };
        let capacity = raw[2];
        ensure!(capacity != 0, "native tuning capacity is zero");
        ensure!(
            HEADER_BYTES + usize::from(capacity) * width.bytes() <= raw.len(),
            "native tuning capacity exceeds its range"
        );
        // Restrict mutation to original file-backed bytes. A source VA alone
        // does not authorize writes into padding, zero tails or another region.
        let segment = self
            .plan()
            .segments
            .iter()
            .find(|s| {
                linked >= s.segment.vm_address
                    && linked
                        .checked_add(u64::from(length))
                        .is_some_and(|e| e <= s.segment.vm_address + s.segment.file_size)
            })
            .context("native tuning is not wholly file-backed")?;
        let target_source_file_offset =
            segment.segment.file_offset + linked - segment.segment.vm_address;
        let bay = self
            .plan()
            .patchbay
            .as_ref()
            .context("native tuning requires patchbay")?;
        ensure!(
            bay.records.iter().all(|r| {
                let start = r.image_offset.saturating_sub(8);
                end <= start || offset >= r.image_offset + u64::from(r.bytes)
            }),
            "native tuning overlaps patchbay records"
        );
        ensure!(
            !self
                .plan()
                .chains
                .pointers
                .iter()
                .any(|p| p.image_offset < end && offset < p.image_offset + 8),
            "native tuning overlaps encoded cold chains"
        );
        let (tables, absent) = match input.native_override {
            Override::Absent(provenance) => {
                provenance.validate()?;
                (input.compiled, provenance)
            }
            Override::Required(provenance) => {
                provenance.validate()?;
                anyhow::bail!("native dynamic tuning override format is not qualified");
            }
        };
        tables.provenance.validate()?;
        for phase in &tables.additional {
            phase.provenance.validate()?;
            ensure!(
                phase.enabled.is_some()
                    || phase.table.as_ref().is_none_or(|t| t.records.is_empty()),
                "native tuning phase bit is unknown for a nonempty provider"
            );
        }
        let mut bytes = raw.to_vec();
        let mut entries = 0usize;
        let mut selected_sources = Vec::new();
        let selected = core::iter::once(&tables.primary)
            .chain(
                tables
                    .additional
                    .iter()
                    .filter(|p| p.enabled != Some(false))
                    .map(|p| &p.table),
            )
            .filter_map(|table| table.as_ref());
        for table in selected {
            ensure!(
                table.width == width && table.source.kind == raw[0],
                "selected native tuning table format disagrees with target"
            );
            let count = table.records.len() / width.bytes();
            ensure!(
                entries + count <= usize::from(capacity),
                "native tuning tables exceed original capacity"
            );
            let start = HEADER_BYTES + entries * width.bytes();
            bytes[start..start + table.records.len()].copy_from_slice(&table.records);
            entries += count;
            selected_sources.push(table.source.clone());
        }
        bytes[3] = u8::try_from(entries)?;
        Ok(Proposal {
            receipt: Receipt {
                source: self.plan().source.clone(),
                product_build: self.plan().product_build.clone(),
                hardware: self.plan().hardware.clone(),
                uuid: self.plan().uuid.clone(),
                original_staged_sha256: self.placement().staged_sha256.clone(),
                target_linked: linked,
                target_image_offset: offset,
                target_source_file_offset,
                target_bytes: length,
                original_target_sha256: sha256(raw),
                configured_target_sha256: sha256(&bytes),
                kind: raw[0],
                width,
                capacity,
                entries: entries as u8,
                absent_override: absent,
                selected_sources,
                provider_provenance: tables.provenance,
                phases: tables.additional.each_ref().map(|p| p.provenance.clone()),
                enabled_phases: tables.additional.each_ref().map(|p| p.enabled),
            },
            bytes,
            address_source_sha256: address_record.source_sha256.clone(),
            length_source_sha256: length_record.source_sha256.clone(),
        })
    }
}

impl Configured {
    pub(in crate::coprocessor) fn validate_tuning(&self) -> Result<()> {
        let bay = self
            .plan()
            .patchbay
            .as_ref()
            .context("configured image lacks patchbay")?;
        let address = bay.records.iter().find(|r| r.tag == ADDRESS);
        let length = bay.records.iter().find(|r| r.tag == LENGTH);
        if address.is_none() && length.is_none() {
            return Ok(());
        }
        let (address, length) = (
            address.context("incomplete native tuning family")?,
            length.context("incomplete native tuning family")?,
        );
        ensure!(
            address.bytes == 8 && length.bytes == 4,
            "native tuning scalar widths disagree"
        );
        let receipt = self
            .receipt
            .tuning
            .as_ref()
            .context("native tuning must be prepared before publication")?;
        let at = usize::try_from(receipt.target_image_offset)?;
        let bytes = self
            .bytes()
            .get(at..)
            .and_then(|b| b.get(..receipt.target_bytes as usize))
            .context("native tuning publication target exceeds bytes")?;
        ensure!(
            sha256(bytes) == receipt.configured_target_sha256,
            "native tuning changed after configuration"
        );
        Ok(())
    }

    /// Join after the complete scalar/cold-header transaction. All checks occur
    /// before a write, and the ordinary configuration hash covers the result.
    pub fn apply_tuning(mut self, proposal: Proposal) -> Result<Self> {
        let receipt = &proposal.receipt;
        ensure!(
            self.receipt.tuning.is_none(),
            "native tuning was already applied"
        );
        ensure!(
            self.placement().staged_sha256 == receipt.original_staged_sha256
                && self.plan().source.decoded_sha256 == receipt.source.decoded_sha256
                && self.plan().source.container_sha256 == receipt.source.container_sha256
                && self.plan().source.component == receipt.source.component
                && self.plan().source.member == receipt.source.member
                && self.plan().source.payload_type == receipt.source.payload_type
                && self.plan().source.description == receipt.source.description
                && self.plan().source.decoded_bytes == receipt.source.decoded_bytes
                && self.plan().product_build == receipt.product_build
                && self.plan().hardware.role == receipt.hardware.role
                && self.plan().hardware.compatible == receipt.hardware.compatible
                && self.plan().uuid == receipt.uuid,
            "native tuning proposal belongs to different staged bytes"
        );
        for (tag, expected) in [
            (ADDRESS, &proposal.address_source_sha256),
            (LENGTH, &proposal.length_source_sha256),
        ] {
            let (_, current) = source_record(&self.staged, tag)?;
            ensure!(
                &sha256(current) == expected,
                "configured tuning scalars differ from proposal"
            );
        }
        let at = usize::try_from(receipt.target_image_offset)?;
        let target = self
            .staged
            .bytes
            .get_mut(at..)
            .and_then(|b| b.get_mut(..receipt.target_bytes as usize))
            .context("native tuning target exceeds configured bytes")?;
        ensure!(
            sha256(target) == receipt.original_target_sha256,
            "native tuning target differs from proposal source"
        );
        target.copy_from_slice(&proposal.bytes);
        self.receipt.tuning = Some(proposal.receipt);
        self.receipt.configured_sha256 = sha256(self.bytes());
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coprocessor::{
        configuration::tests::{config_policy, provenance},
        tests::{fixture, prepare, w32, w64},
    };

    fn original(width: Width) -> Vec<u8> {
        let mut b = fixture();
        b[0x1200..0x1230].fill(0);
        for (at, tag, bytes) in [(0x1200, ADDRESS, 8), (0x1210, LENGTH, 4)] {
            w32(&mut b, at, tag);
            w32(&mut b, at + 4, bytes);
        }
        w64(&mut b, 32 + 232 + 40, 28);
        w64(&mut b, 0x1208, 0x800);
        w32(&mut b, 0x1218, (HEADER_BYTES + 4 * width.bytes()) as u32);
        b[0x1800..0x1808].copy_from_slice(&[
            1,
            2 + u8::from(width == Width::Bits64),
            4,
            0,
            0xff,
            0xff,
            0xff,
            0xff,
        ]);
        b[0x1808..0x1808 + 4 * width.bytes()].fill(0x71);
        b
    }
    fn input(width: Width) -> Result<Input> {
        Ok(Input {
            native_override: Override::Absent(provenance()),
            compiled: Tables {
                provenance: provenance(),
                primary: Some(source::tests::table(width)?),
                additional: [
                    Phase {
                        enabled: Some(false),
                        provenance: provenance(),
                        table: Some(source::tests::table(width)?),
                    },
                    Phase {
                        enabled: Some(true),
                        provenance: provenance(),
                        table: Some(source::tests::table(width)?),
                    },
                ],
            },
        })
    }
    #[test]
    fn tuning_changes_only_target_records_count_and_configuration_hash() -> Result<()> {
        for width in [Width::Bits32, Width::Bits64] {
            let b = original(width);
            let p = prepare(&b)?;
            let policy = config_policy(p.plan());
            let staged = p.stage(0x800000, 0x3000)?;
            let original = staged.bytes().to_vec();
            let proposal = staged.tuning_proposal(input(width)?)?;
            assert_eq!(proposal.receipt().entries, 2);
            assert_eq!(staged.bytes(), original);
            let configured = staged.configure(policy)?.apply_tuning(proposal)?;
            configured.validate_tuning()?;
            let raw = configured.bytes();
            assert_eq!(raw[0x803], 2);
            assert_eq!(&raw[0x804..0x808], &[0xff; 4]);
            assert_eq!(&raw[0x808..0x80c], &0x124u32.to_le_bytes());
            assert_eq!(&raw[..0x800], &original[..0x800]);
            assert_eq!(
                &raw[0x808 + 2 * width.bytes()..],
                &original[0x808 + 2 * width.bytes()..]
            );
            assert!(configured.receipt().tuning.is_some());
            assert_ne!(
                configured.receipt().configured_sha256,
                configured.placement().staged_sha256
            );
            assert_eq!(configured.receipt().configured_sha256, sha256(raw));
        }
        Ok(())
    }
    #[test]
    fn format_capacity_source_and_cold_chain_overlap_refuse() -> Result<()> {
        for case in 0..10 {
            let mut b = original(Width::Bits64);
            match case {
                0 => b[0x1800] = 2,
                1 => b[0x1801] = 1,
                2 => b[0x1802] = 0,
                3 => b[0x1802] = 255,
                4 => w64(&mut b, 0x1208, 0x1000), // unmapped gap
                5 => w64(&mut b, 0x1208, 0x2000), // original encoded chains
                6 => w64(&mut b, 0x1208, 0x200),  // patchbay itself
                7 => b[0x1802] = 1,
                _ => (),
            }
            let s = prepare(&b)?.stage(0x800000, 0x3000)?;
            let mut policy = input(Width::Bits64)?;
            if case == 8 {
                policy.native_override = Override::Required(provenance());
            }
            if case == 9 {
                policy.compiled.additional[0].enabled = None;
            }
            assert!(s.tuning_proposal(policy).is_err(), "case {case}");
        }
        let s = prepare(&original(Width::Bits64))?.stage(0x800000, 0x3000)?;
        assert!(s.tuning_proposal(input(Width::Bits32)?).is_err());
        Ok(())
    }
    #[test]
    fn join_rejects_stale_role_scalar_and_target_without_publishing_a_mutation() -> Result<()> {
        let b = original(Width::Bits64);
        for case in 0..4 {
            let p = prepare(&b)?;
            let mut policy = config_policy(p.plan());
            let s = p.stage(0x800000, 0x3000)?;
            let mut proposal = s.tuning_proposal(input(Width::Bits64)?)?;
            match case {
                0 => proposal.receipt.hardware.role = "other".into(),
                1 => {
                    policy.fields[0].action =
                        super::super::Action::Replace(0x804u64.to_le_bytes().to_vec())
                }
                2 => proposal.receipt.original_target_sha256 = "3".repeat(64),
                _ => proposal.receipt.original_staged_sha256 = "3".repeat(64),
            }
            assert!(s.configure(policy)?.apply_tuning(proposal).is_err());
        }
        Ok(())
    }

    #[test]
    fn publication_requires_prepared_tuning_and_detects_later_byte_changes() -> Result<()> {
        use crate::coprocessor::publication::tests::publication_policy;
        let b = original(Width::Bits64);
        let p = prepare(&b)?;
        let policy = config_policy(p.plan());
        let s = p.stage(0x800000, 0x3000)?;
        let proposal = s.tuning_proposal(input(Width::Bits64)?)?;
        let c = s.configure(policy)?;
        assert!(c.publication_proposal(publication_policy(&c)).is_err());
        let mut c = c.apply_tuning(proposal)?;
        c.publication_proposal(publication_policy(&c))?;
        c.staged.bytes[0x808] ^= 1;
        assert!(c.publication_proposal(publication_policy(&c)).is_err());
        Ok(())
    }

    #[test]
    #[ignore = "requires immutable original DCP/iBoot inputs; does not execute firmware"]
    #[cfg(feature = "std")]
    fn original_t6000_tuning_tables_prepare_complete_bounded_mutation() -> Result<()> {
        use crate::{
            boot_bundle::Source,
            coprocessor::{HardwareIdentity, Limits, prepare_im4p},
        };
        let dir = std::env::var("STELA_COPROCESSOR_FIXTURE_DIR")?;
        let iboot = std::fs::read(std::env::var("STELA_COPROCESSOR_IBOOT_FIXTURE")?)?;
        assert_eq!(
            sha256(&iboot),
            "20dfa3a5e6d4e4b2844c7558e6d4f8ab74397d11eae63312f00a559cf9612b03"
        );
        let claim = |at: usize, bytes: usize| Provenance {
            input_sha256: sha256(&iboot),
            coordinates: alloc::format!("original iBoot file {at:#x}+{bytes:#x}"),
            span_sha256: sha256(&iboot[at..at + bytes]),
        };
        let container = std::fs::read(std::path::Path::new(&dir).join("t600xdcp_restore.im4p"))?;
        let source = Source {
            component: "RestoreDCP".into(),
            member: "Firmware/dcp/t600xdcp_restore.im4p".into(),
            container_sha256: "9a071477954b6888a98fb801a1112ba8be4ff1dfe4f6fe84dc57580fa941ccb9"
                .into(),
            payload_type: "dcpf".into(),
            description: "1".into(),
            decoded_bytes: 11685888,
            decoded_sha256: "976b952c0e36d34af7912b115feef2d3982053133055bb93bcbca54a423f0a10"
                .into(),
        };
        let mut outputs = Vec::new();
        // Threshold branches are source fixtures, not a physical revision claim.
        for revision in [0x10, 0x20] {
            let p = prepare_im4p(
                &container,
                source.clone(),
                "26A434".into(),
                HardwareIdentity {
                    role: "DCPEXT0".into(),
                    compatible: "iop,ascwrap-v4".into(),
                },
                Limits::default(),
            )?;
            let policy = config_policy(p.plan()); // Mechanism test, not complete native cold policy.
            let image_bytes = p.plan().image_bytes;
            let s = p.stage(0x9000_0000, image_bytes)?;
            let original_chains = s
                .plan()
                .chains
                .pointers
                .iter()
                .map(|p| (p.image_offset, p.raw))
                .collect::<Vec<_>>();
            let table = Table::select(
                &iboot,
                source::Input {
                    image_base: 0x102_0000_0000,
                    groups_file_offset: 0x183020,
                    groups: 13,
                    kind: 1,
                    hardware_id: 0x37,
                    revision,
                    source_provenance: claim(0x183020, 13 * 0x38),
                    hardware_provenance: claim(0x1fbf60, 0x1a8),
                    filter: source::Filter::Absent(claim(0x13533c, 8)),
                },
                Width::Bits64,
            )?;
            let proposal = s.tuning_proposal(Input {
                native_override: Override::Absent(claim(0x1351b8, 20)),
                compiled: Tables {
                    provenance: claim(0x113954, 0x1cc),
                    primary: table,
                    additional: [
                        Phase {
                            enabled: None,
                            provenance: claim(0x1d1d10, 40),
                            table: None,
                        },
                        Phase {
                            enabled: None,
                            provenance: claim(0x1d1d38, 40),
                            table: None,
                        },
                    ],
                },
            })?;
            assert_eq!(proposal.receipt().entries, 21);
            assert_eq!(proposal.receipt().capacity, 24);
            let c = s.configure(policy)?.apply_tuning(proposal)?;
            let tuned = &c.bytes()[0x962c2a..0x962c2a + 0x1e8];
            assert_eq!(&tuned[..8], &[1, 3, 24, 21, 0xff, 0xff, 0xff, 0xff]);
            assert!(tuned[8 + 21 * 20..].iter().all(|&b| b == 0));
            assert_eq!(&tuned[8..12], &0x51c18u32.to_le_bytes());
            for (offset, raw) in original_chains {
                assert_eq!(
                    &c.bytes()[offset as usize..offset as usize + 8],
                    &raw.to_le_bytes()
                );
            }
            outputs.push(sha256(tuned));
        }
        assert_eq!(outputs[0], outputs[1]);
        assert_eq!(
            outputs[0],
            "7d9e1ad33f9eaaac71d28d9c92982c23f521b236c3bf1d86f28dabb280fafba4"
        );
        Ok(())
    }
}
