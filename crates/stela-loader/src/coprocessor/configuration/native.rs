//! Source-qualified cold SLID transformation, before the complete patch policy.
//!
//! The boot-policy owner supplies actual hardware classification and entropy
//! provenance. This proposal cannot certify either input or install a mapping.
use super::{Action, Configured, Field, Policy, Provenance, source_record};
use crate::coprocessor::{HardwareIdentity, Staged};
use alloc::string::String;
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use stela_runtime::sha256;

const CHAIN_STARTS: u32 = u32::from_be_bytes(*b"CSSS");
const SLIDE: u32 = u32::from_be_bytes(*b"SLID");
const SLIDE_UNITS_MASK: u64 = 0x3ff;
const SLIDE_GRANULE_MASK: u64 = 0x7000;
const COLD_CHAIN_CONTROL: u64 = 0x10000;
const BOOT_HEADER_MAGIC: u32 = u32::from_le_bytes(*b"uuid");
// Original iBoot 112724 reads the bounded table at file 1e79f8.
const BOOT_HEADER_OFFSETS: [u64; 8] = [0x20, 0xc0, 0x204, 0xc00, 0x1020, 0x1204, 0x4020, 0x4204];

/// Native iBoot's hardware boot-type word is independent of the ASC compatible
/// string and Mach-O CPU subtype. Neither is accepted as a substitute for it.
pub struct ColdSlideInput {
    pub hardware_boot_type: u16,
    pub hardware_provenance: Provenance,
    /// Bytes from the parent's actual entropy owner, not decoded PACE/defaults.
    /// The full entropy value is consumed and is never included in the proposal.
    pub entropy: u64,
    pub entropy_provenance: Provenance,
}

#[derive(Debug, Clone, Serialize)]
pub struct ColdSlideProposal {
    source: crate::boot_bundle::Source,
    product_build: String,
    hardware: HardwareIdentity,
    uuid: String,
    hardware_boot_type: u16,
    hardware_provenance: Provenance,
    entropy_provenance: Provenance,
    original_staged_sha256: String,
    original_control: u64,
    control_file_offset: u64,
    control_source_sha256: String,
    patch_value: u64,
    /// Native header/bootstrap virtual delta. The parent must qualify each
    /// actual segment mapping, including omit-DART policy; never add it to PA.
    remap_slide: u64,
    header_image_offset: u64,
    header_file_offset: u64,
    header_source_sha256: String,
}
impl ColdSlideProposal {
    pub(super) fn header_image_offset(&self) -> u64 {
        self.header_image_offset
    }
    pub fn original_control(&self) -> u64 {
        self.original_control
    }
    pub fn patch_value(&self) -> u64 {
        self.patch_value
    }
    pub fn remap_slide(&self) -> u64 {
        self.remap_slide
    }
    pub fn control_file_offset(&self) -> u64 {
        self.control_file_offset
    }
    /// One proposed decision in the caller's still-required complete policy.
    /// Preserve this proposal alongside the policy for both input provenances.
    pub fn field(&self, policy_provenance: Provenance) -> Result<Field> {
        policy_provenance.validate()?;
        Ok(Field {
            tag: SLIDE,
            action: Action::Replace(self.patch_value.to_le_bytes().to_vec()),
            provenance: policy_provenance,
        })
    }
}

impl Staged {
    /// iBoot 26A434 `155334` selects entropy by the hardware word; `1539a8`
    /// reads SLID, `1539b4..1539f8` produces its replacement and remap delta.
    /// The original CSSS path and 4K bootstrap slide geometry must agree.
    /// Original encoded chains and staged bytes remain entirely unchanged.
    pub fn cold_slide_proposal(&self, input: ColdSlideInput) -> Result<ColdSlideProposal> {
        input.hardware_provenance.validate()?;
        input.entropy_provenance.validate()?;
        let selected = match input.hardware_boot_type {
            0x20 | 0x40 => input.entropy,
            0x100 | 0x101 => input.entropy & 0xfc000,
            0x400 | 0x800 => (input.entropy & 0x0eefe000) | 0x100000,
            _ => anyhow::bail!("unqualified native coprocessor slide hardware type"),
        };
        let plan = self.plan();
        let bay = plan
            .patchbay
            .as_ref()
            .context("cold slide requires an original patchbay")?;
        let scalar = |tag| -> Result<(&super::Record, u64)> {
            let (record, value) = source_record(self, tag)?;
            ensure!(record.bytes == 8, "cold slide tag is not 64-bit");
            Ok((record, u64::from_le_bytes(value.try_into()?)))
        };
        let (_, chain_starts) = scalar(CHAIN_STARTS)?;
        let section = plan
            .sections
            .iter()
            .find(|s| s.name == "__chain_starts")
            .context("cold slide requires original chain-start coordinates")?;
        ensure!(
            chain_starts != 0 && chain_starts == section.virtual_address,
            "cold slide CSSS does not identify the original chain-start section"
        );
        let (record, original_control) = scalar(SLIDE)?;
        let granule = original_control & SLIDE_GRANULE_MASK;
        ensure!(
            granule == 0x1000,
            "native remap granule disagrees with qualified cold bootstrap shift"
        );
        let units = selected & SLIDE_UNITS_MASK;
        let remap_slide = granule * units;
        for segment in &plan.segments {
            segment
                .segment
                .vm_end()
                .checked_add(remap_slide)
                .context("cold slide overflows linked IOP segment map")?;
        }
        // iBoot 112724/1127e8 locates the native uuid header independently of
        // Mach-O LC_UUID. 110ca4 writes the slide to version5 header+0x20.
        let mut headers = BOOT_HEADER_OFFSETS.iter().filter_map(|&offset| {
            let at = usize::try_from(offset).ok()?;
            let raw = self.bytes().get(at..)?.get(..0x40)?;
            (u32::from_le_bytes(raw[..4].try_into().ok()?) == BOOT_HEADER_MAGIC)
                .then_some((offset, raw))
        });
        let (header_image_offset, header) = headers
            .next()
            .context("native cold bootstrap uuid header is absent")?;
        ensure!(
            headers.next().is_none(),
            "ambiguous native bootstrap headers"
        );
        ensure!(
            u32::from_le_bytes(header[4..8].try_into()?) == 5,
            "native cold slide requires a qualified version5 bootstrap header"
        );
        let uuid = plan
            .uuid
            .as_ref()
            .context("native bootstrap lacks Mach-O UUID")?;
        ensure!(
            hex::encode(&header[0x10..0x20]) == *uuid,
            "native bootstrap UUID disagrees with Mach-O"
        );
        let patchbay_section = plan
            .sections
            .iter()
            .find(|s| s.name == "_rtk_patchbay")
            .context("native bootstrap lacks original patchbay section")?;
        ensure!(
            u64::from(u32::from_le_bytes(header[0x28..0x2c].try_into()?))
                == patchbay_section.virtual_address
                && u64::from(u32::from_le_bytes(header[0x2c..0x30].try_into()?)) == bay.bytes,
            "native bootstrap patchbay coordinates disagree with original section"
        );
        let loaded = plan
            .segments
            .iter()
            .find(|s| {
                let start = plan.vm_base + header_image_offset;
                start >= s.segment.vm_address
                    && start
                        .checked_add(0x40)
                        .is_some_and(|end| end <= s.segment.vm_address + s.segment.file_size)
            })
            .context("native bootstrap header is not wholly file-backed")?;
        let header_file_offset = loaded.segment.file_offset
            + (plan.vm_base + header_image_offset - loaded.segment.vm_address);
        let slide_start = header_image_offset + 0x20;
        ensure!(
            !plan
                .chains
                .pointers
                .iter()
                .any(|p| p.image_offset < slide_start + 8 && slide_start < p.image_offset + 8),
            "native bootstrap slide overlaps an encoded chain slot"
        );
        Ok(ColdSlideProposal {
            source: plan.source.clone(),
            product_build: plan.product_build.clone(),
            hardware: plan.hardware.clone(),
            uuid: uuid.clone(),
            hardware_boot_type: input.hardware_boot_type,
            hardware_provenance: input.hardware_provenance,
            entropy_provenance: input.entropy_provenance,
            original_staged_sha256: self.placement().staged_sha256.clone(),
            original_control,
            control_file_offset: record.source_file_offset,
            control_source_sha256: record.source_sha256.clone(),
            patch_value: (original_control & COLD_CHAIN_CONTROL) | units,
            remap_slide,
            header_image_offset,
            header_file_offset,
            header_source_sha256: sha256(header),
        })
    }

    /// Complete the same explicit patchbay transaction plus the independent
    /// native version5 header slide. The proposal is bound to these staged
    /// bytes, and the policy must explicitly install its matching SLID value.
    pub fn configure_cold(self, policy: Policy, slide: ColdSlideProposal) -> Result<Configured> {
        ensure!(
            self.placement().staged_sha256 == slide.original_staged_sha256
                && self.plan().source.decoded_sha256 == slide.source.decoded_sha256
                && self.plan().product_build == slide.product_build
                && self.plan().hardware.role == slide.hardware.role
                && self.plan().hardware.compatible == slide.hardware.compatible,
            "cold bootstrap proposal belongs to different staged source/identity"
        );
        ensure!(
            policy.fields.iter().any(|f| f.tag == SLIDE && matches!(&f.action, Action::Replace(v) if v == &slide.patch_value.to_le_bytes())),
            "complete cold policy must install the proposed SLID value"
        );
        let mut configured = self.configure(policy)?;
        let at = usize::try_from(slide.header_image_offset)?;
        ensure!(
            sha256(&configured.bytes()[at..at + 0x40]) == slide.header_source_sha256,
            "patchbay policy overlaps native bootstrap header"
        );
        configured.staged.bytes[at + 0x20..at + 0x28]
            .copy_from_slice(&slide.remap_slide.to_le_bytes());
        configured.receipt.cold_slide = Some(slide);
        configured.receipt.configured_sha256 = sha256(configured.bytes());
        Ok(configured)
    }
}

#[cfg(test)]
pub(in crate::coprocessor) mod tests {
    use super::*;
    use crate::coprocessor::{
        self as native_root,
        tests::{fixture, prepare, w32, w64},
    };
    use configuration::tests::{config_policy, provenance};
    use native_root::{configuration, publication};
    use publication::tests::publication_policy;

    pub(in crate::coprocessor) fn slide_input(
        kind: u16,
        entropy: u64,
    ) -> configuration::native::ColdSlideInput {
        configuration::native::ColdSlideInput {
            hardware_boot_type: kind,
            hardware_provenance: provenance(),
            entropy,
            entropy_provenance: provenance(),
        }
    }

    pub(in crate::coprocessor) fn slide_fixture() -> Vec<u8> {
        let mut b = fixture();
        w32(&mut b, 0x1020, u32::from_le_bytes(*b"uuid"));
        w32(&mut b, 0x1024, 5);
        b[0x1030..0x1040].fill(1);
        w32(&mut b, 0x1048, 0x200);
        w32(&mut b, 0x104c, 32);
        w64(&mut b, 32 + 232 + 40, 32);
        for (at, tag, value) in [
            (0x1200, u32::from_be_bytes(*b"SLID"), 0x11000),
            (0x1210, u32::from_be_bytes(*b"CSSS"), 0x100),
        ] {
            w32(&mut b, at, tag);
            w32(&mut b, at + 4, 8);
            w64(&mut b, at + 8, value);
        }
        b
    }

    #[test]
    fn cold_slide_preserves_encoded_image_and_separates_remap_from_physical() -> Result<()> {
        let decoded = slide_fixture();
        let prepared = prepare(&decoded)?;
        let mut policy = config_policy(prepared.plan());
        let staged = prepared.stage(0x80000000, 0x3000)?;
        let original = sha256(staged.bytes());
        let proposal = staged.cold_slide_proposal(slide_input(0x40, 0xfffffffffffffd23))?;
        assert_eq!(
            (proposal.patch_value(), proposal.remap_slide()),
            (0x10123, 0x123000)
        );
        assert_eq!(sha256(staged.bytes()), original);
        // A real proposed field enters the same complete transactional policy;
        // neither the other record nor the original encoded fixup slots changes.
        let tag = u32::from_be_bytes(*b"SLID");
        *policy.fields.iter_mut().find(|f| f.tag == tag).unwrap() = proposal.field(provenance())?;
        let configured = staged.configure_cold(policy, proposal.clone())?;
        assert_eq!(
            u64::from_le_bytes(configured.bytes()[0x40..0x48].try_into()?),
            proposal.remap_slide()
        );
        assert!(configured.receipt().cold_slide.is_some());
        assert_eq!(
            configured
                .receipt()
                .fields
                .iter()
                .filter(|f| f.changed)
                .count(),
            1
        );
        let mut publication = publication_policy(&configured);
        for decision in &mut publication.segments {
            if let publication::Action::Publish { iop_remap, .. } = &mut decision.action {
                let segment = configured
                    .plan()
                    .segments
                    .iter()
                    .find(|s| s.segment.name == decision.name)
                    .unwrap();
                *iop_remap = segment.segment.vm_address + proposal.remap_slide();
            }
        }
        let (configured, publication) = configured.finalize_cold_mappings(
            publication,
            configuration::finalization::Input {
                descriptor_flags: 0,
                provenance: provenance(),
            },
        )?;
        let mapped = configured.publication_proposal(publication)?;
        assert_eq!(mapped.entry.physical, 0x80000000);
        assert_eq!(mapped.entry.linked_virtual, 0);
        assert_eq!(mapped.entry.iop_remap, 0x123000);
        for fixup in &configured.plan().chains.pointers {
            let at = fixup.image_offset as usize;
            assert_eq!(&configured.bytes()[at..at + 8], &fixup.raw.to_le_bytes());
        }
        Ok(())
    }

    #[test]
    fn cold_slide_requires_complete_source_geometry_and_hardware_classification() -> Result<()> {
        let decoded = slide_fixture();
        let staged = prepare(&decoded)?.stage(0x80000000, 0x3000)?;
        for kind in [0x20, 0x40] {
            let proposal = staged.cold_slide_proposal(slide_input(kind, 0))?;
            // A genuine entropy owner may return zero; inventing a nonzero slide
            // would disagree with the original producer. It still authorizes no entry.
            assert_eq!(
                (proposal.patch_value(), proposal.remap_slide()),
                (0x10000, 0)
            );
        }
        for kind in [0x100, 0x101, 0x400, 0x800] {
            let proposal = staged.cold_slide_proposal(slide_input(kind, u64::MAX))?;
            assert_eq!(
                (proposal.patch_value(), proposal.remap_slide()),
                (0x10000, 0)
            );
        }
        assert!(staged.cold_slide_proposal(slide_input(0x80, 1)).is_err());
        let mut input = slide_input(0x40, 1);
        input.entropy_provenance.coordinates.clear();
        assert!(staged.cold_slide_proposal(input).is_err());
        for (offset, value) in [(0x1218, 0), (0x1218, 0x104), (0x1208, 0x12000)] {
            let mut decoded = decoded.clone();
            w64(&mut decoded, offset, value);
            let staged = prepare(&decoded)?.stage(0x80000000, 0x3000)?;
            assert!(staged.cold_slide_proposal(slide_input(0x40, 1)).is_err());
        }
        for (offset, value) in [(0x1020, 0), (0x1024, 4), (0x1030, 2), (0x1048, 0x204)] {
            let mut decoded = decoded.clone();
            w32(&mut decoded, offset, value);
            let staged = prepare(&decoded)?.stage(0x80000000, 0x3000)?;
            assert!(staged.cold_slide_proposal(slide_input(0x40, 1)).is_err());
        }
        let prepared = prepare(&decoded)?;
        let policy = config_policy(prepared.plan());
        let staged = prepared.stage(0x80000000, 0x3000)?;
        let proposal = staged.cold_slide_proposal(slide_input(0x40, 1))?;
        assert!(staged.configure_cold(policy, proposal).is_err());
        assert!(
            prepare(&fixture())?
                .stage(0x80000000, 0x3000)?
                .cold_slide_proposal(slide_input(0x40, 1))
                .is_err()
        );
        Ok(())
    }
}
