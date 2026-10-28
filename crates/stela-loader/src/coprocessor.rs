//! Original coprocessor MH_PRELOAD images: checked preparation and owned backing.
//!
//! Physical placement is separate from the image's linked IOP virtual map.
//! Staging preserves encoded pointers. Relocation requires the coprocessor's
//! actual PAC context; neither step authenticates an Apple image, executes it,
//! establishes an IORVBAR lock, or supplies an implementation of its hardware.
use crate::{boot_bundle::Source, im4p, kernel_collection::Segment, thread_state::Arm64UnixThread};
use alloc::{string::String, vec, vec::Vec};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use stela_runtime::{pauth, sha256};

pub mod configuration;
mod fixups;
mod macho;
pub mod publication;
pub use fixups::{Authentication, Fixup, FixupChains};
pub use macho::Section;

/// Hardware ownership supplied by the selected board/restore identity.
#[derive(Debug, Clone, Serialize)]
pub struct HardwareIdentity {
    pub role: String,
    pub compatible: String,
}

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub decoded_bytes: u64,
    pub image_bytes: u64,
    pub command_bytes: u32,
    pub segments: usize,
    pub sections: usize,
    pub fixups: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            decoded_bytes: 64 << 20,
            image_bytes: 64 << 20,
            command_bytes: 1 << 20,
            segments: 256,
            sections: 4096,
            fixups: 1 << 20,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SegmentMap {
    pub segment: Segment,
    pub flags: u32,
    pub file_sha256: String,
}

/// Immutable source-bound requirements, with original coordinates retained.
#[derive(Debug, Clone, Serialize)]
pub struct Plan {
    pub source: Source,
    pub product_build: String,
    pub hardware: HardwareIdentity,
    pub decode: im4p::DecodeReceipt,
    pub cpu_subtype: u32,
    pub header_flags: u32,
    pub uuid: Option<String>,
    pub thread: Arm64UnixThread,
    pub segments: Vec<SegmentMap>,
    pub sections: Vec<Section>,
    pub vm_base: u64,
    pub image_bytes: u64,
    pub minimum_alignment: u64,
    pub chains: FixupChains,
    pub patchbay: Option<configuration::Patchbay>,
}

/// Owns the immutable decoded input and its checked plan.
pub struct Prepared {
    plan: Plan,
    decoded: Vec<u8>,
}

fn label(value: &str) -> bool {
    !value.is_empty() && value.len() <= 1024 && !value.bytes().any(|b| b.is_ascii_control())
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Decode and verify both original-container and decoded identities against the
/// caller's existing source record. SHA-256 integrity is not vendor trust.
pub fn prepare_im4p(
    container: &[u8],
    source: Source,
    product_build: String,
    hardware: HardwareIdentity,
    limits: Limits,
) -> Result<Prepared> {
    ensure!(
        [
            &source.component,
            &source.member,
            &product_build,
            &hardware.role,
            &hardware.compatible
        ]
        .into_iter()
        .all(|s| label(s)),
        "invalid coprocessor source/build/hardware identity"
    );
    ensure!(
        digest(&source.container_sha256) && digest(&source.decoded_sha256),
        "invalid coprocessor SHA-256 identity"
    );
    ensure!(
        sha256(container) == source.container_sha256,
        "coprocessor container SHA-256 mismatch"
    );
    let (decoded, decode) = im4p::decode(container, limits.decoded_bytes)?;
    ensure!(
        decode.payload_type == source.payload_type && decode.description == source.description,
        "coprocessor IM4P type/description disagree with selected source"
    );
    ensure!(
        decode.decoded_bytes as u64 == source.decoded_bytes
            && decode.decoded_sha256 == source.decoded_sha256,
        "coprocessor decoded identity disagrees with selected source"
    );
    let layout = macho::parse(&decoded, limits)?;
    let chains = fixups::parse(&decoded, &layout, limits.fixups)?;
    let mut plan = Plan {
        source,
        product_build,
        hardware,
        decode,
        cpu_subtype: layout.cpu_subtype,
        header_flags: layout.header_flags,
        uuid: layout.uuid,
        thread: layout.thread,
        segments: layout.segments,
        sections: layout.sections,
        vm_base: layout.vm_base,
        image_bytes: layout.image_bytes,
        minimum_alignment: layout.alignment,
        chains,
        patchbay: None,
    };
    plan.patchbay = configuration::parse(&decoded, &plan)?;
    Ok(Prepared { plan, decoded })
}

#[derive(Debug, Clone, Serialize)]
pub struct CopyRange {
    pub source_file_offset: u64,
    pub image_offset: u64,
    pub physical_address: u64,
    pub bytes: u64,
    pub source_sha256: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct ZeroRange {
    pub image_offset: u64,
    pub physical_address: u64,
    pub bytes: u64,
}
#[derive(Debug, Clone, Serialize)]
pub struct Placement {
    pub physical_base: u64,
    pub backing_bytes: u64,
    /// Entry bytes in guest physical backing, not the IORVBAR address. Original
    /// iBoot programs the separate IOP remap/DVA selected by its mapping owner.
    /// Neither address is permission to execute or program a locked register.
    pub entry_physical_address: u64,
    pub copies: Vec<CopyRange>,
    pub zeroes: Vec<ZeroRange>,
    pub staged_sha256: String,
}

/// Owned original bytes laid out in memory, including zero tails and gaps.
/// Encoded chained pointers have not been replaced yet.
pub struct Staged {
    prepared: Prepared,
    placement: Placement,
    bytes: Vec<u8>,
}
impl Prepared {
    pub fn plan(&self) -> &Plan {
        &self.plan
    }
    pub fn decoded(&self) -> &[u8] {
        &self.decoded
    }

    /// Materialize one actual contiguous allocation. Linked IOP VAs remain
    /// unchanged. This does not install a mapping in the IOP's MMU or DART.
    pub fn stage(self, physical_base: u64, backing_bytes: u64) -> Result<Staged> {
        let plan = &self.plan;
        ensure!(
            physical_base != 0 && physical_base.is_multiple_of(plan.minimum_alignment),
            "coprocessor backing base is zero or misaligned"
        );
        ensure!(
            backing_bytes >= plan.image_bytes,
            "coprocessor backing is smaller than its image"
        );
        physical_base
            .checked_add(backing_bytes)
            .context("coprocessor backing range overflows")?;
        let mut bytes = vec![0; usize::try_from(plan.image_bytes)?];
        let mut copies = vec![];
        let mut zeroes = vec![];
        let mut ordered: Vec<_> = plan
            .segments
            .iter()
            .filter(|s| s.segment.vm_size != 0)
            .collect();
        ordered.sort_by_key(|s| s.segment.vm_address);
        let mut cursor = 0;
        for map in ordered {
            let s = &map.segment;
            let offset = s.vm_address - plan.vm_base;
            let mut zero = |start: u64, size: u64| {
                if size != 0 {
                    zeroes.push(ZeroRange {
                        image_offset: start,
                        physical_address: physical_base + start,
                        bytes: size,
                    });
                }
            };
            zero(cursor, offset - cursor);
            zero(offset + s.file_size, s.vm_size - s.file_size);
            if s.file_size != 0 {
                let source = macho::file_bytes(&self.decoded, s.file_offset, s.file_size)?;
                bytes[offset as usize..offset as usize + source.len()].copy_from_slice(source);
                copies.push(CopyRange {
                    source_file_offset: s.file_offset,
                    image_offset: offset,
                    physical_address: physical_base + offset,
                    bytes: s.file_size,
                    source_sha256: map.file_sha256.clone(),
                });
            }
            cursor = offset + s.vm_size;
        }
        let placement = Placement {
            physical_base,
            backing_bytes,
            entry_physical_address: physical_base + (plan.thread.pc - plan.vm_base),
            copies,
            zeroes,
            staged_sha256: sha256(&bytes),
        };
        Ok(Staged {
            prepared: self,
            placement,
            bytes,
        })
    }
}

/// Relocated pointer values and the exact supplied PAC context identity.
/// Vendor authentication and coprocessor execution remain separate requirements.
#[derive(Debug, Clone, Serialize)]
pub struct RelocationReceipt {
    pub iop_virtual_base: u64,
    pub pointer_count: usize,
    pub authenticated_pointer_count: usize,
    pub pauth_address_space: u64,
    pub pauth_profile: String,
    pub tcr_el1: u64,
    pub relocated_sha256: String,
}
pub struct Relocated {
    staged: Staged,
    receipt: RelocationReceipt,
}
impl Staged {
    pub fn plan(&self) -> &Plan {
        self.prepared.plan()
    }
    pub fn placement(&self) -> &Placement {
        &self.placement
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Resolve all rebases transactionally under the *coprocessor's* keys and
    /// translation regime. AP/process keys are not an authority for this image.
    /// This family keeps MH_PRELOAD's linked virtual map; virtual code sliding
    /// is unqualified, independent of relocatable physical backing. This takes
    /// an explicit TCR_EL1 and installs that regime on the supplied context.
    /// Do not use this output for a cold bootstrap that consumes encoded chains
    /// itself: original T6000 DCP does so at VA 0x115d4.
    pub fn relocate(
        mut self,
        iop_virtual_base: u64,
        context: pauth::Context,
        tcr_el1: u64,
    ) -> Result<Relocated> {
        ensure!(
            iop_virtual_base == self.plan().vm_base,
            "MH_PRELOAD virtual sliding is not qualified"
        );
        let lower_bits = 64 - (tcr_el1 & 63);
        ensure!(
            (16..=39).contains(&(tcr_el1 & 63)),
            "unqualified coprocessor lower translation size"
        );
        ensure!(
            self.plan().vm_base + self.plan().image_bytes <= 1u64 << lower_bits,
            "coprocessor virtual image exceeds supplied lower translation regime"
        );
        let context = context.with_translation_regime(tcr_el1);
        let values = fixups::resolve(&self.plan().chains, iop_virtual_base, &context)?;
        for (offset, value) in values {
            self.bytes[offset as usize..offset as usize + 8].copy_from_slice(&value.to_le_bytes());
        }
        let receipt = RelocationReceipt {
            iop_virtual_base,
            pointer_count: self.plan().chains.pointers.len(),
            authenticated_pointer_count: self
                .plan()
                .chains
                .pointers
                .iter()
                .filter(|p| p.authentication.is_some())
                .count(),
            pauth_address_space: context.address_space(),
            pauth_profile: context.profile_id().into(),
            tcr_el1,
            relocated_sha256: sha256(&self.bytes),
        };
        Ok(Relocated {
            staged: self,
            receipt,
        })
    }
}
impl Relocated {
    pub fn plan(&self) -> &Plan {
        self.staged.plan()
    }
    pub fn placement(&self) -> &Placement {
        self.staged.placement()
    }
    pub fn bytes(&self) -> &[u8] {
        self.staged.bytes()
    }
    pub fn receipt(&self) -> &RelocationReceipt {
        &self.receipt
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};
    use configuration::native::tests::slide_input;
    use configuration::tests::{config_policy, provenance};

    pub(in crate::coprocessor) fn w32(b: &mut [u8], at: usize, value: u32) {
        b[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    pub(in crate::coprocessor) fn w64(b: &mut [u8], at: usize, value: u64) {
        b[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }

    pub(in crate::coprocessor) fn name(b: &mut [u8], at: usize, s: &str) {
        b[at..at + s.len()].copy_from_slice(s.as_bytes());
    }

    pub(in crate::coprocessor) fn fixture() -> Vec<u8> {
        let mut b = vec![0; 0x2010];
        for (at, v) in [
            (0, 0xfeedfacf),
            (4, 0x100000c),
            (8, 0x80000002),
            (12, 5),
            (16, 4),
            (20, 696),
        ] {
            w32(&mut b, at, v);
        }
        // Two segments, two sections in TEXT. Header remains outside the loaded map.
        let s = 32;
        w32(&mut b, s, 0x19);
        w32(&mut b, s + 4, 312);
        name(&mut b, s + 8, "__TEXT");
        for (o, v) in [(24, 0), (32, 0x1000), (40, 0x1000), (48, 0x1000)] {
            w64(&mut b, s + o, v);
        }
        for (o, v) in [(56, 5), (60, 5), (64, 3)] {
            w32(&mut b, s + o, v);
        }
        for (at, n, addr, size, off, reserved) in [
            (s + 72, "__text", 0, 4, 0x1000, 0),
            (s + 152, "__chain_starts", 0x100, 16, 0x1100, 2),
        ] {
            name(&mut b, at, n);
            name(&mut b, at + 16, "__TEXT");
            w64(&mut b, at + 32, addr);
            w64(&mut b, at + 40, size);
            w32(&mut b, at + 48, off);
            w32(&mut b, at + 52, 2);
            w32(&mut b, at + 68, reserved);
        }
        let sec = s + 232;
        name(&mut b, sec, "_rtk_patchbay");
        name(&mut b, sec + 16, "__TEXT");
        w64(&mut b, sec + 32, 0x200);
        w64(&mut b, sec + 40, 41);
        w32(&mut b, sec + 48, 0x1200);
        for (at, tag, size) in [
            (0x1200, 0x50414345, 8),
            (0x1210, 0x726f6c65, 4),
            (0x121c, 0x62417267, 5),
        ] {
            w32(&mut b, at, tag);
            w32(&mut b, at + 4, size);
        }
        let s = 344;
        w32(&mut b, s, 0x19);
        w32(&mut b, s + 4, 72);
        name(&mut b, s + 8, "__DATA");
        for (o, v) in [(24, 0x2000), (32, 0x100), (40, 0x2000), (48, 16)] {
            w64(&mut b, s + o, v);
        }
        w32(&mut b, s + 56, 3);
        w32(&mut b, s + 60, 3);
        let t = 416;
        w32(&mut b, t, 5);
        w32(&mut b, t + 4, 288);
        w32(&mut b, t + 8, 6);
        w32(&mut b, t + 12, 68);
        w32(&mut b, 704, 0x1b);
        w32(&mut b, 708, 24);
        b[712..728].copy_from_slice(&[1; 16]);
        w32(&mut b, 0x1000, 0xd503201f);
        for (o, v) in [(0, 7), (4, 1), (8, 0x2000)] {
            w32(&mut b, 0x1100 + o, v);
        }
        w64(
            &mut b,
            0x2000,
            (1 << 63) | (2 << 49) | (1 << 48) | (0x1234 << 32) | (2 << 51) | 8,
        );
        w64(&mut b, 0x2008, 0xabu64 << 43);
        b
    }

    pub(in crate::coprocessor) fn der(tag: u8, data: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if data.len() < 128 {
            out.push(data.len() as u8);
        } else {
            let bytes = data.len().to_be_bytes();
            let first = bytes.iter().position(|&x| x != 0).unwrap();
            out.push(0x80 | (bytes.len() - first) as u8);
            out.extend_from_slice(&bytes[first..]);
        }
        out.extend_from_slice(data);
        out
    }

    pub(in crate::coprocessor) fn input(decoded: &[u8]) -> (Vec<u8>, Source) {
        let mut body = vec![];
        for s in ["IM4P", "dcpf", "1"] {
            body.extend(der(0x16, s.as_bytes()));
        }
        body.extend(der(4, decoded));
        let container = der(0x30, &body);
        let source = Source {
            component: "RestoreDCP".into(),
            member: "firmware.im4p".into(),
            container_sha256: sha256(&container),
            payload_type: "dcpf".into(),
            description: "1".into(),
            decoded_bytes: decoded.len() as u64,
            decoded_sha256: sha256(decoded),
        };
        (container, source)
    }

    pub(in crate::coprocessor) fn prepare(decoded: &[u8]) -> Result<Prepared> {
        let (c, s) = input(decoded);
        prepare_im4p(&c, s, "fixture-build".into(), hardware(), Limits::default())
    }

    pub(in crate::coprocessor) fn hardware() -> HardwareIdentity {
        HardwareIdentity {
            role: "external-display0".into(),
            compatible: "iop,ascwrap-v4".into(),
        }
    }

    pub(in crate::coprocessor) fn context() -> pauth::Context {
        pauth::Context::new(123, pauth::Keys::from_words([1, 2], [3, 4], [5, 6], [7, 8]))
            .with_translation_regime(16)
    }

    #[test]
    fn source_map_entry_zero_and_owned_staging() -> Result<()> {
        let decoded = fixture();
        let p = prepare(&decoded)?;
        assert_eq!(p.plan().thread.pc, 0);
        assert_eq!(p.plan().image_bytes, 0x2100);
        assert_eq!(
            p.plan().uuid.as_deref(),
            Some("01010101010101010101010101010101")
        );
        assert!(!p.plan().decode.signature_validated);
        let s = p.stage(0x800000, 0x3000)?;
        assert_eq!(s.placement().entry_physical_address, 0x800000);
        assert_eq!(&s.bytes()[..4], &decoded[0x1000..0x1004]);
        assert!(s.bytes()[0x1000..0x2000].iter().all(|&v| v == 0));
        assert!(s.bytes()[0x2010..].iter().all(|&v| v == 0));
        assert_eq!(
            s.placement().zeroes.iter().map(|r| r.bytes).sum::<u64>(),
            0x10f0
        );
        assert_eq!(s.placement().copies.len(), 2);
        let second = prepare(&decoded)?.stage(0x1000000, 0x2100)?;
        assert_eq!(second.placement().entry_physical_address, 0x1000000);
        assert_eq!(second.bytes(), s.bytes());
        Ok(())
    }

    #[test]
    fn integrity_placement_and_limits_fail_closed() -> Result<()> {
        let raw = fixture();
        let (c, mut s) = input(&raw);
        s.decoded_sha256 = "0".repeat(64);
        assert!(prepare_im4p(&c, s, "test".into(), hardware(), Limits::default()).is_err());
        let (c, mut s) = input(&raw);
        s.payload_type = "krnl".into();
        assert!(prepare_im4p(&c, s, "test".into(), hardware(), Limits::default()).is_err());
        for (base, bytes) in [
            (0, 0x3000),
            (1, 0x3000),
            (0x800000, 0x2000),
            (u64::MAX - 3, 0x3000),
        ] {
            assert!(prepare(&raw)?.stage(base, bytes).is_err());
        }
        let (c, s) = input(&raw);
        assert!(
            prepare_im4p(
                &c,
                s,
                "test".into(),
                hardware(),
                Limits {
                    fixups: 1,
                    ..Limits::default()
                }
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    #[ignore = "requires immutable original fixture directory; does not execute firmware"]
    #[cfg(feature = "std")]
    fn original_t6000_restore_firmware() -> Result<()> {
        let dir = std::env::var("STELA_COPROCESSOR_FIXTURE_DIR")
            .context("set STELA_COPROCESSOR_FIXTURE_DIR to immutable original inputs")?;
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
        let prepared = prepare_im4p(
            &container,
            source.clone(),
            "26A434".into(),
            HardwareIdentity {
                role: "DCPEXT0".into(),
                compatible: "iop,ascwrap-v4".into(),
            },
            Limits::default(),
        )?;
        let p = prepared.plan();
        let bay = p.patchbay.as_ref().unwrap();
        assert_eq!(bay.records.len(), 61);
        assert_eq!(bay.bytes, 0x75a);
        assert_eq!(
            bay.records
                .iter()
                .find(|r| r.tag == 0x50414345)
                .unwrap()
                .bytes,
            8
        );
        assert_eq!(
            bay.records
                .iter()
                .find(|r| r.tag == 0x726f6c65)
                .unwrap()
                .bytes,
            4
        );
        assert_eq!(p.cpu_subtype, 0x80000002);
        assert_eq!(p.thread.pc, 0);
        assert_eq!(p.uuid.as_deref(), Some("643ec3de5fef38769cd1ddeebc9a9e7e"));
        assert_eq!(
            (p.segments.len(), p.image_bytes, p.minimum_alignment),
            (4, 0xb24000, 0x100000)
        );
        assert_eq!(
            p.chains.starts,
            [
                0x801000, 0x8404f8, 0x9039c8, 0x95ede8, 0xa34168, 0xa41200, 0xb00050
            ]
        );
        assert_eq!(p.chains.pointers.len(), 26103);
        assert_eq!(
            p.chains
                .pointers
                .iter()
                .filter(|p| p.authentication.is_some())
                .count(),
            23858
        );
        let staged = prepared.stage(0x80000000, 0xc00000)?;
        assert_eq!(staged.placement().entry_physical_address, 0x80000000);
        assert!(staged.placement().zeroes.is_empty());
        let cold_hash = sha256(staged.bytes());
        let slide = staged.cold_slide_proposal(slide_input(0x40, 0xabc123))?;
        assert_eq!(slide.original_control(), 0x11000);
        assert_eq!(slide.patch_value(), 0x10123);
        assert_eq!(slide.remap_slide(), 0x123000);
        assert_eq!(slide.control_file_offset(), 0x963924);
        assert_eq!(
            serde_json::to_value(&slide)?["source"]["decoded_sha256"],
            source.decoded_sha256
        );
        assert_eq!(sha256(staged.bytes()), cold_hash);
        let r = staged.relocate(0, context(), 16)?;
        assert_eq!(r.receipt().pointer_count, 26103);
        // Qualify the original native header + SLID transaction without pretending
        // synthetic entropy and preserving other fields form an authentic boot policy.
        let second = prepare_im4p(
            &container,
            source,
            "26A434".into(),
            HardwareIdentity {
                role: "DCPEXT0".into(),
                compatible: "iop,ascwrap-v4".into(),
            },
            Limits::default(),
        )?;
        let mut policy = config_policy(second.plan());
        let staged = second.stage(0x90000000, 0xc00000)?;
        let proposal = staged.cold_slide_proposal(slide_input(0x40, 0x123))?;
        *policy
            .fields
            .iter_mut()
            .find(|f| f.tag == u32::from_be_bytes(*b"SLID"))
            .unwrap() = proposal.field(provenance())?;
        let entropy = staged.entropy_fields(configuration::entropy::Input {
            pace: [0xa5; 8],
            pace_provenance: provenance(),
            stack_guard: vec![0x55; 8],
            stack_guard_choice: 0,
            stack_guard_provenance: provenance(),
        })?;
        for field in [entropy.pace, entropy.stack_guard] {
            let tag = field.tag;
            *policy.fields.iter_mut().find(|f| f.tag == tag).unwrap() = field;
        }
        // Synthetic coordinates exercise field preparation only; no allocator
        // or IOP mapping owner is established by this file-level fixture.
        let heap_policy = configuration::heap::Policy {
            bank: 0x4a,
            alignment: 0x4000,
            state: configuration::heap::BankState::Allocate,
            provenance: provenance(),
        };
        assert_eq!(staged.heap_request(&heap_policy)?.bytes, 0x1000000);
        let heap = staged.heap_fields(
            &heap_policy,
            configuration::heap::Mapping {
                bank: 0x4a,
                physical: 0xa0000000,
                iop: 0x10000000,
                bytes: 0x1000000,
                provenance: provenance(),
            },
        )?;
        for field in [heap.base, heap.size] {
            let tag = field.tag;
            *policy.fields.iter_mut().find(|f| f.tag == tag).unwrap() = field;
        }
        let configured = staged.configure_cold(policy, proposal)?;
        assert_eq!(configured.receipt().fields.len(), 61);
        assert_eq!(
            configured
                .receipt()
                .fields
                .iter()
                .filter(|f| f.changed)
                .count(),
            4 // RHS1 already requests this exact allocated size.
        );
        assert_eq!(
            u64::from_le_bytes(configured.bytes()[0x962908..0x962910].try_into()?),
            0x10000000
        );
        assert_eq!(
            u32::from_le_bytes(configured.bytes()[0x962918..0x96291c].try_into()?),
            0x1000000
        );
        assert_ne!(
            configured.receipt().configured_sha256,
            configured.placement().staged_sha256
        );
        assert_eq!(
            u64::from_le_bytes(configured.bytes()[0x1224..0x122c].try_into()?),
            0x123000
        );
        assert_eq!(
            u64::from_le_bytes(configured.bytes()[0x962924..0x96292c].try_into()?),
            0x10123
        );
        assert_eq!(
            &configured.bytes()[0x9624d8..0x9624e0],
            &[0, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55]
        );
        assert_eq!(&configured.bytes()[0x9629d7..0x9629df], &[0xa5; 8]);
        for fixup in &configured.plan().chains.pointers {
            let at = fixup.image_offset as usize;
            assert_eq!(&configured.bytes()[at..at + 8], &fixup.raw.to_le_bytes());
        }
        assert_eq!(configured.plan().chains.pointers.len(), 26103);
        // Synthetic PAC keys test complete format handling; they are not original trust/key provenance.
        assert_eq!(r.receipt().authenticated_pointer_count, 23858);
        assert_eq!(r.bytes().len(), 0xb24000);
        assert_ne!(r.receipt().relocated_sha256, r.placement().staged_sha256);
        std::println!(
            "original source={} uuid={} image={:#x} pointers={}",
            r.plan().source.decoded_sha256,
            r.plan().uuid.as_deref().unwrap(),
            r.bytes().len(),
            r.receipt().pointer_count
        );
        Ok(())
    }
}
