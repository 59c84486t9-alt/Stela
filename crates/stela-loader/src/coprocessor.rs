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

mod fixups;
mod macho;
pub use fixups::{Authentication, Fixup, FixupChains};
pub use macho::Section;
#[cfg(test)]
mod tests;

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
        decode.decoded_bytes == source.decoded_bytes
            && decode.decoded_sha256 == source.decoded_sha256,
        "coprocessor decoded identity disagrees with selected source"
    );
    let layout = macho::parse(&decoded, limits)?;
    let chains = fixups::parse(&decoded, &layout, limits.fixups)?;
    Ok(Prepared {
        plan: Plan {
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
        },
        decoded,
    })
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
