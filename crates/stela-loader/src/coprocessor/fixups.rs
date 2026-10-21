//! Firmware __chain_starts, not LC_DYLD_CHAINED_FIXUPS.
//!
//! Apple's SDK mach-o/fixup-chains.h specifies dyld_chained_starts_offsets,
//! reserved1=2 VM-offset roots and format7 ARM64E_KERNEL: four-byte stride,
//! unauthenticated VM offsets and authenticated runtime offsets. Bind records
//! and other pointer formats remain explicit unsupported requirements.
use super::macho::{Layout, end, file_bytes};
use alloc::{collections::BTreeMap, vec, vec::Vec};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use stela_runtime::{pauth, sha256};

const FORMAT_ARM64E_KERNEL: u32 = 7;
const STARTS_USE_VM_OFFSET: u32 = 2;
const POINTER_BYTES: u64 = 8;
const STRIDE: u64 = 4;

#[derive(Debug, Clone, Copy, Serialize)]
pub struct Authentication {
    pub key: pauth::Key,
    pub diversity: u16,
    pub address_diversity: bool,
}
#[derive(Debug, Clone, Serialize)]
pub struct Fixup {
    pub image_offset: u64,
    pub file_offset: u64,
    pub raw: u64,
    pub target_offset: u64,
    pub high8: u8,
    pub next_bytes: u64,
    pub authentication: Option<Authentication>,
}
#[derive(Debug, Clone, Serialize)]
pub struct FixupChains {
    pub pointer_format: u32,
    pub starts: Vec<u32>,
    pub section_file_offset: u64,
    pub section_bytes: u64,
    pub section_sha256: alloc::string::String,
    pub pointers: Vec<Fixup>,
}

fn word(b: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        b.get(at..at + 4)
            .context("truncated coprocessor chain-start metadata")?
            .try_into()?,
    ))
}
fn source(layout: &Layout, address: u64) -> Result<(usize, u64)> {
    let (index, s) = layout
        .segments
        .iter()
        .enumerate()
        .find(|(_, s)| {
            address >= s.segment.vm_address
                && end(address, POINTER_BYTES)
                    .is_ok_and(|e| e <= s.segment.vm_address + s.segment.file_size)
        })
        .context("coprocessor chain pointer is not wholly file-backed")?;
    Ok((
        index,
        s.segment.file_offset + address - s.segment.vm_address,
    ))
}

pub(super) fn parse(data: &[u8], layout: &Layout, maximum: usize) -> Result<FixupChains> {
    let mut matches = layout
        .sections
        .iter()
        .filter(|s| s.name == "__chain_starts");
    let section = matches
        .next()
        .context("coprocessor requires a qualified __chain_starts section")?;
    ensure!(
        matches.next().is_none(),
        "duplicate coprocessor __chain_starts"
    );
    ensure!(
        layout.segments[section.segment_index].segment.name == "__TEXT"
            && section.reserved == [STARTS_USE_VM_OFFSET, 0, 0],
        "coprocessor chain-start coordinates are not qualified VM offsets"
    );
    let raw = file_bytes(data, section.file_offset, section.bytes)?;
    let format = word(raw, 0)?;
    ensure!(
        format == FORMAT_ARM64E_KERNEL,
        "unsupported coprocessor chained pointer format {format}"
    );
    let count = word(raw, 4)? as usize;
    ensure!(
        count <= maximum && count <= raw.len().saturating_sub(8) / 4,
        "coprocessor chain-root count exceeds section/limit"
    );
    let used = 8 + count * 4;
    ensure!(
        raw[used..].iter().all(|&b| b == 0),
        "nonzero trailing coprocessor chain metadata"
    );
    let mut starts = Vec::with_capacity(count);
    let mut pointers = vec![];
    let mut visited = BTreeMap::new();
    for index in 0..count {
        let root = word(raw, 8 + index * 4)?;
        starts.push(root);
        let mut offset = u64::from(root);
        let mut owner = None;
        loop {
            ensure!(
                pointers.len() < maximum,
                "coprocessor chained-fixup limit exceeded"
            );
            ensure!(
                offset.is_multiple_of(STRIDE),
                "unaligned coprocessor chain pointer"
            );
            let pointer_end = end(offset, POINTER_BYTES)?;
            ensure!(
                !visited
                    .range(..pointer_end)
                    .next_back()
                    .is_some_and(|(_, &e)| e > offset),
                "overlapping or repeated coprocessor chain pointers"
            );
            visited.insert(offset, pointer_end);
            let address = end(layout.vm_base, offset)?;
            let (segment, file_offset) = source(layout, address)?;
            ensure!(
                owner.is_none_or(|prior| prior == segment),
                "coprocessor pointer chain crosses segments"
            );
            owner = Some(segment);
            let value =
                u64::from_le_bytes(file_bytes(data, file_offset, POINTER_BYTES)?.try_into()?);
            ensure!(
                value & (1 << 62) == 0,
                "coprocessor chained imports require a real resolver"
            );
            let authentication = (value & (1 << 63) != 0).then_some(Authentication {
                key: match (value >> 49) & 3 {
                    0 => pauth::Key::Ia,
                    1 => pauth::Key::Ib,
                    2 => pauth::Key::Da,
                    _ => pauth::Key::Db,
                },
                diversity: (value >> 32) as u16,
                address_diversity: value & (1 << 48) != 0,
            });
            let (target_offset, high8) = if authentication.is_some() {
                (value & 0xffff_ffff, 0)
            } else {
                (value & ((1 << 43) - 1), ((value >> 43) & 0xff) as u8)
            };
            let target = end(layout.vm_base, target_offset)?;
            ensure!(
                layout
                    .segments
                    .iter()
                    .any(|s| target >= s.segment.vm_address && target < s.segment.vm_end()),
                "coprocessor rebase target is outside mapped segments"
            );
            let next_bytes = ((value >> 51) & 0x7ff) * STRIDE;
            pointers.push(Fixup {
                image_offset: offset,
                file_offset,
                raw: value,
                target_offset,
                high8,
                next_bytes,
                authentication,
            });
            if next_bytes == 0 {
                break;
            }
            offset = end(offset, next_bytes)?;
        }
    }
    Ok(FixupChains {
        pointer_format: format,
        starts,
        section_file_offset: section.file_offset,
        section_bytes: section.bytes,
        section_sha256: sha256(raw),
        pointers,
    })
}

pub(super) fn resolve(
    chains: &FixupChains,
    iop_base: u64,
    context: &pauth::Context,
) -> Result<Vec<(u64, u64)>> {
    let mut output = Vec::with_capacity(chains.pointers.len());
    for p in &chains.pointers {
        let target = end(iop_base, p.target_offset)?;
        ensure!(
            target < (1 << 48),
            "coprocessor rebase target exceeds qualified lower virtual map"
        );
        let value = match p.authentication {
            Some(a) => {
                let slot = end(iop_base, p.image_offset)?;
                ensure!(
                    slot < (1 << 48),
                    "coprocessor PAC slot exceeds blend-address range"
                );
                let modifier = if a.address_diversity {
                    slot | (u64::from(a.diversity) << 48)
                } else {
                    u64::from(a.diversity)
                };
                // Format7 runtimeOffset zero denotes the image base, not an
                // inferred null. Architectural PAC signs the resolved value.
                context.sign(a.key, target, modifier)?
            }
            None => target | (u64::from(p.high8) << 56),
        };
        output.push((p.image_offset, value));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coprocessor::tests::{context, fixture, prepare};

    #[test]
    fn full_chains_rebase_and_sign_under_explicit_context() -> Result<()> {
        let s = prepare(&fixture())?.stage(0x800000, 0x3000)?;
        assert_eq!(s.plan().chains.pointers.len(), 2);
        let ctx = context();
        let expected = ctx.sign(pauth::Key::Da, 8, 0x1234_0000_0000_2000)?;
        let r = s.relocate(0, ctx, 16)?;
        let signed = u64::from_le_bytes(r.bytes()[0x2000..0x2008].try_into()?);
        assert_eq!(signed, expected);
        assert_eq!(
            u64::from_le_bytes(r.bytes()[0x2008..0x2010].try_into()?),
            0xab00_0000_0000_0000
        );
        assert_eq!(r.receipt().authenticated_pointer_count, 1);
        assert!(
            prepare(&fixture())?
                .stage(0x800000, 0x3000)?
                .relocate(0x1000, context(), 16)
                .is_err()
        );
        let missing = pauth::Context::new(123, pauth::Keys::from_ib_words(3, 4));
        assert!(
            prepare(&fixture())?
                .stage(0x800000, 0x3000)?
                .relocate(0, missing, 16)
                .is_err()
        );
        Ok(())
    }
}
