//! `map_with_linking_np` (`bsd/vm/vm_unix.c`, `osfmk/vm/vm_dyld_pager.c`):
//! dyld hands the kernel an image's data regions and their chained fixups,
//! and the kernel maps the file over them privately and applies the fixups
//! as the pages come in. The hosted kernel maps the regions and applies
//! every page's fixups at once, with the dyld pager's per-format rules and
//! the process's A keys; the pages read the same as the pager's would.
//!
//! The pager's own limits are kept: only data mappings of one file, A-key
//! authenticated pointers (a B-key pointer ends its page's chain, as the
//! pager fails it), chains that stay inside their page, and the call is
//! refused once dyld ends page-in linking for the process.
use super::{Call, Kernel, Outcome, Pe};
use crate::hosted::darwin::{EINVAL, ENOMEM, VM_PROT_DEFAULT};
use crate::hosted::memory::{self, PAGE_BYTES, Protection};
use crate::pauth;
use anyhow::Result;

/// `struct mwl_region` and `struct mwl_info_hdr`.
const REGION_BYTES: usize = 32;
const HEADER_BYTES: usize = 40;
const MWL_INFO_VERS: u32 = 7;
const MWL_MAX_REGION_COUNT: u64 = 5;
const MWL_MAX_LINK_INFO_SIZE: u64 = 64 << 20;
const VM_PROT_EXECUTE: u32 = 0x4;
const VM_PROT_WRITE: u32 = 0x2;
const VM_PROT_ZF: u32 = 0x10;
const VM_PROT_TPRO: u32 = 0x200;
/// `DYLD_CHAINED_PTR_*`.
const PTR_ARM64E: u16 = 1;
const PTR_64: u16 = 2;
const PTR_64_OFFSET: u16 = 6;
const PTR_ARM64E_USERLAND: u16 = 9;
const PTR_ARM64E_USERLAND24: u16 = 12;
const PTR_ARM64E_SHARED_CACHE: u16 = 13;
const PTR_START_NONE: u16 = 0xffff;
/// `ptrauth_blend_discriminator`.
const BLEND_ADDRESS_MASK: u64 = (1 << 48) - 1;

/// One region to map over.
#[derive(Debug, Clone, Copy)]
struct Region {
    descriptor: i32,
    protections: u32,
    file_offset: u64,
    address: u64,
    size: u64,
}

fn word(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

fn half(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

fn double(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
}

/// The validated link info: header fields, bind targets and the chained
/// starts of each segment.
struct LinkInfo<'a> {
    blob: &'a [u8],
    format: u16,
    binds: Vec<u64>,
    chains: usize,
    slide: u64,
    image: u64,
}

impl LinkInfo<'_> {
    /// The segment holding `address`: its `dyld_chained_starts_in_segment`
    /// offset in the blob and the page index.
    fn segment(&self, address: u64) -> Option<(usize, usize)> {
        let count = word(self.blob, self.chains)? as usize;
        for index in 0..count {
            let segment = self.chains + word(self.blob, self.chains + 4 + index * 4)? as usize;
            let offset = double(self.blob, segment + 8)?;
            let page_size = u64::from(half(self.blob, segment + 4)?);
            let pages = u64::from(half(self.blob, segment + 20)?);
            let start = self.image.wrapping_add(offset);
            if (start..start + pages * page_size).contains(&address) {
                let page = ((address - start) / PAGE_BYTES) as usize;
                return (page < pages as usize).then_some((segment, page));
            }
        }
        None
    }
}

pub(super) fn call(kernel: &mut Kernel, pe: &mut Pe, call: &Call) -> Result<Outcome> {
    let [regions, count, info, size, ..] = call.arguments;
    let (count, size) = (count as u32 as u64, size as u32 as u64);
    if kernel
        .process
        .map_with_linking_ended
        .load(core::sync::atomic::Ordering::SeqCst)
        || count == 0
        || count > MWL_MAX_REGION_COUNT
        || size <= HEADER_BYTES as u64
        || size >= MWL_MAX_LINK_INFO_SIZE
    {
        return Ok(Outcome::Error(EINVAL));
    }
    let (Some(region_bytes), Some(blob)) = (
        memory::read(regions, count as usize * REGION_BYTES),
        memory::read(info, size as usize),
    ) else {
        return Ok(Outcome::Error(EINVAL));
    };
    let regions: Vec<Region> = region_bytes
        .as_chunks::<REGION_BYTES>()
        .0
        .iter()
        .map(|region| Region {
            descriptor: word(region, 0).unwrap() as i32,
            protections: word(region, 4).unwrap(),
            file_offset: double(region, 8).unwrap(),
            address: double(region, 16).unwrap(),
            size: double(region, 24).unwrap(),
        })
        .collect();
    let Some(link) = validate(&blob, &regions) else {
        return Ok(Outcome::Error(EINVAL));
    };
    for region in &regions {
        let Some(end) = region.address.checked_add(region.size) else {
            return Ok(Outcome::Error(EINVAL));
        };
        if (region.address | region.size | region.file_offset) & memory::PAGE_MASK != 0 {
            return Ok(Outcome::Error(EINVAL));
        }
        // No thread executes guest code while the region is writable and
        // its pages are not yet linked.
        let signer = kernel.process.signer.as_ref();
        let linked = kernel.exclusive(|| -> Result<bool> {
            // The private overmapping, writable while its pages are linked.
            // SAFETY: a fixed private mapping over the image's own region.
            let mapped = unsafe {
                libc::mmap(
                    region.address as *mut libc::c_void,
                    region.size as usize,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_FIXED,
                    region.descriptor,
                    region.file_offset as libc::off_t,
                )
            };
            if mapped as u64 != region.address {
                return Ok(false);
            }
            let mut page = region.address;
            while page < end {
                if let Some((segment, index)) = link.segment(page) {
                    fix_page(&link, signer, page, segment, index);
                }
                page += PAGE_BYTES;
            }
            let protection = Protection((region.protections & VM_PROT_DEFAULT) as i32);
            memory::protect(region.address, region.size, protection)?;
            Ok(true)
        })?;
        if !linked {
            return Ok(Outcome::Error(ENOMEM));
        }
        kernel.invalidate_code(pe, region.address, region.size);
    }
    if kernel.trace {
        eprintln!(
            "stela: map_with_linking_np: {} regions of image {:#x}, pointer format {}",
            regions.len(),
            link.image,
            link.format
        );
    }
    Ok(Outcome::value(0))
}

/// The syscall's and the pager's checks on the regions and link info.
fn validate<'a>(blob: &'a [u8], regions: &[Region]) -> Option<LinkInfo<'a>> {
    let size = blob.len() as u64;
    let version = word(blob, 0)?;
    let page_size = u64::from(half(blob, 4)?);
    let format = half(blob, 6)?;
    let binds_offset = u64::from(word(blob, 8)?);
    let binds_count = u64::from(word(blob, 12)?);
    let chains = u64::from(word(blob, 16)?);
    let chains_size = u64::from(word(blob, 20)?);
    let slide = double(blob, 24)?;
    let image = double(blob, 32)?;
    if version != MWL_INFO_VERS || binds_offset > size || page_size != PAGE_BYTES {
        return None;
    }
    if !matches!(
        format,
        PTR_ARM64E
            | PTR_64
            | PTR_64_OFFSET
            | PTR_ARM64E_USERLAND
            | PTR_ARM64E_USERLAND24
            | PTR_ARM64E_SHARED_CACHE
    ) {
        return None;
    }
    if binds_count * 8 > size - binds_offset || chains > size || chains_size < 8 {
        return None;
    }
    if chains_size > size - chains {
        return None;
    }
    let descriptor = regions[0].descriptor;
    for region in regions {
        let protections = region.protections;
        if region.descriptor != descriptor
            || protections & (VM_PROT_EXECUTE | VM_PROT_ZF) != 0
            || (protections & VM_PROT_TPRO != 0 && protections & VM_PROT_WRITE == 0)
        {
            return None;
        }
    }
    let binds = (0..binds_count as usize)
        .map(|index| double(blob, binds_offset as usize + index * 8))
        .collect::<Option<Vec<_>>>()?;
    Some(LinkInfo {
        blob,
        format,
        binds,
        chains: chains as usize,
        slide,
        image,
    })
}

/// `signPointer` with the process's A keys; NULL stays NULL, and without
/// a user JOP key (`dyld_a_key` zero) the target stays unsigned.
fn sign(
    signer: Option<&pauth::Context>,
    target: u64,
    location: u64,
    address_diversity: bool,
    diversity: u64,
    key: pauth::Key,
) -> Option<u64> {
    if target == 0 {
        return Some(0);
    }
    let modifier = if address_diversity {
        (location & BLEND_ADDRESS_MASK) | diversity << 48
    } else {
        diversity
    };
    match signer {
        Some(signer) => signer.sign(key, target, modifier).ok(),
        None => Some(target),
    }
}

/// `fixup_page` on the page at `page`: walk its chain, rewriting each
/// fixup in place, until the chain ends or leaves the page.
fn fix_page(
    link: &LinkInfo,
    signer: Option<&pauth::Context>,
    page: u64,
    segment: usize,
    index: usize,
) {
    let Some(start) = half(link.blob, segment + 22 + index * 2) else {
        return;
    };
    if start == PTR_START_NONE {
        return;
    }
    let cache = link.format == PTR_ARM64E_SHARED_CACHE;
    let authenticated = matches!(
        link.format,
        PTR_ARM64E | PTR_ARM64E_USERLAND | PTR_ARM64E_USERLAND24
    );
    let offset_based = matches!(
        link.format,
        PTR_ARM64E_USERLAND | PTR_ARM64E_USERLAND24 | PTR_64_OFFSET
    );
    let adjust = if offset_based { link.image } else { link.slide };
    let stride = if authenticated || cache { 8 } else { 4 };
    let mut offset = u64::from(start);
    loop {
        if offset + 8 > PAGE_BYTES {
            return;
        }
        let location = page + offset;
        let Some(value) = memory::read_u64(location) else {
            return;
        };
        let bind = |ordinal: u64| link.binds.get(ordinal as usize).copied();
        let (fixed, delta) = if cache {
            let delta = (value >> 52) & 0x7ff;
            let target = (value & 0x3_ffff_ffff) + link.image;
            let fixed = if value >> 63 != 0 {
                let key = if value & 1 << 51 != 0 {
                    pauth::Key::Da
                } else {
                    pauth::Key::Ia
                };
                sign(
                    signer,
                    target,
                    location,
                    value & 1 << 50 != 0,
                    (value >> 34) & 0xffff,
                    key,
                )
            } else {
                Some(target + ((value << 22) & 0xff00_0000_0000_0000))
            };
            (fixed, delta)
        } else if authenticated {
            let delta = (value >> 51) & 0x7ff;
            let is_bind = value & 1 << 62 != 0;
            let fixed = if value >> 63 != 0 {
                let key = match (value >> 49) & 3 {
                    0 => Some(pauth::Key::Ia),
                    2 => Some(pauth::Key::Da),
                    // The pager signs only with the A keys.
                    _ => None,
                };
                let target = if is_bind {
                    bind(value & 0xff_ffff)
                } else {
                    Some((value & 0xffff_ffff) + link.image)
                };
                match (key, target) {
                    (Some(key), Some(target)) => sign(
                        signer,
                        target,
                        location,
                        value & 1 << 48 != 0,
                        (value >> 32) & 0xffff,
                        key,
                    ),
                    _ => None,
                }
            } else if is_bind {
                let mut addend = (value >> 32) & 0x7_ffff;
                if addend & 0x4_0000 != 0 {
                    addend |= 0xffff_ffff_fffc_0000;
                }
                bind(value & 0xff_ffff).map(|target| target.wrapping_add(addend))
            } else {
                Some((value & 0x7ff_ffff_ffff) + adjust + ((value << 13) & 0xff00_0000_0000_0000))
            };
            (fixed, delta)
        } else {
            let delta = (value >> 51) & 0xfff;
            let fixed = if value >> 63 != 0 {
                bind(value & 0xff_ffff).map(|target| target + ((value >> 24) & 0xff))
            } else {
                Some((value & 0xf_ffff_ffff) + adjust + (((value >> 36) & 0xff) << 56))
            };
            (fixed, delta)
        };
        let Some(fixed) = fixed else {
            return;
        };
        if !memory::write_u64(location, fixed) || delta == 0 {
            return;
        }
        offset += delta * stride;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn userland_rebases_bind_and_end_their_chain() {
        // One page with a plain rebase (offset 0x10, high8 0x80) chained to
        // a bind of ordinal 0 with addend 4.
        let page = memory::allocate(0, PAGE_BYTES, true, Protection::READ_WRITE).unwrap();
        let rebase = 0x10u64 | 0x80 << 43 | 1 << 51;
        let bind = 1u64 << 62 | 4 << 32;
        assert!(memory::write_u64(page, rebase));
        assert!(memory::write_u64(page + 8, bind));
        // Chained starts: one segment at offset 0 with one page starting 0.
        let mut blob = vec![0u8; HEADER_BYTES];
        let chains = blob.len();
        blob.extend(1u32.to_le_bytes());
        blob.extend(8u32.to_le_bytes());
        blob.extend(24u32.to_le_bytes()); // size
        blob.extend((PAGE_BYTES as u16).to_le_bytes());
        blob.extend(PTR_ARM64E_USERLAND24.to_le_bytes());
        blob.extend(0u64.to_le_bytes()); // segment_offset
        blob.extend(0u32.to_le_bytes()); // max_valid_pointer
        blob.extend(1u16.to_le_bytes()); // page_count
        blob.extend(0u16.to_le_bytes()); // page_start[0]
        let binds = blob.len();
        blob.extend(0x7000u64.to_le_bytes());
        blob[..4].copy_from_slice(&MWL_INFO_VERS.to_le_bytes());
        blob[4..6].copy_from_slice(&(PAGE_BYTES as u16).to_le_bytes());
        blob[6..8].copy_from_slice(&PTR_ARM64E_USERLAND24.to_le_bytes());
        blob[8..12].copy_from_slice(&(binds as u32).to_le_bytes());
        blob[12..16].copy_from_slice(&1u32.to_le_bytes());
        blob[16..20].copy_from_slice(&(chains as u32).to_le_bytes());
        blob[20..24].copy_from_slice(&((binds - chains) as u32).to_le_bytes());
        blob[32..40].copy_from_slice(&page.to_le_bytes());
        let region = Region {
            descriptor: 3,
            protections: VM_PROT_DEFAULT,
            file_offset: 0,
            address: page,
            size: PAGE_BYTES,
        };
        let link = validate(&blob, &[region]).unwrap();
        assert_eq!(link.segment(page), Some((chains + 8, 0)));
        let signer = pauth::Context::new_with_version(
            0,
            pauth::Keys::from_words([1, 2], [3, 4], [5, 6], [7, 8]),
            pauth::Version::FaultingCombined,
        );
        fix_page(&link, Some(&signer), page, chains + 8, 0);
        assert_eq!(memory::read_u64(page), Some(page + 0x10 + (0x80 << 56)));
        assert_eq!(memory::read_u64(page + 8), Some(0x7004));
        let executable = Region {
            protections: VM_PROT_EXECUTE,
            ..region
        };
        assert!(validate(&blob, &[executable]).is_none());
        memory::deallocate(page, PAGE_BYTES).unwrap();
    }
}
