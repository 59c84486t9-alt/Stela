//! The process's shared region: the dyld shared cache mapped at its slid
//! base with `shared_region_map_and_slide_2_np` semantics (XNU
//! `osfmk/vm/vm_shared_region.c`), already populated when the process
//! starts, as if an earlier process had mapped it; `shared_region_check_np`
//! reports its base.
//!
//! Each `shared_file_mapping_slide_np` maps its file range privately at its
//! address plus the slide. A mapping with slide info starts inaccessible and
//! is slid one slide page at a time on first access, as XNU's shared-region
//! pager does (`vm_shared_region_slide_page_v5`): ordinary pointers become
//! `target + value_add + slide` with their high byte restored, and
//! authenticated pointers are signed with the A key their descriptor names
//! (IA or DA) under the shared region's keys, which are this process's.
use super::memory::{self, PAGE_MASK, Protection};
use crate::pauth;
use anyhow::{Context as _, Result, bail, ensure};
use std::{fs::File, os::fd::AsRawFd, path::PathBuf};

/// `dyld_cache_slide_info5`.
const SLIDE_V5: u32 = 5;
const SLIDE_V5_HEADER: usize = 24;
const PAGE_ATTR_NO_REBASE: u16 = 0xffff;
const RUNTIME_OFFSET_MASK: u64 = (1 << 34) - 1;
const HIGH8_SHIFT: u32 = 22;
const HIGH8_MASK: u64 = 0xff00_0000_0000_0000;
const NEXT_SHIFT: u32 = 52;
const NEXT_MASK: u64 = 0x7ff;
const AUTHENTICATED: u64 = 1 << 63;
const DIVERSITY_SHIFT: u32 = 34;
const ADDRESS_DIVERSITY: u64 = 1 << 50;
const KEY_IS_DATA: u64 = 1 << 51;
/// `ptrauth_blend_discriminator`: the address's low 48 bits under the
/// 16-bit diversity.
const BLEND_ADDRESS_MASK: u64 = (1 << 48) - 1;
const BLEND_DIVERSITY_SHIFT: u32 = 48;
/// Bounds on one mapping's slide info, not XNU limits.
const MAX_SLIDE_INFO: u64 = 64 << 20;

/// One `shared_file_mapping_slide_np`, with its file.
#[derive(Debug, Clone)]
pub struct MappingRequest {
    pub path: PathBuf,
    pub file_offset: u64,
    pub address: u64,
    pub size: u64,
    pub maximum: Protection,
    pub initial: Protection,
    /// File offset and size of the mapping's slide info.
    pub slide_info: Option<(u64, u64)>,
}

struct SlideInfo {
    page_bytes: u64,
    value_add: u64,
    page_starts: Vec<u16>,
}

fn parse_slide_info(bytes: &[u8]) -> Result<SlideInfo> {
    ensure!(bytes.len() >= SLIDE_V5_HEADER, "truncated slide info");
    let word = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().expect("four"));
    let version = word(0);
    if version != SLIDE_V5 {
        bail!("shared-cache slide info version {version} is not supported (v5 only)");
    }
    let page_bytes = u64::from(word(4));
    let count = word(8) as usize;
    let value_add = u64::from_le_bytes(bytes[16..24].try_into()?);
    ensure!(
        page_bytes.is_power_of_two() && page_bytes >= 4096,
        "slide page size {page_bytes:#x}"
    );
    let starts = bytes
        .get(SLIDE_V5_HEADER..SLIDE_V5_HEADER + count * 2)
        .context("truncated slide page starts")?;
    Ok(SlideInfo {
        page_bytes,
        value_add,
        page_starts: starts
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .collect(),
    })
}

struct SlidMapping {
    address: u64,
    size: u64,
    initial: Protection,
    info: SlideInfo,
    pending: Vec<bool>,
}

pub struct SharedRegion {
    start: u64,
    size: u64,
    slide: u64,
    slid: Vec<SlidMapping>,
    slid_pages: u64,
}

impl SharedRegion {
    /// Map `requests` with `slide` into the region `[start, start + size)`
    /// (unslid), which must be free in this process.
    pub fn map(requests: &[MappingRequest], start: u64, size: u64, slide: u64) -> Result<Self> {
        ensure!(
            slide & PAGE_MASK == 0,
            "slide {slide:#x} is not page aligned"
        );
        let base = start.checked_add(slide).context("slide overflow")?;
        let reserved = memory::allocate(base, size, false, Protection::NONE)
            .context("the shared region's address range is occupied in this process")?;
        ensure!(reserved == base, "shared region placed at {reserved:#x}");
        let mut slid = Vec::new();
        for request in requests {
            let address = request.address + slide;
            let file = File::open(&request.path)
                .with_context(|| format!("cannot open {}", request.path.display()))?;
            let protection = if request.slide_info.is_some() {
                Protection::NONE
            } else {
                request.initial
            };
            // SAFETY: a fixed private file mapping inside the reservation
            // this region owns.
            let mapped = unsafe {
                libc::mmap(
                    address as *mut libc::c_void,
                    request.size as usize,
                    protection.0,
                    libc::MAP_PRIVATE | libc::MAP_FIXED,
                    file.as_raw_fd(),
                    request.file_offset as libc::off_t,
                )
            };
            ensure!(
                mapped as u64 == address,
                "cannot map {} at {address:#x}: {}",
                request.path.display(),
                std::io::Error::last_os_error()
            );
            if let Some((offset, bytes)) = request.slide_info {
                ensure!(bytes <= MAX_SLIDE_INFO, "slide info too large");
                let mut buffer = vec![0; bytes as usize];
                std::os::unix::fs::FileExt::read_exact_at(&file, &mut buffer, offset)?;
                let info = parse_slide_info(&buffer)?;
                let pages = request.size.div_ceil(info.page_bytes) as usize;
                ensure!(
                    info.page_starts.len() >= pages,
                    "slide info covers {} of {pages} pages",
                    info.page_starts.len()
                );
                slid.push(SlidMapping {
                    address,
                    size: request.size,
                    initial: request.initial,
                    pending: vec![true; pages],
                    info,
                });
            }
        }
        Ok(Self {
            start,
            size,
            slide,
            slid,
            slid_pages: 0,
        })
    }

    /// The slid base `shared_region_check_np` reports.
    pub fn base(&self) -> u64 {
        self.start + self.slide
    }

    pub fn slide(&self) -> u64 {
        self.slide
    }

    pub fn contains(&self, address: u64) -> bool {
        (self.base()..self.base() + self.size).contains(&address)
    }

    pub fn slid_pages(&self) -> u64 {
        self.slid_pages
    }

    /// Whether `address` lies in a slide page not yet slid.
    pub fn pending(&self, address: u64) -> bool {
        self.slid.iter().any(|mapping| {
            (mapping.address..mapping.address + mapping.size).contains(&address)
                && mapping.pending[((address - mapping.address) / mapping.info.page_bytes) as usize]
        })
    }

    /// Slide the page holding `address` in, if it is pending: false when
    /// there was nothing to do.
    pub fn resolve(&mut self, address: u64, signer: &pauth::Context) -> Result<bool> {
        let slide = self.slide;
        let Some(mapping) = self
            .slid
            .iter_mut()
            .find(|mapping| (mapping.address..mapping.address + mapping.size).contains(&address))
        else {
            return Ok(false);
        };
        let index = ((address - mapping.address) / mapping.info.page_bytes) as usize;
        if !mapping.pending[index] {
            return Ok(false);
        }
        let page = mapping.address + index as u64 * mapping.info.page_bytes;
        let bytes = mapping
            .info
            .page_bytes
            .min(mapping.address + mapping.size - page);
        memory::protect(page, bytes, Protection::READ_WRITE)?;
        let start = mapping.info.page_starts[index];
        if start != PAGE_ATTR_NO_REBASE {
            slide_page(page, bytes, start, mapping.info.value_add, slide, signer)?;
        }
        memory::protect(page, bytes, mapping.initial)?;
        mapping.pending[index] = false;
        self.slid_pages += 1;
        Ok(true)
    }
}

/// `vm_shared_region_slide_page_v5` on the page at `page`, which this
/// process maps read/write.
fn slide_page(
    page: u64,
    bytes: u64,
    start: u16,
    value_add: u64,
    slide: u64,
    signer: &pauth::Context,
) -> Result<()> {
    let mut offset = u64::from(start);
    loop {
        ensure!(
            offset + 8 <= bytes,
            "slide chain leaves its page at {:#x}",
            page + offset
        );
        let location = page + offset;
        let raw = memory::read_u64(location).context("slide location unreadable")?;
        let delta = ((raw >> NEXT_SHIFT) & NEXT_MASK) * 8;
        let target = (raw & RUNTIME_OFFSET_MASK) + value_add + slide;
        let value = if raw & AUTHENTICATED != 0 {
            let diversity = (raw >> DIVERSITY_SHIFT) & 0xffff;
            let modifier = if raw & ADDRESS_DIVERSITY != 0 {
                (location & BLEND_ADDRESS_MASK) | diversity << BLEND_DIVERSITY_SHIFT
            } else {
                diversity
            };
            let key = if raw & KEY_IS_DATA != 0 {
                pauth::Key::Da
            } else {
                pauth::Key::Ia
            };
            signer.sign(key, target, modifier)?
        } else {
            target + ((raw << HIGH8_SHIFT) & HIGH8_MASK)
        };
        ensure!(
            memory::write_u64(location, value),
            "slide location unwritable"
        );
        if delta == 0 {
            return Ok(());
        }
        offset += delta;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer() -> pauth::Context {
        pauth::Context::new_with_version(
            0,
            pauth::Keys::from_words([1, 2], [3, 4], [5, 6], [7, 8]),
            pauth::Version::FaultingCombined,
        )
        .with_translation_regime(super::super::pe::TCR_EL1)
    }

    #[test]
    fn v5_chains_rebase_restore_high8_and_sign_auth_pointers() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cache");
        let page = 0x4000usize;
        let mut data = vec![0u8; page * 2];
        // Ordinary: offset 0x100, high8 0x80, next 1 (8 bytes).
        let ordinary = 0x100u64 | 0x80 << 34 | 1 << NEXT_SHIFT;
        data[16..24].copy_from_slice(&ordinary.to_le_bytes());
        // Authenticated DA with address diversity 0x1234, end of chain.
        let auth =
            0x200u64 | 0x1234 << DIVERSITY_SHIFT | ADDRESS_DIVERSITY | KEY_IS_DATA | AUTHENTICATED;
        data[24..32].copy_from_slice(&auth.to_le_bytes());
        // Slide info at page 1: v5, 16 KiB pages, one page start of 16.
        let mut info = Vec::new();
        info.extend(5u32.to_le_bytes());
        info.extend(0x4000u32.to_le_bytes());
        info.extend(1u32.to_le_bytes());
        info.extend(0u32.to_le_bytes());
        info.extend(0x1_8000_0000u64.to_le_bytes());
        info.extend(16u16.to_le_bytes());
        data[page..page + info.len()].copy_from_slice(&info);
        std::fs::write(&path, &data).unwrap();
        let slide = 0x4000;
        // A free range found here can be taken by a test on another thread
        // before the map reserves it, so a few fresh ranges are tried.
        let mut region = (0..16)
            .find_map(|_| {
                let start = memory::allocate(0, 0x8000, true, Protection::NONE).unwrap();
                memory::deallocate(start, 0x8000).unwrap();
                let request = MappingRequest {
                    path: path.clone(),
                    file_offset: 0,
                    address: start,
                    size: page as u64,
                    maximum: Protection::READ_WRITE,
                    initial: Protection::READ_WRITE,
                    slide_info: Some((page as u64, info.len() as u64)),
                };
                SharedRegion::map(&[request], start, 0x8000, slide).ok()
            })
            .expect("a free guest range for the shared region");
        let base = region.base();
        assert!(region.pending(base + 16));
        assert!(memory::read_u64(base + 16).is_none());
        let signer = signer();
        assert!(region.resolve(base + 16, &signer).unwrap());
        assert!(!region.resolve(base, &signer).unwrap());
        assert_eq!(
            memory::read_u64(base + 16).unwrap(),
            0x1_8000_0100 + slide + (0x80 << 56)
        );
        let location = base + 24;
        let expected = signer
            .sign(
                pauth::Key::Da,
                0x1_8000_0200 + slide,
                (location & BLEND_ADDRESS_MASK) | 0x1234 << 48,
            )
            .unwrap();
        assert_eq!(memory::read_u64(location).unwrap(), expected);
        assert_eq!(region.slid_pages(), 1);
        memory::deallocate(base, 0x8000).unwrap();
    }
}
