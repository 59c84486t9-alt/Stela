//! The process's shared region (XNU `osfmk/vm/vm_shared_region.c`,
//! `bsd/vm/vm_unix.c`). A new process's region is reserved and empty, as it
//! is for the first process to use a shared cache: `shared_region_check_np`
//! fails until dyld maps the cache with `shared_region_map_and_slide_2_np`,
//! at a slide the kernel chooses below the cache's maximum.
//!
//! Each `shared_file_mapping_slide_np` maps its file range privately at its
//! address plus the slide; the caller-memory file (descriptor -1, dyld's
//! dynamic-config page) is copied from the caller. A mapping with slide info
//! starts inaccessible and is slid one slide page at a time on first access,
//! as XNU's shared-region pager does (`vm_shared_region_slide_page_v5`):
//! ordinary pointers become `target + value_add + slide` with their high
//! byte restored, and authenticated pointers are signed with the A key their
//! descriptor names (IA or DA) under the shared region's keys, which are
//! this process's. A protection change over a page not yet slid is kept
//! for it, and the page takes it when slid; a page unmapped before it is
//! slid is no longer slid.
use super::memory::{self, PAGE_MASK, Protection};
use crate::pauth;
use anyhow::{Context as _, Result, bail, ensure};

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

/// The arm64 shared region (`SHARED_REGION_BASE_ARM64`,
/// `SHARED_REGION_SIZE_ARM64`). The size is the 26A434 build's, not the
/// open-source header's 0x1_8000_0000, which the 26A434 cache's own
/// `sharedRegionSize` (0x1_b9b1_4000) exceeds: its dyld reserves
/// 0xe_4000_0000 bytes at the base for the region, and its kernel bounds
/// shared-region addresses by the same size.
pub const REGION_START: u64 = 0x1_8000_0000;
pub const REGION_SIZE: u64 = 0xe_4000_0000;
/// `shared_file_mapping_slide_np` protection extensions. `VM_PROT_NOAUTH`
/// and `VM_PROT_TPRO` need no handling here: every mapping is private to
/// this process and signed with its keys.
const VM_PROT_ZF: u32 = 0x10;
const VM_PROT_SLIDE: u32 = 0x20;
const VM_PROT_BASIC: u32 = 0x7;
/// The descriptor of the file whose bytes are the caller's memory.
const NO_FILE: i32 = -1;
const KERN_INVALID_ARGUMENT: u64 = 4;
const KERN_FAILURE: u64 = 5;

/// One `shared_file_mapping_slide_np`, unslid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mapping {
    pub address: u64,
    pub size: u64,
    /// The file offset, or for the caller-memory file the source address.
    pub file_offset: u64,
    pub slide_size: u64,
    /// Where in the region (unslid) the mapping's slide info lies.
    pub slide_start: u64,
    pub maximum: u32,
    pub initial: u32,
}

/// One `shared_file_np` and its mappings.
#[derive(Debug, Clone)]
pub struct FileMappings {
    pub descriptor: i32,
    pub mappings: Vec<Mapping>,
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
    info: SlideInfo,
    /// Per slide page, the protection it takes once slid, until it is.
    pending: Vec<Option<Protection>>,
}

fn map_anonymous(address: u64, size: u64, protection: Protection) -> Result<()> {
    // SAFETY: a fixed anonymous mapping inside the reservation the region
    // owns.
    let mapped = unsafe {
        libc::mmap(
            address as *mut libc::c_void,
            size as usize,
            protection.0,
            libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED,
            -1,
            0,
        )
    };
    ensure!(
        mapped as u64 == address,
        "cannot map anonymous shared-region memory at {address:#x}: {}",
        std::io::Error::last_os_error()
    );
    Ok(())
}

/// Map a file range, or the host's errno.
fn map_file(
    address: u64,
    mapping: &Mapping,
    descriptor: i32,
    protection: Protection,
) -> Result<(), i32> {
    // SAFETY: a fixed private mapping of the caller's descriptor inside the
    // reservation the region owns.
    let mapped = unsafe {
        libc::mmap(
            address as *mut libc::c_void,
            mapping.size as usize,
            protection.0,
            libc::MAP_PRIVATE | libc::MAP_FIXED,
            descriptor,
            mapping.file_offset as libc::off_t,
        )
    };
    if mapped as u64 == address {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
    }
}

/// The caller-memory file: its bytes are copied from the caller.
fn map_copy(address: u64, mapping: &Mapping, protection: Protection) -> Result<bool> {
    let Some(bytes) = memory::read(mapping.file_offset, mapping.size as usize) else {
        return Ok(false);
    };
    map_anonymous(address, mapping.size, Protection::READ_WRITE)?;
    ensure!(memory::write(address, &bytes), "shared-region copy");
    memory::protect(address, mapping.size, protection)?;
    Ok(true)
}

pub struct SharedRegion {
    start: u64,
    size: u64,
    slide: u64,
    /// The slid address of the first file's first mapping, once mapped.
    first: Option<u64>,
    slid: Vec<SlidMapping>,
    slid_pages: u64,
}

impl SharedRegion {
    /// Reserve the process's empty shared region, which no other
    /// allocation may take (XNU keeps the range out of the task's map).
    pub fn reserve(start: u64, size: u64) -> Result<Self> {
        let reserved = memory::allocate(start, size, false, Protection::NONE)
            .context("the shared region's address range is occupied in this process")?;
        ensure!(reserved == start, "shared region placed at {reserved:#x}");
        Ok(Self::within(start, size))
    }

    /// The empty region over a reservation this process already holds.
    /// Mappings replace pages inside it, never another allocation's.
    fn within(start: u64, size: u64) -> Self {
        Self {
            start,
            size,
            slide: 0,
            first: None,
            slid: Vec::new(),
            slid_pages: 0,
        }
    }

    /// `_shared_region_map_and_slide` at `slide`: map every file's
    /// mappings, the caller-memory file by copying, and prepare the slid
    /// mappings' pages. The inner error is the call's `kern_return_t`.
    pub fn map(&mut self, files: &[FileMappings], slide: u64) -> Result<Result<(), u64>> {
        if self.first.is_some() {
            return Ok(Err(KERN_FAILURE));
        }
        ensure!(
            slide & PAGE_MASK == 0,
            "slide {slide:#x} is not page aligned"
        );
        for mapping in files.iter().flat_map(|file| &file.mappings) {
            let start = mapping.address.checked_add(slide);
            let end = start.and_then(|start| start.checked_add(mapping.size));
            let (Some(start), Some(end)) = (start, end) else {
                return Ok(Err(KERN_INVALID_ARGUMENT));
            };
            if start < self.start
                || end > self.start + self.size
                || (mapping.address | mapping.size) & PAGE_MASK != 0
            {
                return Ok(Err(KERN_INVALID_ARGUMENT));
            }
        }
        let mut sliding = Vec::new();
        for (index, file) in files.iter().enumerate() {
            for (position, mapping) in file.mappings.iter().enumerate() {
                if mapping.size == 0 {
                    continue;
                }
                let address = mapping.address + slide;
                let protection = Protection((mapping.initial & VM_PROT_BASIC) as i32);
                let slid = mapping.slide_size != 0 && mapping.initial & VM_PROT_SLIDE != 0;
                if file.descriptor == NO_FILE {
                    if !map_copy(address, mapping, protection)? {
                        return Ok(Err(KERN_INVALID_ARGUMENT));
                    }
                } else if mapping.maximum & VM_PROT_ZF != 0 {
                    map_anonymous(address, mapping.size, protection)?;
                } else {
                    let initial = if slid { Protection::NONE } else { protection };
                    if let Err(errno) = map_file(address, mapping, file.descriptor, initial) {
                        bail!(
                            "shared region: cannot map descriptor {} at {address:#x}: errno \
                             {errno}",
                            file.descriptor
                        );
                    }
                }
                if index == 0 && position == 0 {
                    self.first = Some(address);
                }
                if slid {
                    sliding.push((address, *mapping, protection));
                }
            }
        }
        // The slide info lies in the region itself (the cache's linkedit),
        // readable once every file is mapped.
        for (address, mapping, initial) in sliding {
            ensure!(mapping.slide_size <= MAX_SLIDE_INFO, "slide info too large");
            let bytes = memory::read(mapping.slide_start + slide, mapping.slide_size as usize)
                .context("slide info is not readable in the shared region")?;
            let info = parse_slide_info(&bytes)?;
            let pages = mapping.size.div_ceil(info.page_bytes) as usize;
            ensure!(
                info.page_starts.len() >= pages,
                "slide info covers {} of {pages} pages",
                info.page_starts.len()
            );
            self.slid.push(SlidMapping {
                address,
                size: mapping.size,
                pending: vec![Some(initial); pages],
                info,
            });
        }
        self.slide = slide;
        Ok(Ok(()))
    }

    /// The address `shared_region_check_np` reports, once mapped.
    pub fn mapped(&self) -> Option<u64> {
        self.first
    }

    pub fn slide(&self) -> u64 {
        self.slide
    }

    pub fn slid_pages(&self) -> u64 {
        self.slid_pages
    }

    /// Whether `address` lies in a slide page not yet slid.
    pub fn pending(&self, address: u64) -> bool {
        self.slid.iter().any(|mapping| {
            (mapping.address..mapping.address + mapping.size).contains(&address)
                && mapping.pending[((address - mapping.address) / mapping.info.page_bytes) as usize]
                    .is_some()
        })
    }

    /// Apply `change` to the protection the range's pending pages take
    /// once slid, or forget them (`None`, for an unmapping). The pages
    /// stay inaccessible until slid; the returned runs, ascending, are the
    /// rest of the range, whose host pages the caller changes itself.
    pub fn update(
        &mut self,
        address: u64,
        size: u64,
        mut change: impl FnMut(Protection) -> Option<Protection>,
    ) -> Vec<(u64, u64)> {
        let end = address.saturating_add(size);
        let mut held = Vec::new();
        for mapping in &mut self.slid {
            let page_bytes = mapping.info.page_bytes;
            for (index, pending) in mapping.pending.iter_mut().enumerate() {
                let page = mapping.address + index as u64 * page_bytes;
                let page_end = (page + page_bytes).min(mapping.address + mapping.size);
                if page >= end || page_end <= address {
                    continue;
                }
                if let Some(protection) = *pending {
                    *pending = change(protection);
                    held.push((page.max(address), page_end.min(end)));
                }
            }
        }
        held.sort_unstable();
        let mut runs = Vec::new();
        let mut cursor = address;
        for (start, stop) in held {
            if start > cursor {
                runs.push((cursor, start - cursor));
            }
            cursor = cursor.max(stop);
        }
        if cursor < end {
            runs.push((cursor, end - cursor));
        }
        runs
    }

    /// Slide the page holding `address` in, if it is pending: false when
    /// there was nothing to do.
    pub fn resolve(&mut self, address: u64, signer: Option<&pauth::Context>) -> Result<bool> {
        let slide = self.slide;
        let Some(mapping) = self
            .slid
            .iter_mut()
            .find(|mapping| (mapping.address..mapping.address + mapping.size).contains(&address))
        else {
            return Ok(false);
        };
        let index = ((address - mapping.address) / mapping.info.page_bytes) as usize;
        let Some(protection) = mapping.pending[index] else {
            return Ok(false);
        };
        let page = mapping.address + index as u64 * mapping.info.page_bytes;
        let bytes = mapping
            .info
            .page_bytes
            .min(mapping.address + mapping.size - page);
        memory::protect(page, bytes, Protection::READ_WRITE)?;
        let start = mapping.info.page_starts[index];
        if start != PAGE_ATTR_NO_REBASE {
            // One copy in and out: a copy per pointer costs a Mach call
            // each, thousands a page.
            let mut contents =
                memory::read(page, bytes as usize).context("slide page unreadable")?;
            slide_page(
                &mut contents,
                page,
                start,
                mapping.info.value_add,
                slide,
                signer,
            )?;
            ensure!(memory::write(page, &contents), "slide page unwritable");
        }
        memory::protect(page, bytes, protection)?;
        mapping.pending[index] = None;
        self.slid_pages += 1;
        Ok(true)
    }
}

/// `vm_shared_region_slide_page_v5` on `contents`, the bytes of the page
/// at `page`.
fn slide_page(
    contents: &mut [u8],
    page: u64,
    start: u16,
    value_add: u64,
    slide: u64,
    signer: Option<&pauth::Context>,
) -> Result<()> {
    let mut offset = usize::from(start);
    loop {
        let Some(word) = contents.get_mut(offset..offset + 8) else {
            bail!("slide chain leaves its page at {:#x}", page + offset as u64);
        };
        let location = page + offset as u64;
        let raw = u64::from_le_bytes((&*word).try_into().expect("eight"));
        let delta = ((raw >> NEXT_SHIFT) & NEXT_MASK) as usize * 8;
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
            // A region without pointer authentication (`si_ptrauth`
            // false: a process whose user JOP is disabled) keeps the
            // target unsigned.
            match signer {
                Some(signer) => signer.sign(key, target, modifier)?,
                None => target,
            }
        } else {
            target + ((raw << HIGH8_SHIFT) & HIGH8_MASK)
        };
        word.copy_from_slice(&value.to_le_bytes());
        if delta == 0 {
            return Ok(());
        }
        offset += delta;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    fn signer() -> pauth::Context {
        pauth::Context::new_with_version(
            0,
            pauth::Keys::from_words([1, 2], [3, 4], [5, 6], [7, 8]),
            pauth::Version::FaultingCombined,
        )
        .with_translation_regime(super::super::pe::TCR_EL1)
    }

    #[test]
    fn a_slide_chain_that_leaves_its_page_is_refused() {
        // An ordinary pointer at the page's last word whose next link
        // points past the page.
        let mut contents = vec![0u8; 0x4000];
        let last = contents.len() - 8;
        let chained = 0x100u64 | 1 << NEXT_SHIFT;
        contents[last..].copy_from_slice(&chained.to_le_bytes());
        let error = slide_page(&mut contents, 0x1_0000, last as u16, 0, 0, None).unwrap_err();
        assert!(error.to_string().contains("leaves its page"), "{error}");
        // The pointer before the bad link was slid.
        assert_eq!(&contents[last..], &0x100u64.to_le_bytes());
    }

    #[test]
    fn mapped_files_slide_lazily_and_the_caller_page_is_copied() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cache");
        let page = 0x4000usize;
        // Page 0: slid data. Page 1: the slide info ("linkedit").
        let mut data = vec![0u8; page * 2];
        // Ordinary: offset 0x100, high8 0x80, next 1 (8 bytes).
        let ordinary = 0x100u64 | 0x80 << 34 | 1 << NEXT_SHIFT;
        data[16..24].copy_from_slice(&ordinary.to_le_bytes());
        // Authenticated DA with address diversity 0x1234, end of chain.
        let auth =
            0x200u64 | 0x1234 << DIVERSITY_SHIFT | ADDRESS_DIVERSITY | KEY_IS_DATA | AUTHENTICATED;
        data[24..32].copy_from_slice(&auth.to_le_bytes());
        // v5, 16 KiB pages, one page start of 16.
        let mut info = Vec::new();
        info.extend(5u32.to_le_bytes());
        info.extend(0x4000u32.to_le_bytes());
        info.extend(1u32.to_le_bytes());
        info.extend(0u32.to_le_bytes());
        info.extend(0x1_8000_0000u64.to_le_bytes());
        info.extend(16u16.to_le_bytes());
        data[page..page + info.len()].copy_from_slice(&info);
        std::fs::write(&path, &data).unwrap();
        let file = std::fs::File::open(&path).unwrap();
        // A four-page reservation: data, linkedit, the copied page, slack.
        // It stays held throughout: freeing it to reserve it again would
        // let a concurrent test's allocation land there first, and the
        // fixed mappings would replace that allocation's pages.
        let start = memory::allocate(0, 0x10000, true, Protection::NONE).unwrap();
        let mut region = SharedRegion::within(start, 0x10000);
        assert_eq!(region.mapped(), None);
        let source = memory::allocate(0, 0x4000, true, Protection::READ_WRITE).unwrap();
        assert!(memory::write(source, b"dyld_data    v4\0"));
        let slide = 0x4000;
        let read = (libc::PROT_READ) as u32;
        let files = [
            FileMappings {
                descriptor: file.as_raw_fd(),
                mappings: vec![
                    Mapping {
                        address: start,
                        size: page as u64,
                        file_offset: 0,
                        slide_size: info.len() as u64,
                        slide_start: start + page as u64,
                        maximum: read | 2 | VM_PROT_SLIDE,
                        initial: read | 2 | VM_PROT_SLIDE,
                    },
                    Mapping {
                        address: start + page as u64,
                        size: page as u64,
                        file_offset: page as u64,
                        slide_size: 0,
                        slide_start: 0,
                        maximum: read,
                        initial: read,
                    },
                ],
            },
            FileMappings {
                descriptor: NO_FILE,
                mappings: vec![Mapping {
                    address: start + 2 * page as u64,
                    size: page as u64,
                    file_offset: source,
                    slide_size: 0,
                    slide_start: 0,
                    maximum: read,
                    initial: read,
                }],
            },
        ];
        // Outside the region: refused with KERN_INVALID_ARGUMENT.
        assert_eq!(
            region.map(&files, 0x8000).unwrap(),
            Err(KERN_INVALID_ARGUMENT)
        );
        region.map(&files, slide).unwrap().unwrap();
        let base = region.mapped().unwrap();
        assert_eq!(base, start + slide);
        assert_eq!(region.map(&files, slide).unwrap(), Err(KERN_FAILURE));
        assert_eq!(
            memory::read(base + 2 * page as u64, 16).unwrap(),
            b"dyld_data    v4\0"
        );
        assert!(!memory::write(base + 2 * page as u64, b"x"));
        assert!(region.pending(base + 16));
        assert!(memory::read_u64(base + 16).is_none());
        // A protection change waits for the pending page; the linkedit
        // page after it is the caller's to change.
        let page_bytes = page as u64;
        assert_eq!(
            region.update(base, 2 * page_bytes, |_| Some(Protection::READ)),
            vec![(base + page_bytes, page_bytes)]
        );
        assert!(memory::read_u64(base + 16).is_none());
        let signer = signer();
        assert!(region.resolve(base + 16, Some(&signer)).unwrap());
        assert!(!region.resolve(base, Some(&signer)).unwrap());
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
        // The protection change took effect when the page was slid.
        assert!(!memory::write(base + 16, b"x"));
        memory::deallocate(start, 0x10000).unwrap();
        memory::deallocate(source, 0x4000).unwrap();
    }
}
