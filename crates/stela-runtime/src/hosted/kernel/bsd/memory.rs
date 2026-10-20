//! Virtual memory calls in the guest's 16 KiB pages (`bsd/kern/kern_mman.c`):
//! ranges are page-rounded as XNU rounds them on arm64 before the host
//! kernel, with its 4 KiB pages, performs them. A placement the guest leaves
//! to the kernel is a 16 KiB-aligned range the hosted kernel reserves first.
//! Mapping or unmapping over guest code drops its compiled blocks. A
//! protection change or unmapping over shared-region pages not yet slid
//! applies to them as they are slid.
//!
//! The shared-region calls (`bsd/vm/vm_unix.c`): `shared_region_check_np`
//! reports the region's first mapping once `shared_region_map_and_slide_2_np`
//! has mapped the cache, and fails with ENOMEM before.
use super::{Call, EFAULT, EINVAL, ENOMEM, Kernel, Outcome, Pe, forward, forward_uninterruptible};
use crate::hosted::memory::{self, PAGE_BYTES, PAGE_MASK, Protection, round_page};
use crate::hosted::{shared_region, threads::lock};
use anyhow::{Result, bail};
use core::sync::atomic::Ordering;

const MAP_FIXED: u64 = 0x0010;
const EBUSY: u64 = 16;
/// `DYLD_VM_END_MWL`: dyld ends `map_with_linking_np` for the process.
const DYLD_VM_END_MWL: u64 = u64::MAX;
const HOST_PAGE_BYTES: u64 = 4096;
const HOST_PAGES_PER_PAGE: usize = (PAGE_BYTES / HOST_PAGE_BYTES) as usize;

pub(super) const CALLS: &[&str] = &[
    "mmap",
    "munmap",
    "mprotect",
    "madvise",
    "mincore",
    "shared_region_check_np",
    "shared_region_map_and_slide_2_np",
    "map_with_linking_np",
];

pub(super) fn call(kernel: &mut Kernel, pe: &mut Pe, call: &Call) -> Result<Option<Outcome>> {
    Ok(Some(match call.entry.name {
        "mmap" => mmap(kernel, pe, call)?,
        "munmap" => {
            let (address, bytes) = (call.argument(0), call.argument(1));
            if address & PAGE_MASK != 0 {
                return Ok(Some(Outcome::Error(EINVAL)));
            }
            let Some(bytes) = round_page(bytes) else {
                return Ok(Some(Outcome::Error(EINVAL)));
            };
            kernel.unslid_change(address, bytes, |_| None);
            let outcome = forward_range(kernel, call, address, bytes)?;
            kernel.invalidate_code(pe, address, bytes);
            outcome
        }
        "mprotect" => {
            let (address, bytes) = (call.argument(0), call.argument(1));
            let start = address & !PAGE_MASK;
            let Some(end) = address.checked_add(bytes).and_then(round_page) else {
                return Ok(Some(Outcome::Error(EINVAL)));
            };
            let protection = Protection(call.argument(2) as i32 & Protection::ALL.0);
            let runs = kernel.unslid_change(start, end - start, |_| Some(protection));
            let mut outcome = Outcome::value(0);
            for (run, size) in runs {
                outcome = forward_range(kernel, call, run, size)?;
                if !matches!(outcome, Outcome::Return(..)) {
                    break;
                }
            }
            outcome
        }
        "madvise" => {
            let (address, bytes) = (call.argument(0), call.argument(1));
            let start = address & !PAGE_MASK;
            let Some(end) = address.checked_add(bytes).and_then(round_page) else {
                return Ok(Some(Outcome::Error(EINVAL)));
            };
            forward_range(kernel, call, start, end - start)?
        }
        "mincore" => mincore(call)?,
        "shared_region_check_np" => shared_region_check(kernel, call)?,
        "shared_region_map_and_slide_2_np" => map_and_slide(kernel, pe, call)?,
        "map_with_linking_np" => super::linking::call(kernel, pe, call)?,
        _ => return Ok(None),
    }))
}

/// Forward `call` with its first two arguments replaced by a rounded range.
fn forward_range(kernel: &mut Kernel, call: &Call, address: u64, bytes: u64) -> Result<Outcome> {
    let mut rounded = Call {
        entry: call.entry,
        arguments: call.arguments,
    };
    rounded.arguments[0] = address;
    rounded.arguments[1] = bytes;
    forward(kernel, &rounded)
}

/// `mmap`: the file offset's position within its page carries over to the
/// returned address, and the whole pages are mapped.
fn mmap(kernel: &mut Kernel, pe: &mut Pe, call: &Call) -> Result<Outcome> {
    let [address, bytes, _, flags, descriptor, position, ..] = call.arguments;
    let offset = position & PAGE_MASK;
    let Some(size) = bytes.checked_add(offset).and_then(round_page) else {
        return Ok(Outcome::Error(EINVAL));
    };
    if size == 0 {
        return Ok(Outcome::Error(EINVAL));
    }
    let fixed = flags & MAP_FIXED != 0;
    let start = if fixed {
        if address & PAGE_MASK != offset {
            return Ok(Outcome::Error(EINVAL));
        }
        address - offset
    } else {
        // The kernel's own choice, 16 KiB aligned, at or above the hint.
        match memory::allocate(address & !PAGE_MASK, size, true, Protection::NONE) {
            Ok(start) => start,
            Err(_) => return Ok(Outcome::Error(super::ENOMEM)),
        }
    };
    let mut placed = Call {
        entry: call.entry,
        arguments: call.arguments,
    };
    placed.arguments[0] = start;
    placed.arguments[1] = size;
    placed.arguments[3] = flags | MAP_FIXED;
    placed.arguments[4] = descriptor;
    placed.arguments[5] = position - offset;
    let mut outcome = forward_uninterruptible(kernel, &placed)?;
    // An object shorter than the guest page, such as a host process's
    // POSIX shared memory sized in 4 KiB pages, refuses a mapping past its
    // end: map it in host pages and fill the rest of the guest page with
    // zeros, as the arm64 kernel's whole-page mapping reads past the end.
    // The filled tail is the process's own, not the object's.
    let host_size = memory::round_host_page(bytes + offset).unwrap_or(size);
    if matches!(outcome, Outcome::Error(EINVAL | EBUSY)) && host_size < size {
        placed.arguments[1] = host_size;
        outcome = forward_uninterruptible(kernel, &placed)?;
        if kernel.trace {
            eprintln!(
                "stela: mmap of {size:#x} bytes refused; mapped {host_size:#x} in host pages: \
                 {outcome:x?}"
            );
        }
        if matches!(outcome, Outcome::Return(mapped, _) if mapped == start) {
            let protection = Protection(call.argument(2) as i32 & Protection::ALL.0);
            let status = memory::fill_host_pages(start + host_size, size - host_size, protection);
            if status != 0 {
                bail!(
                    "the rest of the guest page past a {host_size:#x}-byte mapping at {start:#x} \
                     could not be mapped: kern_return {status}"
                );
            }
        }
    }
    match outcome {
        Outcome::Return(mapped, _) if mapped == start => {
            kernel.invalidate_code(pe, start, size);
            Ok(Outcome::value(start + offset))
        }
        Outcome::Return(mapped, _) => bail!("host mmap placed {mapped:#x}, not {start:#x}"),
        error => {
            if !fixed {
                memory::deallocate(start, size)?;
            }
            Ok(error)
        }
    }
}

/// `mincore`: one status byte per guest page, the union of its host pages'.
fn mincore(call: &Call) -> Result<Outcome> {
    let [address, bytes, vector, ..] = call.arguments;
    let start = address & !PAGE_MASK;
    let Some(end) = address.checked_add(bytes).and_then(round_page) else {
        return Ok(Outcome::Error(EINVAL));
    };
    let pages = ((end - start) / PAGE_BYTES) as usize;
    let mut host = vec![0u8; pages * HOST_PAGES_PER_PAGE];
    // SAFETY: the host fills one byte per 4 KiB page of the range.
    let status = unsafe {
        libc::mincore(
            start as *const libc::c_void,
            (end - start) as usize,
            host.as_mut_ptr().cast(),
        )
    };
    if status != 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Ok(Outcome::Error(errno as u64));
    }
    let guest: Vec<u8> = host
        .as_chunks::<HOST_PAGES_PER_PAGE>()
        .0
        .iter()
        .map(|chunk| chunk.iter().fold(0, |status, &byte| status | byte))
        .collect();
    Ok(if memory::write(vector, &guest) {
        Outcome::value(0)
    } else {
        Outcome::Error(EFAULT)
    })
}

fn shared_region_check(kernel: &mut Kernel, call: &Call) -> Result<Outcome> {
    let pointer = call.argument(0);
    if pointer == DYLD_VM_END_MWL {
        kernel
            .process
            .map_with_linking_ended
            .store(true, Ordering::SeqCst);
        return Ok(Outcome::value(0));
    }
    let region = lock(&kernel.process.shared_region);
    let Some(region) = region.as_ref() else {
        return Ok(Outcome::Error(EINVAL));
    };
    if pointer == 0 {
        bail!("shared_region_check_np(NULL): removing the shared region is not implemented");
    }
    // A region nothing has mapped yet has no first mapping
    // (`vm_shared_region_start_address` fails, and the call with ENOMEM).
    let Some(base) = region.mapped() else {
        return Ok(Outcome::Error(ENOMEM));
    };
    Ok(if memory::write_u64(pointer, base) {
        Outcome::value(0)
    } else {
        Outcome::Error(EFAULT)
    })
}

/// `struct shared_file_np` and `struct shared_file_mapping_slide_np`.
const FILE_BYTES: usize = 12;
const MAPPING_BYTES: usize = 48;
/// `_SR_FILE_MAPPINGS_MAX_FILES` and `SFM_MAX`.
const MAX_FILES: u64 = 256;
const MAX_MAPPINGS: u64 = MAX_FILES * 8;
const KERN_FAILURE: u64 = 5;

/// `shared_region_map_and_slide_2_np(files_count, files, mappings_count,
/// mappings)`: the kernel picks the slide below the first file's
/// `sf_slide`, page aligned, and maps every file's mappings at it.
fn map_and_slide(kernel: &mut Kernel, pe: &mut Pe, call: &Call) -> Result<Outcome> {
    let [files_count, files, mappings_count, mappings, ..] = call.arguments;
    let (files_count, mappings_count) = (files_count as u32 as u64, mappings_count as u32 as u64);
    if files_count == 0 || mappings_count == 0 {
        return Ok(Outcome::value(0));
    }
    if files_count > MAX_FILES || mappings_count > MAX_MAPPINGS {
        return Ok(Outcome::Error(KERN_FAILURE));
    }
    let (Some(file_bytes), Some(mapping_bytes)) = (
        memory::read(files, files_count as usize * FILE_BYTES),
        memory::read(mappings, mappings_count as usize * MAPPING_BYTES),
    ) else {
        return Ok(Outcome::Error(EFAULT));
    };
    let word = |bytes: &[u8], at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
    let double =
        |bytes: &[u8], at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
    let mut records = mapping_bytes
        .as_chunks::<MAPPING_BYTES>()
        .0
        .iter()
        .map(|record| shared_region::Mapping {
            address: double(record, 0),
            size: double(record, 8),
            file_offset: double(record, 16),
            slide_size: double(record, 24),
            slide_start: double(record, 32),
            maximum: word(record, 40),
            initial: word(record, 44),
        });
    let mut grouped = Vec::new();
    for file in file_bytes.as_chunks::<FILE_BYTES>().0 {
        let count = word(file, 4) as usize;
        let mappings: Vec<_> = records.by_ref().take(count).collect();
        if mappings.len() != count {
            return Ok(Outcome::Error(KERN_FAILURE));
        }
        grouped.push(shared_region::FileMappings {
            descriptor: word(file, 0) as i32,
            mappings,
        });
    }
    let maximum = u64::from(word(&file_bytes, 8));
    let slide = if maximum == 0 {
        0
    } else {
        let mut random = 0u32;
        // SAFETY: four bytes into this frame.
        unsafe { libc::getentropy((&raw mut random).cast(), 4) };
        (u64::from(random) % maximum) & !PAGE_MASK
    };
    // No thread executes guest code while the cache's pages appear.
    let process = kernel.process.clone();
    let mapped = kernel.exclusive(|| {
        lock(&process.shared_region)
            .as_mut()
            .map(|region| region.map(&grouped, slide))
    });
    let Some(mapped) = mapped else {
        return Ok(Outcome::Error(KERN_FAILURE));
    };
    Ok(match mapped? {
        Ok(()) => {
            kernel.invalidate_code(pe, shared_region::REGION_START, shared_region::REGION_SIZE);
            if kernel.trace {
                eprintln!("stela: shared region mapped at slide {slide:#x}");
            }
            Outcome::value(0)
        }
        Err(kern_return) => Outcome::Error(kern_return),
    })
}
