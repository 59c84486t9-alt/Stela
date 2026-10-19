//! Virtual memory calls in the guest's 16 KiB pages (`bsd/kern/kern_mman.c`):
//! ranges are page-rounded as XNU rounds them on arm64 before the host
//! kernel, with its 4 KiB pages, performs them. A placement the guest leaves
//! to the kernel is a 16 KiB-aligned range the hosted kernel reserves first.
//! Mapping or unmapping over guest code drops its compiled blocks.
//!
//! `shared_region_check_np` reports the shared region mapped at launch
//! (`bsd/vm/vm_unix.c`).
use super::{Call, EFAULT, EINVAL, Kernel, Outcome, Pe, forward};
use crate::hosted::memory::{self, PAGE_BYTES, PAGE_MASK, Protection, round_page};
use anyhow::{Result, bail};

const MAP_FIXED: u64 = 0x0010;
/// `DYLD_VM_END_MWL`: dyld ends `map_with_linking_np` for the process.
const DYLD_VM_END_MWL: u64 = u64::MAX;
const HOST_PAGE_BYTES: u64 = 4096;
const HOST_PAGES_PER_PAGE: usize = (PAGE_BYTES / HOST_PAGE_BYTES) as usize;

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
            let outcome = forward_range(kernel, call, address, bytes)?;
            pe.invalidate_code(address, bytes);
            outcome
        }
        "mprotect" | "madvise" => {
            let (address, bytes) = (call.argument(0), call.argument(1));
            let start = address & !PAGE_MASK;
            let Some(end) = address.checked_add(bytes).and_then(round_page) else {
                return Ok(Some(Outcome::Error(EINVAL)));
            };
            forward_range(kernel, call, start, end - start)?
        }
        "mincore" => mincore(call)?,
        "shared_region_check_np" => shared_region_check(kernel, call)?,
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
    let outcome = forward(kernel, &placed)?;
    match outcome {
        Outcome::Return(mapped, _) if mapped == start => {
            pe.invalidate_code(start, size);
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
        kernel.map_with_linking_ended = true;
        return Ok(Outcome::value(0));
    }
    let Some(region) = &kernel.shared_region else {
        return Ok(Outcome::Error(EINVAL));
    };
    if pointer == 0 {
        bail!("shared_region_check_np(NULL): removing the shared region is not implemented");
    }
    Ok(if memory::write_u64(pointer, region.base()) {
        Outcome::value(0)
    } else {
        Outcome::Error(EFAULT)
    })
}
