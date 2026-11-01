//! Anonymous files: llvmpipe keeps device memory in one and binds its pages to
//! the addresses of sparse resources. As with memfd, every mapping shares a
//! file's pages, and they last until the file and its mappings have gone.
use super::{PAGE, installed};
use crate::{layout, native_memory::SOURCE, native_mmio::Window};
use alloc::{collections::BTreeMap, vec::Vec};
use core::{
    cell::UnsafeCell,
    ffi::{c_int, c_void},
    ptr,
    sync::atomic::{AtomicBool, Ordering},
};
use stela_boot_core::page_window::Cache;
use stela_drivers::bus::dma::memory::{CacheAttribute, PageSource, PinnedPages};

/// `STELA_LIBC_FILE_BASE`, clear of the Linux environment's descriptors.
const FIRST_DESCRIPTOR: c_int = 1 << 24;

const EBADF: c_int = 9;
const ENOMEM: c_int = 12;
const EBUSY: c_int = 16;
const ENODEV: c_int = 19;
const EINVAL: c_int = 22;
const ENOTSUP: c_int = 95;

#[derive(Default)]
struct File {
    /// The descriptor and the mappings that bind this file.
    references: usize,
    bytes: u64,
    /// By first page; pages exist once something maps them.
    blocks: BTreeMap<u64, PinnedPages>,
}

impl File {
    /// `first` and the `count` pages after it, zeroed where they are new.
    fn pages(&mut self, first: u64, count: u64) -> Result<Vec<u64>, c_int> {
        let mut pages = Vec::new();
        pages
            .try_reserve_exact(count as usize)
            .map_err(|_| ENOMEM)?;
        let (mut page, end) = (first, first + count);
        while page < end {
            let held = self
                .blocks
                .range(..=page)
                .next_back()
                .and_then(|(&at, block)| {
                    let list = block.physical_pages();
                    list.get((page - at) as usize..)
                });
            if let Some(list) = held {
                let taken = list.len().min((end - page) as usize);
                pages.extend_from_slice(&list[..taken]);
                page += taken as u64;
                continue;
            }
            let next = self
                .blocks
                .range(page..)
                .next()
                .map_or(end, |(&at, _)| at.min(end));
            let block = SOURCE
                .allocate(
                    ((next - page) * PAGE) as usize,
                    PAGE as usize,
                    CacheAttribute::WriteBack,
                )
                .map_err(|_| ENOMEM)?;
            for &physical in block.physical_pages() {
                // SAFETY: a page this block owns, in the physical map.
                unsafe {
                    ptr::write_bytes(layout::physical(physical) as *mut u8, 0, PAGE as usize);
                }
            }
            self.blocks.insert(page, block);
        }
        Ok(pages)
    }
}

struct Mapping {
    pages: u64,
    /// The file behind its addresses when nothing is bound there.
    anonymous: Option<c_int>,
    /// Each file bound here, holding one reference.
    bound: Vec<c_int>,
}

#[derive(Default)]
struct Table {
    next: c_int,
    files: BTreeMap<c_int, File>,
    mappings: BTreeMap<u64, Mapping>,
}

impl Table {
    fn create(&mut self, bytes: u64) -> c_int {
        let descriptor = FIRST_DESCRIPTOR + self.next;
        self.next += 1;
        self.files.insert(
            descriptor,
            File {
                references: 1,
                bytes,
                blocks: BTreeMap::new(),
            },
        );
        descriptor
    }

    fn release(&mut self, descriptor: c_int) {
        let Some(file) = self.files.get_mut(&descriptor) else {
            return;
        };
        file.references -= 1;
        if file.references == 0 {
            self.files.remove(&descriptor);
        }
    }

    /// The mapping holding `address..address + pages`, with its base.
    fn holding(&mut self, address: u64, pages: u64) -> Option<(u64, &mut Mapping)> {
        let (&base, mapping) = self.mappings.range_mut(..=address).next_back()?;
        (address + pages * PAGE <= base + mapping.pages * PAGE).then_some((base, mapping))
    }

    /// The pages `fd` puts at `first`, and that it stays bound.
    fn bind(&mut self, fd: c_int, first: u64, count: u64) -> Result<Vec<u64>, c_int> {
        let file = self.files.get_mut(&fd).ok_or(EBADF)?;
        if (first + count) * PAGE > file.bytes {
            return Err(EINVAL);
        }
        let pages = file.pages(first, count)?;
        file.references += 1;
        Ok(pages)
    }
}

struct Locked {
    held: AtomicBool,
    table: UnsafeCell<Option<Table>>,
}

// SAFETY: `held` guards `table`.
unsafe impl Sync for Locked {}

static TABLE: Locked = Locked {
    held: AtomicBool::new(false),
    table: UnsafeCell::new(None),
};

/// Runs `body` over the table. Page table work waits on other processors, so
/// it stays outside.
fn with<T>(body: impl FnOnce(&mut Table) -> T) -> T {
    while TABLE
        .held
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    // SAFETY: the held lock; nothing below re-enters it.
    let result = body(unsafe { &mut *TABLE.table.get() }.get_or_insert_default());
    TABLE.held.store(false, Ordering::Release);
    result
}

fn install(window: &Window, address: u64, pages: &[u64]) -> bool {
    pages
        .iter()
        .zip(0..)
        .all(|(&physical, page)| window.install(address + page * PAGE, physical, Cache::WriteBack))
}

/// New addresses for `fd`'s pages from `offset`, or for fresh ones.
fn map_new(window: &Window, fd: c_int, offset: u64, count: u64) -> Result<u64, c_int> {
    let (file, anonymous, first) = if fd < 0 {
        let file = with(|table| table.create(count * PAGE));
        (file, Some(file), 0)
    } else {
        (fd, None, offset / PAGE)
    };
    let opened = with(|table| {
        let pages = table.bind(file, first, count);
        // What this mapping binds holds the only reference it needs.
        if anonymous.is_some() {
            table.release(file);
        }
        pages
    });
    let pages = opened?;
    let reserved = window.reserve(count as usize).ok_or(ENOMEM);
    let address = reserved.inspect_err(|_| with(|table| table.release(file)))?;
    if !install(window, address, &pages) {
        // A processor that kept the translation keeps the pages too.
        if window.remove(address, count as usize) {
            window.release(address, count as usize);
            with(|table| table.release(file));
        }
        return Err(ENOMEM);
    }
    with(|table| {
        table.mappings.insert(
            address,
            Mapping {
                pages: count,
                anonymous,
                bound: alloc::vec![file],
            },
        )
    });
    Ok(address)
}

/// Binds `fd`'s pages from `offset`, or the mapping's own zeroed ones, at
/// `address` inside a mapping.
fn map_fixed(
    window: &Window,
    fd: c_int,
    offset: u64,
    address: u64,
    count: u64,
) -> Result<u64, c_int> {
    let pages = with(|table| -> Result<Vec<u64>, c_int> {
        let (base, mapping) = table.holding(address, count).ok_or(EINVAL)?;
        let pages = mapping.pages;
        let anonymous = mapping.anonymous;
        if fd >= 0 {
            let bound = table.bind(fd, offset / PAGE, count)?;
            let (_, mapping) = table.holding(address, count).ok_or(EINVAL)?;
            if mapping.bound.contains(&fd) {
                table.release(fd);
            } else {
                mapping.bound.push(fd);
            }
            return Ok(bound);
        }
        let own = match anonymous {
            Some(own) => own,
            None => {
                let own = table.create(pages * PAGE);
                let (_, mapping) = table.holding(address, count).ok_or(EINVAL)?;
                mapping.anonymous = Some(own);
                mapping.bound.push(own);
                own
            }
        };
        let file = table.files.get_mut(&own).ok_or(EBADF)?;
        let bound = file.pages((address - base) / PAGE, count)?;
        for &physical in &bound {
            // SAFETY: a page of this file, in the physical map.
            unsafe { ptr::write_bytes(layout::physical(physical) as *mut u8, 0, PAGE as usize) };
        }
        Ok(bound)
    })?;
    if !window.remove(address, count as usize) {
        return Err(EBUSY);
    }
    if install(window, address, &pages) {
        Ok(address)
    } else {
        Err(ENOMEM)
    }
}

#[unsafe(no_mangle)]
extern "C" fn stela_libc_file_create() -> c_int {
    with(|table| table.create(0))
}

#[unsafe(no_mangle)]
extern "C" fn stela_libc_file_close(fd: c_int) -> c_int {
    with(|table| {
        if !table.files.contains_key(&fd) {
            return -EBADF;
        }
        table.release(fd);
        0
    })
}

#[unsafe(no_mangle)]
extern "C" fn stela_libc_file_resize(fd: c_int, bytes: u64) -> c_int {
    with(|table| {
        let Some(file) = table.files.get_mut(&fd) else {
            return -EBADF;
        };
        // Mesa only ever grows these; nothing here frees mapped pages.
        if bytes < file.bytes {
            return -ENOTSUP;
        }
        file.bytes = bytes;
        0
    })
}

#[unsafe(no_mangle)]
extern "C" fn stela_libc_file_mmap(
    fd: c_int,
    offset: u64,
    size: usize,
    address: *mut c_void,
) -> *mut c_void {
    let mapped = (|| {
        let gpu = installed().ok_or(ENODEV)?;
        let address = address as u64;
        if size == 0 || !offset.is_multiple_of(PAGE) || !address.is_multiple_of(PAGE) {
            return Err(EINVAL);
        }
        let count = (size as u64).div_ceil(PAGE);
        if address == 0 {
            map_new(gpu.window, fd, offset, count)
        } else {
            map_fixed(gpu.window, fd, offset, address, count)
        }
    })();
    match mapped {
        Ok(address) => address as *mut c_void,
        Err(error) => -(error as isize) as *mut c_void,
    }
}

#[unsafe(no_mangle)]
extern "C" fn stela_libc_file_munmap(address: *mut c_void, size: usize) -> c_int {
    let address = address as u64;
    let Some(gpu) = installed() else {
        return 0;
    };
    let count = (size as u64).div_ceil(PAGE);
    let taken = with(|table| {
        let (base, mapping) = table.holding(address, 1)?;
        Some(if base == address && mapping.pages == count {
            table.mappings.remove(&address).ok_or(-EINVAL)
        } else {
            Err(-EINVAL)
        })
    });
    let mapping = match taken {
        None => return 0,
        Some(Err(error)) => return error,
        Some(Ok(mapping)) => mapping,
    };
    // A processor that kept the translation keeps the pages too.
    if gpu.window.remove(address, count as usize) {
        gpu.window.release(address, count as usize);
        with(|table| mapping.bound.iter().for_each(|&file| table.release(file)));
    }
    1
}
