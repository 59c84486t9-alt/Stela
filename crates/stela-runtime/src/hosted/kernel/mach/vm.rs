//! The `mach_vm` MIG routines (`osfmk/mach/mach_vm.defs`) a hosted process
//! sends to its own task port: the virtual memory of its own address
//! space, which the arm64 kernel manages in 16 KiB pages and the x86 host
//! in 4 KiB pages. [`super::server`] serves `mach_vm_map`, `mach_vm`'s
//! deferred reclamation buffer and the other subsystems' routines, and
//! asks [`serve`] for the rest; a routine neither serves stops the run
//! naming it.
//!
//! This task's address space is the host process's own, so each routine
//! is performed by the host's own `mach_vm` call on the guest pages the
//! arm64 kernel would affect: every range is first widened to whole
//! 16 KiB pages (`vm_map_trunc_page`/`vm_map_round_page` over the task's
//! page mask) and every placement the kernel chooses is 16 KiB aligned. A
//! range over a guest page the host maps in parts it would treat apart
//! (of differing protections, or around a hole) is refused by name.
//! Shared-region
//! pages not yet slid are slid before their bytes are read, shared or
//! copied, and keep a protection change or forget an unmapping as the
//! slide pager's pages do. Changed guest ranges drop their compiled blocks
//! in every thread before it next runs guest code.
//!
//! `mach_vm_read`'s data travels out of line in its reply, which the host
//! kernel copies into the guest's new memory and the reply path moves into
//! guest pages of its own; `mach_vm_read_list` copies each range into new
//! guest pages of this task. `mach_vm_region`'s reply carries its
//! `object_name` port and is forwarded where the host's answer is the
//! arm64 kernel's.
use super::super::Kernel;
use super::server::{Descriptor, KERN_INVALID_ARGUMENT, MIG_BAD_ARGUMENTS, Reply, Request};
use crate::hosted::memory::{self, HOST_PAGE_MASK, PAGE_BYTES, PAGE_MASK, Protection};
use crate::hosted::shared_region::{REGION_SIZE, REGION_START};
use crate::hosted::threads::lock;
use anyhow::{Result, bail};

/// The limit of a routine over guest pages the host may map in parts.
const SPLIT_PAGE: &str =
    "a range over a guest page the host maps in parts of differing protections is refused";

/// The routines [`serve`] answers or forwards, with the named limit of a
/// routine served only in part.
pub(crate) const SERVED: &[(&str, Option<&str>)] = &[
    (
        "_kernelrpc_mach_vm_remap_external",
        Some(
            "from this task's own address space; a source over a guest page the host maps in \
             parts of differing protections is refused",
        ),
    ),
    (
        "_kernelrpc_mach_vm_remap_new_external",
        Some(
            "from this task's own address space; a source over a guest page the host maps in \
             parts of differing protections is refused",
        ),
    ),
    (
        "_kernelrpc_mach_vm_allocate_external",
        Some("VM_FLAGS_TPRO and VM_FLAGS_MTE allocations are refused"),
    ),
    ("_kernelrpc_mach_vm_deallocate_external", None),
    (
        "_kernelrpc_mach_vm_reallocate",
        Some(
            "a source over a guest page the host maps in parts of differing protections is \
             refused; JIT and TPRO source entries are not told apart from others",
        ),
    ),
    ("_kernelrpc_mach_vm_protect", None),
    ("mach_vm_inherit", None),
    (
        "mach_vm_write",
        Some(
            "a destination over a guest page the host maps in parts of differing protections, \
             or unreadable out-of-line data, is refused",
        ),
    ),
    (
        "_kernelrpc_mach_vm_read",
        Some(
            "a range over a guest page the host maps in parts of differing protections is \
             refused; the data's offset in its guest page is its offset in its host page, and \
             the rest of its guest pages is zero",
        ),
    ),
    ("mach_vm_read_list", Some(SPLIT_PAGE)),
    ("mach_vm_copy", Some(SPLIT_PAGE)),
    ("mach_vm_read_overwrite", Some(SPLIT_PAGE)),
    (
        "mach_vm_msync",
        Some("VM_SYNC_KILLPAGES and VM_SYNC_REUSABLEPAGES over the shared region are refused"),
    ),
    (
        "mach_vm_behavior_set",
        Some("VM_BEHAVIOR_FREE and the reusable behaviors over the shared region are refused"),
    ),
    (
        "mach_vm_region",
        Some(
            "the basic flavors of a region in whole guest pages outside the shared region, \
             forwarded (its reply is complex); the x86 runtime's own mappings are regions of \
             this task",
        ),
    ),
    (
        "mach_vm_region_recurse",
        Some(
            "regions in whole guest pages outside the shared region, host regions meeting \
             inside a guest page merged into one entry; page counts are the host's restated in \
             guest pages, rounded up; the x86 runtime's own mappings are regions of this task",
        ),
    ),
    (
        "mach_vm_page_query",
        Some(
            "a guest page's disposition is the union of its host pages', its reference count \
             their largest",
        ),
    ),
    (
        "mach_vm_page_info",
        Some(
            "a guest page's disposition is the union of its host pages', its reference count \
             their largest",
        ),
    ),
    (
        "mach_vm_page_range_query",
        Some("a guest page's disposition is the union of its host pages'"),
    ),
    ("_kernelrpc_mach_vm_purgable_control_external", None),
    ("mach_vm_machine_attribute", None),
    ("mach_vm_range_create", None),
    ("_kernelrpc_mach_vm_update_pointers_with_remote_tags", None),
];

/// Routines whose request carries descriptors (`MACH_MSGH_BITS_COMPLEX`).
const COMPLEX: &[&str] = &[
    "_kernelrpc_mach_vm_remap_external",
    "_kernelrpc_mach_vm_remap_new_external",
    "mach_vm_write",
];

/// Answer `routine` sent to this task, or `None` when it is not served
/// here. `complex` is the request's `MACH_MSGH_BITS_COMPLEX`.
pub(super) fn serve(
    kernel: &mut Kernel,
    routine: &str,
    complex: bool,
    request: &Request,
) -> Result<Option<Reply>> {
    route(kernel, routine, complex, request)
}

fn route(
    task: &mut dyn Task,
    routine: &str,
    complex: bool,
    request: &Request,
) -> Result<Option<Reply>> {
    if !SERVED.iter().any(|&(name, _)| name == routine) {
        return Ok(None);
    }
    // The MIG server stub checks the message's shape first.
    if complex != COMPLEX.contains(&routine) {
        return Ok(Some(Reply::Failure(MIG_BAD_ARGUMENTS)));
    }
    Ok(Some(match routine {
        "_kernelrpc_mach_vm_remap_external" => remap(task, request, false)?,
        "_kernelrpc_mach_vm_remap_new_external" => remap(task, request, true)?,
        "_kernelrpc_mach_vm_allocate_external" => allocate(task, request)?,
        "_kernelrpc_mach_vm_deallocate_external" => deallocate(task, request),
        "_kernelrpc_mach_vm_reallocate" => reallocate(task, request)?,
        "_kernelrpc_mach_vm_protect" => protect(task, request),
        "mach_vm_inherit" => inherit(request),
        "mach_vm_write" => write(task, request)?,
        "_kernelrpc_mach_vm_read" => read(task, request)?,
        "mach_vm_read_list" => read_list(task, request)?,
        "mach_vm_copy" => copy(task, request)?,
        "mach_vm_read_overwrite" => read_overwrite(task, request)?,
        "mach_vm_msync" => msync(request)?,
        "mach_vm_behavior_set" => behavior_set(request)?,
        "mach_vm_region" => region(request)?,
        "mach_vm_region_recurse" => region_recurse(request)?,
        "mach_vm_page_query" => page_query(request),
        "mach_vm_page_info" => page_info(request),
        "mach_vm_page_range_query" => page_range_query(request),
        "_kernelrpc_mach_vm_purgable_control_external" => purgable_control(request),
        "mach_vm_machine_attribute" => machine_attribute(task, request),
        // Release macOS kernels are built without user VM ranges
        // (`CONFIG_MAP_RANGES`, KERN_NOT_SUPPORTED) and the M2 without
        // MTE (`HAS_MTE`): the host's answers, after the same argument
        // checks, are the arm64 kernel's.
        "mach_vm_range_create" | "_kernelrpc_mach_vm_update_pointers_with_remote_tags" => {
            Reply::Forward
        }
        _ => unreachable!("every served routine is routed"),
    }))
}

/// What a routine needs of the hosted kernel beyond the host's own VM
/// calls on this task.
trait Task {
    /// This task's port name in its own space.
    fn port(&self) -> u32;
    /// Slide the shared-region pages of `[start, end)` not yet slid.
    fn page_in(&mut self, start: u64, end: u64) -> Result<()>;
    /// [`Kernel::unslid_change`].
    fn unslid_change(
        &mut self,
        start: u64,
        size: u64,
        change: &mut dyn FnMut(Protection) -> Option<Protection>,
    ) -> Vec<(u64, u64)>;
    /// Drop the compiled blocks of a changed range in every thread.
    fn invalidate(&self, address: u64, bytes: u64);
}

/// A registry identifier no thread has (the service threads' own), so
/// that every thread, the calling one included, drops the range before it
/// next runs guest code: a MIG routine has no engine of its own at hand.
const EVERY_THREAD: u64 = u64::MAX;

impl Task for Kernel {
    fn port(&self) -> u32 {
        self.process.task_port()
    }

    fn page_in(&mut self, start: u64, end: u64) -> Result<()> {
        let (low, high) = (start.max(REGION_START), end.min(REGION_START + REGION_SIZE));
        if low >= high {
            return Ok(());
        }
        let pending: Vec<u64> = {
            let region = lock(&self.process.shared_region);
            let Some(region) = region.as_ref() else {
                return Ok(());
            };
            (memory::trunc_page(low)..high)
                .step_by(PAGE_BYTES as usize)
                .filter(|&page| region.pending(page))
                .collect()
        };
        for page in pending {
            Kernel::page_in(self, page)?;
        }
        Ok(())
    }

    fn unslid_change(
        &mut self,
        start: u64,
        size: u64,
        change: &mut dyn FnMut(Protection) -> Option<Protection>,
    ) -> Vec<(u64, u64)> {
        Kernel::unslid_change(self, start, size, change)
    }

    fn invalidate(&self, address: u64, bytes: u64) {
        if bytes != 0 {
            self.process
                .runtime
                .registry
                .invalidate(EVERY_THREAD, address, bytes);
        }
    }
}

const KERN_SUCCESS: i32 = 0;
const KERN_INVALID_ADDRESS: u32 = 1;
/// `MIG_TYPE_ERROR`: a field's type or size disagrees with the routine.
const MIG_TYPE_ERROR: u32 = (-300i32) as u32;

/// `osfmk/mach/vm_statistics.h`.
const VM_FLAGS_ANYWHERE: i32 = 0x1;
const VM_FLAGS_TPRO: i32 = 0x1000;
const VM_FLAGS_MTE: i32 = 0x2000;
const VM_FLAGS_OVERWRITE: i32 = 0x4000;
const VM_FLAGS_SUPERPAGE_MASK: i32 = 0x7_0000;
const VM_FLAGS_RETURN_DATA_ADDR: i32 = 0x10_0000;
const VM_FLAGS_ALIAS_MASK: i32 = 0xff00_0000_u32 as i32;
/// `VM_REALLOCATE_ZERO_FILL_SOURCE`, the one option besides the default
/// `VM_REALLOCATE_DEALLOCATE_SOURCE` (0).
const VM_REALLOCATE_ZERO_FILL_SOURCE: i32 = 0x1;
/// `VM_FLAGS_USER_REMAP`: FIXED, ANYWHERE, RANDOM_ADDR, OVERWRITE,
/// RETURN_DATA_ADDR, RESILIENT_CODESIGN and RESILIENT_MEDIA.
const VM_FLAGS_USER_REMAP: i32 = 0x1 | 0x8 | 0x4000 | 0x10_0000 | 0x20 | 0x40;
/// `VM_PROT_DEFAULT`, `VM_INHERIT_DEFAULT` (`VM_INHERIT_COPY`).
const VM_PROT_DEFAULT: i32 = 3;
const VM_INHERIT_DEFAULT: u32 = 1;
/// `osfmk/mach/vm_sync.h`.
const VM_SYNC_KILLPAGES: u32 = 0x08;
const VM_SYNC_REUSABLEPAGES: u32 = 0x40;
/// `osfmk/mach/vm_behavior.h`.
const VM_BEHAVIOR_FREE: u32 = 6;
const VM_BEHAVIOR_REUSABLE: u32 = 8;
const VM_BEHAVIOR_CAN_REUSE: u32 = 10;
/// `osfmk/mach/vm_region.h`.
const VM_REGION_BASIC_INFO_64: i32 = 9;
const VM_REGION_BASIC_INFO: u32 = 10;
const VM_REGION_TOP_INFO: u32 = 12;
const VM_REGION_EXTENDED_INFO: u32 = 13;
const VM_REGION_BASIC_INFO_COUNT_64: u32 = 9;
/// `vm_region_recurse_info_t`'s MIG bound and the submap layouts' sizes
/// in words: `VM_REGION_SUBMAP_INFO_V0_COUNT_64` and `_V1_`.
const RECURSE_INFO_MAX: u32 = 19;
const SUBMAP_INFO_V0_COUNT: u32 = 16;
const SUBMAP_INFO_V1_COUNT: u32 = 17;
/// The page counts of `vm_region_submap_info_64`, by word:
/// `pages_resident`, `pages_shared_now_private`, `pages_swapped_out`,
/// `pages_dirtied`, then the v1 `pages_reusable`.
const SUBMAP_PAGE_WORDS: [usize; 4] = [6, 7, 8, 9];
const SUBMAP_REUSABLE_WORD: usize = 16;
/// `vm_page_info_t`'s MIG bound; `VM_PAGE_INFO_BASIC` and its
/// `disposition` and `ref_count` words.
const PAGE_INFO_MAX: u32 = 32;
const VM_PAGE_INFO_BASIC: i32 = 1;
const PAGE_INFO_BASIC_COUNT: u32 = 8;

/// `mach_msg_port_descriptor_t` and `mach_msg_ool_descriptor64_t` types
/// and the send dispositions a request may carry a port with.
const MACH_MSG_PORT_DESCRIPTOR: u8 = 0;
const MACH_MSG_OOL_DESCRIPTOR: u8 = 1;
const MACH_MSG_TYPE_MOVE_SEND: u8 = 17;
const MACH_MSG_TYPE_COPY_SEND: u8 = 19;
const MACH_PORT_DEAD: u32 = u32::MAX;

/// A simple request's arguments start after its NDR record; a request
/// with one port descriptor's after the descriptor count, the 12-byte
/// descriptor and the NDR record; with one out-of-line descriptor, after
/// the count, the 16-byte descriptor and the NDR record.
const SIMPLE: usize = 8;
const ONE_PORT: usize = 4 + 12 + 8;
const ONE_OOL: usize = 4 + 16 + 8;

/// Host pages per guest page.
const HOST_PAGES: u64 = PAGE_BYTES / (HOST_PAGE_MASK + 1);
const HOST_PAGE_BYTES: u64 = HOST_PAGE_MASK + 1;

unsafe extern "C" {
    fn mach_vm_allocate(task: u32, address: *mut u64, size: u64, flags: i32) -> i32;
    fn mach_vm_deallocate(task: u32, address: u64, size: u64) -> i32;
    fn mach_vm_protect(task: u32, address: u64, size: u64, maximum: i32, protection: i32) -> i32;
    fn mach_vm_inherit(task: u32, address: u64, size: u64, inheritance: u32) -> i32;
    fn mach_vm_write(task: u32, address: u64, data: usize, count: u32) -> i32;
    fn mach_vm_copy(task: u32, source: u64, size: u64, destination: u64) -> i32;
    fn mach_vm_read(task: u32, address: u64, size: u64, data: *mut usize, count: *mut u32) -> i32;
    fn mach_vm_read_list(task: u32, list: *mut u64, count: u32) -> i32;
    fn mach_vm_read_overwrite(
        task: u32,
        address: u64,
        size: u64,
        data: u64,
        out_size: *mut u64,
    ) -> i32;
    fn mach_vm_msync(task: u32, address: u64, size: u64, flags: u32) -> i32;
    fn mach_vm_behavior_set(task: u32, address: u64, size: u64, behavior: u32) -> i32;
    #[allow(clippy::too_many_arguments)]
    fn mach_vm_remap(
        target: u32,
        address: *mut u64,
        size: u64,
        mask: u64,
        flags: i32,
        source: u32,
        source_address: u64,
        copy: i32,
        current: *mut i32,
        maximum: *mut i32,
        inheritance: u32,
    ) -> i32;
    #[allow(clippy::too_many_arguments)]
    fn mach_vm_remap_new(
        target: u32,
        address: *mut u64,
        size: u64,
        mask: u64,
        flags: i32,
        source: u32,
        source_address: u64,
        copy: i32,
        current: *mut i32,
        maximum: *mut i32,
        inheritance: u32,
    ) -> i32;
    fn mach_vm_region(
        task: u32,
        address: *mut u64,
        size: *mut u64,
        flavor: i32,
        info: *mut i32,
        count: *mut u32,
        object: *mut u32,
    ) -> i32;
    fn mach_vm_region_recurse(
        task: u32,
        address: *mut u64,
        size: *mut u64,
        depth: *mut u32,
        info: *mut i32,
        count: *mut u32,
    ) -> i32;
    fn mach_vm_page_query(
        task: u32,
        offset: u64,
        disposition: *mut i32,
        references: *mut i32,
    ) -> i32;
    fn mach_vm_page_info(
        task: u32,
        address: u64,
        flavor: i32,
        info: *mut i32,
        count: *mut u32,
    ) -> i32;
    fn mach_vm_page_range_query(
        task: u32,
        address: u64,
        size: u64,
        dispositions: u64,
        count: *mut u64,
    ) -> i32;
    fn mach_vm_purgable_control(task: u32, address: u64, control: i32, state: *mut i32) -> i32;
    fn mach_port_deallocate(task: u32, name: u32) -> i32;
}

fn host() -> u32 {
    crate::hosted::host::task()
}

/// A routine's fields, or `None` when the request is too short for them.
fn fields<T>(parse: impl FnOnce() -> Option<T>) -> Option<T> {
    parse()
}

/// The guest pages `[address, address + size)` touches, as the arm64
/// kernel widens a range to its 16 KiB pages: their start and length, or
/// `None` when the range wraps. An empty range stays empty.
fn pages(address: u64, size: u64) -> Option<(u64, u64)> {
    let start = memory::trunc_page(address);
    if size == 0 {
        return Some((start, 0));
    }
    let end = memory::round_page(address.checked_add(size)?)?;
    Some((start, end - start))
}

fn status(code: i32) -> Reply {
    if code == KERN_SUCCESS {
        Reply::Success(Vec::new())
    } else {
        Reply::Failure(code as u32)
    }
}

fn words(values: impl IntoIterator<Item = u32>) -> Vec<u8> {
    values.into_iter().flat_map(u32::to_le_bytes).collect()
}

/// Whether `[start, start + size)` reaches the shared region.
fn in_shared_region(start: u64, size: u64) -> bool {
    start < REGION_START + REGION_SIZE && start.saturating_add(size) > REGION_START
}

/// Refuse a range of whole guest pages any of which the host maps in
/// parts it would treat apart, where the arm64 kernel maps the page whole:
/// host regions meeting inside a guest page must be contiguous and of the
/// same protections, and no hole may begin or end inside one.
fn whole_pages(what: &str, start: u64, size: u64) -> Result<()> {
    let end = start.saturating_add(size);
    let mut cursor = start;
    // The previous region's end and protections.
    let mut previous: Option<(u64, i32, i32)> = None;
    let refuse = |at: u64, parts: String| {
        bail!(
            "{what} over guest pages {start:#x}..{end:#x}: the host maps the guest page at \
             {:#x} in parts it treats apart ({parts}), where the arm64 kernel maps it whole; a \
             partial guest page is not implemented",
            memory::trunc_page(at)
        )
    };
    while cursor < end {
        let (mut at, mut bytes) = (cursor, 0u64);
        let mut info = [0i32; VM_REGION_BASIC_INFO_COUNT_64 as usize];
        let mut count = VM_REGION_BASIC_INFO_COUNT_64;
        let mut object = 0u32;
        // SAFETY: out-parameters sized for VM_REGION_BASIC_INFO_64.
        let found = unsafe {
            mach_vm_region(
                host(),
                &mut at,
                &mut bytes,
                VM_REGION_BASIC_INFO_64,
                info.as_mut_ptr(),
                &mut count,
                &mut object,
            )
        };
        let open = previous.filter(|&(previous_end, ..)| previous_end & PAGE_MASK != 0);
        // No region at or after the cursor in the range: the rest is a
        // hole, which must begin on a guest page.
        if found != KERN_SUCCESS || at >= end {
            return match open {
                Some((previous_end, ..)) => {
                    refuse(previous_end, format!("a hole from {previous_end:#x}"))
                }
                None => Ok(()),
            };
        }
        let (protection, maximum) = (info[0], info[1]);
        let joined = previous.is_some_and(|(previous_end, current, max)| {
            previous_end == at && current == protection && max == maximum
        });
        if ((at > start && at & PAGE_MASK != 0) || open.is_some()) && !joined {
            let parts = match previous {
                Some((previous_end, current, max)) if previous_end == at => format!(
                    "protections {current}/{max} before {at:#x}, {protection}/{maximum} after"
                ),
                Some((previous_end, ..)) => format!("a hole from {previous_end:#x} to {at:#x}"),
                None => format!("a hole before {at:#x}"),
            };
            return refuse(open.map_or(at, |(previous_end, ..)| previous_end), parts);
        }
        let region_end = at.saturating_add(bytes);
        previous = Some((region_end, protection, maximum));
        cursor = region_end;
    }
    Ok(())
}

/// The source task of a remap: this task, as the request's port
/// descriptor names it. Another task's address space is refused.
fn source_task(task: &dyn Task, request: &Request) -> Result<Result<u8, Reply>> {
    let (Some(1), Some(name), Some(&disposition), Some(&kind)) = (
        request.word(0),
        request.word(4),
        request.body.get(14),
        request.body.get(15),
    ) else {
        return Ok(Err(Reply::Failure(MIG_BAD_ARGUMENTS)));
    };
    if kind != MACH_MSG_PORT_DESCRIPTOR {
        return Ok(Err(Reply::Failure(MIG_TYPE_ERROR)));
    }
    // A null or dead port converts to no map.
    if name == 0 || name == MACH_PORT_DEAD {
        return Ok(Err(Reply::Failure(KERN_INVALID_ARGUMENT)));
    }
    if name != task.port() {
        bail!(
            "mach_vm_remap from task port {name:#x}: remapping another task's memory is not \
             implemented"
        );
    }
    if !matches!(
        disposition,
        MACH_MSG_TYPE_COPY_SEND | MACH_MSG_TYPE_MOVE_SEND
    ) {
        bail!(
            "mach_vm_remap: a source task port sent with disposition {disposition} is not implemented"
        );
    }
    Ok(Ok(disposition))
}

/// `mach_vm_remap_external` and `mach_vm_remap_new_external`
/// (`osfmk/vm/vm_user.c`, `vm_map_remap`): the source pages of this task
/// mapped again, shared or copied, at a placement in guest pages. The
/// legacy routine reports the strictest protections of the source; the
/// new one applies the protections it is given and always returns the
/// address of the data within its page.
fn remap(task: &mut dyn Task, request: &Request, new: bool) -> Result<Reply> {
    let disposition = match source_task(task, request)? {
        Ok(disposition) => disposition,
        Err(reply) => return Ok(reply),
    };
    let at = ONE_PORT;
    let Some((target, size, mask, flags, source, copy)) = fields(|| {
        Some((
            request.double(at)?,
            request.double(at + 8)?,
            request.double(at + 16)?,
            request.word(at + 24)? as i32,
            request.double(at + 28)?,
            request.word(at + 36)?,
        ))
    }) else {
        return Ok(Reply::Failure(MIG_BAD_ARGUMENTS));
    };
    let Some((mut current, mut maximum, inheritance)) = fields(|| {
        Some(if new {
            (
                request.word(at + 40)? as i32,
                request.word(at + 44)? as i32,
                request.word(at + 48)?,
            )
        } else {
            (0, 0, request.word(at + 40)?)
        })
    }) else {
        return Ok(Reply::Failure(MIG_BAD_ARGUMENTS));
    };
    let reply = remap_pages(
        task,
        new,
        (target, size, mask, flags, source, copy),
        (&mut current, &mut maximum, inheritance),
    )?;
    if disposition == MACH_MSG_TYPE_MOVE_SEND {
        // The kernel consumes a moved right with the request.
        // SAFETY: a user reference the request gave up.
        unsafe { mach_port_deallocate(host(), task.port()) };
    }
    Ok(reply)
}

fn remap_pages(
    task: &mut dyn Task,
    new: bool,
    (target, size, mask, flags, source, copy): (u64, u64, u64, i32, u64, u32),
    (current, maximum, inheritance): (&mut i32, &mut i32, u32),
) -> Result<Reply> {
    if flags & !VM_FLAGS_USER_REMAP != 0 {
        return Ok(Reply::Failure(KERN_INVALID_ARGUMENT));
    }
    let Some((start, bytes)) = pages(source, size) else {
        return Ok(Reply::Failure(KERN_INVALID_ARGUMENT));
    };
    let anywhere = flags & VM_FLAGS_ANYWHERE != 0;
    let placement = memory::trunc_page(target);
    whole_pages("mach_vm_remap", start, bytes)?;
    task.page_in(start, start + bytes)?;
    let data = new || flags & VM_FLAGS_RETURN_DATA_ADDR != 0;
    let mut placed = placement;
    let host_flags = flags & !VM_FLAGS_RETURN_DATA_ADDR;
    let host_mask = if anywhere { mask | PAGE_MASK } else { mask };
    // SAFETY: this task's own pages mapped again where the guest asked,
    // or where the host finds room in guest pages; out-parameters are
    // locals.
    let code = unsafe {
        let remap = if new {
            mach_vm_remap_new
        } else {
            mach_vm_remap
        };
        remap(
            host(),
            &mut placed,
            bytes,
            host_mask,
            host_flags,
            host(),
            start,
            i32::from(copy != 0),
            current,
            maximum,
            inheritance,
        )
    };
    if code != KERN_SUCCESS {
        return Ok(Reply::Failure(code as u32));
    }
    if flags & VM_FLAGS_OVERWRITE != 0 {
        task.unslid_change(placed, bytes, &mut |_| None);
    }
    task.invalidate(placed, bytes);
    let address = if data {
        placed + (source & PAGE_MASK)
    } else {
        placed
    };
    let mut body = address.to_le_bytes().to_vec();
    body.extend(words([*current as u32, *maximum as u32]));
    Ok(Reply::Success(body))
}

/// `mach_vm_allocate_external`: `mach_vm_map` of zero-fill memory with
/// the default protections, in guest pages. The arm64 kernel has no
/// superpages.
fn allocate(task: &mut dyn Task, request: &Request) -> Result<Reply> {
    let Some((address, size, flags)) = fields(|| {
        Some((
            request.double(SIMPLE)?,
            request.double(SIMPLE + 8)?,
            request.word(SIMPLE + 16)? as i32,
        ))
    }) else {
        return Ok(Reply::Failure(MIG_BAD_ARGUMENTS));
    };
    if flags & VM_FLAGS_SUPERPAGE_MASK != 0 {
        return Ok(Reply::Failure(KERN_INVALID_ARGUMENT));
    }
    if flags & (VM_FLAGS_TPRO | VM_FLAGS_MTE) != 0 {
        bail!("mach_vm_allocate with flags {flags:#x}: TPRO and MTE memory are not implemented");
    }
    if size == 0 {
        // No page is touched: the host's answer is the kernel's.
        let mut at = address;
        // SAFETY: an empty allocation.
        let code = unsafe { mach_vm_allocate(host(), &mut at, 0, flags) };
        return Ok(if code == KERN_SUCCESS {
            Reply::Success(at.to_le_bytes().to_vec())
        } else {
            Reply::Failure(code as u32)
        });
    }
    let anywhere = flags & VM_FLAGS_ANYWHERE != 0;
    let range = if anywhere {
        memory::round_page(size).map(|size| (address, size))
    } else {
        pages(address, size)
    };
    let Some((start, bytes)) = range else {
        return Ok(Reply::Failure(KERN_INVALID_ARGUMENT));
    };
    let (code, placed) = memory::map_anonymous(
        start,
        bytes,
        if anywhere { PAGE_MASK } else { 0 },
        flags,
        false,
        Protection(VM_PROT_DEFAULT),
        Protection::ALL,
        VM_INHERIT_DEFAULT,
    );
    if code != KERN_SUCCESS {
        return Ok(Reply::Failure(code as u32));
    }
    if flags & VM_FLAGS_OVERWRITE != 0 {
        task.unslid_change(placed, bytes, &mut |_| None);
    }
    task.invalidate(placed, bytes);
    Ok(Reply::Success(placed.to_le_bytes().to_vec()))
}

/// The host's `mach_vm_reallocate`, which hosts before macOS 26 lack.
type HostReallocate = unsafe extern "C" fn(u32, u64, u64, *mut u64, u64, u64, i32, i32) -> i32;

fn host_reallocate() -> Option<HostReallocate> {
    static FOUND: std::sync::OnceLock<Option<HostReallocate>> = std::sync::OnceLock::new();
    *FOUND.get_or_init(|| {
        // SAFETY: a lookup of a libSystem function by its NUL-terminated
        // name; the symbol, when present, has this signature
        // (`mach/mach_vm.h`).
        let symbol = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"mach_vm_reallocate".as_ptr()) };
        (!symbol.is_null())
            .then(|| unsafe { core::mem::transmute::<*mut libc::c_void, HostReallocate>(symbol) })
    })
}

/// `mach_vm_reallocate` (`osfmk/vm/vm_map.c`, `vm_map_reallocate`): the
/// source pages moved, atomically, to a destination of equal or greater
/// size, expanded in place where the source already satisfies the
/// alignment and the following pages are free. The arm64 kernel's checks
/// run here on guest pages; the host's own reallocation then moves the
/// whole guest pages with an alignment widened to them, so the source's
/// entries keep their objects, protections and inheritance.
fn reallocate(task: &mut dyn Task, request: &Request) -> Result<Reply> {
    let Some((source, source_size, destination, destination_size, align_mask, options, flags)) =
        fields(|| {
            Some((
                request.double(SIMPLE)?,
                request.double(SIMPLE + 8)?,
                request.double(SIMPLE + 16)?,
                request.double(SIMPLE + 24)?,
                request.double(SIMPLE + 32)?,
                request.word(SIMPLE + 40)? as i32,
                request.word(SIMPLE + 44)? as i32,
            ))
        })
    else {
        return Ok(Reply::Failure(MIG_BAD_ARGUMENTS));
    };
    // `vm_map_reallocate_sanitize`, on guest pages.
    let anywhere = flags & VM_FLAGS_ANYWHERE != 0;
    if flags & !(VM_FLAGS_ANYWHERE | VM_FLAGS_OVERWRITE | VM_FLAGS_ALIAS_MASK) != 0
        || options & !VM_REALLOCATE_ZERO_FILL_SOURCE != 0
        || destination_size == 0
        || destination_size & PAGE_MASK != 0
        || (!anywhere && destination & PAGE_MASK != 0)
    {
        return Ok(Reply::Failure(KERN_INVALID_ARGUMENT));
    }
    if !anywhere && destination & align_mask != 0 {
        return Ok(Reply::Failure(KERN_INVALID_ADDRESS));
    }
    if source_size == 0 || (source | source_size) & PAGE_MASK != 0 {
        return Ok(Reply::Failure(KERN_INVALID_ARGUMENT));
    }
    if source.checked_add(source_size).is_none() {
        return Ok(Reply::Failure(KERN_INVALID_ARGUMENT));
    }
    // The shared region is a submap, which `vm_map_relocate_preflight`
    // refuses.
    if in_shared_region(source, source_size) {
        return Ok(Reply::Failure(KERN_INVALID_ADDRESS));
    }
    whole_pages("mach_vm_reallocate", source, source_size)?;
    let Some(host_reallocate) = host_reallocate() else {
        bail!(
            "mach_vm_reallocate: the host kernel has no mach_vm_reallocate (macOS 26 or later), \
             and relocating map entries otherwise is not implemented"
        );
    };
    let mut placed = destination;
    // SAFETY: this task's own pages moved where the guest asked, or where
    // the host finds room in guest pages; the out-parameter is a local.
    let code = unsafe {
        host_reallocate(
            host(),
            source,
            source_size,
            &mut placed,
            destination_size,
            align_mask | PAGE_MASK,
            options,
            flags,
        )
    };
    if code != KERN_SUCCESS {
        return Ok(Reply::Failure(code as u32));
    }
    if flags & VM_FLAGS_OVERWRITE != 0 {
        task.unslid_change(placed, destination_size, &mut |_| None);
    }
    task.invalidate(source, source_size);
    task.invalidate(placed, destination_size);
    Ok(Reply::Success(placed.to_le_bytes().to_vec()))
}

/// `mach_vm_deallocate_external` over guest pages; shared-region pages
/// not yet slid are no longer slid.
fn deallocate(task: &mut dyn Task, request: &Request) -> Reply {
    let Some((address, size)) =
        fields(|| Some((request.double(SIMPLE)?, request.double(SIMPLE + 8)?)))
    else {
        return Reply::Failure(MIG_BAD_ARGUMENTS);
    };
    let Some((start, bytes)) = pages(address, size) else {
        return Reply::Failure(KERN_INVALID_ARGUMENT);
    };
    task.unslid_change(start, bytes, &mut |_| None);
    // SAFETY: the guest unmaps its own pages.
    let code = unsafe { mach_vm_deallocate(host(), start, bytes) };
    task.invalidate(start, bytes);
    status(code)
}

/// `mach_vm_protect` over guest pages, as the protect trap: a pending
/// shared-region page keeps the change until it is slid.
fn protect(task: &mut dyn Task, request: &Request) -> Reply {
    let Some((address, size, set_maximum, protection)) = fields(|| {
        Some((
            request.double(SIMPLE)?,
            request.double(SIMPLE + 8)?,
            request.word(SIMPLE + 16)? != 0,
            request.word(SIMPLE + 20)? as i32,
        ))
    }) else {
        return Reply::Failure(MIG_BAD_ARGUMENTS);
    };
    let Some((start, bytes)) = pages(address, size) else {
        return Reply::Failure(KERN_INVALID_ARGUMENT);
    };
    let new = protection & Protection::ALL.0;
    let runs = task.unslid_change(start, bytes, &mut |current| {
        Some(if set_maximum {
            Protection(current.0 & new)
        } else {
            Protection(new)
        })
    });
    for (run, size) in runs {
        // SAFETY: the guest changes its own pages.
        let code =
            unsafe { mach_vm_protect(host(), run, size, i32::from(set_maximum), protection) };
        if code != KERN_SUCCESS {
            return Reply::Failure(code as u32);
        }
    }
    Reply::Success(Vec::new())
}

/// `MACH_VM_MAX_ADDRESS` of a 64-bit arm64 macOS task, its map's end.
const MACH_VM_MAX_ADDRESS: u64 = 0x0000_7fff_fe00_0000;
/// `MATTR_CACHE`, the one machine attribute.
const MATTR_CACHE: u32 = 1;
const KERN_FAILURE: u32 = 5;

/// This task's map's start (`vm_map_min`): its `__PAGEZERO`'s end, which
/// the host task's shares (`TASK_VM_INFO`'s `min_address`).
fn map_min() -> u64 {
    const TASK_VM_INFO: i32 = 22;
    const MIN_ADDRESS: usize = 152 / 4;
    unsafe extern "C" {
        fn task_info(task: u32, flavor: i32, info: *mut u32, count: *mut u32) -> i32;
    }
    let mut info = [0u32; 128];
    let mut count = info.len() as u32;
    // SAFETY: the host fills at most `count` words.
    let status = unsafe { task_info(host(), TASK_VM_INFO, info.as_mut_ptr(), &mut count) };
    if status != KERN_SUCCESS || (count as usize) < MIN_ADDRESS + 2 {
        return 0;
    }
    u64::from(info[MIN_ADDRESS]) | u64::from(info[MIN_ADDRESS + 1]) << 32
}

/// Whether the host maps every byte of `[start, end)`: no hole, as an
/// atomic range lock requires (`VMRL_EX_ATOMIC`).
fn covered(start: u64, end: u64) -> bool {
    let mut cursor = start;
    while cursor < end {
        let (mut at, mut bytes) = (cursor, 0u64);
        let mut info = [0i32; VM_REGION_BASIC_INFO_COUNT_64 as usize];
        let mut count = VM_REGION_BASIC_INFO_COUNT_64;
        let mut object = 0u32;
        // SAFETY: out-parameters sized for VM_REGION_BASIC_INFO_64.
        let found = unsafe {
            mach_vm_region(
                host(),
                &mut at,
                &mut bytes,
                VM_REGION_BASIC_INFO_64,
                info.as_mut_ptr(),
                &mut count,
                &mut object,
            )
        };
        if found != KERN_SUCCESS || at > cursor {
            return false;
        }
        cursor = at + bytes;
    }
    true
}

/// `mach_vm_machine_attribute(address, size, attribute, value)`
/// (`vm_map_machine_attribute`): `MATTR_CACHE` over a range of mapped
/// guest pages synchronizes the instruction cache with each resident
/// page (`pmap_attribute_cache_sync`, `cache_sync_page`), which drops the
/// range's compiled blocks; the value is returned as given. The x86
/// host's pmap answers KERN_INVALID_ADDRESS for any resident page, so
/// the routine is answered here.
fn machine_attribute(task: &mut dyn Task, request: &Request) -> Reply {
    let Some((address, size, attribute, value)) = fields(|| {
        Some((
            request.double(SIMPLE)?,
            request.double(SIMPLE + 8)?,
            request.word(SIMPLE + 16)?,
            request.word(SIMPLE + 20)?,
        ))
    }) else {
        return Reply::Failure(MIG_BAD_ARGUMENTS);
    };
    if size == 0 {
        return Reply::Success(value.to_le_bytes().to_vec());
    }
    let Some((start, bytes)) = pages(address, size) else {
        return Reply::Failure(KERN_INVALID_ARGUMENT);
    };
    let end = start + bytes;
    if start < map_min() || end > MACH_VM_MAX_ADDRESS || attribute != MATTR_CACHE {
        return Reply::Failure(KERN_INVALID_ADDRESS);
    }
    if !covered(start, end) {
        return Reply::Failure(KERN_FAILURE);
    }
    task.invalidate(start, bytes);
    Reply::Success(value.to_le_bytes().to_vec())
}

/// `mach_vm_inherit` over guest pages. A pending shared-region page is
/// mapped on the host, inaccessible, and takes the inheritance itself.
fn inherit(request: &Request) -> Reply {
    let Some((address, size, inheritance)) = fields(|| {
        Some((
            request.double(SIMPLE)?,
            request.double(SIMPLE + 8)?,
            request.word(SIMPLE + 16)?,
        ))
    }) else {
        return Reply::Failure(MIG_BAD_ARGUMENTS);
    };
    let Some((start, bytes)) = pages(address, size) else {
        return Reply::Failure(KERN_INVALID_ARGUMENT);
    };
    // SAFETY: the guest changes its own pages.
    status(unsafe { mach_vm_inherit(host(), start, bytes, inheritance) })
}

/// `mach_vm_write`: the request's out-of-line data overwrites
/// `[address, address + dataCnt)` (`vm_map_copy_overwrite`). The data is
/// still in the sender's pages, as the kernel would copy it in.
fn write(task: &mut dyn Task, request: &Request) -> Result<Reply> {
    let Some((1, data, deallocate, kind, ool_size)) = fields(|| {
        Some((
            request.word(0)?,
            request.double(4)?,
            *request.body.get(12)?,
            *request.body.get(15)?,
            request.word(16)?,
        ))
    }) else {
        return Ok(Reply::Failure(MIG_BAD_ARGUMENTS));
    };
    let Some((address, count)) =
        fields(|| Some((request.double(ONE_OOL)?, request.word(ONE_OOL + 8)?)))
    else {
        return Ok(Reply::Failure(MIG_BAD_ARGUMENTS));
    };
    if kind != MACH_MSG_OOL_DESCRIPTOR || ool_size != count {
        return Ok(Reply::Failure(MIG_TYPE_ERROR));
    }
    let (Some((source, source_bytes)), Some((start, bytes))) = (
        pages(data, u64::from(count)),
        pages(address, u64::from(count)),
    ) else {
        return Ok(Reply::Failure(KERN_INVALID_ARGUMENT));
    };
    task.page_in(source, source + source_bytes)?;
    let Some(bytes_in) = memory::read(data, count as usize) else {
        bail!(
            "mach_vm_write: its out-of-line data at {data:#x} ({count:#x} bytes) is unreadable, \
             which fails the send (MACH_SEND_INVALID_MEMORY): not implemented"
        );
    };
    whole_pages("mach_vm_write", start, bytes)?;
    task.page_in(start, start + bytes)?;
    // SAFETY: the buffer holds `count` bytes; the destination is this
    // task's own memory.
    let code = unsafe { mach_vm_write(host(), address, bytes_in.as_ptr() as usize, count) };
    task.invalidate(address, u64::from(count));
    if deallocate != 0 && source_bytes != 0 {
        // The kernel takes the sender's pages with the message.
        task.unslid_change(source, source_bytes, &mut |_| None);
        // SAFETY: pages the sender gave up.
        unsafe { mach_vm_deallocate(host(), source, source_bytes) };
        task.invalidate(source, source_bytes);
    }
    Ok(status(code))
}

/// `mach_vm_read` (`address`, `size`): the bytes copied in
/// (`vm_map_copyin`) and sent out of line; out `dataCnt`. The host's copy
/// of them is the reply's data, released from this task as the reply is
/// sent.
fn read(task: &mut dyn Task, request: &Request) -> Result<Reply> {
    let Some((address, size)) =
        fields(|| Some((request.double(SIMPLE)?, request.double(SIMPLE + 8)?)))
    else {
        return Ok(Reply::Failure(MIG_BAD_ARGUMENTS));
    };
    let Some((start, bytes)) = pages(address, size) else {
        return Ok(Reply::Failure(KERN_INVALID_ARGUMENT));
    };
    whole_pages("mach_vm_read", start, bytes)?;
    task.page_in(start, start + bytes)?;
    let (mut data, mut count) = (0usize, 0u32);
    // SAFETY: the host copies this task's bytes into new memory of it.
    let code = unsafe { mach_vm_read(host(), address, size, &mut data, &mut count) };
    if code != KERN_SUCCESS {
        return Ok(Reply::Failure(code as u32));
    }
    Ok(Reply::Complex {
        descriptors: vec![Descriptor::Memory {
            address: data as u64,
            size: count,
            deallocate: count != 0,
        }],
        body: count.to_le_bytes().to_vec(),
    })
}

/// `mach_vm_read_entry_t`'s bound (`VM_MAP_ENTRY_MAX`) and size.
const READ_LIST_MAX: u32 = 256;
const READ_ENTRY_BYTES: usize = 16;

/// `mach_vm_read_list` (`data_list`, `count`): each nonempty range's guest
/// pages copied in and out to new guest pages of this task
/// (`vm_map_copyout`, which maps them with the default protections),
/// each entry's address becoming its bytes' new address, or the entry
/// zeroed when its copy fails. The routine's status is the last nonempty
/// entry's.
fn read_list(task: &mut dyn Task, request: &Request) -> Result<Reply> {
    let list_bytes = READ_LIST_MAX as usize * READ_ENTRY_BYTES;
    let (Some(list), Some(count)) = (
        request.body.get(SIMPLE..SIMPLE + list_bytes),
        request.word(SIMPLE + list_bytes),
    ) else {
        return Ok(Reply::Failure(MIG_BAD_ARGUMENTS));
    };
    if count > READ_LIST_MAX {
        return Ok(Reply::Failure(KERN_INVALID_ARGUMENT));
    }
    let mut entries: Vec<[u64; 2]> = list
        .as_chunks::<READ_ENTRY_BYTES>()
        .0
        .iter()
        .map(|entry| {
            [
                u64::from_le_bytes(entry[..8].try_into().unwrap()),
                u64::from_le_bytes(entry[8..].try_into().unwrap()),
            ]
        })
        .collect();
    let mut code = KERN_SUCCESS;
    for entry in &mut entries[..count as usize] {
        let [address, size] = *entry;
        if size != 0 {
            let (status, placed) = read_into_guest_pages(task, address, size)?;
            code = status;
            if status == KERN_SUCCESS {
                entry[0] = placed;
                continue;
            }
        }
        *entry = [0, 0];
    }
    if code != KERN_SUCCESS {
        return Ok(Reply::Failure(code as u32));
    }
    Ok(Reply::Success(
        entries
            .iter()
            .flatten()
            .flat_map(|word| word.to_le_bytes())
            .collect(),
    ))
}
/// One `mach_vm_read_list` entry: the guest pages of
/// `[address, address + size)` copied by the host into new memory, moved
/// to guest pages of their own; the status and the bytes' new address.
/// their own; the status and the bytes' new address.
fn read_into_guest_pages(task: &mut dyn Task, address: u64, size: u64) -> Result<(i32, u64)> {
    let mut list = [[0u64; 2]; READ_LIST_MAX as usize];
    let Some((start, bytes)) = pages(address, size) else {
        // A wrapping range: the host's refusal is the kernel's.
        list[0] = [address, size];
        // SAFETY: the list holds VM_MAP_ENTRY_MAX entries.
        let code = unsafe { mach_vm_read_list(host(), list.as_mut_ptr().cast(), 1) };
        if code == KERN_SUCCESS {
            bail!("mach_vm_read_list: the host copied the wrapping range {address:#x}+{size:#x}");
        }
        return Ok((code, 0));
    };
    whole_pages("mach_vm_read_list", start, bytes)?;
    task.page_in(start, start + bytes)?;
    list[0] = [start, bytes];
    // SAFETY: the list holds VM_MAP_ENTRY_MAX entries; the host copies
    // this task's pages into new memory of it.
    let code = unsafe { mach_vm_read_list(host(), list.as_mut_ptr().cast(), 1) };
    if code != KERN_SUCCESS {
        return Ok((code, 0));
    }
    let copied = list[0][0];
    let placed = memory::own_guest_pages(copied, bytes)?.unwrap_or(copied);
    Ok((KERN_SUCCESS, placed + (address & PAGE_MASK)))
}

/// `mach_vm_copy`: `[source, source + size)` overwrites the range at
/// `destination`.
fn copy(task: &mut dyn Task, request: &Request) -> Result<Reply> {
    let Some((source, size, destination)) = fields(|| {
        Some((
            request.double(SIMPLE)?,
            request.double(SIMPLE + 8)?,
            request.double(SIMPLE + 16)?,
        ))
    }) else {
        return Ok(Reply::Failure(MIG_BAD_ARGUMENTS));
    };
    let (Some(from), Some(to)) = (pages(source, size), pages(destination, size)) else {
        return Ok(Reply::Failure(KERN_INVALID_ARGUMENT));
    };
    for (start, bytes) in [from, to] {
        whole_pages("mach_vm_copy", start, bytes)?;
        task.page_in(start, start + bytes)?;
    }
    // SAFETY: both ranges are this task's own memory.
    let code = unsafe { mach_vm_copy(host(), source, size, destination) };
    task.invalidate(destination, size);
    Ok(status(code))
}

/// `mach_vm_read_overwrite`: `[address, address + size)` copied over the
/// range at `data`; out `outsize`.
fn read_overwrite(task: &mut dyn Task, request: &Request) -> Result<Reply> {
    let Some((address, size, data)) = fields(|| {
        Some((
            request.double(SIMPLE)?,
            request.double(SIMPLE + 8)?,
            request.double(SIMPLE + 16)?,
        ))
    }) else {
        return Ok(Reply::Failure(MIG_BAD_ARGUMENTS));
    };
    let (Some(from), Some(to)) = (pages(address, size), pages(data, size)) else {
        return Ok(Reply::Failure(KERN_INVALID_ARGUMENT));
    };
    for (start, bytes) in [from, to] {
        whole_pages("mach_vm_read_overwrite", start, bytes)?;
        task.page_in(start, start + bytes)?;
    }
    let mut copied = 0u64;
    // SAFETY: both ranges are this task's own memory.
    let code = unsafe { mach_vm_read_overwrite(host(), address, size, data, &mut copied) };
    task.invalidate(data, size);
    Ok(if code == KERN_SUCCESS {
        Reply::Success(copied.to_le_bytes().to_vec())
    } else {
        Reply::Failure(code as u32)
    })
}

/// `mach_vm_msync` over guest pages. Discarding the shared region's slid
/// pages would bring back the file's unslid bytes, where the slide pager
/// slides them again.
fn msync(request: &Request) -> Result<Reply> {
    let Some((address, size, flags)) = fields(|| {
        Some((
            request.double(SIMPLE)?,
            request.double(SIMPLE + 8)?,
            request.word(SIMPLE + 16)?,
        ))
    }) else {
        return Ok(Reply::Failure(MIG_BAD_ARGUMENTS));
    };
    let Some((start, bytes)) = pages(address, size) else {
        return Ok(Reply::Failure(KERN_INVALID_ARGUMENT));
    };
    if flags & (VM_SYNC_KILLPAGES | VM_SYNC_REUSABLEPAGES) != 0 && in_shared_region(start, bytes) {
        bail!(
            "mach_vm_msync({start:#x}, {bytes:#x}, {flags:#x}): discarding shared-region pages \
             is not implemented"
        );
    }
    // SAFETY: the guest's own pages.
    Ok(status(unsafe {
        mach_vm_msync(host(), start, bytes, flags)
    }))
}

/// `mach_vm_behavior_set` over guest pages: the reusable behaviors align
/// to the hardware page, which on arm64 is the guest page too.
fn behavior_set(request: &Request) -> Result<Reply> {
    let Some((address, size, behavior)) = fields(|| {
        Some((
            request.double(SIMPLE)?,
            request.double(SIMPLE + 8)?,
            request.word(SIMPLE + 16)?,
        ))
    }) else {
        return Ok(Reply::Failure(MIG_BAD_ARGUMENTS));
    };
    let Some((start, bytes)) = pages(address, size) else {
        return Ok(Reply::Failure(KERN_INVALID_ARGUMENT));
    };
    if (behavior == VM_BEHAVIOR_FREE
        || (VM_BEHAVIOR_REUSABLE..=VM_BEHAVIOR_CAN_REUSE).contains(&behavior))
        && in_shared_region(start, bytes)
    {
        bail!(
            "mach_vm_behavior_set({start:#x}, {bytes:#x}, {behavior}): discarding shared-region \
             pages is not implemented"
        );
    }
    // SAFETY: the guest's own pages.
    Ok(status(unsafe {
        mach_vm_behavior_set(host(), start, bytes, behavior)
    }))
}

/// The host's region at or after `address`, its basic information's
/// status, start and size.
fn host_region(address: u64) -> (i32, u64, u64) {
    let (mut at, mut size) = (address, 0u64);
    let mut info = [0i32; VM_REGION_BASIC_INFO_COUNT_64 as usize];
    let mut count = VM_REGION_BASIC_INFO_COUNT_64;
    let mut object = 0u32;
    // SAFETY: out-parameters sized for VM_REGION_BASIC_INFO_64.
    let code = unsafe {
        mach_vm_region(
            host(),
            &mut at,
            &mut size,
            VM_REGION_BASIC_INFO_64,
            info.as_mut_ptr(),
            &mut count,
            &mut object,
        )
    };
    (code, at, size)
}

/// `mach_vm_region` (`address`, `flavor`, `infoCnt`): the region at or
/// after `address`. The basic flavors describe it in protections,
/// inheritance and sharing, the same for the arm64 kernel as the host's
/// where the region is whole guest pages, so the request is forwarded; its
/// reply carries the `object_name` port. The top and extended flavors
/// count pages.
fn region(request: &Request) -> Result<Reply> {
    let Some((address, flavor)) =
        fields(|| Some((request.double(SIMPLE)?, request.word(SIMPLE + 8)?)))
    else {
        return Ok(Reply::Failure(MIG_BAD_ARGUMENTS));
    };
    match flavor {
        flavor if flavor == VM_REGION_BASIC_INFO_64 as u32 || flavor == VM_REGION_BASIC_INFO => {}
        VM_REGION_TOP_INFO | VM_REGION_EXTENDED_INFO => bail!(
            "mach_vm_region flavor {flavor} at {address:#x}: page counts in guest pages need a \
             complex reply, which is not implemented"
        ),
        _ => return Ok(Reply::Failure(KERN_INVALID_ARGUMENT)),
    }
    let (code, start, size) = host_region(address);
    if code != KERN_SUCCESS {
        return Ok(Reply::Failure(code as u32));
    }
    if in_shared_region(start, size) {
        bail!(
            "mach_vm_region at {address:#x}: the shared region's nested submap is not \
             implemented"
        );
    }
    if (start | size) & PAGE_MASK != 0 {
        bail!(
            "mach_vm_region at {address:#x}: the host region {start:#x}+{size:#x} splits a guest \
             page; a merged region needs a complex reply, which is not implemented"
        );
    }
    Ok(Reply::Forward)
}

/// `mach_vm_region_recurse` (`address`, `nesting_depth`, `infoCnt`): the
/// region at or after `address` as the arm64 kernel's 16 KiB map shows
/// it, in whole guest pages. Host regions whose bounds fall inside a guest
/// page are one map entry there, so they are merged (see [`merge_submap`])
/// and the page counts restated in guest pages.
fn region_recurse(request: &Request) -> Result<Reply> {
    let Some((address, depth, count)) = fields(|| {
        Some((
            request.double(SIMPLE)?,
            request.word(SIMPLE + 8)?,
            request.word(SIMPLE + 12)?,
        ))
    }) else {
        return Ok(Reply::Failure(MIG_BAD_ARGUMENTS));
    };
    let count = count.min(RECURSE_INFO_MAX);
    let first = match host_recurse(address, depth, count) {
        Ok(first) => first,
        Err(code) => return Ok(Reply::Failure(code as u32)),
    };
    // Back to the first host region of the guest page it starts in.
    let mut start = memory::trunc_page(first.start);
    while start < first.start {
        match host_recurse(start, depth, count) {
            Ok(region) if region.start < start => start = memory::trunc_page(region.start),
            _ => break,
        }
    }
    // Forward over every region that begins before the merged end.
    let mut pieces: Vec<HostRegion> = Vec::new();
    let (mut cursor, mut end) = (start, start);
    while let Ok(region) = host_recurse(cursor, depth, count) {
        if !pieces.is_empty() && region.start >= end {
            break;
        }
        let region_end = region.start + region.size;
        end = end.max(memory::round_page(region_end).unwrap_or(!PAGE_MASK));
        cursor = region_end;
        pieces.push(region);
        if region_end >= end {
            break;
        }
    }
    if pieces.is_empty() {
        end = memory::round_page(first.start + first.size).unwrap_or(!PAGE_MASK);
        pieces.push(first);
    }
    let head = &pieces[0];
    let start = memory::trunc_page(head.start);
    let size = end - start;
    if in_shared_region(start, size) {
        bail!(
            "mach_vm_region_recurse at {address:#x}: the shared region's nested submap is not \
             implemented"
        );
    }
    let mut info = merge_submap(&pieces, start, count);
    restate_submap_pages(&mut info, size);
    let mut body = start.to_le_bytes().to_vec();
    body.extend(size.to_le_bytes());
    body.extend(words([head.depth, count]));
    body.extend(words(info));
    Ok(Reply::Success(body))
}

/// One host region `mach_vm_region_recurse` reported.
struct HostRegion {
    start: u64,
    size: u64,
    depth: u32,
    info: Vec<u32>,
}

/// The host's region at or after `address` at `depth`, with `count` words
/// of information, or its failure.
fn host_recurse(address: u64, depth: u32, count: u32) -> Result<HostRegion, i32> {
    let (mut start, mut size, mut depth) = (address, 0u64, depth);
    let mut info = [0i32; RECURSE_INFO_MAX as usize];
    let mut filled = count;
    // SAFETY: `info` holds the MIG bound's words, `filled` at most.
    let code = unsafe {
        mach_vm_region_recurse(
            host(),
            &mut start,
            &mut size,
            &mut depth,
            info.as_mut_ptr(),
            &mut filled,
        )
    };
    if code != KERN_SUCCESS {
        return Err(code);
    }
    let filled = filled.min(count) as usize;
    Ok(HostRegion {
        start,
        size,
        depth,
        info: info[..filled].iter().map(|&word| word as u32).collect(),
    })
}

/// `vm_region_submap_info_64` and `vm_region_submap_short_info_64`
/// fields, by word: the long layout's (`VM_REGION_SUBMAP_INFO_V0_COUNT_64`
/// and more) and the short one's.
struct SubmapWords {
    ref_count: usize,
    /// `shadow_depth` (16 bits), `external_pager`, `share_mode`.
    packed: usize,
    is_submap: usize,
    user_wired_count: usize,
}
const LONG: SubmapWords = SubmapWords {
    ref_count: 10,
    packed: 11,
    is_submap: 12,
    user_wired_count: 15,
};
const SHORT: SubmapWords = SubmapWords {
    ref_count: 6,
    packed: 7,
    is_submap: 8,
    user_wired_count: 11,
};
const SUBMAP_PROTECTION: usize = 0;
const SUBMAP_MAX_PROTECTION: usize = 1;
const SUBMAP_OFFSET: usize = 3;
/// `share_mode` values (`vm_region.h`), least shared first: a guest page
/// partly of one mode and partly of another is reported as the more
/// shared.
const SHARE_MODES_BY_SHARING: [u32; 8] = [3, 2, 8, 6, 1, 4, 7, 5];

/// One map entry's information from host regions sharing guest pages:
/// the first region's identity (inheritance, tag, behavior, object) with
/// its offset moved back to `start`; the protections all of them allow;
/// summed page counts; the largest reference count, shadow depth and
/// wiring; an external pager or submap if any has one; the most shared
/// share mode.
fn merge_submap(pieces: &[HostRegion], start: u64, count: u32) -> Vec<u32> {
    let mut info = pieces[0].info.clone();
    if info.len() <= SUBMAP_MAX_PROTECTION {
        return info;
    }
    let long = count >= SUBMAP_INFO_V0_COUNT;
    let layout = if long { &LONG } else { &SHORT };
    if info.len() > SUBMAP_OFFSET + 1 {
        let offset = u64::from(info[SUBMAP_OFFSET]) | u64::from(info[SUBMAP_OFFSET + 1]) << 32;
        let offset = offset.saturating_sub(pieces[0].start - start);
        info[SUBMAP_OFFSET] = offset as u32;
        info[SUBMAP_OFFSET + 1] = (offset >> 32) as u32;
    }
    let rank = |mode: u32| {
        SHARE_MODES_BY_SHARING
            .iter()
            .position(|&m| m == mode)
            .unwrap_or(0)
    };
    for piece in &pieces[1..] {
        let other = &piece.info;
        let both = info.len().min(other.len());
        info[SUBMAP_PROTECTION] &= other[SUBMAP_PROTECTION];
        info[SUBMAP_MAX_PROTECTION] &= other[SUBMAP_MAX_PROTECTION];
        if long {
            for index in SUBMAP_PAGE_WORDS
                .into_iter()
                .chain((both > SUBMAP_REUSABLE_WORD).then_some(SUBMAP_REUSABLE_WORD))
            {
                info[index] = info[index].saturating_add(other[index]);
            }
        }
        let max = |info: &mut Vec<u32>, index: usize, mask: u32| {
            if index < both {
                let merged = (info[index] & mask).max(other[index] & mask);
                info[index] = info[index] & !mask | merged;
            }
        };
        max(&mut info, layout.ref_count, u32::MAX);
        max(&mut info, layout.packed, 0xffff);
        max(&mut info, layout.user_wired_count, 0xffff);
        if layout.packed < both {
            let pager = (info[layout.packed] | other[layout.packed]) & 0x00ff_0000;
            let (mine, theirs) = (info[layout.packed] >> 24, other[layout.packed] >> 24);
            let mode = if rank(theirs) > rank(mine) {
                theirs
            } else {
                mine
            };
            info[layout.packed] = info[layout.packed] & 0xffff | pager | mode << 24;
        }
        if layout.is_submap < both {
            info[layout.is_submap] |= other[layout.is_submap];
        }
    }
    info
}

/// Restate a `vm_region_submap_info_64`'s host page counts in guest
/// pages, a partly counted guest page counting whole; the short layout
/// has none.
fn restate_submap_pages(info: &mut [u32], size: u64) {
    let count = info.len() as u32;
    if count < SUBMAP_INFO_V0_COUNT {
        return;
    }
    let mut counted: Vec<usize> = SUBMAP_PAGE_WORDS.to_vec();
    if count >= SUBMAP_INFO_V1_COUNT {
        counted.push(SUBMAP_REUSABLE_WORD);
    }
    let pages = u32::try_from(size / PAGE_BYTES).unwrap_or(u32::MAX);
    for index in counted {
        info[index] = info[index].div_ceil(HOST_PAGES as u32).min(pages);
    }
}

/// The host page dispositions and reference counts of the guest page
/// holding `address`, the page holding `address` first.
fn host_dispositions(address: u64) -> Vec<(i32, i32, i32)> {
    let page = memory::trunc_page(address);
    let own = address & !HOST_PAGE_MASK;
    core::iter::once(own)
        .chain(
            (0..HOST_PAGES)
                .map(|index| page + index * HOST_PAGE_BYTES)
                .filter(|&host_page| host_page != own),
        )
        .map(|host_page| {
            let (mut disposition, mut references) = (0, 0);
            // SAFETY: out-parameters are locals.
            let code =
                unsafe { mach_vm_page_query(host(), host_page, &mut disposition, &mut references) };
            (code, disposition, references)
        })
        .collect()
}

/// A guest page's disposition and reference count from its host pages':
/// the union of the dispositions the host reports and the largest count.
fn union(pages: &[(i32, i32, i32)]) -> (i32, i32) {
    pages
        .iter()
        .filter(|&&(code, ..)| code == KERN_SUCCESS)
        .fold((0, 0), |(disposition, references), &(_, d, r)| {
            (disposition | d, references.max(r))
        })
}

/// `mach_vm_page_query` (`offset`): out `disposition`, `ref_count` of the
/// guest page holding `offset`.
fn page_query(request: &Request) -> Reply {
    let Some(offset) = request.double(SIMPLE) else {
        return Reply::Failure(MIG_BAD_ARGUMENTS);
    };
    let pages = host_dispositions(offset);
    if pages[0].0 != KERN_SUCCESS {
        return Reply::Failure(pages[0].0 as u32);
    }
    let (disposition, references) = union(&pages);
    Reply::Success(words([disposition as u32, references as u32]))
}

/// `mach_vm_page_info` (`address`, `flavor`, `infoCnt`): the host's
/// basic information for `address`, whose object and offset are the
/// arm64 kernel's, with the guest page's disposition and reference count.
fn page_info(request: &Request) -> Reply {
    let Some((address, flavor, count)) = fields(|| {
        Some((
            request.double(SIMPLE)?,
            request.word(SIMPLE + 8)? as i32,
            request.word(SIMPLE + 12)?,
        ))
    }) else {
        return Reply::Failure(MIG_BAD_ARGUMENTS);
    };
    let mut info = [0i32; PAGE_INFO_MAX as usize];
    let mut count = count.min(PAGE_INFO_MAX);
    // SAFETY: `info` holds the MIG bound's words, `count` at most.
    let code = unsafe { mach_vm_page_info(host(), address, flavor, info.as_mut_ptr(), &mut count) };
    if code != KERN_SUCCESS {
        return Reply::Failure(code as u32);
    }
    let count = count.min(PAGE_INFO_MAX);
    if flavor == VM_PAGE_INFO_BASIC && count >= PAGE_INFO_BASIC_COUNT {
        let (disposition, references) = union(&host_dispositions(address));
        info[0] = disposition;
        info[1] = references;
    }
    let mut body = count.to_le_bytes().to_vec();
    body.extend(words(info[..count as usize].iter().map(|&w| w as u32)));
    Reply::Success(body)
}

/// Guest pages a `mach_vm_page_range_query` asks the host about at once.
const RANGE_QUERY_CHUNK: u64 = 1024;

/// `mach_vm_page_range_query` (`address`, `size`, `dispositions`,
/// `dispositions_count`): one disposition per guest page of the range,
/// up to the caller's count, copied out to `dispositions`; out the number
/// copied.
fn page_range_query(request: &Request) -> Reply {
    let Some((address, size, dispositions, capacity)) = fields(|| {
        Some((
            request.double(SIMPLE)?,
            request.double(SIMPLE + 8)?,
            request.double(SIMPLE + 16)?,
            request.double(SIMPLE + 24)?,
        ))
    }) else {
        return Reply::Failure(MIG_BAD_ARGUMENTS);
    };
    if size == 0 || capacity == 0 {
        return Reply::Success(capacity.to_le_bytes().to_vec());
    }
    let Some((start, bytes)) = pages(address, size) else {
        return Reply::Failure(KERN_INVALID_ARGUMENT);
    };
    let total = (bytes / PAGE_BYTES).min(capacity);
    let mut done = 0u64;
    while done < total {
        let chunk = (total - done).min(RANGE_QUERY_CHUNK);
        let mut host_pages = vec![0i32; (chunk * HOST_PAGES) as usize];
        let mut count = chunk * HOST_PAGES;
        // SAFETY: the host copies at most `count` dispositions out to the
        // local buffer, in this task.
        let code = unsafe {
            mach_vm_page_range_query(
                host(),
                start + done * PAGE_BYTES,
                chunk * PAGE_BYTES,
                host_pages.as_mut_ptr() as u64,
                &mut count,
            )
        };
        if code != KERN_SUCCESS {
            return Reply::Failure(code as u32);
        }
        let guest: Vec<u32> = host_pages
            .chunks(HOST_PAGES as usize)
            .map(|page| page.iter().fold(0, |union, &d| union | d) as u32)
            .collect();
        if !memory::write(dispositions + done * 4, &words(guest)) {
            return Reply::Failure(KERN_INVALID_ADDRESS);
        }
        done += chunk;
    }
    Reply::Success(total.to_le_bytes().to_vec())
}

/// `mach_vm_purgable_control` (`address`, `control`, `state`) on the
/// object mapped at the guest page holding `address`; out `state`.
fn purgable_control(request: &Request) -> Reply {
    let Some((address, control, state)) = fields(|| {
        Some((
            request.double(SIMPLE)?,
            request.word(SIMPLE + 8)? as i32,
            request.word(SIMPLE + 12)? as i32,
        ))
    }) else {
        return Reply::Failure(MIG_BAD_ARGUMENTS);
    };
    let mut state = state;
    // SAFETY: the guest's own mapping; `state` is a local.
    let code = unsafe {
        mach_vm_purgable_control(host(), memory::trunc_page(address), control, &mut state)
    };
    if code == KERN_SUCCESS {
        Reply::Success((state as u32).to_le_bytes().to_vec())
    } else {
        Reply::Failure(code as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_served_routine_is_a_mach_vm_routine() {
        for (routine, limit) in SERVED {
            assert!(
                crate::mach::mig::subsystems()
                    .iter()
                    .filter(|subsystem| subsystem.name == "mach_vm")
                    .flat_map(|subsystem| (subsystem.base..subsystem.end)
                        .filter_map(crate::mach::mig::routine))
                    .any(|entry| entry.name == *routine),
                "{routine}"
            );
            assert!(limit.is_none_or(|limit| !limit.is_empty()));
        }
        for routine in COMPLEX {
            assert!(SERVED.iter().any(|(name, _)| name == routine));
        }
    }

    /// This process as a hosted task without a shared region.
    struct Bare;

    impl Task for Bare {
        fn port(&self) -> u32 {
            host()
        }

        fn page_in(&mut self, _: u64, _: u64) -> Result<()> {
            Ok(())
        }

        fn unslid_change(
            &mut self,
            start: u64,
            size: u64,
            _: &mut dyn FnMut(Protection) -> Option<Protection>,
        ) -> Vec<(u64, u64)> {
            vec![(start, size)]
        }

        fn invalidate(&self, _: u64, _: u64) {}
    }

    fn bare() -> Bare {
        Bare
    }

    fn simple(fields: &[&[u8]]) -> Vec<u8> {
        let mut body = super::super::server::NDR_RECORD.to_vec();
        for field in fields {
            body.extend(*field);
        }
        body
    }

    fn with_port(name: u32, disposition: u8, fields: &[&[u8]]) -> Vec<u8> {
        let mut body = 1u32.to_le_bytes().to_vec();
        body.extend(name.to_le_bytes());
        body.extend([0; 6]);
        body.extend([disposition, MACH_MSG_PORT_DESCRIPTOR]);
        body.extend(simple(fields));
        body
    }

    fn call(task: &mut Bare, routine: &str, complex: bool, body: &[u8]) -> Result<Reply> {
        Ok(route(task, routine, complex, &Request { body })?.expect("served"))
    }

    fn success(reply: Reply) -> Vec<u8> {
        match reply {
            Reply::Success(body) => body,
            Reply::Failure(code) => panic!("kern_return {code:#x}"),
            _ => panic!("not a simple success"),
        }
    }

    fn failure(reply: Reply) -> u32 {
        match reply {
            Reply::Failure(code) => code,
            _ => panic!("succeeded"),
        }
    }

    fn u64_at(body: &[u8], at: usize) -> u64 {
        u64::from_le_bytes(body[at..at + 8].try_into().unwrap())
    }

    fn u32_at(body: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(body[at..at + 4].try_into().unwrap())
    }

    fn allocate_pages(task: &mut Bare, pages: u64) -> u64 {
        let body = simple(&[
            &0u64.to_le_bytes(),
            &(pages * PAGE_BYTES - 100).to_le_bytes(),
            &VM_FLAGS_ANYWHERE.to_le_bytes(),
        ]);
        let address = u64_at(
            &success(call(task, "_kernelrpc_mach_vm_allocate_external", false, &body).unwrap()),
            0,
        );
        assert_eq!(address & PAGE_MASK, 0);
        address
    }

    fn remap_body(target: u64, size: u64, flags: i32, source: u64, copy: bool) -> Vec<u8> {
        with_port(
            host(),
            MACH_MSG_TYPE_COPY_SEND,
            &[
                &target.to_le_bytes(),
                &size.to_le_bytes(),
                &0u64.to_le_bytes(),
                &flags.to_le_bytes(),
                &source.to_le_bytes(),
                &u32::from(copy).to_le_bytes(),
                &VM_INHERIT_DEFAULT.to_le_bytes(),
            ],
        )
    }

    fn reallocate_body(
        source: u64,
        source_size: u64,
        destination: u64,
        destination_size: u64,
        options: i32,
        flags: i32,
    ) -> Vec<u8> {
        simple(&[
            &source.to_le_bytes(),
            &source_size.to_le_bytes(),
            &destination.to_le_bytes(),
            &destination_size.to_le_bytes(),
            &0u64.to_le_bytes(),
            &options.to_le_bytes(),
            &flags.to_le_bytes(),
        ])
    }

    fn reallocate(task: &mut Bare, body: &[u8]) -> Reply {
        call(task, "_kernelrpc_mach_vm_reallocate", false, body).unwrap()
    }

    /// Whether a byte of `address` is mapped readable.
    fn mapped(address: u64) -> bool {
        memory::read(address, 1).is_some()
    }

    /// Take the guest page after `source`, unless something holds it
    /// already: either way growing the source cannot stay in place. The
    /// page, when this took it.
    fn block_after(source: u64) -> Option<u64> {
        let mut blocker = source + PAGE_BYTES;
        // SAFETY: a fixed allocation of a free page of this task.
        (unsafe { mach_vm_allocate(host(), &mut blocker, PAGE_BYTES, 0) } == KERN_SUCCESS)
            .then_some(blocker)
    }

    fn release(address: u64, bytes: u64) {
        // SAFETY: pages this test allocated.
        unsafe { mach_vm_deallocate(host(), address, bytes) };
    }

    #[test]
    fn reallocate_moves_whole_guest_pages_and_unmaps_the_source() {
        let mut task = bare();
        let source = allocate_pages(&mut task, 1);
        assert!(memory::write(source + 0x10, b"moved"));
        let blocker = block_after(source);
        let body = reallocate_body(source, PAGE_BYTES, 0, 3 * PAGE_BYTES, 0, VM_FLAGS_ANYWHERE);
        let moved = u64_at(&success(reallocate(&mut task, &body)), 0);
        assert_ne!(moved, source);
        assert_eq!(moved & PAGE_MASK, 0);
        assert_eq!(memory::read(moved + 0x10, 5).unwrap(), b"moved");
        // The grown pages are zero-filled with the source's protections.
        assert_eq!(memory::read(moved + 2 * PAGE_BYTES, 4).unwrap(), [0; 4]);
        assert!(memory::write(moved + 3 * PAGE_BYTES - 1, b"!"));
        // The default option unmaps the source.
        assert!(!mapped(source));
        release(moved, 3 * PAGE_BYTES);
        if let Some(blocker) = blocker {
            release(blocker, PAGE_BYTES);
        }
    }

    #[test]
    fn reallocate_can_leave_zero_filled_pages_at_the_source() {
        let mut task = bare();
        let source = allocate_pages(&mut task, 1);
        assert!(memory::write(source, b"data"));
        let blocker = block_after(source);
        let body = reallocate_body(
            source,
            PAGE_BYTES,
            0,
            2 * PAGE_BYTES,
            VM_REALLOCATE_ZERO_FILL_SOURCE,
            VM_FLAGS_ANYWHERE,
        );
        let moved = u64_at(&success(reallocate(&mut task, &body)), 0);
        assert_eq!(memory::read(moved, 4).unwrap(), b"data");
        assert_eq!(memory::read(source, 4).unwrap(), [0; 4]);
        release(moved, 2 * PAGE_BYTES);
        release(source, PAGE_BYTES);
        if let Some(blocker) = blocker {
            release(blocker, PAGE_BYTES);
        }
    }

    #[test]
    fn reallocate_checks_its_arguments_on_guest_pages() {
        let mut task = bare();
        let source = allocate_pages(&mut task, 2);
        let refused = |task: &mut Bare, body: Vec<u8>| failure(reallocate(task, &body));
        // A source or destination size in host pages but not guest pages.
        let host_page = HOST_PAGE_BYTES;
        assert_eq!(
            refused(
                &mut task,
                reallocate_body(source, host_page, 0, PAGE_BYTES, 0, 1)
            ),
            KERN_INVALID_ARGUMENT
        );
        assert_eq!(
            refused(
                &mut task,
                reallocate_body(source, PAGE_BYTES, 0, PAGE_BYTES + host_page, 0, 1)
            ),
            KERN_INVALID_ARGUMENT
        );
        // A source start inside a guest page.
        assert_eq!(
            refused(
                &mut task,
                reallocate_body(source + host_page, PAGE_BYTES, 0, PAGE_BYTES, 0, 1)
            ),
            KERN_INVALID_ARGUMENT
        );
        // Shrinking is the allocator's.
        assert_eq!(
            refused(
                &mut task,
                reallocate_body(source, 2 * PAGE_BYTES, 0, PAGE_BYTES, 0, 1)
            ),
            KERN_INVALID_ARGUMENT
        );
        // Unknown flags and options.
        assert_eq!(
            refused(
                &mut task,
                reallocate_body(source, PAGE_BYTES, 0, PAGE_BYTES, 2, 1)
            ),
            KERN_INVALID_ARGUMENT
        );
        assert_eq!(
            refused(
                &mut task,
                reallocate_body(source, PAGE_BYTES, 0, PAGE_BYTES, 0, 0x8)
            ),
            KERN_INVALID_ARGUMENT
        );
        // A fixed overwrite onto the source itself.
        assert_eq!(
            refused(
                &mut task,
                reallocate_body(
                    source,
                    PAGE_BYTES,
                    source,
                    2 * PAGE_BYTES,
                    0,
                    VM_FLAGS_OVERWRITE
                )
            ),
            KERN_INVALID_ADDRESS
        );
        // The shared region is a submap.
        assert_eq!(
            refused(
                &mut task,
                reallocate_body(REGION_START, PAGE_BYTES, 0, PAGE_BYTES, 0, 1)
            ),
            KERN_INVALID_ADDRESS
        );
        // An equal size already aligned is the source itself.
        let body = reallocate_body(source, PAGE_BYTES, 0, PAGE_BYTES, 0, VM_FLAGS_ANYWHERE);
        assert_eq!(u64_at(&success(reallocate(&mut task, &body)), 0), source);
        release(source, 2 * PAGE_BYTES);
    }

    #[test]
    fn remap_shares_or_copies_whole_guest_pages() {
        let mut task = bare();
        let source = allocate_pages(&mut task, 2);
        assert!(memory::write(source + 0x10, b"shared"));
        // Shared: a store through either mapping is seen through the
        // other; the strictest protections are reported.
        let body = remap_body(0, 0x20, VM_FLAGS_ANYWHERE, source + 0x10, false);
        let reply =
            success(call(&mut task, "_kernelrpc_mach_vm_remap_external", true, &body).unwrap());
        let alias = u64_at(&reply, 0);
        assert_eq!(alias & PAGE_MASK, 0);
        assert_eq!(
            (u32_at(&reply, 8), u32_at(&reply, 12)),
            (VM_PROT_DEFAULT as u32, Protection::ALL.0 as u32)
        );
        assert_eq!(memory::read(alias + 0x10, 6).unwrap(), b"shared");
        assert!(memory::write(alias + PAGE_BYTES - 1, b"!"));
        assert_eq!(memory::read(source + PAGE_BYTES - 1, 1).unwrap(), b"!");
        // A host page past the first of the guest page came with it.
        // Copied, returning the data's address: the copy is private.
        let flags = VM_FLAGS_ANYWHERE | VM_FLAGS_RETURN_DATA_ADDR;
        let body = remap_body(0, 6, flags, source + 0x10, true);
        let reply =
            success(call(&mut task, "_kernelrpc_mach_vm_remap_external", true, &body).unwrap());
        let copy = u64_at(&reply, 0);
        assert_eq!(copy & PAGE_MASK, 0x10);
        assert!(memory::write(copy, b"copied"));
        assert_eq!(memory::read(source + 0x10, 6).unwrap(), b"shared");
        // Fixed over the copy, replacing it.
        let flags = VM_FLAGS_OVERWRITE;
        let body = remap_body(copy + 0x123, PAGE_BYTES, flags, source + PAGE_BYTES, false);
        let reply =
            success(call(&mut task, "_kernelrpc_mach_vm_remap_external", true, &body).unwrap());
        assert_eq!(u64_at(&reply, 0), copy - 0x10);
        // The new routine applies its protections and returns the data's
        // address; a kernel-only flag and a writable executable maximum
        // are refused.
        let mut body = with_port(
            host(),
            MACH_MSG_TYPE_COPY_SEND,
            &[
                &0u64.to_le_bytes(),
                &8u64.to_le_bytes(),
                &0u64.to_le_bytes(),
                &VM_FLAGS_ANYWHERE.to_le_bytes(),
                &(source + 8).to_le_bytes(),
                &0u32.to_le_bytes(),
                &1u32.to_le_bytes(),
                &1u32.to_le_bytes(),
                &VM_INHERIT_DEFAULT.to_le_bytes(),
            ],
        );
        let reply = success(
            call(
                &mut task,
                "_kernelrpc_mach_vm_remap_new_external",
                true,
                &body,
            )
            .unwrap(),
        );
        let read_only = u64_at(&reply, 0);
        assert_eq!(read_only & PAGE_MASK, 8);
        assert_eq!((u32_at(&reply, 8), u32_at(&reply, 12)), (1, 1));
        assert!(!memory::write(read_only, b"x"));
        let maximum = ONE_PORT + 44;
        body[maximum..maximum + 4].copy_from_slice(&7u32.to_le_bytes());
        let code = failure(
            call(
                &mut task,
                "_kernelrpc_mach_vm_remap_new_external",
                true,
                &body,
            )
            .unwrap(),
        );
        assert_eq!(code, 2, "KERN_PROTECTION_FAILURE");
        let body = remap_body(0, 8, VM_FLAGS_ANYWHERE | 0x80, source, false);
        assert_eq!(
            failure(call(&mut task, "_kernelrpc_mach_vm_remap_external", true, &body).unwrap()),
            KERN_INVALID_ARGUMENT
        );
        // Another task's port is refused by name; a simple request is
        // malformed.
        let mut other = remap_body(0, 8, VM_FLAGS_ANYWHERE, source, false);
        other[4..8].copy_from_slice(&(host() + 4).to_le_bytes());
        let error = call(&mut task, "_kernelrpc_mach_vm_remap_external", true, &other)
            .err()
            .unwrap();
        assert!(error.to_string().contains("another task"), "{error}");
        assert_eq!(
            failure(
                call(
                    &mut task,
                    "_kernelrpc_mach_vm_remap_external",
                    false,
                    &other
                )
                .unwrap()
            ),
            MIG_BAD_ARGUMENTS
        );
        for (address, pages) in [
            (source, 2),
            (alias, 1),
            (copy - 0x10, 1),
            (read_only - 8, 1),
        ] {
            memory::deallocate(address, pages * PAGE_BYTES).unwrap();
        }
    }

    #[test]
    fn a_source_splitting_a_guest_page_is_refused() {
        let mut task = bare();
        let source = allocate_pages(&mut task, 1);
        let remap = |task: &mut Bare| {
            let body = remap_body(0, 8, VM_FLAGS_ANYWHERE, source, false);
            call(task, "_kernelrpc_mach_vm_remap_external", true, &body)
        };
        // A host page of another object but the same protections inside
        // the guest page: the host treats the page as one.
        let mut part = source + HOST_PAGE_BYTES;
        // SAFETY: a host page of the test's own allocation.
        let code =
            unsafe { mach_vm_allocate(host(), &mut part, HOST_PAGE_BYTES, VM_FLAGS_OVERWRITE) };
        assert_eq!(code, KERN_SUCCESS);
        let alias = u64_at(&success(remap(&mut task).unwrap()), 0);
        memory::deallocate(alias, PAGE_BYTES).unwrap();
        // Differing protections, or a hole, inside it are refused.
        memory::protect(part, HOST_PAGE_BYTES, Protection::READ).unwrap();
        let error = remap(&mut task).err().unwrap();
        assert!(
            error.to_string().contains("protections 3/7 before"),
            "{error}"
        );
        memory::deallocate(part, HOST_PAGE_BYTES).unwrap();
        let error = remap(&mut task).err().unwrap();
        assert!(error.to_string().contains("a hole from"), "{error}");
        memory::deallocate(source, PAGE_BYTES).unwrap();
    }

    #[test]
    fn ranges_cover_whole_guest_pages() {
        let mut task = bare();
        let base = allocate_pages(&mut task, 3);
        let range = |address: u64, size: u64, extra: &[&[u8]]| {
            let mut fields: Vec<&[u8]> = Vec::new();
            let (address, size) = (address.to_le_bytes(), size.to_le_bytes());
            fields.push(&address);
            fields.push(&size);
            fields.extend(extra);
            simple(&fields)
        };
        // Protect one byte: its whole guest page changes.
        let body = range(
            base + PAGE_BYTES + 5,
            1,
            &[&0u32.to_le_bytes(), &1u32.to_le_bytes()],
        );
        success(call(&mut task, "_kernelrpc_mach_vm_protect", false, &body).unwrap());
        assert!(!memory::write(base + PAGE_BYTES + PAGE_BYTES - 1, b"x"));
        assert!(memory::write(base + PAGE_BYTES - 1, b"x"));
        assert!(memory::write(base + 2 * PAGE_BYTES, b"x"));
        // Inheritance and behavior over a partial page.
        let body = range(base + 1, 2, &[&2u32.to_le_bytes()]);
        success(call(&mut task, "mach_vm_inherit", false, &body).unwrap());
        let body = range(base + 1, 2, &[&VM_BEHAVIOR_REUSABLE.to_le_bytes()]);
        success(call(&mut task, "mach_vm_behavior_set", false, &body).unwrap());
        let body = range(base + 1, 2, &[&2u32.to_le_bytes()]);
        success(call(&mut task, "mach_vm_msync", false, &body).unwrap());
        // Copy, read_overwrite and write move exact bytes.
        assert!(memory::write(base, b"abcdef"));
        let body = range(base, 6, &[&(base + 2 * PAGE_BYTES + 3).to_le_bytes()]);
        success(call(&mut task, "mach_vm_copy", false, &body).unwrap());
        assert_eq!(
            memory::read(base + 2 * PAGE_BYTES + 2, 8).unwrap(),
            b"\0abcdef\0"
        );
        let body = range(base + 1, 3, &[&(base + 0x100).to_le_bytes()]);
        let reply = success(call(&mut task, "mach_vm_read_overwrite", false, &body).unwrap());
        assert_eq!(u64_at(&reply, 0), 3);
        assert_eq!(memory::read(base + 0x100, 3).unwrap(), b"bcd");
        let data = b"written";
        let mut body = 1u32.to_le_bytes().to_vec();
        body.extend((data.as_ptr() as u64).to_le_bytes());
        body.extend([0, 0, 0, MACH_MSG_OOL_DESCRIPTOR]);
        body.extend((data.len() as u32).to_le_bytes());
        body.extend(simple(&[
            &(base + 0x200).to_le_bytes(),
            &(data.len() as u32).to_le_bytes(),
        ]));
        success(call(&mut task, "mach_vm_write", true, &body).unwrap());
        assert_eq!(memory::read(base + 0x200, data.len()).unwrap(), data);
        // A write into the read-only page fails as the kernel's does.
        body[ONE_OOL..ONE_OOL + 8].copy_from_slice(&(base + PAGE_BYTES).to_le_bytes());
        failure(call(&mut task, "mach_vm_write", true, &body).unwrap());
        // Deallocate one byte of the last page: the whole page goes.
        let body = range(base + 2 * PAGE_BYTES + 7, 1, &[]);
        success(
            call(
                &mut task,
                "_kernelrpc_mach_vm_deallocate_external",
                false,
                &body,
            )
            .unwrap(),
        );
        // (The freed page may be reused by a concurrent test at once; the
        // page before it is still the test's own.)
        assert!(memory::read(base + 2 * PAGE_BYTES - 1, 1).is_some());
        // A wrapping range is refused.
        let body = range(u64::MAX - 4, 8, &[]);
        assert_eq!(
            failure(
                call(
                    &mut task,
                    "_kernelrpc_mach_vm_deallocate_external",
                    false,
                    &body
                )
                .unwrap()
            ),
            KERN_INVALID_ARGUMENT
        );
        memory::deallocate(base, 2 * PAGE_BYTES).unwrap();
    }

    #[test]
    fn allocations_are_placed_in_guest_pages() {
        let mut task = bare();
        let base = allocate_pages(&mut task, 2);
        // A fixed allocation over an occupied page fails; with overwrite
        // it replaces the whole guest page.
        assert!(memory::write(base + PAGE_BYTES, b"old"));
        let fixed = |flags: i32| {
            simple(&[
                &(base + PAGE_BYTES + 0x10).to_le_bytes(),
                &1u64.to_le_bytes(),
                &flags.to_le_bytes(),
            ])
        };
        assert_eq!(
            failure(
                call(
                    &mut task,
                    "_kernelrpc_mach_vm_allocate_external",
                    false,
                    &fixed(0)
                )
                .unwrap()
            ),
            3,
            "KERN_NO_SPACE"
        );
        let reply = success(
            call(
                &mut task,
                "_kernelrpc_mach_vm_allocate_external",
                false,
                &fixed(VM_FLAGS_OVERWRITE),
            )
            .unwrap(),
        );
        assert_eq!(u64_at(&reply, 0), base + PAGE_BYTES);
        assert_eq!(memory::read(base + PAGE_BYTES, 3).unwrap(), [0; 3]);
        // The arm64 kernel has no superpages.
        let body = simple(&[
            &0u64.to_le_bytes(),
            &PAGE_BYTES.to_le_bytes(),
            &(VM_FLAGS_ANYWHERE | 0x2_0000).to_le_bytes(),
        ]);
        assert_eq!(
            failure(
                call(
                    &mut task,
                    "_kernelrpc_mach_vm_allocate_external",
                    false,
                    &body
                )
                .unwrap()
            ),
            KERN_INVALID_ARGUMENT
        );
        memory::deallocate(base, 2 * PAGE_BYTES).unwrap();
    }

    #[test]
    fn queries_describe_guest_pages() {
        let mut task = bare();
        // Two guest pages between inaccessible guards, so no neighboring
        // host allocation joins their region.
        let outer = allocate_pages(&mut task, 4);
        for guard in [outer, outer + 3 * PAGE_BYTES] {
            memory::protect(guard, PAGE_BYTES, Protection::NONE).unwrap();
        }
        let base = outer + PAGE_BYTES;
        // Touch one host page of the first guest page only.
        assert!(memory::write(base + 3 * HOST_PAGE_BYTES, b"x"));
        let body = simple(&[&base.to_le_bytes()]);
        let reply = success(call(&mut task, "mach_vm_page_query", false, &body).unwrap());
        assert_ne!(u32_at(&reply, 0) & 1, 0, "VM_PAGE_QUERY_PAGE_PRESENT");
        let body = simple(&[
            &(base + 8).to_le_bytes(),
            &VM_PAGE_INFO_BASIC.to_le_bytes(),
            &PAGE_INFO_BASIC_COUNT.to_le_bytes(),
        ]);
        let reply = success(call(&mut task, "mach_vm_page_info", false, &body).unwrap());
        assert_eq!(u32_at(&reply, 0), PAGE_INFO_BASIC_COUNT);
        assert_ne!(u32_at(&reply, 4) & 1, 0);
        // One disposition per guest page, bounded by the caller's count.
        let mut dispositions = [0xffff_ffffu32; 4];
        let body = simple(&[
            &base.to_le_bytes(),
            &(2 * PAGE_BYTES).to_le_bytes(),
            &(dispositions.as_mut_ptr() as u64).to_le_bytes(),
            &4u64.to_le_bytes(),
        ]);
        let reply = success(call(&mut task, "mach_vm_page_range_query", false, &body).unwrap());
        assert_eq!(u64_at(&reply, 0), 2);
        assert_ne!(dispositions[0] & 1, 0);
        assert_eq!(dispositions[1] & 1, 0);
        assert_eq!(dispositions[2], 0xffff_ffff);
        // The region holding the allocation, whole guest pages.
        let body = simple(&[
            &base.to_le_bytes(),
            &0u32.to_le_bytes(),
            &RECURSE_INFO_MAX.to_le_bytes(),
        ]);
        let reply = success(call(&mut task, "mach_vm_region_recurse", false, &body).unwrap());
        assert_eq!(
            (u64_at(&reply, 0), u64_at(&reply, 8)),
            (base, 2 * PAGE_BYTES)
        );
        assert_eq!(u32_at(&reply, 20), RECURSE_INFO_MAX);
        assert_eq!(u32_at(&reply, 24), VM_PROT_DEFAULT as u32);
        let body = simple(&[
            &base.to_le_bytes(),
            &9u32.to_le_bytes(),
            &9u32.to_le_bytes(),
        ]);
        assert!(matches!(
            call(&mut task, "mach_vm_region", false, &body).unwrap(),
            Reply::Forward
        ));
        let body = simple(&[
            &base.to_le_bytes(),
            &99u32.to_le_bytes(),
            &9u32.to_le_bytes(),
        ]);
        assert_eq!(
            failure(call(&mut task, "mach_vm_region", false, &body).unwrap()),
            KERN_INVALID_ARGUMENT
        );
        // A non-purgeable object's state.
        let body = simple(&[
            &base.to_le_bytes(),
            &1u32.to_le_bytes(),
            &0u32.to_le_bytes(),
        ]);
        let _ = call(
            &mut task,
            "_kernelrpc_mach_vm_purgable_control_external",
            false,
            &body,
        )
        .unwrap();
        memory::deallocate(outer, 4 * PAGE_BYTES).unwrap();
    }

    #[test]
    fn reads_copy_guest_pages() {
        let mut task = bare();
        let base = allocate_pages(&mut task, 2);
        assert!(memory::write(base + 0x10, b"before"));
        assert!(memory::write(base + PAGE_BYTES + 0x2345, b"listed"));
        // The data travels out of line from the host's copy, which the
        // reply's send releases.
        let body = simple(&[&(base + 0x10).to_le_bytes(), &6u64.to_le_bytes()]);
        let Reply::Complex { descriptors, body } =
            call(&mut task, "_kernelrpc_mach_vm_read", false, &body).unwrap()
        else {
            panic!("not a complex reply");
        };
        assert_eq!(body, 6u32.to_le_bytes());
        let [
            Descriptor::Memory {
                address,
                size: 6,
                deallocate: true,
            },
        ] = descriptors[..]
        else {
            panic!("{descriptors:?}");
        };
        assert_eq!(memory::read(address, 6).unwrap(), b"before");
        memory::deallocate(address & !HOST_PAGE_MASK, HOST_PAGE_BYTES).unwrap();
        // Each listed range's guest pages land in new guest pages, at the
        // range's offset in them; an empty entry is zeroed.
        let mut list = vec![0u8; READ_LIST_MAX as usize * READ_ENTRY_BYTES];
        list[..8].copy_from_slice(&(base + PAGE_BYTES + 0x2345).to_le_bytes());
        list[8..16].copy_from_slice(&6u64.to_le_bytes());
        list[16..24].copy_from_slice(&base.to_le_bytes());
        let body = simple(&[&list, &2u32.to_le_bytes()]);
        let reply = success(call(&mut task, "mach_vm_read_list", false, &body).unwrap());
        let (copied, size) = (u64_at(&reply, 0), u64_at(&reply, 8));
        assert_eq!((copied & PAGE_MASK, size), (0x2345, 6));
        assert_eq!(memory::read(copied, 6).unwrap(), b"listed");
        assert!(memory::write(copied - 0x2345, b"writable"));
        assert_eq!(u64_at(&reply, 16), 0);
        memory::deallocate(copied & !PAGE_MASK, PAGE_BYTES).unwrap();
        // An unreadable last range (this process's __PAGEZERO) fails the
        // routine.
        list[8..16].copy_from_slice(&0u64.to_le_bytes());
        list[16..24].copy_from_slice(&PAGE_BYTES.to_le_bytes());
        list[24..32].copy_from_slice(&8u64.to_le_bytes());
        let body = simple(&[&list, &2u32.to_le_bytes()]);
        failure(call(&mut task, "mach_vm_read_list", false, &body).unwrap());
        let body = simple(&[&list, &(READ_LIST_MAX + 1).to_le_bytes()]);
        assert_eq!(
            failure(call(&mut task, "mach_vm_read_list", false, &body).unwrap()),
            KERN_INVALID_ARGUMENT
        );
        memory::deallocate(base, 2 * PAGE_BYTES).unwrap();
    }

    #[test]
    fn host_regions_sharing_a_guest_page_merge_into_one_entry() {
        let region = |start: u64, info: Vec<u32>| HostRegion {
            start,
            size: HOST_PAGE_BYTES,
            depth: 0,
            info,
        };
        let mut first = vec![0u32; 19];
        first[SUBMAP_PROTECTION] = 3;
        first[SUBMAP_MAX_PROTECTION] = 7;
        first[SUBMAP_OFFSET] = 0x3000;
        first[6] = 3;
        first[LONG.ref_count] = 1;
        first[LONG.packed] = 2 << 24 | 1;
        let mut second = first.clone();
        second[SUBMAP_PROTECTION] = 1;
        second[6] = 1;
        second[LONG.ref_count] = 4;
        second[LONG.packed] = 4 << 24 | 1 << 16;
        let merged = merge_submap(
            &[region(0x1000, first), region(0x2000, second)],
            0,
            RECURSE_INFO_MAX,
        );
        assert_eq!(merged[SUBMAP_PROTECTION], 1);
        assert_eq!(merged[SUBMAP_MAX_PROTECTION], 7);
        assert_eq!(merged[SUBMAP_OFFSET], 0x2000);
        assert_eq!(merged[6], 4);
        assert_eq!(merged[LONG.ref_count], 4);
        // Shadow depth 1, an external pager, shared over private.
        assert_eq!(merged[LONG.packed], 4 << 24 | 1 << 16 | 1);
    }

    #[test]
    fn a_region_split_inside_a_guest_page_is_reported_whole() {
        let mut task = bare();
        let base = allocate_pages(&mut task, 4);
        // Guard pages either side, so no neighbor joins the region.
        for guard in [base, base + 3 * PAGE_BYTES] {
            memory::protect(guard, PAGE_BYTES, Protection::NONE).unwrap();
        }
        let query = |task: &mut Bare| {
            let body = simple(&[
                &(base + PAGE_BYTES).to_le_bytes(),
                &0u32.to_le_bytes(),
                &RECURSE_INFO_MAX.to_le_bytes(),
            ]);
            let reply = success(call(task, "mach_vm_region_recurse", false, &body).unwrap());
            (u64_at(&reply, 0), u64_at(&reply, 8), u32_at(&reply, 24))
        };
        assert_eq!(
            query(&mut task),
            (base + PAGE_BYTES, 2 * PAGE_BYTES, VM_PROT_DEFAULT as u32)
        );
        // One host page made read-only splits the host's region inside the
        // second guest page: the guest still sees one entry, read-only.
        // SAFETY: a host page of this test's own allocation.
        let status = unsafe {
            mach_vm_protect(
                host(),
                base + 2 * PAGE_BYTES + HOST_PAGE_BYTES,
                HOST_PAGE_BYTES,
                0,
                1,
            )
        };
        assert_eq!(status, KERN_SUCCESS);
        assert_eq!(query(&mut task), (base + PAGE_BYTES, 2 * PAGE_BYTES, 1));
        memory::deallocate(base, 4 * PAGE_BYTES).unwrap();
    }

    #[test]
    fn page_counts_are_restated_in_guest_pages() {
        let mut info = [8u32; 19];
        info[6] = 5;
        restate_submap_pages(&mut info, 8 * PAGE_BYTES);
        assert_eq!(&info[5..11], &[8, 2, 2, 2, 2, 8]);
        assert_eq!(info[16], 2);
        // No more pages than the region holds.
        let mut full = [8u32; 19];
        restate_submap_pages(&mut full, PAGE_BYTES);
        assert_eq!(full[6], 1);
        let mut short = [8u32; 12];
        restate_submap_pages(&mut short, PAGE_BYTES);
        assert_eq!(short, [8; 12]);
        assert_eq!(union(&[(0, 1, 2), (0, 8, 5), (1, 0x10, 9)]), (9, 5));
        assert_eq!(pages(PAGE_BYTES + 1, 0), Some((PAGE_BYTES, 0)));
        assert_eq!(pages(PAGE_BYTES - 1, 2), Some((0, 2 * PAGE_BYTES)));
        assert_eq!(pages(u64::MAX - 1, 1), None);
    }
}
