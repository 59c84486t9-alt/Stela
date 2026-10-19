//! Deferred memory reclamation (`osfmk/vm/vm_reclaim.c`): the ring buffer
//! libmalloc fills with memory it no longer needs, and the kernel side that
//! reclaims its entries. The ring lives in the guest's pages and its
//! deadlines are guest absolute time, so the hosted kernel keeps the ring
//! itself; the reclamations are host deallocations or reusable marks of
//! whole 16 KiB pages.
//!
//! The kernel's synchronous paths are modeled: allocation, flush, resize
//! and the accounting update with its working-set sample and autotrim. The
//! sampling period and autotrim percentage follow the host's memory
//! pressure level (`kern.memorystatus_vm_pressure_level`); the scavenger
//! thread's asynchronous reclamation under pressure and the swap-active
//! critical period are not modeled.
use crate::hosted::{host, memory};

/// `struct mach_vm_reclaim_ring_s` field offsets.
const RING_RECLAIMABLE_BYTES: u64 = 72;
const RING_RECLAIMABLE_BYTES_MIN: u64 = 80;
const RING_HEAD: u64 = 88;
const RING_BUSY: u64 = 96;
const RING_TAIL: u64 = 104;
const RING_ENTRIES: u64 = 128;
/// `struct mach_vm_reclaim_entry_s`: `address`, `size`, `behavior`.
const ENTRY_BYTES: u64 = 16;
/// `VM_RECLAIM_MAX_BUFFER_SIZE`.
const MAX_BUFFER_BYTES: u64 = 128 << 20;
/// `kReclaimChunkSize` on a release kernel.
const CHUNK: u64 = 16;
const VM_RECLAIM_FREE: u8 = 1;
const VM_RECLAIM_DEALLOCATE: u8 = 2;
/// The macOS sampling periods (`VMDR_SAMPLING_PERIOD_*_NS`).
const PERIOD_NORMAL_NS: u64 = 10_000_000_000;
const PERIOD_PRESSURE_NS: u64 = 1_000_000_000;
/// The macOS autotrim percentages (`vm_reclaim_autotrim_pct_*`).
const AUTOTRIM_NORMAL: u64 = 10;
const AUTOTRIM_PRESSURE: u64 = 5;
const AUTOTRIM_CRITICAL: u64 = 1;
/// The working-set average's weights and unit (`vm_reclaim_wma_*`,
/// `VMDR_WMA_UNIT`) and `vm_reclaim_abandonment_threshold`.
const WMA_BASE: u64 = 3;
const WMA_CURRENT: u64 = 1;
const WMA_DENOMINATOR: u64 = 4;
const WMA_UNIT: u64 = 1 << 8;
const ABANDONMENT_THRESHOLD: u64 = 512;

const KERN_SUCCESS: u32 = 0;
const KERN_INVALID_ARGUMENT: u32 = 4;
const KERN_FAILURE: u32 = 5;
const KERN_NO_SPACE: u32 = 3;
const KERN_INVALID_TASK: u32 = 16;
const KERN_ABORTED: u32 = 14;
const KERN_NOT_FOUND: u32 = 56;
/// `VM_RECLAIM_RESOURCE_SHORTAGE`.
const RESOURCE_SHORTAGE: u32 = 6;
const VM_FLAGS_ANYWHERE: i32 = 1;
const VM_INHERIT_COPY: u32 = 1;
/// `NOTE_MEMORYSTATUS_PRESSURE_WARN` and `_CRITICAL`, as the sysctl reports.
const PRESSURE_WARN: i32 = 2;
const PRESSURE_CRITICAL: i32 = 4;

/// The process's registered ring (`vm_deferred_reclamation_metadata_s`).
#[derive(Debug)]
pub(in crate::hosted) struct Ring {
    address: u64,
    bytes: u64,
    len: u64,
    last_sample: u64,
    wma: u64,
}

/// Guest absolute time now.
fn now() -> u64 {
    host::counter_at(host::host_nanoseconds())
}

/// Nanoseconds as guest absolute time units (24 MHz).
fn absolute(nanoseconds: u64) -> u64 {
    host::counter_at(nanoseconds) - host::counter_at(0)
}

/// The host's memory-pressure level as the sysctl reports it.
fn pressure() -> i32 {
    let mut level = 0i32;
    let mut size = std::mem::size_of::<i32>();
    // SAFETY: an `int` sysctl into a local.
    let status = unsafe {
        libc::sysctlbyname(
            c"kern.memorystatus_vm_pressure_level".as_ptr(),
            (&raw mut level).cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if status == 0 { level } else { 1 }
}

/// `vmdr_sampling_period_for_ring`.
fn sampling_period() -> u64 {
    match pressure() {
        PRESSURE_CRITICAL => 0,
        PRESSURE_WARN => absolute(PERIOD_PRESSURE_NS),
        _ => absolute(PERIOD_NORMAL_NS),
    }
}

/// `vmdr_round_len_to_size`: the ring's header and `count` entries, in
/// whole guest pages.
fn ring_bytes(count: u64) -> u64 {
    memory::round_page(RING_ENTRIES + count * ENTRY_BYTES).unwrap_or(0)
}

/// `vm_deferred_reclamation_buffer_allocate_internal`: the ring's address
/// and the first accounting deadline.
pub(super) fn allocate(ring: &mut Option<Ring>, len: u32, max_len: u32) -> Result<(u64, u64), u32> {
    if len == 0 || max_len == 0 || max_len < len {
        return Err(KERN_INVALID_ARGUMENT);
    }
    let bytes = ring_bytes(u64::from(max_len));
    if bytes == 0 {
        return Err(KERN_INVALID_ARGUMENT);
    }
    if bytes > MAX_BUFFER_BYTES {
        return Err(KERN_NO_SPACE);
    }
    if ring.is_some() {
        return Err(RESOURCE_SHORTAGE);
    }
    let (status, address) = memory::map_anonymous(
        0,
        bytes,
        0,
        VM_FLAGS_ANYWHERE,
        false,
        memory::Protection::READ_WRITE,
        memory::Protection::READ_WRITE,
        VM_INHERIT_COPY,
    );
    if status != 0 {
        return Err(status as u32);
    }
    *ring = Some(Ring {
        address,
        bytes,
        len: u64::from(len),
        last_sample: 0,
        wma: 0,
    });
    Ok((address, now() + sampling_period()))
}

impl Ring {
    fn read(&self, offset: u64) -> Option<u64> {
        memory::read_u64(self.address + offset)
    }

    fn write(&self, offset: u64, value: u64) -> bool {
        memory::write_u64(self.address + offset, value)
    }

    /// `reclaim_chunk`: reclaim up to `chunk` entries, stopping once
    /// `wanted` bytes are reclaimed. Returns the bytes and entries
    /// reclaimed, or the failing `kern_return_t`.
    fn chunk(&self, wanted: u64, chunk: u64) -> Result<(u64, u64), u32> {
        let (Some(busy), Some(mut head), Some(mut tail)) = (
            self.read(RING_BUSY),
            self.read(RING_HEAD),
            self.read(RING_TAIL),
        ) else {
            return Err(KERN_FAILURE);
        };
        if busy < head || busy - head > CHUNK {
            // The kernel kills the process with a reclaim-index guard.
            return Err(KERN_FAILURE);
        }
        if tail < head {
            return Err(KERN_ABORTED);
        }
        let mut count = tail - head;
        let mut busy;
        loop {
            count = count.min(chunk);
            if count == 0 {
                break;
            }
            busy = head + count;
            if !self.write(RING_BUSY, busy) {
                return Err(KERN_FAILURE);
            }
            std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
            let Some(new_tail) = self.read(RING_TAIL) else {
                return Err(KERN_FAILURE);
            };
            if new_tail >= busy {
                break;
            }
            tail = new_tail;
            if tail < head {
                self.write(RING_BUSY, head);
                return Err(KERN_ABORTED);
            }
            count = tail - head;
            if count == 0 {
                if !self.write(RING_BUSY, head) {
                    return Err(KERN_FAILURE);
                }
                break;
            }
        }
        let mut entries = Vec::with_capacity(count as usize);
        for index in head..head + count {
            let at = RING_ENTRIES + (index % self.len) * ENTRY_BYTES;
            let Some(entry) = memory::read(self.address + at, ENTRY_BYTES as usize) else {
                return Err(KERN_FAILURE);
            };
            entries.push(entry);
        }
        let (mut bytes, mut reclaimed) = (0u64, 0u64);
        for entry in &entries {
            if bytes >= wanted {
                break;
            }
            let address = u64::from_le_bytes(entry[..8].try_into().unwrap());
            let size = u64::from(u32::from_le_bytes(entry[8..12].try_into().unwrap()));
            if address != 0 && size != 0 {
                let start = memory::trunc_page(address);
                let Some(end) = address.checked_add(size).and_then(memory::round_page) else {
                    return Err(KERN_FAILURE);
                };
                match entry[12] {
                    VM_RECLAIM_DEALLOCATE => {
                        if memory::deallocate(start, end - start).is_err() {
                            return Err(KERN_FAILURE);
                        }
                    }
                    VM_RECLAIM_FREE => {
                        // SAFETY: marks the guest's own pages reusable.
                        unsafe {
                            libc::madvise(
                                start as *mut libc::c_void,
                                (end - start) as usize,
                                libc::MADV_FREE_REUSABLE,
                            );
                        }
                    }
                    _ => return Err(KERN_FAILURE),
                }
                bytes += size;
            }
            reclaimed += 1;
        }
        head += reclaimed;
        if !self.write(RING_HEAD, head) {
            return Err(KERN_FAILURE);
        }
        if self.read(RING_BUSY).is_some_and(|busy| busy > head) && !self.write(RING_BUSY, head) {
            return Err(KERN_FAILURE);
        }
        Ok((bytes, reclaimed))
    }

    /// `vmdr_reclaim_from_buffer`.
    fn reclaim(&self, wanted: u64) -> (u64, u32) {
        let mut total = 0;
        while total < wanted {
            match self.chunk(wanted - total, CHUNK) {
                Ok((bytes, entries)) => {
                    total += bytes;
                    if entries == 0 {
                        break;
                    }
                }
                Err(status) => return (total, status),
            }
        }
        (total, KERN_SUCCESS)
    }
}

/// `vm_deferred_reclamation_buffer_flush_internal`: bytes reclaimed and the
/// next deadline.
pub(super) fn flush(ring: &Option<Ring>, entries: u32) -> Result<(u64, u64), u32> {
    let Some(ring) = ring else {
        return Err(KERN_INVALID_ARGUMENT);
    };
    let (mut total, mut bytes) = (0u64, 0u64);
    let mut status = KERN_SUCCESS;
    while total < u64::from(entries) {
        let chunk = (u64::from(entries) - total).min(CHUNK);
        match ring.chunk(u64::MAX, chunk) {
            Ok((reclaimed_bytes, reclaimed)) => {
                total += reclaimed;
                bytes += reclaimed_bytes;
                if reclaimed == 0 {
                    break;
                }
            }
            // A lost race with the guest: the kernel yields and retries.
            Err(KERN_ABORTED) => continue,
            Err(failed) => {
                status = failed;
                break;
            }
        }
    }
    let deadline = now() + sampling_period();
    if status == KERN_SUCCESS {
        Ok((bytes, deadline))
    } else {
        Err(status)
    }
}

/// `vm_deferred_reclamation_buffer_resize_internal`.
pub(super) fn resize(ring: &mut Option<Ring>, len: u32) -> Result<(u64, u64), u32> {
    let Some(ring) = ring else {
        return Err(KERN_INVALID_TASK);
    };
    if len == 0 {
        return Err(KERN_INVALID_ARGUMENT);
    }
    let bytes = ring_bytes(u64::from(len));
    if bytes == 0 {
        return Err(KERN_INVALID_ARGUMENT);
    }
    if bytes > ring.bytes {
        return Err(KERN_NO_SPACE);
    }
    let mut total = 0;
    loop {
        let (reclaimed_bytes, entries) = ring.chunk(u64::MAX, CHUNK)?;
        total += reclaimed_bytes;
        if entries == 0 {
            break;
        }
    }
    ring.len = u64::from(len);
    Ok((total, now() + sampling_period()))
}

/// The process's lifetime peak physical footprint (`TASK_VM_INFO`'s
/// `ledger_phys_footprint_peak`).
fn footprint_peak() -> u64 {
    const TASK_VM_INFO: i32 = 22;
    const PEAK: usize = 168 / 4;
    unsafe extern "C" {
        fn task_info(task: u32, flavor: i32, info: *mut u32, count: *mut u32) -> i32;
    }
    let mut info = [0u32; 128];
    let mut count = info.len() as u32;
    // SAFETY: the host fills at most `count` words.
    let status = unsafe { task_info(host::task(), TASK_VM_INFO, info.as_mut_ptr(), &mut count) };
    if status != 0 || (count as usize) < PEAK + 2 {
        return 0;
    }
    u64::from(info[PEAK]) | u64::from(info[PEAK + 1]) << 32
}

/// `vm_deferred_reclamation_update_accounting_internal`: bytes reclaimed
/// and the next deadline.
pub(super) fn update_accounting(ring: &mut Option<Ring>) -> Result<(u64, u64), u32> {
    let Some(ring) = ring else {
        return Err(KERN_NOT_FOUND);
    };
    let now = now();
    let period = sampling_period();
    if period != 0 && now - ring.last_sample < period {
        return Ok((0, ring.last_sample + period));
    }
    // `vmdr_sample_working_set_locked`.
    let (Some(minimum), Some(current)) = (
        ring.read(RING_RECLAIMABLE_BYTES_MIN),
        ring.read(RING_RECLAIMABLE_BYTES),
    ) else {
        return Err(KERN_FAILURE);
    };
    if !ring.write(RING_RECLAIMABLE_BYTES_MIN, current) {
        return Err(KERN_FAILURE);
    }
    // A zero period reverts to maximally aggressive reclamation.
    let trim = if let Some(elapsed) = (now - ring.last_sample).checked_div(period) {
        let mix = |base: u64, sample: u64| {
            (WMA_BASE * base + sample * WMA_UNIT * WMA_CURRENT) / WMA_DENOMINATOR
        };
        // As the kernel computes it: each elapsed period mixes the minimum
        // into the stored average, and no elapsed period resets it.
        ring.wma = if elapsed > ABANDONMENT_THRESHOLD {
            mix(0, current)
        } else if elapsed > 0 {
            mix(ring.wma, minimum)
        } else {
            0
        };
        let unneeded = minimum.min(ring.wma / WMA_UNIT);
        let percent = match pressure() {
            PRESSURE_CRITICAL => AUTOTRIM_CRITICAL,
            PRESSURE_WARN => AUTOTRIM_PRESSURE,
            _ => AUTOTRIM_NORMAL,
        };
        let threshold = footprint_peak() * percent / 100;
        if unneeded >= memory::PAGE_BYTES && unneeded >= threshold {
            memory::round_page(unneeded).unwrap_or(unneeded)
        } else {
            0
        }
    } else {
        current
    };
    ring.last_sample = self::now();
    let deadline = ring.last_sample + period;
    let mut reclaimed = 0;
    if trim != 0 {
        let (bytes, status) = ring.reclaim(trim);
        reclaimed = bytes;
        if status != KERN_SUCCESS && status != KERN_ABORTED {
            return Err(status);
        }
    }
    Ok((reclaimed, deadline))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_flush_deallocates_the_entries_between_head_and_tail() {
        let mut ring = None;
        let (address, deadline) = allocate(&mut ring, 8, 8).unwrap();
        assert!(deadline > 0);
        assert_eq!(allocate(&mut ring, 8, 8), Err(RESOURCE_SHORTAGE));
        let region = memory::allocate(
            0,
            2 * memory::PAGE_BYTES,
            true,
            memory::Protection::READ_WRITE,
        )
        .unwrap();
        // One entry: deallocate the first page of the region.
        let mut entry = region.to_le_bytes().to_vec();
        entry.extend((memory::PAGE_BYTES as u32).to_le_bytes());
        entry.extend([VM_RECLAIM_DEALLOCATE, 0, 0, 0]);
        assert!(memory::write(address + RING_ENTRIES, &entry));
        assert!(memory::write_u64(address + RING_TAIL, 1));
        let (bytes, _) = flush(&ring, 4).unwrap();
        assert_eq!(bytes, memory::PAGE_BYTES);
        assert_eq!(memory::read_u64(address + RING_HEAD), Some(1));
        assert_eq!(memory::read_u64(address + RING_BUSY), Some(1));
        // The first page is gone (and may already be another test's): free
        // only the second.
        memory::deallocate(region + memory::PAGE_BYTES, memory::PAGE_BYTES).unwrap();
        let ring = ring.take().unwrap();
        memory::deallocate(ring.address, ring.bytes).unwrap();
    }
}
