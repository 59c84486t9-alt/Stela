//! The arm64 commpage the hosted kernel maps into the guest: the read/write
//! data page at `_COMM_PAGE64_BASE_ADDRESS`, the read-only page at
//! `_COMM_PAGE64_RO_ADDRESS` and the text page whose address the `pfz=`
//! apple string names. Both data pages are read-only to EL0, as XNU maps
//! them. Layout `osfmk/arm/cpu_capabilities.h`, contents
//! `osfmk/arm/commpage/commpage.c` `commpage_populate`.
//!
//! The text page holds the routines libplatform's `OSAtomicFifoEnqueue` and
//! `OSAtomicFifoDequeue` and the atomic TPIDR_EL0 update call through its
//! 32-entry jump table, with the contract of XNU's `commpage_asm.s`: a
//! queue head of first element, last element and a 32-bit spin lock, and
//! the lock taken, the queue changed and the lock dropped inside the
//! preemption-free zone (PFZ), which holds the jump table and those
//! helpers. A thread whose time slice ends in the zone keeps running and
//! finds X15 set; on leaving the zone the routine clears it and enters the
//! kernel through `pfz_exit` to be preempted, suspended or signalled there.
//! The rest of the page is `BRK #666`, XNU's filler.
use super::{
    features::{Identification, cpu_capabilities},
    hardware::Hardware,
    memory::{self, PAGE_BYTES, Protection},
};
use anyhow::{Result, ensure};

pub const DATA_ADDRESS: u64 = 0xf_ffff_c000;
pub const READ_ONLY_ADDRESS: u64 = 0xf_ffff_4000;
/// Inside XNU's commpage nesting region `[0xfc0000000, 0x1000000000)`,
/// where XNU places the randomized text page.
pub const TEXT_ADDRESS: u64 = 0xf_ffff_8000;

const SIGNATURE: usize = 0x000;
const SIGNATURE_STRING: &[u8] = b"commpage 64-bit";
const CPU_CAPABILITIES64: usize = 0x010;
const VERSION: usize = 0x01e;
const THIS_VERSION: u16 = 3;
const CPU_CAPABILITIES: usize = 0x020;
const NCPUS: usize = 0x022;
const USER_PAGE_SHIFT_32: usize = 0x024;
const USER_PAGE_SHIFT_64: usize = 0x025;
const CACHE_LINESIZE: usize = 0x026;
const CPU_CLUSTERS: usize = 0x02f;
const ACTIVE_CPUS: usize = 0x034;
const PHYSICAL_CPUS: usize = 0x035;
const LOGICAL_CPUS: usize = 0x036;
const KERNEL_PAGE_SHIFT: usize = 0x037;
const MEMORY_SIZE: usize = 0x038;
const CPUFAMILY: usize = 0x080;
const DEV_FIRM: usize = 0x084;
const TIMEBASE_OFFSET: usize = 0x088;
const USER_TIMEBASE: usize = 0x090;
const CONT_HWCLOCK: usize = 0x091;
const CONT_TIMEBASE: usize = 0x098;
const BOOTTIME_USEC: usize = 0x0a0;
const CONT_HW_TIMEBASE: usize = 0x0a8;
const APPROX_TIME_SUPPORTED: usize = 0x0c8;
const KDEBUG_ENABLE: usize = 0x100;
const REMOTETIME_PARAMS: usize = 0x148;
const DYLD_FLAGS: usize = 0x160;
const CPU_TO_CLUSTER: usize = 0x200;
/// `USER_TIMEBASE_NOSPEC_APPLE`: EL0 reads Apple's non-speculative
/// ACNTVCT_EL0 (`HAS_ACNTVCT`, as on every Apple-silicon Mac).
const USER_TIMEBASE_NOSPEC_APPLE: u8 = 3;
/// `BT_RESET_SENTINEL_TS`: no bridge remote-time parameters.
const BT_RESET_SENTINEL_TS: u64 = u64::MAX;
/// The 16 KiB user and kernel pages of Apple-silicon macOS.
const SIXTEENK_PAGE_SHIFT: u8 = 14;
/// `BRK #666`.
const BRK_666: u32 = 0xd420_5340;

/// The time state the data page carries, in guest counter ticks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Time {
    /// `mach_continuous_time() - mach_absolute_time()`.
    pub continuous_offset: u64,
    pub boot_microseconds: u64,
}

/// The data and read-only pages' bytes.
pub fn data_page(hardware: &Hardware, identification: &Identification, time: Time) -> Vec<u8> {
    let mut page = vec![0u8; PAGE_BYTES as usize];
    let mut put = |offset: usize, bytes: &[u8]| {
        page[offset..offset + bytes.len()].copy_from_slice(bytes);
    };
    let cpus = hardware.cpus();
    let capabilities = cpu_capabilities(identification, hardware.cache_line, cpus);
    put(SIGNATURE, SIGNATURE_STRING);
    put(CPU_CAPABILITIES64, &capabilities.to_le_bytes());
    put(VERSION, &THIS_VERSION.to_le_bytes());
    put(CPU_CAPABILITIES, &(capabilities as u32).to_le_bytes());
    put(NCPUS, &[cpus]);
    put(USER_PAGE_SHIFT_32, &[SIXTEENK_PAGE_SHIFT]);
    put(USER_PAGE_SHIFT_64, &[SIXTEENK_PAGE_SHIFT]);
    put(CACHE_LINESIZE, &(hardware.cache_line as u16).to_le_bytes());
    put(CPU_CLUSTERS, &[hardware.clusters.len() as u8]);
    put(ACTIVE_CPUS, &[cpus]);
    put(PHYSICAL_CPUS, &[cpus]);
    put(LOGICAL_CPUS, &[cpus]);
    put(KERNEL_PAGE_SHIFT, &[SIXTEENK_PAGE_SHIFT]);
    put(MEMORY_SIZE, &hardware.memory_bytes.to_le_bytes());
    put(CPUFAMILY, &hardware.cpu_family.to_le_bytes());
    put(DEV_FIRM, &0u32.to_le_bytes());
    put(TIMEBASE_OFFSET, &0u64.to_le_bytes());
    put(USER_TIMEBASE, &[USER_TIMEBASE_NOSPEC_APPLE]);
    put(CONT_HWCLOCK, &[0]);
    put(CONT_TIMEBASE, &time.continuous_offset.to_le_bytes());
    put(BOOTTIME_USEC, &time.boot_microseconds.to_le_bytes());
    put(CONT_HW_TIMEBASE, &time.continuous_offset.to_le_bytes());
    put(APPROX_TIME_SUPPORTED, &[0]);
    put(KDEBUG_ENABLE, &0u32.to_le_bytes());
    put(REMOTETIME_PARAMS, &BT_RESET_SENTINEL_TS.to_le_bytes());
    put(DYLD_FLAGS, &0u64.to_le_bytes());
    put(CPU_TO_CLUSTER, &hardware.cpu_clusters());
    page
}

/// The jump table's used entries (`cpu_capabilities.h`
/// `_COMM_PAGE_TEXT_ATOMIC_ENQUEUE`, `_DEQUEUE` and the TPIDR_EL0 update):
/// branches to the routines below.
const JUMP_TABLE: [u32; 3] = [
    0x1400_0044, // 0x000: b enqueue
    0x1400_0053, // 0x004: b dequeue
    0x1400_0063, // 0x008: b tpidr_update
];
/// Where the routines start, past the jump table.
const ROUTINES_OFFSET: u64 = 0x80;
/// The end of the preemption-free zone: the first preemptible routine.
const PREEMPTIBLE_OFFSET: u64 = 0x110;

/// The routines, from [`ROUTINES_OFFSET`]. The helpers before
/// [`PREEMPTIBLE_OFFSET`] run in the zone, with no backward branch, using
/// only X10 and X11.
const ROUTINES: &[u32] = &[
    // trylock_enqueue(x0 head, x1 element, x2 link offset, x3 lock):
    // x0 = 0, or -1 while the lock is held.
    0x5280000a, // 0x080: mov w10, #0x0
    0x5280002b, // 0x084: mov w11, #0x1
    0x88ea7c6b, // 0x088: casa w10, w11, [x3]
    0x3500014a, // 0x08c: cbnz w10, 0xb4
    0xf940040a, // 0x090: ldr x10, [x0, #0x8]
    0xb500006a, // 0x094: cbnz x10, 0xa0
    0xf9000001, // 0x098: str x1, [x0]
    0x14000002, // 0x09c: b 0xa4
    0xf8226941, // 0x0a0: str x1, [x10, x2]
    0xf9000401, // 0x0a4: str x1, [x0, #0x8]
    0x889ffc7f, // 0x0a8: stlr wzr, [x3]
    0xd2800000, // 0x0ac: mov x0, #0x0
    0xd65f03c0, // 0x0b0: ret
    0x92800000, // 0x0b4: mov x0, #-0x1
    0xd65f03c0, // 0x0b8: ret
    // trylock_dequeue(x0 head, x1 link offset, x2 lock): x0 = the old head
    // (NULL for an empty queue), or -1 while the lock is held.
    0x5280000a, // 0x0bc: mov w10, #0x0
    0x5280002b, // 0x0c0: mov w11, #0x1
    0x88ea7c4b, // 0x0c4: casa w10, w11, [x2]
    0x3500016a, // 0x0c8: cbnz w10, 0xf4
    0xf940000a, // 0x0cc: ldr x10, [x0]
    0xb40000ca, // 0x0d0: cbz x10, 0xe8
    0xf861694b, // 0x0d4: ldr x11, [x10, x1]
    0xb500004b, // 0x0d8: cbnz x11, 0xe0
    0xf900041f, // 0x0dc: str xzr, [x0, #0x8]
    0xf821695f, // 0x0e0: str xzr, [x10, x1]
    0xf900000b, // 0x0e4: str x11, [x0]
    0xaa0a03e0, // 0x0e8: mov x0, x10
    0x889ffc5f, // 0x0ec: stlr wzr, [x2]
    0xd65f03c0, // 0x0f0: ret
    0x92800000, // 0x0f4: mov x0, #-0x1
    0xd65f03c0, // 0x0f8: ret
    // tpidr_helper(x0 upper bits): TPIDR_EL0 bits 12 and up from x0, the
    // CPU number below kept (`MACHDEP_TPIDR_CPU_DATA_COUNT`).
    0xd53bd041, // 0x0fc: mrs x1, TPIDR_EL0
    0xd34cfc00, // 0x100: lsr x0, x0, #12
    0xb374cc01, // 0x104: bfi x1, x0, #12, #52
    0xd51bd041, // 0x108: msr TPIDR_EL0, x1
    0xd65f03c0, // 0x10c: ret
    // enqueue(x0 head, x1 element, x2 link offset): the lock at head + 16.
    0xa9bf7bfd, // 0x110: stp x29, x30, [sp, #-0x10]!
    0x910003fd, // 0x114: mov x29, sp
    0xf822683f, // 0x118: str xzr, [x1, x2]
    0xaa1f03ef, // 0x11c: mov x15, xzr
    0x91004003, // 0x120: add x3, x0, #0x10
    0xaa0003ec, // 0x124: mov x12, x0
    0x97ffffd6, // 0x128: bl trylock_enqueue
    0xaa0003ed, // 0x12c: mov x13, x0
    0xaa0c03e0, // 0x130: mov x0, x12
    0x9400001e, // 0x134: bl take_preemption
    0xb400008d, // 0x138: cbz x13, 0x148
    0xaa0303ee, // 0x13c: mov x14, x3
    0x94000024, // 0x140: bl backoff
    0x17fffff8, // 0x144: b 0x124
    0xa8c17bfd, // 0x148: ldp x29, x30, [sp], #0x10
    0xd65f03c0, // 0x14c: ret
    // dequeue(x0 head, x1 link offset): x0 the element taken, or NULL.
    0xa9bf7bfd, // 0x150: stp x29, x30, [sp, #-0x10]!
    0x910003fd, // 0x154: mov x29, sp
    0xaa1f03ef, // 0x158: mov x15, xzr
    0x91004002, // 0x15c: add x2, x0, #0x10
    0xaa0003ec, // 0x160: mov x12, x0
    0x97ffffd6, // 0x164: bl trylock_dequeue
    0xaa0003ed, // 0x168: mov x13, x0
    0xaa0c03e0, // 0x16c: mov x0, x12
    0x9400000f, // 0x170: bl take_preemption
    0xb10005bf, // 0x174: cmn x13, #0x1
    0x54000081, // 0x178: b.ne 0x188
    0xaa0203ee, // 0x17c: mov x14, x2
    0x94000014, // 0x180: bl backoff
    0x17fffff7, // 0x184: b 0x160
    0xaa0d03e0, // 0x188: mov x0, x13
    0xa8c17bfd, // 0x18c: ldp x29, x30, [sp], #0x10
    0xd65f03c0, // 0x190: ret
    // tpidr_update(x0 upper bits).
    0xa9bf7bfd, // 0x194: stp x29, x30, [sp, #-0x10]!
    0x910003fd, // 0x198: mov x29, sp
    0x97ffffd8, // 0x19c: bl tpidr_helper
    0x94000003, // 0x1a0: bl take_preemption
    0xa8c17bfd, // 0x1a4: ldp x29, x30, [sp], #0x10
    0xd65f03c0, // 0x1a8: ret
    // take_preemption: with X15 set in the zone, clear it and call
    // `pfz_exit` (Mach trap 58).
    0xb400010f, // 0x1ac: cbz x15, 0x1cc
    0xaa1f03ef, // 0x1b0: mov x15, xzr
    0xa9bf07e0, // 0x1b4: stp x0, x1, [sp, #-0x10]!
    0xa9bf0fe2, // 0x1b8: stp x2, x3, [sp, #-0x10]!
    0x92800730, // 0x1bc: mov x16, #-0x3a
    0xd4001001, // 0x1c0: svc #0x80
    0xa8c10fe2, // 0x1c4: ldp x2, x3, [sp], #0x10
    0xa8c107e0, // 0x1c8: ldp x0, x1, [sp], #0x10
    0xd65f03c0, // 0x1cc: ret
    // backoff(x14 lock): return once the lock reads free.
    0x885f7dcb, // 0x1d0: ldxr w11, [x14]
    0x3400006b, // 0x1d4: cbz w11, 0x1e0
    0xd503205f, // 0x1d8: wfe
    0x17fffffd, // 0x1dc: b 0x1d0
    0xd5033f5f, // 0x1e0: clrex
    0xd65f03c0, // 0x1e4: ret
];

/// The text page's preemption-free zone (`commpage_is_in_pfz64`): the jump
/// table and the helpers that hold the queue lock.
const PREEMPTION_FREE_ZONE: core::ops::Range<u64> = TEXT_ADDRESS..TEXT_ADDRESS + PREEMPTIBLE_OFFSET;

/// Whether a thread at `pc` is inside the preemption-free zone, so its
/// time slice, suspension and signals wait for the zone's exit.
pub fn preemption_free(pc: u64) -> bool {
    PREEMPTION_FREE_ZONE.contains(&pc)
}

/// The register a zone routine reads on leaving the zone: set when the
/// kernel deferred a preemption there (`SS64_X15` in `locore.s`).
pub const DEFERRED_PREEMPTION_REGISTER: usize = 15;

pub fn text_page() -> Vec<u8> {
    let mut words = vec![BRK_666; PAGE_BYTES as usize / 4];
    words[..JUMP_TABLE.len()].copy_from_slice(&JUMP_TABLE);
    let start = ROUTINES_OFFSET as usize / 4;
    words[start..start + ROUTINES.len()].copy_from_slice(ROUTINES);
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

/// Map the three pages at their fixed addresses, read-only to the guest.
pub fn map(data: &[u8]) -> Result<()> {
    for (address, bytes, protection) in [
        (DATA_ADDRESS, data.to_vec(), Protection::READ),
        (READ_ONLY_ADDRESS, data.to_vec(), Protection::READ),
        (TEXT_ADDRESS, text_page(), Protection::READ_EXECUTE),
    ] {
        ensure!(bytes.len() == PAGE_BYTES as usize, "commpage size");
        let at = memory::allocate(address, PAGE_BYTES, false, Protection::READ_WRITE)?;
        ensure!(at == address, "commpage placed at {at:#x}");
        ensure!(memory::write(address, &bytes), "commpage write");
        memory::protect(address, PAGE_BYTES, protection)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::Chip;

    #[test]
    fn data_page_carries_the_declared_fields() {
        let hardware = Hardware::of(Chip::AppleM2, 16 << 30).unwrap();
        let page = data_page(
            &hardware,
            &Identification(&[]),
            Time {
                continuous_offset: 5,
                boot_microseconds: 7,
            },
        );
        assert_eq!(&page[..15], SIGNATURE_STRING);
        assert_eq!(page[NCPUS], 8);
        assert_eq!(page[USER_PAGE_SHIFT_64], 14);
        assert_eq!(
            u32::from_le_bytes(page[CPUFAMILY..CPUFAMILY + 4].try_into().unwrap()),
            CPUFAMILY_ARM_BLIZZARD_AVALANCHE_FOR_TEST
        );
        assert_eq!(page[CPU_TO_CLUSTER + 7], 1);
        assert_eq!(page[BOOTTIME_USEC], 7);
    }

    #[test]
    fn the_text_page_jumps_to_its_routines_and_the_zone_only_branches_forward() {
        const JUMP_TABLE_ENTRIES: usize = 32;
        let text = text_page();
        let word = |offset: usize| u32::from_le_bytes(text[offset..offset + 4].try_into().unwrap());
        // `B imm26` from `offset`.
        let target = |offset: usize| {
            let imm = (word(offset) & 0x03ff_ffff) as i32;
            (offset as i64 + i64::from((imm << 6) >> 4)) as u64
        };
        assert_eq!(target(0), PREEMPTIBLE_OFFSET);
        assert_eq!(target(4), 0x150);
        assert_eq!(target(8), 0x194);
        assert!((JUMP_TABLE.len()..JUMP_TABLE_ENTRIES).all(|entry| word(entry * 4) == BRK_666));
        let end = ROUTINES_OFFSET as usize + ROUTINES.len() * 4;
        assert!(
            (end..PAGE_BYTES as usize)
                .step_by(4)
                .all(|at| word(at) == BRK_666)
        );
        // CBZ/CBNZ and B in the zone's helpers: forward only.
        for at in (ROUTINES_OFFSET as usize..PREEMPTIBLE_OFFSET as usize).step_by(4) {
            let instruction = word(at);
            if instruction & 0x7e00_0000 == 0x3400_0000 {
                assert_eq!(instruction & 0x0080_0000, 0, "{at:#x}");
            }
            if instruction & 0xfc00_0000 == 0x1400_0000 {
                assert!(target(at) > at as u64, "{at:#x}");
            }
        }
        assert!(preemption_free(TEXT_ADDRESS + 0x88));
        assert!(!preemption_free(TEXT_ADDRESS + PREEMPTIBLE_OFFSET));
    }

    const CPUFAMILY_ARM_BLIZZARD_AVALANCHE_FOR_TEST: u32 =
        super::super::hardware::CPUFAMILY_ARM_BLIZZARD_AVALANCHE;
}
