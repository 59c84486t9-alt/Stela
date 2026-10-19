//! The arm64 commpage the hosted kernel maps into the guest: the read/write
//! data page at `_COMM_PAGE64_BASE_ADDRESS`, the read-only page at
//! `_COMM_PAGE64_RO_ADDRESS` and the text page whose address the `pfz=`
//! apple string names. Both data pages are read-only to EL0, as XNU maps
//! them. Layout `osfmk/arm/cpu_capabilities.h`, contents
//! `osfmk/arm/commpage/commpage.c` `commpage_populate`.
//!
//! The text page holds XNU's preemption-free-zone routines for
//! `OSAtomicFifoEnqueue`/`Dequeue` and the atomic TPIDR_EL0 update. They are
//! not provided: the page is filled with `BRK #666`, the filler XNU puts past
//! its routines, so a call stops explicitly instead of running wrong code.
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

pub fn text_page() -> Vec<u8> {
    BRK_666
        .to_le_bytes()
        .iter()
        .copied()
        .cycle()
        .take(PAGE_BYTES as usize)
        .collect()
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
        let text = text_page();
        assert_eq!(&text[..4], &BRK_666.to_le_bytes());
    }

    const CPUFAMILY_ARM_BLIZZARD_AVALANCHE_FOR_TEST: u32 =
        super::super::hardware::CPUFAMILY_ARM_BLIZZARD_AVALANCHE;
}
