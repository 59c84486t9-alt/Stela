//! The per-chip facts of iBoot's DeviceTree hand-off that the boot bundle
//! (`stela_loader::handoff`, `docs/research/iboot-handoff.md`) writes in
//! iBoot's place.
//!
//! Every fact was read from the 26A434 `Firmware/all_flash/LLB.<board>` and
//! `iBoot.<board>` RELEASE payloads of one board per ApChipID ([`Evidence`];
//! offsets are payload file offsets, the payload running at
//! 0x9_0000_0000 + offset):
//!
//! - Carveout 1, the hand-off region `/chosen iboot-handoff` names, is placed
//!   at build time: both stages' carveout tables (64-byte records, 40-byte on
//!   the T8103: base, 0, size, then the region ID in the low 16 bits) give it
//!   the DRAM base and 16 KiB on every SoC ([`HANDOFF_REGION`]).
//! - Carveout 98, the panic region `/pram reg` and `/chosen
//!   embedded-panic-log-size` name, is sized at run time by LLB. Its table
//!   record holds `~0`; LLB's window walker ([`Evidence::llb_window_walker`],
//!   J473 0xe0aa4, called with a 2 MiB window at 0x22d8) packs the regions its
//!   4-entry list names ([`Evidence::llb_window`], J473 0x1aa848: regions 0xc,
//!   0x62, 0x60 and 0x61, 0x18 bytes apart, tagged 0x46554e4b twice, 0x44434f53
//!   and 0x41324641) behind a 24-byte header each and an 8-byte trailer, skips 0xc (no table has it), and gives
//!   region 98 the rest rounded down to iBoot's page size (parameter 0x1600,
//!   16 KiB). With regions 0x60 and 0x61 at 256 KiB and 208 KiB in every table
//!   that is 0x188000 bytes ([`PANIC_REGION_BYTES`]).
//! - The boot CPU's `clock-frequency`, `memory-frequency`, `bus-frequency`,
//!   `peripheral-frequency`, `fixed-frequency` and `timebase-frequency` are
//!   iBoot's clock getter at indices 0, 2, 3, 1, 4 and 5 (J473 0x397f0..
//!   0x398f0 calling 0x5a928), which on every SoC returns the 24 MHz reference
//!   (parameter 0x1500, or the literal 0x16e3600 on the M1 and M2 families;
//!   [`BOOT_CLOCK_HZ`]).
//! - `/arm-io usbphy-frequency` is the same getter at an index it does not
//!   define (J473 0x107 at 0x39ac4), which returns 0 on every SoC
//!   ([`USB_PHY_HZ`]). No 26A434 Mac DeviceTree has an `audio-complex`, so
//!   iBoot writes no `ncoref-frequency`.
//! - `/chosen dram-type` is a literal string (J473 0x1c767b through 0x3ada4);
//!   `dram-vendor-id` is the top byte of the DRAM scratch register
//!   0x2_3b73_0024 LLB fills from the LPDDR mode registers (0x3ae00), and
//!   `dram-vendor` its name (0x125798: 1 Samsung, 6 Hynix, 0xff Micron).
//! - `/arm-io chip-revision` is fused (0x40494: fuse 0x2_3d2c_8060 bits
//!   27..29 and 30..32), and its zero test (0x3d688) picks the `-a0`
//!   `iop-pmp-nub` sensor tables over `-v1`/`-v2` (0x3d770).
//! - `socd-trace-ram reg` is a buffer the SMC firmware owns: both stages read
//!   its base and size from SMC keys (LLB 0xee4bc, iBoot 0x106cc4, SMC read
//!   command 0x10) and iBoot writes a window of it (0x107010..0x107080).
//!
//! Emulated-die choices, not readings of an Apple part: the DRAM identity
//! ([`DRAM_VENDOR`]) and the chip revision ([`CHIP_REVISION`]).
use crate::Result;

/// One carveout iBoot places at build time: its region ID and its offset from
/// the SoC's DRAM base and size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Carveout {
    pub id: u16,
    pub dram_offset: u64,
    pub bytes: u64,
}

/// Carveout 1, `/chosen iboot-handoff`: the first 16 KiB of DRAM.
pub const HANDOFF_REGION: Carveout = Carveout {
    id: 1,
    dram_offset: 0,
    bytes: 0x4000,
};

/// Carveout 98's region ID.
pub const PANIC_REGION_ID: u16 = 0x62;
/// The window LLB packs the panic region into.
pub const PANIC_WINDOW_BYTES: u64 = 2 << 20;
/// The other regions in that window that every table sizes, 0x60 and 0x61.
pub const PANIC_WINDOW_MEMBERS: [(u16, u64); 2] = [(0x60, 0x40000), (0x61, 0x34000)];
/// The header LLB places before each region of the window, and its trailer.
const WINDOW_HEADER_BYTES: u64 = 0x18;
const WINDOW_TRAILER_BYTES: u64 = 8;
/// iBoot's page size, parameter 0x1600 in both stages.
pub const IBOOT_PAGE_BYTES: u64 = 0x4000;

/// Carveout 98's size: the window less its other regions, one header per
/// region (the panic region's included) and the trailer, rounded down to a
/// page.
pub const PANIC_REGION_BYTES: u64 = {
    let mut used = WINDOW_TRAILER_BYTES + WINDOW_HEADER_BYTES;
    let mut index = 0;
    while index < PANIC_WINDOW_MEMBERS.len() {
        used += PANIC_WINDOW_MEMBERS[index].1 + WINDOW_HEADER_BYTES;
        index += 1;
    }
    (PANIC_WINDOW_BYTES - used) / IBOOT_PAGE_BYTES * IBOOT_PAGE_BYTES
};

/// The SoC reference clock iBoot reports for every boot CPU clock.
pub const BOOT_CLOCK_HZ: u64 = 24_000_000;
/// What iBoot writes to `/arm-io usbphy-frequency`.
pub const USB_PHY_HZ: u32 = 0;

/// The DRAM identity the emulated die presents: JEDEC LPDDR manufacturer ID
/// 1 (mode register 5), which iBoot names Samsung. Stela's choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DramVendor {
    pub id: u32,
    pub name: &'static str,
}

pub const DRAM_VENDOR: DramVendor = DramVendor {
    id: 1,
    name: "Samsung",
};

/// The `/arm-io chip-revision` the emulated die reports: 0, the revision
/// whose tunings the cluster rows program (the T8112's revision 0 DVMR list)
/// and the IPSW template's value.
pub const CHIP_REVISION: u32 = 0;

/// The SMC keys whose values place the SoC debug trace buffer: base, size.
pub const SOCD_TRACE_KEYS: [&str; 2] = ["LGDA", "LGDS"];

/// Where a board's facts were read: the board and, in its LLB, the window
/// list and walker and, in its iBoot, the clock getter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Evidence {
    pub board: &'static str,
    pub llb_window: u32,
    pub llb_window_walker: u32,
    pub iboot_clock_getter: u32,
}

/// One SoC's hand-off facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Handoff {
    pub chip_id: u32,
    /// `/chosen dram-type`.
    pub dram_type: &'static str,
    /// The `iop-pmp-nub` sensor-table suffix [`CHIP_REVISION`] selects:
    /// `Ok(None)` when the board's tables have no variants, `Err` when iBoot's
    /// selection rule is not established.
    pub pmp_variant: Result<Option<&'static str>, &'static str>,
    pub evidence: Evidence,
}

const fn row(
    chip_id: u32,
    dram_type: &'static str,
    pmp_variant: Result<Option<&'static str>, &'static str>,
    evidence: (&'static str, u32, u32, u32),
) -> Handoff {
    Handoff {
        chip_id,
        dram_type,
        pmp_variant,
        evidence: Evidence {
            board: evidence.0,
            llb_window: evidence.1,
            llb_window_walker: evidence.2,
            iboot_clock_getter: evidence.3,
        },
    }
}

const LPDDR4: &str = "LPDDR4";
const LPDDR5: &str = "LPDDR5";
/// The T8122's `iop-pmp-nub` carries `temp-sensor-n3` tables beside the
/// plain ones; which one iBoot keeps is not traced.
const N3_UNTRACED: &str = "iBoot's choice between the T8122 temp-sensor and temp-sensor-n3 \
    tables is not traced";

/// The rows, one per ApChipID of the `machine::soc` SoC rows.
const HANDOFFS: [Handoff; 20] = [
    row(
        0x8103,
        LPDDR4,
        Ok(None),
        ("j274", 0x135268, 0x92140, 0x47f7c),
    ),
    row(
        0x6000,
        LPDDR5,
        Ok(None),
        ("j314s", 0x1b53f8, 0xdef6c, 0x5317c),
    ),
    row(
        0x6001,
        LPDDR5,
        Ok(None),
        ("j314c", 0x1d17c8, 0xe2a0c, 0x531a4),
    ),
    row(
        0x6002,
        LPDDR5,
        Ok(None),
        ("j375d", 0x1fa578, 0xf7b80, 0x533cc),
    ),
    row(
        0x8112,
        LPDDR5,
        Ok(Some("-a0")),
        ("j473", 0x1aa848, 0xe0aa4, 0x5a928),
    ),
    row(
        0x6020,
        LPDDR5,
        Ok(None),
        ("j414s", 0x1a74d8, 0xd8cf0, 0x55ec4),
    ),
    row(
        0x6021,
        LPDDR5,
        Ok(None),
        ("j414c", 0x1b8348, 0xdbf10, 0x56014),
    ),
    row(
        0x6022,
        LPDDR5,
        Ok(None),
        ("j180d", 0x1de898, 0xe6080, 0x57bb8),
    ),
    row(
        0x8122,
        LPDDR5,
        Err(N3_UNTRACED),
        ("j504", 0x1cf6c8, 0xf1db0, 0x59c3c),
    ),
    row(
        0x6030,
        LPDDR5,
        Ok(None),
        ("j514s", 0x1db818, 0xf17f0, 0x59f58),
    ),
    row(
        0x6031,
        LPDDR5,
        Ok(None),
        ("j514c", 0x2189f8, 0x112010, 0x66fa4),
    ),
    row(
        0x6034,
        LPDDR5,
        Ok(None),
        ("j514m", 0x218178, 0x1113b0, 0x66db8),
    ),
    row(
        0x6032,
        LPDDR5,
        Ok(None),
        ("j575d", 0x262e88, 0x1351a0, 0x693e8),
    ),
    row(
        0x8132,
        LPDDR5,
        Ok(None),
        ("j604", 0x291838, 0x11cf94, 0x64ba4),
    ),
    row(
        0x6040,
        LPDDR5,
        Ok(None),
        ("j614s", 0x274d68, 0x13f054, 0x6a844),
    ),
    row(
        0x6041,
        LPDDR5,
        Ok(None),
        ("j614c", 0x2b8d58, 0x15b134, 0x6adc0),
    ),
    row(
        0x8140,
        LPDDR5,
        Ok(None),
        ("j700", 0x2a94f8, 0x1593f4, 0x631a8),
    ),
    row(
        0x8142,
        LPDDR5,
        Ok(None),
        ("j704", 0x2ce2f8, 0x12d394, 0x6d374),
    ),
    row(
        0x6050,
        LPDDR5,
        Ok(None),
        ("j714s", 0x2fcbc8, 0x179654, 0x7cdd4),
    ),
    row(
        0x8152,
        LPDDR5,
        Ok(None),
        ("j873g", 0x35a1c8, 0x182874, 0x70000),
    ),
];

/// The hand-off facts of the SoC with `chip_id`.
pub fn handoff(chip_id: u32) -> Option<&'static Handoff> {
    HANDOFFS.iter().find(|row| row.chip_id == chip_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_panic_region_fills_its_window_to_a_page() {
        assert_eq!(PANIC_REGION_BYTES, 0x18_8000);
        assert!(PANIC_REGION_BYTES.is_multiple_of(IBOOT_PAGE_BYTES));
        let members: u64 = PANIC_WINDOW_MEMBERS.iter().map(|&(_, bytes)| bytes).sum();
        assert!(PANIC_REGION_BYTES + members < PANIC_WINDOW_BYTES);
        assert!(PANIC_WINDOW_BYTES - members - PANIC_REGION_BYTES < IBOOT_PAGE_BYTES + 0x100);
    }

    #[test]
    fn every_soc_row_has_its_handoff_facts() {
        for soc in super::super::SOCS {
            let row = handoff(soc.chip_id).expect("a hand-off row");
            assert!(row.dram_type.starts_with("LPDDR"));
            assert!(row.evidence.board.starts_with('j'));
        }
        assert_eq!(handoff(0x8112).unwrap().pmp_variant, Ok(Some("-a0")));
        assert_eq!(handoff(0x8103).unwrap().dram_type, LPDDR4);
        assert!(handoff(0x8122).unwrap().pmp_variant.is_err());
        assert!(handoff(0x8101).is_none());
    }
}
