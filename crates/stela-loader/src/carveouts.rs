//! iBoot's DRAM carveouts: memory iBoot reserves for coprocessors and the
//! monitors before SPTM starts. Each carveout is published in
//! `/chosen/carveout-memory-map` as `region-id-<id>`, a u64 base and a u64
//! size, and stays outside the managed range `boot_args` describes
//! (`physBase` to `physBase + memSize`): SPTM's
//! `iommu_bootstrap_register_io_range` refuses a managed page, an unaligned
//! or empty range, or one of 64K pages or more.
//!
//! The tables come from the original 26A434 iBoot of every board
//! (`docs/research/iboot-handoff.md#carveout-tables` gives each board's table
//! offset, record count and hash). Each iBoot names its table once, in a
//! descriptor that returns its bounds and record count (J473 file offset
//! 0x3b22c, J314s 0x3c7e8), and the region lookup the sgx setup calls compares
//! the region ID at +0x18 at the table's stride. Records are 64 bytes, 40 on
//! the T8103: base `~0` until placed, size at +0x10 (`~0` until sized at run
//! time), region ID at +0x18 and attributes at +0x1a. Every board of one
//! ApChipID carries the same fixed-size records, and the T6040 and T6041 share
//! theirs, so a table belongs to its ApChipIDs ([`FAMILIES`]). Only ordinary
//! fixed-size records are listed: unplaced, sized, nonzero and with attributes
//! 0x8000_0009. Run-time sizes, empty entries, absolute original ranges and
//! the fixed-size records with other attributes (each table's
//! [`Family::special`]) stay absent, except the panic region below. iBoot's placement policy
//! is not established, so Stela places carveouts back to back from the DRAM
//! base and starts the managed range at the next 32 MiB boundary, the block
//! size of XNU's physical aperture.
//!
//! The panic region, carveout 98, is XNU's panic buffer, and every SoC with
//! hand-off facts gets it ([`PANIC`]; LLB sizes it alike on every SoC,
//! `machine::board::PANIC_REGION_BYTES`). iBoot writes it as `/pram reg` (base,
//! size; 26A434 J473 iBoot 0x23028 calling 0x24d70, only when `/pram`
//! exists) and its size as the u32 `/chosen embedded-panic-log-size`
//! (0x24420). 26A434 XNU's `check_for_panic_log` (kernel 0xfffffe000c4d8790,
//! called from `PE_create_console` at 0xfffffe000c52d3ac) needs both: it maps
//! `reg[0]` write-combined for `embedded-panic-log-size` bytes as
//! `gPanicBase` (0xfffffe000ca640b0) and `panic_info` (0xfffffe000ca640b8),
//! and `debug_log_init` puts the panic log 0x331 bytes in, past the panic
//! header. Without them `panic_info` stays NULL and the panic path faults
//! writing the header (`docs/research/iboot-handoff.md#panic-region`).
//!
//! The GPU's UAT regions come from four of them. iBoot's sgx setup (26A434
//! iBoot `0xd9328`) looks up regions 8, 0x34, 0xd9 and 0x38 and writes their
//! bases and sizes to `/arm-io/sgx`, which SPTM's `uat_bootstrap_parse_dt`
//! requires: the TTBAT (`gpu-region`), the ASC carveout
//! (`gfx-shared-region`), one page of shared TTBR1 level-2 table
//! (`gfx-shared-l2-region`) and the firmware handoff (`gfx-handoff`). SPTM
//! builds the TTBR1 root and the handoff header itself. iBoot also writes the
//! AGX firmware's loaded data segments (`gfx-data*`), `gptbat-ready`,
//! `ttbat-phys-addr-base` and `rtkit-private-vm-region-*`, which need the
//! firmware loaded and the GPU's MMU programmed, so they stay absent.
use crate::Result;
use crate::apple_device_tree::DeviceTree;
use crate::kernel_collection::PAGE_BYTES;
use alloc::{format, string::String, vec::Vec};
use stela_contracts::{refuse, require};
pub use stela_formats::boot_bundle::schema::Placed;
use stela_soc_data::board;

pub const MEMORY_MAP: &str = "/chosen/carveout-memory-map";
/// iBoot's loaded-object state, which holds the manifests
/// `/chosen/boot-object-manifests` names: 26A434 J473 iBEC looks the region
/// up (0xe7fc4), checks its header (magic 0x686d6674), and its publisher
/// (0xe8c2c) gives each record's manifest as an address inside it. Being a
/// carveout, it lies outside the memory SPTM types for XNU.
pub const LOADED_OBJECTS: u16 = 0x4c;
const SGX: &str = "/arm-io/sgx";
/// The node whose `reg` names the panic region.
pub const PRAM: &str = "/pram";
/// The `/chosen` u32 that bounds XNU's panic buffer.
pub const PANIC_LOG_SIZE: &str = "embedded-panic-log-size";
/// XNU maps its physical aperture in 32 MiB blocks (m1n1 `_write_boot_args`
/// offsets `virtBase` by `physBase` modulo this).
pub const MANAGED_ALIGNMENT: u64 = 32 << 20;

/// One fixed-size entry of iBoot's carveout table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Carveout {
    pub id: u16,
    pub bytes: u64,
}

const fn carveout(id: u16, bytes: u64) -> Carveout {
    Carveout { id, bytes }
}

/// Carveout 98, the panic region, at the size LLB gives it on every SoC.
pub const PANIC: Carveout = carveout(board::PANIC_REGION_ID, board::PANIC_REGION_BYTES);

/// `id: bytes` pairs as ordinary fixed-size [`Carveout`]s, in table order.
macro_rules! table {
    ($($id:literal: $bytes:literal),* $(,)?) => {
        &[$(carveout($id, $bytes)),*]
    };
}

/// One iBoot carveout table: the ApChipIDs whose iBoots carry it, its
/// ordinary fixed-size records in table order, and the IDs of its fixed-size
/// unplaced records whose attributes differ, which stay absent.
pub struct Family {
    pub chips: &'static [u32],
    pub fixed: &'static [Carveout],
    pub special: &'static [u16],
}

/// iBoot.j274 table 0x14e5c8, 100 records: 18 ordinary fixed-size.
const T8103: &[Carveout] = table![
    0x51: 0x40000, 0x7: 0x4000, 0x8: 0x4000, 0x34: 0x40000, 0xd9: 0x4000, 0x38: 0x4000,
    0x37: 0x4000, 0x4c: 0xc000, 0x5a: 0x4000, 0x10: 0x28000, 0x12: 0x28000, 0x11: 0x8000,
    0x44: 0x28000, 0x46: 0x28000, 0x45: 0x8000, 0x50: 0x18000, 0x60: 0x40000, 0x61: 0x34000,
];

/// iBoot.j314s table 0x1ffce8, 112 records: 21 ordinary fixed-size.
const T6000: &[Carveout] = table![
    0x51: 0x40000, 0x7: 0x4000, 0x8: 0x4000, 0x34: 0x40000, 0xd9: 0x4000, 0x38: 0x4000,
    0x37: 0x4000, 0x5a: 0x4000, 0x4c: 0xc000, 0x50: 0x18000, 0x10: 0x20000, 0x12: 0x20000,
    0x11: 0x8000, 0x44: 0x4000, 0x46: 0x10000, 0x45: 0x4000, 0x53: 0x4000, 0x55: 0x10000,
    0x54: 0x4000, 0x60: 0x40000, 0x61: 0x34000,
];

/// iBoot.j314c table 0x218938, 122 records: 27 ordinary fixed-size.
const T6001: &[Carveout] = table![
    0x51: 0x40000, 0x7: 0x4000, 0x8: 0x4000, 0x34: 0x40000, 0xd9: 0x4000, 0x38: 0x4000,
    0x37: 0x4000, 0x5a: 0x4000, 0x4c: 0xc000, 0x50: 0x18000, 0x10: 0x20000, 0x12: 0x20000,
    0x11: 0x8000, 0x44: 0x4000, 0x46: 0x10000, 0x45: 0x4000, 0x53: 0x4000, 0x55: 0x10000,
    0x54: 0x4000, 0x6a: 0x4000, 0x6c: 0x10000, 0x6b: 0x4000, 0x72: 0x4000, 0x74: 0x10000,
    0x73: 0x4000, 0x60: 0x40000, 0x61: 0x34000,
];

/// iBoot.j375d table 0x238e88, 139 records: 39 ordinary fixed-size.
const T6002: &[Carveout] = table![
    0x51: 0x40000, 0x7: 0x4000, 0x8: 0x4000, 0x34: 0x40000, 0xd9: 0x4000, 0x38: 0x4000,
    0x37: 0x4000, 0x5a: 0x4000, 0x4c: 0xc000, 0x50: 0x18000, 0x10: 0x20000, 0x12: 0x20000,
    0x11: 0x8000, 0x44: 0x4000, 0x46: 0x10000, 0x45: 0x4000, 0x53: 0x4000, 0x55: 0x10000,
    0x54: 0x4000, 0x6a: 0x4000, 0x6c: 0x10000, 0x6b: 0x4000, 0x72: 0x4000, 0x74: 0x10000,
    0x73: 0x4000, 0x7a: 0x4000, 0x7c: 0x10000, 0x7b: 0x4000, 0x82: 0x4000, 0x84: 0x10000,
    0x83: 0x4000, 0x8a: 0x4000, 0x8c: 0x10000, 0x8b: 0x4000, 0x92: 0x4000, 0x94: 0x10000,
    0x93: 0x4000, 0x60: 0x40000, 0x61: 0x34000,
];

/// iBoot.j413 table 0x1e2388, 103 records: 18 ordinary fixed-size.
const T8112: &[Carveout] = table![
    0x51: 0x40000, 0x7: 0x4000, 0x8: 0x4000, 0x34: 0x40000, 0xd9: 0x4000, 0x38: 0x4000,
    0x37: 0x4000, 0x5a: 0x4000, 0x4c: 0xc000, 0x10: 0x40000, 0x12: 0x40000, 0x11: 0xc000,
    0x44: 0x40000, 0x46: 0x40000, 0x45: 0xc000, 0x50: 0x18000, 0x60: 0x40000, 0x61: 0x34000,
];

/// iBoot.j414s table 0x210268, 118 records: 23 ordinary fixed-size.
const T6020: &[Carveout] = table![
    0x51: 0x40000, 0x7: 0x4000, 0x8: 0x4000, 0x34: 0x40000, 0xd9: 0x4000, 0x38: 0x4000,
    0x37: 0x4000, 0x5a: 0x4000, 0x4c: 0xc000, 0xb1: 0x4000, 0x10: 0x40000, 0x12: 0x40000,
    0x11: 0x20000, 0x44: 0x40000, 0x46: 0x40000, 0x45: 0x20000, 0x53: 0x40000, 0x55: 0x40000,
    0x54: 0x20000, 0x50: 0x18000, 0xa2: 0x800000, 0x60: 0x40000, 0x61: 0x34000,
];

/// iBoot.j414c table 0x222b00, 128 records: 29 ordinary fixed-size.
const T6021: &[Carveout] = table![
    0x51: 0x40000, 0x7: 0x4000, 0x8: 0x4000, 0x34: 0x40000, 0xd9: 0x4000, 0x38: 0x4000,
    0x37: 0x4000, 0x5a: 0x4000, 0x4c: 0xc000, 0xb1: 0x4000, 0x10: 0x40000, 0x12: 0x40000,
    0x11: 0x20000, 0x44: 0x40000, 0x46: 0x40000, 0x45: 0x20000, 0x53: 0x40000, 0x55: 0x40000,
    0x54: 0x20000, 0x6a: 0x40000, 0x6c: 0x40000, 0x6b: 0x20000, 0x72: 0x40000, 0x74: 0x40000,
    0x73: 0x20000, 0x50: 0x18000, 0xa2: 0x800000, 0x60: 0x40000, 0x61: 0x34000,
];

/// iBoot.j180d table 0x25eb20, 142 records: 38 ordinary fixed-size.
const T6022: &[Carveout] = table![
    0x51: 0x40000, 0x7: 0x4000, 0x8: 0x4000, 0x34: 0x40000, 0xd9: 0x4000, 0x38: 0x4000,
    0x37: 0x4000, 0x5a: 0x4000, 0x4c: 0xc000, 0xb1: 0x4000, 0x44: 0x40000, 0x46: 0x40000,
    0x45: 0x20000, 0x53: 0x40000, 0x55: 0x40000, 0x54: 0x20000, 0x6a: 0x40000, 0x6c: 0x40000,
    0x6b: 0x20000, 0x72: 0x40000, 0x74: 0x40000, 0x73: 0x20000, 0x7a: 0x40000, 0x7c: 0x40000,
    0x7b: 0x20000, 0x82: 0x40000, 0x84: 0x40000, 0x83: 0x20000, 0x8a: 0x40000, 0x8c: 0x40000,
    0x8b: 0x20000, 0x92: 0x40000, 0x94: 0x40000, 0x93: 0x20000, 0x50: 0x18000, 0xa2: 0x800000,
    0x60: 0x40000, 0x61: 0x34000,
];

/// iBoot.j433 table 0x1fa800, 101 records: 19 ordinary fixed-size.
const T8122: &[Carveout] = table![
    0x51: 0x40000, 0x7: 0x4000, 0x8: 0x4000, 0x34: 0x40000, 0xd9: 0x4000, 0x38: 0x4000,
    0x37: 0x4000, 0x5a: 0x4000, 0x4c: 0x8000, 0x50: 0x18000, 0xb1: 0x4000, 0x10: 0x40000,
    0x12: 0x40000, 0x11: 0x10000, 0x44: 0x40000, 0x46: 0x40000, 0x45: 0x10000, 0x60: 0x40000,
    0x61: 0x34000,
];

/// iBoot.j514s table 0x20f750, 109 records: 22 ordinary fixed-size.
const T6030: &[Carveout] = table![
    0x51: 0x40000, 0x7: 0x4000, 0x8: 0x4000, 0x34: 0x40000, 0xd9: 0x4000, 0x38: 0x4000,
    0x37: 0x4000, 0x5a: 0x4000, 0x4c: 0xc000, 0x50: 0x18000, 0x10: 0x40000, 0x12: 0x40000,
    0x11: 0x10000, 0xb1: 0x4000, 0x44: 0x40000, 0x46: 0x40000, 0x45: 0x10000, 0x53: 0x40000,
    0x55: 0x40000, 0x54: 0x10000, 0x60: 0x40000, 0x61: 0x34000,
];

/// iBoot.j514c table 0x277280, 123 records: 30 ordinary fixed-size.
const T6031: &[Carveout] = table![
    0x51: 0x40000, 0x7: 0x4000, 0x8: 0x4000, 0x34: 0x40000, 0xd9: 0x4000, 0x38: 0x4000,
    0x37: 0x4000, 0x5a: 0x4000, 0x4c: 0xc000, 0x50: 0x18000, 0xb1: 0x4000, 0xc4: 0x4000,
    0x10: 0x40000, 0x12: 0x40000, 0x11: 0x10000, 0x44: 0x40000, 0x46: 0x40000, 0x45: 0x10000,
    0x53: 0x40000, 0x55: 0x40000, 0x54: 0x10000, 0x6a: 0x40000, 0x6c: 0x40000, 0x6b: 0x10000,
    0x72: 0x40000, 0x74: 0x40000, 0x73: 0x10000, 0xa2: 0x800000, 0x60: 0x40000, 0x61: 0x34000,
];

/// iBoot.j514m table 0x277278, 122 records: 29 ordinary fixed-size.
const T6034: &[Carveout] = table![
    0x51: 0x40000, 0x7: 0x4000, 0x8: 0x4000, 0x34: 0x40000, 0xd9: 0x4000, 0x38: 0x4000,
    0x37: 0x4000, 0x5a: 0x4000, 0x4c: 0xc000, 0x50: 0x18000, 0xb1: 0x4000, 0x10: 0x40000,
    0x12: 0x40000, 0x11: 0x10000, 0x44: 0x40000, 0x46: 0x40000, 0x45: 0x10000, 0x53: 0x40000,
    0x55: 0x40000, 0x54: 0x10000, 0x6a: 0x40000, 0x6c: 0x40000, 0x6b: 0x10000, 0x72: 0x40000,
    0x74: 0x40000, 0x73: 0x10000, 0xa2: 0x800000, 0x60: 0x40000, 0x61: 0x34000,
];

/// iBoot.j575d table 0x2d6f20, 154 records: 39 ordinary fixed-size.
const T6032: &[Carveout] = table![
    0x51: 0x40000, 0x7: 0x4000, 0x8: 0x4000, 0x34: 0x40000, 0xd9: 0x4000, 0x38: 0x4000,
    0x37: 0x4000, 0x5a: 0x4000, 0x4c: 0xc000, 0x50: 0x18000, 0xb1: 0x4000, 0xc8: 0x4000,
    0x44: 0x40000, 0x46: 0x40000, 0x45: 0x10000, 0x53: 0x40000, 0x55: 0x40000, 0x54: 0x10000,
    0x6a: 0x40000, 0x6c: 0x40000, 0x6b: 0x10000, 0x72: 0x40000, 0x74: 0x40000, 0x73: 0x10000,
    0x7a: 0x40000, 0x7c: 0x40000, 0x7b: 0x10000, 0x82: 0x40000, 0x84: 0x40000, 0x83: 0x10000,
    0x8a: 0x40000, 0x8c: 0x40000, 0x8b: 0x10000, 0x92: 0x40000, 0x94: 0x40000, 0x93: 0x10000,
    0xa2: 0x800000, 0x60: 0x40000, 0x61: 0x34000,
];

/// iBoot.j604 table 0x28dfe8, 117 records: 24 ordinary fixed-size.
const T8132: &[Carveout] = table![
    0x51: 0x40000, 0x7: 0x4000, 0x8: 0x4000, 0x34: 0x40000, 0xd9: 0x4000, 0x38: 0x4000,
    0x37: 0x4000, 0xc5: 0x4000, 0x5a: 0x4000, 0x4c: 0xc000, 0x50: 0x18000, 0xb1: 0x4000,
    0x10: 0x20000, 0x12: 0x30000, 0x11: 0x10000, 0x44: 0x20000, 0x46: 0x30000, 0x45: 0x10000,
    0x53: 0x20000, 0x55: 0x30000, 0x54: 0x10000, 0xbd: 0x4000, 0x60: 0x40000, 0x61: 0x34000,
];

/// iBoot.j575c table 0x2ff4b0, 134 records: 32 ordinary fixed-size.
const T6040: &[Carveout] = table![
    0x51: 0x40000, 0x7: 0x4000, 0x8: 0x4000, 0x34: 0x40000, 0xd9: 0x4000, 0x38: 0x4000,
    0x37: 0x4000, 0xc5: 0x4000, 0x5a: 0x4000, 0x4c: 0xc000, 0x50: 0x18000, 0xb1: 0x4000,
    0xc4: 0x4000, 0x10: 0x20000, 0x12: 0x30000, 0x11: 0x10000, 0x44: 0x20000, 0x46: 0x30000,
    0x45: 0x10000, 0x53: 0x20000, 0x55: 0x30000, 0x54: 0x10000, 0x6a: 0x20000, 0x6c: 0x30000,
    0x6b: 0x10000, 0x72: 0x20000, 0x74: 0x30000, 0x73: 0x10000, 0xa2: 0x800000, 0xbd: 0x4000,
    0x60: 0x40000, 0x61: 0x34000,
];

/// iBoot.j700 table 0x2e3dd8, 144 records: 33 ordinary fixed-size.
const T8140: &[Carveout] = table![
    0x51: 0x40000, 0x7: 0x4000, 0x8: 0x4000, 0x34: 0x80000, 0xd9: 0x4000, 0x38: 0x4000,
    0x37: 0x4000, 0xc5: 0x4000, 0x5a: 0x4000, 0x4c: 0xc000, 0x10: 0x20000, 0x12: 0x20000,
    0xd0: 0x20000, 0xce: 0x20000, 0xcf: 0x20000, 0x11: 0x8000, 0x44: 0x20000, 0x46: 0x20000,
    0xd1: 0x20000, 0x45: 0x8000, 0xe3: 0x20000, 0xe4: 0x20000, 0xe5: 0x20000, 0xe6: 0x20000,
    0xe7: 0x20000, 0xe8: 0x20000, 0xf3: 0x20000, 0x10e: 0x20000, 0xf4: 0x20000, 0x50: 0x18000,
    0xbd: 0x4000, 0x60: 0x40000, 0x61: 0x34000,
];

/// iBoot.j704 table 0x295d60, 161 records: 34 ordinary fixed-size.
const T8142: &[Carveout] = table![
    0x51: 0x40000, 0x7: 0x4000, 0x8: 0x4000, 0x34: 0x80000, 0xd9: 0x4000, 0x38: 0x4000,
    0x37: 0x4000, 0x5a: 0x4000, 0x4c: 0xc000, 0x50: 0x18000, 0xb1: 0x4000, 0xfc: 0x4000,
    0x10: 0x20000, 0x12: 0x30000, 0x11: 0x10000, 0x44: 0x20000, 0x46: 0x30000, 0xd1: 0x30000,
    0x45: 0x10000, 0x53: 0x20000, 0x55: 0x30000, 0xd2: 0x30000, 0x54: 0x10000, 0xe3: 0x20000,
    0xe4: 0x20000, 0xe5: 0x20000, 0xe6: 0x20000, 0xe7: 0x20000, 0xe8: 0x20000, 0xf3: 0x20000,
    0xf4: 0x20000, 0xbd: 0x4000, 0x60: 0x40000, 0x61: 0x34000,
];

/// iBoot.j714c table 0x3abb08, 255 records: 66 ordinary fixed-size.
const T6050: &[Carveout] = table![
    0x51: 0x40000, 0x7: 0x4000, 0x126: 0x10000, 0x8: 0x4000, 0x34: 0x80000, 0xd9: 0x4000,
    0x38: 0x4000, 0x37: 0x4000, 0xc5: 0x4000, 0x5a: 0x4000, 0x4c: 0xc000, 0x50: 0x18000,
    0x10: 0x20000, 0x12: 0x30000, 0xce: 0x20000, 0xcf: 0x20000, 0xd0: 0x30000, 0x11: 0x10000,
    0x44: 0x20000, 0x46: 0x30000, 0xd1: 0x30000, 0x45: 0x10000, 0x53: 0x20000, 0x55: 0x30000,
    0xd2: 0x30000, 0x54: 0x10000, 0x6a: 0x20000, 0x6c: 0x30000, 0xd3: 0x30000, 0x6b: 0x10000,
    0x72: 0x20000, 0x74: 0x30000, 0xd4: 0x30000, 0x73: 0x10000, 0x7a: 0x20000, 0x7c: 0x30000,
    0xd5: 0x30000, 0x7b: 0x10000, 0x82: 0x20000, 0x84: 0x30000, 0xd6: 0x30000, 0x83: 0x10000,
    0x8a: 0x20000, 0x8c: 0x30000, 0xd7: 0x30000, 0x8b: 0x10000, 0x92: 0x20000, 0x94: 0x30000,
    0xd8: 0x30000, 0x93: 0x10000, 0xe3: 0x20000, 0xe4: 0x20000, 0xe5: 0x20000, 0xe6: 0x20000,
    0xe7: 0x20000, 0xe8: 0x20000, 0xf3: 0x20000, 0xf4: 0x20000, 0xb1: 0x4000, 0xc8: 0x4000,
    0xc4: 0x4000, 0x125: 0x4000, 0xa2: 0x800000, 0xbd: 0x4000, 0x60: 0x40000, 0x61: 0x34000,
];

/// iBoot.j873g table 0x3794e8, 203 records: 37 ordinary fixed-size.
const T8152: &[Carveout] = table![
    0x26e: 0x8000, 0x126: 0x100000, 0x8: 0x4000, 0x34: 0x80000, 0xd9: 0x4000, 0x38: 0x4000,
    0x5a: 0x4000, 0x50: 0x18000, 0xb1: 0x4000, 0xfc: 0x4000, 0x10: 0x20000, 0x12: 0x30000,
    0x11: 0x10000, 0xce: 0x20000, 0xcf: 0x20000, 0xd0: 0x30000, 0x44: 0x20000, 0x46: 0x30000,
    0x45: 0x10000, 0xd1: 0x30000, 0x53: 0x20000, 0x55: 0x30000, 0x54: 0x10000, 0xd2: 0x30000,
    0xe3: 0x20000, 0xe4: 0x20000, 0xe5: 0x20000, 0xe6: 0x20000, 0xe7: 0x20000, 0xe8: 0x20000,
    0xf3: 0x20000, 0x10e: 0x20000, 0x142: 0x20000, 0xa2: 0x800000, 0xbd: 0x4000, 0x60: 0x40000,
    0x61: 0x34000,
];

/// The carveout table of every ApChipID with a SoC row.
#[rustfmt::skip]
pub const FAMILIES: [Family; 19] = [
    Family { chips: &[0x8103], fixed: T8103, special: &[0x108] },
    Family { chips: &[0x6000], fixed: T6000, special: &[0x108] },
    Family { chips: &[0x6001], fixed: T6001, special: &[0x108] },
    Family { chips: &[0x6002], fixed: T6002, special: &[0x108] },
    Family { chips: &[0x8112], fixed: T8112, special: &[0x108] },
    Family { chips: &[0x6020], fixed: T6020, special: &[0x108] },
    Family { chips: &[0x6021], fixed: T6021, special: &[0x108] },
    Family { chips: &[0x6022], fixed: T6022, special: &[0x108] },
    Family { chips: &[0x8122], fixed: T8122, special: &[0x108] },
    Family { chips: &[0x6030], fixed: T6030, special: &[0x108] },
    Family { chips: &[0x6031], fixed: T6031, special: &[0x108] },
    Family { chips: &[0x6034], fixed: T6034, special: &[0x108] },
    Family { chips: &[0x6032], fixed: T6032, special: &[0x108] },
    Family { chips: &[0x8132], fixed: T8132, special: &[0x108] },
    Family { chips: &[0x6040, 0x6041], fixed: T6040, special: &[0x108] },
    Family { chips: &[0x8140], fixed: T8140, special: &[0x108] },
    Family { chips: &[0x8142], fixed: T8142, special: &[0x108] },
    Family { chips: &[0x6050], fixed: T6050, special: &[0x108] },
    Family { chips: &[0x8152], fixed: T8152, special: &[0x51, 0x7, 0x37, 0x4c, 0x108] },
];

/// The regions iBoot names in `/arm-io/sgx`, as `<prefix>-base` and
/// `<prefix>-size`.
const SGX_REGIONS: [(u16, &str); 4] = [
    (0x08, "gpu-region"),
    (0x34, "gfx-shared-region"),
    (0xd9, "gfx-shared-l2-region"),
    (0x38, "gfx-handoff"),
];

/// The carveout table of the SoC with `chip_id`; `None` for a SoC whose
/// iBoot has not been read.
pub fn family(chip_id: u32) -> Option<&'static Family> {
    FAMILIES
        .iter()
        .find(|family| family.chips.contains(&chip_id))
}

/// iBoot's ordinary fixed-size carveouts for the SoC with `chip_id`; `None`
/// for a SoC whose iBoot has not been read.
pub fn table(chip_id: u32) -> Option<&'static [Carveout]> {
    Some(family(chip_id)?.fixed)
}

/// The carveouts a bundle places for the SoC with `chip_id`: its fixed-size
/// table when read, then the panic region on every SoC with hand-off facts.
pub fn for_chip(chip_id: u32) -> Vec<Carveout> {
    let fixed = table(chip_id).unwrap_or_default();
    let panic = board::handoff(chip_id).map(|_| PANIC);
    fixed.iter().copied().chain(panic).collect()
}

/// Checked placement within the guest DRAM allocation. This reserves guest
/// physical addresses; the system mount separately owns their native backing.
#[derive(Debug)]
pub struct Reservation {
    regions: Vec<Placed>,
    managed_floor: u64,
}

impl Reservation {
    pub fn regions(&self) -> &[Placed] {
        &self.regions
    }

    pub fn into_regions(self) -> Vec<Placed> {
        self.regions
    }

    pub fn managed_floor(&self) -> u64 {
        self.managed_floor
    }
}

/// Place required protocol-sized ranges back to back inside guest DRAM.
/// The alignment padding is reserved too; at least one managed page must remain.
pub fn reserve(table: &[Carveout], dram_base: u64, dram_bytes: u64) -> Result<Reservation> {
    require!(
        dram_base.is_multiple_of(PAGE_BYTES),
        "carveout DRAM base is unaligned"
    );
    require!(
        dram_bytes > 0 && dram_bytes.is_multiple_of(PAGE_BYTES),
        "carveout DRAM size is empty or unaligned"
    );
    let dram_end = dram_base
        .checked_add(dram_bytes)
        .ok_or(refuse!("carveout DRAM end overflows"))?;
    let mut cursor = dram_base;
    let mut regions: Vec<Placed> = Vec::with_capacity(table.len());
    for carveout in table {
        require!(
            carveout.bytes > 0
                && carveout.bytes.is_multiple_of(PAGE_BYTES)
                && carveout.bytes / PAGE_BYTES < 0x10000,
            "carveout {id} violates SPTM page bounds",
            id = carveout.id
        );
        require!(
            !regions.iter().any(|region| region.id == carveout.id),
            "duplicate carveout {id}",
            id = carveout.id
        );
        let end = cursor
            .checked_add(carveout.bytes)
            .ok_or(refuse!("carveout end overflows"))?;
        require!(
            end <= dram_end,
            "carveout {id} exceeds guest DRAM",
            id = carveout.id
        );
        regions.push(Placed {
            id: carveout.id,
            base: cursor,
            bytes: carveout.bytes,
        });
        cursor = end;
    }
    let managed_floor = cursor
        .checked_next_multiple_of(MANAGED_ALIGNMENT)
        .ok_or(refuse!("managed DRAM alignment overflows"))?;
    require!(
        managed_floor < dram_end,
        "carveouts and alignment padding exhaust guest DRAM"
    );
    Ok(Reservation {
        regions,
        managed_floor,
    })
}

fn range(base: u64, bytes: u64) -> Vec<u8> {
    [base.to_le_bytes(), bytes.to_le_bytes()].concat()
}

/// Publishes the carveouts as iBoot does: every one in
/// `/chosen/carveout-memory-map`, the panic region in `/pram reg` (when the
/// template has `/pram`) and `/chosen embedded-panic-log-size`, and the GPU's
/// UAT regions in `/arm-io/sgx` when the board has a GPU.
pub fn publish(tree: &mut DeviceTree, placed: &[Placed]) -> Result<()> {
    if placed.is_empty() {
        return Ok(());
    }
    if let Some(panic) = placed.iter().find(|carveout| carveout.id == PANIC.id) {
        if tree.node(PRAM).is_some() {
            tree.set_property(PRAM, "reg", range(panic.base, panic.bytes))?;
        }
        tree.set_property(
            "/chosen",
            PANIC_LOG_SIZE,
            u32::try_from(panic.bytes)
                .map_err(|_| {
                    refuse!(
                        "panic log of {bytes:#x} bytes exceeds the u32 {PANIC_LOG_SIZE}",
                        bytes = panic.bytes,
                        PANIC_LOG_SIZE
                    )
                })?
                .to_le_bytes()
                .to_vec(),
        )?;
    }
    tree.ensure_child("/chosen", "carveout-memory-map")?;
    let map = tree
        .node_mut(MEMORY_MAP)
        .ok_or(refuse!("carveout-memory-map"))?;
    for carveout in placed {
        map.set_property(
            &format!("region-id-{}", carveout.id),
            range(carveout.base, carveout.bytes),
        )?;
    }
    if tree.node(SGX).is_none() {
        return Ok(());
    }
    for (id, prefix) in SGX_REGIONS {
        let carveout = placed
            .iter()
            .find(|carveout| carveout.id == id)
            .ok_or_else(|| refuse!("{SGX} needs carveout region {id:#x}", SGX, id))?;
        tree.set_property(
            SGX,
            &format!("{prefix}-base"),
            carveout.base.to_le_bytes().to_vec(),
        )?;
        tree.set_property(
            SGX,
            &format!("{prefix}-size"),
            carveout.bytes.to_le_bytes().to_vec(),
        )?;
    }
    Ok(())
}

/// What the bundle leaves out of iBoot's carveout setup.
pub fn gaps(tree: &DeviceTree, chip_id: Option<u32>) -> Vec<String> {
    let mut gaps = Vec::new();
    match chip_id.and_then(family) {
        Some(family) => {
            let special: Vec<String> = family.special.iter().map(|id| format!("{id:#x}")).collect();
            gaps.push(format!(
                "{MEMORY_MAP}: the fixed-size carveouts with special attributes ({}) and the \
                 absolute original carveouts have no qualified placement or resource ownership",
                special.join(", ")
            ));
            gaps.push(format!(
                "{MEMORY_MAP}: the carveouts iBoot sizes at run time, other than the panic \
                 region, are absent"
            ));
        }
        None => gaps.push(format!(
            "{MEMORY_MAP}: no iBoot carveout table for this SoC; its fixed-size carveouts are \
             absent"
        )),
    }
    if chip_id.and_then(board::handoff).is_none() {
        gaps.push(format!(
            "{PRAM} reg, /chosen {PANIC_LOG_SIZE}: no hand-off facts for this SoC; the kernel \
             keeps no panic buffer"
        ));
    } else if tree.node(PRAM).is_none() {
        gaps.push(format!(
            "{PRAM} reg: the template has no {PRAM} node; the kernel keeps no panic buffer"
        ));
    }
    if tree.node(SGX).is_some() {
        gaps.push(format!(
            "{SGX}: AGX firmware is not loaded, so gfx-data*, gptbat-ready, ttbat-phys-addr-base and rtkit-private-vm-region-* are absent"
        ));
    }
    gaps
}

#[cfg(test)]
mod tests;
