//! The AGX Unified Address Translator (UAT): the GPU's MMU, modeled at the
//! page-table encodings the 26A434 `AGXUATSingleStage` writes and the public
//! Asahi layout confirms.
//!
//! Known (26A434 `AGXUATSingleStage`, unslid VAs; see docs/research/agx.md §3):
//! - 16 KiB pages, 8-byte little-endian entries, three levels.
//! - `encodePTE` (0x1b9f820): `PA & 0xff_ffff_c000 | flags`.
//! - `encodePDE`/`encodePCE` (0x1b9f830/0x1b9f87c): `table & ~0x3fff | 3`.
//! - `encodePTEFlags(kind, ap, pxn, uxn, gpu, attr)` (0x1b9f8c8):
//!   `0x403` (kind != 0) or `0xc03` (kind 0, bit 11 non-global)
//!   `| ap << 6 | attr << 2 | pxn << 53 | uxn << 54 | gpu << 55`, where
//!   `attr << 6` lands in bits 39..13 only through the wide mask
//!   `0x3f_ffff_f3c0` applied to `attr << 6` — the physical-address field and
//!   the memory-attribute index share no bits with the AP/XN/GPU flags.
//! - `isPTEValid`/`isPDEValid`/`isPCEValid` (0x1b9f938..): bit 0.
//! - `isPhysicalAddressValid` (0x1b9f928): bits 63:40 and 13:0 are clear, so a
//!   valid output address is 14..39 bits.
//! - A GPTBAT holds 16 bytes per context (`mapTaskIdIntoGPTBAT` 0x1b9f768):
//!   entry `2*ctx` is `TTBR0 & ~0x3fff | ctx << 48 | 1`, entry `2*ctx + 1` is
//!   `TTBR1 & ~0x3fff | ctx << 48 | 1` with the low TTBR0 bits cleared;
//!   `invalidateGPTBATEntry` (0x1b9f6bc) clears bit 0 of both.
//!
//! Public (Asahi `drivers/gpu/drm/asahi/pgtable.rs`, pinned
//! `94fb23346d522edf53722357c426a3e58030beea`): input address size 39 bits,
//! VA bit 39 selects the shared TTBR1 half; AP 0 firmware+GPU, 1 firmware, 2
//! GPU; bit 55 grants GPU access; memory-attribute index 0 cached, 1 device,
//! 2 uncached. The walk indexes bits 36, 25 and 14 with 8, 2048 and 2048
//! entries.
//!
//! This module owns the encodings and a walk over guest RAM; wiring it to a
//! stream's [`Iommu`](crate::platform::dma::Iommu) is the integration layer
//! and is not done here.

use crate::platform::dma::Memory;

/// Page shift and size (`UAT_PGBIT`/`UAT_PGSZ`).
pub const PAGE_SHIFT: u32 = 14;
pub const PAGE_BYTES: u64 = 1 << PAGE_SHIFT;
const PAGE_MASK: u64 = PAGE_BYTES - 1;

/// Table-entry size and the entries per table level.
const ENTRY_BYTES: u64 = 8;
const LEVEL_BITS: u32 = PAGE_SHIFT - 3; // 11: 2048 entries per 16 KiB table
const LEVELS: u32 = 3;

/// Input address size; bit [`IAS`] selects TTBR1.
pub const IAS: u32 = 39;
const TTBR_SELECT_BIT: u64 = 1 << IAS;

/// The address field of a valid entry (bits 39:14).
const ADDRESS_MASK: u64 = 0xff_ffff_c000;
/// A physical address is valid when nothing outside bits 39:14 is set
/// (`isPhysicalAddressValid`: `tst x1, #0xffffff0000003fff`).
const PHYSICAL_INVALID: u64 = 0xffff_ff00_0000_0000 | PAGE_MASK;

const VALID: u64 = 1;
/// A table descriptor (PDE/PCE): `table | 3`.
const TABLE: u64 = 3;

const AP_SHIFT: u32 = 6;
const AP_MASK: u64 = 3 << AP_SHIFT;
const ATTR_SHIFT: u32 = 2;
const ATTR_MASK: u64 = 7 << ATTR_SHIFT;
const PXN: u64 = 1 << 53;
const UXN: u64 = 1 << 54;
const GPU_ACCESS: u64 = 1 << 55;
const NON_GLOBAL: u64 = 1 << 11;

/// Access permission of a leaf entry (`AGXUATSingleStage` AP field).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// AP 0: firmware and GPU.
    FirmwareGpu,
    /// AP 1: firmware only.
    Firmware,
    /// AP 2: GPU only.
    Gpu,
}

impl Access {
    const fn bits(self) -> u64 {
        match self {
            Access::FirmwareGpu => 0,
            Access::Firmware => 1,
            Access::Gpu => 2,
        }
    }

    fn from_bits(bits: u64) -> Option<Access> {
        match bits {
            0 => Some(Access::FirmwareGpu),
            1 => Some(Access::Firmware),
            2 => Some(Access::Gpu),
            _ => None,
        }
    }
}

/// Memory-attribute index of a leaf entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryAttr {
    Cached,
    Device,
    Uncached,
}

impl MemoryAttr {
    const fn index(self) -> u64 {
        match self {
            MemoryAttr::Cached => 0,
            MemoryAttr::Device => 1,
            MemoryAttr::Uncached => 2,
        }
    }
}

/// The decoded flags of a leaf page-table entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flags {
    pub access: Access,
    pub memory: MemoryAttr,
    pub global: bool,
    /// Privileged-execute-never and unprivileged-execute-never.
    pub pxn: bool,
    pub uxn: bool,
    pub gpu_access: bool,
}

impl Flags {
    /// The flag bits of a leaf entry, as `encodePTEFlags` forms them. `kind`
    /// 0 marks the mapping non-global (its `0xc03` base), any other value
    /// keeps it global (`0x403`).
    pub fn encode(&self) -> u64 {
        let base = if self.global { 0x403 } else { 0xc03 };
        base | self.access.bits() << AP_SHIFT
            | self.memory.index() << ATTR_SHIFT
            | u64::from(self.pxn) << 53
            | u64::from(self.uxn) << 54
            | u64::from(self.gpu_access) << 55
    }

    fn decode(entry: u64) -> Option<Flags> {
        Some(Flags {
            access: Access::from_bits((entry & AP_MASK) >> AP_SHIFT)?,
            memory: match (entry & ATTR_MASK) >> ATTR_SHIFT {
                0 => MemoryAttr::Cached,
                1 => MemoryAttr::Device,
                2 => MemoryAttr::Uncached,
                _ => return None,
            },
            global: entry & NON_GLOBAL == 0,
            pxn: entry & PXN != 0,
            uxn: entry & UXN != 0,
            gpu_access: entry & GPU_ACCESS != 0,
        })
    }
}

/// Encode a leaf (page) entry for a 16 KiB-aligned physical address.
pub fn encode_pte(physical: u64, flags: &Flags) -> u64 {
    (physical & ADDRESS_MASK) | flags.encode()
}

/// Encode a table descriptor (PDE or PCE) for a 16 KiB-aligned table base.
pub fn encode_table(table: u64) -> u64 {
    (table & !PAGE_MASK) | TABLE
}

/// Encode the two GPTBAT words for a context: TTBR0 then TTBR1.
pub fn encode_gptbat(context: u16, ttbr0: u64, ttbr1: u64) -> [u64; 2] {
    let tag = (u64::from(context) << 48) | VALID;
    [(ttbr0 & !PAGE_MASK) | tag, (ttbr1 & !PAGE_MASK) | tag]
}

/// Why a UAT walk did not reach a page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// The input address has bits set above [`IAS`] (ignoring the TTBR select).
    OutOfRange,
    /// A table or leaf entry had bit 0 clear.
    NotPresent { level: u32 },
    /// A table base or output address was outside bits 39:14.
    BadAddress { level: u32 },
    /// A table could not be read from guest RAM.
    Memory { level: u32 },
}

/// Which half (translation table base register) an input address selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Half {
    /// Per-context user half (VA bit 39 clear).
    Ttbr0,
    /// Shared kernel/firmware half (VA bit 39 set).
    Ttbr1,
}

/// The half and the three table indices an input address walks.
pub fn indices(input: u64) -> (Half, [usize; LEVELS as usize]) {
    let half = if input & TTBR_SELECT_BIT != 0 {
        Half::Ttbr1
    } else {
        Half::Ttbr0
    };
    let va = input & (TTBR_SELECT_BIT - 1);
    let mut idx = [0usize; LEVELS as usize];
    for (level, slot) in idx.iter_mut().enumerate() {
        let shift = PAGE_SHIFT + (LEVELS - 1 - level as u32) * LEVEL_BITS;
        *slot = ((va >> shift) & ((1 << LEVEL_BITS) - 1)) as usize;
    }
    (half, idx)
}

fn read_entry(memory: &mut dyn Memory, table: u64, index: usize, level: u32) -> Result<u64, Fault> {
    let mut bytes = [0u8; 8];
    if !memory.read(table + index as u64 * ENTRY_BYTES, &mut bytes) {
        return Err(Fault::Memory { level });
    }
    Ok(u64::from_le_bytes(bytes))
}

/// The result of a successful translation: the output physical address and
/// the leaf flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mapping {
    pub physical: u64,
    pub flags: Flags,
}

/// Walk the table rooted at `ttbr` for `input`, reading entries from guest
/// RAM. `ttbr` is the 16 KiB-aligned base of the top-level (PCE) table.
pub fn translate(memory: &mut dyn Memory, ttbr: u64, input: u64) -> Result<Mapping, Fault> {
    if input & !(TTBR_SELECT_BIT - 1) & !TTBR_SELECT_BIT != 0 {
        return Err(Fault::OutOfRange);
    }
    let (_, idx) = indices(input);
    let mut table = ttbr & !PAGE_MASK;
    for level in 0..LEVELS - 1 {
        let entry = read_entry(memory, table, idx[level as usize], level)?;
        if entry & VALID == 0 {
            return Err(Fault::NotPresent { level });
        }
        let next = entry & ADDRESS_MASK;
        if next & PHYSICAL_INVALID != 0 {
            return Err(Fault::BadAddress { level });
        }
        table = next;
    }
    let leaf = LEVELS - 1;
    let entry = read_entry(memory, table, idx[leaf as usize], leaf)?;
    if entry & VALID == 0 {
        return Err(Fault::NotPresent { level: leaf });
    }
    let base = entry & ADDRESS_MASK;
    if base & PHYSICAL_INVALID != 0 {
        return Err(Fault::BadAddress { level: leaf });
    }
    let flags = Flags::decode(entry).ok_or(Fault::BadAddress { level: leaf })?;
    Ok(Mapping {
        physical: base | (input & PAGE_MASK),
        flags,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::dma::tests::Ram;

    #[test]
    fn leaf_flags_round_trip_and_match_the_kext_constants() {
        // encodePTEFlags(kind=1, ap=GPU(2), pxn=1, uxn=1, gpu=1, attr=uncached)
        let flags = Flags {
            access: Access::Gpu,
            memory: MemoryAttr::Uncached,
            global: true,
            pxn: true,
            uxn: true,
            gpu_access: true,
        };
        let bits = flags.encode();
        // Global base 0x403, AP 2 << 6, attr 2 << 2, PXN|UXN|GPU high bits.
        assert_eq!(
            bits,
            0x403 | (2 << 6) | (2 << 2) | (1 << 53) | (1 << 54) | (1 << 55)
        );
        assert_eq!(Flags::decode(bits), Some(flags));
        // kind 0 clears bit 0x400 route but sets non-global 0xc03.
        let ng = Flags {
            global: false,
            ..flags
        };
        assert_eq!(ng.encode() & 0xc03, 0xc03);
        assert!(!Flags::decode(ng.encode()).unwrap().global);
    }

    #[test]
    fn descriptor_and_gptbat_encodings_match_the_kext() {
        assert_eq!(
            encode_pte(0x1_2345_c000, &demo_flags()) & ADDRESS_MASK,
            0x12345c000 & ADDRESS_MASK
        );
        assert_eq!(encode_table(0x8_0100_7fff), 0x8_0100_4000 | 3);
        assert_eq!(
            encode_gptbat(5, 0x8_0040_0123, 0x8_0080_0000),
            [0x8_0040_0000 | (5 << 48) | 1, 0x8_0080_0000 | (5 << 48) | 1]
        );
    }

    fn demo_flags() -> Flags {
        Flags {
            access: Access::FirmwareGpu,
            memory: MemoryAttr::Cached,
            global: true,
            pxn: false,
            uxn: false,
            gpu_access: true,
        }
    }

    #[test]
    fn indices_split_the_input_and_select_the_half() {
        let (half, idx) = indices(0);
        assert_eq!(half, Half::Ttbr0);
        assert_eq!(idx, [0, 0, 0]);
        // Set one bit in each level field and the TTBR1 select.
        let input = TTBR_SELECT_BIT | (1 << 36) | (2 << 25) | (3 << 14) | 0x3ab;
        let (half, idx) = indices(input);
        assert_eq!(half, Half::Ttbr1);
        assert_eq!(idx, [1, 2, 3]);
    }

    #[test]
    fn a_three_level_walk_reaches_a_mapped_page_and_reports_faults() {
        // Build PCE -> PDE -> PTE tables in RAM for input 0.
        let mut ram = Ram::new(0x8_0000_0000, 0x1_0000 * 4);
        let pce = 0x8_0000_0000;
        let pde = 0x8_0000_4000;
        let pte = 0x8_0000_8000;
        let page = 0x8_0000_c000;
        ram.put_u64(pce, encode_table(pde));
        ram.put_u64(pde, encode_table(pte));
        let flags = demo_flags();
        ram.put_u64(pte, encode_pte(page, &flags));
        let got = translate(&mut ram, pce, 0x20).unwrap();
        assert_eq!(got.physical, page | 0x20);
        assert_eq!(got.flags, flags);
        // An unmapped sibling leaf faults as not-present at the leaf level.
        assert_eq!(
            translate(&mut ram, pce, PAGE_BYTES),
            Err(Fault::NotPresent { level: 2 })
        );
        // An input above the 39-bit space is out of range.
        assert_eq!(translate(&mut ram, pce, 1 << 40), Err(Fault::OutOfRange));
        // A missing top-level table reads as zero and faults present at 0.
        ram.put_u64(pce, 0);
        assert_eq!(
            translate(&mut ram, pce, 0),
            Err(Fault::NotPresent { level: 0 })
        );
    }

    #[test]
    fn a_table_outside_ram_faults_on_memory() {
        let mut ram = Ram::new(0x8_0000_0000, 0x4000);
        // PCE points at a table far outside the RAM region.
        ram.put_u64(0x8_0000_0000, encode_table(0x9_0000_0000));
        assert_eq!(
            translate(&mut ram, 0x8_0000_0000, 0),
            Err(Fault::Memory { level: 1 })
        );
    }
}
