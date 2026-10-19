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
//! [`Uat`] is the translator itself: a stream [`Iommu`] whose stream number
//! is a context, rooted at the TTBAT the AP programs through the `sgx` MMU
//! configuration registers ([`super::sgx`]). One [`Agent`] (firmware or GPU)
//! translates through a [`Uat::agent`] view.
//!
//! Inferred (Asahi): the firmware runs in context 0 and reaches its shared
//! objects through the TTBR1 half; a VA's bits above bit 39 repeat bit 39
//! (kernel objects at `0xffff_ffa0_0000_0000`). The firmware addresses the
//! kext sends are 44 bits wide ([`canonical_firmware_va`]).
//!
//! The model walks the tables on every access and caches nothing, so a TLB or
//! TTBA-cache invalidation has nothing to discard.

use super::super::bus::Access as BusAccess;
use crate::platform::dma::{DmaError, Iommu, Memory};

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
    /// The leaf does not permit the access.
    Permission,
}

/// Contexts in the TTBAT (Asahi `UAT_NUM_CTX`).
pub const CONTEXTS: usize = 64;
/// TTBAT bytes per context: the TTBR0 then the TTBR1 word.
const TTBAT_ENTRY_BYTES: u64 = 16;
/// The context tag of a TTBAT word, bits 55:48 (`mapTaskIdIntoGPTBAT`).
const CONTEXT_SHIFT: u32 = 48;
const CONTEXT_MASK: u64 = 0xff;
/// The context the GFX firmware runs in.
pub const FIRMWARE_CONTEXT: usize = 0;
/// Width of the firmware VAs the kext hands the firmware (the 0x81 initdata
/// message's 44-bit field).
const FIRMWARE_VA_BITS: u32 = 44;

/// The full VA of a 44-bit firmware address: bits 63:44 repeat bit 43.
pub fn canonical_firmware_va(va: u64) -> u64 {
    let shift = 64 - FIRMWARE_VA_BITS;
    (((va << shift) as i64) >> shift) as u64
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
/// `input`'s bits above [`IAS`] must all equal its TTBR-select bit.
pub fn translate(memory: &mut dyn Memory, ttbr: u64, input: u64) -> Result<Mapping, Fault> {
    let upper = input >> (IAS + 1);
    let expected = if input & TTBR_SELECT_BIT != 0 {
        u64::MAX >> (IAS + 1)
    } else {
        0
    };
    if upper != expected {
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

/// Who reaches memory through the UAT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Agent {
    /// The GFX coprocessor's firmware.
    Firmware,
    /// The GPU's own units.
    Gpu,
}

/// What a leaf permits one agent: reads and writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Permits {
    read: bool,
    write: bool,
}

const NONE: Option<Permits> = Some(Permits {
    read: false,
    write: false,
});
const RO: Option<Permits> = Some(Permits {
    read: true,
    write: false,
});
const WO: Option<Permits> = Some(Permits {
    read: false,
    write: true,
});
const RW: Option<Permits> = Some(Permits {
    read: true,
    write: true,
});

/// The permissions of `(AP, UXN, PXN)` with the GPU-access bit set, as
/// (firmware, GPU), for the combinations whose meaning Asahi's working
/// mappings establish (`pgtable.rs` `prot`: FW_GPU_NA, FW_GPU_RW, FW_RO,
/// FW_RW, FW_RW_GPU_RO, GPU_RO, GPU_WO, GPU_RW). `None` is an agent whose
/// access to such a page no source states; it refuses rather than guesses.
fn permits(flags: &Flags, agent: Agent) -> Option<Permits> {
    if !flags.gpu_access {
        return None;
    }
    let (firmware, gpu) = match (flags.access, flags.uxn, flags.pxn) {
        (Access::FirmwareGpu, false, false) => (NONE, NONE),
        (Access::FirmwareGpu, true, true) => (RW, RW),
        (Access::Firmware, false, false) => (RO, None),
        (Access::Firmware, true, false) => (RW, None),
        (Access::Firmware, true, true) => (RW, RO),
        (Access::Gpu, false, false) => (None, RO),
        (Access::Gpu, false, true) => (None, WO),
        (Access::Gpu, true, false) => (None, RW),
        _ => (None, None),
    };
    match agent {
        Agent::Firmware => firmware,
        Agent::Gpu => gpu,
    }
}

/// A recorded translation fault, for diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FaultRecord {
    pub agent: Agent,
    pub context: usize,
    pub address: u64,
    pub write: bool,
    pub fault: Fault,
}

/// Fault codes a [`DmaError::Fault`] carries.
const FAULT_TRANSLATION: u32 = 1;
const FAULT_PERMISSION: u32 = 2;

/// The GPU address translator: per-context TTBR pairs in the TTBAT at a
/// physical base the AP programs.
#[derive(Debug, Default)]
pub struct Uat {
    ttbat: Option<u64>,
    last_fault: Option<FaultRecord>,
}

impl Uat {
    /// The TTBAT's physical base, once configured.
    pub fn ttbat(&self) -> Option<u64> {
        self.ttbat
    }

    /// Root the translator at a 16 KiB-aligned TTBAT.
    pub fn configure(&mut self, ttbat: u64) -> Result<(), &'static str> {
        if ttbat & PHYSICAL_INVALID != 0 {
            return Err("UAT TTBAT base outside bits 39:14");
        }
        self.ttbat = Some(ttbat);
        Ok(())
    }

    /// The last fault, if any.
    pub fn last_fault(&self) -> Option<FaultRecord> {
        self.last_fault
    }

    /// The translator as `agent` sees it, for a [`crate::platform::dma::Port`].
    pub fn agent(&mut self, agent: Agent) -> AgentView<'_> {
        AgentView { uat: self, agent }
    }

    /// The table root of `context`'s half for `iova`.
    fn root(&self, memory: &mut dyn Memory, context: usize, iova: u64) -> Result<u64, DmaError> {
        let ttbat = self.ttbat.ok_or(DmaError::Unsupported(
            "UAT access before the TTBAT is configured",
        ))?;
        if context >= CONTEXTS {
            return Err(DmaError::Unsupported("UAT context outside the TTBAT"));
        }
        let half = u64::from(iova & TTBR_SELECT_BIT != 0);
        let address = ttbat + context as u64 * TTBAT_ENTRY_BYTES + half * ENTRY_BYTES;
        let mut bytes = [0; 8];
        if !memory.read(address, &mut bytes) {
            return Err(DmaError::Memory);
        }
        Ok(u64::from_le_bytes(bytes))
    }

    fn walk(
        &mut self,
        memory: &mut dyn Memory,
        agent: Agent,
        context: usize,
        iova: u64,
        write: bool,
    ) -> Result<u64, DmaError> {
        let ttbr = self.root(memory, context, iova)?;
        let mut record = |fault, code| {
            self.last_fault = Some(FaultRecord {
                agent,
                context,
                address: iova,
                write,
                fault,
            });
            DmaError::Fault(code)
        };
        if ttbr & VALID == 0 {
            return Err(record(Fault::NotPresent { level: 0 }, FAULT_TRANSLATION));
        }
        if (ttbr >> CONTEXT_SHIFT) & CONTEXT_MASK != context as u64 {
            return Err(DmaError::Unsupported(
                "UAT TTBAT entry tagged with another context",
            ));
        }
        let mapping = match translate(memory, ttbr & ADDRESS_MASK, iova) {
            Ok(mapping) => mapping,
            Err(Fault::Memory { .. }) => return Err(DmaError::Memory),
            Err(fault) => return Err(record(fault, FAULT_TRANSLATION)),
        };
        let permits = permits(&mapping.flags, agent).ok_or(DmaError::Unsupported(
            "UAT leaf permission encoding not modeled for this agent",
        ))?;
        if !(if write { permits.write } else { permits.read }) {
            return Err(record(Fault::Permission, FAULT_PERMISSION));
        }
        Ok(mapping.physical)
    }
}

/// One agent's view of the [`Uat`]; the stream number is the context.
pub struct AgentView<'a> {
    uat: &'a mut Uat,
    agent: Agent,
}

impl Iommu for AgentView<'_> {
    fn page(&self) -> u64 {
        PAGE_BYTES
    }

    /// A fault is recorded in the translator. The GFX firmware handles GPU
    /// faults itself; it raises no AP interrupt line.
    fn translate(
        &mut self,
        memory: &mut dyn Memory,
        stream: usize,
        iova: u64,
        last: u64,
        write: bool,
        _access: &mut BusAccess<'_>,
    ) -> Result<u64, DmaError> {
        debug_assert!(last >= iova && last >> PAGE_SHIFT == iova >> PAGE_SHIFT);
        self.uat.walk(memory, self.agent, stream, iova, write)
    }
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
        // Bits above the 39-bit space must repeat the TTBR-select bit.
        assert_eq!(translate(&mut ram, pce, 1 << 40), Err(Fault::OutOfRange));
        assert_eq!(
            translate(&mut ram, pce, TTBR_SELECT_BIT),
            Err(Fault::OutOfRange)
        );
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

    /// RAM holding a TTBAT at its base and one firmware page mapped at the
    /// TTBR1 VA `0xffff_ffa0_0000_4000` of context 0 with `flags`.
    fn firmware_space(flags: Flags) -> (Ram, Uat, u64, u64) {
        let base = 0x8_0000_0000;
        let mut ram = Ram::new(base, 0x4000 * 6);
        let (ttbat, pce, pde, pte, page) = (
            base,
            base + 0x4000,
            base + 0x8000,
            base + 0xc000,
            base + 0x1_0000,
        );
        let [ttbr0, ttbr1] = encode_gptbat(0, 0, pce);
        ram.put_u64(ttbat, ttbr0 & !VALID);
        ram.put_u64(ttbat + 8, ttbr1);
        let va = 0xffff_ffa0_0000_4000;
        let (_, idx) = indices(va);
        ram.put_u64(pce + idx[0] as u64 * 8, encode_table(pde));
        ram.put_u64(pde + idx[1] as u64 * 8, encode_table(pte));
        ram.put_u64(pte + idx[2] as u64 * 8, encode_pte(page, &flags));
        let mut uat = Uat::default();
        uat.configure(ttbat).unwrap();
        (ram, uat, va, page)
    }

    fn port_read(
        uat: &mut Uat,
        agent: Agent,
        ram: &mut Ram,
        context: usize,
        va: u64,
    ) -> Result<u64, DmaError> {
        use crate::platform::apple::interrupt::InterruptLatch;
        use crate::platform::dma::Port;
        let mut latch = InterruptLatch::new();
        let mut access = BusAccess::new(0, 0, &mut latch);
        let mut view = uat.agent(agent);
        let mut port = Port {
            iommu: &mut view,
            stream: context,
            memory: ram,
            access: &mut access,
        };
        let mut word = [0; 8];
        port.read(va, &mut word)?;
        Ok(u64::from_le_bytes(word))
    }

    fn shared(access: Access, uxn: bool, pxn: bool) -> Flags {
        Flags {
            access,
            memory: MemoryAttr::Uncached,
            global: true,
            pxn,
            uxn,
            gpu_access: true,
        }
    }

    #[test]
    fn the_firmware_reads_its_ttbr1_objects_through_the_ttbat() {
        let (mut ram, mut uat, va, page) = firmware_space(shared(Access::Firmware, true, false));
        ram.put_u64(page + 0x10, 0x0c8a_6342_8392_04c8);
        // The 44-bit address the kext sends widens to the TTBR1 VA.
        assert_eq!(canonical_firmware_va(va & ((1 << 44) - 1)), va);
        assert_eq!(
            port_read(
                &mut uat,
                Agent::Firmware,
                &mut ram,
                FIRMWARE_CONTEXT,
                va + 0x10
            ),
            Ok(0x0c8a_6342_8392_04c8)
        );
        // Context 0's TTBR0 is invalid: a user-half access faults and is recorded.
        assert_eq!(
            port_read(&mut uat, Agent::Firmware, &mut ram, 0, 0x4000),
            Err(DmaError::Fault(FAULT_TRANSLATION))
        );
        let fault = uat.last_fault().unwrap();
        assert_eq!((fault.context, fault.address), (0, 0x4000));
        // A firmware-RW page's GPU access is stated nowhere: it refuses.
        assert!(matches!(
            port_read(&mut uat, Agent::Gpu, &mut ram, 0, va),
            Err(DmaError::Unsupported(_))
        ));
        // A context past the TTBAT refuses.
        assert!(matches!(
            port_read(&mut uat, Agent::Firmware, &mut ram, CONTEXTS, va),
            Err(DmaError::Unsupported(_))
        ));
    }

    #[test]
    fn leaf_permissions_follow_the_established_encodings() {
        let fw_ro = shared(Access::Firmware, false, false);
        assert_eq!(permits(&fw_ro, Agent::Firmware), RO);
        let fw_rw_gpu_ro = shared(Access::Firmware, true, true);
        assert_eq!(permits(&fw_rw_gpu_ro, Agent::Gpu), RO);
        assert_eq!(permits(&shared(Access::Gpu, false, true), Agent::Gpu), WO);
        assert_eq!(
            permits(&shared(Access::FirmwareGpu, true, true), Agent::Firmware),
            RW
        );
        // Without the GPU-access bit no source states the meaning.
        let hidden = Flags {
            gpu_access: false,
            ..fw_ro
        };
        assert_eq!(permits(&hidden, Agent::Firmware), None);
        // A firmware write to a read-only page faults on permission.
        let (mut ram, mut uat, va, _) = firmware_space(fw_ro);
        use crate::platform::apple::interrupt::InterruptLatch;
        let mut latch = InterruptLatch::new();
        let mut access = BusAccess::new(0, 0, &mut latch);
        let mut view = uat.agent(Agent::Firmware);
        assert_eq!(
            view.translate(&mut ram, 0, va, va + 7, true, &mut access),
            Err(DmaError::Fault(FAULT_PERMISSION))
        );
        assert_eq!(uat.last_fault().unwrap().fault, Fault::Permission);
    }

    #[test]
    fn an_unconfigured_or_misaligned_ttbat_refuses() {
        let mut uat = Uat::default();
        let mut ram = Ram::new(0x8_0000_0000, 0x4000);
        assert!(matches!(
            port_read(&mut uat, Agent::Firmware, &mut ram, 0, 0),
            Err(DmaError::Unsupported(_))
        ));
        assert!(uat.configure(0x8_0000_0100).is_err());
        assert!(uat.configure(1 << 40).is_err());
    }
}
