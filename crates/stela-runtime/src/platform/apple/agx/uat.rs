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
//!   valid output address is 14..39 bits. The `AGXG14X` encoders are the
//!   same instructions, though its SoC's DRAM lies at 1 TiB: the GPU tables
//!   are SPTM's (docs/research/agx.md §3), not these encoders'.
//! - A GPTBAT holds 16 bytes per context (`mapTaskIdIntoGPTBAT` 0x1b9f768):
//!   entry `2*ctx` is `TTBR0 & ~0x3fff | ctx << 48 | 1`, entry `2*ctx + 1` is
//!   `TTBR1 & ~0x3fff | ctx << 48 | 1` with the low TTBR0 bits cleared;
//!   `invalidateGPTBATEntry` (0x1b9f6bc) clears bit 0 of both.
//!
//! Public (Asahi `drivers/gpu/drm/asahi/pgtable.rs` and `hw/*.rs`, pinned
//! `94fb23346d522edf53722357c426a3e58030beea`): an output address fills bits
//! `oas - 1..14` of an entry, `oas` (`uat_oas`) being 40 on T8103 and T8112
//! and 42 on T600x and T602x ([`Uat::new`]); input address size 39 bits,
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
//! Inferred (26A434 SPTM and observed restore boots): the TTBR1 window at
//! level-0 index [`SHARED_INDEX`] (`0xffff_ffa0_0000_0000`, 64 GiB) is shared
//! by every context through one page-directory page, `gfx-shared-l2-region`.
//! SPTM names that region "the TTBR1 shared L2" and requires it to be one
//! page (`uat_bootstrap_parse_dt`); its UAT endpoints install every kernel
//! mapping there through a global state object (`sptm_uat_map_table` level
//! 2), while the per-context TTBR1 roots it creates (`sptm_uat_init_state`,
//! placed in the TTBAT by `sptm_uat_set_ctx_id`) never link it, and no RAM
//! word holds a table entry for it. The window therefore resolves from the
//! shared L2 for every context ([`Uat::share_kernel_window`]).
//!
//! The model walks the tables on every access and caches nothing, so a TLB or
//! TTBA-cache invalidation has nothing to discard.

use alloc::rc::Rc;
use core::cell::Cell;
use stela_contracts::bus::Access as BusAccess;
use {stela_contracts::dma::DmaError, stela_contracts::dma::Iommu, stela_contracts::dma::Memory};

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

/// The widest address field the entry layout leaves below its flags (bits
/// 51:14; the GPU-access, UXN and PXN flags start at bit 53).
const ENTRY_ADDRESS: u64 = 0x000f_ffff_ffff_c000;

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
const ACCESS_FLAG: u64 = 1 << 10;
const SHAREABILITY: u64 = 3 << 8;
const LEAF_FLAGS: u64 =
    TABLE | ATTR_MASK | AP_MASK | SHAREABILITY | ACCESS_FLAG | NON_GLOBAL | PXN | UXN | GPU_ACCESS;

/// Access permission of a leaf entry (`AGXUATSingleStage` AP field).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// AP 0: firmware and GPU.
    FirmwareGpu,
    /// AP 1: firmware only.
    Firmware,
    /// AP 2: GPU only.
    Gpu,
    /// AP 3: neither agent, when the GPU-access bit is set (Public:
    /// m1n1 `PTE.access_fw`/`access_gpu`).
    None,
}

impl Access {
    #[cfg(test)]
    const fn bits(self) -> u64 {
        match self {
            Access::FirmwareGpu => 0,
            Access::Firmware => 1,
            Access::Gpu => 2,
            Access::None => 3,
        }
    }

    fn from_bits(bits: u64) -> Option<Access> {
        match bits {
            0 => Some(Access::FirmwareGpu),
            1 => Some(Access::Firmware),
            2 => Some(Access::Gpu),
            3 => Some(Access::None),
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

#[cfg(test)]
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
    #[cfg(test)]
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

/// Encode a leaf (page) entry for a 16 KiB-aligned physical address within
/// the translator's output size.
#[cfg(test)]
pub fn encode_pte(physical: u64, flags: &Flags) -> u64 {
    (physical & ENTRY_ADDRESS) | flags.encode()
}

/// The address field of an entry whose output addresses are `bits` wide:
/// bits `bits - 1..14`.
const fn output_mask(bits: u32) -> u64 {
    ((1 << bits) - 1) & !PAGE_MASK
}

/// Encode a table descriptor (PDE or PCE) for a 16 KiB-aligned table base.
#[cfg(test)]
pub fn encode_table(table: u64) -> u64 {
    (table & !PAGE_MASK) | TABLE
}

/// Encode the two GPTBAT words for a context: TTBR0 then TTBR1.
#[cfg(test)]
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
    /// A table base or output address was misaligned or outside the
    /// configured output address width.
    BadAddress { level: u32 },
    /// The descriptor uses a type, flag or attribute whose behavior the
    /// model does not implement. This is an explicit model refusal, not a
    /// claim that hardware reports an architectural translation fault.
    UnsupportedDescriptor { level: u32 },
    /// A table could not be read from guest RAM.
    Memory { level: u32 },
    /// The leaf does not permit the access.
    Permission,
}

/// Contexts in the TTBAT (Asahi `UAT_NUM_CTX`).
pub const CONTEXTS: usize = 64;
/// TTBAT bytes per context: the TTBR0 then the TTBR1 word.
const TTBAT_ENTRY_BYTES: u64 = 16;
/// The context tag of a TTBAT word, bits 63:48 (m1n1 `TTBR.ASID`;
/// `mapTaskIdIntoGPTBAT` inserts the context at bit 48).
const CONTEXT_SHIFT: u32 = 48;
const CONTEXT_MASK: u64 = 0xffff;
const TTBAT_CONTEXT: u64 = CONTEXT_MASK << CONTEXT_SHIFT;
const TTBAT_ADDRESS: u64 = ((1 << CONTEXT_SHIFT) - 1) & !PAGE_MASK;
/// The context the GFX firmware runs in.
pub const FIRMWARE_CONTEXT: usize = 0;
/// The stream bit of a GPU-unit access on the GFX coprocessor's port. The
/// firmware and the GPU it drives are one bus master behind one UAT
/// (Decision): the machine hands the coprocessor a firmware view, and work
/// the firmware runs reaches its context's memory with the GPU's
/// permissions through `gpu_stream(context)`.
pub const GPU_STREAM: usize = 1 << 8;

/// The port stream of a GPU-unit access in `context`.
#[cfg(test)]
pub const fn gpu_stream(context: usize) -> Result<usize, DmaError> {
    // Validate before inserting the agent bit: otherwise context 0x100
    // would be encoded exactly like GPU context 0 and silently alias it.
    if context >= CONTEXTS {
        return Err(DmaError::Unsupported("UAT context outside the TTBAT"));
    }
    Ok(GPU_STREAM | context)
}
/// The level-0 index of the TTBR1 window every context shares through the
/// shared L2 (`0xffff_ffa0_0000_0000`).
pub const SHARED_INDEX: usize = 2;
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
/// RAM, whose entries hold `output_bits`-bit addresses. `ttbr` is the
/// 16 KiB-aligned base of the top-level (PCE) table. `input`'s bits above
/// [`IAS`] must all equal its TTBR-select bit.
#[cfg(test)]
pub fn translate(
    memory: &mut dyn Memory,
    ttbr: u64,
    input: u64,
    output_bits: u32,
) -> Result<Mapping, Fault> {
    in_range(input)?;
    let mask = output_mask(output_bits);
    if ttbr & !mask != 0 {
        return Err(Fault::BadAddress { level: 0 });
    }
    let (_, idx) = indices(input);
    walk_from(memory, ttbr, 0, &idx, input, mask)
}

/// `input`'s bits above [`IAS`] must all equal its TTBR-select bit.
fn in_range(input: u64) -> Result<(), Fault> {
    let upper = input >> (IAS + 1);
    let expected = if input & TTBR_SELECT_BIT != 0 {
        u64::MAX >> (IAS + 1)
    } else {
        0
    };
    if upper != expected {
        return Err(Fault::OutOfRange);
    }
    Ok(())
}

/// Walk from `table` at `first` level for an input whose `idx` are known,
/// taking each entry's address through `mask`.
fn walk_from(
    memory: &mut dyn Memory,
    mut table: u64,
    first: u32,
    idx: &[usize; LEVELS as usize],
    input: u64,
    mask: u64,
) -> Result<Mapping, Fault> {
    for level in first..LEVELS - 1 {
        let entry = read_entry(memory, table, idx[level as usize], level)?;
        if entry & VALID == 0 {
            return Err(Fault::NotPresent { level });
        }
        if entry & ENTRY_ADDRESS & !mask != 0 {
            return Err(Fault::BadAddress { level });
        }
        if entry & !mask != TABLE {
            return Err(Fault::UnsupportedDescriptor { level });
        }
        table = entry & mask;
    }
    let leaf = LEVELS - 1;
    let entry = read_entry(memory, table, idx[leaf as usize], leaf)?;
    if entry & VALID == 0 {
        return Err(Fault::NotPresent { level: leaf });
    }
    if entry & ENTRY_ADDRESS & !mask != 0 {
        return Err(Fault::BadAddress { level: leaf });
    }
    if entry & TABLE != TABLE || entry & ACCESS_FLAG == 0 || entry & !(mask | LEAF_FLAGS) != 0 {
        return Err(Fault::UnsupportedDescriptor { level: leaf });
    }
    let base = entry & mask;
    let flags = Flags::decode(entry).ok_or(Fault::UnsupportedDescriptor { level: leaf })?;
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
/// (firmware, GPU), from the pinned Asahi `pgtable.rs` protection constants
/// and m1n1 `hw/uat.py` `PTE.access_fw`/`access_gpu` (commit
/// 25b1d89ca50be848b136ce771ce7167244852a91). `None` marks an uncertain
/// permission: firmware on the shared write-only combination, or a page
/// without the GPU-access bit (firmware EL/GL permissions differ there).
fn permits(flags: &Flags, agent: Agent) -> Option<Permits> {
    if !flags.gpu_access {
        return match agent {
            Agent::Firmware => None,
            Agent::Gpu => NONE,
        };
    }
    let (firmware, gpu) = match (flags.access, flags.uxn, flags.pxn) {
        (Access::FirmwareGpu, false, false) => (NONE, NONE),
        (Access::FirmwareGpu, false, true) => (RO, RO),
        (Access::FirmwareGpu, true, false) => (None, WO),
        (Access::FirmwareGpu, true, true) => (RW, RW),
        (Access::Firmware, false, false) => (RO, NONE),
        (Access::Firmware, false, true) => (NONE, NONE),
        (Access::Firmware, true, false) => (RW, NONE),
        (Access::Firmware, true, true) => (RW, RO),
        (Access::Gpu, false, false) => (NONE, RO),
        (Access::Gpu, false, true) => (NONE, WO),
        (Access::Gpu, true, false) => (NONE, RW),
        (Access::Gpu, true, true) | (Access::None, _, _) => (NONE, NONE),
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
#[derive(Debug)]
pub struct Uat {
    available: bool,
    gpu_available: Rc<Cell<bool>>,
    /// The address field of an entry ([`output_mask`]).
    output: u64,
    ttbat: Option<u64>,
    /// The page-directory page of the shared TTBR1 window.
    shared_l2: Option<u64>,
    last_fault: Option<FaultRecord>,
}

impl Uat {
    /// A translator whose output addresses are `output_bits` wide
    /// ([`super::generation::Model::uat_output_bits`]).
    pub fn new(output_bits: u32) -> Self {
        Self {
            available: true,
            gpu_available: Rc::new(Cell::new(true)),
            output: output_mask(output_bits),
            ttbat: None,
            shared_l2: None,
            last_fault: None,
        }
    }

    /// Physical SGX lifecycle gates every firmware and GPU agent view,
    /// independently of its retained translation roots and mappings.
    pub(super) fn set_available(&mut self, available: bool) {
        self.available = available;
    }

    /// Native GPU power gates execution without preventing the firmware
    /// agent from completing its retained wake/restore accesses.
    pub(super) fn set_gpu_availability(&mut self, available: Rc<Cell<bool>>) {
        self.gpu_available = available;
    }

    /// Whether `address` is a 16 KiB-aligned output address.
    fn outputs(&self, address: u64) -> bool {
        address & !self.output == 0
    }

    /// The TTBAT's physical base, once configured.
    pub fn ttbat(&self) -> Option<u64> {
        self.ttbat
    }

    /// Root the translator at a 16 KiB-aligned TTBAT.
    pub fn configure(&mut self, ttbat: u64) -> Result<(), &'static str> {
        if !self.outputs(ttbat) {
            return Err("UAT TTBAT base is not an aligned output address");
        }
        self.ttbat = Some(ttbat);
        Ok(())
    }

    /// Resolve the shared TTBR1 window ([`SHARED_INDEX`]) of every context
    /// from the 16 KiB-aligned page-directory page `l2`.
    pub fn share_kernel_window(&mut self, l2: u64) -> Result<(), &'static str> {
        if !self.outputs(l2) || l2 == 0 {
            return Err("UAT shared L2 is not an aligned output address");
        }
        self.shared_l2 = Some(l2);
        Ok(())
    }

    /// The shared TTBR1 window's page-directory page, once configured.
    #[cfg(test)]
    pub fn shared_l2(&self) -> Option<u64> {
        self.shared_l2
    }

    /// The last fault, if any.
    pub fn last_fault(&self) -> Option<FaultRecord> {
        self.last_fault
    }

    /// The translator as `agent` sees it, for a [`stela_contracts::dma::Port`].
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
        // Reject a noncanonical VA before it can select or read a root.
        if let Err(fault) = in_range(iova) {
            return Err(self.record(agent, context, iova, write, fault));
        }
        let ttbr = match self.root(memory, context, iova) {
            Ok(ttbr) => ttbr,
            Err(DmaError::Memory) => {
                return Err(self.record(agent, context, iova, write, Fault::Memory { level: 0 }));
            }
            Err(error) => return Err(error),
        };
        if ttbr & VALID == 0 {
            return Err(self.record(agent, context, iova, write, Fault::NotPresent { level: 0 }));
        }
        if (ttbr >> CONTEXT_SHIFT) & CONTEXT_MASK != context as u64 {
            return Err(DmaError::Unsupported(
                "UAT TTBAT entry tagged with another context",
            ));
        }
        if ttbr & TTBAT_ADDRESS & !self.output != 0 {
            return Err(self.record(agent, context, iova, write, Fault::BadAddress { level: 0 }));
        }
        if ttbr & !(self.output | TTBAT_CONTEXT | VALID) != 0 {
            return Err(DmaError::Unsupported(
                "UAT TTBAT entry has unsupported low address bits",
            ));
        }
        let (half, idx) = indices(iova);
        let shared = (half == Half::Ttbr1 && idx[0] == SHARED_INDEX)
            .then_some(self.shared_l2)
            .flatten();
        let walked = match shared {
            Some(l2) => walk_from(memory, l2, 1, &idx, iova, self.output),
            None => walk_from(memory, ttbr & self.output, 0, &idx, iova, self.output),
        };
        let mapping = match walked {
            Ok(mapping) => mapping,
            Err(fault) => return Err(self.record(agent, context, iova, write, fault)),
        };
        let permits = permits(&mapping.flags, agent).ok_or(DmaError::Unsupported(
            "UAT leaf permission encoding not modeled for this agent",
        ))?;
        if !(if write { permits.write } else { permits.read }) {
            return Err(self.record(agent, context, iova, write, Fault::Permission));
        }
        Ok(mapping.physical)
    }

    /// Preserve the diagnostic reason independently of whether the device
    /// boundary reports a hardware fault, inaccessible RAM or a model limit.
    fn record(
        &mut self,
        agent: Agent,
        context: usize,
        address: u64,
        write: bool,
        fault: Fault,
    ) -> DmaError {
        self.last_fault = Some(FaultRecord {
            agent,
            context,
            address,
            write,
            fault,
        });
        match fault {
            Fault::Memory { .. } => DmaError::Memory,
            Fault::UnsupportedDescriptor { .. } => {
                DmaError::Unsupported("UAT descriptor type, flags or attributes are not modeled")
            }
            Fault::Permission => DmaError::Fault(FAULT_PERMISSION),
            _ => DmaError::Fault(FAULT_TRANSLATION),
        }
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
        if !self.uat.available {
            return Err(DmaError::Unsupported(
                "SGX DMA while PMGR inhibits execution",
            ));
        }
        debug_assert!(last >= iova && last >> PAGE_SHIFT == iova >> PAGE_SHIFT);
        // A GPU stream is the GPU's units in that context, whichever view
        // carries it.
        let (agent, context) = if stream & GPU_STREAM != 0 {
            (Agent::Gpu, stream & !GPU_STREAM)
        } else {
            (self.agent, stream)
        };
        if agent == Agent::Gpu && !self.uat.gpu_available.get() {
            return Err(DmaError::Unsupported(
                "GPU DMA while native Fender sleep inhibits execution",
            ));
        }
        self.uat.walk(memory, agent, context, iova, write)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_contracts::dma::test_support::Ram;

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
            encode_pte(0x1_2345_c000, &demo_flags()) & output_mask(40),
            0x12345c000
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
        let got = translate(&mut ram, pce, 0x20, 40).unwrap();
        assert_eq!(got.physical, page | 0x20);
        assert_eq!(got.flags, flags);
        // An unmapped sibling leaf faults as not-present at the leaf level.
        assert_eq!(
            translate(&mut ram, pce, PAGE_BYTES, 40),
            Err(Fault::NotPresent { level: 2 })
        );
        // Bits above the 39-bit space must repeat the TTBR-select bit.
        assert_eq!(
            translate(&mut ram, pce, 1 << 40, 40),
            Err(Fault::OutOfRange)
        );
        assert_eq!(
            translate(&mut ram, pce, TTBR_SELECT_BIT, 40),
            Err(Fault::OutOfRange)
        );
        // A missing top-level table reads as zero and faults present at 0.
        ram.put_u64(pce, 0);
        assert_eq!(
            translate(&mut ram, pce, 0, 40),
            Err(Fault::NotPresent { level: 0 })
        );
    }

    #[test]
    fn a_table_outside_ram_faults_on_memory() {
        let mut ram = Ram::new(0x8_0000_0000, 0x4000);
        // PCE points at a table far outside the RAM region.
        ram.put_u64(0x8_0000_0000, encode_table(0x9_0000_0000));
        assert_eq!(
            translate(&mut ram, 0x8_0000_0000, 0, 40),
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
        let mut uat = Uat::new(40);
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
        use stela_contracts::dma::Port;
        use stela_contracts::interrupt::InterruptLatch;
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
        // A firmware-RW page denies GPU accesses.
        assert_eq!(
            port_read(&mut uat, Agent::Gpu, &mut ram, 0, va),
            Err(DmaError::Fault(FAULT_PERMISSION))
        );
        // A context past the TTBAT refuses.
        assert!(matches!(
            port_read(&mut uat, Agent::Firmware, &mut ram, CONTEXTS, va),
            Err(DmaError::Unsupported(_))
        ));
    }

    #[test]
    fn every_context_shares_the_kernel_window_through_the_shared_l2() {
        // Contexts 0 and 3 with empty TTBR1 roots; the shared L2 maps one
        // page of the window for both, firmware and GPU alike.
        let base = 0x8_0000_0000;
        let mut ram = Ram::new(base, 0x4000 * 6);
        let (ttbat, root0, root3, l2, pte, page) = (
            base,
            base + 0x4000,
            base + 0x8000,
            base + 0xc000,
            base + 0x1_0000,
            base + 0x1_4000,
        );
        for (context, root) in [(0u16, root0), (3, root3)] {
            let [ttbr0, ttbr1] = encode_gptbat(context, root, root);
            ram.put_u64(ttbat + u64::from(context) * 16, ttbr0);
            ram.put_u64(ttbat + u64::from(context) * 16 + 8, ttbr1);
        }
        let va = 0xffff_ffa0_0000_4000;
        let (_, idx) = indices(va);
        assert_eq!(idx[0], SHARED_INDEX);
        let flags = Flags {
            access: Access::FirmwareGpu,
            uxn: true,
            pxn: true,
            ..demo_flags()
        };
        ram.put_u64(l2 + idx[1] as u64 * 8, encode_table(pte));
        ram.put_u64(pte + idx[2] as u64 * 8, encode_pte(page, &flags));
        ram.put_u64(page, 0x5157_e1a0);
        let mut uat = Uat::new(40);
        uat.configure(ttbat).unwrap();
        // Before the boot stage names the shared L2, the window faults.
        assert_eq!(
            port_read(&mut uat, Agent::Firmware, &mut ram, 0, va),
            Err(DmaError::Fault(FAULT_TRANSLATION))
        );
        uat.share_kernel_window(l2).unwrap();
        assert_eq!(uat.shared_l2(), Some(l2));
        assert_eq!(
            port_read(&mut uat, Agent::Firmware, &mut ram, 0, va),
            Ok(0x5157_e1a0)
        );
        assert_eq!(
            port_read(&mut uat, Agent::Gpu, &mut ram, 3, va),
            Ok(0x5157_e1a0)
        );
        // TTBR1 outside the window still walks the context's own root.
        assert_eq!(
            port_read(
                &mut uat,
                Agent::Firmware,
                &mut ram,
                0,
                0xffff_ff80_0000_4000
            ),
            Err(DmaError::Fault(FAULT_TRANSLATION))
        );
        assert_eq!(
            uat.last_fault().map(|fault| fault.fault),
            Some(Fault::NotPresent { level: 0 })
        );
        // An invalid TTBAT entry still refuses the context.
        ram.put_u64(ttbat + 3 * 16 + 8, 0);
        assert_eq!(
            port_read(&mut uat, Agent::Gpu, &mut ram, 3, va),
            Err(DmaError::Fault(FAULT_TRANSLATION))
        );
        assert!(uat.share_kernel_window(0).is_err());
        assert!(uat.share_kernel_window(1 << 40).is_err());
    }

    #[test]
    fn physical_gate_prevents_a_real_agent_walk_and_retains_the_mapping() {
        let (mut ram, mut uat, va, page) = firmware_space(shared(Access::FirmwareGpu, true, true));
        ram.put_u64(page, 0x12345678);
        assert_eq!(
            port_read(&mut uat, Agent::Firmware, &mut ram, FIRMWARE_CONTEXT, va),
            Ok(0x12345678)
        );
        uat.set_available(false);
        for agent in [Agent::Firmware, Agent::Gpu] {
            assert_eq!(
                port_read(&mut uat, agent, &mut ram, FIRMWARE_CONTEXT, va),
                Err(DmaError::Unsupported(
                    "SGX DMA while PMGR inhibits execution"
                ))
            );
        }
        uat.set_available(true);
        assert_eq!(
            port_read(&mut uat, Agent::Firmware, &mut ram, FIRMWARE_CONTEXT, va),
            Ok(0x12345678)
        );
    }

    #[test]
    fn the_coprocessor_port_reaches_a_context_with_gpu_permissions() {
        // Context 0's TTBR0 maps a GPU-RW page (AP 2, UXN 1, PXN 0): the
        // firmware's own accesses are denied there, while the GPU stream
        // of the same context reads it.
        let base = 0x8_0000_0000;
        let mut ram = Ram::new(base, 0x4000 * 6);
        let (ttbat, pce, pde, pte, page) = (
            base,
            base + 0x4000,
            base + 0x8000,
            base + 0xc000,
            base + 0x1_0000,
        );
        let [ttbr0, ttbr1] = encode_gptbat(5, pce, pce);
        ram.put_u64(ttbat + 5 * 16, ttbr0);
        ram.put_u64(ttbat + 5 * 16 + 8, ttbr1);
        let va = 0x11_0000_4000;
        let (_, idx) = indices(va);
        ram.put_u64(pce + idx[0] as u64 * 8, encode_table(pde));
        ram.put_u64(pde + idx[1] as u64 * 8, encode_table(pte));
        let flags = shared(Access::Gpu, true, false);
        ram.put_u64(pte + idx[2] as u64 * 8, encode_pte(page, &flags));
        ram.put_u64(page + 8, 0xa6e5);
        let mut uat = Uat::new(40);
        uat.configure(ttbat).unwrap();
        assert_eq!(
            port_read(&mut uat, Agent::Firmware, &mut ram, 5, va + 8),
            Err(DmaError::Fault(FAULT_PERMISSION))
        );
        assert_eq!(
            port_read(
                &mut uat,
                Agent::Firmware,
                &mut ram,
                gpu_stream(5).unwrap(),
                va + 8
            ),
            Ok(0xa6e5)
        );
        // An unmapped GPU address faults and is recorded as the GPU's.
        assert_eq!(
            port_read(
                &mut uat,
                Agent::Firmware,
                &mut ram,
                gpu_stream(5).unwrap(),
                0x4000
            ),
            Err(DmaError::Fault(FAULT_TRANSLATION))
        );
        let fault = uat.last_fault().unwrap();
        assert_eq!(
            (fault.agent, fault.context, fault.address),
            (Agent::Gpu, 5, 0x4000)
        );
        // The context tag must still match, and the context fit the TTBAT.
        assert!(matches!(
            port_read(
                &mut uat,
                Agent::Firmware,
                &mut ram,
                gpu_stream(4).unwrap(),
                va
            ),
            Err(DmaError::Fault(FAULT_TRANSLATION))
        ));
        assert!(matches!(
            gpu_stream(CONTEXTS),
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
        use stela_contracts::interrupt::InterruptLatch;
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
        let mut uat = Uat::new(40);
        let mut ram = Ram::new(0x8_0000_0000, 0x4000);
        assert!(matches!(
            port_read(&mut uat, Agent::Firmware, &mut ram, 0, 0),
            Err(DmaError::Unsupported(_))
        ));
        assert!(uat.configure(0x8_0000_0100).is_err());
        assert!(uat.configure(1 << 40).is_err());
        assert!(Uat::new(42).configure(1 << 40).is_ok());
    }

    /// T600x and T602x DRAM lies at 1 TiB: their 42-bit entries reach it,
    /// where a 40-bit translator would drop the address's top bits.
    #[test]
    fn a_42_bit_translator_reaches_dram_above_one_tebibyte() {
        let base = 0x100_0000_0000;
        let mut ram = Ram::new(base, 0x4000 * 4);
        let (pce, pde, pte, page) = (base, base + 0x4000, base + 0x8000, base + 0xc000);
        ram.put_u64(pce, encode_table(pde));
        ram.put_u64(pde, encode_table(pte));
        ram.put_u64(pte, encode_pte(page, &demo_flags()));
        assert_eq!(
            translate(&mut ram, pce, 0x10, 42).unwrap().physical,
            page | 0x10
        );
        assert!(translate(&mut ram, pce, 0x10, 40).is_err());
    }

    #[test]
    fn an_output_address_past_the_profile_never_aliases_a_lower_page() {
        // This catches masking a malformed high PA down to a valid table
        // or target. Exercise every descriptor level on both profile widths.
        for bits in [40, 42] {
            let base = 0x8_0000_0000;
            let mut ram = Ram::new(base, 4 * PAGE_BYTES as usize);
            let entries = [base, base + PAGE_BYTES, base + 2 * PAGE_BYTES];
            let valid = [
                encode_table(entries[1]),
                encode_table(entries[2]),
                encode_pte(base + 3 * PAGE_BYTES, &demo_flags()),
            ];
            for (address, entry) in entries.into_iter().zip(valid) {
                ram.put_u64(address, entry);
            }
            for (level, address) in entries.into_iter().enumerate() {
                ram.put_u64(address, valid[level] | 1 << bits);
                assert_eq!(
                    translate(&mut ram, base, 0, bits),
                    Err(Fault::BadAddress {
                        level: level as u32
                    })
                );
                ram.put_u64(address, valid[level]);
            }
            for root in [base | 8, base | 1 << bits] {
                assert_eq!(
                    translate(&mut ram, root, 0, bits),
                    Err(Fault::BadAddress { level: 0 })
                );
            }
            assert_eq!(
                translate(&mut ram, base, 0, bits).unwrap().physical,
                base + 3 * PAGE_BYTES
            );
        }
    }

    #[test]
    fn unsupported_descriptors_are_not_successful_page_mappings() {
        let base = 0x8_0000_0000;
        let mut ram = Ram::new(base, 4 * PAGE_BYTES as usize);
        let entries = [base, base + PAGE_BYTES, base + 2 * PAGE_BYTES];
        let valid = [
            encode_table(entries[1]),
            encode_table(entries[2]),
            encode_pte(base + 3 * PAGE_BYTES, &demo_flags()),
        ];
        for (address, entry) in entries.into_iter().zip(valid) {
            ram.put_u64(address, entry);
        }
        for (level, address) in entries.into_iter().enumerate() {
            // Block descriptors, unknown low flags, and unknown high flags
            // have no implemented effects. Keep them explicit model limits.
            for bad in [
                valid[level] & !2,
                valid[level] | 1 << 12,
                valid[level] | 1 << 63,
            ] {
                ram.put_u64(address, bad);
                assert_eq!(
                    translate(&mut ram, base, 0, 40),
                    Err(Fault::UnsupportedDescriptor {
                        level: level as u32
                    })
                );
            }
            ram.put_u64(address, valid[level]);
        }
        for bad in [valid[2] & !ACCESS_FLAG, valid[2] | ATTR_MASK] {
            ram.put_u64(entries[2], bad);
            assert_eq!(
                translate(&mut ram, base, 0, 40),
                Err(Fault::UnsupportedDescriptor { level: 2 })
            );
        }
    }

    #[test]
    fn malformed_roots_and_unreadable_tables_preserve_fault_diagnostics() {
        let flags = shared(Access::FirmwareGpu, true, true);
        for level in 0..3 {
            let (mut ram, mut uat, va, _) = firmware_space(flags);
            let ttbat = ram.base;
            let root = ttbat + PAGE_BYTES;
            let (_, idx) = indices(va);
            let missing = ttbat + 10 * PAGE_BYTES;
            let at = match level {
                0 => {
                    uat.configure(missing).unwrap();
                    None
                }
                1 => Some(root + idx[0] as u64 * ENTRY_BYTES),
                _ => Some(root + PAGE_BYTES + idx[1] as u64 * ENTRY_BYTES),
            };
            if let Some(at) = at {
                ram.put_u64(at, encode_table(missing));
            }
            assert_eq!(
                port_read(&mut uat, Agent::Gpu, &mut ram, 0, va),
                Err(DmaError::Memory)
            );
            assert_eq!(
                uat.last_fault(),
                Some(FaultRecord {
                    agent: Agent::Gpu,
                    context: 0,
                    address: va,
                    write: false,
                    fault: Fault::Memory { level },
                })
            );
        }
        let (mut ram, mut uat, va, _) = firmware_space(flags);
        let root_word = ram.base + 8;
        let valid = encode_gptbat(0, 0, ram.base + PAGE_BYTES)[1];
        ram.put_u64(root_word, valid | 1 << 40);
        assert_eq!(
            port_read(&mut uat, Agent::Firmware, &mut ram, 0, va),
            Err(DmaError::Fault(FAULT_TRANSLATION))
        );
        assert_eq!(
            uat.last_fault().unwrap().fault,
            Fault::BadAddress { level: 0 }
        );
        for invalid in [valid | 2, valid | 1 << 56] {
            ram.put_u64(root_word, invalid);
            assert!(matches!(
                port_read(&mut uat, Agent::Firmware, &mut ram, 0, va),
                Err(DmaError::Unsupported(_))
            ));
        }
    }

    #[test]
    fn noncanonical_inputs_are_rejected_before_any_memory_access() {
        struct Inaccessible;
        impl Memory for Inaccessible {
            fn read(&mut self, _: u64, _: &mut [u8]) -> bool {
                panic!("a malformed VA must not reach physical memory");
            }
            fn write(&mut self, _: u64, _: &[u8]) -> bool {
                panic!("a malformed VA must not reach physical memory");
            }
        }
        let mut memory = Inaccessible;
        let mut uat = Uat::new(40);
        uat.configure(0x8_0000_0000).unwrap();
        for va in [
            TTBR_SELECT_BIT,
            1 << 40,
            0xffff_ffff_ffff & !TTBR_SELECT_BIT,
        ] {
            assert_eq!(
                uat.walk(&mut memory, Agent::Gpu, 0, va, true),
                Err(DmaError::Fault(FAULT_TRANSLATION))
            );
            assert_eq!(
                uat.last_fault(),
                Some(FaultRecord {
                    agent: Agent::Gpu,
                    context: 0,
                    address: va,
                    write: true,
                    fault: Fault::OutOfRange,
                })
            );
        }
    }

    #[test]
    fn firmware_owned_mappings_never_grant_gpu_access() {
        for access in [
            Access::FirmwareGpu,
            Access::Firmware,
            Access::Gpu,
            Access::None,
        ] {
            for xn in 0..4 {
                let flags = Flags {
                    gpu_access: false,
                    ..shared(access, xn & 2 != 0, xn & 1 != 0)
                };
                let (mut ram, mut uat, va, _) = firmware_space(flags);
                assert_eq!(
                    port_read(&mut uat, Agent::Gpu, &mut ram, 0, va),
                    Err(DmaError::Fault(FAULT_PERMISSION))
                );
            }
        }
    }

    #[test]
    fn protection_table_enforces_each_agent_and_direction_without_writing_denied_memory() {
        use stela_contracts::dma::Port;
        use stela_contracts::interrupt::InterruptLatch;
        // Independent permission tables in m1n1 PTE.access_fw/access_gpu,
        // OS=1, AP rows and (UXN << 1 | PXN) columns. 1=read, 2=write;
        // None is its uncertain firmware "-?" entry.
        let firmware = [
            [Some(0), Some(1), None, Some(3)],
            [Some(1), Some(0), Some(3), Some(3)],
            [Some(0); 4],
            [Some(0); 4],
        ];
        let gpu = [[0, 1, 2, 3], [0, 0, 0, 1], [1, 2, 3, 0], [0; 4]];
        for ap in 0..4 {
            for xn in 0..4 {
                for agent in [Agent::Firmware, Agent::Gpu] {
                    let expected = match agent {
                        Agent::Firmware => firmware[ap][xn],
                        Agent::Gpu => Some(gpu[ap][xn]),
                    };
                    for write in [false, true] {
                        let flags = shared(
                            Access::from_bits(ap as u64).unwrap(),
                            xn & 2 != 0,
                            xn & 1 != 0,
                        );
                        let (mut ram, mut uat, va, page) = firmware_space(flags);
                        ram.put_u64(page, 0xaabb_ccdd);
                        let before = ram.bytes.clone();
                        let mut latch = InterruptLatch::new();
                        let mut access = BusAccess::new(0, 0, &mut latch);
                        let mut view = uat.agent(agent);
                        let mut port = Port {
                            iommu: &mut view,
                            stream: 0,
                            memory: &mut ram,
                            access: &mut access,
                        };
                        let mut buffer = [0; 8];
                        let result = if write {
                            port.write(va, &0x1234u64.to_le_bytes())
                        } else {
                            port.read(va, &mut buffer)
                        };
                        match expected {
                            None => assert!(matches!(result, Err(DmaError::Unsupported(_)))),
                            Some(bits) if bits & if write { 2 } else { 1 } == 0 => {
                                assert_eq!(result, Err(DmaError::Fault(FAULT_PERMISSION)));
                                assert_eq!(uat.last_fault().unwrap().write, write);
                            }
                            Some(_) => {
                                assert_eq!(result, Ok(()));
                                if !write {
                                    assert_eq!(u64::from_le_bytes(buffer), 0xaabb_ccdd);
                                }
                            }
                        }
                        if result.is_err() || !write {
                            assert_eq!(ram.bytes, before);
                        }
                    }
                }
            }
        }
    }
}
