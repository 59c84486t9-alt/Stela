//! The Apple DART of T8110 layout (`dart,t8110`; ADT `/arm-io/dart-*`), the
//! IOMMU through which a device's stream (SID) reaches RAM.
//!
//! Documented by Linux `drivers/iommu/apple-dart.c` and `io-pgtable-dart.c`
//! (Asahi), registers 32-bit:
//! - PARAMS1 (0x00): access region protection 31 (below) and the page
//!   size's shift in [27:24]; PARAMS2 (0x04):
//!   BYPASS_SUPPORT 0; PARAMS3 (0x08): PA_WIDTH [29:24], VA_WIDTH [21:16]
//!   and the hardware version, major [15:8] and minor [7:0]; PARAMS4
//!   (0x0c): NUM_SIDS [8:0]. The 26A434 J473AP `AppleT8110DART::
//!   _dartValidateConfig` panics unless the shift is 14 (16 KiB pages) and,
//!   for a stream its DeviceTree has bypass, unless bypass is supported.
//!   Its `_hwVersion` accepts versions 1.0, 1.1, 2.0 to 2.4 and 3.0, and
//!   SPTM's `t8110dart_init_instance` also 3.2; SPTM requires a VA space
//!   above 40 bits from version 2 on, so this two-level DART of 36-bit VAs
//!   (and 42-bit PAs, its entries' address field) reports version 1.0.
//! - TLB_CMD (0x80): BUSY 31, OP [10:8] (0 flush all, 1 flush one stream;
//!   SPTM also issues 2 and 4, see `TLB_OPS`),
//!   STREAM [7:0]; SPTM's completion barrier at 0x600/0x604 (`TLB_SYNC`).
//! - ERROR (0x100): FLAG 31, STREAM [27:20], CODE [14:0] (READ_FAULT 5,
//!   WRITE_FAULT 4, NO_PTE 3, NO_PMD 2, NO_PGD 1, NO_TTBR 0) and region
//!   protect 29 (below); software
//!   writes back what it read to clear it; SPTM also writes only the code.
//!   ERROR_MASK (0x104), ERROR_ADDR_LO
//!   and _HI (0x170, 0x174) and the per-stream ERROR_STREAMS bitmap (0x1c0),
//!   which software clears by writing ones.
//! - PROTECT, UNPROTECT and PROTECT_LOCK (0x200, 0x204, 0x208), whose
//!   TTBR_TCR bit 0 locks every stream's TCR and TTBR.
//! - ENABLE_STREAMS and DISABLE_STREAMS (0xc00, 0xc20): bitmaps setting and
//!   clearing which streams may access memory at all.
//! - Per stream, TCR (0x1000 + 4 × SID: TRANSLATE_ENABLE 0, BYPASS_DART 1,
//!   BYPASS_DAPF 2, FOUR_LEVEL 3, REMAP_EN 7, REMAP [11:8]) and one TTBR
//!   (0x1400 + 4 × SID: VALID 0, the table's address >> 14 from bit 2).
//! - Tables of 2048 eight-byte entries in 16 KiB pages: a TTBR's table maps
//!   IOVA [35:25] to tables that map [24:14] to pages, unless FOUR_LEVEL adds
//!   a level. An entry is VALID 0, with its target's address >> 4 in
//!   [37:10]; a page entry adds NO_WRITE 2, NO_READ 3 and the first and last
//!   accessible 4-byte unit of the page in [63:52] and [51:40].
//!
//! A DART may pair with an address permission filter (`instance` `DAPF`,
//! the node's second `reg`): `n-apfs-instance-0` slices of 0x40 bytes, each a
//! 32-bit control (`0x333` meaningful), the first and last address as two
//! 32-bit halves at 0x08 and 0x10, and a 256-bit bitmap of the streams it
//! applies to at 0x20. The 26A434 J473AP SPTM programs every slice from
//! `dapf-instance-0` while PROTECT bit 2 (APF) is clear, then writes 4 to
//! PROTECT and PROTECT_LOCK, and verifies instead of writing once both read
//! bit 2 set (`t8110dart` power-up and `t8110dart_write_dapf_reg`). PROTECT
//! and PROTECT_LOCK hold one bit per protection domain: 0 TTBR and TCR, 2
//! APF; a write sets bits, UNPROTECT clears those not locked.
//!
//! SPTM's `t8110dart_powerup` (26A434 file offset 0xcbb90, store at
//! 0xcc014) restores the protected-write word at +0x210. Stela's handoff
//! disables that policy and has no protected-write violation, so a full-word
//! zero write/read succeeds. Nonzero policy encodings remain unsupported;
//! the status test of bit 1 on newer revisions alone does not describe how
//! to enable or acknowledge it. This register is separate from PROTECT.
//! The transaction-limit configuration at +0x228/+0x22c is saved on resume
//! (0xcc678..0xcc684), restored through the write-or-verify helper
//! (0xcc9cc..0xcc9f0), and clamped to zero by `clamp_tlimits`
//! (0xc8bd0..0xc8be0). Each full-word value retains writes, initially zero.
//! DMA is synchronous with no outstanding transaction queue, so the clamp
//! has no queued transaction to drain; no physical credit rate is invented.
//!
//! Power-cycle evidence: SPTM saves enabled-stream words and optional
//! performance state before power-down (file 0xcd47c..0xcd7c4) and restores
//! TCR/TTBR, APF, interrupt masks and enabled words on power-up
//! (0xcc3d0..0xcc9bc). Linux `apple_dart_suspend`/`apple_dart_resume` also
//! save and restore stream tables around reset. Inferred: ordinary state is
//! lost on a PMGR power gate unless the DT declares `retention`; clock gating
//! preserves it. MMIO and DMA to an unpowered DART refuse. Secure TZ words
//! survive: SPTM checks PROTECT/LOCK bits 3 and 4, +504 select bit0, +500
//! enable bits 2:0 and nine region words at +508..548, stride8, masked with
//! 0x3ffffffc (0xcc038..0xcc13c), before restoring ordinary registers.
//! Stela establishes disabled zero zones in that boot-owned bank. Active TZ
//! programming remains unsupported, so PARAMS2 does not advertise it. The
//! recovered conditional path does not justify enabling that capability.
//!
//! Inferred, not documented: the model caches no translations, so TLB
//! commands complete at once and BUSY never reads set; a fault latches the
//! first error until software acknowledges its FLAG or code, and the interrupt follows
//! FLAG with an unmasked code; a missing first-level entry is NO_PMD and a
//! missing page entry NO_PTE; an access to a stream not enabled, without
//! translation or out of the 36-bit space faults NO_TTBR; while TTBR_TCR is
//! protected, TCR and TTBR writes have no effect, and PROTECT_LOCK keeps it
//! protected; likewise APF protection makes the filter's slices read-only.
//! The filter's slices are SoC register windows a coprocessor's own firmware
//! reaches; the machine's device models make no such accesses, so a
//! transfer on a stream that does not bypass a present filter refuses
//! rather than pass unfiltered.
//!
//! Access region protection is the page entries' accessible-unit bounds.
//! 26A434 `AppleT8110DART` reads the DeviceTree `dart-options` word
//! (`IODARTFamily` file 0x3b55130..0x3b551c0); its bit 1 asks for access
//! region protection, and the instance validation (file 0x2f1d6a4) panics
//! "access region protection is incorrectly configured" unless PARAMS1 bit
//! 31 reports it (J473AP `dart-usb0` sets the option). With the option the
//! driver maps start/end ranges at its `protection-granularity` within a
//! page (0x2f15774) and names ERROR bit 29 "region protect" (0x2f16fe4),
//! beside bits 4 and 5, write and read protect. Inferred: an access outside
//! a page's bounds reports bit 29 after the entry's NO_READ/NO_WRITE
//! checks, and bit 29 masks and signals like CODE. The identification
//! fields not listed above (PARAMS2 bit 4, PARAMS4 NUM_CLIENTS) read 0; FOUR_LEVEL
//! and REMAP_EN are refused until their behavior is known.
//!
//! Full family evidence, capability gates and qualification gaps are in
//! `docs/research/dart-iommu.md`. The paired SMMU view exposes the capture
//! count of this cacheless implementation, not a physical chip's dump.
use super::super::bus::{Access, Direction, MmioDevice, MmioError, Width, refuse};
use super::super::interrupt::{AicInput, Wire};
use super::descriptor::Format;
use super::{DAPF_BYTES, DAPF_OFFSET, Fault, SMMU_BYTES, SMMU_OFFSET, SmmuBlock};
use crate::platform::dma::{DmaError, Iommu, Memory};
#[cfg(not(feature = "std"))]
use alloc::vec;
use alloc::{rc::Rc, vec::Vec};
use core::cell::RefCell;

const NAME: &str = "dart-t8110";

const PARAMS1: u64 = 0x00;
const PARAMS2: u64 = 0x04;
/// PARAMS1: access region protection (page entries' accessible-unit
/// bounds) and the page shift, 16 KiB pages.
const PARAMS1_VALUE: u32 = REGION_PROTECTION | PAGE_SHIFT << 24;
const REGION_PROTECTION: u32 = 1 << 31;
/// PARAMS2: streams can bypass translation (TCR BYPASS_DART).
const BYPASS_SUPPORT: u32 = 1;
const PARAMS3: u64 = 0x08;
const PARAMS4: u64 = 0x0c;
/// PARAMS3: the PA and VA widths and version 1.0.
const PARAMS3_VALUE: u32 = PA_BITS << 24 | IOVA_BITS << 16 | 0x0100;
const TLB_CMD: u64 = 0x80;
const TLB_OP: u32 = 0x7 << 8;
const TLB_OP_FLUSH_ALL: u32 = 0;
const TLB_OP_FLUSH_STREAM: u32 = 1 << 8;
const TLB_STREAM: u32 = 0xff;
/// SPTM's invalidation requests (file 0xc8618..0xc8718): OP 0 and 4 on
/// every instance, OP 1 for one stream, optionally (bit 14) bounded by the
/// range words at +0x98/+0xa0, and OP 2 with its parameter at +0x84. Bits
/// 13 and 15 qualify a request further: SPTM's whole-DART flush is OP 0
/// with bit 13, and bit 15 too from version 2.2 on (file 0xcd7cc..0xcd7dc).
/// With no translation cached, each completes at once whatever subset it
/// names; the words are retained.
const TLB_OPS: [u32; 4] = [TLB_OP_FLUSH_ALL, TLB_OP_FLUSH_STREAM, 2 << 8, 4 << 8];
const TLB_QUALIFIERS: u32 = 1 << 13 | 1 << 14 | 1 << 15;
const TLB_PARAMETER: u64 = 0x84;
const TLB_RANGE: [u64; 2] = [0x98, 0xa0];
/// After a bit-15 request of OP 0 or 1, SPTM writes zero to +0x600 on each
/// instance whose descriptor asks for it (flag +0xc06, file 0xc8718..0xc8758)
/// and waits for bit 0 of +0x604 to clear (file 0xc8884..0xc8894): a
/// completion barrier for the invalidation. It completes with the request,
/// so the trigger reads zero and the status is never busy.
const TLB_SYNC: u64 = 0x600;
const TLB_SYNC_STATUS: u64 = 0x604;
const ERROR: u64 = 0x100;
const ERROR_MASK: u64 = 0x104;
const ERROR_ADDRESS_LOW: u64 = 0x170;
const ERROR_ADDRESS_HIGH: u64 = 0x174;
const ERROR_STREAMS: u64 = 0x1c0;
const PROTECT: u64 = 0x200;
const UNPROTECT: u64 = 0x204;
const PROTECT_LOCK: u64 = 0x208;
/// Protected-write control/status, restored by SPTM at file offset 0xcc014.
const PROTECTED_WRITE: u64 = 0x210;
const TLIMITS: [u64; 2] = [0x228, 0x22c];
/// Interrupt words of the version 2.1-and-earlier layout. SPTM's table
/// (file 0x159e0) gives ERROR_MASK 0x104 and these three; later versions
/// move them to 0x4060 and 0x4200..0x4220. 0x700 enables and 0x704
/// reports the performance counters' interrupts, bits 0x777 (SPTM's
/// clear-performance-interrupts call writes that mask at file 0xc9840;
/// power-up enables all and clears all, file 0xcc8f8..0xcc930; power-down
/// disables, 0xcd624). The counters (+0x760..0x788) exist only for a node
/// with `enable-perf-counters`, which no J473AP DART has: the counters are
/// absent here (their words refuse), so no counter interrupt is ever
/// pending. At 0x720 power-up writes one bit per stream from SPTM's set of
/// streams in use (file 0xcc948); whether these gate the error interrupt
/// per stream is unrecovered, so they are retained and the error
/// interrupt follows ERROR_MASK alone.
const PERF_INTERRUPT_ENABLE: u64 = 0x700;
const PERF_INTERRUPT_STATUS: u64 = 0x704;
const PERF_INTERRUPTS: u32 = 0x777;
const STREAM_INTERRUPTS: u64 = 0x720;
const ENABLE_STREAMS: u64 = 0xc00;
const DISABLE_STREAMS: u64 = 0xc20;
const TCR: u64 = 0x1000;
const TTBR: u64 = 0x1400;
/// Bitmap words of the 256 streams the layout addresses.
const STREAM_WORDS: u64 = 8;

const ERROR_FLAG: u32 = 1 << 31;
const ERROR_WRITE: u32 = 1 << 28;
const ERROR_STREAM_SHIFT: u32 = 20;
const ERROR_CODE: u32 = 0x7fff | Fault::Region as u32;
const PROTECT_TTBR_TCR: u32 = 1;
const PROTECT_APF: u32 = 1 << 2;
/// Secure translation-zone configuration is outside the switched DART state.
const PROTECT_TZ: u32 = (1 << 3) | (1 << 4);
const TZ_CONFIG: u64 = 0x500;
const TZ_SELECT: u64 = 0x504;
const TZ_FIRST: u64 = 0x508;
const TZ_END: u64 = 0x550;

const SLICE: u64 = 0x40;
const SLICE_CONTROL: u64 = 0x00;
const SLICE_START: u64 = 0x08;
const SLICE_END: u64 = 0x10;
const SLICE_STREAMS: u64 = 0x20;
const SLICE_CONTROL_KNOWN: u32 = 0x333;

const TCR_TRANSLATE: u32 = 1;
const TCR_BYPASS_DART: u32 = 1 << 1;
const TCR_BYPASS_DAPF: u32 = 1 << 2;
const TCR_FOUR_LEVEL: u32 = 1 << 3;
const TCR_REMAP_ENABLE: u32 = 1 << 7;
const TCR_REMAP: u32 = 0xf << 8;
const TCR_KNOWN: u32 = TCR_TRANSLATE
    | TCR_BYPASS_DART
    | TCR_BYPASS_DAPF
    | TCR_FOUR_LEVEL
    | TCR_REMAP_ENABLE
    | TCR_REMAP;
const TTBR_VALID: u32 = 1;
const TTBR_ADDRESS_SHIFT: u32 = 2;
/// The 28-bit page-number field, independently defined by m1n1's R_TTBR.
const TTBR_ADDRESS: u32 = 0x3fff_fffc;

const PAGE_SHIFT: u32 = 14;
const PAGE: u64 = 1 << PAGE_SHIFT;
const LEVEL_BITS: u32 = 11;
const IOVA_BITS: u32 = PAGE_SHIFT + 2 * LEVEL_BITS;
/// The PAs an entry's address field reaches.
const PA_BITS: u32 = (ENTRY_ADDRESS << ENTRY_ADDRESS_SHIFT).ilog2() + 1;
const ENTRY_VALID: u64 = 1;
const ENTRY_NO_WRITE: u64 = 1 << 2;
const ENTRY_NO_READ: u64 = 1 << 3;
const ENTRY_ADDRESS: u64 = 0x3f_ffff_fc00;
const ENTRY_ADDRESS_SHIFT: u32 = 4;
const SUBPAGE_UNIT: u64 = 4;

pub struct Dart {
    streams: usize,
    powered: bool,
    clock_enabled: bool,
    quiesced: bool,
    reset: bool,
    tlimits: [u32; 2],
    tlb_words: [u32; 3],
    tcr: Vec<u32>,
    ttbr: Vec<u32>,
    enabled: [u32; STREAM_WORDS as usize],
    perf_interrupts: u32,
    stream_interrupts: [u32; STREAM_WORDS as usize],
    error: u32,
    error_mask: u32,
    error_address: u64,
    error_streams: [u32; STREAM_WORDS as usize],
    protect: u32,
    locked: u32,
    /// The address permission filter's slices, when the DART has one.
    apf: Option<Vec<Slice>>,
    smmu: Option<SmmuBlock>,
    irq: Option<AicInput>,
    irq_level: bool,
    shared_fault: Option<(Rc<RefCell<Vec<bool>>>, usize)>,
}

/// One address permission filter slice, as its 32-bit registers hold it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Slice {
    control: u32,
    start: [u32; 2],
    end: [u32; 2],
    streams: [u32; STREAM_WORDS as usize],
}

impl Slice {
    fn register(&mut self, offset: u64) -> Option<(&mut u32, u32)> {
        let word = |base: u64| usize::try_from((offset - base) / 4).ok();
        match offset {
            SLICE_CONTROL => Some((&mut self.control, SLICE_CONTROL_KNOWN)),
            SLICE_START | 0x0c => Some((&mut self.start[word(SLICE_START)?], u32::MAX)),
            SLICE_END | 0x14 => Some((&mut self.end[word(SLICE_END)?], u32::MAX)),
            _ if (SLICE_STREAMS..SLICE).contains(&offset) => {
                Some((&mut self.streams[word(SLICE_STREAMS)?], u32::MAX))
            }
            _ => None,
        }
    }
}

impl Dart {
    pub(super) fn bind_shared_irq(&mut self, irq: &super::SharedIrq) -> Result<(), &'static str> {
        if self.irq != Some(irq.input) {
            return Err("DART shared IRQ does not match its physical input");
        }
        if self.irq_level
            || self
                .shared_fault
                .as_ref()
                .is_some_and(|(levels, _)| levels.borrow().iter().any(|&level| level))
        {
            return Err("an asserted DART IRQ source cannot be rebound");
        }
        self.shared_fault = Some(irq.source());
        Ok(())
    }

    pub(super) const fn stream_capacity(&self) -> usize {
        self.streams
    }

    /// A DART of `streams` streams (`sid-count`, at most 256), every stream
    /// disabled and untranslated, signalling faults on `irq`.
    pub fn new(streams: usize, irq: Option<AicInput>) -> Self {
        assert!(
            (1..=256).contains(&streams),
            "the T8110 layout addresses 1..256 streams"
        );
        Self {
            streams,
            powered: true,
            clock_enabled: true,
            quiesced: false,
            reset: false,
            tlimits: [0; 2],
            tlb_words: [0; 3],
            tcr: vec![0; streams],
            ttbr: vec![0; streams],
            enabled: [0; STREAM_WORDS as usize],
            perf_interrupts: 0,
            stream_interrupts: [0; STREAM_WORDS as usize],
            error: 0,
            error_mask: 0,
            error_address: 0,
            error_streams: [0; STREAM_WORDS as usize],
            protect: 0,
            locked: 0,
            apf: None,
            smmu: None,
            irq,
            irq_level: false,
            shared_fault: None,
        }
    }

    /// Independent TRAD instances sharing one level-sensitive fault output.
    /// The J473AP `dart-usb0` DT has two ranges and one `interrupts` cell.
    /// Clearing one instance cannot deassert another instance's pending fault.
    pub fn group(streams: usize, irq: Option<AicInput>, count: usize) -> Vec<Self> {
        let levels = Rc::new(RefCell::new(vec![false; count]));
        (0..count)
            .map(|index| {
                let mut dart = Self::new(streams, irq);
                dart.shared_fault = Some((levels.clone(), index));
                dart
            })
            .collect()
    }

    /// The DART with an address permission filter of `slices` slices.
    pub fn with_apf(mut self, slices: usize) -> Self {
        assert!(
            slices as u64 * SLICE <= DAPF_BYTES,
            "APF slices exceed the filter's registers"
        );
        self.apf = Some(vec![Slice::default(); slices]);
        self
    }

    /// Attach the view to an already placed TRAD. Returns false if already
    /// attached, so the machine can reject duplicate physical views. The
    /// device group's power, retention, quiesce and reset apply to both views.
    pub fn enable_smmu(&mut self) -> bool {
        if self.smmu.is_some() {
            return false;
        }
        self.smmu = Some(SmmuBlock);
        true
    }

    pub fn has_smmu(&self) -> bool {
        self.smmu.is_some()
    }

    /// Apply a PMGR supply transition. Clock gating keeps this state; a
    /// power gate resets ordinary registers unless the DT declares retention.
    /// Secure translation-zone configuration/protection remains outside the
    /// switched supply: SPTM verifies it before restoring ordinary state.
    pub fn set_power(&mut self, powered: bool, retention: bool, access: &mut Access<'_>) {
        if self.powered && !powered && !retention {
            self.clear_ordinary(access);
        }
        self.powered = powered;
    }

    /// Quiesce a bus master before resetting its domain. DMA is synchronous,
    /// so there are no outstanding transactions to drain. Configuration stays
    /// accessible until reset is asserted; releasing reset does not undo this
    /// separate inhibit. The machine applies PMGR transitions in order.
    pub fn set_quiesced(&mut self, quiesced: bool) {
        self.quiesced = quiesced;
    }

    pub fn set_clock(&mut self, enabled: bool) {
        self.clock_enabled = enabled;
    }

    /// Apply the ordinary register bank's reset line independently of power
    /// retention. Assertion clears ordinary state and faults; while held, MMIO
    /// and DMA refuse. The disabled secure-zone bank is boot-owned and outside
    /// this reset, as it is outside the switched ordinary power domain.
    pub fn set_reset(&mut self, asserted: bool, access: &mut Access<'_>) {
        if asserted && !self.reset {
            self.clear_ordinary(access);
        }
        self.reset = asserted;
    }

    fn clear_ordinary(&mut self, access: &mut Access<'_>) {
        self.tlimits.fill(0);
        self.tlb_words.fill(0);
        self.tcr.fill(0);
        self.ttbr.fill(0);
        self.enabled.fill(0);
        self.perf_interrupts = 0;
        self.stream_interrupts.fill(0);
        self.error = 0;
        self.error_mask = 0;
        self.error_address = 0;
        self.error_streams.fill(0);
        self.protect &= PROTECT_TZ;
        self.locked &= PROTECT_TZ;
        if let Some(apf) = &mut self.apf {
            apf.fill(Slice::default());
        }
        self.signal(access);
    }

    /// The protection domains this DART has.
    fn domains(&self) -> u32 {
        PROTECT_TTBR_TCR | PROTECT_TZ | if self.apf.is_some() { PROTECT_APF } else { 0 }
    }

    /// The filter register at `offset` from the filter's start and the bits
    /// it holds.
    fn apf_register(&mut self, offset: u64) -> Option<(&mut u32, u32)> {
        let slices = self.apf.as_mut()?;
        let slice = slices.get_mut(usize::try_from(offset / SLICE).ok()?)?;
        if !offset.is_multiple_of(4) {
            return None;
        }
        slice.register(offset % SLICE)
    }

    fn stream_enabled(&self, sid: usize) -> bool {
        self.enabled[sid / 32] >> (sid % 32) & 1 != 0
    }

    fn walk(
        &self,
        memory: &mut dyn Memory,
        sid: usize,
        iova: u64,
        last: u64,
        write: bool,
    ) -> Result<u64, DmaError> {
        if !self.powered {
            return Err(DmaError::Unsupported("DART power domain is off"));
        }
        if !self.clock_enabled {
            return Err(DmaError::Unsupported("DART functional clock is gated"));
        }
        if self.reset {
            return Err(DmaError::Unsupported("DART reset is asserted"));
        }
        if self.quiesced {
            return Err(DmaError::Unsupported("DART DMA is quiesced"));
        }
        if sid >= self.streams {
            return Err(DmaError::Unsupported(
                "DART incoming stream is outside the native profile",
            ));
        }
        if !self.stream_enabled(sid) {
            return Err(fault(Fault::NoTtbr));
        }
        let tcr = self.tcr[sid];
        if tcr & (TCR_BYPASS_DART | TCR_TRANSLATE) == TCR_BYPASS_DART | TCR_TRANSLATE {
            return Err(DmaError::Unsupported(
                "DART simultaneous translation and bypass",
            ));
        }
        if tcr & TCR_REMAP_ENABLE != 0 {
            return Err(DmaError::Unsupported("DART stream remapping"));
        }
        if self.apf.is_some() && tcr & TCR_BYPASS_DAPF == 0 {
            return Err(DmaError::Unsupported("DART address permission filtering"));
        }
        if tcr & TCR_BYPASS_DART != 0 {
            return Ok(iova);
        }
        if tcr & TCR_TRANSLATE == 0 || iova >> IOVA_BITS != 0 {
            return Err(fault(Fault::NoTtbr));
        }
        if tcr & TCR_FOUR_LEVEL != 0 {
            return Err(DmaError::Unsupported("four-level DART tables"));
        }
        let ttbr = self.ttbr[sid];
        if ttbr & TTBR_VALID == 0 {
            return Err(fault(Fault::NoTtbr));
        }
        let root = u64::from((ttbr & TTBR_ADDRESS) >> TTBR_ADDRESS_SHIFT) << PAGE_SHIFT;
        let first = entry(memory, root, iova >> (PAGE_SHIFT + LEVEL_BITS))?;
        if first & ENTRY_VALID == 0 {
            return Err(fault(Fault::NoPmd));
        }
        let page = entry(memory, target(first, false)?, iova >> PAGE_SHIFT)?;
        if page & ENTRY_VALID == 0 {
            return Err(fault(Fault::NoPte));
        }
        let target = target(page, true)?;
        let offset = iova & (PAGE - 1);
        let (first_unit, last_unit) = (page >> 52 & 0xfff, page >> 40 & 0xfff);
        let inside =
            offset / SUBPAGE_UNIT >= first_unit && (last & (PAGE - 1)) / SUBPAGE_UNIT <= last_unit;
        match write {
            true if page & ENTRY_NO_WRITE != 0 => Err(fault(Fault::Write)),
            false if page & ENTRY_NO_READ != 0 => Err(fault(Fault::Read)),
            _ if !inside => Err(fault(Fault::Region)),
            _ => Ok(target + offset),
        }
    }

    fn report(&mut self, sid: usize, iova: u64, code: u32, write: bool, access: &mut Access<'_>) {
        if self.error & ERROR_FLAG == 0 {
            self.error = ERROR_FLAG
                | (sid as u32 & 0xff) << ERROR_STREAM_SHIFT
                | if write { ERROR_WRITE } else { 0 }
                | code;
            self.error_address = iova;
        }
        if sid < 256 {
            self.error_streams[sid / 32] |= 1 << (sid % 32);
        }
        self.signal(access);
    }

    fn signal(&mut self, access: &mut Access<'_>) {
        let level = self.error & ERROR_FLAG != 0 && self.error & ERROR_CODE & !self.error_mask != 0;
        if level != self.irq_level {
            self.irq_level = level;
            let level = if let Some((levels, index)) = &self.shared_fault {
                let mut levels = levels.borrow_mut();
                levels[*index] = level;
                levels.iter().any(|&level| level)
            } else {
                level
            };
            if let Some(irq) = self.irq {
                access.interrupts.set_level(Wire::Aic(irq), level);
            }
        }
    }

    /// The stream of a per-stream register at `offset` from `base`.
    fn stream(&self, offset: u64, base: u64) -> Option<usize> {
        if !offset.is_multiple_of(4) {
            return None;
        }
        let index = usize::try_from(offset.checked_sub(base)? / 4).ok()?;
        (index < self.streams).then_some(index)
    }
}

fn fault(fault: Fault) -> DmaError {
    DmaError::Fault(fault as u32)
}

impl Iommu for Dart {
    fn page(&self) -> u64 {
        PAGE
    }

    /// A fault is latched in ERROR and signalled.
    fn translate(
        &mut self,
        memory: &mut dyn Memory,
        sid: usize,
        iova: u64,
        last: u64,
        write: bool,
        access: &mut Access<'_>,
    ) -> Result<u64, DmaError> {
        debug_assert!(last >= iova && last >> PAGE_SHIFT == iova >> PAGE_SHIFT);
        let result = self.walk(memory, sid, iova, last, write);
        if let Err(DmaError::Fault(code)) = result {
            self.report(sid, iova, code, write, access);
        }
        result
    }
}

/// The entry `index` (masked to a table) of the table at `table`.
fn entry(memory: &mut dyn Memory, table: u64, index: u64) -> Result<u64, DmaError> {
    let mut bytes = [0; 8];
    let address = table + (index & ((1 << LEVEL_BITS) - 1)) * 8;
    if !memory.read(address, &mut bytes) {
        return Err(DmaError::Memory);
    }
    Ok(u64::from_le_bytes(bytes))
}

/// The address an entry points at.
fn target(entry: u64, leaf: bool) -> Result<u64, DmaError> {
    Format::Dart2.target(entry, PA_BITS, PAGE, leaf)
}

fn bitmap_word(offset: u64, base: u64) -> Option<usize> {
    let word = offset.checked_sub(base)? / 4;
    (word < STREAM_WORDS && offset.is_multiple_of(4)).then_some(word as usize)
}

impl MmioDevice for Dart {
    fn name(&self) -> &'static str {
        NAME
    }

    fn read(
        &mut self,
        offset: u64,
        width: Width,
        access: &mut Access<'_>,
    ) -> Result<u64, MmioError> {
        let fail = |reason| refuse(NAME, offset, width, Direction::Read, reason);
        if width != Width::Word {
            return Err(fail("DART registers are 32-bit"));
        }
        if !self.powered {
            return Err(fail("DART power domain is off"));
        }
        if !self.clock_enabled {
            return Err(fail("DART functional clock is gated"));
        }
        if self.reset {
            return Err(fail("DART reset is asserted"));
        }
        if (SMMU_OFFSET..SMMU_OFFSET + SMMU_BYTES).contains(&offset) {
            return self
                .smmu
                .as_mut()
                .ok_or_else(|| fail("DART has no paired SMMU instance"))?
                .read(offset - SMMU_OFFSET, width, access);
        }
        if let Some(apf) = offset.checked_sub(DAPF_OFFSET) {
            return self
                .apf_register(apf)
                .map(|(value, _)| u64::from(*value))
                .ok_or_else(|| fail("unknown DART APF register"));
        }
        let value = match offset {
            PARAMS1 => PARAMS1_VALUE,
            PARAMS2 => BYPASS_SUPPORT,
            PARAMS3 => PARAMS3_VALUE,
            PARAMS4 => self.streams as u32,
            TLB_CMD | TLB_SYNC | TLB_SYNC_STATUS => 0,
            TLB_PARAMETER => self.tlb_words[0],
            _ if TLB_RANGE.contains(&offset) => {
                self.tlb_words[1 + usize::from(offset == TLB_RANGE[1])]
            }
            ERROR => self.error,
            ERROR_MASK => self.error_mask,
            ERROR_ADDRESS_LOW => self.error_address as u32,
            ERROR_ADDRESS_HIGH => (self.error_address >> 32) as u32,
            // UNPROTECT and DISABLE_STREAMS are clear-side views of the
            // protection and enable state. SPTM reads each register back
            // after writing it to order the write (file 0xcd75c), ignoring
            // the value; inferred: the view reads the state it clears.
            PROTECT | UNPROTECT => self.protect,
            PROTECT_LOCK => self.locked,
            // The boot stage leaves protected-write reporting disabled and
            // there is no pending protected-write violation.
            PROTECTED_WRITE => 0,
            PERF_INTERRUPT_ENABLE => self.perf_interrupts,
            PERF_INTERRUPT_STATUS => 0,
            _ if TLIMITS.contains(&offset) => self.tlimits[((offset - TLIMITS[0]) / 4) as usize],
            TZ_CONFIG | TZ_SELECT => 0,
            _ if (TZ_FIRST..TZ_END).contains(&offset) && (offset - TZ_FIRST).is_multiple_of(8) => 0,
            _ => {
                if let Some(word) = bitmap_word(offset, ERROR_STREAMS) {
                    self.error_streams[word]
                } else if let Some(word) = bitmap_word(offset, ENABLE_STREAMS)
                    .or_else(|| bitmap_word(offset, DISABLE_STREAMS))
                {
                    self.enabled[word]
                } else if let Some(word) = bitmap_word(offset, STREAM_INTERRUPTS) {
                    self.stream_interrupts[word]
                } else if let Some(sid) = self.stream(offset, TCR).filter(|_| offset < TTBR) {
                    self.tcr[sid]
                } else if let Some(sid) = self.stream(offset, TTBR) {
                    self.ttbr[sid]
                } else {
                    return Err(fail("unknown DART register"));
                }
            }
        };
        Ok(u64::from(value))
    }

    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        access: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        let fail = |reason| refuse(NAME, offset, width, Direction::Write, reason);
        if width != Width::Word {
            return Err(fail("DART registers are 32-bit"));
        }
        if !self.powered {
            return Err(fail("DART power domain is off"));
        }
        if !self.clock_enabled {
            return Err(fail("DART functional clock is gated"));
        }
        if self.reset {
            return Err(fail("DART reset is asserted"));
        }
        if (SMMU_OFFSET..SMMU_OFFSET + SMMU_BYTES).contains(&offset) {
            return self
                .smmu
                .as_mut()
                .ok_or_else(|| fail("DART has no paired SMMU instance"))?
                .write(offset - SMMU_OFFSET, width, value, access);
        }
        let value = value as u32;
        if let Some(apf) = offset.checked_sub(DAPF_OFFSET) {
            let locked = self.protect & PROTECT_APF != 0;
            let (register, known) = self
                .apf_register(apf)
                .ok_or_else(|| fail("unknown DART APF register"))?;
            if value & !known != 0 {
                return Err(fail("DART APF slice control bits outside 0x333"));
            }
            if !locked {
                *register = value;
            }
            return Ok(());
        }
        let protected = self.protect & PROTECT_TTBR_TCR != 0;
        if matches!(offset, PROTECT | UNPROTECT | PROTECT_LOCK) && value & !self.domains() != 0 {
            return Err(fail("DART protection domain without a model"));
        }
        match offset {
            TLB_CMD => {
                if value & !(TLB_STREAM | TLB_OP | TLB_QUALIFIERS) != 0
                    || !TLB_OPS.contains(&(value & TLB_OP))
                {
                    return Err(fail("unknown DART TLB command"));
                }
            }
            TLB_SYNC if value == 0 => {}
            TLB_SYNC => return Err(fail("DART TLB barrier trigger takes zero")),
            TLB_PARAMETER => self.tlb_words[0] = value,
            _ if TLB_RANGE.contains(&offset) => {
                self.tlb_words[1 + usize::from(offset == TLB_RANGE[1])] = value
            }
            ERROR => {
                // Linux writes the captured word. SPTM also acknowledges
                // one code without FLAG (26A434 file 0xc99e8).
                if value & ERROR_FLAG != 0 || value & self.error & ERROR_CODE != 0 {
                    self.error = 0;
                }
            }
            ERROR_MASK => self.error_mask = value & ERROR_CODE,
            TZ_CONFIG | TZ_SELECT => {
                return Err(fail(
                    "translation zones are owned by the boot stage; active-zone programming is unsupported",
                ));
            }
            _ if (TZ_FIRST..TZ_END).contains(&offset) && (offset - TZ_FIRST).is_multiple_of(8) => {
                return Err(fail("translation-zone bounds are owned by the boot stage"));
            }
            _ if TLIMITS.contains(&offset) => {
                self.tlimits[((offset - TLIMITS[0]) / 4) as usize] = value
            }
            PERF_INTERRUPT_ENABLE => self.perf_interrupts = value & PERF_INTERRUPTS,
            // Write-one-to-clear; nothing is pending.
            PERF_INTERRUPT_STATUS => {}
            PROTECTED_WRITE if value == 0 => {}
            PROTECTED_WRITE => return Err(fail("nonzero protected-write policy is not described")),
            PROTECT => self.protect |= value,
            UNPROTECT => self.protect &= !(value & !self.locked),
            PROTECT_LOCK => self.locked |= value,
            _ => {
                if let Some(word) = bitmap_word(offset, ERROR_STREAMS) {
                    self.error_streams[word] &= !value;
                } else if let Some(word) = bitmap_word(offset, ENABLE_STREAMS) {
                    self.enabled[word] |= value;
                } else if let Some(word) = bitmap_word(offset, DISABLE_STREAMS) {
                    self.enabled[word] &= !value;
                } else if let Some(word) = bitmap_word(offset, STREAM_INTERRUPTS) {
                    self.stream_interrupts[word] = value;
                } else if let Some(sid) = self.stream(offset, TCR).filter(|_| offset < TTBR) {
                    if value & !TCR_KNOWN != 0 {
                        return Err(fail("DART TCR reserved bits"));
                    }
                    if !protected {
                        self.tcr[sid] = value;
                    }
                } else if let Some(sid) = self.stream(offset, TTBR) {
                    if !protected {
                        self.ttbr[sid] = value;
                    }
                } else {
                    return Err(fail("unknown DART register"));
                }
            }
        }
        self.signal(access);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::interrupt::InterruptLatch;
    use super::*;
    use crate::platform::dma::tests::Ram;

    const ROOT: u64 = 0x1_0000_0000;
    const LEAVES: u64 = ROOT + PAGE;
    const FRAME: u64 = ROOT + 4 * PAGE;

    fn table_entry(address: u64) -> u64 {
        (address >> ENTRY_ADDRESS_SHIFT) & ENTRY_ADDRESS | ENTRY_VALID
    }

    fn setup() -> (Dart, Ram, InterruptLatch) {
        let mut dart = Dart::new(16, Some(AicInput::new(0, 0x301)));
        let mut ram = Ram::new(ROOT, 8 * PAGE as usize);
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        // IOVA 0x200_4000: first-level entry 1, page entry 1.
        ram.put_u64(ROOT + 8, table_entry(LEAVES));
        ram.put_u64(
            LEAVES + 8,
            table_entry(FRAME) | 0xfff << 40 | ENTRY_NO_WRITE,
        );
        for (offset, value) in [
            (ENABLE_STREAMS, 0xffff),
            (TCR + 4, TCR_TRANSLATE),
            (
                TTBR + 4,
                ((ROOT >> PAGE_SHIFT) << TTBR_ADDRESS_SHIFT) as u32 | TTBR_VALID,
            ),
            (TCR + 8, TCR_BYPASS_DART | TCR_BYPASS_DAPF),
        ] {
            dart.write(offset, Width::Word, u64::from(value), &mut access)
                .unwrap();
        }
        (dart, ram, latch)
    }

    #[test]
    fn resume_saves_and_restores_transaction_limits_and_clamp_retains_zero() {
        let mut d = Dart::new(16, None);
        let mut sink = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut sink);
        for (index, offset) in TLIMITS.into_iter().enumerate() {
            assert_eq!(d.read(offset, Width::Word, &mut a), Ok(0));
            d.write(offset, Width::Word, 0x1234_5678 + index as u64, &mut a)
                .unwrap();
            let saved = d.read(offset, Width::Word, &mut a).unwrap();
            d.set_power(false, false, &mut a);
            d.set_power(true, false, &mut a);
            assert_eq!(d.read(offset, Width::Word, &mut a), Ok(0));
            d.write(offset, Width::Word, saved, &mut a).unwrap();
            assert_eq!(d.read(offset, Width::Word, &mut a), Ok(saved));
            d.write(offset, Width::Word, 0, &mut a).unwrap();
            assert_eq!(d.read(offset, Width::Word, &mut a), Ok(0));
            assert!(d.read(offset, Width::Double, &mut a).is_err());
        }
    }

    #[test]
    fn sptm_power_cycle_programs_the_interrupt_words_and_no_counter_interrupt_pends() {
        let mut d = Dart::new(16, None);
        let mut sink = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut sink);
        // Power-down: clear all, disable the counter interrupts.
        d.write(PERF_INTERRUPT_STATUS, Width::Word, 0xffff_ffff, &mut a)
            .unwrap();
        assert_eq!(d.read(PERF_INTERRUPT_STATUS, Width::Word, &mut a), Ok(0));
        d.write(PERF_INTERRUPT_ENABLE, Width::Word, 0, &mut a)
            .unwrap();
        d.set_power(false, false, &mut a);
        d.set_power(true, false, &mut a);
        // Power-up: enable all, clear all, restore the in-use streams.
        d.write(PERF_INTERRUPT_ENABLE, Width::Word, 0xffff_ffff, &mut a)
            .unwrap();
        assert_eq!(
            d.read(PERF_INTERRUPT_ENABLE, Width::Word, &mut a),
            Ok(u64::from(PERF_INTERRUPTS))
        );
        d.write(STREAM_INTERRUPTS + 4, Width::Word, 0x5, &mut a)
            .unwrap();
        assert_eq!(d.read(STREAM_INTERRUPTS + 4, Width::Word, &mut a), Ok(5));
        // Every invalidation SPTM issues completes; OP 3 is undefined.
        for (offset, value) in [
            (TLB_RANGE[0], 0x40),
            (TLB_RANGE[1], 0x80),
            (TLB_CMD, 1 << 14 | 1 << 8 | 3),
            (TLB_PARAMETER, 7),
            (TLB_CMD, 2 << 8),
            (TLB_CMD, 1 << 15 | 4 << 8),
            (TLB_CMD, 1 << 15 | 1 << 13),
            (TLB_SYNC, 0),
        ] {
            d.write(offset, Width::Word, value, &mut a).unwrap();
        }
        assert_eq!(d.read(TLB_RANGE[1], Width::Word, &mut a), Ok(0x80));
        assert_eq!(d.read(TLB_CMD, Width::Word, &mut a), Ok(0));
        assert_eq!(d.read(TLB_SYNC, Width::Word, &mut a), Ok(0));
        assert_eq!(d.read(TLB_SYNC_STATUS, Width::Word, &mut a), Ok(0));
        assert!(d.write(TLB_CMD, Width::Word, 3 << 8, &mut a).is_err());
        assert!(d.write(TLB_SYNC, Width::Word, 1, &mut a).is_err());
        // The counters themselves are absent.
        assert!(d.read(0x760, Width::Word, &mut a).is_err());
        // Power-down disables each stream and reads the word back.
        d.write(ENABLE_STREAMS + 4, Width::Word, 0x3, &mut a)
            .unwrap();
        d.write(DISABLE_STREAMS + 4, Width::Word, 0x1, &mut a)
            .unwrap();
        assert_eq!(d.read(DISABLE_STREAMS + 4, Width::Word, &mut a), Ok(2));
        assert_eq!(d.read(UNPROTECT, Width::Word, &mut a), Ok(0));
        d.set_power(false, false, &mut a);
        d.set_power(true, false, &mut a);
        assert_eq!(d.read(STREAM_INTERRUPTS + 4, Width::Word, &mut a), Ok(0));
    }

    #[test]
    fn power_gates_lose_ordinary_state_but_retention_and_secure_zone_locks_survive() {
        for retention in [false, true] {
            let (mut d, mut ram, mut latch) = setup();
            let mut a = Access::new(0, 0, &mut latch);
            d.write(PROTECT, Width::Word, u64::from(PROTECT_TZ | 1), &mut a)
                .unwrap();
            d.write(PROTECT_LOCK, Width::Word, u64::from(PROTECT_TZ | 1), &mut a)
                .unwrap();
            d.set_power(false, retention, &mut a);
            assert!(d.read(PARAMS1, Width::Word, &mut a).is_err());
            assert_eq!(
                d.translate(&mut ram, 2, ROOT, ROOT, false, &mut a),
                Err(DmaError::Unsupported("DART power domain is off"))
            );
            d.set_power(true, retention, &mut a);
            assert_eq!(
                d.read(TCR + 4, Width::Word, &mut a),
                Ok(if retention { 1 } else { 0 })
            );
            assert_eq!(
                d.read(PROTECT_LOCK, Width::Word, &mut a),
                Ok(u64::from(PROTECT_TZ) | u64::from(retention))
            );
            for offset in [TZ_CONFIG, TZ_SELECT, TZ_FIRST, TZ_END - 8] {
                assert_eq!(d.read(offset, Width::Word, &mut a), Ok(0));
                assert!(d.write(offset, Width::Word, 1, &mut a).is_err());
            }
            assert!(d.read(TZ_FIRST + 4, Width::Word, &mut a).is_err());
            if !retention {
                d.write(
                    TCR + 8,
                    Width::Word,
                    u64::from(TCR_BYPASS_DART | TCR_BYPASS_DAPF),
                    &mut a,
                )
                .unwrap();
                d.write(ENABLE_STREAMS, Width::Word, 4, &mut a).unwrap();
                assert_eq!(
                    d.translate(&mut ram, 2, ROOT, ROOT, false, &mut a),
                    Ok(ROOT)
                );
            }
        }
    }

    #[test]
    fn powerup_restores_disabled_protected_write_policy_without_unlocking_tables() {
        let (mut dart, _, mut latch) = setup();
        let mut access = Access::new(0, 0, &mut latch);
        dart.write(PROTECT, Width::Word, 1, &mut access).unwrap();
        dart.write(PROTECT_LOCK, Width::Word, 1, &mut access)
            .unwrap();
        dart.write(PROTECTED_WRITE, Width::Word, 0, &mut access)
            .unwrap();
        assert_eq!(dart.read(PROTECTED_WRITE, Width::Word, &mut access), Ok(0));
        assert_eq!(dart.read(PROTECT_LOCK, Width::Word, &mut access), Ok(1));
        assert!(
            dart.write(PROTECTED_WRITE, Width::Word, 2, &mut access)
                .is_err()
        );
        assert!(
            dart.read(PROTECTED_WRITE, Width::Double, &mut access)
                .is_err()
        );
    }

    #[test]
    fn instances_keep_separate_registers_and_or_their_shared_fault_wire() {
        let irq = AicInput::new(0, 1035);
        let mut group = Dart::group(16, Some(irq), 2);
        let mut latch = InterruptLatch::new();
        let mut ram = Ram::new(0, 0x4000);
        {
            let mut access = Access::new(0, 0, &mut latch);
            for (instance, sid) in [(0, 0), (1, 1)] {
                assert!(
                    group[instance]
                        .translate(&mut ram, sid, 0, 3, false, &mut access)
                        .is_err()
                );
            }
            group[0].write(TCR, Width::Word, 2, &mut access).unwrap();
            assert_eq!(group[1].read(TCR, Width::Word, &mut access), Ok(0));
        }
        assert!(latch.is_asserted(Wire::Aic(irq)));
        {
            let mut access = Access::new(0, 0, &mut latch);
            group[0]
                .write(ERROR, Width::Word, u64::from(ERROR_FLAG), &mut access)
                .unwrap();
        }
        assert!(latch.is_asserted(Wire::Aic(irq)));
        {
            let mut access = Access::new(0, 0, &mut latch);
            group[1]
                .write(ERROR, Width::Word, u64::from(ERROR_FLAG), &mut access)
                .unwrap();
        }
        assert!(!latch.is_asserted(Wire::Aic(irq)));
    }

    #[test]
    fn streams_translate_through_two_levels_or_bypass() {
        let (mut dart, mut ram, mut latch) = setup();
        let mut access = Access::new(0, 0, &mut latch);
        assert_eq!(
            dart.read(PARAMS1, Width::Word, &mut access),
            Ok(1 << 31 | 0xe << 24)
        );
        assert_eq!(dart.read(PARAMS2, Width::Word, &mut access), Ok(1));
        assert_eq!(
            dart.read(PARAMS3, Width::Word, &mut access),
            Ok(42 << 24 | 36 << 16 | 0x100)
        );
        assert_eq!(dart.read(PARAMS4, Width::Word, &mut access), Ok(16));
        let iova = 0x200_4000 + 0x123;
        assert_eq!(
            dart.translate(&mut ram, 1, iova, iova + 3, false, &mut access),
            Ok(FRAME + 0x123)
        );
        assert_eq!(
            dart.translate(&mut ram, 2, 0x8_1234_5678, 0x8_1234_5678, true, &mut access),
            Ok(0x8_1234_5678)
        );
    }

    #[test]
    fn faults_latch_the_first_error_and_raise_the_interrupt_until_cleared() {
        let (mut dart, mut ram, mut latch) = setup();
        let mut access = Access::new(0, 0, &mut latch);
        let iova = 0x200_4000;
        assert_eq!(
            dart.translate(&mut ram, 1, iova, iova, true, &mut access),
            Err(fault(Fault::Write))
        );
        assert_eq!(
            dart.translate(&mut ram, 1, 0x400_0000, 0x400_0000, false, &mut access),
            Err(fault(Fault::NoPmd))
        );
        // Page entry 2 allows bytes 0x10..0x1f: a read past them violates
        // its region.
        ram.put_u64(LEAVES + 16, table_entry(FRAME) | 4 << 52 | 7 << 40);
        let narrow = 0x200_8000;
        assert_eq!(
            dart.translate(&mut ram, 1, narrow + 0x10, narrow + 0x1f, true, &mut access),
            Ok(FRAME + 0x10)
        );
        for (first, last) in [(0xc, 0xf), (0x1c, 0x20)] {
            assert_eq!(
                dart.translate(
                    &mut ram,
                    1,
                    narrow + first,
                    narrow + last,
                    false,
                    &mut access
                ),
                Err(fault(Fault::Region))
            );
        }
        let read = |dart: &mut Dart, offset, access: &mut Access<'_>| {
            dart.read(offset, Width::Word, access).unwrap() as u32
        };
        let error = read(&mut dart, ERROR, &mut access);
        assert_eq!(
            error,
            ERROR_FLAG | ERROR_WRITE | 1 << ERROR_STREAM_SHIFT | Fault::Write as u32
        );
        assert_eq!(read(&mut dart, ERROR_ADDRESS_LOW, &mut access), iova as u32);
        assert_eq!(read(&mut dart, ERROR_STREAMS, &mut access), 0b10);
        assert!(dart.irq_level);
        dart.write(ERROR, Width::Word, u64::from(error), &mut access)
            .unwrap();
        assert_eq!(read(&mut dart, ERROR, &mut access), 0);
        assert!(!dart.irq_level);
        // A masked code latches without signalling.
        dart.write(ERROR_MASK, Width::Word, Fault::NoTtbr as u64, &mut access)
            .unwrap();
        let _ = dart.translate(&mut ram, 3, 0, 0, false, &mut access);
        assert_eq!(read(&mut dart, ERROR, &mut access) & ERROR_CODE, 1);
        assert!(!dart.irq_level);
    }

    #[test]
    fn sptm_code_only_acknowledgement_clears_the_fault_and_shared_irq() {
        let irq = AicInput::new(0, 0x301);
        let (mut dart, mut ram, mut sink) = setup();
        let iova = 0x200_4000;
        {
            let mut a = Access::new(0, 0, &mut sink);
            assert_eq!(
                dart.translate(&mut ram, 1, iova, iova, true, &mut a),
                Err(fault(Fault::Write))
            );
            // A later read failure keeps the first write's address/direction.
            assert!(dart.translate(&mut ram, 3, 0, 0, false, &mut a).is_err());
            assert_eq!(dart.read(ERROR_ADDRESS_LOW, Width::Word, &mut a), Ok(iova));
            assert_ne!(
                dart.read(ERROR, Width::Word, &mut a).unwrap() & u64::from(ERROR_WRITE),
                0
            );
            dart.write(ERROR, Width::Word, Fault::Read as u64, &mut a)
                .unwrap();
        }
        assert!(sink.is_asserted(Wire::Aic(irq)));
        {
            let mut a = Access::new(0, 0, &mut sink);
            // The original SPTM writes the code, without ERROR_FLAG.
            dart.write(ERROR, Width::Word, Fault::Write as u64, &mut a)
                .unwrap();
            assert_eq!(dart.read(ERROR, Width::Word, &mut a), Ok(0));
            // Per-stream fault evidence is independently W1C.
            assert_eq!(dart.read(ERROR_STREAMS, Width::Word, &mut a), Ok(0xa));
            dart.write(ERROR_STREAMS, Width::Word, 2, &mut a).unwrap();
            assert_eq!(dart.read(ERROR_STREAMS, Width::Word, &mut a), Ok(8));
        }
        assert!(!sink.is_asserted(Wire::Aic(irq)));
        {
            let mut a = Access::new(0, 0, &mut sink);
            assert!(dart.translate(&mut ram, 3, 0, 0, false, &mut a).is_err());
            assert_eq!(
                dart.read(ERROR, Width::Word, &mut a).unwrap() & u64::from(ERROR_WRITE),
                0
            );
        }
        assert!(sink.is_asserted(Wire::Aic(irq)));
    }

    #[test]
    fn ttbr_uses_only_the_address_field_and_stream_words_never_alias_unaligned_offsets() {
        let (mut dart, mut ram, mut sink) = setup();
        let mut a = Access::new(0, 0, &mut sink);
        let ttbr = dart.read(TTBR + 4, Width::Word, &mut a).unwrap();
        // R_TTBR.ADDR is [29:2]; bits31:30 and bit1 are not address bits.
        dart.write(TTBR + 4, Width::Word, ttbr | 0xc000_0002, &mut a)
            .unwrap();
        let iova = 0x200_4000;
        assert_eq!(
            dart.translate(&mut ram, 1, iova, iova, false, &mut a),
            Ok(FRAME)
        );
        for offset in [TCR + 5, TTBR + 5, TCR + 4 * 16, TTBR + 4 * 16] {
            assert!(dart.read(offset, Width::Word, &mut a).is_err());
            assert!(dart.write(offset, Width::Word, 0, &mut a).is_err());
        }
        assert_eq!(
            dart.read(TCR + 4, Width::Word, &mut a),
            Ok(u64::from(TCR_TRANSLATE))
        );
        assert_eq!(
            dart.translate(&mut ram, 1, iova, iova, false, &mut a),
            Ok(FRAME)
        );
    }

    #[test]
    fn unimplemented_and_invalid_translation_modes_never_bypass_permissions() {
        let (mut dart, mut ram, mut sink) = setup();
        let mut a = Access::new(0, 0, &mut sink);
        for (mode, reason) in [
            (
                TCR_TRANSLATE | TCR_BYPASS_DART,
                "DART simultaneous translation and bypass",
            ),
            (
                TCR_TRANSLATE | TCR_REMAP_ENABLE | 3 << 8,
                "DART stream remapping",
            ),
            (TCR_TRANSLATE | TCR_FOUR_LEVEL, "four-level DART tables"),
        ] {
            dart.write(TCR + 4, Width::Word, u64::from(mode), &mut a)
                .unwrap();
            assert_eq!(
                dart.translate(&mut ram, 1, 0, 0, true, &mut a),
                Err(DmaError::Unsupported(reason))
            );
            assert_eq!(dart.read(ERROR, Width::Word, &mut a), Ok(0));
        }
    }

    #[test]
    fn dma_completes_prior_pages_but_stops_before_a_protected_page() {
        let (mut dart, mut ram, mut sink) = setup();
        ram.put_u64(LEAVES + 8, table_entry(FRAME) | 0xfff << 40);
        ram.put_u64(
            LEAVES + 16,
            table_entry(FRAME + PAGE) | 0xfff << 40 | ENTRY_NO_WRITE,
        );
        let mut a = Access::new(0, 0, &mut sink);
        let first = 0x200_8000 - 4;
        let mut port = crate::platform::dma::Port {
            iommu: &mut dart,
            stream: 1,
            memory: &mut ram,
            access: &mut a,
        };
        assert_eq!(
            port.write(first, &[1, 2, 3, 4, 5, 6, 7, 8]),
            Err(fault(Fault::Write))
        );
        let mut bytes = [0; 8];
        assert!(ram.read(FRAME + PAGE - 4, &mut bytes));
        assert_eq!(bytes, [1, 2, 3, 4, 0, 0, 0, 0]);
        assert_eq!(
            dart.read(ERROR_ADDRESS_LOW, Width::Word, &mut a),
            Ok(0x200_8000)
        );
    }

    #[test]
    fn quiesce_and_reset_are_distinct_from_retained_power() {
        let (mut dart, mut ram, mut sink) = setup();
        let mut a = Access::new(0, 0, &mut sink);
        dart.write(PROTECT, Width::Word, 1, &mut a).unwrap();
        dart.write(PROTECT_LOCK, Width::Word, 1, &mut a).unwrap();
        dart.set_quiesced(true);
        assert_eq!(dart.read(TCR + 4, Width::Word, &mut a), Ok(1));
        assert_eq!(
            dart.translate(&mut ram, 2, ROOT, ROOT, false, &mut a),
            Err(DmaError::Unsupported("DART DMA is quiesced"))
        );
        dart.set_power(false, true, &mut a);
        dart.set_power(true, true, &mut a);
        assert_eq!(dart.read(PROTECT_LOCK, Width::Word, &mut a), Ok(1));
        // Reset assertion clears state even when the supply retained it.
        dart.set_reset(true, &mut a);
        assert!(dart.read(TCR + 4, Width::Word, &mut a).is_err());
        assert!(dart.write(TCR, Width::Word, 1, &mut a).is_err());
        assert_eq!(
            dart.translate(&mut ram, 2, ROOT, ROOT, false, &mut a),
            Err(DmaError::Unsupported("DART reset is asserted"))
        );
        dart.set_reset(false, &mut a);
        assert_eq!(dart.read(TCR + 4, Width::Word, &mut a), Ok(0));
        assert_eq!(dart.read(PROTECT_LOCK, Width::Word, &mut a), Ok(0));
        assert_eq!(
            dart.translate(&mut ram, 2, ROOT, ROOT, false, &mut a),
            Err(DmaError::Unsupported("DART DMA is quiesced"))
        );
        dart.set_quiesced(false);
        // Releasing reset does not restore a software-owned table or enable.
        assert_eq!(
            dart.translate(&mut ram, 2, ROOT, ROOT, false, &mut a),
            Err(fault(Fault::NoTtbr))
        );
    }

    #[test]
    fn cacheless_invalidation_observes_new_tables_and_permissions() {
        let (mut dart, mut ram, mut sink) = setup();
        let mut a = Access::new(0, 0, &mut sink);
        let iova = 0x200_4000;
        assert_eq!(
            dart.translate(&mut ram, 1, iova, iova, false, &mut a),
            Ok(FRAME)
        );
        ram.put_u64(
            LEAVES + 8,
            table_entry(FRAME + PAGE) | 0xfff << 40 | ENTRY_NO_READ,
        );
        dart.write(
            TLB_CMD,
            Width::Word,
            u64::from(TLB_OP_FLUSH_STREAM | 1),
            &mut a,
        )
        .unwrap();
        assert_eq!(dart.read(TLB_CMD, Width::Word, &mut a), Ok(0));
        assert_eq!(
            dart.translate(&mut ram, 1, iova, iova, false, &mut a),
            Err(fault(Fault::Read))
        );
        assert_eq!(
            dart.translate(&mut ram, 1, iova, iova, true, &mut a),
            Ok(FRAME + PAGE)
        );
        ram.put_u64(LEAVES + 8, 0);
        dart.write(TLB_CMD, Width::Word, 0, &mut a).unwrap();
        assert_eq!(
            dart.translate(&mut ram, 1, iova, iova, true, &mut a),
            Err(fault(Fault::NoPte))
        );
    }

    #[test]
    fn smmu_view_shares_trad_power_and_reset_without_creating_capture_entries() {
        let mut sink = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut sink);
        let mut plain = Dart::new(16, None);
        assert!(plain.read(SMMU_OFFSET, Width::Word, &mut a).is_err());
        assert!(plain.enable_smmu());
        assert!(!plain.enable_smmu());
        let mut dart = Dart::new(16, None);
        assert!(dart.enable_smmu());
        for model in [&mut plain, &mut dart] {
            assert_eq!(model.read(SMMU_OFFSET, Width::Word, &mut a), Ok(0));
            assert!(
                model
                    .write(SMMU_OFFSET + 0x80, Width::Word, 0, &mut a)
                    .is_err()
            );
            assert!(
                model
                    .read(SMMU_OFFSET + 0x2000, Width::Word, &mut a)
                    .is_err()
            );
            model.set_power(false, true, &mut a);
            assert!(model.read(SMMU_OFFSET, Width::Word, &mut a).is_err());
            model.set_power(true, true, &mut a);
            model.set_reset(true, &mut a);
            assert!(model.read(SMMU_OFFSET, Width::Word, &mut a).is_err());
            model.set_reset(false, &mut a);
            assert_eq!(model.read(SMMU_OFFSET, Width::Word, &mut a), Ok(0));
        }
    }

    #[test]
    fn the_apf_holds_its_slices_until_sptm_locks_them() {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut dart = Dart::new(16, None).with_apf(16);
        let slice = |s: u64, register: u64| DAPF_OFFSET + s * SLICE + register;
        for (offset, value) in [
            (slice(1, SLICE_START), 0x0001_c000),
            (slice(1, SLICE_START + 4), 0x2),
            (slice(1, SLICE_END), 0x0005_1000),
            (slice(1, SLICE_END + 4), 0x2),
            (slice(1, SLICE_STREAMS), 0x1),
            (slice(1, SLICE_CONTROL), 0x103),
        ] {
            dart.write(offset, Width::Word, value, &mut access).unwrap();
            assert_eq!(dart.read(offset, Width::Word, &mut access), Ok(value));
        }
        assert!(
            dart.write(slice(1, SLICE_CONTROL), Width::Word, 0x4, &mut access)
                .is_err()
        );
        assert!(dart.read(slice(1, 0x04), Width::Word, &mut access).is_err());
        assert!(dart.read(slice(16, 0), Width::Word, &mut access).is_err());
        // SPTM locks the filter; its slices then keep their values.
        dart.write(PROTECT, Width::Word, 4, &mut access).unwrap();
        dart.write(PROTECT_LOCK, Width::Word, 4, &mut access)
            .unwrap();
        dart.write(UNPROTECT, Width::Word, 4, &mut access).unwrap();
        assert_eq!(dart.read(PROTECT, Width::Word, &mut access), Ok(4));
        assert_eq!(dart.read(PROTECT_LOCK, Width::Word, &mut access), Ok(4));
        dart.write(slice(1, SLICE_STREAMS), Width::Word, 0, &mut access)
            .unwrap();
        assert_eq!(
            dart.read(slice(1, SLICE_STREAMS), Width::Word, &mut access),
            Ok(1)
        );
        // A transfer that the filter would check refuses.
        let mut ram = Ram::new(ROOT, PAGE as usize);
        dart.write(ENABLE_STREAMS, Width::Word, 1, &mut access)
            .unwrap();
        dart.write(TCR, Width::Word, u64::from(TCR_BYPASS_DART), &mut access)
            .unwrap();
        assert_eq!(
            dart.translate(&mut ram, 0, ROOT, ROOT, false, &mut access),
            Err(DmaError::Unsupported("DART address permission filtering"))
        );
        // A DART without a filter has no APF domain.
        let mut plain = Dart::new(16, None);
        assert!(plain.write(PROTECT, Width::Word, 4, &mut access).is_err());
        assert!(plain.read(DAPF_OFFSET, Width::Word, &mut access).is_err());
    }

    #[test]
    fn protection_freezes_stream_tables_and_the_lock_keeps_it() {
        let (mut dart, _, mut latch) = setup();
        let mut access = Access::new(0, 0, &mut latch);
        for (offset, value) in [
            (PROTECT, 1),
            (PROTECT_LOCK, 1),
            (UNPROTECT, 1),
            (TCR + 4, 0),
        ] {
            dart.write(offset, Width::Word, value, &mut access).unwrap();
        }
        assert_eq!(dart.read(PROTECT, Width::Word, &mut access), Ok(1));
        assert_eq!(
            dart.read(TCR + 4, Width::Word, &mut access),
            Ok(u64::from(TCR_TRANSLATE))
        );
        // Unknown registers and four-level tables are refused.
        assert!(dart.read(0x10, Width::Word, &mut access).is_err());
        assert!(
            dart.write(TCR + 4 * 16, Width::Word, 0, &mut access)
                .is_err()
        );
    }
}
