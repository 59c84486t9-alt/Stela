//! The Apple DART of T8110 layout (`dart,t8110`; ADT `/arm-io/dart-*`), the
//! IOMMU through which a device's stream (SID) reaches RAM.
//!
//! Documented by Linux `drivers/iommu/apple-dart.c` and `io-pgtable-dart.c`
//! (Asahi), registers 32-bit:
//! - TLB_CMD (0x80): BUSY 31, OP [10:8] (0 flush all, 1 flush one stream),
//!   STREAM [7:0].
//! - ERROR (0x100): FLAG 31, STREAM [27:20], CODE [14:0] (READ_FAULT 5,
//!   WRITE_FAULT 4, NO_PTE 3, NO_PMD 2, NO_PGD 1, NO_TTBR 0); software
//!   writes back what it read to clear it. ERROR_MASK (0x104), ERROR_ADDR_LO
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
//! Inferred, not documented: the model caches no translations, so TLB
//! commands complete at once and BUSY never reads set; a fault latches the
//! first error until software clears its FLAG, and the interrupt follows
//! FLAG with an unmasked code; a missing first-level entry is NO_PMD and a
//! missing page entry NO_PTE; an access to a stream not enabled, without
//! translation or out of the 36-bit space faults NO_TTBR; while TTBR_TCR is
//! protected, TCR and TTBR writes have no effect, and PROTECT_LOCK keeps it
//! protected; likewise APF protection makes the filter's slices read-only.
//! The filter's slices are SoC register windows a coprocessor's own firmware
//! reaches; the machine's device models make no such accesses, so a
//! transfer on a stream that does not bypass a present filter refuses
//! rather than pass unfiltered. The identification registers, FOUR_LEVEL and REMAP_EN are
//! refused until their values or behavior are known.
use super::bus::{Access, Direction, MmioDevice, MmioError, Width, refuse};
use super::interrupt::{AicInput, Wire};
use crate::platform::dma::{DmaError, Iommu, Memory};
#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

const NAME: &str = "dart-t8110";

const TLB_CMD: u64 = 0x80;
const TLB_OP: u32 = 0x7 << 8;
const TLB_OP_FLUSH_ALL: u32 = 0;
const TLB_OP_FLUSH_STREAM: u32 = 1 << 8;
const TLB_STREAM: u32 = 0xff;
const ERROR: u64 = 0x100;
const ERROR_MASK: u64 = 0x104;
const ERROR_ADDRESS_LOW: u64 = 0x170;
const ERROR_ADDRESS_HIGH: u64 = 0x174;
const ERROR_STREAMS: u64 = 0x1c0;
const PROTECT: u64 = 0x200;
const UNPROTECT: u64 = 0x204;
const PROTECT_LOCK: u64 = 0x208;
const ENABLE_STREAMS: u64 = 0xc00;
const DISABLE_STREAMS: u64 = 0xc20;
const TCR: u64 = 0x1000;
const TTBR: u64 = 0x1400;
/// Bitmap words of the 256 streams the layout addresses.
const STREAM_WORDS: u64 = 8;

const ERROR_FLAG: u32 = 1 << 31;
const ERROR_STREAM_SHIFT: u32 = 20;
const ERROR_CODE: u32 = 0x7fff;
const PROTECT_TTBR_TCR: u32 = 1;
const PROTECT_APF: u32 = 1 << 2;

/// The filter's registers in the device's space, past the DART's.
pub const DAPF_OFFSET: u64 = 0x4000;
/// The filter's register span.
pub const DAPF_BYTES: u64 = 0x4000;
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

const PAGE_SHIFT: u32 = 14;
const PAGE: u64 = 1 << PAGE_SHIFT;
const LEVEL_BITS: u32 = 11;
const IOVA_BITS: u32 = PAGE_SHIFT + 2 * LEVEL_BITS;
const ENTRY_VALID: u64 = 1;
const ENTRY_NO_WRITE: u64 = 1 << 2;
const ENTRY_NO_READ: u64 = 1 << 3;
const ENTRY_ADDRESS: u64 = 0x3f_ffff_fc00;
const ENTRY_ADDRESS_SHIFT: u32 = 4;
const SUBPAGE_UNIT: u64 = 4;

/// A translation fault's ERROR code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    NoTtbr = 1,
    NoPmd = 1 << 2,
    NoPte = 1 << 3,
    Write = 1 << 4,
    Read = 1 << 5,
}

pub struct Dart {
    streams: usize,
    tcr: Vec<u32>,
    ttbr: Vec<u32>,
    enabled: [u32; STREAM_WORDS as usize],
    error: u32,
    error_mask: u32,
    error_address: u64,
    error_streams: [u32; STREAM_WORDS as usize],
    protect: u32,
    locked: u32,
    /// The address permission filter's slices, when the DART has one.
    apf: Option<Vec<Slice>>,
    irq: Option<AicInput>,
    irq_level: bool,
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
    /// A DART of `streams` streams (`sid-count`, at most 256), every stream
    /// disabled and untranslated, signalling faults on `irq`.
    pub fn new(streams: usize, irq: Option<AicInput>) -> Self {
        assert!(streams <= 256, "the T8110 layout addresses 256 streams");
        Self {
            streams,
            tcr: vec![0; streams],
            ttbr: vec![0; streams],
            enabled: [0; STREAM_WORDS as usize],
            error: 0,
            error_mask: 0,
            error_address: 0,
            error_streams: [0; STREAM_WORDS as usize],
            protect: 0,
            locked: 0,
            apf: None,
            irq,
            irq_level: false,
        }
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

    /// The protection domains this DART has.
    fn domains(&self) -> u32 {
        PROTECT_TTBR_TCR | if self.apf.is_some() { PROTECT_APF } else { 0 }
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
        if sid >= self.streams || !self.stream_enabled(sid) {
            return Err(fault(Fault::NoTtbr));
        }
        let tcr = self.tcr[sid];
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
        let root = u64::from(ttbr >> TTBR_ADDRESS_SHIFT) << PAGE_SHIFT;
        let first = entry(memory, root, iova >> (PAGE_SHIFT + LEVEL_BITS))?;
        if first & ENTRY_VALID == 0 {
            return Err(fault(Fault::NoPmd));
        }
        let page = entry(memory, target(first), iova >> PAGE_SHIFT)?;
        if page & ENTRY_VALID == 0 {
            return Err(fault(Fault::NoPte));
        }
        let offset = iova & (PAGE - 1);
        let (first_unit, last_unit) = (page >> 52 & 0xfff, page >> 40 & 0xfff);
        let inside =
            offset / SUBPAGE_UNIT >= first_unit && (last & (PAGE - 1)) / SUBPAGE_UNIT <= last_unit;
        match write {
            true if page & ENTRY_NO_WRITE != 0 || !inside => Err(fault(Fault::Write)),
            false if page & ENTRY_NO_READ != 0 || !inside => Err(fault(Fault::Read)),
            _ => Ok(target(page) + offset),
        }
    }

    fn report(&mut self, sid: usize, iova: u64, code: u32, access: &mut Access<'_>) {
        if self.error & ERROR_FLAG == 0 {
            self.error = ERROR_FLAG | (sid as u32) << ERROR_STREAM_SHIFT | code;
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
            if let Some(irq) = self.irq {
                access.interrupts.set_level(Wire::Aic(irq), level);
            }
        }
    }

    /// The stream of a per-stream register at `offset` from `base`.
    fn stream(&self, offset: u64, base: u64) -> Option<usize> {
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
            self.report(sid, iova, code, access);
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
fn target(entry: u64) -> u64 {
    (entry & ENTRY_ADDRESS) << ENTRY_ADDRESS_SHIFT
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
        _access: &mut Access<'_>,
    ) -> Result<u64, MmioError> {
        let fail = |reason| refuse(NAME, offset, width, Direction::Read, reason);
        if width != Width::Word {
            return Err(fail("DART registers are 32-bit"));
        }
        if let Some(apf) = offset.checked_sub(DAPF_OFFSET) {
            return self
                .apf_register(apf)
                .map(|(value, _)| u64::from(*value))
                .ok_or_else(|| fail("unknown DART APF register"));
        }
        let value = match offset {
            TLB_CMD => 0,
            ERROR => self.error,
            ERROR_MASK => self.error_mask,
            ERROR_ADDRESS_LOW => self.error_address as u32,
            ERROR_ADDRESS_HIGH => (self.error_address >> 32) as u32,
            PROTECT => self.protect,
            PROTECT_LOCK => self.locked,
            _ => {
                if let Some(word) = bitmap_word(offset, ERROR_STREAMS) {
                    self.error_streams[word]
                } else if let Some(word) = bitmap_word(offset, ENABLE_STREAMS) {
                    self.enabled[word]
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
            TLB_CMD => match value & !TLB_STREAM & !TLB_OP {
                0 if matches!(value & TLB_OP, TLB_OP_FLUSH_ALL | TLB_OP_FLUSH_STREAM) => {}
                _ => return Err(fail("unknown DART TLB command")),
            },
            ERROR => {
                if value & ERROR_FLAG != 0 {
                    self.error = 0;
                }
            }
            ERROR_MASK => self.error_mask = value & ERROR_CODE,
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
    use super::super::interrupt::InterruptLatch;
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
    fn streams_translate_through_two_levels_or_bypass() {
        let (mut dart, mut ram, mut latch) = setup();
        let mut access = Access::new(0, 0, &mut latch);
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
        let read = |dart: &mut Dart, offset, access: &mut Access<'_>| {
            dart.read(offset, Width::Word, access).unwrap() as u32
        };
        let error = read(&mut dart, ERROR, &mut access);
        assert_eq!(
            error,
            ERROR_FLAG | 1 << ERROR_STREAM_SHIFT | Fault::Write as u32
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
        assert!(dart.read(0x8, Width::Word, &mut access).is_err());
        assert!(
            dart.write(TCR + 4 * 16, Width::Word, 0, &mut access)
                .is_err()
        );
    }
}
