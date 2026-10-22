//! Legacy Apple DART t8020/t6000 register and page-entry formats.
//!
//! Linux v6.17 apple-dart.c and io-pgtable-dart.c define the separate old
//! register layout and APPLE_DART/APPLE_DART2 entries. m1n1's dart8020.py
//! independently identifies the stream remap bytes and CONFIG lock. Original
//! 26A434 T8103 SPTM compares the remap words with the DT routes, or with
//! identity when there are none (VA 0xfffffff0270dc51c..0xfffffff0270dc594),
//! and gates CONFIG lock15 on PARAMS2 bit1 (0xd8454); the original mac13g kernel
//! checks page shift and region/bypass capabilities at VA9dc20b4, and decodes
//! a fault's SID from bits27:24 at VA9dc09e8 (full VAs start fffffe000).
//!
//! Original T6000 SPTM, like T8103's, programs source->context bytes at80..8c before
//! enabling streams (VA270bce64..bcecc); mapper entry270be1e0..be22c
//! rejects remapped sources. DMA therefore remaps the incoming SID once,
//! before context enable/TCR/TTBR. Remapped-fault SID provenance remains
//! unqualified and refuses instead of inventing captured metadata.
//! A separate T6000 UMMS owner exposes the native absent capture store and
//! disabled performance state. Unsupported SMMU context selection
//! (TCR23:16), active performance, APF filtering, auxiliary fault/capture
//! fields and the different 64-SID USB4 interface refuse explicitly.
//! This module does not qualify those board configurations by constructing a
//! successful-looking superset. Translation is cacheless and DMA synchronous.
use super::super::bus::{Access, Direction, MmioDevice, MmioError, Width, refuse};
use super::super::interrupt::{AicInput, Wire};
use super::{Profile, SMMU_BYTES, SMMU_OFFSET, descriptor::Format, legacy_umms};
use crate::platform::dma::{DmaError, Iommu, Memory};
use alloc::{rc::Rc, vec, vec::Vec};
use core::cell::RefCell;

const PARAMS1: u64 = 0;
const PARAMS2: u64 = 4;
const T6000_PARAMS3: u64 = 8;
const REGION: u32 = 1 << 31;
const SUPPORT_BYPASS: u32 = 1;
const SUPPORT_LOCK: u32 = 1 << 1;
const COMMAND: u64 = 0x20;
const INVALIDATE: u32 = 1 << 20;
const SELECT: u64 = 0x34;
const ERROR: u64 = 0x40;
const ERROR_ADDRESS: [u64; 2] = [0x50, 0x54];
const CONFIG: u64 = 0x60;
const LOCK: u32 = 1 << 15;
const REMAP: u64 = 0x80;
const ENABLED: u64 = 0xfc;
const TCR: u64 = 0x100;
const TTBR: u64 = 0x200;
const TRANSLATE: u32 = 1 << 7;
const BYPASS: u32 = 1 << 8;
const BYPASS_APF: u32 = 1 << 12;
const SMMU_CONTEXT: u32 = 0xff << 16;
const TCR_KNOWN: u32 = TRANSLATE | BYPASS | BYPASS_APF;
const TTBR_VALID: u32 = 1 << 31;
const TTBR_ADDRESS: u32 = !TTBR_VALID;
const TTBR_SHIFT: u32 = 12;
const TABLES: usize = 4;
const IOVA_BITS: u32 = 32;
const T8020_PA_BITS: u32 = 36;
const T6000_PA_BITS: u32 = 42;
const VALID: u64 = 1;
const SUBPAGE_DISABLE: u64 = 1 << 1;
const SUBPAGE_UNIT: u64 = 4;
const FLAG: u32 = 1 << 31;
const WRITE_ACCESS: u32 = 1 << 10;
const SID_SHIFT: u32 = 24;
const NO_TTBR: u32 = 1;
const NO_PMD: u32 = 1 << 1;
const NO_PTE: u32 = 1 << 2;
const WRITE_FAULT: u32 = 1 << 3;
const READ_FAULT: u32 = 1 << 4;
const REGION_FAULT: u32 = 1 << 7;
const T6000_ERROR_ACK_CODES: u32 = 0xb7f;
const PERF_CONTROL: u64 = 0x1000;
const PERF_STATUS: u64 = 0x100c;
const PERF_ACK_CODES: u32 = 0x2d;

pub(super) struct Dart {
    profile: Profile,
    streams: usize,
    page_shift: u32,
    powered: bool,
    clock_enabled: bool,
    quiesced: bool,
    reset: bool,
    apf: bool,
    select: u32,
    enabled: u32,
    locked: bool,
    remap: [u8; 16],
    tcr: Vec<u32>,
    ttbr: Vec<[u32; TABLES]>,
    error: u32,
    error_address: u64,
    irq: Option<AicInput>,
    level: bool,
    shared_fault: Option<(Rc<RefCell<Vec<bool>>>, usize)>,
    smmu: Option<legacy_umms::Umms>,
    performance: legacy_umms::Performance,
}

impl Dart {
    pub(super) fn bind_shared_irq(&mut self, irq: &super::SharedIrq) -> Result<(), &'static str> {
        if self.irq != Some(irq.input) {
            return Err("DART shared IRQ does not match its physical input");
        }
        if self.level
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

    pub(super) fn new(profile: Profile, streams: usize, irq: Option<AicInput>) -> Self {
        Self {
            profile,
            streams,
            page_shift: 14,
            powered: true,
            clock_enabled: true,
            quiesced: false,
            reset: false,
            apf: false,
            select: 0,
            enabled: 0,
            locked: false,
            remap: core::array::from_fn(|sid| sid as u8),
            tcr: vec![0; streams],
            ttbr: vec![[0; TABLES]; streams],
            error: 0,
            error_address: 0,
            irq,
            level: false,
            shared_fault: None,
            smmu: None,
            performance: legacy_umms::Performance::default(),
        }
    }

    pub(super) fn group(
        profile: Profile,
        streams: usize,
        irq: Option<AicInput>,
        count: usize,
    ) -> Vec<Self> {
        let levels = Rc::new(RefCell::new(vec![false; count]));
        (0..count)
            .map(|index| {
                let mut dart = Self::new(profile, streams, irq);
                dart.shared_fault = Some((levels.clone(), index));
                dart
            })
            .collect()
    }

    pub(super) fn with_apf(mut self, slices: usize) -> Self {
        self.apf = slices != 0;
        self
    }

    pub(super) fn supports_smmu(&self) -> bool {
        self.profile == Profile::T6000
    }

    pub(super) fn enable_smmu(&mut self) -> Result<(), &'static str> {
        if !self.supports_smmu() {
            return Err("legacy DART paired SMMU capture format is unsupported");
        }
        if self.smmu.is_some() {
            return Err("DART already has a paired SMMU instance");
        }
        self.smmu = Some(legacy_umms::Umms::default());
        Ok(())
    }

    pub(super) fn has_smmu(&self) -> bool {
        self.smmu.is_some()
    }

    pub(super) fn set_power(&mut self, powered: bool, retention: bool, access: &mut Access<'_>) {
        if self.powered && !powered && !retention {
            self.clear(access);
        }
        self.powered = powered;
    }

    pub(super) fn set_quiesced(&mut self, quiesced: bool) {
        self.quiesced = quiesced;
    }

    pub(super) fn set_clock(&mut self, enabled: bool) {
        self.clock_enabled = enabled;
    }

    pub(super) fn set_reset(&mut self, asserted: bool, access: &mut Access<'_>) {
        if asserted && !self.reset {
            self.clear(access);
        }
        self.reset = asserted;
    }

    fn clear(&mut self, access: &mut Access<'_>) {
        self.select = 0;
        self.enabled = 0;
        self.locked = false;
        self.remap = core::array::from_fn(|sid| sid as u8);
        self.tcr.fill(0);
        self.ttbr.fill([0; TABLES]);
        self.error = 0;
        self.error_address = 0;
        if let Some(smmu) = &mut self.smmu {
            smmu.clear();
        }
        self.performance = legacy_umms::Performance::default();
        self.signal(access);
    }

    fn unavailable(&self) -> Option<&'static str> {
        if !self.powered {
            Some("DART power domain is off")
        } else if !self.clock_enabled {
            Some("DART functional clock is gated")
        } else if self.reset {
            Some("DART reset is asserted")
        } else {
            None
        }
    }

    fn mask(&self) -> u32 {
        (1 << self.streams) - 1
    }

    fn sid_register(&self, offset: u64, base: u64, stride: u64) -> Option<usize> {
        let offset = offset.checked_sub(base)?;
        let sid = usize::try_from(offset / stride).ok()?;
        (offset.is_multiple_of(4) && sid < self.streams).then_some(sid)
    }

    fn target(&self, entry: u64, leaf: bool) -> Result<u64, DmaError> {
        let (format, bits) = match self.profile {
            Profile::T8020 => (Format::Dart1, T8020_PA_BITS),
            Profile::T6000 => (Format::Dart2, T6000_PA_BITS),
            Profile::T8110 => unreachable!("legacy format"),
        };
        format.target(entry, bits, self.page(), leaf)
    }

    fn entry(&self, memory: &mut dyn Memory, table: u64, index: u64) -> Result<u64, DmaError> {
        let mut bytes = [0; 8];
        let bits = self.page_shift - 3;
        if !memory.read(table + (index & ((1 << bits) - 1)) * 8, &mut bytes) {
            return Err(DmaError::Memory);
        }
        Ok(u64::from_le_bytes(bytes))
    }

    fn walk(
        &self,
        memory: &mut dyn Memory,
        input_sid: usize,
        iova: u64,
        last: u64,
        write: bool,
    ) -> Result<u64, DmaError> {
        if let Some(reason) = self.unavailable() {
            return Err(DmaError::Unsupported(reason));
        }
        if self.quiesced {
            return Err(DmaError::Unsupported("DART DMA is quiesced"));
        }
        if input_sid >= self.streams {
            return Err(DmaError::Unsupported(
                "DART incoming stream is outside the native profile",
            ));
        }
        let sid = usize::from(self.remap[input_sid]);
        if sid >= self.streams {
            return Err(DmaError::Unsupported(
                "DART remap target is outside the native profile",
            ));
        }
        if self.enabled & (1 << sid) == 0 {
            return Err(DmaError::Fault(NO_TTBR));
        }
        let tcr = self.tcr[sid];
        if tcr & (TRANSLATE | BYPASS) == TRANSLATE | BYPASS {
            return Err(DmaError::Unsupported(
                "DART simultaneous translation and bypass",
            ));
        }
        if self.apf && tcr & BYPASS_APF == 0 {
            return Err(DmaError::Unsupported(
                "legacy DART address permission filtering",
            ));
        }
        if tcr & BYPASS != 0 {
            return Ok(iova);
        }
        if tcr & TRANSLATE == 0 || iova >> IOVA_BITS != 0 {
            return Err(DmaError::Fault(NO_TTBR));
        }
        let bits = self.page_shift - 3;
        let ttbr_index = (iova >> (self.page_shift + 2 * bits)) as usize;
        let ttbr = self.ttbr[sid][ttbr_index];
        if ttbr & TTBR_VALID == 0 {
            return Err(DmaError::Fault(NO_TTBR));
        }
        let root = u64::from(ttbr & TTBR_ADDRESS) << TTBR_SHIFT;
        let pa_bits = if self.profile == Profile::T8020 {
            T8020_PA_BITS
        } else {
            T6000_PA_BITS
        };
        if root >> pa_bits != 0 {
            return Err(DmaError::Unsupported(
                "DART root address exceeds its native profile",
            ));
        }
        if root & (self.page() - 1) != 0 {
            return Err(DmaError::Unsupported("unaligned legacy DART root table"));
        }
        let first = self.entry(memory, root, iova >> (self.page_shift + bits))?;
        if first & VALID == 0 {
            return Err(DmaError::Fault(NO_PMD));
        }
        let page = self.entry(memory, self.target(first, false)?, iova >> self.page_shift)?;
        if page & VALID == 0 {
            return Err(DmaError::Fault(NO_PTE));
        }
        let target = self.target(page, true)?;
        let (no_read, no_write) = if self.profile == Profile::T8020 {
            (1 << 8, 1 << 7)
        } else {
            (1 << 3, 1 << 2)
        };
        if write && page & no_write != 0 {
            return Err(DmaError::Fault(WRITE_FAULT));
        }
        if !write && page & no_read != 0 {
            return Err(DmaError::Fault(READ_FAULT));
        }
        let offset = iova & (self.page() - 1);
        let subpage_disabled = self.profile == Profile::T8020 && page & SUBPAGE_DISABLE != 0;
        if !subpage_disabled {
            let first = page >> 52 & 0xfff;
            let end = page >> 40 & 0xfff;
            if offset / SUBPAGE_UNIT < first || (last & (self.page() - 1)) / SUBPAGE_UNIT > end {
                return Err(DmaError::Fault(REGION_FAULT));
            }
        }
        Ok(target + offset)
    }

    pub(super) fn context_route_geometry(&self) -> bool {
        self.profile == Profile::T6000 && self.streams == 16 && self.page_shift == 14 && !self.apf
    }

    /// Check every current incoming preimage without producing a fault.
    /// Successful walks have no cache, counter, descriptor or IRQ effects.
    pub(super) fn checked_context_translation(
        &self,
        memory: &mut dyn Memory,
        context: usize,
        iova: u64,
        last: u64,
        write: bool,
    ) -> Result<u64, DmaError> {
        let mut physical = None;
        for input in 0..self.streams {
            if usize::from(self.remap[input]) != context {
                continue;
            }
            let candidate =
                self.walk(memory, input, iova, last, write)
                    .map_err(|error| match error {
                        DmaError::Fault(_) => DmaError::Unsupported(
                            "T6000 context route has a faulting incoming SID alternative",
                        ),
                        DmaError::Memory => DmaError::Unsupported(
                            "T6000 context route has an inaccessible table alternative",
                        ),
                        other => other,
                    })?;
            if physical.is_some_and(|previous| previous != candidate) {
                return Err(DmaError::Unsupported(
                    "T6000 context route incoming SID alternatives diverge",
                ));
            }
            physical = Some(candidate);
        }
        physical.ok_or(DmaError::Unsupported(
            "T6000 context route has no current incoming SID preimage",
        ))
    }

    fn signal(&mut self, access: &mut Access<'_>) {
        let level = self.error & FLAG != 0;
        if self.level == level {
            return;
        }
        self.level = level;
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

    fn acknowledge_error(&mut self, value: u32) -> Result<(), &'static str> {
        if self.profile != Profile::T6000 {
            if value != 0 && value & FLAG == 0 {
                return Err("legacy DART code-only fault acknowledgement is not specified");
            }
            if value & FLAG != 0 {
                self.error = 0;
            }
            return Ok(());
        }
        if value & FLAG != 0 {
            // The original clear-all path reads ERROR and writes that exact
            // captured word (SPTM270bb83c..bb840). It does not establish
            // FLAG-only or stale/modified metadata acknowledgement effects.
            if value != self.error {
                return Err("T6000 DART acknowledgement is not its captured fault snapshot");
            }
            self.error = 0;
        } else if value != 0 {
            // SPTM270bbc64..bbc9c writes one selected code and reads back.
            // Validate the entire write before changing the first capture.
            if value & !T6000_ERROR_ACK_CODES != 0 || value.count_ones() != 1 {
                return Err("unknown T6000 DART code acknowledgement");
            }
            if self.error & value != 0 {
                self.error &= !value;
                if self.error & T6000_ERROR_ACK_CODES == 0 {
                    self.error = 0;
                }
            }
        }
        Ok(())
    }
}

impl Iommu for Dart {
    fn page(&self) -> u64 {
        1 << self.page_shift
    }

    fn translate(
        &mut self,
        memory: &mut dyn Memory,
        stream: usize,
        iova: u64,
        last: u64,
        write: bool,
        access: &mut Access<'_>,
    ) -> Result<u64, DmaError> {
        debug_assert!(last >= iova && last / self.page() == iova / self.page());
        let result = self.walk(memory, stream, iova, last, write);
        if let Err(DmaError::Fault(code)) = result {
            if stream < self.streams && usize::from(self.remap[stream]) != stream {
                return Err(DmaError::Unsupported(
                    "legacy DART remapped fault source-versus-context SID provenance",
                ));
            }
            if self.error & FLAG == 0 {
                self.error = FLAG
                    | (stream as u32 & 0xf) << SID_SHIFT
                    | if write { WRITE_ACCESS } else { 0 }
                    | code;
                self.error_address = iova;
            }
            self.signal(access);
        }
        result
    }
}

impl MmioDevice for Dart {
    fn name(&self) -> &'static str {
        if self.profile == Profile::T8020 {
            "dart-t8020"
        } else {
            "dart-t6000"
        }
    }

    fn read(&mut self, offset: u64, width: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        let fail = |reason| refuse(self.name(), offset, width, Direction::Read, reason);
        if width != Width::Word || !offset.is_multiple_of(4) {
            return Err(fail("legacy DART registers are aligned 32-bit words"));
        }
        if let Some(reason) = self.unavailable() {
            return Err(fail(reason));
        }
        if (SMMU_OFFSET..SMMU_OFFSET + SMMU_BYTES).contains(&offset) {
            return self
                .smmu
                .as_ref()
                .ok_or_else(|| fail("legacy DART has no paired UMMS instance"))?
                .read(offset - SMMU_OFFSET)
                .map(u64::from)
                .map_err(fail);
        }
        let value = match offset {
            PARAMS1 => REGION | self.page_shift << 24,
            PARAMS2 => SUPPORT_BYPASS | SUPPORT_LOCK,
            // Original T6000 SPTM270bc554..bc5b8 derives the native PA
            // aperture from bits29:24 and requires at most42 address bits.
            T6000_PARAMS3 if self.profile == Profile::T6000 => T6000_PA_BITS << 24,
            COMMAND => 0,
            SELECT => self.select,
            ERROR => self.error,
            CONFIG => {
                if self.locked {
                    LOCK
                } else {
                    0
                }
            }
            ENABLED => self.enabled,
            PERF_CONTROL if self.profile == Profile::T6000 => self.performance.control(),
            PERF_STATUS if self.profile == Profile::T6000 => self.performance.status(),
            _ if ERROR_ADDRESS.contains(&offset) => {
                (self.error_address >> (32 * usize::from(offset == ERROR_ADDRESS[1]))) as u32
            }
            _ if (REMAP..REMAP + 16).contains(&offset) => {
                let sid = (offset - REMAP) as usize;
                u32::from_le_bytes(
                    self.remap[sid..sid + 4]
                        .try_into()
                        .expect("four remap bytes"),
                )
            }
            _ if (TCR..TCR + 16 * 4).contains(&offset) => {
                let sid = self
                    .sid_register(offset, TCR, 4)
                    .ok_or_else(|| fail("legacy DART stream is outside the native profile"))?;
                self.tcr[sid]
            }
            _ if (TTBR..TTBR + 16 * 16).contains(&offset) => {
                let sid = self
                    .sid_register(offset, TTBR, 16)
                    .ok_or_else(|| fail("legacy DART stream is outside the native profile"))?;
                self.ttbr[sid][((offset - TTBR) % 16 / 4) as usize]
            }
            _ => {
                return Err(fail(
                    "unknown legacy DART register or unsupported capture/filter view",
                ));
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
        let name = self.name();
        let fail = |reason| refuse(name, offset, width, Direction::Write, reason);
        if width != Width::Word || !offset.is_multiple_of(4) {
            return Err(fail("legacy DART registers are aligned 32-bit words"));
        }
        if let Some(reason) = self.unavailable() {
            return Err(fail(reason));
        }
        let value = value as u32;
        if (SMMU_OFFSET..SMMU_OFFSET + SMMU_BYTES).contains(&offset) {
            return self
                .smmu
                .as_mut()
                .ok_or_else(|| fail("legacy DART has no paired UMMS instance"))?
                .write(offset - SMMU_OFFSET, value)
                .map_err(fail);
        }
        match offset {
            COMMAND if value == INVALIDATE => {}
            // T6000 powerup270bcfcc and powerdown270bdf60 initialize
            // an idle command word before polling. There is no queued work
            // or translation cache to cancel in this native profile.
            COMMAND if self.profile == Profile::T6000 && value == 0 => {}
            COMMAND => return Err(fail("unknown legacy DART stream command")),
            SELECT => self.select = value & self.mask(),
            ERROR => self.acknowledge_error(value).map_err(fail)?,
            CONFIG => {
                if value & !LOCK != 0 {
                    return Err(fail("unknown legacy DART CONFIG bits"));
                }
                self.locked |= value & LOCK != 0;
            }
            ENABLED => {
                if self.locked {
                    return Err(fail(
                        "legacy DART enabled-stream lock coverage is not specified",
                    ));
                }
                self.enabled = value & self.mask();
            }
            PERF_CONTROL if self.profile == Profile::T6000 => {
                self.performance.disable(value).map_err(fail)?;
            }
            PERF_STATUS if self.profile == Profile::T6000 => {
                self.performance
                    .acknowledge(value, PERF_ACK_CODES)
                    .map_err(fail)?;
            }
            _ if (REMAP..REMAP + 16).contains(&offset) => {
                if self.locked {
                    return Err(fail("legacy DART remap lock coverage is not specified"));
                }
                let sid = (offset - REMAP) as usize;
                if value
                    .to_le_bytes()
                    .iter()
                    .any(|&sid| usize::from(sid) >= self.streams)
                {
                    return Err(fail(
                        "legacy DART remap target is outside the native profile",
                    ));
                }
                self.remap[sid..sid + 4].copy_from_slice(&value.to_le_bytes());
            }
            _ if (TCR..TCR + 16 * 4).contains(&offset) => {
                let sid = self
                    .sid_register(offset, TCR, 4)
                    .ok_or_else(|| fail("legacy DART stream is outside the native profile"))?;
                if value & SMMU_CONTEXT != 0 {
                    return Err(fail("legacy DART SMMU stream context selection"));
                }
                if value & !TCR_KNOWN != 0 {
                    return Err(fail("unknown legacy DART TCR bits"));
                }
                if !self.locked {
                    self.tcr[sid] = value;
                }
            }
            _ if (TTBR..TTBR + 16 * 16).contains(&offset) => {
                let sid = self
                    .sid_register(offset, TTBR, 16)
                    .ok_or_else(|| fail("legacy DART stream is outside the native profile"))?;
                if !self.locked {
                    self.ttbr[sid][((offset - TTBR) % 16 / 4) as usize] = value;
                }
            }
            _ => {
                return Err(fail(
                    "unknown legacy DART register or unsupported capture/filter view",
                ));
            }
        }
        self.signal(access);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::{
        apple::interrupt::InterruptLatch,
        dma::{Port, tests::Ram},
    };

    const ROOT: u64 = 0x8_0000_0000;
    const PAGE: u64 = 0x4000;
    const LEAF: u64 = ROOT + PAGE;
    const FRAME: u64 = ROOT + 2 * PAGE;
    const IOVA: u64 = 0x0200_4000;

    fn pte(profile: Profile, physical: u64) -> u64 {
        let address = if profile == Profile::T8020 {
            physical
        } else {
            physical >> 4
        };
        address | VALID
    }

    fn setup(profile: Profile) -> (Dart, Ram, InterruptLatch) {
        let mut model = Dart::new(profile, 16, Some(AicInput::new(0, 7)));
        let mut ram = Ram::new(ROOT, (4 * PAGE) as usize);
        ram.put_u64(ROOT + 8, pte(profile, LEAF));
        ram.put_u64(LEAF + 8, pte(profile, FRAME) | 0xfff << 40);
        let mut sink = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut sink);
        for (offset, value) in [
            (ENABLED, 3),
            (TCR + 4, TRANSLATE),
            (TTBR + 16, TTBR_VALID | (ROOT >> TTBR_SHIFT) as u32),
        ] {
            model
                .write(offset, Width::Word, u64::from(value), &mut a)
                .unwrap();
        }
        (model, ram, sink)
    }

    #[test]
    fn both_legacy_formats_walk_and_transfer_through_the_public_dma_boundary() {
        for profile in [Profile::T8020, Profile::T6000] {
            let (mut model, mut ram, mut sink) = setup(profile);
            let mut a = Access::new(0, 0, &mut sink);
            let mut port = Port {
                iommu: &mut model,
                stream: 1,
                memory: &mut ram,
                access: &mut a,
            };
            port.write(IOVA + 7, &[0xde, 0xad, 0xbe, 0xef]).unwrap();
            let mut actual = [0; 4];
            assert!(ram.read(FRAME + 7, &mut actual));
            assert_eq!(actual, [0xde, 0xad, 0xbe, 0xef]);
            assert_eq!(
                model.read(PARAMS1, Width::Word, &mut a),
                Ok(u64::from(REGION | 14 << 24))
            );
            assert_eq!(model.read(PARAMS2, Width::Word, &mut a), Ok(3));
        }
    }

    fn remapped_t6000() -> (Dart, Ram, InterruptLatch) {
        let (mut model, ram, mut sink) = setup(Profile::T6000);
        let mut access = Access::new(0, 0, &mut sink);
        for (offset, value) in [
            (ENABLED, 1),
            (TCR, TRANSLATE),
            (TTBR, TTBR_VALID | (ROOT >> TTBR_SHIFT) as u32),
            (REMAP + 4, 0x0706_0004),
        ] {
            model
                .write(offset, Width::Word, u64::from(value), &mut access)
                .unwrap();
        }
        (model, ram, sink)
    }

    #[test]
    fn t6000_remap_selects_the_target_context_before_enable_and_tables() {
        let (mut model, mut ram, mut sink) = remapped_t6000();
        let mut access = Access::new(0, 0, &mut sink);
        assert_eq!(
            model.read(T6000_PARAMS3, Width::Word, &mut access),
            Ok(u64::from(T6000_PA_BITS << 24))
        );
        assert!(
            model
                .write(T6000_PARAMS3, Width::Word, 0, &mut access)
                .is_err()
        );
        // Only context0 is enabled, and only its root is used. Incoming5 is
        // absent from the enable bitmap and must not select context5 tables.
        let mut port = Port {
            iommu: &mut model,
            stream: 5,
            memory: &mut ram,
            access: &mut access,
        };
        port.write(IOVA, &[0x35, 0x79]).unwrap();
        let mut bytes = [0; 2];
        assert!(ram.read(FRAME, &mut bytes));
        assert_eq!(bytes, [0x35, 0x79]);
        assert_eq!(model.read(ERROR, Width::Word, &mut access), Ok(0));
        assert!(
            model
                .write(REMAP + 4, Width::Word, 0x0710_0004, &mut access)
                .is_err()
        );
        assert_eq!(
            model.read(REMAP + 4, Width::Word, &mut access),
            Ok(0x0706_0004)
        );
        // Invalidation cannot rewrite the stream table or target context.
        model
            .write(COMMAND, Width::Word, u64::from(INVALIDATE), &mut access)
            .unwrap();
        model.write(COMMAND, Width::Word, 0, &mut access).unwrap();
        assert_eq!(
            model.translate(&mut ram, 5, IOVA, IOVA, false, &mut access),
            Ok(FRAME)
        );
    }

    #[test]
    fn remapped_fault_refuses_unknown_metadata_after_preserving_completed_pages() {
        let (mut model, mut ram, mut sink) = remapped_t6000();
        let mut access = Access::new(0, 0, &mut sink);
        let mut port = Port {
            iommu: &mut model,
            stream: 5,
            memory: &mut ram,
            access: &mut access,
        };
        assert_eq!(
            port.write(IOVA + PAGE - 2, &[1, 2, 3, 4]),
            Err(DmaError::Unsupported(
                "legacy DART remapped fault source-versus-context SID provenance"
            ))
        );
        let mut bytes = [0; 2];
        assert!(ram.read(FRAME + PAGE - 2, &mut bytes));
        assert_eq!(bytes, [1, 2]);
        assert_eq!(model.read(ERROR, Width::Word, &mut access), Ok(0));
        assert!(!sink.is_asserted(Wire::Aic(AicInput::new(0, 7))));
    }

    #[test]
    fn remapped_partial_failure_and_unqualified_acknowledgements_preserve_the_first_capture() {
        let (mut model, mut ram, mut sink) = remapped_t6000();
        let first_address = IOVA + 0x80;
        let first_capture = {
            let mut access = Access::new(0, 0, &mut sink);
            assert_eq!(
                model.translate(
                    &mut ram,
                    2,
                    first_address,
                    first_address,
                    false,
                    &mut access
                ),
                Err(DmaError::Fault(NO_TTBR))
            );
            let captured = model.read(ERROR, Width::Word, &mut access).unwrap();
            for bad in [
                u64::from(FLAG),
                captured ^ (1 << SID_SHIFT),
                captured ^ u64::from(WRITE_ACCESS),
                captured | 1 << 30,
            ] {
                assert!(model.write(ERROR, Width::Word, bad, &mut access).is_err());
                assert_eq!(model.read(ERROR, Width::Word, &mut access), Ok(captured));
            }
            model.write(ERROR, Width::Word, 0, &mut access).unwrap();
            model
                .write(ERROR, Width::Word, u64::from(NO_PTE), &mut access)
                .unwrap();
            let mut port = Port {
                iommu: &mut model,
                stream: 5,
                memory: &mut ram,
                access: &mut access,
            };
            assert_eq!(
                port.write(IOVA + PAGE - 2, &[0x21, 0x43, 0x65, 0x87]),
                Err(DmaError::Unsupported(
                    "legacy DART remapped fault source-versus-context SID provenance"
                ))
            );
            let mut bytes = [0; 2];
            assert!(ram.read(FRAME + PAGE - 2, &mut bytes));
            assert_eq!(bytes, [0x21, 0x43]);
            assert!(ram.read(FRAME + PAGE, &mut bytes));
            assert_eq!(bytes, [0, 0]);
            assert_eq!(model.read(ERROR, Width::Word, &mut access), Ok(captured));
            assert_eq!(
                model.read(ERROR_ADDRESS[0], Width::Word, &mut access),
                Ok(first_address)
            );
            captured
        };
        assert!(sink.is_asserted(Wire::Aic(AicInput::new(0, 7))));
        {
            let mut access = Access::new(0, 0, &mut sink);
            model
                .write(ERROR, Width::Word, first_capture, &mut access)
                .unwrap();
        }
        assert!(!sink.is_asserted(Wire::Aic(AicInput::new(0, 7))));
        {
            let mut access = Access::new(0, 0, &mut sink);
            assert_eq!(
                model.translate(&mut ram, 1, IOVA, IOVA, true, &mut access),
                Err(DmaError::Fault(NO_TTBR))
            );
            let next_capture = model.read(ERROR, Width::Word, &mut access).unwrap();
            assert_ne!(first_capture, next_capture);
            assert!(
                model
                    .write(ERROR, Width::Word, first_capture, &mut access)
                    .is_err()
            );
            assert_eq!(
                model.read(ERROR, Width::Word, &mut access),
                Ok(next_capture)
            );
            assert_eq!(
                model.read(ERROR_ADDRESS[0], Width::Word, &mut access),
                Ok(IOVA)
            );
            model
                .write(ERROR, Width::Word, u64::from(NO_TTBR), &mut access)
                .unwrap();
        }
        assert!(!sink.is_asserted(Wire::Aic(AicInput::new(0, 7))));
    }

    #[test]
    fn t6000_code_ack_clears_only_the_pending_code_and_updates_irq() {
        let (mut model, mut ram, mut sink) = setup(Profile::T6000);
        {
            let mut access = Access::new(0, 0, &mut sink);
            assert_eq!(
                model.translate(&mut ram, 2, IOVA, IOVA, false, &mut access),
                Err(DmaError::Fault(NO_TTBR))
            );
            model
                .write(ERROR, Width::Word, u64::from(NO_PTE), &mut access)
                .unwrap();
            assert_ne!(model.read(ERROR, Width::Word, &mut access), Ok(0));
            assert!(
                model
                    .write(ERROR, Width::Word, u64::from(NO_TTBR | NO_PTE), &mut access)
                    .is_err()
            );
        }
        assert!(sink.is_asserted(Wire::Aic(AicInput::new(0, 7))));
        {
            let mut access = Access::new(0, 0, &mut sink);
            model
                .write(ERROR, Width::Word, u64::from(NO_TTBR), &mut access)
                .unwrap();
            assert_eq!(model.read(ERROR, Width::Word, &mut access), Ok(0));
        }
        assert!(!sink.is_asserted(Wire::Aic(AicInput::new(0, 7))));
    }

    #[test]
    fn t6000_umms_has_distinct_fault_ownership_and_no_invented_diagnostic_fields() {
        let (mut model, mut ram, mut sink) = setup(Profile::T6000);
        model.enable_smmu().unwrap();
        let mut access = Access::new(0, 0, &mut sink);
        assert_eq!(model.read(SMMU_OFFSET, Width::Word, &mut access), Ok(0));
        assert_eq!(
            model.read(SMMU_OFFSET + 0x1008, Width::Word, &mut access),
            Ok(0)
        );
        assert_eq!(model.read(PERF_STATUS, Width::Word, &mut access), Ok(0));
        assert_eq!(
            model.translate(&mut ram, 2, IOVA, IOVA, false, &mut access),
            Err(DmaError::Fault(NO_TTBR))
        );
        // UMMS acknowledgements cannot clear a paired TRAD translation fault.
        model
            .write(SMMU_OFFSET + 0x40, Width::Word, 4, &mut access)
            .unwrap();
        model
            .write(SMMU_OFFSET + 0x1008, Width::Word, 1 << 20, &mut access)
            .unwrap();
        assert_ne!(model.read(ERROR, Width::Word, &mut access), Ok(0));
        assert_eq!(
            model.read(SMMU_OFFSET + 0x40, Width::Word, &mut access),
            Ok(0)
        );
        for offset in [
            0x44, 0x48, 0x4c, 0x50, 0x58, 0x60, 0x64, 0x1004, 0x1020, 0x2000, 0x3ffc,
        ] {
            assert!(
                model
                    .read(SMMU_OFFSET + offset, Width::Word, &mut access)
                    .is_err()
            );
        }
        for offset in [0, 0x5c, 0x80, 0x2000] {
            assert!(
                model
                    .write(SMMU_OFFSET + offset, Width::Word, 0, &mut access)
                    .is_err()
            );
        }
        assert!(
            model
                .write(SMMU_OFFSET + 0x1000, Width::Word, 1, &mut access)
                .is_err()
        );
        assert!(
            model
                .write(PERF_CONTROL, Width::Word, 1, &mut access)
                .is_err()
        );
        for (offset, value) in [
            (PERF_STATUS, 2),
            (SMMU_OFFSET + 0x1008, 1),
            (SMMU_OFFSET + 0x40, 0x8000_0000),
            (SMMU_OFFSET + 0x40, 0xc),
        ] {
            assert!(
                model
                    .write(offset, Width::Word, value, &mut access)
                    .is_err()
            );
        }
        assert_eq!(
            model.read(SMMU_OFFSET + 0x1000, Width::Word, &mut access),
            Ok(0)
        );
        assert!(
            model
                .write(SMMU_OFFSET + 0x20, Width::Word, LOCK.into(), &mut access)
                .is_err()
        );
        assert_eq!(
            model.read(SMMU_OFFSET + 0x20, Width::Word, &mut access),
            Ok(0)
        );
        assert_ne!(model.read(ERROR, Width::Word, &mut access), Ok(0));
    }

    #[test]
    fn paired_t6000_umms_obeys_the_translator_lifecycle_and_retention() {
        for retention in [false, true] {
            let (mut model, mut ram, mut sink) = setup(Profile::T6000);
            model.enable_smmu().unwrap();
            let mut access = Access::new(0, 0, &mut sink);
            model
                .write(SMMU_OFFSET + 0x20, Width::Word, 1 << 31, &mut access)
                .unwrap();
            model.set_clock(false);
            assert!(model.read(SMMU_OFFSET, Width::Word, &mut access).is_err());
            model.set_clock(true);
            model.set_quiesced(true);
            assert!(
                model
                    .translate(&mut ram, 1, IOVA, IOVA, false, &mut access)
                    .is_err()
            );
            assert_eq!(
                model.read(SMMU_OFFSET + 0x20, Width::Word, &mut access),
                Ok(1 << 31)
            );
            model.set_power(false, retention, &mut access);
            assert!(model.read(SMMU_OFFSET, Width::Word, &mut access).is_err());
            model.set_power(true, retention, &mut access);
            let retained = model.read(SMMU_OFFSET + 0x20, Width::Word, &mut access);
            if retention {
                assert_eq!(retained, Ok(1 << 31));
            } else {
                assert!(retained.is_err());
            }
            model.set_reset(true, &mut access);
            assert!(model.read(SMMU_OFFSET, Width::Word, &mut access).is_err());
            model.set_reset(false, &mut access);
            assert!(model.has_smmu());
            assert!(
                model
                    .read(SMMU_OFFSET + 0x20, Width::Word, &mut access)
                    .is_err()
            );
            model
                .write(SMMU_OFFSET + 0x20, Width::Word, 0, &mut access)
                .unwrap();
            assert_eq!(
                model.read(SMMU_OFFSET + 0x20, Width::Word, &mut access),
                Ok(0)
            );
        }
    }

    #[test]
    fn permissions_and_subpage_disable_have_generation_specific_effects() {
        for profile in [Profile::T8020, Profile::T6000] {
            let (mut model, mut ram, mut sink) = setup(profile);
            let mut a = Access::new(0, 0, &mut sink);
            let (read, write) = if profile == Profile::T8020 {
                (1 << 8, 1 << 7)
            } else {
                (1 << 3, 1 << 2)
            };
            for (bits, is_write, fault) in [(read, false, READ_FAULT), (write, true, WRITE_FAULT)] {
                ram.put_u64(LEAF + 8, pte(profile, FRAME) | 0xfff << 40 | bits);
                assert_eq!(
                    model.translate(&mut ram, 1, IOVA, IOVA, is_write, &mut a),
                    Err(DmaError::Fault(fault))
                );
                let captured = model.read(ERROR, Width::Word, &mut a).unwrap();
                model.write(ERROR, Width::Word, captured, &mut a).unwrap();
            }
            // Only bytes0x10..0x1f are accessible. t8020 bit1 disables this
            // bound; t6000 bit1 means uncached and cannot bypass protection.
            ram.put_u64(
                LEAF + 8,
                pte(profile, FRAME) | 4 << 52 | 7 << 40 | SUBPAGE_DISABLE,
            );
            assert_eq!(
                model.translate(&mut ram, 1, IOVA + 0x10, IOVA + 0x1f, false, &mut a),
                Ok(FRAME + 0x10)
            );
            let result = model.translate(&mut ram, 1, IOVA, IOVA, false, &mut a);
            assert_eq!(
                result,
                if profile == Profile::T8020 {
                    Ok(FRAME)
                } else {
                    Err(DmaError::Fault(REGION_FAULT))
                }
            );
            if profile == Profile::T6000 {
                // Region7 is outside the original code-only ACK mask, but
                // the clear-all path can acknowledge its captured snapshot.
                let captured = model.read(ERROR, Width::Word, &mut a).unwrap();
                assert!(
                    model
                        .write(ERROR, Width::Word, REGION_FAULT.into(), &mut a)
                        .is_err()
                );
                assert_eq!(model.read(ERROR, Width::Word, &mut a), Ok(captured));
                model.write(ERROR, Width::Word, captured, &mut a).unwrap();
                assert_eq!(model.read(ERROR, Width::Word, &mut a), Ok(0));
            }
        }
    }

    #[test]
    fn missing_tables_disabled_streams_and_out_of_range_iovas_fault() {
        for profile in [Profile::T8020, Profile::T6000] {
            let (mut model, mut ram, mut sink) = setup(profile);
            let mut a = Access::new(0, 0, &mut sink);
            for (sid, iova, fault) in [
                (2, IOVA, NO_TTBR),
                (1, 1 << 32, NO_TTBR),
                (1, 0x400_0000, NO_PMD),
                (1, IOVA + PAGE, NO_PTE),
            ] {
                assert_eq!(
                    model.translate(&mut ram, sid, iova, iova, false, &mut a),
                    Err(DmaError::Fault(fault))
                );
                let captured = model.read(ERROR, Width::Word, &mut a).unwrap();
                model.write(ERROR, Width::Word, captured, &mut a).unwrap();
            }
            model.write(TTBR + 16, Width::Word, 0, &mut a).unwrap();
            assert_eq!(
                model.translate(&mut ram, 1, IOVA, IOVA, false, &mut a),
                Err(DmaError::Fault(NO_TTBR))
            );
        }
    }

    #[test]
    fn fault_capture_preserves_direction_and_address_until_acknowledged() {
        let (mut model, mut ram, mut sink) = setup(Profile::T8020);
        {
            let mut a = Access::new(0, 0, &mut sink);
            ram.put_u64(LEAF + 8, pte(Profile::T8020, FRAME) | 0xfff << 40 | 1 << 7);
            assert_eq!(
                model.translate(&mut ram, 1, IOVA, IOVA, true, &mut a),
                Err(DmaError::Fault(WRITE_FAULT))
            );
            assert_eq!(
                model.read(ERROR, Width::Word, &mut a),
                Ok(u64::from(
                    FLAG | WRITE_ACCESS | 1 << SID_SHIFT | WRITE_FAULT
                ))
            );
            assert!(model.translate(&mut ram, 0, 0, 0, false, &mut a).is_err());
            assert_eq!(model.read(ERROR_ADDRESS[0], Width::Word, &mut a), Ok(IOVA));
        }
        assert!(sink.is_asserted(Wire::Aic(AicInput::new(0, 7))));
        {
            let mut a = Access::new(0, 0, &mut sink);
            model
                .write(ERROR, Width::Word, u64::from(FLAG | WRITE_FAULT), &mut a)
                .unwrap();
        }
        assert!(!sink.is_asserted(Wire::Aic(AicInput::new(0, 7))));
    }

    #[test]
    fn stream_bypass_and_cacheless_invalidation_do_not_skip_other_controls() {
        let (mut model, mut ram, mut sink) = setup(Profile::T6000);
        let mut a = Access::new(0, 0, &mut sink);
        model
            .write(TCR, Width::Word, u64::from(BYPASS | BYPASS_APF), &mut a)
            .unwrap();
        assert_eq!(
            model.translate(&mut ram, 0, FRAME, FRAME, true, &mut a),
            Ok(FRAME)
        );
        model
            .write(TCR, Width::Word, u64::from(TRANSLATE | BYPASS), &mut a)
            .unwrap();
        assert!(matches!(
            model.translate(&mut ram, 0, FRAME, FRAME, false, &mut a),
            Err(DmaError::Unsupported(_))
        ));
        ram.put_u64(LEAF + 8, pte(Profile::T6000, FRAME + PAGE) | 0xfff << 40);
        model.write(SELECT, Width::Word, 2, &mut a).unwrap();
        model
            .write(COMMAND, Width::Word, u64::from(INVALIDATE), &mut a)
            .unwrap();
        assert_eq!(model.read(COMMAND, Width::Word, &mut a), Ok(0));
        assert_eq!(
            model.translate(&mut ram, 1, IOVA, IOVA, false, &mut a),
            Ok(FRAME + PAGE)
        );
        ram.put_u64(LEAF + 8, 0);
        assert_eq!(
            model.translate(&mut ram, 1, IOVA, IOVA, false, &mut a),
            Err(DmaError::Fault(NO_PTE))
        );
    }

    #[test]
    fn dma_fault_on_a_later_page_preserves_completed_bytes_and_first_fault() {
        for profile in [Profile::T8020, Profile::T6000] {
            let (mut model, mut ram, mut sink) = setup(profile);
            let mut a = Access::new(0, 0, &mut sink);
            let mut port = Port {
                iommu: &mut model,
                stream: 1,
                memory: &mut ram,
                access: &mut a,
            };
            assert_eq!(
                port.write(IOVA + PAGE - 2, &[0x12, 0x34, 0x56, 0x78]),
                Err(DmaError::Fault(NO_PTE))
            );
            let mut actual = [0; 2];
            assert!(ram.read(FRAME + PAGE - 2, &mut actual));
            assert_eq!(actual, [0x12, 0x34]);
            assert!(ram.read(FRAME + PAGE, &mut actual));
            assert_eq!(actual, [0, 0]);
            assert_eq!(
                model.read(ERROR_ADDRESS[0], Width::Word, &mut a),
                Ok(IOVA + PAGE)
            );
            assert_eq!(
                model.read(ERROR, Width::Word, &mut a),
                Ok(u64::from(FLAG | WRITE_ACCESS | 1 << SID_SHIFT | NO_PTE))
            );
        }
    }

    #[test]
    fn inaccessible_tables_and_unrepresentable_roots_do_not_fabricate_a_translation() {
        for profile in [Profile::T8020, Profile::T6000] {
            let (mut model, mut ram, mut sink) = setup(profile);
            let mut a = Access::new(0, 0, &mut sink);
            // A valid root within the profile but outside backing RAM is
            // an actual memory failure, with no guessed hardware AXI code.
            model
                .write(
                    TTBR + 16,
                    Width::Word,
                    u64::from(TTBR_VALID) | (ROOT + 4 * PAGE) >> TTBR_SHIFT,
                    &mut a,
                )
                .unwrap();
            assert_eq!(
                model.translate(&mut ram, 1, IOVA, IOVA, false, &mut a),
                Err(DmaError::Memory)
            );
            assert_eq!(model.read(ERROR, Width::Word, &mut a), Ok(0));
            model
                .write(
                    TTBR + 16,
                    Width::Word,
                    u64::from(TTBR_VALID) | (ROOT + 0x1000) >> TTBR_SHIFT,
                    &mut a,
                )
                .unwrap();
            assert_eq!(
                model.translate(&mut ram, 1, IOVA, IOVA, false, &mut a),
                Err(DmaError::Unsupported("unaligned legacy DART root table"))
            );
            assert_eq!(model.read(ERROR, Width::Word, &mut a), Ok(0));
            let pa_bits = if profile == Profile::T8020 {
                T8020_PA_BITS
            } else {
                T6000_PA_BITS
            };
            model
                .write(
                    TTBR + 16,
                    Width::Word,
                    u64::from(TTBR_VALID) | 1 << (pa_bits - TTBR_SHIFT),
                    &mut a,
                )
                .unwrap();
            assert_eq!(
                model.translate(&mut ram, 1, IOVA, IOVA, false, &mut a),
                Err(DmaError::Unsupported(
                    "DART root address exceeds its native profile"
                ))
            );
            assert_eq!(model.read(ERROR, Width::Word, &mut a), Ok(0));
        }
    }

    #[test]
    fn lifecycle_and_configuration_lock_preserve_isolation() {
        for retention in [false, true] {
            let (mut model, mut ram, mut sink) = setup(Profile::T8020);
            let mut a = Access::new(0, 0, &mut sink);
            model
                .write(CONFIG, Width::Word, u64::from(LOCK), &mut a)
                .unwrap();
            model
                .write(TCR + 4, Width::Word, u64::from(BYPASS), &mut a)
                .unwrap();
            assert_eq!(
                model.read(TCR + 4, Width::Word, &mut a),
                Ok(u64::from(TRANSLATE))
            );
            model.set_quiesced(true);
            assert!(matches!(
                model.translate(&mut ram, 1, IOVA, IOVA, false, &mut a),
                Err(DmaError::Unsupported(_))
            ));
            model.set_power(false, retention, &mut a);
            assert!(model.read(PARAMS1, Width::Word, &mut a).is_err());
            model.set_power(true, retention, &mut a);
            assert_eq!(
                model.read(TCR + 4, Width::Word, &mut a),
                Ok(if retention { u64::from(TRANSLATE) } else { 0 })
            );
            model.set_reset(true, &mut a);
            assert!(model.read(PARAMS1, Width::Word, &mut a).is_err());
            model.set_reset(false, &mut a);
            assert_eq!(model.read(CONFIG, Width::Word, &mut a), Ok(0));
            assert_eq!(model.read(ENABLED, Width::Word, &mut a), Ok(0));
        }
    }

    #[test]
    fn unknown_contexts_and_capture_refuse_without_fabricating_effects() {
        let (mut model, mut ram, mut sink) = setup(Profile::T8020);
        let mut a = Access::new(0, 0, &mut sink);
        assert!(
            model
                .write(TCR + 4, Width::Word, u64::from(TRANSLATE | 1 << 16), &mut a)
                .is_err()
        );
        assert_eq!(
            model.read(TCR + 4, Width::Word, &mut a),
            Ok(u64::from(TRANSLATE))
        );
        for (offset, width) in [
            (0x44, Width::Word),
            (0x2000, Width::Word),
            (TCR + 1, Width::Word),
            (PARAMS1, Width::Double),
        ] {
            assert!(model.read(offset, width, &mut a).is_err());
        }
        // M1 routes an incoming stream like T6000: SID 0 takes context 1.
        let direct = model.translate(&mut ram, 1, IOVA, IOVA, false, &mut a);
        assert!(direct.is_ok());
        model
            .write(REMAP, Width::Word, 0x0302_0101, &mut a)
            .unwrap();
        assert_eq!(
            model.translate(&mut ram, 0, IOVA, IOVA, false, &mut a),
            direct
        );
        let mut filtered = Dart::new(Profile::T6000, 16, None).with_apf(1);
        filtered.write(ENABLED, Width::Word, 1, &mut a).unwrap();
        filtered
            .write(TCR, Width::Word, u64::from(BYPASS), &mut a)
            .unwrap();
        assert_eq!(
            filtered.translate(&mut ram, 0, FRAME, FRAME, false, &mut a),
            Err(DmaError::Unsupported(
                "legacy DART address permission filtering"
            ))
        );
    }
}
