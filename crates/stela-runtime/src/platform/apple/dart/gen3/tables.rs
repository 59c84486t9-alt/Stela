//! Recovered gen3 table/data effects, with explicit context qualification.
//!
//! The original software walk/leaf builder and fault levels are pinned in
//! `docs/research/dart-iommu.md`. This is not a gen3 MMIO profile: full VA
//! context, untranslated/bypass, security/APF, remap, IRQ and ordering are
//! still independently required. Explicit software contexts can bind their
//! recovered bounds/geometry; native out-of-context faults remain unqualified.
use super::context::{Context, Geometry, PAGE_BYTES as PAGE};
use super::descriptor::Encoding;
use super::fault::{Capture, Code, Level, Record};
use super::handoff::Handoff;
use super::streams::{self, Command, Snapshot};
use crate::platform::{
    apple::bus::Access,
    dma::{DmaError, Iommu, Memory},
};
use alloc::{vec, vec::Vec};

const PA_BITS: u32 = 42;
const TRANSLATE: u32 = 1;
const CONTEXT: u32 = 1 << 3;
const TTBR_VALID: u32 = 1;
const TTBR_ADDRESS: u32 = 0x3fff_fffc;
const ENTRY_VALID: u64 = 1;
const NO_WRITE: u64 = 1 << 2;
const NO_READ: u64 = 1 << 3;
const SUBPAGE_UNIT: u64 = 4;

#[derive(Clone, Copy, Default)]
struct Stream {
    enabled: bool,
    config: u32,
    ttbr: u32,
    context: Option<Context>,
}

pub struct Tables {
    streams: Vec<Stream>,
    encoding: Encoding,
    faults: Capture,
    quiesced: bool,
}

impl Tables {
    pub fn new(streams: usize) -> Result<Self, &'static str> {
        Self::with_encoding(streams, Encoding::Shift4)
    }

    /// Bind the original builder's explicit RAM encoding. Native revision
    /// and mode qualification belong to the profile owner; this constructor
    /// does not infer them from software context or expose an MMIO profile.
    pub fn with_encoding(streams: usize, encoding: Encoding) -> Result<Self, &'static str> {
        let faults = Capture::new(streams)?;
        Ok(Self {
            streams: vec![Stream::default(); streams],
            encoding,
            faults,
            quiesced: false,
        })
    }

    /// Set only the recovered zero-context translation configurations. The
    /// register owner must enforce protection and supply lifecycle before
    /// calling; this does not implement missing register-security domains.
    pub fn configure(&mut self, sid: usize, config: u32, ttbr: u32) -> Result<(), &'static str> {
        self.configure_stream(sid, config, ttbr, None)
    }

    /// Bind source-validated software bounds before allowing a high-window
    /// walk. This is not native context/security or MMIO profile admission.
    pub fn configure_context(
        &mut self,
        sid: usize,
        config: u32,
        ttbr: u32,
        context: Context,
    ) -> Result<(), &'static str> {
        if Geometry::from_tcr(config) != context.geometry() {
            return Err("gen3 DART TCR geometry disagrees with its validated context");
        }
        self.configure_stream(sid, config, ttbr, Some(context))
    }

    /// Use the original native-client root qualification for actual RAM
    /// walks. This still exposes no native MMIO profile: filter, security,
    /// fault metadata and publication completion remain independent gates.
    pub fn configure_handoff(
        &mut self,
        sid: usize,
        ttbr: u32,
        handoff: Handoff,
    ) -> Result<(), &'static str> {
        if self.encoding != handoff.encoding() {
            return Err("gen3 DART RAM encoding disagrees with the qualified handoff");
        }
        self.configure_stream(sid, handoff.config(), ttbr, Some(handoff.context()))
    }

    fn configure_stream(
        &mut self,
        sid: usize,
        config: u32,
        ttbr: u32,
        context: Option<Context>,
    ) -> Result<(), &'static str> {
        if config & !(TRANSLATE | CONTEXT) != 0 {
            return Err("gen3 DART stream context, remap or filter configuration is unsupported");
        }
        if ttbr & !(TTBR_VALID | TTBR_ADDRESS) != 0 {
            return Err("gen3 DART TTBR contains unmodeled fields");
        }
        let stream = self
            .streams
            .get_mut(sid)
            .ok_or("gen3 DART configuration SID is outside its native bounds")?;
        stream.config = config;
        stream.ttbr = ttbr;
        stream.context = context;
        Ok(())
    }

    pub fn set_enabled(&mut self, sid: usize, enabled: bool) -> Result<(), &'static str> {
        self.streams
            .get_mut(sid)
            .ok_or("gen3 DART enable SID is outside its native bounds")?
            .enabled = enabled;
        Ok(())
    }

    /// The original readable set-side words. Clear-side readback is not
    /// inferred from an ignored posted-write drain read in the source.
    pub fn read_streams(&self, offset: u64) -> Result<u32, &'static str> {
        if streams::word(offset, streams::DISABLE).is_ok() {
            return Err("gen3 DART clear-side stream readback is unqualified");
        }
        let word = streams::word(offset, streams::ENABLE)?;
        streams::validate(self.streams.len(), word, 0)?;
        Ok(
            self.streams[word * 32..self.streams.len().min((word + 1) * 32)]
                .iter()
                .enumerate()
                .fold(0, |bits, (sid, stream)| {
                    bits | u32::from(stream.enabled) << sid
                }),
        )
    }

    /// Execute a native set/clear word without changing unselected streams,
    /// translation bindings or pending faults. Validate every bit first.
    pub fn stream_command(&mut self, command: Command) -> Result<(), &'static str> {
        streams::validate(self.streams.len(), command.word(), command.bits())?;
        let first = command.word() * 32;
        let last = self.streams.len().min(first + 32);
        for (sid, stream) in self.streams[first..last].iter_mut().enumerate() {
            if command.bits() & (1 << sid) != 0 {
                stream.enabled = command.enabled();
            }
        }
        Ok(())
    }

    /// Execute the recovered retained stream shutdown after the owning
    /// boundary's DSB SY. This saves actual enable words and disables only
    /// translating streams. It does not claim physical power/reset effects,
    /// clear fault evidence or synthesize MMIO write/error completion.
    pub fn save_disable_translation(&mut self) -> Snapshot {
        let words = (0..self.streams.len().div_ceil(32))
            .map(|word| {
                self.read_streams(streams::ENABLE + word as u64 * 4)
                    .unwrap()
            })
            .collect();
        for stream in &mut self.streams {
            if stream.config & TRANSLATE != 0 {
                stream.enabled = false;
            }
        }
        Snapshot::new(self.streams.len(), words)
    }

    /// Execute the original set-side restore of actual saved words. This
    /// ORs their bits; it does not replace or clear newly enabled streams.
    /// The register owner must restore/qualify other state before calling.
    pub fn restore_enables(&mut self, snapshot: &Snapshot) -> Result<(), &'static str> {
        if snapshot.streams() != self.streams.len() {
            return Err("gen3 DART saved enable state belongs to a different SID geometry");
        }
        for (word, bits) in snapshot.words().iter().copied().enumerate() {
            self.stream_command(Command::decode(streams::ENABLE + word as u64 * 4, bits)?)?;
        }
        Ok(())
    }

    pub fn set_quiesced(&mut self, quiesced: bool) {
        self.quiesced = quiesced;
    }

    /// Clear ordinary translation and pending capture state. The register
    /// owner decides whether reset or a non-retained supply requires this.
    pub fn clear(&mut self) {
        self.streams.fill(Stream::default());
        self.faults.clear();
    }

    pub fn faults(&self) -> &Capture {
        &self.faults
    }

    pub fn acknowledge_faults(&mut self, word: usize, bits: u32) -> Result<(), &'static str> {
        self.faults.acknowledge(word, bits)
    }

    fn walk(
        &self,
        memory: &mut dyn Memory,
        sid: usize,
        iova: u64,
        last: u64,
        write: bool,
    ) -> Result<u64, WalkError> {
        if self.quiesced {
            return Err(DmaError::Unsupported("gen3 DART DMA is quiesced").into());
        }
        let stream = self.streams.get(sid).ok_or(DmaError::Unsupported(
            "gen3 DART incoming stream is outside its native bounds",
        ))?;
        if !stream.enabled {
            return Err(
                DmaError::Unsupported("gen3 DART disabled-stream fault classification").into(),
            );
        }
        if stream.config & TRANSLATE == 0 {
            return Err(DmaError::Unsupported("gen3 DART untranslated or bypass stream").into());
        }
        let indices = match stream.context {
            Some(context) => context.transfer(iova, last),
            None => Geometry::from_tcr(stream.config).zero_indices(iova),
        }
        .map_err(DmaError::Unsupported)?;
        if stream.ttbr & TTBR_VALID == 0 {
            return Err(WalkError::Fault(Code::Invalid, Level::Ttbr));
        }
        let mut table = u64::from(stream.ttbr & TTBR_ADDRESS) << 12;
        if let Some(context) = indices.context() {
            table = next(memory, table, context, Level::Cte, self.encoding)?;
        }
        table = next(memory, table, indices.segment(), Level::Ste, self.encoding)?;
        let leaf = read(memory, table, indices.page())?;
        if leaf & ENTRY_VALID == 0 {
            return Err(WalkError::Fault(Code::Invalid, Level::Pte));
        }
        let target = self.encoding.target(leaf, PA_BITS, PAGE, true)?;
        if write && leaf & NO_WRITE != 0 {
            return Err(WalkError::Fault(Code::Write, Level::Pte));
        }
        if !write && leaf & NO_READ != 0 {
            return Err(WalkError::Fault(Code::Read, Level::Pte));
        }
        let offset = iova & (PAGE - 1);
        let first_unit = leaf >> 52 & 0xfff;
        let last_unit = leaf >> 40 & 0xfff;
        if offset / SUBPAGE_UNIT < first_unit || (last & (PAGE - 1)) / SUBPAGE_UNIT > last_unit {
            return Err(WalkError::Fault(Code::Region, Level::Pte));
        }
        Ok(target + offset)
    }
}

enum WalkError {
    Fault(Code, Level),
    Dma(DmaError),
}

impl From<DmaError> for WalkError {
    fn from(error: DmaError) -> Self {
        Self::Dma(error)
    }
}

fn read(memory: &mut dyn Memory, table: u64, index: u16) -> Result<u64, DmaError> {
    let mut bytes = [0; 8];
    if !memory.read(table + u64::from(index) * 8, &mut bytes) {
        return Err(DmaError::Memory);
    }
    Ok(u64::from_le_bytes(bytes))
}

fn next(
    memory: &mut dyn Memory,
    table: u64,
    index: u16,
    level: Level,
    encoding: Encoding,
) -> Result<u64, WalkError> {
    let entry = read(memory, table, index)?;
    if entry & ENTRY_VALID == 0 {
        return Err(WalkError::Fault(Code::Invalid, level));
    }
    Ok(encoding.target(entry, PA_BITS, PAGE, false)?)
}

impl Iommu for Tables {
    fn page(&self) -> u64 {
        PAGE
    }

    fn translate(
        &mut self,
        memory: &mut dyn Memory,
        sid: usize,
        iova: u64,
        last: u64,
        write: bool,
        _: &mut Access<'_>,
    ) -> Result<u64, DmaError> {
        debug_assert!(last >= iova && last / PAGE == iova / PAGE);
        match self.walk(memory, sid, iova, last, write) {
            Ok(physical) => Ok(physical),
            Err(WalkError::Dma(error)) => Err(error),
            Err(WalkError::Fault(code, level)) => {
                let record = Record {
                    code,
                    level,
                    address: iova,
                    write,
                };
                self.faults
                    .capture(sid, record)
                    .map_err(DmaError::Unsupported)?;
                Err(DmaError::Fault(record.class()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::context::{BoundsPolicy, TableLevel};
    use super::*;
    use crate::platform::{
        apple::interrupt::InterruptLatch,
        dma::{Port, tests::Ram},
    };

    const ROOT: u64 = 0x8_0000_0000;
    const CTE: u64 = ROOT + PAGE;
    const LEAF: u64 = ROOT + 2 * PAGE;
    const FRAME: u64 = ROOT + 3 * PAGE;
    const IOVA: u64 = 0x10_0200_4000;

    fn entry(address: u64) -> u64 {
        address >> 4 | ENTRY_VALID
    }

    #[test]
    fn explicitly_qualified_native_low_root_executes_dma_without_relaxing_context_bounds() {
        let iova = 0x200_4000;
        let context = Context::from_vm_range(0x200_0000, 0x100_0000).unwrap();
        assert!(Handoff::new(0x300, TRANSLATE, context).is_err());
        let handoff = Handoff::native_client(
            0x300,
            TRANSLATE,
            context,
            BoundsPolicy::NoncompliantDeadMappings,
        )
        .unwrap();
        let indices = context
            .map(iova, 4, BoundsPolicy::Strict)
            .unwrap()
            .indices();
        let mut ram = Ram::new(ROOT, (4 * PAGE) as usize);
        ram.put_u64(ROOT + u64::from(indices.segment()) * 8, entry(LEAF));
        ram.put_u64(
            LEAF + u64::from(indices.page()) * 8,
            entry(FRAME) | 0xfff << 40,
        );
        let mut tables = Tables::new(256).unwrap();
        tables
            .configure_handoff(255, (ROOT >> 12) as u32 | 1, handoff)
            .unwrap();
        tables.set_enabled(255, true).unwrap();
        let mut sink = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut sink);
        Port {
            iommu: &mut tables,
            stream: 255,
            memory: &mut ram,
            access: &mut access,
        }
        .write(iova, &[2, 3, 5, 7])
        .unwrap();
        let mut actual = [0; 4];
        assert!(ram.read(FRAME, &mut actual));
        assert_eq!(actual, [2, 3, 5, 7]);
        for foreign in [iova - 0x10000, iova + (1 << 36), iova + (16 << 36)] {
            assert!(matches!(
                tables.translate(&mut ram, 255, foreign, foreign + 3, false, &mut access),
                Err(DmaError::Unsupported(_))
            ));
        }
        assert_eq!(tables.faults().pending(7), Ok(0));
        assert_eq!(
            tables.translate(&mut ram, 255, iova, iova + 3, false, &mut access),
            Ok(FRAME)
        );
    }

    #[test]
    fn qualified_handoffs_execute_both_native_roots_without_rebinding_an_encoding() {
        for (base, bytes, iova, config) in [
            (0x10000004000, 0xffff0000, 0x10002004000, TRANSLATE),
            (0x10000000000, 3 << 40, 0x21002004000, TRANSLATE | CONTEXT),
        ] {
            let context = Context::from_vm_range(base, bytes).unwrap();
            let handoff = Handoff::new(0x300, config, context).unwrap();
            let indices = context
                .map(iova, 4, BoundsPolicy::Strict)
                .unwrap()
                .indices();
            let mut ram = Ram::new(ROOT, (5 * PAGE) as usize);
            let parent = if let Some(slot) = indices.context() {
                ram.put_u64(ROOT + u64::from(slot) * 8, entry(CTE));
                CTE
            } else {
                ROOT
            };
            ram.put_u64(parent + u64::from(indices.segment()) * 8, entry(LEAF));
            ram.put_u64(
                LEAF + u64::from(indices.page()) * 8,
                entry(FRAME) | 0xfff << 40,
            );
            let mut tables = Tables::new(256).unwrap();
            tables
                .configure_handoff(255, (ROOT >> 12) as u32 | 1, handoff)
                .unwrap();
            tables.set_enabled(255, true).unwrap();
            let mut sink = InterruptLatch::new();
            let mut access = Access::new(0, 0, &mut sink);
            Port {
                iommu: &mut tables,
                stream: 255,
                memory: &mut ram,
                access: &mut access,
            }
            .write(iova, &[1, 9, 25, 49])
            .unwrap();
            let mut actual = [0; 4];
            assert!(ram.read(FRAME, &mut actual));
            assert_eq!(actual, [1, 9, 25, 49]);
            assert!(tables.configure_handoff(256, 0, handoff).is_err());
            assert!(tables.configure_handoff(255, 2, handoff).is_err());
            assert_eq!(
                tables.translate(&mut ram, 255, iova, iova + 3, false, &mut access),
                Ok(FRAME)
            );
            let foreign = iova & ((1 << 40) - 1);
            assert!(matches!(
                tables.translate(&mut ram, 255, foreign, foreign + 3, false, &mut access),
                Err(DmaError::Unsupported(_))
            ));
            assert_eq!(tables.faults().pending(7), Ok(0));
            let mut compact = Tables::with_encoding(1, Encoding::Shift8).unwrap();
            assert!(compact.configure_handoff(0, 1, handoff).is_err());
            assert!(compact.streams[0].context.is_none());
        }
    }

    #[test]
    fn explicit_encodings_walk_both_geometries_and_preserve_partial_dma_and_faults() {
        for encoding in [Encoding::Shift4, Encoding::Shift8] {
            let entry = |address: u64| {
                address
                    >> match encoding {
                        Encoding::Shift4 => 4,
                        Encoding::Shift8 => 8,
                    }
                    | ENTRY_VALID
            };
            for three_levels in [false, true] {
                let (context, iova, config) = if three_levels {
                    (
                        Context::from_vm_range(0x10000000000, 0x30000000000).unwrap(),
                        0x21002004000,
                        TRANSLATE | CONTEXT,
                    )
                } else {
                    (
                        Context::from_vm_range(0x10000004000, 0xffff0000).unwrap(),
                        0x10002004000,
                        TRANSLATE,
                    )
                };
                let map = context.map(iova, 4, BoundsPolicy::Strict).unwrap();
                let page = context
                    .map_table(iova, TableLevel::Page, BoundsPolicy::Strict)
                    .unwrap();
                let mut ram = Ram::new(ROOT, (5 * PAGE) as usize);
                let parent = if three_levels {
                    let segment = context
                        .map_table(iova, TableLevel::Segment, BoundsPolicy::Strict)
                        .unwrap();
                    ram.put_u64(ROOT + u64::from(segment.slot()) * 8, entry(CTE));
                    CTE
                } else {
                    ROOT
                };
                let parent_slot = parent + u64::from(page.slot()) * 8;
                let leaf_slot = LEAF + u64::from(map.indices().page()) * 8;
                ram.put_u64(parent_slot, entry(LEAF));
                ram.put_u64(leaf_slot, entry(FRAME) | 0xfff << 40);
                let mut tables = Tables::with_encoding(256, encoding).unwrap();
                // Native TTBR encoding stays PA>>12 under both RAM forms.
                tables
                    .configure_context(255, config, (ROOT >> 12) as u32 | 1, context)
                    .unwrap();
                tables.set_enabled(255, true).unwrap();
                let mut sink = InterruptLatch::new();
                let mut access = Access::new(0, 0, &mut sink);
                assert_eq!(
                    Port {
                        iommu: &mut tables,
                        stream: 255,
                        memory: &mut ram,
                        access: &mut access
                    }
                    .write(iova + PAGE - 4, &[1, 2, 3, 4, 5, 6, 7, 8]),
                    Err(DmaError::Fault(3 << 12))
                );
                let mut actual = [0; 8];
                assert!(ram.read(FRAME + PAGE - 4, &mut actual));
                assert_eq!(actual, [1, 2, 3, 4, 0, 0, 0, 0]);
                assert_eq!(
                    tables.faults().record(255).unwrap().unwrap(),
                    Record {
                        code: Code::Invalid,
                        level: Level::Pte,
                        write: true,
                        address: iova + PAGE,
                    }
                );
                tables.acknowledge_faults(7, 1 << 31).unwrap();
                ram.put_u64(leaf_slot, entry(FRAME) | 0xfff << 40 | NO_WRITE);
                assert_eq!(
                    tables.translate(&mut ram, 255, iova, iova + 3, true, &mut access),
                    Err(DmaError::Fault(1))
                );
                assert_eq!(
                    tables.translate(&mut ram, 255, iova, iova + 3, false, &mut access),
                    Ok(FRAME)
                );
                tables.acknowledge_faults(7, 1 << 31).unwrap();
                ram.put_u64(parent_slot, entry(LEAF) | 1 << 40);
                assert!(matches!(
                    tables.translate(&mut ram, 255, iova, iova + 3, false, &mut access),
                    Err(DmaError::Unsupported(_))
                ));
                assert_eq!(tables.faults().pending(7), Ok(0));
                if encoding == Encoding::Shift8 {
                    for slot in [parent_slot, leaf_slot] {
                        ram.put_u64(parent_slot, entry(LEAF));
                        ram.put_u64(leaf_slot, entry(FRAME) | 0xfff << 40);
                        let value = if slot == parent_slot {
                            entry(LEAF)
                        } else {
                            entry(FRAME) | 0xfff << 40
                        };
                        ram.put_u64(slot, value | 1 << 34);
                        assert!(matches!(
                            tables.translate(&mut ram, 255, iova, iova + 3, false, &mut access),
                            Err(DmaError::Unsupported(_))
                        ));
                        assert_eq!(tables.faults().pending(7), Ok(0));
                    }
                }
            }
        }
    }

    #[test]
    fn original_high_vm_windows_use_absolute_map_and_map_table_indices_for_dma() {
        for (base, bytes, iova) in [
            (0x10000004000, 0xffff0000, 0x10002004007),
            (0x10000100000, 0x3fe00000, 0x10000100007),
        ] {
            let context = Context::from_vm_range(base, bytes).unwrap();
            let request = context.map(iova, 4, BoundsPolicy::Strict).unwrap();
            let root = context
                .map_table(iova, TableLevel::Segment, BoundsPolicy::Strict)
                .unwrap();
            assert!(root.is_root());
            let page = context
                .map_table(iova, TableLevel::Page, BoundsPolicy::Strict)
                .unwrap();
            let mut tables = Tables::new(16).unwrap();
            let mut ram = Ram::new(ROOT, (5 * PAGE) as usize);
            ram.put_u64(ROOT + u64::from(page.slot()) * 8, entry(LEAF));
            ram.put_u64(
                LEAF + u64::from(request.indices().page()) * 8,
                entry(FRAME) | 0xfff << 40,
            );
            tables
                .configure_context(14, TRANSLATE, (ROOT >> 12) as u32 | 1, context)
                .unwrap();
            tables.set_enabled(14, true).unwrap();
            let mut sink = InterruptLatch::new();
            let mut access = Access::new(0, 0, &mut sink);
            let mut port = Port {
                iommu: &mut tables,
                stream: 14,
                memory: &mut ram,
                access: &mut access,
            };
            port.write(iova, &[1, 4, 9, 16]).unwrap();
            let mut actual = [0; 4];
            assert!(ram.read(FRAME + 7, &mut actual));
            assert_eq!(actual, [1, 4, 9, 16]);
            // These DVAs have the same low table-index bits. Their upper
            // contexts differ, and no data access or native fault is invented.
            let alias = iova ^ (1 << 40);
            assert!(matches!(
                tables.translate(&mut ram, 14, alias, alias + 3, true, &mut access),
                Err(DmaError::Unsupported(_))
            ));
            assert_eq!(tables.faults().pending(0), Ok(0));
        }
    }

    #[test]
    fn three_level_context_keeps_high_index_and_fault_address_through_rejected_reconfiguration() {
        let context = Context::from_vm_range(0x10000000000, 0x30000000000).unwrap();
        let iova = 0x21002004000;
        let segment = context
            .map_table(iova, TableLevel::Segment, BoundsPolicy::Strict)
            .unwrap();
        let page = context
            .map_table(iova, TableLevel::Page, BoundsPolicy::Strict)
            .unwrap();
        let mapping = context.map(iova, 4, BoundsPolicy::Strict).unwrap();
        let mut tables = Tables::new(256).unwrap();
        let mut ram = Ram::new(ROOT, (5 * PAGE) as usize);
        ram.put_u64(ROOT + u64::from(segment.slot()) * 8, entry(CTE));
        ram.put_u64(CTE + u64::from(page.slot()) * 8, entry(LEAF));
        ram.put_u64(
            LEAF + u64::from(mapping.indices().page()) * 8,
            entry(FRAME) | 0xfff << 40 | NO_WRITE,
        );
        tables
            .configure_context(255, TRANSLATE | CONTEXT, (ROOT >> 12) as u32 | 1, context)
            .unwrap();
        tables.set_enabled(255, true).unwrap();
        assert!(
            tables
                .configure_context(255, TRANSLATE, 0, context)
                .is_err()
        );
        assert!(
            tables
                .configure_context(255, TRANSLATE | CONTEXT | 1 << 16, 0, context)
                .is_err()
        );
        let mut sink = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut sink);
        assert_eq!(
            tables.translate(&mut ram, 255, iova, iova + 3, false, &mut access),
            Ok(FRAME)
        );
        assert_eq!(
            tables.translate(&mut ram, 255, iova, iova + 3, true, &mut access),
            Err(DmaError::Fault(1))
        );
        assert_eq!(tables.faults().record(255).unwrap().unwrap().address, iova);
        tables.acknowledge_faults(7, 1 << 31).unwrap();
        assert!(matches!(
            tables.translate(&mut ram, 255, 0, 3, false, &mut access),
            Err(DmaError::Unsupported(_))
        ));
        assert_eq!(tables.faults().pending(7), Ok(0));
    }

    #[test]
    fn source_software_bounds_do_not_qualify_aliased_hardware_fill_regions() {
        let context = Context::from_vm_range((1 << 40) - PAGE, 1 << 20).unwrap();
        let mut tables = Tables::new(1).unwrap();
        tables.configure_context(0, TRANSLATE, 1, context).unwrap();
        tables.set_enabled(0, true).unwrap();
        let mut ram = Ram::new(0, PAGE as usize);
        let mut sink = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut sink);
        assert_eq!(
            tables.translate(&mut ram, 0, 1 << 40, (1 << 40) + 3, false, &mut access),
            Err(DmaError::Unsupported(
                "gen3 DART two-level window spans unqualified upper fill regions"
            ))
        );
        assert_eq!(tables.faults().pending(0), Ok(0));
    }

    #[test]
    fn original_display_sid_override_uses_two_levels_inside_a_three_level_global_window() {
        let base = 0x10000000000;
        let global = Context::from_vm_range(base, 0x30000000000).unwrap();
        let context = global.for_sid(Some(base), Some(1 << 36), false).unwrap();
        let iova = base + PAGE;
        let root = context
            .map_table(iova, TableLevel::Segment, BoundsPolicy::Strict)
            .unwrap();
        let page = context
            .map_table(iova, TableLevel::Page, BoundsPolicy::Strict)
            .unwrap();
        let map = context.map(iova, 4, BoundsPolicy::Strict).unwrap();
        assert!(root.is_root());
        assert_eq!(map.indices().context(), None);
        let mut ram = Ram::new(ROOT, (5 * PAGE) as usize);
        ram.put_u64(ROOT + u64::from(page.slot()) * 8, entry(LEAF));
        ram.put_u64(
            LEAF + u64::from(map.indices().page()) * 8,
            entry(FRAME) | 0xfff << 40,
        );
        ram.put_u64(FRAME, 0x1234_5678);
        let mut tables = Tables::new(32).unwrap();
        tables
            .configure_context(16, TRANSLATE, (ROOT >> 12) as u32 | 1, context)
            .unwrap();
        tables.set_enabled(16, true).unwrap();
        assert!(tables.configure_context(16, TRANSLATE, 0, global).is_err());
        let mut sink = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut sink);
        let mut data = [0; 4];
        Port {
            iommu: &mut tables,
            stream: 16,
            memory: &mut ram,
            access: &mut access,
        }
        .read(iova, &mut data)
        .unwrap();
        assert_eq!(u32::from_le_bytes(data), 0x1234_5678);
        assert!(matches!(
            tables.translate(
                &mut ram,
                16,
                base + (1 << 36),
                base + (1 << 36) + 3,
                false,
                &mut access
            ),
            Err(DmaError::Unsupported(_))
        ));
        assert_eq!(tables.faults().pending(0), Ok(0));
    }

    #[test]
    fn recovered_context_walk_transfers_data_and_tracks_a_later_page_fault_per_sid() {
        let mut tables = Tables::new(256).unwrap();
        let mut ram = Ram::new(ROOT, (5 * PAGE) as usize);
        ram.put_u64(ROOT + 8, entry(CTE));
        ram.put_u64(CTE + 8, entry(LEAF));
        ram.put_u64(LEAF + 8, entry(FRAME) | 0xfff << 40);
        tables
            .configure(255, TRANSLATE | CONTEXT, (ROOT >> 12) as u32 | 1)
            .unwrap();
        tables.set_enabled(255, true).unwrap();
        let mut sink = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut sink);
        let mut port = Port {
            iommu: &mut tables,
            stream: 255,
            memory: &mut ram,
            access: &mut a,
        };
        port.write(IOVA + 7, &[1, 2, 3, 4]).unwrap();
        assert_eq!(
            port.write(IOVA + PAGE - 2, &[9, 8, 7, 6]),
            Err(DmaError::Fault(0x3000))
        );
        let mut bytes = [0; 4];
        assert!(ram.read(FRAME + 7, &mut bytes));
        assert_eq!(bytes, [1, 2, 3, 4]);
        assert!(ram.read(FRAME + PAGE - 2, &mut bytes));
        assert_eq!(bytes, [9, 8, 0, 0]);
        assert_eq!(tables.faults().pending(7), Ok(1 << 31));
        assert_eq!(
            tables.faults().record(255).unwrap(),
            Some(Record {
                code: Code::Invalid,
                level: Level::Pte,
                write: true,
                address: IOVA + PAGE,
            })
        );
        tables.acknowledge_faults(7, 1 << 31).unwrap();
        assert_eq!(tables.faults().pending(7), Ok(0));
    }

    #[test]
    fn table_levels_permissions_and_subpage_bounds_have_distinct_fault_classes() {
        let mut tables = Tables::new(16).unwrap();
        let mut ram = Ram::new(ROOT, (5 * PAGE) as usize);
        let mut sink = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut sink);
        tables.configure(1, TRANSLATE | CONTEXT, 0).unwrap();
        tables.set_enabled(1, true).unwrap();
        for (class, install) in [(0x0000, 0), (0x1000, 1), (0x2000, 2), (0x3000, 3)] {
            if install == 1 {
                tables
                    .configure(1, TRANSLATE | CONTEXT, (ROOT >> 12) as u32 | 1)
                    .unwrap();
            }
            if install == 2 {
                ram.put_u64(ROOT + 8, entry(CTE));
            }
            if install == 3 {
                ram.put_u64(CTE + 8, entry(LEAF));
            }
            assert_eq!(
                tables.translate(&mut ram, 1, IOVA, IOVA, false, &mut a),
                Err(DmaError::Fault(class))
            );
            tables.acknowledge_faults(0, 2).unwrap();
        }
        for (attributes, write, class) in [
            (NO_READ | 0xfff << 40, false, 2),
            (NO_WRITE | 0xfff << 40, true, 1),
            (4 << 52 | 7 << 40, false, 7),
        ] {
            ram.put_u64(LEAF + 8, entry(FRAME) | attributes);
            assert_eq!(
                tables.translate(&mut ram, 1, IOVA, IOVA, write, &mut a),
                Err(DmaError::Fault(class))
            );
            tables.acknowledge_faults(0, 2).unwrap();
        }
    }

    #[test]
    fn two_level_data_path_survives_rejected_configuration_without_aliasing_upper_addresses() {
        let mut tables = Tables::new(1).unwrap();
        let mut ram = Ram::new(ROOT, (5 * PAGE) as usize);
        ram.put_u64(ROOT + 8, entry(LEAF));
        ram.put_u64(LEAF + 8, entry(FRAME) | 0xfff << 40);
        tables
            .configure(0, TRANSLATE, (ROOT >> 12) as u32 | 1)
            .unwrap();
        tables.set_enabled(0, true).unwrap();
        let mut sink = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut sink);
        let iova = IOVA & ((1 << 36) - 1);
        for (config, ttbr) in [
            (TRANSLATE | 1 << 7, 1),
            (TRANSLATE | 1 << 16, 1),
            (TRANSLATE, 3),
        ] {
            assert!(tables.configure(0, config, ttbr).is_err());
            assert_eq!(
                tables.translate(&mut ram, 0, iova, iova, false, &mut a),
                Ok(FRAME)
            );
        }
        assert!(matches!(
            tables.translate(&mut ram, 0, iova | 1 << 36, iova | 1 << 36, false, &mut a),
            Err(DmaError::Unsupported(_))
        ));
        assert!(matches!(
            tables.translate(&mut ram, 1, iova, iova, false, &mut a),
            Err(DmaError::Unsupported(_))
        ));
        assert_eq!(tables.faults().pending(0), Ok(0));
        let mut port = Port {
            iommu: &mut tables,
            stream: 0,
            memory: &mut ram,
            access: &mut a,
        };
        port.write(iova, &[4, 3, 2, 1]).unwrap();
        let mut bytes = [0; 4];
        port.read(iova, &mut bytes).unwrap();
        assert_eq!(bytes, [4, 3, 2, 1]);
    }

    #[test]
    fn unrecovered_contexts_and_quiescence_never_fall_through_to_identity_dma() {
        for streams in [0, 257, usize::MAX] {
            assert!(Tables::new(streams).is_err());
        }
        let mut tables = Tables::new(1).unwrap();
        let mut ram = Ram::new(ROOT, PAGE as usize);
        let mut sink = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut sink);
        tables.set_enabled(0, true).unwrap();
        assert!(matches!(
            tables.translate(&mut ram, 0, 0, 0, false, &mut a),
            Err(DmaError::Unsupported(_))
        ));
        assert!(tables.configure(0, TRANSLATE | 1 << 7, 1).is_err());
        assert!(tables.configure(0, TRANSLATE | 1 << 16, 1).is_err());
        tables.configure(0, TRANSLATE, 1).unwrap();
        assert!(matches!(
            tables.translate(&mut ram, 0, IOVA, IOVA, false, &mut a),
            Err(DmaError::Unsupported(_))
        ));
        tables.set_quiesced(true);
        assert_eq!(
            tables.translate(&mut ram, 0, 0, 0, false, &mut a),
            Err(DmaError::Unsupported("gen3 DART DMA is quiesced"))
        );
        assert_eq!(tables.faults().pending(0), Ok(0));
    }
}
