//! Recovered gen3 table/data effects, with explicit context qualification.
//!
//! The original software walk/leaf builder and fault levels are pinned in
//! `docs/research/dart-iommu.md`. This is not a gen3 MMIO profile: full VA
//! context, untranslated/bypass, security/APF, remap, IRQ and ordering are
//! still independently required. Explicit software contexts can bind their
//! recovered bounds/geometry; native out-of-context faults remain unqualified.
use super::context::{Context, Geometry, PAGE_BYTES as PAGE};
use super::fault::{Capture, Code, Level, Record};
use crate::platform::{
    apple::{bus::Access, dart::descriptor::Format},
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
    faults: Capture,
    quiesced: bool,
}

impl Tables {
    pub fn new(streams: usize) -> Result<Self, &'static str> {
        let faults = Capture::new(streams)?;
        Ok(Self {
            streams: vec![Stream::default(); streams],
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
            table = next(memory, table, context, Level::Cte)?;
        }
        table = next(memory, table, indices.segment(), Level::Ste)?;
        let leaf = read(memory, table, indices.page())?;
        if leaf & ENTRY_VALID == 0 {
            return Err(WalkError::Fault(Code::Invalid, Level::Pte));
        }
        let target = Format::Dart2.target(leaf, PA_BITS, PAGE, true)?;
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

fn next(memory: &mut dyn Memory, table: u64, index: u16, level: Level) -> Result<u64, WalkError> {
    let entry = read(memory, table, index)?;
    if entry & ENTRY_VALID == 0 {
        return Err(WalkError::Fault(Code::Invalid, level));
    }
    Ok(Format::Dart2.target(entry, PA_BITS, PAGE, false)?)
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
