use super::super::context::{BoundsPolicy, TableLevel};
use super::*;
use {
    stela_contracts::dma::Port, stela_contracts::dma::test_support::Ram,
    stela_contracts::interrupt::InterruptLatch,
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
