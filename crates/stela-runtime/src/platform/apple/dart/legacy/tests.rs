use super::*;
use {
    stela_contracts::dma::Port, stela_contracts::dma::test_support::Ram,
    stela_contracts::interrupt::InterruptLatch,
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
        // a memory failure, with no guessed hardware AXI code.
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
