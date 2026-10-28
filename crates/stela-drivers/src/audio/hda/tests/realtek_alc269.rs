// SPDX-License-Identifier: GPL-2.0-only
//! realtek alc269 behavior tests.
use super::*;

#[test]
fn alc269_live_silicon_variants_use_exact_pll_eapd_and_revision_controls() {
    for (zero, variant) in [
        (0x0000, Alc269Variant::Va),
        (0x0014, Alc269Variant::Vb),
        (0x0016, Alc269Variant::Vb),
        (0x0017, Alc269Variant::Vb),
        (0x0018, Alc269Variant::Vb),
        (0x0020, Alc269Variant::Vc),
        (0x0030, Alc269Variant::Vd),
    ] {
        let mut fixture = Fixture::new();
        let model = realtek_desktop_model(0x10ec0269);
        {
            let mut m = model.borrow_mut();
            for (index, value) in [
                (0, zero),
                (4, 0x8021),
                (0x0d, 0x0030),
                (0x10, u16::MAX),
                (0x17, 0x0050),
            ] {
                m.coefficients.insert((0x20, index), value);
            }
        }
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        assert!(matches!(
            controller.initialize_realtek_common(&graph),
            Err(Error::UnsupportedTopology)
        ));
        let report = controller.initialize_realtek_alc269_common(&graph).unwrap();
        assert_eq!(report.coefficient_zero, zero);
        assert_eq!(report.variant, variant);
        assert_eq!(report.common.codec_id, 0x10ec0269);
        let m = model.borrow();
        match variant {
            Alc269Variant::Va | Alc269Variant::Vc => {
                assert_eq!(m.coefficients[&(0x20, 4)], 0x0021)
            }
            Alc269Variant::Vd => assert_eq!(m.coefficients[&(0x20, 0x10)], 0xfdff),
            Alc269Variant::Vb => {
                assert_eq!(m.coefficients[&(0x20, 4)], 0x8821);
                assert_eq!(
                    m.coefficients[&(0x20, 0x0d)],
                    if zero == 0x18 { 0x4430 } else { 0x4030 }
                );
                if zero < 0x15 || zero == 0x16 {
                    assert_eq!(m.coefficients[&(0x20, 0x0f)], 0x960b);
                    assert_eq!(
                        m.coefficients[&(0x20, 0x0e)],
                        if zero == 0x16 { 0x8814 } else { 0x8817 }
                    );
                }
                if zero == 0x18 {
                    assert_eq!(m.coefficients[&(0x20, 0x17)], 0x00d0);
                }
            }
        }
        let writes = m.coefficient_writes;
        drop(m);
        controller.initialize_realtek_alc269_common(&graph).unwrap();
        // The literal early-VB writes are mandatory transactions even when
        // the last value already equals the donor's desired value.
        if zero == 0x14 || zero == 0x16 {
            assert_eq!(model.borrow().coefficient_writes, writes + 2);
        }
        let endpoint = graph
            .analog_endpoints(Direction::Playback, stereo())
            .unwrap()
            .remove(0);
        let stream = controller
            .allocate_stream(
                Direction::Playback,
                stereo(),
                128,
                2,
                &mut fixture.allocator,
            )
            .unwrap();
        controller
            .configure_analog_route(
                &graph,
                &endpoint.route,
                stream,
                0,
                PinOptions::Playback {
                    headphone: false,
                    eapd: None,
                },
            )
            .unwrap();
        controller.write_pcm(stream, 0, &[0x35; 256]).unwrap();
        controller.start(stream).unwrap();
        model.borrow_mut().dma_step_bytes = 128;
        advance(&model, 4);
        assert!(controller.status(stream).unwrap().period_completed);
        controller.stop(stream).unwrap();
        assert!(model.borrow().playback.iter().all(|byte| *byte == 0x35));
        controller.shutdown().unwrap();
    }
}

#[test]
fn alc269_vb18_preserves_the_donor_or_operations_and_does_not_normalize_fields() {
    for (old_d, old_17) in [(0x0420, 0x0110), (0x0c20, 0x0190)] {
        let mut fixture = Fixture::new();
        let model = realtek_desktop_model(0x10ec0269);
        {
            let mut m = model.borrow_mut();
            m.coefficients.insert((0x20, 0), 0x18);
            m.coefficients.insert((0x20, 0x0d), old_d);
            m.coefficients.insert((0x20, 0x17), old_17);
        }
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        let report = controller.initialize_realtek_alc269_common(&graph).unwrap();
        assert_eq!(model.borrow().coefficients[&(0x20, 0x0d)], old_d | 0x4000);
        assert_eq!(model.borrow().coefficients[&(0x20, 0x17)], old_17);
        assert_eq!(
            report
                .common
                .coefficients
                .iter()
                .filter(|change| change.index == 0x17)
                .count(),
            usize::from(old_17 & 0x1c0 != 0x100)
        );
    }
}

#[test]
fn alc269_companion_dsp_or_unknown_companion_identity_refuses_before_any_codec_mutation() {
    for identity in [0x10ec5505, 0x12345678, u32::MAX] {
        let mut fixture = Fixture::new();
        let model = realtek_desktop_model(0x10ec0269);
        model.borrow_mut().parameters.insert((0x51, 0), identity);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        let before = model.borrow().commands.len();
        assert_eq!(
            controller.initialize_realtek_alc269_common(&graph),
            Err(Error::UnsupportedTopology)
        );
        assert!(
            model.borrow().commands[before..]
                .iter()
                .all(|command| (command >> 16) & 15 >= 8)
        );
        assert!(model.borrow().power_ready.is_empty());
        assert!(model.borrow().coefficient_indexes.is_empty());
        assert!(!controller.routing_failed);
    }
}

#[test]
fn alc269_unknown_variant_failed_revision_and_literal_readback_refuse_and_gate_partial_state() {
    for fault in 0..3 {
        let mut fixture = Fixture::new();
        let model = realtek_desktop_model(0x10ec0269);
        model
            .borrow_mut()
            .coefficients
            .insert((0x20, 0), if fault == 0 { 0x40 } else { 0x14 });
        if fault != 0 {
            model.borrow_mut().coefficient_read_fault = Some(u32::MAX);
            model.borrow_mut().coefficient_fault_after_write = fault == 2;
        }
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        let stream = controller
            .allocate_stream(
                Direction::Playback,
                stereo(),
                128,
                2,
                &mut fixture.allocator,
            )
            .unwrap();
        let expected = match fault {
            0 => Error::UnsupportedTopology,
            1 => Error::CoefficientRejected {
                node: 0x20,
                index: 0,
            },
            _ => Error::CoefficientRejected {
                node: 0x20,
                index: 0x0f,
            },
        };
        assert_eq!(
            controller
                .initialize_realtek_alc269_common(&graph)
                .unwrap_err(),
            expected
        );
        assert_eq!(model.borrow().coefficient_writes, usize::from(fault == 2));
        assert_eq!(controller.start(stream), Err(Error::NeedsReset));
        let before = access_counts(&model);
        assert_eq!(
            controller.initialize_realtek_alc269_common(&graph),
            Err(Error::NeedsReset)
        );
        assert_eq!(access_counts(&model), before);
    }
}
