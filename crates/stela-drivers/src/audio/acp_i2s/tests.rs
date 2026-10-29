use super::test_support::*;
use super::*;
use alloc::vec::Vec;
// All tests below are authored SOURCE ONLY, UNRUN until the parent's finite gate.
#[test]
fn four_stream_pte_dma_duplex_and_independent_auxiliary_layouts() {
    for revision in [0, 0x50] {
        let (mut controller, device, source) = fixture(revision);
        controller.initialize().unwrap();
        let pcm: Vec<u8> = (0..8192).map(|index| (index * 37 + 9) as u8).collect();
        for port in PORTS {
            controller
                .prepare(
                    port,
                    stereo(),
                    Ring {
                        period_bytes: 2048,
                        periods: 4,
                    },
                    if port.direction() == Direction::Playback {
                        Some(&pcm)
                    } else {
                        None
                    },
                    &source,
                )
                .unwrap();
        }
        for port in PORTS {
            controller.start(port).unwrap();
        }
        let mut capture = vec![0xa5; 2048];
        for period in 0..12u64 {
            for slot in 0..4 {
                device.lock().unwrap().advance(slot, 256, 4);
            }
            for port in [Port::SpeakerCapture, Port::AuxiliaryCapture] {
                assert_eq!(
                    controller.capture_period(port, &mut capture).unwrap(),
                    Some(CapturePeriod {
                        first_frame: period * 256,
                        frames: 256
                    })
                );
                for frame in 0..256 {
                    for channel in 0..2 {
                        let offset = frame * 8 + channel * 4;
                        assert_eq!(
                            i32::from_le_bytes(capture[offset..offset + 4].try_into().unwrap()),
                            sample(period * 256 + frame as u64, channel)
                        );
                    }
                }
            }
            if period == 5 {
                controller.stop(Port::SpeakerPlayback).unwrap();
                assert_eq!(
                    device.lock().unwrap().words[0x2400 / 4],
                    1,
                    "capture keeps shared serial IER"
                );
                controller.start(Port::SpeakerPlayback).unwrap();
            }
        }
        for slot in [0, 2] {
            assert_eq!(device.lock().unwrap().output[slot], pcm.repeat(3));
        }
        assert_eq!(device.lock().unwrap().maps, 4);
        assert_eq!(source.drops.load(Ordering::Relaxed), 0);
        controller.shutdown().unwrap();
        assert_eq!(device.lock().unwrap().unmaps, 4);
        assert_eq!(source.drops.load(Ordering::Relaxed), 4);
        assert!(controller.into_stopped().is_ok());
    }
}
#[test]
fn real_kept_pte_clock_and_pcm_epochs_survive_controller_pm() {
    for revision in [0, 0x50] {
        let (mut controller, device, source) = fixture(revision);
        controller.initialize().unwrap();
        controller
            .prepare(
                Port::AuxiliaryCapture,
                stereo(),
                Ring {
                    period_bytes: 1024,
                    periods: 4,
                },
                None,
                &source,
            )
            .unwrap();
        let address = controller.streams[3]
            .as_ref()
            .unwrap()
            .dma
            .address()
            .unwrap();
        controller.start(Port::AuxiliaryCapture).unwrap();
        device.lock().unwrap().advance(3, 128, 4);
        let mut output = vec![0; 1024];
        assert!(
            controller
                .capture_period(Port::AuxiliaryCapture, &mut output)
                .unwrap()
                .is_some()
        );
        controller.suspend_held_d0().unwrap();
        assert_eq!(controller.state(), State::Suspended);
        assert_eq!(device.lock().unwrap().unmaps, 0);
        if revision == 0 {
            assert_eq!(device.lock().unwrap().words[0x1418 / 4], 0x40);
        } else {
            assert_eq!(device.lock().unwrap().words[0x142c / 4], 0);
            assert_eq!(device.lock().unwrap().words[0x1004 / 4], 0);
        }
        controller.resume_held_d0().unwrap();
        assert_eq!(controller.state(), State::Prepared);
        assert_eq!(
            controller.streams[3]
                .as_ref()
                .unwrap()
                .dma
                .address()
                .unwrap(),
            address
        );
        controller.start(Port::AuxiliaryCapture).unwrap();
        assert_eq!(
            controller
                .capture_period(Port::AuxiliaryCapture, &mut output)
                .unwrap(),
            None
        );
        device.lock().unwrap().advance(3, 128, 4);
        assert_eq!(
            controller
                .capture_period(Port::AuxiliaryCapture, &mut output)
                .unwrap()
                .unwrap()
                .first_frame,
            0
        );
        assert_eq!(
            i32::from_le_bytes(output[..4].try_into().unwrap()),
            sample(128, 0)
        );
        controller.shutdown().unwrap();
        assert_eq!(device.lock().unwrap().maps, 1);
        assert_eq!(source.drops.load(Ordering::Relaxed), 1);
    }
}
#[test]
fn malformed_formats_master_ratios_and_link_pair_conflicts_have_no_dma_effects() {
    let (mut controller, device, source) = fixture(0x50);
    controller.initialize().unwrap();
    for format in [
        Format {
            rate: 192_000,
            ..stereo()
        },
        Format {
            channels: 8,
            ..stereo()
        },
        Format {
            signal: Signal::DspA {
                slots: 1,
                slot_bits: 32,
            },
            ..stereo()
        },
        Format {
            signal: Signal::DspA {
                slots: 2,
                slot_bits: 16,
            },
            ..stereo()
        },
    ] {
        assert!(
            controller
                .prepare(
                    Port::SpeakerCapture,
                    format,
                    Ring {
                        period_bytes: 1024,
                        periods: 4
                    },
                    None,
                    &source
                )
                .is_err()
        );
    }
    assert_eq!(device.lock().unwrap().maps, 0);
    controller.config.clock = Clock::Master {
        reference_hz: 196_608_000,
    };
    assert_eq!(
        controller.master_control(stereo()).unwrap(),
        Some(1 | (64 << 2) | (64 << 11))
    );
    assert!(
        controller
            .master_control(Format {
                rate: 44_100,
                ..stereo()
            })
            .is_err()
    );
    controller.config.clock = Clock::Master {
        reference_hz: 180_633_600,
    };
    assert!(
        controller
            .master_control(Format {
                rate: 44_100,
                ..stereo()
            })
            .is_ok()
    );
    controller.config.clock = Clock::External;
    controller
        .prepare(
            Port::SpeakerCapture,
            stereo(),
            Ring {
                period_bytes: 1024,
                periods: 4,
            },
            None,
            &source,
        )
        .unwrap();
    let pcm = vec![0; 4096];
    assert_eq!(
        controller.prepare(
            Port::SpeakerPlayback,
            Format {
                rate: 44_100,
                ..stereo()
            },
            Ring {
                period_bytes: 1024,
                periods: 4
            },
            Some(&pcm),
            &source
        ),
        Err(Error::InvalidFormat)
    );
    controller.shutdown().unwrap();
}
#[test]
fn capture_coalescing_overrun_and_mid_copy_race_never_publish_stale_periods() {
    for race in [false, true] {
        let (mut controller, device, source) = fixture(0);
        controller.initialize().unwrap();
        controller
            .prepare(
                Port::SpeakerCapture,
                stereo(),
                Ring {
                    period_bytes: 1024,
                    periods: 4,
                },
                None,
                &source,
            )
            .unwrap();
        controller.start(Port::SpeakerCapture).unwrap();
        device
            .lock()
            .unwrap()
            .advance(1, if race { 128 } else { 512 }, 4);
        if race {
            let mut model = device.lock().unwrap();
            model.race_copy = Some((model.coherent + 3, 1, 384));
        }
        let mut pcm = vec![0; 1024];
        assert!(matches!(
            controller.capture_period(Port::SpeakerCapture, &mut pcm),
            Err(Error::CaptureOverrun { .. })
        ));
        assert_eq!(controller.streams[1].as_ref().unwrap().consumed, 0);
        assert_eq!(source.drops.load(Ordering::Relaxed), 0);
        controller.shutdown().unwrap();
    }
}
#[test]
fn stop_payload_drain_and_faulted_reset_do_not_release_a_published_iova() {
    let (mut controller, device, source) = fixture(0x50);
    controller.initialize().unwrap();
    controller
        .prepare(
            Port::AuxiliaryCapture,
            stereo(),
            Ring {
                period_bytes: 1024,
                periods: 4,
            },
            None,
            &source,
        )
        .unwrap();
    controller.start(Port::AuxiliaryCapture).unwrap();
    {
        let mut model = device.lock().unwrap();
        model.defer_payload = true;
        model.advance(3, 128, 4);
        model.drain_fail = true;
    }
    assert_eq!(
        controller.stop(Port::AuxiliaryCapture),
        Err(Error::Dma(
            crate::bus::dma::mapping::DmaError::InvalidationFailed
        ))
    );
    assert_eq!(source.drops.load(Ordering::Relaxed), 0);
    assert_eq!(device.lock().unwrap().unmaps, 0);
    device.lock().unwrap().reset_never = true;
    assert_eq!(
        controller.shutdown(),
        Err(Error::Timeout(Phase::ResetClear))
    );
    assert_eq!(device.lock().unwrap().unmaps, 0);
    {
        let mut model = device.lock().unwrap();
        model.reset_never = false;
        model.drain_fail = false;
    }
    controller.shutdown().unwrap();
    assert!(device.lock().unwrap().posted.is_empty());
    assert_eq!(source.drops.load(Ordering::Relaxed), 1);
}
#[test]
fn pin_pte_pci_and_clock_permission_loss_quarantine_dma() {
    for fault in 0..4 {
        let (mut controller, device, source) = fixture(0x50);
        controller.initialize().unwrap();
        controller
            .prepare(
                Port::SpeakerCapture,
                stereo(),
                Ring {
                    period_bytes: 1024,
                    periods: 4,
                },
                None,
                &source,
            )
            .unwrap();
        controller.start(Port::SpeakerCapture).unwrap();
        {
            let mut model = device.lock().unwrap();
            match fault {
                0 => model.words[0x1400 / 4] = 4,
                1 => model.words[0x10100 / 4] ^= 0x1000,
                2 => model.identity.device ^= 1,
                _ => model.words[0x142c / 4] = 0,
            }
        }
        assert!(controller.position(Port::SpeakerCapture).is_err());
        assert_eq!(controller.state(), State::Faulted);
        assert_eq!(source.drops.load(Ordering::Relaxed), 0);
        {
            let mut model = device.lock().unwrap();
            model.identity.device = 0x15e2;
        }
        controller.shutdown().unwrap();
        assert_eq!(source.drops.load(Ordering::Relaxed), 1);
    }
}
#[test]
fn successful_but_late_power_start_and_stop_effects_keep_original_owners() {
    for phase in [Phase::PowerOn, Phase::DmaStart, Phase::DmaStop] {
        let (mut controller, device, source) = fixture(0x50);
        if phase != Phase::PowerOn {
            controller.initialize().unwrap();
            controller
                .prepare(
                    Port::SpeakerCapture,
                    stereo(),
                    Ring {
                        period_bytes: 1024,
                        periods: 4,
                    },
                    None,
                    &source,
                )
                .unwrap();
        }
        if phase == Phase::DmaStop {
            controller.start(Port::SpeakerCapture).unwrap();
        }
        let (offset, value, budget) = match phase {
            Phase::PowerOn => (0x1424, 1, 501),
            Phase::DmaStart => (0x2404, 41, 100001),
            _ => (0x2404, 40, 100001),
        };
        device.lock().unwrap().jump_write = Some((offset, value, budget));
        let result = match phase {
            Phase::PowerOn => controller.initialize(),
            Phase::DmaStart => controller.start(Port::SpeakerCapture),
            _ => controller.stop(Port::SpeakerCapture),
        };
        assert_eq!(result, Err(Error::Timeout(phase)));
        assert_eq!(source.drops.load(Ordering::Relaxed), 0);
        assert_eq!(device.lock().unwrap().unmaps, 0);
        controller.shutdown().unwrap();
    }
}
#[test]
fn exact_generation_admission_and_active_drop_do_not_invent_native_completion() {
    for revision in 0..=255 {
        assert_eq!(
            Generation::identify(Identity {
                vendor: 0x1022,
                device: 0x15e2,
                revision
            })
            .is_ok(),
            matches!(revision, 0 | 0x50)
        );
    }
    let (mut controller, device, source) = fixture(0);
    controller.initialize().unwrap();
    controller
        .prepare(
            Port::SpeakerCapture,
            stereo(),
            Ring {
                period_bytes: 1024,
                periods: 4,
            },
            None,
            &source,
        )
        .unwrap();
    controller.start(Port::SpeakerCapture).unwrap();
    drop(controller);
    assert_eq!(source.drops.load(Ordering::Relaxed), 0);
    assert_eq!(device.lock().unwrap().unmaps, 0);
    device.lock().unwrap().advance(1, 128, 4);
}
#[test]
fn coherent_and_resume_failures_keep_ring_leases() {
    let (mut controller, device, source) = fixture(0x50);
    controller.initialize().unwrap();
    device.lock().unwrap().coherent_fail = true;
    assert_eq!(
        controller.prepare(
            Port::SpeakerCapture,
            stereo(),
            Ring {
                period_bytes: 1024,
                periods: 4
            },
            None,
            &source
        ),
        Err(Error::Dma(
            crate::bus::dma::mapping::DmaError::CoherenceUnavailable
        ))
    );
    assert_eq!(device.lock().unwrap().unmaps, 1);
    assert_eq!(source.drops.load(Ordering::Relaxed), 1);
    device.lock().unwrap().coherent_fail = false;
    controller.initialize().unwrap();
    controller
        .prepare(
            Port::SpeakerCapture,
            stereo(),
            Ring {
                period_bytes: 1024,
                periods: 4,
            },
            None,
            &source,
        )
        .unwrap();
    controller.start(Port::SpeakerCapture).unwrap();
    controller.suspend_held_d0().unwrap();
    let address = controller.streams[1]
        .as_ref()
        .unwrap()
        .dma
        .address()
        .unwrap();
    {
        let mut model = device.lock().unwrap();
        model.words[0x10104 / 4] = 0; // Actual retained SRAM was lost across suspend.
        model.ignore = Some(0x10104);
    }
    assert_eq!(
        controller.resume_held_d0(),
        Err(Error::RegisterRejected(0x10104))
    );
    assert_eq!(
        controller.streams[1]
            .as_ref()
            .unwrap()
            .dma
            .address()
            .unwrap(),
        address
    );
    assert_eq!(device.lock().unwrap().unmaps, 1);
    device.lock().unwrap().ignore = None;
    controller.shutdown().unwrap();
    assert_eq!(source.drops.load(Ordering::Relaxed), 2);
}
#[test]
fn full_counter_halves_and_partial_frames_do_not_alias_the_raven_header_or_bug() {
    let (mut controller, device, source) = fixture(0);
    controller.initialize().unwrap();
    controller
        .prepare(
            Port::SpeakerCapture,
            stereo(),
            Ring {
                period_bytes: 1024,
                periods: 4,
            },
            None,
            &source,
        )
        .unwrap();
    device.lock().unwrap().count[1] = 0x1_ffff_ffff;
    controller.start(Port::SpeakerCapture).unwrap();
    assert_eq!(
        controller.streams[1].as_ref().unwrap().baseline,
        0x1_ffff_ffff
    );
    device.lock().unwrap().advance(1, 128, 4);
    let mut pcm = vec![0; 1024];
    assert_eq!(
        controller
            .capture_period(Port::SpeakerCapture, &mut pcm)
            .unwrap()
            .unwrap()
            .first_frame,
        0
    );
    device.lock().unwrap().count[1] += 3;
    assert_eq!(
        controller.position(Port::SpeakerCapture).unwrap().bytes,
        1024
    );
    controller.shutdown().unwrap();
}
#[test]
#[ignore = "oracle: STELA_ACP_I2S_ORACLE"]
fn unchanged_linux_acp3x_acp5x_dma_configuration() {
    extern crate std;
    use std::fmt::Write;
    let original = std::fs::read_to_string(std::env::var("STELA_ACP_I2S_ORACLE").unwrap()).unwrap();
    let mut actual = std::string::String::from("linux a804c5742bff224d4cb4d25dd383554d598be32b\n");
    for revision in [0, 0x50] {
        for port in PORTS {
            let (mut controller, device, source) = fixture(revision);
            controller.initialize().unwrap();
            device.lock().unwrap().writes.clear();
            let pcm = vec![0x37; 12288];
            controller
                .prepare(
                    port,
                    stereo(),
                    Ring {
                        period_bytes: 3072,
                        periods: 4,
                    },
                    if port.direction() == Direction::Playback {
                        Some(&pcm)
                    } else {
                        None
                    },
                    &source,
                )
                .unwrap();
            writeln!(actual, "case {revision:02x} {}", port as usize).unwrap();
            let regs = controller.generation.stream(port);
            let first_pte = SCRATCH + regs.pte;
            for (offset, value) in &device.lock().unwrap().writes {
                if (*offset == PAGE_BASE && *value == SRAM | PTE_VALID)
                    || *offset == PAGE_SIZE
                    || (*offset == IRQ_CONTROL && *value != 0)
                    || [
                        regs.ring,
                        regs.fifo_address(),
                        regs.fifo_size(),
                        regs.dma_size(),
                    ]
                    .contains(offset)
                    || (first_pte..first_pte + 3 * 8).contains(offset)
                {
                    writeln!(actual, "w {offset:04x} {value:08x}").unwrap();
                }
            }
            controller.shutdown().unwrap();
        }
    }
    assert_eq!(actual, original);
}
