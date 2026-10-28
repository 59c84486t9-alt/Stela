// SPDX-License-Identifier: GPL-2.0-only
//! mapped behavior tests.
use super::*;

#[test]
fn exact_conventional_intel_profile_requires_mapped_preflight_and_pci_reset_adapter() {
    for &device in INTEL_CLOCK_GATE_IDS {
        let (mut function, timer, bar) = modern_pci_model();
        set_identity(&mut function, INTEL, device);
        assert_eq!(
            prepare_model(&mut function, &timer, bar).unwrap_err(),
            AttachError::MappedPreflightRequired
        );
        assert!(function.config().writes.is_empty());
        let registers = MappedModel::new();
        let adapter = unsafe {
            prepare_with_registers(
                &mut function,
                bar,
                &timer,
                Ownership::ExclusiveLegacy,
                registers.clone(),
            )
        }
        .unwrap();
        let config = adapter.config();
        assert_eq!(config.reset_policy, ResetPolicy::IntelClockGate);
        assert_eq!(config.stream_tag_policy, StreamTagPolicy::PerDirection);
        assert_eq!(config.dma_address_bits, 64);
        assert_eq!(config.position_policy, PositionPolicy::Link);
        assert_eq!(config.probe_policy, ProbePolicy::Once);
        drop(adapter);
        assert!(registers.reads.get() > 0);
        assert_eq!(function.config().words[30], 0xf91f_7255);
        assert_eq!(function.config().words[17], 0x5ac3_a5f0);
        assert!(
            function
                .config()
                .writes
                .iter()
                .all(|(offset, _, _, _)| *offset != CGCTL)
        );
    }
}

#[test]
fn mapped_pci_identity_power_capability_and_mapping_failures_precede_mmio_and_mutation() {
    for fault in 0..12 {
        let (mut function, timer, bar) = modern_pci_model();
        let registers = MappedModel::new();
        let ownership = match fault {
            0 => Ownership::Unknown,
            1 => Ownership::Dsp,
            _ => Ownership::ExclusiveLegacy,
        };
        match fault {
            2 => function.config().words[2] = 0x0401_0000,
            3 => function.config().words[2] = 0x0403_8000,
            4 => function.config().set16(0x54, 3),
            5 => function.config().set16(PCI_COMMAND, 0),
            6 => function.config().set16(PCI_COMMAND, u16::MAX),
            7 => function.config().words[18] = u32::MAX,
            8 => {
                function.config().words[13] = 0x48;
                function.config().words[18] = 0x0003_5001;
            }
            9 => {
                function.config().words[13] = 0x40;
                function.config().words[16] = 0x50ff;
            }
            10 => registers.bytes.borrow_mut().resize(0x8000, 0),
            11 => function.config().words[4] = 0xfebe_0000,
            _ => (),
        }
        let result = unsafe {
            prepare_with_registers(&mut function, bar, &timer, ownership, registers.clone())
        };
        assert!(result.is_err(), "fault {fault}");
        drop(result);
        assert_eq!(registers.reads.get(), 0, "fault {fault}");
        assert!(function.config().writes.is_empty(), "fault {fault}");
    }
}

#[test]
fn first_link_failed_reads_uncertain_power_and_unadvertised_clock_refuse_before_pci_writes() {
    for (value, frequencies, expected) in [
        (
            u32::MAX,
            0x3f,
            crate::audio::Error::RegisterUnavailable { offset: 0x544 },
        ),
        (
            1 << 16,
            0x3f,
            crate::audio::Error::LinkPowerUncertain { offset: 0x544 },
        ),
        (
            1 << 23,
            0x3f,
            crate::audio::Error::LinkPowerUncertain { offset: 0x544 },
        ),
        (
            15 | (1 << 16) | (1 << 23),
            0x3f,
            crate::audio::Error::UnsupportedLink { offset: 0x544 },
        ),
        (
            3 | (1 << 16) | (1 << 23),
            1 << 2,
            crate::audio::Error::UnsupportedLink { offset: 0x544 },
        ),
    ] {
        let (mut function, timer, bar) = modern_pci_model_for(0x7e28);
        let registers = MappedModel::new();
        registers.set(0x14, 0x500);
        registers.set(0x500, 0x1002_0000);
        registers.set(0x540, frequencies);
        registers.set(0x544, value);
        let before = registers.bytes.borrow().clone();
        let result = unsafe {
            prepare_with_registers(
                &mut function,
                bar,
                &timer,
                Ownership::ExclusiveLegacy,
                registers.clone(),
            )
        };
        assert!(matches!(result, Err(AttachError::MmioPreflight(error)) if error == expected));
        drop(result);
        assert!(function.config().writes.is_empty());
        assert_eq!(*registers.bytes.borrow(), before);
    }
    // Known conventional link powered down is valid: initialization obtains
    // its actual power acknowledgement after PCI clock-bracketed reset.
    for (clock, powered) in [(0, 0), (2, 0), (3, (1 << 16) | (1 << 23))] {
        let (mut function, timer, bar) = modern_pci_model_for(0x7e28);
        let registers = MappedModel::new();
        registers.set(0x14, 0x500);
        registers.set(0x500, 0x1002_0000);
        registers.set(0x540, 0x3f);
        registers.set(0x544, clock | powered);
        let before = registers.bytes.borrow().clone();
        let adapter = unsafe {
            prepare_with_registers(
                &mut function,
                bar,
                &timer,
                Ownership::ExclusiveLegacy,
                registers.clone(),
            )
        }
        .unwrap();
        drop(adapter);
        assert_eq!(*registers.bytes.borrow(), before);
        assert!(!function.config().writes.is_empty());
    }
}

#[test]
fn each_new_conventional_intel_identity_refuses_dsp_and_selectable_classes_before_mmio() {
    for device in [
        0x34c8, 0x3dc8, 0xa0c8, 0x43c8, 0x7ad0, 0x51c8, 0x51c9, 0x51cd, 0x51cc, 0x54c8, 0x7e28,
    ] {
        for class in [[4, 1, 0], [4, 3, 0x80], [4, 3, 1]] {
            for stale_enumeration in [true, false] {
                let (mut function, timer, bar) = modern_pci_model_for(device);
                if !stale_enumeration {
                    function.class = class;
                }
                function.config().words[2] = (u32::from(class[0]) << 24)
                    | (u32::from(class[1]) << 16)
                    | (u32::from(class[2]) << 8);
                let registers = MappedModel::new();
                let result = unsafe {
                    prepare_with_registers(
                        &mut function,
                        bar,
                        &timer,
                        Ownership::ExclusiveLegacy,
                        registers.clone(),
                    )
                };
                assert!(matches!(result, Err(AttachError::UnsupportedController)));
                drop(result);
                assert_eq!(registers.reads.get(), 0);
                assert!(function.config().writes.is_empty());
            }
        }
    }
}

#[test]
fn mapped_interrupt_control_read_failures_do_not_publish_failed_words() {
    for offset in [0x60, 0xb0] {
        for after_preflight in [false, true] {
            let (mut function, timer, bar) = modern_pci_model();
            if after_preflight {
                function.config().failed_interrupt_read = Some(offset);
            } else {
                function.config().set16(offset + 2, u16::MAX);
            }
            let result = unsafe {
                prepare_with_registers(
                    &mut function,
                    bar,
                    &timer,
                    Ownership::ExclusiveLegacy,
                    MappedModel::new(),
                )
            };
            assert!(matches!(
                result,
                Err(AttachError::ConfigurationRejected | AttachError::InvalidCapabilities)
            ));
            drop(result);
            let config = function.config();
            assert!(
                config
                    .writes
                    .iter()
                    .all(|(off, _, _, _)| *off != offset + 2)
            );
            if after_preflight {
                assert_eq!(config.get16(PCI_COMMAND) & COMMAND_MASTER, 0);
                assert!(config.writes.iter().any(|(off, _, _, _)| *off == TCSEL));
            } else {
                assert!(config.writes.is_empty());
            }
        }
    }
}

#[test]
fn mapped_active_dma_failed_controls_and_extended_ownership_refuse_before_pci_mutation() {
    for (offset, value, expected) in [
        (0x4c, 2, AttachError::ActiveDma { offset: 0x4c }),
        (0x5c, 2, AttachError::ActiveDma { offset: 0x5c }),
        (0xe0, 2, AttachError::ActiveDma { offset: 0xe0 }), //Last descriptor.
        (
            0x4c,
            0xff,
            AttachError::MmioPreflight(crate::audio::Error::RegisterUnavailable { offset: 0x4c }),
        ),
        (
            0xe0,
            0xff,
            AttachError::MmioPreflight(crate::audio::Error::RegisterUnavailable { offset: 0xe0 }),
        ),
        (
            0x504,
            1 << 30,
            AttachError::MmioPreflight(crate::audio::Error::ProcessingOwned { offset: 0x504 }),
        ),
        (
            0x500,
            0x2003_0000,
            AttachError::MmioPreflight(crate::audio::Error::UnsupportedExtendedCapability {
                id: 3,
                version: 2,
            }),
        ),
    ] {
        let (mut function, timer, bar) = modern_pci_model();
        let registers = MappedModel::new();
        registers.set(0x14, 0x500);
        registers.set(0x500, 0x1003_0000);
        registers.set(offset, value);
        let result = unsafe {
            prepare_with_registers(
                &mut function,
                bar,
                &timer,
                Ownership::ExclusiveLegacy,
                registers.clone(),
            )
        };
        assert!(
            matches!(result, Err(error) if error == expected),
            "offset {offset:x}"
        );
        drop(result);
        assert!(registers.reads.get() > 0);
        assert!(function.config().writes.is_empty());
    }
}
