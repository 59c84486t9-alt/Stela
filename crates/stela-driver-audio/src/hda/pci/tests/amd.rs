// SPDX-License-Identifier: GPL-2.0-only
//! amd behavior tests.
use super::*;
use crate::bus::pci::regs;

#[test]
fn profile_selects_fifo_and_dma_policy() {
    for device in [0x1457, 0x1487, 0x15e3] {
        let (mut function, timer, bar) = fixture(3);
        set_identity(&mut function, AMD, device);
        function.config().words[16] = 0x5aa5_1234;
        let prepared = prepare_model(&mut function, &timer, bar).unwrap();
        let policy = prepared.config();
        assert_eq!(policy.corb_reset, CorbReset::Handshake);
        assert_eq!(policy.dma_address_bits, 40);
        assert_eq!(policy.position_policy, PositionPolicy::AmdFifo32);
        assert_eq!(
            policy.probe_policy,
            ProbePolicy::Retry {
                attempts: 60,
                delay_us: 1_000_000
            }
        );
        assert_eq!(function.config().words[16], 0x5aa2_1234);
        assert!(
            !function
                .config()
                .writes
                .iter()
                .any(|(offset, _, _, _)| *offset == TCSEL)
        );
        assert_eq!(function.config().get16(0x54) & 3, 0);
        assert!(timer.now_us() >= 10_000);
    }
    for (vendor, device) in [(INTEL, 0x2668), (ATI, 0x4383), (AMD, 0x157a)] {
        let selected = identity(vendor, device, CLASS).unwrap();
        assert_eq!(selected.position_policy, PositionPolicy::Link);
        assert_eq!(selected.probe_policy, ProbePolicy::Once);
    }
}

#[test]
fn excluded_subsystems_rejected() {
    for (device, subvendor, subdevice, error) in [
        (0x1487, 0x1043, 0x874f, AttachError::SubsystemExcluded),
        (0x1487, 0x1462, 0xcb59, AttachError::SubsystemExcluded),
        (0x1487, 0x1462, 0xcb60, AttachError::SubsystemExcluded),
        (0x15e3, 0x1462, 0xee59, AttachError::BoardIdentityRequired),
        (0x1457, 0xffff, 0xffff, AttachError::SubsystemUnavailable),
    ] {
        let (mut function, timer, bar) = fixture(0);
        set_identity(&mut function, AMD, device);
        function.config().words[usize::from(regs::SUBSYSTEM_VENDOR_ID / 4)] =
            subvendor | (subdevice << 16);
        assert_eq!(
            prepare_model(&mut function, &timer, bar).unwrap_err(),
            error
        );
        assert!(function.config().writes.is_empty());
    }
    // Similar pairs do not inherit another subsystem's exclusion.
    for (device, subvendor, subdevice) in [
        (0x1487, 0x1043, 0x8750),
        (0x1487, 0x1463, 0xcb59),
        (0x15e3, 0x1462, 0xee60),
    ] {
        let (mut function, timer, bar) = fixture(0);
        set_identity(&mut function, AMD, device);
        function.config().words[usize::from(regs::SUBSYSTEM_VENDOR_ID / 4)] =
            subvendor | (subdevice << 16);
        prepare_model(&mut function, &timer, bar).unwrap();
    }
}

#[test]
fn board_exclusion_uses_dmi_identity() {
    for (vendor, name, expected) in [
        (
            "Micro-Star International Co., Ltd.",
            "MAG X870E TOMAHAWK WIFI (MS-7E59)",
            Some(AttachError::BoardExcluded),
        ),
        (
            "OEM Micro-Star International Co., Ltd. ",
            "prefix MAG X870E TOMAHAWK WIFI (MS-7E59) rev2",
            Some(AttachError::BoardExcluded),
        ),
        (
            "Micro-Star International Co., Ltd.",
            "Different verified laptop board",
            None,
        ),
        (
            "Different verified vendor",
            "MAG X870E TOMAHAWK WIFI (MS-7E59)",
            None,
        ),
        (
            "",
            "MAG X870E TOMAHAWK WIFI (MS-7E59)",
            Some(AttachError::BoardIdentityRequired),
        ),
        (
            "Micro-Star International Co., Ltd.",
            "  ",
            Some(AttachError::BoardIdentityRequired),
        ),
    ] {
        let (mut function, timer, bar) = fixture(0);
        set_identity(&mut function, AMD, 0x15e3);
        function.config().words[usize::from(regs::SUBSYSTEM_VENDOR_ID / 4)] = 0xee59_1462;
        // SAFETY: modeled target firmware strings, no real platform state.
        let result = unsafe {
            prepare_with_board(
                &mut function,
                bar,
                &timer,
                Ownership::ExclusiveLegacy,
                BoardIdentity::Known { vendor, name },
            )
        };
        if let Some(error) = expected {
            assert_eq!(result.unwrap_err(), error);
            assert!(function.config().writes.is_empty());
        } else {
            result.unwrap();
        }
    }
}

#[test]
fn dsp_and_gpu_profiles_rejected() {
    for (vendor, device) in [
        (AMD, 0x15e2),
        (AMD, 0x1640),
        (AMD, 0xab28),
        (ATI, 0x157a),
        (ATI, 0x0002),
        (NVIDIA, 0x0bea),
        (INTEL, 0xa828),
    ] {
        let (mut function, timer, bar) = fixture(0);
        set_identity(&mut function, vendor, device);
        assert_eq!(
            prepare_model(&mut function, &timer, bar).unwrap_err(),
            AttachError::UnsupportedController
        );
        assert!(function.config().writes.is_empty());
    }
}

#[test]
fn rejected_snoop_keeps_mastering_disabled() {
    for variant in 0..3 {
        let (mut function, timer, bar) = fixture(0);
        set_identity(&mut function, AMD, 0x780d);
        match variant {
            0 => {
                function.config().words[13] = 0x40;
                function.config().words[16] = 0x0003_0001;
            }
            1 => function.config().reject_vendor_control = true,
            _ => function.config().words[16] = 0x00ff_0000,
        }
        let result = prepare_model(&mut function, &timer, bar).unwrap_err();
        if variant == 0 {
            assert_eq!(result, AttachError::InvalidCapabilities);
            assert!(function.config().writes.is_empty());
        } else {
            assert_eq!(result, AttachError::ConfigurationRejected);
            assert_eq!(
                function.config().get16(regs::COMMAND)
                    & (regs::COMMAND_MEMORY | regs::COMMAND_MASTER),
                0
            );
        }
        assert!(
            !function
                .config()
                .writes
                .iter()
                .any(|(offset, _, _, _)| *offset == TCSEL)
        );
    }
}

#[test]
fn failed_controls_rejected_before_updates() {
    for vendor_fault in [false, true] {
        let (mut function, timer, bar) = fixture(0);
        if vendor_fault {
            function.config().words[17] |= 0xff;
        } else {
            function.config().set16(regs::COMMAND, u16::MAX);
        }
        assert_eq!(
            prepare_model(&mut function, &timer, bar).unwrap_err(),
            AttachError::ConfigurationRejected
        );
        if vendor_fault {
            assert!(
                !function
                    .config()
                    .writes
                    .iter()
                    .any(|(offset, _, _, _)| *offset == TCSEL)
            );
        } else {
            assert!(function.config().writes.is_empty());
        }
    }
}
