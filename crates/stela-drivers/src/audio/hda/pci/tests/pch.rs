// SPDX-License-Identifier: GPL-2.0-only
//! pch behavior tests.
use super::*;

#[test]
fn hsw_bdw_pch_word_snoop_preserves_device_status_and_tcsel_neighbors_after_d3hot() {
    for device in [0x8c20, 0x8ca0, 0x8d20, 0x8d21, 0x9c20, 0x9c21, 0x9ca0] {
        for (version, kind) in [(1, 9), (2, 9), (1, 0), (2, 0)] {
            let (mut function, timer, bar) = pch_fixture(device, version, kind);
            let prepared = prepare_model(&mut function, &timer, bar).unwrap();
            assert_eq!(prepared.config().probe_policy, ProbePolicy::Once);
            assert_eq!(prepared.config().position_policy, PositionPolicy::Link);
            assert_eq!(prepared.config().dma_address_bits, 64);
            assert_eq!(function.config().words[30], 0xf91f_7255);
            assert_eq!(function.config().words[17], 0x5ac3_a5f0);
            assert_eq!(function.config().get16(0xb2) & (1 << 15), 0);
            let writes = &function.config().writes;
            assert!(
                writes
                    .iter()
                    .any(|(offset, width, value, time)| *offset == SCH_HDA_DEVC
                        && *width == 2
                        && *value == 0x7255
                        && *time >= 10_000)
            );
            assert!(
                !writes
                    .iter()
                    .any(|(offset, _, _, _)| matches!(*offset, 0x7a | ATI_SNOOP_CONTROL))
            );
            let written = writes.len();
            // Already coherent: the donor avoids rewriting Device Control.
            prepare_model(&mut function, &timer, bar).unwrap();
            assert!(
                !function.config().writes[written..]
                    .iter()
                    .any(|(offset, _, _, _)| *offset == SCH_HDA_DEVC)
            );
            assert_eq!(function.config().words[30], 0xf91f_7255);
        }
    }
}

#[test]
fn remaining_legacy_pch_profiles_prepare_with_exact_word_snoop_and_global_tags() {
    for device in [
        0x1c20, 0x1d20, 0x1e20, 0x3b56, 0x3b57, 0x811b, 0x080a, 0x0f04, 0x2284,
    ] {
        let (mut function, timer, bar) = pch_fixture(device, 2, 9);
        let prepared = prepare_model(&mut function, &timer, bar).unwrap();
        assert_eq!(prepared.config().reset_policy, ResetPolicy::Generic);
        assert_eq!(prepared.config().stream_tag_policy, StreamTagPolicy::Global);
        assert_eq!(prepared.config().position_policy, PositionPolicy::Link);
        assert_eq!(function.config().words[30], 0xf91f_7255);
        assert_eq!(function.config().words[17], 0x5ac3_a5f0);
        assert!(
            !function
                .config()
                .writes
                .iter()
                .any(|(offset, _, _, _)| *offset == CGCTL)
        );
        assert!(timer.now_us() >= 10_000);
    }
}

#[test]
fn lewisburg_requires_mapped_ownership_and_separate_tags_without_skl_reset() {
    for &device in INTEL_LBG_IDS {
        let (mut function, timer, bar) = modern_pci_model_for(device);
        assert_eq!(
            prepare_model(&mut function, &timer, bar).unwrap_err(),
            AttachError::MappedPreflightRequired
        );
        assert!(function.config().writes.is_empty());
        let adapter = unsafe {
            prepare_with_registers(
                &mut function,
                bar,
                &timer,
                Ownership::ExclusiveLegacy,
                MappedModel::new(),
            )
        }
        .unwrap();
        assert_eq!(adapter.config().reset_policy, ResetPolicy::Generic);
        assert_eq!(
            adapter.config().stream_tag_policy,
            StreamTagPolicy::PerDirection
        );
        drop(adapter);
        assert_eq!(function.config().words[30], 0xf91f_7255);
        assert!(
            !function
                .config()
                .writes
                .iter()
                .any(|(offset, _, _, _)| *offset == CGCTL)
        );
    }
}

#[test]
fn pch_snoop_capability_ownership_rejects_unrelated_headers_bodies_and_wrong_pcie_layout() {
    for variant in 0..11 {
        let (mut function, timer, bar) = pch_fixture(0x8c20, 2, 9);
        match variant {
            0 => {
                // Unknown header directly aliases DEVC78.
                function.config().words[24] = 0x0001_7805;
                function.config().words[30] = 0xfe;
            }
            1 => {
                // PM74 body aliases DEVC; list contains no PCIe owner.
                function.config().words[24] = 0x0001_7405;
                function.config().words[29] = 0x0003_0001;
            }
            2 => {
                // MSI-X70 body aliases the owned field.
                function.config().words[28] = 0x8000_0011;
            }
            3 => {
                // A PCIe cap74 makes78 Device Capability, not Control.
                function.config().words[24] = 0x0001_7405;
                function.config().words[29] = 0x0092_0010;
            }
            4 => {
                // Unknown PCIe version.
                function.config().words[28] = 0x0090_b010;
            }
            5 => {
                // Root event collector lacks endpoint Device Control.
                function.config().words[28] = 0x00a2_b010;
            }
            6 => {
                // A second header in the owned PCIe body.
                function.config().words[28] = 0x0092_8010;
                function.config().words[32] = 0xfe;
            }
            7 => {
                // A reverse alias: earlier MSI body contains PCIe header.
                function.config().words[24] = 0x0101_6c05;
                function.config().words[27] = 0x0092_0010;
            }
            8 => {
                // Failed PCIe flags read cannot select a layout.
                function.config().words[28] = 0xffff_b010;
            }
            9 => {
                // Unknown body70 cannot prove ownership of78.
                function.config().words[28] = 0xb0fe;
            }
            _ => {
                // Absent capabilities cannot establish Device Control.
                function.config().words[1] &= !(u32::from(STATUS_CAPABILITIES) << 16);
            }
        }
        assert_eq!(
            prepare_model(&mut function, &timer, bar).unwrap_err(),
            AttachError::InvalidCapabilities
        );
        assert!(function.config().writes.is_empty(), "variant {variant}");
    }
}

#[test]
fn pch_snoop_control_failures_refuse_and_attempt_cleanup_after_the_failed_word_access() {
    for variant in 0..3 {
        let (mut function, timer, bar) = pch_fixture(0x9ca0, 2, 9);
        match variant {
            0 => function.config().set16(SCH_HDA_DEVC, u16::MAX),
            1 => function.config().reject_snoop = true,
            _ => function.config().failed_snoop_read = true,
        }
        assert_eq!(
            prepare_model(&mut function, &timer, bar).unwrap_err(),
            AttachError::ConfigurationRejected
        );
        let config = function.config();
        assert_eq!(
            config.get16(PCI_COMMAND) & (COMMAND_MASTER | COMMAND_MEMORY),
            0
        );
        if variant == 0 {
            assert!(
                !config
                    .writes
                    .iter()
                    .any(|(offset, _, _, _)| *offset == SCH_HDA_DEVC)
            );
        } else {
            let failed_access = config
                .writes
                .iter()
                .rposition(|(offset, _, _, _)| *offset == SCH_HDA_DEVC)
                .unwrap();
            assert!(
                config.writes[failed_access + 1..]
                    .iter()
                    .any(|(offset, width, value, _)| *offset == PCI_COMMAND
                        && *width == 2
                        && *value & u32::from(COMMAND_MASTER | COMMAND_MEMORY) == 0)
            );
        }
        assert!(
            !config
                .writes
                .iter()
                .any(|(offset, _, value, _)| *offset == PCI_COMMAND
                    && *value & u32::from(COMMAND_MASTER) != 0)
        );
        assert_eq!(config.words[30] >> 16, 0xf91f);
    }
}

#[test]
fn pch_dsp_and_selectable_classes_refuse_before_writes_and_unimplemented_intel_stays_unknown() {
    for (class, stale_enumeration) in [
        ([4, 1, 0], false),
        ([4, 3, 0x80], false),
        ([4, 1, 0], true),
        ([4, 3, 0x80], true),
    ] {
        let (mut function, timer, bar) = pch_fixture(0x8c20, 2, 9);
        if !stale_enumeration {
            function.class = class;
        }
        function.config().words[2] =
            (u32::from(class[0]) << 24) | (u32::from(class[1]) << 16) | (u32::from(class[2]) << 8);
        assert_eq!(
            prepare_model(&mut function, &timer, bar).unwrap_err(),
            AttachError::UnsupportedController
        );
        assert!(function.config().writes.is_empty());
    }
    for device in [0x0a0c, 0x160c, 0xa828, 0xe428, 0xe328, 0xd328, 0x5a98] {
        assert_eq!(
            identity(INTEL, device, CLASS),
            Err(AttachError::UnsupportedController)
        );
    }
}
