// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2007-2010 Advanced Micro Devices, Inc.
// Author: Joerg Roedel <jroedel@suse.de>
//         Leo Duran <leo.duran@amd.com>
// Host-only device-entry fields and persistent IVHD policy adapted from Linux
// drivers/iommu/amd/{init.c,iommu.c,amd_iommu.h,amd_iommu_types.h}, commit
// cc9de5d4b5ab6459f5774946aa3195ad51236fa8. See platform/THIRD_PARTY.md.
//! AMD IOMMU device-table entries and the IVHD settings they carry.
use super::DeviceTableError;
use crate::bus::dma::amd::format::{DomainId, PhysicalAddress, TableLevel};

const VALID: u64 = 1;
const TRANSLATION: u64 = 1 << 1;
const READ: u64 = 1 << 61;
const WRITE: u64 = 1 << 62;
const ROOT: u64 = 0x000f_ffff_ffff_f000;
const MODE: u64 = 7 << 9;
const DOMAIN: u64 = 0xffff;
const INTERRUPTS: u64 = 0xff0f_ffff_ffff_ffff;
const SYSTEM_MANAGEMENT: u8 = 3 << 4;

#[derive(Clone, Copy)]
pub(super) struct Policy(u8);

impl Policy {
    pub(super) fn new(flags: u8) -> Self {
        Self(flags)
    }

    fn words(self) -> [u64; 4] {
        // IVHD bit3 is ATCPermit metadata (AMD48882rev3.11 Table106),
        // not DTE bit3 or DTE.I. Permission never enables ATS in this
        // separately admitted host-only profile with ATS/ATC off.
        let mut words = [0; 4];
        for (flag, bit) in [(1, 56), (2, 57), (4, 58), (64, 62), (128, 63)] {
            if self.0 & flag != 0 {
                words[2] |= 1 << bit;
            }
        }
        words[1] = u64::from((self.0 & SYSTEM_MANAGEMENT) >> 4) << 40;
        // AMD erratum 63: the SYSMGT=1 policy needs IW even in a blocked DTE.
        if self.0 & SYSTEM_MANAGEMENT == 1 << 4 {
            words[0] |= WRITE;
        }
        words
    }
}

/// Only the admitted host-only image. No passthrough mode, guest translation,
/// access/dirty writer, ATS, IRQ table or raw unknown-field constructor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Entry([u64; 4]);

impl Entry {
    pub(super) fn blocked(policy: Policy) -> Self {
        let mut words = policy.words();
        words[0] |= VALID;
        Self(words)
    }

    pub(super) fn translated(
        policy: Policy,
        root: PhysicalAddress,
        level: TableLevel,
        domain: DomainId,
    ) -> Result<Self, DeviceTableError> {
        if !root.value().is_multiple_of(4096) {
            return Err(DeviceTableError::Format(super::FormatError::Alignment));
        }
        let mut words = Self::blocked(policy).0;
        words[0] |= TRANSLATION | READ | WRITE | root.value() | (u64::from(level.mode()) << 9);
        words[1] |= u64::from(domain.value());
        Ok(Self(words))
    }

    pub(super) fn existing(
        words: [u64; 4],
        policy: Policy,
        physical_bits: u8,
    ) -> Result<Self, DeviceTableError> {
        if words == Self::blocked(policy).0 {
            return Ok(Self(words));
        }
        let domain = DomainId::new((words[1] & DOMAIN) as u16).ok_or(DeviceTableError::Profile)?;
        let level = TableLevel::new(((words[0] & MODE) >> 9) as u8)
            .map_err(|_| DeviceTableError::Profile)?;
        let root = PhysicalAddress::new(words[0] & ROOT, physical_bits)
            .map_err(|_| DeviceTableError::Profile)?;
        let expected = Self::translated(policy, root, level, domain)?;
        if expected.0 != words {
            return Err(DeviceTableError::Profile);
        }
        Ok(expected)
    }

    pub(super) fn domain(self) -> Option<DomainId> {
        DomainId::new((self.0[1] & DOMAIN) as u16)
    }
    pub(super) fn words(self) -> [u64; 4] {
        self.0
    }

    pub(super) fn preserving_interrupts(self, old: Self) -> Self {
        let mut words = self.0;
        words[2] = (words[2] & !INTERRUPTS) | (old.0[2] & INTERRUPTS);
        Self(words)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT_ADDRESS: u64 = 0x0000_1234_5678_9000;

    fn translated(flags: u8, mode: u8) -> Entry {
        Entry::translated(
            Policy::new(flags),
            PhysicalAddress::new(ROOT_ADDRESS, 48).unwrap(),
            TableLevel::new(mode).unwrap(),
            DomainId::new(0x5a7c).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn literal_host_words_distinguish_blocked_initial_and_translated_entries() {
        let clean = Policy::new(0);
        assert_eq!(Entry::blocked(clean).words(), [1, 0, 0, 0]);
        assert_eq!(Entry::blocked(clean).domain(), None);
        // Initial V|TV with zero rights is not Linux's runtime blocked image.
        assert_eq!(
            Entry::existing([3, 0, 0, 0], clean, 48),
            Err(DeviceTableError::Profile)
        );
        let entry = translated(0, 4);
        assert_eq!(
            entry.words(),
            [0x6000_1234_5678_9803, 0x0000_0000_0000_5a7c, 0, 0]
        );
        assert_eq!(entry.domain().map(DomainId::value), Some(0x5a7c));
        assert_eq!(Entry::existing(entry.words(), clean, 48), Ok(entry));

        // INIT/EINT/NMI, SYSMGT=1, LINT0/LINT1, including erratum 63.
        let policy = Policy::new(0xd7);
        let blocked = Entry::blocked(policy);
        assert_eq!(
            blocked.words(),
            [
                0x4000_0000_0000_0001,
                0x0000_0100_0000_0000,
                0xc700_0000_0000_0000,
                0,
            ]
        );
        let entry = translated(0xd7, 4);
        assert_eq!(
            entry.words(),
            [
                0x6000_1234_5678_9803,
                0x0000_0100_0000_5a7c,
                0xc700_0000_0000_0000,
                0,
            ]
        );
        assert_eq!(entry.preserving_interrupts(blocked), entry);
        assert_eq!(blocked.preserving_interrupts(entry), blocked);
        assert_eq!(blocked.domain(), None);
    }

    #[test]
    fn every_policy_byte_preserves_literal_ivhd_positions_with_atc_permission_as_metadata() {
        for flags in 0u8..=u8::MAX {
            let policy = Policy::new(flags);
            // Independent DTE word masks from the pinned global bit numbers:
            // 184/185/186/190/191 and system-management bits 104/105.
            let mut interrupts = 0;
            for (flag, mask) in [
                (0x01, 0x0100_0000_0000_0000u64),
                (0x02, 0x0200_0000_0000_0000),
                (0x04, 0x0400_0000_0000_0000),
                (0x40, 0x4000_0000_0000_0000),
                (0x80, 0x8000_0000_0000_0000),
            ] {
                if flags & flag != 0 {
                    interrupts |= mask;
                }
            }
            let system = (flags / 16) % 4;
            let write = if system == 1 {
                0x4000_0000_0000_0000
            } else {
                0
            };
            let expected = [
                write | 1,
                u64::from(system) * 0x0000_0100_0000_0000,
                interrupts,
                0,
            ];
            let blocked = Entry::blocked(policy);
            assert_eq!(blocked.words(), expected, "flags={flags:#04x}");
            assert_eq!(Entry::existing(expected, policy, 48), Ok(blocked));
            let entry = translated(flags, 4);
            assert_eq!(
                entry.words(),
                [0x6000_1234_5678_9803, expected[1] | 0x5a7c, interrupts, 0,],
                "flags={flags:#04x}"
            );
            assert_eq!(Entry::existing(entry.words(), policy, 48), Ok(entry));
        }
    }

    #[test]
    fn atc_permission_never_enables_actual_ats_or_a_reserved_dte_bit() {
        for flags in (0u8..=u8::MAX).filter(|flags| flags & 8 == 0) {
            let ordinary = Policy::new(flags);
            let permitted = Policy::new(flags | 8);
            assert_eq!((ordinary.0, permitted.0), (flags, flags | 8));
            assert_eq!(Entry::blocked(ordinary), Entry::blocked(permitted));
            for mode in 1..=6 {
                let expected = translated(flags, mode);
                let actual = translated(flags | 8, mode);
                assert_eq!(actual, expected);
                assert_eq!(actual.words()[0] & 8, 0, "actual DTE bit3 stays reserved");
                assert_eq!(actual.words()[1] & (1 << 32), 0, "DTE.I stays off");
                for image in [Entry::blocked(permitted).words(), actual.words()] {
                    for (word, mask) in [(0, 8), (1, 1 << 32)] {
                        let mut wrong = image;
                        wrong[word] |= mask;
                        assert_eq!(
                            Entry::existing(wrong, permitted, 48),
                            Err(DeviceTableError::Profile)
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn erratum_write_permission_is_only_required_for_system_management_one() {
        for (flags, low, system) in [
            (0x00, 0x0000_0000_0000_0001, 0x0000_0000_0000_0000),
            (0x10, 0x4000_0000_0000_0001, 0x0000_0100_0000_0000),
            (0x20, 0x0000_0000_0000_0001, 0x0000_0200_0000_0000),
            (0x30, 0x0000_0000_0000_0001, 0x0000_0300_0000_0000),
        ] {
            let policy = Policy::new(flags);
            let blocked = Entry::blocked(policy);
            assert_eq!(blocked.words(), [low, system, 0, 0]);
            // The admitted image includes exactly the policy's IW requirement.
            let mut wrong = blocked.words();
            wrong[0] ^= 0x4000_0000_0000_0000;
            assert_eq!(
                Entry::existing(wrong, policy, 48),
                Err(DeviceTableError::Profile)
            );
        }
    }

    #[test]
    fn host_modes_root_alignment_and_narrower_physical_width_are_checked() {
        let policy = Policy::new(0);
        for (mode, low) in [
            (1, 0x6000_1234_5678_9203),
            (2, 0x6000_1234_5678_9403),
            (3, 0x6000_1234_5678_9603),
            (4, 0x6000_1234_5678_9803),
            (5, 0x6000_1234_5678_9a03),
            (6, 0x6000_1234_5678_9c03),
        ] {
            let entry = translated(0, mode);
            assert_eq!(entry.words(), [low, 0x5a7c, 0, 0]);
            assert_eq!(Entry::existing(entry.words(), policy, 48), Ok(entry));
        }
        assert_eq!(
            Entry::translated(
                policy,
                PhysicalAddress::new(ROOT_ADDRESS + 1, 48).unwrap(),
                TableLevel::new(4).unwrap(),
                DomainId::new(0x5a7c).unwrap(),
            ),
            Err(DeviceTableError::Format(
                super::super::FormatError::Alignment
            ))
        );
        let wide = Entry::translated(
            policy,
            PhysicalAddress::new(1 << 40, 52).unwrap(),
            TableLevel::new(4).unwrap(),
            DomainId::new(0x5a7c).unwrap(),
        )
        .unwrap();
        assert_eq!(
            Entry::existing(wide.words(), policy, 32),
            Err(DeviceTableError::Profile)
        );
        let last = Entry::translated(
            policy,
            PhysicalAddress::new(0xffff_f000, 32).unwrap(),
            TableLevel::new(4).unwrap(),
            DomainId::new(0x5a7c).unwrap(),
        )
        .unwrap();
        assert_eq!(Entry::existing(last.words(), policy, 32), Ok(last));
        assert!(DomainId::new(0).is_none());
    }

    #[test]
    fn unknown_dma_irq_guest_and_reserved_profiles_are_not_reconstructed() {
        let policy = Policy::new(0);
        let base = [0x6000_1234_5678_9803, 0x5a7c, 0, 0];
        for (word, mask) in [
            (0, 1u64 << 2), // Reserved low control.
            (0, 1 << 3),    // DTE bit3 is not IVHD ATCPermit.
            (0, 1 << 7),    // HAD.
            (0, 1 << 8),    // HAD.
            (0, 1 << 52),   // PPR.
            (0, 1 << 53),   // Unknown control.
            (0, 1 << 54),   // GIOV.
            (0, 1 << 55),   // GV.
            (0, 1 << 56),   // GLX.
            (0, 1 << 58),   // GCR3.
            (0, 1 << 60),   // Reserved for this profile.
            (0, 1 << 63),   // Reserved for this profile.
            (1, 1 << 16),   // Guest root fragment.
            (1, 1 << 32),   // ATS IOTLB enable.
            (1, 1 << 34),   // No-page-fault policy is not admitted.
            (1, 1 << 40),   // Different immutable SYSMGT policy.
            (2, 1),         // Interrupt remapping enable.
            (2, 0x4000),    // IRQ table physical pointer.
            (2, 1 << 52),   // Guest translation fields.
            (2, 1 << 56),   // Different immutable INIT policy.
            (2, 1 << 60),   // Interrupt remapping control.
            (3, 1),         // Unknown upper word.
        ] {
            let mut wrong = base;
            wrong[word] |= mask;
            assert_eq!(
                Entry::existing(wrong, policy, 48),
                Err(DeviceTableError::Profile)
            );
        }
        // Both DTE rights must remain set for translation; leaf permissions
        // independently implement DMA direction. V, TV and a nonzero DID are
        // mandatory, and passthrough/unknown modes are not admitted here.
        for mask in [1, 2, 0x2000_0000_0000_0000, 0x4000_0000_0000_0000, 0xe00] {
            let mut wrong = base;
            wrong[0] &= !mask;
            assert_eq!(
                Entry::existing(wrong, policy, 48),
                Err(DeviceTableError::Profile)
            );
        }
        let mut mode_seven = base;
        mode_seven[0] = (mode_seven[0] & !0xe00) | 0xe00;
        assert_eq!(
            Entry::existing(mode_seven, policy, 48),
            Err(DeviceTableError::Profile)
        );
        let mut domain_zero = base;
        domain_zero[1] = 0;
        assert_eq!(
            Entry::existing(domain_zero, policy, 48),
            Err(DeviceTableError::Profile)
        );
        assert_eq!(
            Entry::existing([0; 4], policy, 48),
            Err(DeviceTableError::Profile)
        );
    }
}
