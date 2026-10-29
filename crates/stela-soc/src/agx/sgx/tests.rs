use super::super::generation::{self, GPUS};
use super::*;
use stela_contracts::interrupt::InterruptLatch;
use stela_contracts::refuse;

const MMU_TTBAT: u64 = 0xd0_802c;
const MMU_TTBA_INVALIDATE: u64 = 0xd0_8030;
const CORE_MASK_0: u64 = 0xd0_1500;
const CORE_MASK_1: u64 = 0xd0_1514;

fn t8112() -> &'static Gpu {
    generation::by_chip(0x8112).unwrap()
}

fn read(sgx: &mut Sgx, offset: u64) -> Result<u64, MmioError> {
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    sgx.read(offset, Width::Word, &mut access)
}

fn write(sgx: &mut Sgx, offset: u64, value: u32) -> Result<(), MmioError> {
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    sgx.write(offset, Width::Word, u64::from(value), &mut access)
}

fn firmware_region_at(
    kind: crate::research::agx_pio::Kind,
    physical: u64,
    va: u64,
) -> crate::research::agx_pio::Region {
    use super::super::ring::tests::Flat;
    use crate::research::agx_pio::Region;
    let mut flat = Flat::new(0x1000, 0x2000);
    let descriptor = 0x1000 + 0x640 + kind as u64 * 0x28;
    flat.put_u64(descriptor, physical);
    flat.put_u64(descriptor + 8, va);
    flat.put_u32(descriptor + 0x10, 0xc000);
    flat.put_u32(descriptor + 0x14, 0xc000);
    flat.put_u32(descriptor + 0x20, 2);
    Region::read(&mut flat, 0x1000, kind).unwrap()
}

#[test]
fn native_firmware_pio_walks_the_uat_and_shares_the_ap_register() {
    use super::super::generation::{G13G, G13X, G14G, G14X, G15G};
    use {stela_contracts::dma::Port, stela_contracts::dma::test_support::Ram};
    let physical = 0x204000000;
    let base = 0x800000000;
    for family in [&G13G, &G13X, &G14G, &G14X, &G15G] {
        let gpu = if family == &G15G {
            // G15G's interface is recovered, but its real identity is not
            // admitted. Exercise that layout on an explicit test fixture.
            t8112()
        } else {
            GPUS.iter()
                .find(|gpu| gpu.family == family && gpu.admitted().is_ok())
                .unwrap()
        };
        let mut sgx = Sgx::handed_off(gpu, base, base + 0x8000).unwrap();
        sgx.family = family;
        sgx.model = family.model().unwrap();
        let power = sgx.firmware_power(&[(physical, 0x4000000, 0)]).unwrap();
        let region = firmware_region_at(
            crate::research::agx_pio::Kind::GFender,
            physical + 0xd04000,
            0x10000,
        );
        let mut ram = Ram::new(base, 0x10000);
        let [ttbr0, ttbr1] = uat::encode_gptbat(0, base + 0x4000, 0);
        ram.put_u64(base, ttbr0);
        ram.put_u64(base + 8, ttbr1);
        ram.put_u64(base + 0x4000, uat::encode_table(base + 0x8000));
        ram.put_u64(base + 0x8000, uat::encode_table(base + 0xc000));
        let pte = base + 0xc000 + 4 * 8;
        let flags = uat::Flags {
            access: uat::Access::Firmware,
            memory: uat::MemoryAttr::Device,
            global: true,
            pxn: true,
            uxn: true,
            gpu_access: true,
        };
        // RAM holds only page tables. A successful native MMIO access
        // therefore proves the target was not sent through DMA Memory.
        ram.put_u64(pte, uat::encode_pte(physical + 0xd04000, &flags));
        write(&mut sgx, GATING_CONTROL, 2).unwrap();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut access_native = |sgx: &mut Sgx, ram: &mut Ram, value| {
            let mut view = sgx.uat().agent(uat::Agent::Firmware);
            let mut port = Port {
                iommu: &mut view,
                stream: 0,
                memory: ram,
                access: &mut access,
            };
            if let Some(value) = value {
                power.write(&mut port, &region, 0x2030, value)
            } else {
                assert_eq!(power.read(&mut port, &region, 0x2030), Ok(2));
                Ok(())
            }
        };
        access_native(&mut sgx, &mut ram, None).unwrap();
        // Missing PTE: no register effect; retry after fixing the table
        // succeeds without re-authoring or weakening the descriptor.
        ram.put_u64(pte, 0);
        assert!(
            access_native(&mut sgx, &mut ram, Some(4))
                .unwrap_err()
                .to_string()
                .contains("UAT")
        );
        assert_eq!(read(&mut sgx, GATING_CONTROL), Ok(2));
        ram.put_u64(pte, uat::encode_pte(physical + 0xd08000, &flags));
        assert!(
            access_native(&mut sgx, &mut ram, Some(4))
                .unwrap_err()
                .to_string()
                .contains("disagrees")
        );
        assert_eq!(read(&mut sgx, GATING_CONTROL), Ok(2));
        ram.put_u64(pte, uat::encode_pte(physical + 0xd04000, &flags));
        access_native(&mut sgx, &mut ram, Some(4)).unwrap();
        assert_eq!(read(&mut sgx, GATING_CONTROL), Ok(4));
        assert!(access_native(&mut sgx, &mut ram, Some(8)).is_err());
        assert_eq!(read(&mut sgx, GATING_CONTROL), Ok(4));
        // PMGR gating inhibits this physical owner too.
        let paused = LifecycleState {
            clocked: false,
            retention: true,
            ..sgx.lifecycle
        };
        sgx.check_lifecycle(paused).unwrap();
        let mut latch = InterruptLatch::new();
        sgx.set_lifecycle(paused, &mut Access::new(0, 0, &mut latch));
        assert!(
            access_native(&mut sgx, &mut ram, Some(0))
                .unwrap_err()
                .to_string()
                .contains("PMGR")
        );
        let running = LifecycleState {
            clocked: true,
            ..paused
        };
        sgx.set_lifecycle(running, &mut Access::new(0, 0, &mut latch));
        assert_eq!(read(&mut sgx, GATING_CONTROL), Ok(4));

        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let native_write =
            |sgx: &mut Sgx, ram: &mut Ram, access: &mut Access<'_>, offset, value| {
                let mut view = sgx.uat().agent(uat::Agent::Firmware);
                let mut port = Port {
                    iommu: &mut view,
                    stream: 0,
                    memory: ram,
                    access,
                };
                power.write(&mut port, &region, offset, value)
            };
        let translate = |sgx: &mut Sgx, ram: &mut Ram, access: &mut Access<'_>, agent| {
            use stela_contracts::dma::Iommu;
            sgx.uat()
                .agent(agent)
                .translate(ram, 0, 0x12030, 0x12033, false, access)
        };
        assert!(translate(&mut sgx, &mut ram, &mut access, uat::Agent::Gpu).is_ok());
        if !fender_sleep_supported(family) {
            assert!(native_write(&mut sgx, &mut ram, &mut access, 0x74, 1).is_err());
            assert!(translate(&mut sgx, &mut ram, &mut access, uat::Agent::Gpu).is_ok());
            continue;
        }
        assert!(native_write(&mut sgx, &mut ram, &mut access, 0x74, 2).is_err());
        assert!(translate(&mut sgx, &mut ram, &mut access, uat::Agent::Gpu).is_ok());
        native_write(&mut sgx, &mut ram, &mut access, 0x74, 1).unwrap();
        assert!(
            power
                .check_reset()
                .unwrap_err()
                .to_string()
                .contains("restore ownership")
        );
        assert!(
            matches!(translate(&mut sgx, &mut ram, &mut access, uat::Agent::Gpu),
                Err(stela_contracts::dma::DmaError::Unsupported(reason)) if reason.to_string().contains("Fender sleep"))
        );
        assert!(translate(&mut sgx, &mut ram, &mut access, uat::Agent::Firmware).is_ok());
        assert!(
            native_write(&mut sgx, &mut ram, &mut access, 0x2020, 1)
                .unwrap_err()
                .to_string()
                .contains("remains asserted")
        );
        assert!(translate(&mut sgx, &mut ram, &mut access, uat::Agent::Gpu).is_err());
        // Clearing the request is distinct from waking the GPU. The
        // original callback clears this request after polling completion.
        native_write(&mut sgx, &mut ram, &mut access, 0x74, 0).unwrap();
        assert!(translate(&mut sgx, &mut ram, &mut access, uat::Agent::Gpu).is_err());
        let status = gifaf_status(family).unwrap();
        let status_pte = base + 0xc000 + 8 * 8;
        ram.put_u64(
            status_pte,
            uat::encode_pte((physical + status) & !0x3fff, &flags),
        );
        // Account for the PIO base's sub-page offset; it is not a new
        // physical range and must survive the source mapping unchanged.
        let subpage = (status & !0xfff) & 0x3fff;
        let gifaf = firmware_region_at(
            crate::research::agx_pio::Kind::GmGifaf,
            physical + (status & !0xfff),
            0x20000 + subpage,
        );
        let native_status = |sgx: &mut Sgx, ram: &mut Ram, access: &mut Access<'_>| {
            let mut view = sgx.uat().agent(uat::Agent::Firmware);
            let mut port = Port {
                iommu: &mut view,
                stream: 0,
                memory: ram,
                access,
            };
            power.read(&mut port, &gifaf, 0x90)
        };
        assert_eq!(
            native_status(&mut sgx, &mut ram, &mut access),
            Ok(GIFAF_SLEEP_COMPLETE)
        );
        // A fault at the later wake PIO never clears kept inhibition.
        ram.put_u64(pte, 0);
        assert!(native_write(&mut sgx, &mut ram, &mut access, 0x2020, 1).is_err());
        assert!(translate(&mut sgx, &mut ram, &mut access, uat::Agent::Gpu).is_err());
        assert_eq!(
            native_status(&mut sgx, &mut ram, &mut access),
            Ok(GIFAF_SLEEP_COMPLETE)
        );
        ram.put_u64(pte, uat::encode_pte(physical + 0xd04000, &flags));
        native_write(&mut sgx, &mut ram, &mut access, 0x2020, 1).unwrap();
        assert!(translate(&mut sgx, &mut ram, &mut access, uat::Agent::Gpu).is_ok());
        assert_eq!(native_status(&mut sgx, &mut ram, &mut access), Ok(0));
        assert_eq!(power.check_reset(), Ok(()));
    }
}

#[test]
fn native_asc_binding_uses_declared_placement_and_checks_the_whole_private_word() {
    let mut sgx = Sgx::new(t8112()).unwrap();
    write(&mut sgx, GATING_CONTROL, 4).unwrap();
    let power = sgx.firmware_power(&[(0x204000000, 0x4000000, 0)]).unwrap();
    assert_eq!(power.asc_wrapper(), None);
    assert_eq!(power.native_asc_control(), None);
    let bound = power.clone().with_asc_wrapper(0x206400000).unwrap();
    assert_eq!(bound.asc_wrapper(), Some(0x206400000));
    assert_eq!(bound.native_asc_control(), Some(0x206540120));
    assert_eq!(bound.logical(0x206540120), Ok(0x2540120));
    assert!(bound.clone().with_asc_wrapper(0x206400000).is_ok());
    assert!(bound.clone().with_asc_wrapper(0x206500000).is_err());
    assert!(power.clone().with_asc_wrapper(0x304000000).is_err());
    assert!(power.with_asc_wrapper(u64::MAX).is_err());
    // The first byte alone cannot check an eight-byte native register.
    let short = sgx.firmware_power(&[(0x204000000, 0x2540124, 0)]).unwrap();
    assert!(short.with_asc_wrapper(0x206400000).is_err());
    assert_eq!(read(&mut sgx, GATING_CONTROL), Ok(4));
}

#[test]
fn firmware_power_owner_requires_complete_unambiguous_physical_geometry() {
    let sgx = Sgx::new(t8112()).unwrap();
    for banks in [
        vec![],
        vec![(0x204000000, 0x1000, 0)],
        vec![(0x204000000, GIFAF_IDLE_STATUS_G13_G14 + 1, 0)],
        vec![(0x204000000, 0x4000000, 0), (0x204000004, 4, 0x5000000)],
        vec![(0x204000000, 0x4000000, 0), (0x304000000, 4, 4)],
        vec![(0x204000000, 0x4000000, 0), (u64::MAX, 2, 0x5000000)],
    ] {
        assert!(sgx.firmware_power(&banks).is_err());
    }
    let power = sgx.firmware_power(&[(0x204000000, 0x4000000, 0)]).unwrap();
    assert!(power.logical(0x304d06030).is_err());
}

#[test]
fn physical_gates_inhibit_the_mmu_and_preserve_boot_roots_until_released() {
    use {stela_contracts::dma::Iommu, stela_contracts::dma::test_support::Ram};
    let mut sgx = Sgx::handed_off(t8112(), 0x8_0000_0000, 0x8_0000_4000).unwrap();
    let active = sgx.lifecycle;
    let mut ram = Ram::new(0, 0x1000);
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    for gated in [
        LifecycleState {
            clocked: false,
            ..active
        },
        LifecycleState {
            quiesced: true,
            ..active
        },
        LifecycleState {
            powered: false,
            retention: true,
            ..active
        },
    ] {
        sgx.check_lifecycle(gated).unwrap();
        sgx.set_lifecycle(gated, &mut access);
        assert!(matches!(
            sgx.uat().agent(uat::Agent::Firmware).translate(
                &mut ram,
                0,
                0x4000,
                0x4007,
                false,
                &mut access
            ),
            Err(stela_contracts::dma::DmaError::Unsupported(
                reason
            )) if reason == refuse!("SGX DMA while PMGR inhibits execution")
        ));
        assert_eq!(sgx.uat().ttbat(), Some(0x8_0000_0000));
        assert_eq!(sgx.uat().shared_l2(), Some(0x8_0000_4000));
        assert!(
            sgx.check_lifecycle(LifecycleState {
                reset: true,
                ..active
            })
            .is_err()
        );
        sgx.set_lifecycle(active, &mut access);
        assert_eq!(sgx.read(MMU_ENABLE, Width::Word, &mut access), Ok(1));
    }
}

#[test]
fn identification_decodes_as_readchipinfo_reads_it() {
    let mut sgx = Sgx::new(t8112()).unwrap();
    let version = read(&mut sgx, ID_VERSION).unwrap();
    assert_eq!(version >> 24, 5);
    assert_eq!((version >> 16) & 0xff, 2);
    // Revision B0: major 1 in bits 15:12, minor 0 in bits 11:8.
    assert_eq!((version >> 8) & 0xff, 0x10);
    let counts = read(&mut sgx, ID_COUNTS_1).unwrap();
    assert_eq!((counts & 0xff, (counts >> 8) & 0xff), (10, 10));
    assert_eq!((read(&mut sgx, ID_COUNTS_2).unwrap() >> 16) & 0xff, 4);
    assert_eq!((read(&mut sgx, ID_CLUSTERS).unwrap() >> 12) & 0xff, 1);
    assert_eq!(read(&mut sgx, CORE_MASK_0).unwrap(), 0x3ff);
    assert_eq!(read(&mut sgx, CORE_MASK_1).unwrap(), 0);
    // A word no AP code reads refuses, as do other widths and the
    // core-mask words of another family.
    assert!(read(&mut sgx, 0xd0_4008).is_err());
    assert!(read(&mut sgx, 0xe0_1500).is_err());
    assert!(read(&mut sgx, 0).is_err());
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    assert!(sgx.read(ID_VERSION, Width::Double, &mut access).is_err());
}

#[test]
fn a_gpu_whose_family_is_not_modeled_has_no_registers() {
    for gpu in GPUS.iter().filter(|gpu| gpu.admitted().is_err()) {
        assert!(Sgx::new(gpu).is_err(), "{}", gpu.compatible);
    }
}

/// The register writes of `setupMMUConfig`, in its order.
fn setup_mmu(sgx: &mut Sgx, ttbat: u64) -> Result<(), MmioError> {
    assert_eq!(read(sgx, MMU_ENABLE)?, 0);
    write(sgx, MMU_TTBAT, (ttbat >> 14) as u32 & ((1 << 26) - 1))?;
    for (offset, value) in [
        (0xd0_8014, 0x80d8),
        (0xd0_8018, 0x80d8),
        (0xd0_800c, 0),
        (0xd0_8010, 0),
        (0xd0_801c, 0),
        (0xd0_8020, 0),
        (0xd0_8024, 0),
        (0xd0_8028, 0),
        (0xd0_8008, 1),
        (0xd0_8004, 0x3ff),
    ] {
        write(sgx, offset, value)?;
        assert_eq!(read(sgx, offset)?, u64::from(value));
    }
    write(sgx, MMU_ENABLE, 1)
}

#[test]
fn the_mmu_configuration_roots_the_uat_at_the_programmed_ttbat() {
    let mut sgx = Sgx::new(t8112()).unwrap();
    assert_eq!(sgx.uat().ttbat(), None);
    setup_mmu(&mut sgx, 0x8_1234_4000).unwrap();
    assert_eq!(read(&mut sgx, MMU_ENABLE).unwrap(), 1);
    assert_eq!(sgx.uat().ttbat(), Some(0x8_1234_4000));
    // A second setup sees the MMU enabled; reconfiguring refuses.
    assert!(write(&mut sgx, MMU_TTBAT, 0x1).is_err());
    // TTBA-cache invalidations are accepted and read back.
    write(&mut sgx, MMU_TTBA_INVALIDATE, 3 << 8 | 1).unwrap();
    assert_eq!(read(&mut sgx, MMU_TTBA_INVALIDATE).unwrap(), 0x301);
}

#[test]
fn the_boot_stage_hands_off_the_mmu_setup_would_have_configured() {
    let mut configured = Sgx::new(t8112()).unwrap();
    setup_mmu(&mut configured, 0x8_0004_4000).unwrap();
    let mut handed = Sgx::handed_off(t8112(), 0x8_0004_4000, 0x8_0008_8000).unwrap();
    for offset in [MMU_ENABLE, MMU_TTBAT]
        .into_iter()
        .chain(t8112().family.mmu.configuration.iter().map(|&(o, _)| o))
    {
        assert_eq!(read(&mut handed, offset), read(&mut configured, offset));
    }
    assert_eq!(handed.uat().ttbat(), Some(0x8_0004_4000));
    // setupMMUConfig then returns at once; a rewrite refuses.
    assert!(write(&mut handed, MMU_TTBAT, 0x1).is_err());
    assert!(Sgx::handed_off(t8112(), 0, 0x8_0008_8000).is_err());
    assert!(Sgx::handed_off(t8112(), 0x8_0004_4001, 0x8_0008_8000).is_err());
    assert!(Sgx::handed_off(t8112(), 1 << 40, 0x8_0008_8000).is_err());
    assert!(Sgx::handed_off(t8112(), 0x8_0004_4000, 0x8_0008_8001).is_err());
}

#[test]
fn an_unknown_mmu_configuration_refuses() {
    let mut sgx = Sgx::new(t8112()).unwrap();
    assert!(write(&mut sgx, 0xd0_8014, 0x80d9).is_err());
    // Enabling before the configuration is written refuses.
    write(&mut sgx, MMU_TTBAT, 0x2_0000).unwrap();
    assert!(write(&mut sgx, MMU_ENABLE, 1).is_err());
    assert!(write(&mut sgx, MMU_TTBAT, 1 << 26).is_err());
}

#[test]
fn g14x_identification_counts_dies_and_its_fender_moves() {
    let gpu = generation::by_chip(0x6022).unwrap();
    let mut sgx = Sgx::new(gpu).unwrap();
    let version = read(&mut sgx, ID_VERSION).unwrap();
    assert_eq!((version >> 24, (version >> 16) & 0xff), (6, 4));
    // Two dies of four 10-core clusters; 0xd0401c names no count.
    assert_eq!(read(&mut sgx, ID_COUNTS_1).unwrap(), 2 << 16 | 4 << 8 | 10);
    assert_eq!(read(&mut sgx, ID_CLUSTERS).unwrap(), 0);
    let masks: alloc::vec::Vec<_> = [0xe0_1500, 0xe0_1504, 0xe0_1508]
        .into_iter()
        .map(|offset| read(&mut sgx, offset).unwrap())
        .collect();
    assert_eq!(masks, [0xffff_ffff, 0xffff_ffff, 0xffff]);
    write(&mut sgx, 0xe0_1010, 0b11).unwrap();
    assert_eq!(read(&mut sgx, 0xe0_1010).unwrap(), 0b11);
    assert_eq!(read(&mut sgx, 0xe0_1000).unwrap(), 0);
    assert!(read(&mut sgx, 0xd0_1000).is_err());
    assert!(read(&mut sgx, 0xd4_0e10).is_err());
}

#[test]
fn fender_controls_hold_their_bits_and_raise_nothing() {
    const GPC: u64 = 0xd0_1000;
    let mut sgx = Sgx::new(t8112()).unwrap();
    assert_eq!(read(&mut sgx, GPC + GPC_PERFORMANCE_STATE).unwrap(), 0);
    write(&mut sgx, GPC + GPC_HOST_INTERRUPT_ENABLE, 0b101).unwrap();
    assert_eq!(
        read(&mut sgx, GPC + GPC_HOST_INTERRUPT_ENABLE).unwrap(),
        0b101
    );
    assert!(write(&mut sgx, GPC + GPC_HOST_INTERRUPT_ENABLE, 0b1000).is_err());
    assert_eq!(read(&mut sgx, GPC + GPC_HOST_INTERRUPT_STATUS).unwrap(), 0);
    assert!(read(&mut sgx, 0xe0_1000).is_err());
    // Disable then enable dynamic gating, as the Fender does.
    let gating = read(&mut sgx, GATING_CONTROL).unwrap() as u32;
    write(&mut sgx, GATING_CONTROL, gating | 0b100).unwrap();
    let gating = read(&mut sgx, GATING_CONTROL).unwrap() as u32;
    write(&mut sgx, GATING_CONTROL, gating & !0b110).unwrap();
    assert_eq!(read(&mut sgx, GATING_CONTROL).unwrap(), 0);
    assert!(write(&mut sgx, GATING_CONTROL, 1).is_err());
}
