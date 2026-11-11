use super::super::generation::{self, GPUS};
use super::*;
use stela_contracts::interrupt::InterruptLatch;
use stela_contracts::refuse;

const MMU_TTBAT: u64 = 0xd0_802c;
const MMU_TTBA_INVALIDATE: u64 = 0xd0_8030;
const CORE_MASK_0: u64 = 0xd0_1500;
const CORE_MASK_1: u64 = 0xd0_1514;

impl FirmwarePower {
    fn logical(&self, physical: u64) -> Result<u64> {
        for &(base, bytes, offset) in &self.banks {
            if let Some(at) = physical.checked_sub(base)
                && at.checked_add(4).is_some_and(|end| end <= bytes)
            {
                return Ok(offset + at);
            }
        }
        Err(refuse!(
            "GFX firmware PIO does not target a mounted SGX bank"
        ))
    }
}

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
