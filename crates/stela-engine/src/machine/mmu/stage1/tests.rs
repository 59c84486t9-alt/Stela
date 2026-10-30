use super::*;
use crate::machine::mmu::{MemoryType, SPRR_CONFIG_EN, Sprr};
use alloc::collections::BTreeMap;

#[derive(Default)]
struct Tables(BTreeMap<u64, u64>);

impl TableMemory for Tables {
    fn read_descriptor(&mut self, physical: u64) -> Option<u64> {
        (physical < 0x1_0000_0000).then(|| self.0.get(&physical).copied().unwrap_or(0))
    }
    fn update_descriptor(&mut self, _: u64, _: u64, _: u64) -> Option<bool> {
        unreachable!("the profile has no hardware descriptor updates")
    }
}

const KERNEL: Requester = Requester {
    el: 1,
    pan: false,
    unprivileged: false,
    guarded: false,
};
const USER: Requester = Requester { el: 0, ..KERNEL };
// 16 KiB granules for both halves, 47-bit low and 36-bit high regions,
// 48-bit IPS.
const TCR: u64 = (2 << 14) | 17 | (1 << 30) | (28 << 16) | TCR_TBI0 | (5 << 32);
const PAGE: u64 = 1 << 14;
const ATTRS: u64 = DESCRIPTOR_VALID | DESCRIPTOR_TABLE | ACCESS_FLAG | (1 << 2);
const TABLE: u64 = DESCRIPTOR_VALID | DESCRIPTOR_TABLE;

/// SCTLR_EL1 with the MMU and both caches enabled.
const CACHED: u64 = SCTLR_M | (1 << 2) | (1 << 12);

fn controls() -> Controls {
    Controls {
        sctlr: CACHED,
        tcr: TCR,
        ttbr0: 0x10_0000 | (5 << 48),
        ttbr1: 0x20_0000,
        mair: 0xff00, // index 0 Device-nGnRnE, index 1 Normal WB
        xs: super::super::test_xs(),
        ..Controls::default()
    }
}

/// Map `va` at level 3 of a 16 KiB, 47-bit low-half walk (levels 1–3)
/// or a 36-bit high-half walk (levels 2–3).
fn map(tables: &mut Tables, controls: &Controls, va: u64, pa: u64, leaf: u64) -> u64 {
    let upper = va & (1 << 55) != 0;
    let (root, shifts): (u64, &[u32]) = if upper {
        (controls.ttbr1 & OUTPUT_ADDRESS, &[25])
    } else {
        (controls.ttbr0 & OUTPUT_ADDRESS, &[36, 25])
    };
    let mut table = root;
    for (depth, shift) in shifts.iter().enumerate() {
        let slot = table + ((va >> shift) & 0x7ff) * 8;
        let next = 0x100_0000 + (u64::from(upper) << 20) + depth as u64 * PAGE;
        tables.0.entry(slot).or_insert(next | TABLE);
        table = tables.0[&slot] & OUTPUT_ADDRESS;
    }
    let slot = table + ((va >> 14) & 0x7ff) * 8;
    tables.0.insert(slot, pa | leaf);
    slot
}

fn faults(outcome: Outcome) -> Option<(FaultKind, i8)> {
    match outcome {
        Outcome::Fault(fault) => Some((fault.kind, fault.level)),
        _ => None,
    }
}

fn rights(outcome: Outcome) -> (bool, bool, bool) {
    let Outcome::Mapped(translation) = outcome else {
        panic!("{outcome:?}")
    };
    (
        translation.readable,
        translation.writable,
        translation.executable,
    )
}

#[test]
fn walks_16k_tables_in_both_halves_with_permissions_and_types() {
    let controls = controls();
    let mut tables = Tables::default();
    let kernel_va = 0xffff_fff0_0000_4000_u64;
    let user_va = 0x1_0000_8000_u64;
    map(
        &mut tables,
        &controls,
        kernel_va,
        0x8_0000_4000,
        ATTRS | UXN | 3 << 8,
    );
    let user_leaf = TABLE | ACCESS_FLAG | AP_EL0 | PXN | NOT_GLOBAL;
    map(&mut tables, &controls, user_va, 0x8_0010_0000, user_leaf);
    let Outcome::Mapped(kernel) = translate(
        &controls,
        kernel_va + 0x123,
        Access::Execute,
        KERNEL,
        &mut tables,
    ) else {
        panic!("kernel text")
    };
    assert_eq!(kernel.physical, 0x8_0000_4123);
    assert_eq!(
        (kernel.memory, kernel.attributes, kernel.shareability),
        (MemoryType::Normal, 0xff, 0b11)
    );
    assert!(kernel.global && kernel.writable && kernel.size == PAGE);
    // With SCTLR.I clear a fetch is Normal Non-cacheable, Outer
    // Shareable; with SCTLR.C clear so is a data access.
    for (sctlr, access) in [
        (CACHED & !(1 << 12), Access::Execute),
        (CACHED & !(1 << 2), Access::Read),
    ] {
        let uncached = Controls { sctlr, ..controls };
        let Outcome::Mapped(output) = translate(&uncached, kernel_va, access, KERNEL, &mut tables)
        else {
            panic!("caches off")
        };
        // Under FEAT_XS it keeps the Write-Back's XS of 0: 0x40.
        let non_cacheable = if super::super::test_xs() { 0x40 } else { 0x44 };
        assert_eq!(
            (output.attributes, output.shareability),
            (non_cacheable, 0b10)
        );
    }
    assert_eq!(
        faults(translate(
            &controls,
            kernel_va,
            Access::Read,
            USER,
            &mut tables
        )),
        Some((FaultKind::Permission, 3))
    );
    // User data: Device-nGnRnE, Outer Shareable, EL0 writable, never
    // EL1-executable, tagged with the ASID.
    let Outcome::Mapped(user) = translate(&controls, user_va + 8, Access::Write, USER, &mut tables)
    else {
        panic!("user data")
    };
    assert_eq!(user.physical, 0x8_0010_0008);
    assert_eq!(
        (user.memory, user.shareability, user.global, user.asid),
        (MemoryType::Device, 0b10, false, 5)
    );
    assert!(user.executable, "EL0 may execute its own writable page");
    assert_eq!(
        faults(translate(
            &controls,
            user_va,
            Access::Execute,
            KERNEL,
            &mut tables
        )),
        Some((FaultKind::Permission, 3))
    );
    // TBI0 ignores the top byte of low-half data, never of TTBR1 addresses.
    assert!(matches!(
        translate(
            &controls,
            user_va | (0x5a << 56),
            Access::Read,
            USER,
            &mut tables
        ),
        Outcome::Mapped(_)
    ));
    assert_eq!(
        faults(translate(
            &controls,
            kernel_va & !(1 << 60),
            Access::Read,
            KERNEL,
            &mut tables
        )),
        Some((FaultKind::Translation, 0))
    );
}

#[test]
fn access_permissions_follow_ap_xn_wxn_and_pan() {
    let mut controls = controls();
    let pan = Requester {
        pan: true,
        ..KERNEL
    };
    let unprivileged = Requester {
        unprivileged: true,
        ..KERNEL
    };
    let leaf = |controls: &Controls, requester, descriptor| {
        super::rights(controls, requester, &Hierarchy::default(), descriptor)
    };
    // AP[2:1] 00..11 with UXN=PXN=0: the rights of EL1, EL0, EL1 with
    // PAN, and an unprivileged EL1 access.
    let expected = [
        // EL1 RW, EL0 execute-only.
        [
            (true, true, true),
            (false, false, true),
            (true, true, true),
            (false, false, true),
        ],
        // EL1 RW, EL0 RW: implicitly PXN; PAN removes EL1 data access.
        [
            (true, true, false),
            (true, true, true),
            (false, false, false),
            (true, true, false),
        ],
        // EL1 RO, EL0 execute-only.
        [
            (true, false, true),
            (false, false, true),
            (true, false, true),
            (false, false, true),
        ],
        // EL1 RO, EL0 RO.
        [
            (true, false, true),
            (true, false, true),
            (false, false, true),
            (true, false, true),
        ],
    ];
    for (ap, expected) in expected.into_iter().enumerate() {
        let descriptor = ATTRS | (ap as u64) << 6;
        let observed = [KERNEL, USER, pan, unprivileged]
            .map(|requester| leaf(&controls, requester, descriptor));
        assert_eq!(observed, expected, "AP[2:1] = {ap:02b}");
    }
    // UXN and PXN.
    let never = ATTRS | AP_EL0 | AP_READ_ONLY | UXN | PXN;
    assert_eq!(leaf(&controls, USER, never), (true, false, false));
    assert_eq!(leaf(&controls, KERNEL, never), (true, false, false));
    // WXN: writable means execute-never at that level.
    controls.sctlr |= SCTLR_WXN;
    assert_eq!(leaf(&controls, KERNEL, ATTRS), (true, true, false));
    assert_eq!(leaf(&controls, USER, ATTRS | AP_EL0), (true, true, false));
    assert_eq!(leaf(&controls, USER, ATTRS | 3 << 6), (true, false, true));
    // Through a walk, PAN faults an EL1 read of an EL0 page.
    let mut tables = Tables::default();
    let va = 0x1_0000_4000;
    map(&mut tables, &controls, va, 0x8_0000_0000, ATTRS | AP_EL0);
    assert_eq!(
        faults(translate(&controls, va, Access::Read, pan, &mut tables)),
        Some((FaultKind::Permission, 3))
    );
}

#[test]
fn epan_extends_pan_to_locations_el0_may_execute() {
    let mut controls = controls();
    let pan = Requester {
        pan: true,
        ..KERNEL
    };
    let leaf = |controls: &Controls, hierarchy: &Hierarchy, descriptor| {
        super::rights(controls, pan, hierarchy, descriptor)
    };
    let execute_only = ATTRS; // AP[2:1] 00, EL0 execute-only.
    let read_only_execute_only = ATTRS | AP_READ_ONLY;
    let none = Hierarchy::default();
    assert_eq!(leaf(&controls, &none, execute_only), (true, true, true));
    controls.sctlr |= SCTLR_EPAN;
    assert_eq!(leaf(&controls, &none, execute_only), (false, false, true));
    assert_eq!(
        leaf(&controls, &none, read_only_execute_only),
        (false, false, true)
    );
    // UXN, in the leaf or a table, leaves the location to EL1.
    assert_eq!(
        leaf(&controls, &none, execute_only | UXN),
        (true, true, true)
    );
    let uxn_table = Hierarchy {
        uxn: true,
        ..Hierarchy::default()
    };
    assert_eq!(
        leaf(&controls, &uxn_table, execute_only),
        (true, true, true)
    );
    // WXN does not remove EL0 execution from EPAN's view.
    controls.sctlr |= SCTLR_WXN;
    let el0_writable = ATTRS | AP_EL0;
    assert_eq!(leaf(&controls, &none, el0_writable), (false, false, false));
    // Without PSTATE.PAN, EPAN has no effect.
    assert_eq!(
        super::rights(&controls, KERNEL, &none, execute_only),
        (true, true, false)
    );
}

#[test]
fn table_permissions_apply_unless_hierarchical_permissions_are_disabled() {
    let mut controls = controls();
    let mut tables = Tables::default();
    let va = 0x2_0000_0000_u64;
    map(&mut tables, &controls, va, 0x8_0000_0000, ATTRS | AP_EL0);
    let root = controls.ttbr0 & OUTPUT_ADDRESS;
    let slot = root + ((va >> 36) & 0x7ff) * 8;
    *tables.0.get_mut(&slot).unwrap() |=
        AP_TABLE_NO_EL0 | AP_TABLE_READ_ONLY | PXN_TABLE | UXN_TABLE;
    assert_eq!(
        rights(translate(&controls, va, Access::Read, KERNEL, &mut tables)),
        (true, false, false)
    );
    assert_eq!(
        faults(translate(&controls, va, Access::Read, USER, &mut tables)),
        Some((FaultKind::Permission, 3))
    );
    controls.tcr |= TCR_HPD0;
    assert_eq!(
        rights(translate(&controls, va, Access::Read, USER, &mut tables)),
        (true, true, true)
    );
}

#[test]
fn reports_translation_access_flag_and_address_size_faults() {
    let mut controls = controls();
    let mut tables = Tables::default();
    let va = 0x2_0000_0000_u64;
    assert_eq!(
        faults(translate(&controls, va, Access::Read, KERNEL, &mut tables)),
        Some((FaultKind::Translation, 1))
    );
    let leaf = map(&mut tables, &controls, va, 0x8_0000_0000, TABLE);
    // AF=0 always faults: TCR.HA is RES0 without FEAT_HAFDBS.
    controls.tcr |= 1 << 39;
    assert_eq!(
        faults(translate(&controls, va, Access::Read, KERNEL, &mut tables)),
        Some((FaultKind::AccessFlag, 3))
    );
    assert_eq!(
        Fault::stage1(FaultKind::AccessFlag, 3).status_code(),
        0b00_1011
    );
    // An output address above a 36-bit IPS is an Address size fault at
    // the leaf; one above 48 bits for any IPS.
    tables.0.insert(leaf, 0x10_0000_0000 | ATTRS);
    controls.tcr = (controls.tcr & !(7 << 32)) | 1 << 32;
    assert_eq!(
        faults(translate(&controls, va, Access::Read, KERNEL, &mut tables)),
        Some((FaultKind::AddressSize, 3))
    );
    controls.tcr |= 7 << 32;
    assert!(matches!(
        translate(&controls, va, Access::Read, KERNEL, &mut tables),
        Outcome::Mapped(_)
    ));
    // A table address beyond the output size faults at the table's level,
    // and so does a TTBR beyond it, at level 0.
    controls.tcr &= !(7 << 32);
    tables.0.insert(leaf, 0x8000_0000 | ATTRS);
    let root = controls.ttbr0 & OUTPUT_ADDRESS;
    let slot = root + ((va >> 36) & 0x7ff) * 8;
    let table = tables.0[&slot];
    tables.0.insert(slot, 0x1_0000_0000 | TABLE);
    assert_eq!(
        faults(translate(&controls, va, Access::Read, KERNEL, &mut tables)),
        Some((FaultKind::AddressSize, 1))
    );
    tables.0.insert(slot, table);
    assert!(matches!(
        translate(&controls, va, Access::Read, KERNEL, &mut tables),
        Outcome::Mapped(_)
    ));
    let ttbr0 = controls.ttbr0;
    controls.ttbr0 |= 1 << 40;
    assert_eq!(
        faults(translate(&controls, va, Access::Read, KERNEL, &mut tables)),
        Some((FaultKind::AddressSize, 0))
    );
    controls.ttbr0 = ttbr0;
    // Bits above the 47-bit region, EPD0, and E0PD0 for EL0 and
    // unprivileged accesses fault at level 0 without a walk.
    assert_eq!(
        faults(translate(
            &controls,
            1 << 47,
            Access::Read,
            KERNEL,
            &mut tables
        )),
        Some((FaultKind::Translation, 0))
    );
    controls.tcr |= TCR_E0PD0;
    assert!(matches!(
        translate(&controls, va, Access::Read, KERNEL, &mut tables),
        Outcome::Mapped(_)
    ));
    let unprivileged = Requester {
        unprivileged: true,
        ..KERNEL
    };
    for requester in [USER, unprivileged] {
        assert_eq!(
            faults(translate(
                &controls,
                va,
                Access::Read,
                requester,
                &mut tables
            )),
            Some((FaultKind::Translation, 0))
        );
    }
    controls.tcr = (controls.tcr & !TCR_E0PD0) | TCR_EPD0;
    assert_eq!(
        faults(translate(&controls, va, Access::Read, KERNEL, &mut tables)),
        Some((FaultKind::Translation, 0))
    );
    // A walk that leaves RAM is a synchronous external abort on the walk.
    controls.tcr &= !TCR_EPD0;
    tables.0.insert(slot, 0x2_0000_0000 | TABLE);
    controls.tcr |= 5 << 32;
    assert_eq!(
        faults(translate(&controls, va, Access::Read, KERNEL, &mut tables)),
        Some((FaultKind::ExternalOnWalk, 2))
    );
}

#[test]
fn four_kib_walks_take_blocks_at_levels_one_and_two_only() {
    // 4 KiB, T0SZ 25 (39 bits): levels 1..3.
    let controls = Controls {
        tcr: 25 | 5 << 32,
        ..controls()
    };
    let mut tables = Tables::default();
    let root = 0x10_0000;
    let level2 = 0x11_0000;
    let level3 = 0x12_0000;
    // 0x0000_0000 → 1 GiB block at 0x8_4000_0000.
    tables
        .0
        .insert(root, 0x8_4000_0000 | ATTRS & !DESCRIPTOR_TABLE);
    // 0x4000_0000 → table → 2 MiB block at 0x8_0020_0000 and a table.
    tables.0.insert(root + 8, level2 | TABLE);
    tables
        .0
        .insert(level2, 0x8_0020_0000 | ATTRS & !DESCRIPTOR_TABLE);
    tables.0.insert(level2 + 8, level3 | TABLE);
    tables.0.insert(level3 + 8, 0x8_0000_1000 | ATTRS);
    // Type 0b01 at level 3 is reserved.
    tables
        .0
        .insert(level3 + 16, 0x8_0000_2000 | ATTRS & !DESCRIPTOR_TABLE);
    let mapped = |address: u64, tables: &mut Tables| match translate(
        &controls,
        address,
        Access::Read,
        KERNEL,
        tables,
    ) {
        Outcome::Mapped(translation) => Some((translation.physical, translation.size)),
        _ => None,
    };
    assert_eq!(
        mapped(0x1234_5678, &mut tables),
        Some((0x8_5234_5678, 1 << 30))
    );
    assert_eq!(
        mapped(0x4012_3456, &mut tables),
        Some((0x8_0032_3456, 1 << 21))
    );
    assert_eq!(
        mapped(0x4020_1abc, &mut tables),
        Some((0x8_0000_1abc, 1 << 12))
    );
    assert_eq!(
        faults(translate(
            &controls,
            0x4020_2000,
            Access::Read,
            KERNEL,
            &mut tables
        )),
        Some((FaultKind::Translation, 3))
    );
    // A 48-bit region starts at level 0, where a block is a Translation fault.
    let wide = Controls {
        tcr: 16 | 5 << 32,
        ..controls
    };
    let mut tables = Tables::default();
    tables
        .0
        .insert(root, 0x8_0000_0000 | ATTRS & !DESCRIPTOR_TABLE);
    assert_eq!(
        faults(translate(&wide, 0x1000, Access::Read, KERNEL, &mut tables)),
        Some((FaultKind::Translation, 0))
    );
}

#[test]
fn sixteen_kib_walks_take_32_mib_blocks_at_level_two_only() {
    let controls = controls();
    let mut tables = Tables::default();
    let root = controls.ttbr0 & OUTPUT_ADDRESS;
    let va = 0x2_0000_0000_u64 + (3 << 25) + 0x1234;
    let level2 = 0x100_0000;
    tables
        .0
        .insert(root + ((va >> 36) & 0x7ff) * 8, level2 | TABLE);
    tables.0.insert(
        level2 + ((va >> 25) & 0x7ff) * 8,
        0x8_0200_0000 | ATTRS & !DESCRIPTOR_TABLE,
    );
    let Outcome::Mapped(block) = translate(&controls, va, Access::Read, KERNEL, &mut tables) else {
        panic!("block")
    };
    assert_eq!((block.physical, block.size), (0x8_0200_1234, 1 << 25));
    tables.0.insert(
        root + ((va >> 36) & 0x7ff) * 8,
        0x80_0000_0000 | ATTRS & !DESCRIPTOR_TABLE,
    );
    assert_eq!(
        faults(translate(&controls, va, Access::Read, KERNEL, &mut tables)),
        Some((FaultKind::Translation, 1))
    );
}

#[test]
fn region_sizes_are_forced_and_unimplemented_granules_refuse() {
    let mut controls = controls();
    let mut tables = Tables::default();
    let va = 0x1_0000_4000_u64;
    map(&mut tables, &controls, va, 0x8_0000_0000, ATTRS);
    // T0SZ 63 is forced to 39, so a 47-bit address is out of range.
    controls.tcr = (controls.tcr & !TNSZ_MASK) | 63;
    assert_eq!(
        faults(translate(&controls, va, Access::Read, KERNEL, &mut tables)),
        Some((FaultKind::Translation, 0))
    );
    controls.tcr = (controls.tcr & !TNSZ_MASK) | 17;
    controls.tcr = (controls.tcr & !(3 << 14)) | 1 << 14;
    assert_eq!(
        translate(&controls, va, Access::Read, KERNEL, &mut tables),
        Outcome::Unsupported(Unsupported::Granule { bits: 16 })
    );
    controls.tcr |= 3 << 14;
    assert_eq!(
        translate(&controls, va, Access::Read, KERNEL, &mut tables),
        Outcome::Unsupported(Unsupported::Granule { bits: 0 })
    );
    // A range disabled by EPD faults whatever its granule field holds.
    controls.tcr = (controls.tcr & !(3 << 30)) | TCR_EPD1;
    assert_eq!(
        faults(translate(
            &controls,
            0xffff_ffff_0000_0000,
            Access::Read,
            KERNEL,
            &mut tables
        )),
        Some((FaultKind::Translation, 0))
    );
}

#[test]
fn stage_one_disabled_is_flat_with_default_attributes() {
    let mut controls = Controls {
        sctlr: 0,
        ..controls()
    };
    let mut tables = Tables::default();
    let Outcome::Mapped(data) =
        translate(&controls, 0x8_0000_0010, Access::Write, KERNEL, &mut tables)
    else {
        panic!("flat")
    };
    assert_eq!(
        (
            data.physical,
            data.memory,
            data.attributes,
            data.shareability
        ),
        (0x8_0000_0010, MemoryType::Device, 0x00, 0b10)
    );
    assert!(matches!(
        translate(
            &controls,
            0x8_0000_0010,
            Access::Execute,
            KERNEL,
            &mut tables
        ),
        Outcome::Mapped(Translation {
            memory: MemoryType::Normal,
            attributes: 0x44,
            ..
        })
    ));
    // Above 48 bits is an Address size fault, unless TBI ignores the top byte.
    assert_eq!(
        faults(translate(
            &controls,
            1 << 48,
            Access::Read,
            KERNEL,
            &mut tables
        )),
        Some((FaultKind::AddressSize, 0))
    );
    assert!(matches!(
        translate(
            &controls,
            0x5a << 56 | 0x1000,
            Access::Read,
            KERNEL,
            &mut tables
        ),
        Outcome::Mapped(Translation {
            physical: 0x1000,
            ..
        })
    ));
    controls.tcr &= !TCR_TBI0;
    assert_eq!(
        faults(translate(
            &controls,
            0x5a << 56 | 0x1000,
            Access::Read,
            KERNEL,
            &mut tables
        )),
        Some((FaultKind::AddressSize, 0))
    );
}

#[test]
fn the_el2_regime_has_one_range_one_privilege_level_and_no_asids() {
    // Non-VHE TCR_EL2: T0SZ 17, TG0 16 KiB, PS 48 bits.
    let controls = Controls {
        regime: Regime::El2,
        tcr: 17 | 2 << 14 | 5 << 16,
        ttbr1: 0,
        ..controls()
    };
    let mut tables = Tables::default();
    let va = 0x1_0000_4000_u64;
    // AP[1] clear and PXN set do not matter; NOT_GLOBAL is ignored.
    map(
        &mut tables,
        &controls,
        va,
        0x8_0000_0000,
        ATTRS | PXN | NOT_GLOBAL,
    );
    let el2 = Requester { el: 2, ..KERNEL };
    let Outcome::Mapped(translation) = translate(&controls, va, Access::Execute, el2, &mut tables)
    else {
        panic!("EL2 text")
    };
    assert!(translation.global && translation.asid == 0 && translation.writable);
    map(
        &mut tables,
        &controls,
        va + PAGE,
        0x8_0000_4000,
        ATTRS | UXN | AP_READ_ONLY,
    );
    assert_eq!(
        rights(translate(
            &controls,
            va + PAGE,
            Access::Read,
            el2,
            &mut tables
        )),
        (true, false, false)
    );
    // There is no upper range.
    assert_eq!(
        faults(translate(
            &controls,
            0xffff_8000_0000_0000,
            Access::Read,
            el2,
            &mut tables
        )),
        Some((FaultKind::Translation, 0))
    );
}

#[test]
fn the_el2_and_0_regime_walks_like_el1_and_0_with_asids() {
    let controls = Controls {
        regime: Regime::El20,
        ..controls()
    };
    let mut tables = Tables::default();
    let va = 0x1_0000_4000_u64;
    map(
        &mut tables,
        &controls,
        va,
        0x8_0000_0000,
        ATTRS | AP_EL0 | NOT_GLOBAL,
    );
    let el2 = Requester { el: 2, ..KERNEL };
    let Outcome::Mapped(translation) = translate(&controls, va, Access::Read, el2, &mut tables)
    else {
        panic!("EL2&0 data")
    };
    assert_eq!(
        (translation.global, translation.asid, translation.executable),
        (false, 5, false)
    );
    assert!(rights(translate(&controls, va, Access::Read, USER, &mut tables)).2);
}

#[test]
fn sprr_indexes_ap_and_execute_never_bits_into_el_and_gl_permissions() {
    let mut controls = controls();
    let mut tables = Tables::default();
    // SPTM's SPRR_PERM_EL1 value. Nibbles: index 0 is 5 (EL r-x, GL
    // r-x), index 3 (UXN, PXN) is 0xb (EL rw-, GL r--) and index 5
    // (AP[0], PXN) is 2 (EL r--, GL ---).
    controls.sprr = Sprr {
        config: SPRR_CONFIG_EN,
        el1: 0x2020_a52a_302a_baf5,
        el0: 0,
        fields: [0; 2],
    };
    let va = 0x4_0000_0000_u64;
    map(&mut tables, &controls, va, 0x8_0000_0000, ATTRS);
    let guarded = Requester {
        guarded: true,
        ..KERNEL
    };
    for requester in [KERNEL, guarded] {
        assert_eq!(
            rights(translate(
                &controls,
                va,
                Access::Execute,
                requester,
                &mut tables
            )),
            (true, false, true)
        );
    }
    let data = 0x5_0000_0000_u64;
    map(
        &mut tables,
        &controls,
        data,
        0x8_0000_4000,
        ATTRS | UXN | PXN,
    );
    assert_eq!(
        rights(translate(
            &controls,
            data,
            Access::Write,
            KERNEL,
            &mut tables
        )),
        (true, true, false)
    );
    assert_eq!(
        faults(translate(
            &controls,
            data,
            Access::Write,
            guarded,
            &mut tables
        )),
        Some((FaultKind::Permission, 3))
    );
    let el_only = 0x7_0000_0000_u64;
    map(
        &mut tables,
        &controls,
        el_only,
        0x8_0000_c000,
        ATTRS | AP_EL0 | PXN,
    );
    assert!(matches!(
        translate(&controls, el_only, Access::Read, KERNEL, &mut tables),
        Outcome::Mapped(_)
    ));
    assert!(
        faults(translate(
            &controls,
            el_only,
            Access::Read,
            guarded,
            &mut tables
        ))
        .is_some()
    );
    // The special combinations: GL r-x with EL rw- is EL ---, GL r-- with
    // EL r-x is EL --x.
    controls.sprr.el1 = 0x7 | 0x9 << 4;
    assert!(faults(translate(&controls, va, Access::Read, KERNEL, &mut tables)).is_some());
    map(
        &mut tables,
        &controls,
        0x4_0000_4000,
        0x8_0001_0000,
        ATTRS | PXN,
    );
    assert_eq!(
        rights(translate(
            &controls,
            0x4_0000_4000,
            Access::Execute,
            KERNEL,
            &mut tables
        )),
        (false, false, true)
    );
    let pan = Requester {
        pan: true,
        ..KERNEL
    };
    // PAN under SPRR follows SPRR_PERM_EL0: this page has AP[1] set but
    // no EL0 access, so the kernel keeps its rights.
    assert_eq!(
        translate(&controls, va, Access::Read, pan, &mut tables),
        translate(&controls, va, Access::Read, KERNEL, &mut tables)
    );
}

#[test]
fn sprr_table_execute_never_and_per_index_fields() {
    let mut controls = controls();
    let mut tables = Tables::default();
    controls.sprr = Sprr {
        config: SPRR_CONFIG_EN,
        el1: 0x2020_a52a_302a_baf5,
        el0: 0,
        fields: [0; 2],
    };
    // Index 0: EL r-x.
    let va = 0x4_0000_0000_u64;
    map(&mut tables, &controls, va, 0x8_0000_0000, ATTRS);
    let root = controls.ttbr0 & OUTPUT_ADDRESS;
    let slot = root + ((va >> 36) & 0x7ff) * 8;
    *tables.0.get_mut(&slot).unwrap() |= PXN_TABLE;
    // PXNTable removes execution and leaves the index's read right.
    assert_eq!(
        rights(translate(&controls, va, Access::Read, KERNEL, &mut tables)),
        (true, false, false)
    );
    assert_eq!(
        faults(translate(
            &controls,
            va,
            Access::Execute,
            KERNEL,
            &mut tables
        )),
        Some((FaultKind::Permission, 3))
    );
    // S3_6_C15_C3_x fields concern SPRR_PERM writes, not accesses.
    controls.sprr.fields = [0b01, 0b01 << (2 * 9)];
    assert!(matches!(
        translate(&controls, va, Access::Read, KERNEL, &mut tables),
        Outcome::Mapped(_)
    ));
    // APTable keeps stopping.
    controls.sprr.fields = [0; 2];
    *tables.0.get_mut(&slot).unwrap() |= AP_TABLE_READ_ONLY;
    assert_eq!(
        translate(&controls, va, Access::Read, KERNEL, &mut tables),
        Outcome::Unsupported(Unsupported::Sprr("APTable with SPRR"))
    );
}
