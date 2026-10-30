use super::*;
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

const TABLE: u64 = DESCRIPTOR_VALID | DESCRIPTOR_TABLE;
/// A readable, writable, executable Normal Write-Back Inner Shareable page.
const PAGE: u64 = TABLE | ACCESS_FLAG | S2AP_READ | S2AP_WRITE | 0b1111 << 2 | 0b11 << 8;
const KERNEL_DATA: Input = Input {
    attributes: 0xff,
    shareability: 0b11,
};

/// 4 KiB, 40-bit IPA starting at level 1 with two concatenated tables
/// (SL0 1), 48-bit PS.
const VTCR_4K: u64 = 24 | 1 << 6 | 5 << 16 | 1 << 31;
/// 16 KiB, 36-bit IPA starting at level 2 (SL0 1), 40-bit PS.
const VTCR_16K: u64 = 28 | 1 << 6 | 2 << 14 | 2 << 16 | 1 << 31;

fn stage2(vtcr: u64) -> Stage2 {
    Stage2 {
        hcr: 1,
        vtcr,
        vttbr: 0x10_0000 | 7 << 48,
        xs: super::super::test_xs(),
    }
}

fn data(stage2: &Stage2, ipa: u64, access: Access, tables: &mut Tables) -> Result<Output, Stop> {
    translate(
        stage2,
        ipa,
        Purpose::Access(access),
        false,
        Some(KERNEL_DATA),
        None,
        tables,
    )
}

fn fault(result: Result<Output, Stop>) -> Option<(FaultKind, i8, bool)> {
    match result {
        Err(Stop::Fault(fault)) => {
            let second_stage = fault.second_stage.expect("stage-2 fault");
            Some((fault.kind, fault.level, second_stage.walk))
        }
        _ => None,
    }
}

/// Map `ipa` through a 4 KiB level-1 (concatenated), 2 and 3 walk.
fn map_4k(tables: &mut Tables, ipa: u64, leaf: u64) {
    let level1 = 0x10_0000 + ((ipa >> 30) & 0x3ff) * 8;
    let level2 = 0x20_0000 + ((ipa >> 21) & 0x1ff) * 8;
    let level3 = 0x30_0000 + ((ipa >> 12) & 0x1ff) * 8;
    tables.0.insert(level1, 0x20_0000 | TABLE);
    tables.0.insert(level2, 0x30_0000 | TABLE);
    tables.0.insert(level3, leaf);
}

#[test]
fn walks_4k_concatenated_and_16k_tables_with_blocks() {
    let mut tables = Tables::default();
    let s2 = stage2(VTCR_4K);
    // IPA bit 39 selects the second concatenated level-1 table.
    let ipa = 0x80_4000_5123;
    map_4k(&mut tables, ipa, 0x8_0000_1000 | PAGE);
    let output = data(&s2, ipa, Access::Write, &mut tables).unwrap();
    assert_eq!(output.physical, 0x8_0000_1123);
    assert_eq!(
        (output.attributes, output.shareability, output.size),
        (0xff, 0b11, 1 << 12)
    );
    // A 2 MiB block at level 2 and a 1 GiB block at level 1.
    let block = (PAGE & !DESCRIPTOR_TABLE) | 0x8_0020_0000;
    tables
        .0
        .insert(0x20_0000 + ((ipa >> 21) & 0x1ff) * 8, block);
    let output = data(&s2, ipa, Access::Read, &mut tables).unwrap();
    assert_eq!((output.physical, output.size), (0x8_0020_5123, 1 << 21));
    tables.0.insert(
        0x10_0000 + ((ipa >> 30) & 0x3ff) * 8,
        (PAGE & !DESCRIPTOR_TABLE) | 0x8_4000_0000,
    );
    let output = data(&s2, ipa, Access::Read, &mut tables).unwrap();
    assert_eq!((output.physical, output.size), (0x8_4000_5123, 1 << 30));

    // 16 KiB: levels 2 and 3, 32 MiB blocks at level 2 only.
    let s2 = stage2(VTCR_16K);
    let mut tables = Tables::default();
    let ipa = 0xf_ffff_c010;
    tables
        .0
        .insert(0x10_0000 + ((ipa >> 25) & 0x7ff) * 8, 0x40_0000 | TABLE);
    tables
        .0
        .insert(0x40_0000 + ((ipa >> 14) & 0x7ff) * 8, 0x80_0000_8000 | PAGE);
    let output = data(&s2, ipa, Access::Read, &mut tables).unwrap();
    assert_eq!((output.physical, output.size), (0x80_0000_8010, 1 << 14));
    tables.0.insert(
        0x10_0000 + ((ipa >> 25) & 0x7ff) * 8,
        (PAGE & !DESCRIPTOR_TABLE) | 0x80_0200_0000,
    );
    let output = data(&s2, ipa, Access::Read, &mut tables).unwrap();
    assert_eq!((output.physical, output.size), (0x80_03ff_c010, 1 << 25));
    // A 16 KiB level-3 block encoding is a Translation fault.
    tables
        .0
        .insert(0x10_0000 + ((ipa >> 25) & 0x7ff) * 8, 0x40_0000 | TABLE);
    tables.0.insert(
        0x40_0000 + ((ipa >> 14) & 0x7ff) * 8,
        (PAGE & !DESCRIPTOR_TABLE) | 0x80_0000_8000,
    );
    assert_eq!(
        fault(data(&s2, ipa, Access::Read, &mut tables)),
        Some((FaultKind::Translation, 3, false))
    );
}

#[test]
fn start_level_input_size_and_output_size_faults_are_reported() {
    let mut tables = Tables::default();
    let ipa = 0x1000;
    map_4k(&mut tables, ipa, 0x10_0000_1000 | PAGE);
    let translation = |vtcr: u64, ipa: u64, tables: &mut Tables| {
        fault(data(&stage2(vtcr), ipa, Access::Read, tables))
    };
    // SL0 0b11 (no FEAT_TTST) and 16 KiB SL0 0b11 (no FEAT_LPA2).
    assert_eq!(
        translation(VTCR_4K | 3 << 6, ipa, &mut tables),
        Some((FaultKind::Translation, 0, false))
    );
    assert_eq!(
        translation(VTCR_16K | 3 << 6, ipa, &mut tables),
        Some((FaultKind::Translation, 0, false))
    );
    // A 40-bit IPA starting at level 2 would need 512 concatenated tables.
    let inconsistent = VTCR_4K & !(3 << 6);
    assert_eq!(
        translation(inconsistent, ipa, &mut tables),
        Some((FaultKind::Translation, 0, false))
    );
    // An IPA beyond the 40-bit input size.
    assert_eq!(
        translation(VTCR_4K, 1 << 40, &mut tables),
        Some((FaultKind::Translation, 0, false))
    );
    // An output above a 36-bit PS faults at the leaf; a table above it
    // at the level that pointed to it; VTTBR above it at level 0.
    let small = (VTCR_4K & !(7 << 16)) | 1 << 16;
    assert_eq!(
        translation(small, ipa, &mut tables),
        Some((FaultKind::AddressSize, 3, false))
    );
    let mut far = Tables::default();
    far.0.insert(0x10_0000, 0x10_0000_0000 | TABLE);
    assert_eq!(
        translation(small, ipa, &mut far),
        Some((FaultKind::AddressSize, 1, false))
    );
    let high = Stage2 {
        vttbr: 0x10_0000_0000,
        ..stage2(small)
    };
    assert_eq!(
        fault(data(&high, ipa, Access::Read, &mut tables)),
        Some((FaultKind::AddressSize, 0, false))
    );
    // Invalid descriptors, AF clear and walks outside memory.
    map_4k(&mut tables, ipa, 0x8_0000_1000 | (PAGE & !ACCESS_FLAG));
    assert_eq!(
        translation(VTCR_4K, ipa, &mut tables),
        Some((FaultKind::AccessFlag, 3, false))
    );
    assert_eq!(
        translation(VTCR_4K, 0x4000_0000, &mut tables),
        Some((FaultKind::Translation, 1, false))
    );
    let outside = Stage2 {
        vttbr: 0x2_0000_0000,
        ..stage2(VTCR_4K)
    };
    assert_eq!(
        fault(data(&outside, ipa, Access::Read, &mut tables)),
        Some((FaultKind::ExternalOnWalk, 1, false))
    );
    // T0SZ below 16 is forced, not faulted; 64 KiB and reserved TG0 refuse.
    assert_eq!(
        data(&stage2(VTCR_16K | 3 << 14), ipa, Access::Read, &mut tables),
        Err(Stop::Unsupported(Unsupported::Granule { bits: 0 }))
    );
    assert_eq!(
        data(
            &stage2((VTCR_4K & !(3 << 14)) | 1 << 14),
            ipa,
            Access::Read,
            &mut tables
        ),
        Err(Stop::Unsupported(Unsupported::Granule { bits: 16 }))
    );
}

#[test]
fn s2ap_and_xnx_give_read_write_and_per_el_execute() {
    let mut tables = Tables::default();
    let s2 = stage2(VTCR_4K);
    let ipa = 0x7000;
    let rights = |leaf: u64, el0: bool, tables: &mut Tables| {
        map_4k(tables, ipa, 0x8_0000_0000 | leaf);
        [Access::Read, Access::Write, Access::Execute].map(|access| {
            translate(
                &s2,
                ipa,
                Purpose::Access(access),
                el0,
                Some(KERNEL_DATA),
                None,
                tables,
            )
            .is_ok()
        })
    };
    let base = PAGE & !(S2AP_READ | S2AP_WRITE);
    assert_eq!(rights(base, false, &mut tables), [false, false, true]);
    assert_eq!(
        rights(base | S2AP_READ, false, &mut tables),
        [true, false, true]
    );
    assert_eq!(
        rights(base | S2AP_WRITE, false, &mut tables),
        [false, true, true]
    );
    // XN[1:0]: 01 executes at EL0 only, 10 nowhere, 11 at EL1 only.
    assert_eq!(rights(PAGE | XNX, false, &mut tables), [true, true, false]);
    assert_eq!(rights(PAGE | XNX, true, &mut tables), [true, true, true]);
    assert_eq!(rights(PAGE | XN, true, &mut tables), [true, true, false]);
    assert_eq!(
        rights(PAGE | XN | XNX, false, &mut tables),
        [true, true, true]
    );
    assert_eq!(
        rights(PAGE | XN | XNX, true, &mut tables),
        [true, true, false]
    );
    map_4k(&mut tables, ipa, 0x8_0000_0000 | (PAGE & !S2AP_WRITE));
    assert_eq!(
        fault(data(&s2, ipa, Access::Write, &mut tables)),
        Some((FaultKind::Permission, 3, false))
    );
    // A walk needs read permission, and with HCR_EL2.PTW Normal memory.
    map_4k(&mut tables, ipa, 0x8_0000_0000 | (PAGE & !S2AP_READ));
    let walk = |s2: &Stage2, tables: &mut Tables| {
        fault(translate(s2, ipa, Purpose::Walk, false, None, None, tables))
    };
    assert_eq!(
        walk(&s2, &mut tables),
        Some((FaultKind::Permission, 3, true))
    );
    let device = (PAGE & !(0xf << 2)) | 0b0001 << 2;
    map_4k(&mut tables, ipa, 0x8_0000_0000 | device);
    assert_eq!(walk(&s2, &mut tables), None);
    let ptw = Stage2 {
        hcr: s2.hcr | HCR_PTW,
        ..s2
    };
    assert_eq!(
        walk(&ptw, &mut tables),
        Some((FaultKind::Permission, 3, true))
    );
}

#[test]
fn attributes_combine_with_stage_one_or_are_forced() {
    let mut tables = Tables::default();
    let s2 = stage2(VTCR_4K);
    let ipa = 0x9000;
    let leaf = |field: u64, shareability: u64| {
        PAGE & !(0xf << 2 | 3 << 8) | field << 2 | shareability << 8
    };
    let mut attributes = |s2: &Stage2, input: Input, leaf: u64, execute: bool| {
        map_4k(&mut tables, ipa, 0x8_0000_0000 | leaf);
        let access = if execute {
            Access::Execute
        } else {
            Access::Read
        };
        let output = translate(
            s2,
            ipa,
            Purpose::Access(access),
            false,
            Some(input),
            None,
            &mut tables,
        );
        output.map(|output| (output.attributes, output.shareability))
    };
    let non_shareable = Input {
        attributes: 0xff,
        shareability: 0,
    };
    // Stage 2 Normal WT Inner Shareable: WT with stage 1's hints, ISH.
    assert_eq!(
        attributes(&s2, non_shareable, leaf(0b1010, 0b11), false),
        Ok((0xbb, 0b11))
    );
    // Stage 2 Device-nGnRE: Device, Outer Shareable, with stage 1's
    // Write-Back XS of 0 under FEAT_XS.
    let device = if super::super::test_xs() { 0x05 } else { 0x04 };
    assert_eq!(
        attributes(&s2, non_shareable, leaf(0b0001, 0), false),
        Ok((device, 0b10))
    );
    // Reserved MemAttr refuses.
    assert_eq!(
        attributes(&s2, non_shareable, leaf(0b1000, 0), false),
        Err(Stop::Unsupported(Unsupported::Stage2Attributes {
            field: 0b1000
        }))
    );
    // HCR_EL2.CD makes Normal data Non-cacheable; HCR_EL2.ID and Device
    // memory make instruction fetch Non-cacheable, keeping stage 1's
    // Write-Back XS of 0 under FEAT_XS.
    let nc = if super::super::test_xs() { 0x40 } else { 0x44 };
    let cd = Stage2 {
        hcr: s2.hcr | HCR_CD,
        ..s2
    };
    assert_eq!(
        attributes(&cd, non_shareable, leaf(0b1111, 0b11), false),
        Ok((nc, 0b10))
    );
    assert_eq!(
        attributes(&s2, non_shareable, leaf(0b0000, 0), true),
        Ok((nc, 0b10))
    );
    let id = Stage2 {
        hcr: s2.hcr | HCR_ID,
        ..s2
    };
    assert_eq!(
        attributes(&id, non_shareable, leaf(0b1111, 0b11), true),
        Ok((nc, 0b10))
    );
    // FWB: 0b110 forces Write-Back over stage-1 Device, and the SH
    // fields still combine.
    let fwb = Stage2 {
        hcr: s2.hcr | HCR_FWB,
        ..s2
    };
    let device_ngre = if super::super::test_xs() { 0x09 } else { 0x08 };
    let device = Input {
        attributes: 0x00,
        shareability: 0,
    };
    assert_eq!(
        attributes(&fwb, device, leaf(0b0110, 0b11), false),
        Ok((0xff, 0b11))
    );
    assert_eq!(
        attributes(&fwb, non_shareable, leaf(0b0111, 0), false),
        Ok((0xff, 0))
    );
    assert_eq!(
        attributes(&fwb, non_shareable, leaf(0b0010, 0), false),
        Ok((device_ngre, 0b10))
    );
    // FEAT_XS: stage-1 Device-nGnRE with XS 1 stays XS 1 unless the
    // descriptor's FnXS clears it, with and without FWB; without
    // FEAT_XS bit 11 is ignored.
    let xs = Stage2 { xs: true, ..s2 };
    let fwb_xs = Stage2 { xs: true, ..fwb };
    let device = Input {
        attributes: 0x04,
        shareability: 0,
    };
    for s2 in [&xs, &fwb_xs] {
        assert_eq!(
            attributes(s2, device, leaf(0b0111, 0), false).map(|(a, _)| a),
            Ok(0x04)
        );
        assert_eq!(
            attributes(s2, device, leaf(0b0111, 0) | FNXS, false).map(|(a, _)| a),
            Ok(0x05)
        );
    }
    let no_xs = Stage2 { xs: false, ..s2 };
    assert_eq!(
        attributes(&no_xs, device, leaf(0b0111, 0) | FNXS, false).map(|(a, _)| a),
        Ok(0x04)
    );
}
