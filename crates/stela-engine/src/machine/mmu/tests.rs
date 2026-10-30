use super::*;

#[test]
fn par_reports_the_output_attributes_or_the_fault() {
    // PAR_EL1.PA holds the chip's 48-bit physical address.
    test_translation_chip();
    let translation = Translation {
        physical: 0x8_1234_5678,
        memory: MemoryType::Normal,
        attributes: 0xff,
        shareability: 0b11,
        readable: true,
        writable: true,
        executable: false,
        guarded: false,
        global: true,
        asid: 0,
        size: 1 << 14,
        alignment: Alignment::default(),
    };
    assert_eq!(
        par(&Outcome::Mapped(translation)),
        Some(0xff00_0008_1234_5000 | 1 << 11 | 1 << 9 | 0b11 << 7)
    );
    let device = Translation {
        attributes: 0x04,
        shareability: 0b10,
        memory: MemoryType::Device,
        ..translation
    };
    assert_eq!(
        par(&Outcome::Mapped(device)),
        Some(0x0400_0008_1234_5000 | 1 << 11 | 1 << 9 | 0b10 << 7)
    );
    let fault = Fault::stage1(FaultKind::Permission, 3);
    assert_eq!(
        par(&Outcome::Fault(fault)),
        Some(1 << 11 | 0b00_1111 << 1 | 1)
    );
    let second_stage = |walk| Fault {
        kind: FaultKind::Translation,
        level: 2,
        second_stage: Some(SecondStage {
            ipa: 0x8000_4000,
            walk,
        }),
    };
    assert_eq!(
        par(&Outcome::Fault(second_stage(false))),
        Some(1 << 11 | 1 << 9 | 0b00_0110 << 1 | 1)
    );
    assert_eq!(
        par(&Outcome::Fault(second_stage(true))),
        Some(1 << 11 | 1 << 9 | 1 << 8 | 0b00_0110 << 1 | 1)
    );
    assert_eq!(par(&Outcome::Unsupported(Unsupported::Stage2)), None);
}

#[test]
fn ctrr_permission_faults_preserve_allowed_reads_at_and_physical_boundaries() {
    let protected = (0x8000_4000, 0x8000_4fff);
    let mut controls = Controls {
        ctrr: Ctrr {
            privileged: [
                Some(CtrrRegion {
                    first: protected.0,
                    last: protected.1,
                    write_protect: true,
                    execute_inside_only: true,
                }),
                None,
            ],
            memory: [None; 4],
        },
        ..Controls::default()
    };
    let mut tables = Tables::default();
    let permission = Outcome::Fault(Fault::stage1(FaultKind::Permission, 3));
    assert_eq!(
        translate(&controls, protected.0, Access::Write, KERNEL, &mut tables),
        permission
    );
    assert_eq!(
        translate(
            &controls,
            protected.1 + 1,
            Access::Execute,
            KERNEL,
            &mut tables
        ),
        permission
    );
    let Outcome::Mapped(read) =
        translate(&controls, protected.0, Access::Read, KERNEL, &mut tables)
    else {
        panic!("CTRR must permit reads");
    };
    assert!(!read.writable && read.executable);
    for (address, access) in [
        (protected.0 - 1, Access::Write),
        (protected.1 + 1, Access::Write),
        (protected.0, Access::Execute),
    ] {
        assert!(matches!(
            translate(&controls, address, access, KERNEL, &mut tables),
            Outcome::Mapped(_)
        ));
    }
    // AT reports the translation tables, not the subsequent physical
    // core protection. Core CTRR does not restrict an EL0 requester.
    assert!(matches!(
        translate_tables(&controls, protected.0, Access::Write, KERNEL, &mut tables),
        Outcome::Mapped(_)
    ));
    let user = Requester { el: 0, ..KERNEL };
    assert!(matches!(
        translate(&controls, protected.0, Access::Write, user, &mut tables),
        Outcome::Mapped(_)
    ));
    // Memory-controller locks bind writes from EL0 as well.
    controls.ctrr.privileged = [None; 2];
    controls.ctrr.memory[0] = Some(protected);
    assert_eq!(
        translate(&controls, protected.0, Access::Write, user, &mut tables),
        permission
    );
    assert!(matches!(
        translate(&controls, protected.0, Access::Read, user, &mut tables),
        Outcome::Mapped(_)
    ));
}

#[test]
fn ctrr_checks_the_final_pa_and_does_not_report_a_stage_two_walk_fault() {
    let (mut controls, mut tables) = two_stages(0x4000_0000);
    controls.ctrr.memory[0] = Some((0x8000_4000, 0x8000_4fff));
    let address = 0x4008;
    let Outcome::Fault(fault) = translate(&controls, address, Access::Write, KERNEL, &mut tables)
    else {
        panic!("the final physical CTRR region must deny the store");
    };
    assert_eq!((fault.kind, fault.level), (FaultKind::Permission, 3));
    assert_eq!(fault.data_syndrome(true, false), 0x4f);
    assert_eq!(fault.instruction_syndrome(), 0x0f);
    assert!(!fault.to_el2());
    assert_eq!(fault.hpfar(), None);
    assert!(matches!(
        translate_tables(&controls, address, Access::Write, KERNEL, &mut tables),
        Outcome::Mapped(Translation {
            physical: 0x8000_4008,
            ..
        })
    ));
}

#[derive(Default)]
struct Tables(alloc::collections::BTreeMap<u64, u64>);

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
/// Stage 2: 4 KiB, 40-bit IPA from two concatenated level-1 tables at
/// PA 0x10_0000, mapping IPA 1-2 GiB to PA 2-3 GiB as a Normal
/// Write-Back, Inner Shareable, read/write block.
const VTCR: u64 = 24 | 1 << 6 | 5 << 16 | 1 << 31;
const STAGE2_BLOCK: u64 = 0x8000_0000 | 1 | 1 << 10 | 0b11 << 6 | 0b1111 << 2 | 0b11 << 8;
/// Stage 1: 4 KiB, 39-bit VA from level 1 (EPD1), 48-bit IPS.
const TCR: u64 = 25 | 1 << 23 | 5 << 32;

/// Stage-1 table at IPA 0x4000_0000 (PA 0x8000_0000) whose first entry
/// maps VA 0-1 GiB as a block at `output`.
fn two_stages(output: u64) -> (Controls, Tables) {
    let mut tables = Tables::default();
    tables.0.insert(0x10_0008, STAGE2_BLOCK);
    tables
        .0
        .insert(0x8000_0000, output | 1 | 1 << 10 | 0b11 << 8);
    let controls = Controls {
        sctlr: SCTLR_M | alignment::SCTLR_C,
        tcr: TCR,
        ttbr0: 0x4000_0000,
        mair: 0xff,
        stage2: true,
        second_stage: Some(Stage2 {
            hcr: HCR_VM,
            vtcr: VTCR,
            vttbr: 0x10_0000,
            xs: test_xs(),
        }),
        xs: test_xs(),
        ..Controls::default()
    };
    (controls, tables)
}

#[test]
fn stage_one_tables_and_output_translate_through_stage_two() {
    let (controls, mut tables) = two_stages(0x4000_0000);
    let Outcome::Mapped(full) = translate(&controls, 0x1234, Access::Write, KERNEL, &mut tables)
    else {
        panic!("full translation")
    };
    assert_eq!(full.physical, 0x8000_1234);
    assert_eq!(
        (full.attributes, full.shareability, full.size),
        (0xff, 0b11, 1 << 30)
    );
    let Outcome::Mapped(first) =
        translate_stage1(&controls, 0x1234, Access::Read, KERNEL, &mut tables)
    else {
        panic!("stage 1 alone")
    };
    assert_eq!(first.physical, 0x4000_1234);

    // An output IPA stage 2 does not map: a stage-2 Translation fault on
    // the access, reported with its IPA.
    let (controls, mut tables) = two_stages(0xc000_0000);
    let Outcome::Fault(fault) = translate(&controls, 0x1234, Access::Read, KERNEL, &mut tables)
    else {
        panic!("stage-2 fault")
    };
    assert_eq!((fault.kind, fault.level), (FaultKind::Translation, 1));
    assert_eq!(
        fault.second_stage,
        Some(SecondStage {
            ipa: 0xc000_1234,
            walk: false
        })
    );
    assert_eq!(fault.hpfar(), Some(0x000c_0001 << 4));

    // A stage-1 table at an IPA stage 2 does not map: a stage-2 fault
    // on the walk, for AT S1E* as well.
    let (mut controls, mut tables) = two_stages(0x4000_0000);
    controls.ttbr0 = 0;
    let walk = Fault {
        kind: FaultKind::Translation,
        level: 1,
        second_stage: Some(SecondStage { ipa: 0, walk: true }),
    };
    assert_eq!(
        translate(&controls, 0x1234, Access::Read, KERNEL, &mut tables),
        Outcome::Fault(walk)
    );
    assert_eq!(
        translate_stage1(&controls, 0x1234, Access::Read, KERNEL, &mut tables),
        Outcome::Fault(walk)
    );
    assert_eq!(
        par(&Outcome::Fault(walk)),
        Some(1 << 11 | 1 << 9 | 1 << 8 | 0b00_0101 << 1 | 1)
    );
}

#[test]
fn stage_two_applies_under_vm_or_dc_without_tge_and_is_never_skipped() {
    let (mut controls, mut tables) = two_stages(0x4000_0000);
    // HCR_EL2.DC alone: stage 1 behaves as disabled with Normal
    // Write-Back Non-shareable output, and stage 2 applies.
    controls.second_stage = Some(Stage2 {
        hcr: HCR_DC,
        ..controls.second_stage.unwrap()
    });
    let Outcome::Mapped(default) =
        translate(&controls, 0x4000_1234, Access::Read, KERNEL, &mut tables)
    else {
        panic!("HCR_EL2.DC")
    };
    assert_eq!(default.physical, 0x8000_1234);
    assert_eq!((default.attributes, default.shareability), (0xff, 0b11));
    // HCR_EL2.DCT makes that default Tagged where the chip has
    // FEAT_MTE2 (AArch64.S1DisabledOutput), through stage 2's
    // Write-Back memory.
    controls.second_stage = Some(Stage2 {
        hcr: HCR_DC | HCR_DCT,
        ..controls.second_stage.unwrap()
    });
    for tagged in [false, true] {
        controls.tagged = tagged;
        let Outcome::Mapped(default) =
            translate(&controls, 0x4000_1234, Access::Read, KERNEL, &mut tables)
        else {
            panic!("HCR_EL2.DCT")
        };
        assert_eq!(
            default.attributes,
            if tagged { attributes::TAGGED } else { 0xff }
        );
    }
    // A descriptor selecting MAIR's 0xf0 is Tagged through stage 2's
    // Write-Back block; stage-2 Non-cacheable memory is Untagged.
    controls.mair = u64::from(attributes::TAGGED);
    for (block, expected) in [
        (STAGE2_BLOCK, attributes::TAGGED),
        (
            STAGE2_BLOCK & !(0b1111 << 2) | 0b0101 << 2,
            attributes::non_cacheable(attributes::TAGGED, test_xs()),
        ),
    ] {
        tables.0.insert(0x10_0008, block);
        controls.second_stage = Some(Stage2 {
            hcr: HCR_VM,
            ..controls.second_stage.unwrap()
        });
        let Outcome::Mapped(tagged) =
            translate(&controls, 0x1234, Access::Read, KERNEL, &mut tables)
        else {
            panic!("Tagged stage 1")
        };
        assert_eq!(tagged.attributes, expected);
    }
    tables.0.insert(0x10_0008, STAGE2_BLOCK);
    controls.mair = 0xff;
    controls.tagged = false;
    controls.second_stage = Some(Stage2 {
        hcr: HCR_DC,
        ..controls.second_stage.unwrap()
    });
    // TGE set: the EL1&0 regime has no stage 2, so TTBR0 is a PA.
    tables.0.insert(0x4000_0000, tables.0[&0x8000_0000]);
    controls.second_stage = Some(Stage2 {
        hcr: HCR_VM | HCR_TGE,
        ..controls.second_stage.unwrap()
    });
    let Outcome::Mapped(stage1) = translate(&controls, 0x1234, Access::Read, KERNEL, &mut tables)
    else {
        panic!("TGE")
    };
    assert_eq!(stage1.physical, 0x4000_1234);
    // Stage 2 required without its controls refuses.
    controls.second_stage = None;
    assert_eq!(
        translate(&controls, 0x1234, Access::Read, KERNEL, &mut tables),
        Outcome::Unsupported(Unsupported::Stage2)
    );
    assert_eq!(
        Stage2 {
            vttbr: 0xab << 48,
            ..Stage2::default()
        }
        .vmid(),
        0xab
    );
}

#[test]
fn alignment_is_checked_before_translation_and_ahead_of_permissions() {
    use alignment::{Kind, Shape};
    let plain = Shape {
        kind: Kind::Plain,
        bytes: 8,
        pair: false,
    };
    let atomic = Shape {
        kind: Kind::Atomic,
        ..plain
    };
    let alignment_fault = |outcome: Outcome| match outcome {
        Outcome::Fault(fault) => Some((fault.kind, fault.second_stage.is_some())),
        _ => None,
    };
    let (mut controls, mut tables) = two_stages(0x4000_0000);
    controls.stage2 = false;
    controls.second_stage = None;
    let checked = |controls: &Controls, address, shape, requester, tables: &mut Tables| {
        translate_checked(controls, address, Access::Read, requester, shape, tables)
    };
    // Stage 1 maps VA 0-1 GiB at PA 0x4000_0000 (no stage 2), Normal
    // Write-Back Inner Shareable, EL1 only.
    tables
        .0
        .insert(0x4000_0000, 0x4000_0000 | 1 | 1 << 10 | 0b11 << 8);
    controls.ttbr0 = 0x4000_0000;
    let user = Requester { el: 0, ..KERNEL };
    assert!(matches!(
        checked(&controls, 0x1004, plain, KERNEL, &mut tables),
        Outcome::Mapped(_)
    ));
    // SCTLR.A faults before the walk, even where nothing is mapped.
    controls.sctlr |= alignment::SCTLR_A;
    assert_eq!(
        alignment_fault(checked(
            &controls,
            0x7fff_ffff_0004,
            plain,
            KERNEL,
            &mut tables
        )),
        Some((FaultKind::Alignment, false))
    );
    controls.sctlr &= !(alignment::SCTLR_A | alignment::SCTLR_C);
    // An unaligned atomic inside 16 bytes needs no Write-Back memory or
    // SCTLR.C (Arm's choice for Unpredictable_LSE2_ALIGNMENT_FAULT).
    for sctlr in [controls.sctlr, controls.sctlr | alignment::SCTLR_C] {
        controls.sctlr = sctlr;
        assert!(matches!(
            checked(&controls, 0x1004, atomic, KERNEL, &mut tables),
            Outcome::Mapped(_)
        ));
    }
    // Device memory (AttrIndx 1, MAIR byte 0) faults an unaligned access
    // ahead of the Permission fault EL0 would take.
    controls.mair = 0x00ff;
    tables
        .0
        .insert(0x4000_0000, 0x4000_0000 | 1 | 1 << 10 | 1 << 2);
    assert_eq!(
        alignment_fault(checked(&controls, 0x1004, plain, user, &mut tables)),
        Some((FaultKind::Alignment, false))
    );
    assert_eq!(
        alignment_fault(checked(&controls, 0x1008, plain, user, &mut tables)),
        Some((FaultKind::Permission, false))
    );

    // Stage 2 Device memory under Normal stage 1: a stage-2 Alignment
    // fault, taken to EL2 without HPFAR_EL2.
    let (controls, mut tables) = two_stages(0x4000_0000);
    let device = (STAGE2_BLOCK & !(0xf << 2)) | 0b0001 << 2;
    tables.0.insert(0x10_0008, device);
    let Outcome::Fault(fault) = checked(&controls, 0x1004, plain, KERNEL, &mut tables) else {
        panic!("stage-2 alignment")
    };
    assert_eq!(fault.kind, FaultKind::Alignment);
    assert!(fault.to_el2() && fault.hpfar().is_none());
    assert_eq!(fault.data_syndrome(false, false), 0b10_0001);
    let Outcome::Mapped(aligned) = checked(&controls, 0x1008, plain, KERNEL, &mut tables) else {
        panic!("aligned Device access")
    };
    assert_eq!(aligned.alignment, Alignment { device: true });
}

#[test]
fn fault_syndromes_and_hpfar_follow_the_stage_and_the_walk() {
    // HPFAR_EL2.FIPA holds IPA[47:12] of the chip's 48-bit IPA space.
    test_translation_chip();
    let stage1 = Fault::stage1(FaultKind::Translation, 3);
    assert_eq!(stage1.data_syndrome(true, false), 0b100_0111);
    assert_eq!(stage1.data_syndrome(false, true), 1 << 8 | 1 << 6 | 0b111);
    assert!(!stage1.to_el2() && stage1.hpfar().is_none());
    let fault = |kind, walk| Fault {
        kind,
        level: 1,
        second_stage: Some(SecondStage {
            ipa: 0x8_1234_5678,
            walk,
        }),
    };
    let walk = fault(FaultKind::Permission, true);
    assert!(walk.to_el2());
    assert_eq!(walk.data_syndrome(false, false), 1 << 7 | 0b00_1101);
    assert_eq!(walk.instruction_syndrome(), 1 << 7 | 0b00_1101);
    assert_eq!(walk.hpfar(), Some(0x0081_2345 << 4));
    // A stage-2 Permission fault on the access itself leaves HPFAR_EL2
    // UNKNOWN (no FEAT_EAESR); Translation, Access flag and Address size
    // faults report it.
    assert_eq!(fault(FaultKind::Permission, false).hpfar(), None);
    assert_eq!(
        fault(FaultKind::AccessFlag, false).hpfar(),
        Some(0x0081_2345 << 4)
    );
    assert_eq!(fault(FaultKind::ExternalOnWalk, false).hpfar(), None);
}
