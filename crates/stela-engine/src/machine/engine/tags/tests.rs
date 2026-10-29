use super::super::{
    FaultCause, NativeExit, NativeFault,
    tests::{BASE, FakeHost, machine_on, normal_memory},
};
use super::*;
use stela_compiler::{TargetCpu, block::ExitKind};
use {
    crate::machine::NoDevices, crate::machine::exception::Pstate, crate::machine::identification,
    crate::machine::registers::encodings, crate::machine::system::Register as SystemRegister,
    stela_contracts::Chip,
};

type Test = Machine<FakeHost, NoDevices>;

const DATA: u64 = BASE + 0x1000;
const VBAR: u64 = BASE + 0x8000;
const SYNCHRONOUS: u64 = VBAR + 0x200;
const LOWER: u64 = VBAR + 0x400;
const HCR_ATA: u64 = 1 << 56;
const HCR_TID5: u64 = 1 << 58;
const SCTLR_ATA: u64 = 1 << 43;
const SCTLR_ATA0: u64 = 1 << 42;
const SCTLR_TCF_SYNC: u64 = 1 << 40;
const SCTLR_TCF0_SYNC: u64 = 1 << 38;
const TCR_TBI0: u64 = 1 << 37;
const TCR_TCMA0: u64 = 1 << 57;
const MTE_CHIPS: [Chip; 2] = [Chip::AppleM5, Chip::AppleM6];
/// Data Aborts at the current EL: a Tag Check fault, read and write,
/// and a write's Alignment fault.
const TAG_CHECK_READ: u64 = 0x9600_0011;
const TAG_CHECK_WRITE: u64 = 0x9600_0051;
const ALIGNMENT_WRITE: u64 = 0x9600_0061;
const UNDEFINED: u64 = 0x0200_0000;

/// `tag` in an address's bits 59:56.
const fn tagged_pointer(tag: u64, address: u64) -> u64 {
    tag << 56 | address
}

/// `chip` at EL1 with its test RAM identity-mapped as Tagged memory
/// (MAIR 0xf0), Allocation Tag access at EL0 and EL1, TBI0, and the
/// chip's CTR_EL0, GMID_EL1 and CLIDR_EL1.
fn tagged(chip: Chip, words: &[u32], el0: bool) -> Test {
    let mut machine = machine_on(chip, words);
    normal_memory(&mut machine, el0);
    let registers = &mut machine.cpu.registers;
    registers.set(SystemRegister::MAIR_EL1, 0, 0xf0);
    registers.set(SystemRegister::MAIR_EL2, 0, 0xf0);
    let hcr = registers.get(SystemRegister::HCR_EL2, 0);
    registers.set(SystemRegister::HCR_EL2, 0, hcr | HCR_ATA);
    let sctlr = registers.get(SystemRegister::SCTLR_EL1, 0);
    registers.set(SystemRegister::SCTLR_EL1, 0, sctlr | SCTLR_ATA | SCTLR_ATA0);
    let tcr = registers.get(SystemRegister::TCR_EL1, 0);
    registers.set(SystemRegister::TCR_EL1, 0, tcr | TCR_TBI0);
    registers.set(SystemRegister::VBAR_EL1, 0, VBAR);
    registers.set(SystemRegister::VBAR_EL2, 0, VBAR);
    let derived = identification::derive(
        chip,
        TargetCpu::Baseline,
        true,
        identification::Speculation::NONE,
    );
    for (register, encoding) in [
        (SystemRegister::CTR_EL0, encodings::CTR_EL0),
        (SystemRegister::GMID_EL1, encodings::GMID_EL1),
        (SystemRegister::CLIDR_EL1, encodings::CLIDR_EL1),
    ] {
        let (_, value) = derived
            .iter()
            .find(|(candidate, _)| *candidate == encoding)
            .expect("an identification register");
        machine.cpu.registers.set_raw(register, 0, *value);
        machine
            .profile_missing
            .retain(|&missing| missing != register);
    }
    machine.translations_changed();
    machine
}

fn update(machine: &mut Test, register: SystemRegister, set: u64, clear: u64) {
    let value = machine.cpu.read(register) & !clear | set;
    machine.cpu.registers.set(register, 0, value);
    machine.translations_changed();
}

/// Run `word` as a System exit at `el` from PC BASE.
fn run(machine: &mut Test, el: u8, word: u32) {
    machine.cpu.set_pstate(Pstate {
        sp: el != 0,
        ..Pstate::reset(el.max(1))
    });
    machine.cpu.pstate.el = el;
    machine.cpu.pc = BASE;
    machine.translations_changed();
    machine.system_instruction(word).unwrap();
}

/// The syndrome and fault address of the exception just taken to EL1,
/// or None when the instruction completed.
fn fault(machine: &Test) -> Option<(u64, u64)> {
    (machine.cpu.pc != BASE + 4).then(|| {
        (
            machine.cpu.read(SystemRegister::ESR_EL1),
            machine.cpu.read(SystemRegister::FAR_EL1),
        )
    })
}

fn ram(machine: &Test, address: u64, bytes: usize) -> &[u8] {
    let offset = (address - BASE) as usize;
    &machine.host.ram[offset..offset + bytes]
}

fn fill(machine: &mut Test, address: u64, bytes: usize, value: u8) {
    let offset = (address - BASE) as usize;
    machine.host.ram[offset..offset + bytes].fill(value);
}

fn set_x(machine: &mut Test, values: &[(usize, u64)]) {
    for &(register, value) in values {
        machine.cpu.state.x[register] = value;
    }
}

#[test]
fn tag_stores_and_loads_reach_tagged_memory_behind_allocation_tag_access() {
    const STG: u32 = 0xd920_0822; // stg x2, [x1]
    const STG_PRE: u32 = 0xd920_2c22; // stg x2, [x1, #32]!
    const STG_POST: u32 = 0xd93f_f422; // stg x2, [x1], #-16
    const STZG: u32 = 0xd960_0822; // stzg x2, [x1]
    const ST2G: u32 = 0xd9a0_0822; // st2g x2, [x1]
    const STZ2G: u32 = 0xd9ff_e822; // stz2g x2, [x1, #-32]
    const STGP: u32 = 0x6900_1023; // stgp x3, x4, [x1]
    const LDG: u32 = 0xd960_1020; // ldg x0, [x1, #16]
    for chip in MTE_CHIPS {
        let mut machine = tagged(chip, &[], false);
        set_x(&mut machine, &[(1, DATA), (2, tagged_pointer(0xa, 0))]);
        run(&mut machine, 1, STG);
        assert_eq!(fault(&machine), None);
        assert_eq!(
            (machine.tags.get(DATA), machine.tags.get(DATA + 16)),
            (0xa, 0)
        );
        // LDG aligns its address and replaces Xt's tag alone.
        set_x(&mut machine, &[(0, 0x0f00_0000_0000_1234), (1, DATA - 11)]);
        run(&mut machine, 1, LDG);
        assert_eq!(machine.cpu.state.x[0], 0x0a00_0000_0000_1234);
        // Pre- and post-index writeback.
        set_x(&mut machine, &[(1, DATA), (2, tagged_pointer(0xb, 0))]);
        run(&mut machine, 1, STG_PRE);
        assert_eq!(
            (machine.cpu.state.x[1], machine.tags.get(DATA + 32)),
            (DATA + 32, 0xb)
        );
        set_x(&mut machine, &[(2, tagged_pointer(0xc, 0))]);
        run(&mut machine, 1, STG_POST);
        assert_eq!(
            (machine.cpu.state.x[1], machine.tags.get(DATA + 32)),
            (DATA + 16, 0xc)
        );
        // STZG zeroes its granule; ST2G and STZ2G cover two.
        fill(&mut machine, DATA + 0x40, 0xc0, 0xaa);
        set_x(&mut machine, &[(1, DATA + 0x40), (2, tagged_pointer(3, 0))]);
        run(&mut machine, 1, STZG);
        assert_eq!(ram(&machine, DATA + 0x40, 16), [0; 16]);
        assert_eq!(ram(&machine, DATA + 0x50, 1), [0xaa]);
        assert_eq!(machine.tags.get(DATA + 0x40), 3);
        set_x(&mut machine, &[(1, DATA + 0x80), (2, tagged_pointer(4, 0))]);
        run(&mut machine, 1, ST2G);
        assert_eq!(
            [0x80, 0x90, 0xa0].map(|offset| machine.tags.get(DATA + offset)),
            [4, 4, 0]
        );
        assert_eq!(ram(&machine, DATA + 0x80, 1), [0xaa]);
        set_x(&mut machine, &[(1, DATA + 0xe0), (2, tagged_pointer(5, 0))]);
        run(&mut machine, 1, STZ2G);
        assert_eq!(ram(&machine, DATA + 0xc0, 32), [0; 32]);
        assert_eq!(ram(&machine, DATA + 0xe0, 1), [0xaa]);
        assert_eq!(
            [0xc0, 0xd0, 0xe0].map(|offset| machine.tags.get(DATA + offset)),
            [5, 5, 0]
        );
        // STGP stores the pair and the address's own tag.
        set_x(
            &mut machine,
            &[
                (1, tagged_pointer(6, DATA + 0x100)),
                (3, 0x1122_3344_5566_7788),
                (4, 0x99aa_bbcc_ddee_ff00),
            ],
        );
        run(&mut machine, 1, STGP);
        let mut pair = [0; 16];
        pair[..8].copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
        pair[8..].copy_from_slice(&0x99aa_bbcc_ddee_ff00u64.to_le_bytes());
        assert_eq!(ram(&machine, DATA + 0x100, 16), pair);
        assert_eq!(machine.tags.get(DATA + 0x100), 6);
        // An unaligned tag store takes an Alignment fault.
        set_x(&mut machine, &[(1, DATA + 8)]);
        run(&mut machine, 1, STG);
        assert_eq!(fault(&machine), Some((ALIGNMENT_WRITE, DATA + 8)));
        assert_eq!(machine.cpu.pc, SYNCHRONOUS);
        // Without HCR_EL2.ATA, EL1 reaches no tags: LDG reads 0, and
        // STZG zeroes its data alone.
        update(&mut machine, SystemRegister::HCR_EL2, 0, HCR_ATA);
        set_x(&mut machine, &[(1, DATA + 0x40), (2, tagged_pointer(9, 0))]);
        fill(&mut machine, DATA + 0x40, 16, 0xaa);
        run(&mut machine, 1, STZG);
        assert_eq!(ram(&machine, DATA + 0x40, 16), [0; 16]);
        assert_eq!(machine.tags.get(DATA + 0x40), 3);
        set_x(&mut machine, &[(0, tagged_pointer(0xf, 0)), (1, DATA - 16)]);
        run(&mut machine, 1, LDG);
        assert_eq!(machine.cpu.state.x[0], 0);
        // EL0 needs SCTLR_EL1.ATA0, and Untagged memory has no tags.
        update(&mut machine, SystemRegister::HCR_EL2, HCR_ATA, 0);
        update(&mut machine, SystemRegister::SCTLR_EL1, 0, SCTLR_ATA0);
        set_x(&mut machine, &[(1, DATA)]);
        run(&mut machine, 0, STG);
        assert_eq!(machine.tags.get(DATA), 0xa);
        update(&mut machine, SystemRegister::MAIR_EL1, 0xff, 0xff);
        run(&mut machine, 1, STG);
        assert_eq!(machine.tags.get(DATA), 0xa);
    }
    // Without FEAT_MTE the forms are UNDEFINED.
    let mut machine = tagged(Chip::AppleM4, &[], false);
    set_x(&mut machine, &[(1, DATA)]);
    run(&mut machine, 1, STG);
    assert_eq!(fault(&machine).map(|fault| fault.0), Some(UNDEFINED));
}

#[test]
fn irg_addg_and_subg_choose_tags_under_gcr_and_rgsr() {
    const IRG: u32 = 0x9ac2_1020; // irg x0, x1, x2
    const IRG_SP: u32 = 0x9adf_13e0; // irg x0, sp
    const ADDG: u32 = 0x9182_0c20; // addg x0, x1, #32, #3
    const SUBG: u32 = 0xd181_0420; // subg x0, x1, #16, #1
    const RRND: u64 = 1 << 16;
    fn controls(machine: &mut Test, gcr: u64, rgsr: u64) {
        machine.cpu.registers.set(SystemRegister::GCR_EL1, 0, gcr);
        machine.cpu.registers.set(SystemRegister::RGSR_EL1, 0, rgsr);
    }
    fn rgsr(machine: &Test) -> u64 {
        machine.cpu.read(SystemRegister::RGSR_EL1)
    }
    for chip in MTE_CHIPS {
        let mut machine = tagged(chip, &[], false);
        // Arm `AArch64_RandomTag` steps SEED 0x1234 to 0xe123 with
        // offset 14, which from TAG 0xf over the tags GCR_EL1 (15) and
        // Xm (0) leave reaches 0xe.
        controls(&mut machine, 0x8000, 0x1234 << 8 | 0xf);
        set_x(&mut machine, &[(1, tagged_pointer(3, DATA)), (2, 1)]);
        run(&mut machine, 1, IRG);
        assert_eq!(machine.cpu.state.x[0], tagged_pointer(0xe, DATA));
        assert_eq!(rgsr(&machine), 0xe123 << 8 | 0xe);
        // Then offset 6 from 0xe, Xm excluding 4 to 6.
        let state = rgsr(&machine);
        controls(&mut machine, 0, state);
        set_x(&mut machine, &[(2, 0x70)]);
        run(&mut machine, 1, IRG);
        assert_eq!(machine.cpu.state.x[0], tagged_pointer(7, DATA));
        assert_eq!(rgsr(&machine), 0x6e12 << 8 | 7);
        // IRG Xd, SP takes SP.
        machine.cpu.state.sp = DATA + 0x20;
        run(&mut machine, 1, IRG_SP);
        assert_eq!(machine.cpu.state.x[0] & !(0xf << 56), DATA + 0x20);
        // With RRND, every tag excluded gives 0 with RGSR_EL1
        // unchanged, and the one tag left is chosen.
        controls(&mut machine, RRND | 0xffff, 0x1234 << 8 | 0xf);
        run(&mut machine, 1, IRG);
        assert_eq!(
            (machine.cpu.state.x[0], rgsr(&machine)),
            (DATA, 0x1234 << 8 | 0xf)
        );
        controls(&mut machine, RRND | 0xfffe, 0x1234 << 8 | 0xf);
        set_x(&mut machine, &[(2, 0)]);
        run(&mut machine, 1, IRG);
        assert_eq!(machine.cpu.state.x[0], DATA);
        // ADDG and SUBG step the source's tag over GCR_EL1.Exclude.
        controls(&mut machine, 0, 0);
        set_x(&mut machine, &[(1, tagged_pointer(0xa, DATA))]);
        run(&mut machine, 1, ADDG);
        assert_eq!(machine.cpu.state.x[0], tagged_pointer(0xd, DATA + 32));
        controls(&mut machine, 0x1800, 0);
        run(&mut machine, 1, ADDG);
        assert_eq!(machine.cpu.state.x[0], tagged_pointer(0xf, DATA + 32));
        controls(&mut machine, 0x8001, 0);
        set_x(&mut machine, &[(1, tagged_pointer(0xe, DATA))]);
        run(&mut machine, 1, SUBG);
        assert_eq!(machine.cpu.state.x[0], tagged_pointer(1, DATA - 16));
        // Without Allocation Tag access the tag is 0 and RGSR_EL1 stays.
        update(&mut machine, SystemRegister::HCR_EL2, 0, HCR_ATA);
        run(&mut machine, 1, SUBG);
        assert_eq!(machine.cpu.state.x[0], DATA - 16);
        controls(&mut machine, 0, 0x1234 << 8);
        run(&mut machine, 1, IRG);
        assert_eq!(
            (machine.cpu.state.x[0], rgsr(&machine)),
            (DATA, 0x1234 << 8)
        );
    }
    let mut machine = tagged(Chip::AppleM4, &[], false);
    for word in [IRG, ADDG] {
        run(&mut machine, 1, word);
        assert_eq!(fault(&machine).map(|fault| fault.0), Some(UNDEFINED));
    }
}

/// An M5 PE whose identification masks ID_AA64PFR1_EL1.MTE and MTE_frac
/// (the validation machine's) lacks memory tagging exactly as the M4 does:
/// IRG, ADDG and STG are UNDEFINED, exception entry leaves TCO alone and
/// no access is Tagged.
#[test]
fn a_masked_m5_pe_has_no_memory_tagging() {
    const STG: u32 = 0xd920_0822; // stg x2, [x1]
    const MTE_FIELDS: u64 = 0xf << 8 | 0xf << 40;
    let mut fixed = identification::derive(
        Chip::AppleM5,
        TargetCpu::Baseline,
        true,
        identification::Speculation::NONE,
    );
    for (register, value) in &mut fixed {
        if *register == encodings::ID_AA64PFR1_EL1 {
            *value &= !MTE_FIELDS;
        }
    }
    let withheld = identification::withheld(Chip::AppleM5, &fixed);
    let mut machine = tagged(Chip::AppleM5, &[], false);
    machine.cpu.present(withheld);
    machine.translations_changed();
    assert!(!machine.cpu.mte());
    assert!(!machine.cpu.allocation_tags(1));
    set_x(&mut machine, &[(1, DATA), (2, tagged_pointer(3, DATA))]);
    for word in [0x9ac2_1020, 0x9182_0c20, STG] {
        run(&mut machine, 1, word);
        assert_eq!(fault(&machine).map(|fault| fault.0), Some(UNDEFINED));
    }
    // The same PE presenting its full identification has it.
    machine.cpu.present(0);
    assert!(machine.cpu.mte());
}

#[test]
fn block_tag_forms_cover_gmid_and_dczid_blocks() {
    const LDGM: u32 = 0xd9e0_0020; // ldgm x0, [x1]
    const STGM: u32 = 0xd9a0_0022; // stgm x2, [x1]
    const STZGM: u32 = 0xd920_0022; // stzgm x2, [x1]
    const DC_GVA: u32 = 0xd50b_7461; // dc gva, x1
    const DC_GZVA: u32 = 0xd50b_7481; // dc gzva, x1
    // dc cgvac, cgdvac, cgvap, cgdvap, cgvadp, cgdvadp, cigvac,
    // cigdvac, igvac, igdvac, cgsw, cgdsw, cigsw, cigdsw, igsw and
    // igdsw, each of x1.
    const DC_TAG_MAINTENANCE: [u32; 16] = [
        0xd50b_7a61,
        0xd50b_7aa1,
        0xd50b_7c61,
        0xd50b_7ca1,
        0xd50b_7d61,
        0xd50b_7da1,
        0xd50b_7e61,
        0xd50b_7ea1,
        0xd508_7661,
        0xd508_76a1,
        0xd508_7a81,
        0xd508_7ac1,
        0xd508_7e81,
        0xd508_7ec1,
        0xd508_7681,
        0xd508_76c1,
    ];
    for chip in MTE_CHIPS {
        let mut machine = tagged(chip, &[], true);
        // LDGM puts each granule's tag at its index, address bits 7:4.
        for (index, tag) in (0..4).zip(1..) {
            machine.tags.set(DATA + 0x40 + 16 * index, tag);
        }
        set_x(&mut machine, &[(1, DATA + 0x53)]);
        run(&mut machine, 1, LDGM);
        assert_eq!(machine.cpu.state.x[0], 0x4321 << 16);
        set_x(&mut machine, &[(2, 0x8765_4321_dcba_9876)]);
        run(&mut machine, 1, STGM);
        assert_eq!(
            [0x40, 0x50, 0x60, 0x70].map(|offset| machine.tags.get(DATA + offset)),
            [0xa, 0xb, 0xc, 0xd]
        );
        // STZGM: Xt's low tag for the DC ZVA block, zeroed.
        fill(&mut machine, DATA + 0x80, 0x80, 0xaa);
        set_x(&mut machine, &[(1, DATA + 0x90)]);
        run(&mut machine, 1, STZGM);
        assert_eq!(ram(&machine, DATA + 0x80, 64), [0; 64]);
        assert_eq!(ram(&machine, DATA + 0xc0, 1), [0xaa]);
        assert_eq!(machine.tags.get(DATA + 0xb0), 6);
        // At EL0 the three are UNDEFINED.
        for word in [LDGM, STGM, STZGM] {
            run(&mut machine, 0, word);
            assert_eq!(machine.cpu.pc, LOWER);
            assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), UNDEFINED);
        }
        // DC GVA tags the DC ZVA block with Xt's tag; DC GZVA zeroes it.
        set_x(&mut machine, &[(1, tagged_pointer(7, DATA + 0xc5))]);
        run(&mut machine, 1, DC_GVA);
        assert_eq!(fault(&machine), None);
        assert_eq!(
            [0xc0, 0xf0, 0x100].map(|offset| machine.tags.get(DATA + offset)),
            [7, 7, 0]
        );
        assert_eq!(ram(&machine, DATA + 0xc0, 1), [0xaa]);
        set_x(&mut machine, &[(1, tagged_pointer(8, DATA + 0xc5))]);
        run(&mut machine, 1, DC_GZVA);
        assert_eq!(ram(&machine, DATA + 0xc0, 64), [0; 64]);
        assert_eq!(machine.tags.get(DATA + 0xf0), 8);
        // The tag maintenance forms act as their data forms.
        for word in DC_TAG_MAINTENANCE {
            run(&mut machine, 1, word);
            assert_eq!(fault(&machine), None, "{word:#x}");
        }
        // With stage 1 off memory is Device: DC GVA takes an Alignment
        // fault reporting Xt.
        update(&mut machine, SystemRegister::SCTLR_EL1, 0, 1);
        run(&mut machine, 1, DC_GVA);
        let (syndrome, address) = fault(&machine).unwrap();
        assert_eq!(
            (syndrome & 0x3f, address),
            (0x21, tagged_pointer(8, DATA + 0xc5))
        );
    }
}

#[test]
fn tag_checked_accesses_fault_on_a_mismatch() {
    const LDXR: u32 = 0xc85f_7c20; // ldxr x0, [x1]
    const STXR: u32 = 0xc806_7c20; // stxr w6, x0, [x1]
    const LDTR: u32 = 0xf840_0820; // ldtr x0, [x1]
    const LDRAA: u32 = 0xf820_0420; // ldraa x0, [x1]
    const DC_ZVA: u32 = 0xd50b_7421; // dc zva, x1
    for chip in MTE_CHIPS {
        let mut machine = tagged(chip, &[], true);
        for offset in (0..0x40).step_by(16) {
            machine.tags.set(DATA + offset, 0xa);
        }
        machine.host.ram[0x1000..0x1008].copy_from_slice(&0x55u64.to_le_bytes());
        let matching = tagged_pointer(0xa, DATA);
        // Without SCTLR_EL1.TCF nothing is checked.
        set_x(&mut machine, &[(1, DATA)]);
        run(&mut machine, 1, LDXR);
        assert_eq!(fault(&machine), None);
        update(&mut machine, SystemRegister::SCTLR_EL1, SCTLR_TCF_SYNC, 0);
        run(&mut machine, 1, LDXR);
        assert_eq!(fault(&machine), Some((TAG_CHECK_READ, DATA)));
        set_x(&mut machine, &[(1, matching)]);
        run(&mut machine, 1, LDXR);
        assert_eq!((fault(&machine), machine.cpu.state.x[0]), (None, 0x55));
        // A store-exclusive that passes is checked.
        set_x(&mut machine, &[(1, tagged_pointer(0xb, DATA))]);
        run(&mut machine, 1, STXR);
        assert_eq!(
            fault(&machine),
            Some((TAG_CHECK_WRITE, tagged_pointer(0xb, DATA)))
        );
        // PSTATE.TCO, TCMA0 for a 0 tag, and the asynchronous and
        // reserved TCF values leave mismatches unchecked.
        set_x(&mut machine, &[(1, DATA)]);
        machine.cpu.set_pstate(Pstate {
            tco: true,
            ..Pstate::reset(1)
        });
        machine.cpu.pc = BASE;
        machine.system_instruction(LDXR).unwrap();
        assert_eq!(fault(&machine), None);
        update(&mut machine, SystemRegister::TCR_EL1, TCR_TCMA0, 0);
        run(&mut machine, 1, LDXR);
        assert_eq!(fault(&machine), None);
        set_x(&mut machine, &[(1, tagged_pointer(0xb, DATA))]);
        run(&mut machine, 1, LDXR);
        assert!(fault(&machine).is_some());
        update(&mut machine, SystemRegister::TCR_EL1, 0, TCR_TCMA0);
        for tcf in [0b10, 0b11] {
            update(
                &mut machine,
                SystemRegister::SCTLR_EL1,
                tcf << 40,
                0b11 << 40,
            );
            run(&mut machine, 1, LDXR);
            assert_eq!(fault(&machine), None);
        }
        update(
            &mut machine,
            SystemRegister::SCTLR_EL1,
            SCTLR_TCF_SYNC,
            0b11 << 40,
        );
        // LDTR from EL1 checks as EL0, under TCF0.
        set_x(&mut machine, &[(1, DATA)]);
        run(&mut machine, 1, LDTR);
        assert_eq!(fault(&machine), None);
        update(&mut machine, SystemRegister::SCTLR_EL1, SCTLR_TCF0_SYNC, 0);
        run(&mut machine, 1, LDTR);
        assert_eq!(fault(&machine), Some((TAG_CHECK_READ, DATA)));
        // LDRAA with its key disabled loads from Xn, checked.
        machine.cpu.set_pstate(Pstate::reset(1));
        machine.cpu.pc = BASE;
        machine.pointer_authentication(LDRAA).unwrap();
        assert_eq!(fault(&machine), Some((TAG_CHECK_READ, DATA)));
        set_x(&mut machine, &[(0, 0), (1, matching)]);
        machine.cpu.set_pstate(Pstate::reset(1));
        machine.cpu.pc = BASE;
        machine.pointer_authentication(LDRAA).unwrap();
        assert_eq!((fault(&machine), machine.cpu.state.x[0]), (None, 0x55));
        // DC ZVA is checked over its block, reporting Xt.
        set_x(&mut machine, &[(1, DATA + 0x25)]);
        run(&mut machine, 1, DC_ZVA);
        assert_eq!(fault(&machine), Some((TAG_CHECK_WRITE, DATA + 0x25)));
        assert_eq!(ram(&machine, DATA, 8), 0x55u64.to_le_bytes());
        set_x(&mut machine, &[(1, tagged_pointer(0xa, DATA + 0x25))]);
        run(&mut machine, 1, DC_ZVA);
        assert_eq!(fault(&machine), None);
        assert_eq!(ram(&machine, DATA, 8), [0; 8]);
    }
}

/// While EL1 checks the tags of untagged lower-half pointers, the
/// shadow keeps that half's Tagged memory out; a native access there
/// exits and takes its Tag Check fault, or runs with its page passed.
/// A tagged pointer's tags are checked before the untagged retry.
#[test]
fn native_accesses_to_checked_tagged_memory_exit_to_the_tag_check() {
    const LDR: u32 = 0xf940_0020; // ldr x0, [x1]
    const ADD: u32 = 0x9100_0400; // add x0, x0, #1
    for chip in MTE_CHIPS {
        let mut machine = tagged(chip, &[LDR, ADD], false);
        machine.tags.set(DATA, 0xa);
        update(&mut machine, SystemRegister::SCTLR_EL1, SCTLR_TCF_SYNC, 0);
        let regime = *machine.host.regimes.last().unwrap();
        assert_eq!(regime.tag_checks, [true, false]);
        assert!(regime.tag_blocks(DATA, TAGGED) && !regime.tag_blocks(DATA, 0xff));
        machine.cpu.pc = BASE;
        machine.host.exits = vec![NativeExit::Exit {
            next_pc: BASE + 8,
            kind: ExitKind::Fallthrough as u64,
        }];
        machine.step().unwrap();
        let access_offset = super::super::tests::native_fault_site(
            &mut machine,
            BASE,
            stela_compiler::block::RecoverySiteKind::GuestAccess,
        );
        let check_offset = super::super::tests::native_fault_site(
            &mut machine,
            BASE,
            stela_compiler::block::RecoverySiteKind::GuestCheck,
        );
        let exit = |cause| {
            NativeExit::Fault(NativeFault {
                origin: crate::machine::NativeFaultOrigin::Exception,
                trap: if matches!(cause, FaultCause::InvalidOpcode) {
                    6
                } else {
                    14
                },
                error_code: 0,
                spills: stela_compiler::block::HostSpillSnapshot::new(),
                registers: stela_compiler::block::HostGprSnapshot::legacy([0; 16]),
                offset: if matches!(cause, FaultCause::InvalidOpcode) {
                    check_offset
                } else {
                    access_offset
                },
                address: DATA,
                write: false,
                cause,
            })
        };
        // A mismatch faults.
        set_x(&mut machine, &[(1, DATA)]);
        machine.cpu.pc = BASE;
        machine.host.exits = vec![exit(FaultCause::TagChecked)];
        machine.step().unwrap();
        assert_eq!(fault(&machine), Some((TAG_CHECK_READ, DATA)));
        // Exception entry sets PSTATE.TCO: EL1 no longer checks.
        assert!(machine.cpu.pstate.tco);
        assert_eq!(machine.host.regimes.last().unwrap().tag_checks, [false; 2]);
        // A tagged pointer fails the range check: its tag matches, and
        // the instruction runs again untagged with the page passed.
        machine.cpu.set_pstate(Pstate::reset(1));
        machine.translations_changed();
        set_x(&mut machine, &[(1, tagged_pointer(0xa, DATA))]);
        machine.cpu.pc = BASE;
        machine.host.exits = vec![
            exit(FaultCause::InvalidOpcode),
            exit(FaultCause::TagChecked),
            NativeExit::Exit {
                next_pc: BASE + 4,
                kind: ExitKind::Fallthrough as u64,
            },
        ];
        machine.step().unwrap();
        assert!(machine.host.exits.is_empty());
        assert_eq!(machine.cpu.pc, BASE + 4);
        assert_eq!(machine.cpu.state.x[1], tagged_pointer(0xa, DATA));
        assert!(
            machine
                .host
                .regimes
                .iter()
                .any(|regime| regime.watch.pass[0] == Some(DATA))
        );
        // A mismatching tagged pointer faults before the retry.
        set_x(&mut machine, &[(1, tagged_pointer(0xb, DATA + 8))]);
        machine.cpu.pc = BASE;
        machine.host.exits = vec![exit(FaultCause::InvalidOpcode)];
        machine.step().unwrap();
        assert_eq!(
            fault(&machine),
            Some((TAG_CHECK_READ, tagged_pointer(0xb, DATA + 8)))
        );
    }
}

#[test]
fn mte_system_registers_and_tco_follow_the_profile() {
    const MRS_GMID: u32 = 0xd539_0085; // mrs x5, gmid_el1
    const MRS_CTR: u32 = 0xd53b_0025; // mrs x5, ctr_el0
    const MSR_GCR: u32 = 0xd518_10c5; // msr gcr_el1, x5
    const MRS_GCR: u32 = 0xd538_10c5; // mrs x5, gcr_el1
    const MSR_RGSR: u32 = 0xd518_10a5; // msr rgsr_el1, x5
    const MRS_RGSR: u32 = 0xd538_10a5; // mrs x5, rgsr_el1
    const MSR_TFSR: u32 = 0xd518_5605; // msr tfsr_el1, x5
    const MRS_TFSR: u32 = 0xd538_5605; // mrs x5, tfsr_el1
    const MRS_TFSRE0: u32 = 0xd538_5625; // mrs x5, tfsre0_el1
    const MRS_TFSR_EL3: u32 = 0xd53e_5605; // mrs x5, tfsr_el3
    const MSR_TFSR_EL3: u32 = 0xd51e_5605; // msr tfsr_el3, x5
    const MSR_TFSRE0: u32 = 0xd518_5625; // msr tfsre0_el1, x5
    const MRS_TFSR_EL2: u32 = 0xd53c_5605; // mrs x5, tfsr_el2
    const MSR_TFSR_EL2: u32 = 0xd51c_5605; // msr tfsr_el2, x5
    const MRS_TFSR_EL12: u32 = 0xd53d_5605; // mrs x5, tfsr_el12
    const MSR_TFSR_EL12: u32 = 0xd51d_5605; // msr tfsr_el12, x5
    const MRS_DSPSR: u32 = 0xd53b_4505; // mrs x5, dspsr_el0
    const MSR_CSSELR: u32 = 0xd51a_0005; // msr csselr_el1, x5
    const MRS_CSSELR: u32 = 0xd53a_0005; // mrs x5, csselr_el1
    const MRS_CLIDR: u32 = 0xd539_0025; // mrs x5, clidr_el1
    const MSR_TCO_1: u32 = 0xd503_419f; // msr tco, #1
    const MSR_TCO_0: u32 = 0xd503_409f; // msr tco, #0
    const MSR_TCO: u32 = 0xd51b_42e5; // msr tco, x5
    const MRS_TCO: u32 = 0xd53b_42e5; // mrs x5, tco
    const AT_S1E1R: u32 = 0xd508_7801; // at s1e1r, x1
    const SVC: u32 = 0xd400_0001; // svc #0
    const ERET: u32 = 0xd69f_03e0; // eret
    const TCO: u64 = 1 << 25;
    fn read(machine: &mut Test, el: u8, word: u32) -> u64 {
        machine.cpu.state.x[5] = 0xdead;
        run(machine, el, word);
        assert_eq!(fault(machine), None, "{word:#x}");
        machine.cpu.state.x[5]
    }
    fn write(machine: &mut Test, el: u8, word: u32, value: u64) {
        machine.cpu.state.x[5] = value;
        run(machine, el, word);
        assert_eq!(fault(machine), None, "{word:#x}");
    }
    fn class(machine: &Test, register: SystemRegister) -> u64 {
        machine.cpu.read(register) >> 26
    }
    for chip in MTE_CHIPS {
        let mut machine = tagged(chip, &[], false);
        // GMID_EL1.BS 4 and CTR_EL0.TminLine 4: 64 bytes. With no
        // caches CLIDR_EL1's Ttype fields are 0.
        assert_eq!(read(&mut machine, 1, MRS_GMID), 4);
        assert_eq!(read(&mut machine, 1, MRS_CTR) >> 32 & 0xf, 4);
        assert_eq!(read(&mut machine, 1, MRS_CLIDR) >> 33, 0);
        update(&mut machine, SystemRegister::HCR_EL2, HCR_TID5, 0);
        run(&mut machine, 1, MRS_GMID);
        assert_eq!(machine.cpu.pstate.el, 2);
        assert_eq!(class(&machine, SystemRegister::ESR_EL2), 0x18);
        update(&mut machine, SystemRegister::HCR_EL2, 0, HCR_TID5);
        // GCR_EL1 keeps Exclude and RRND; RGSR_EL1 TAG and SEED, bits
        // 55:8, of which IRG steps the low 16.
        write(&mut machine, 1, MSR_GCR, u64::MAX);
        assert_eq!(read(&mut machine, 1, MRS_GCR), 0x1_ffff);
        write(&mut machine, 1, MSR_RGSR, u64::MAX);
        assert_eq!(read(&mut machine, 1, MRS_RGSR), 0x00ff_ffff_ffff_ff0f);
        // Without asynchronous checks the TFSR registers are RAZ/WI;
        // TFSR_EL3 has no EL3 to be at.
        write(&mut machine, 1, MSR_TFSR, u64::MAX);
        write(&mut machine, 1, MSR_TFSRE0, u64::MAX);
        assert_eq!(read(&mut machine, 1, MRS_TFSR), 0);
        assert_eq!(read(&mut machine, 1, MRS_TFSRE0), 0);
        // At EL2 TFSR_EL1 names TFSR_EL2 and TFSR_EL12 TFSR_EL1.
        for word in [MSR_TFSR, MSR_TFSR_EL2, MSR_TFSR_EL12] {
            write(&mut machine, 2, word, u64::MAX);
        }
        for word in [MRS_TFSR, MRS_TFSR_EL2, MRS_TFSR_EL12] {
            assert_eq!(read(&mut machine, 2, word), 0);
        }
        for word in [MRS_TFSR_EL3, MSR_TFSR_EL3, MRS_DSPSR] {
            run(&mut machine, 1, word);
            assert_eq!(fault(&machine).map(|fault| fault.0), Some(UNDEFINED));
        }
        // AT reports Tagged memory as PAR_EL1.ATTR 0xf0.
        machine.cpu.state.x[1] = DATA;
        run(&mut machine, 1, AT_S1E1R);
        assert_eq!(machine.cpu.read(SystemRegister::PAR_EL1) >> 56, 0xf0);
        // CSSELR_EL1.TnD is stored.
        write(&mut machine, 1, MSR_CSSELR, 0x10);
        assert_eq!(read(&mut machine, 1, MRS_CSSELR), 0x10);
        // PSTATE.TCO: its immediate and register forms, at EL0 too.
        run(&mut machine, 0, MSR_TCO_1);
        assert!(machine.cpu.pstate.tco);
        for (word, tco) in [(MRS_TCO, true), (MSR_TCO_0, false), (MSR_TCO, true)] {
            machine.cpu.state.x[5] = TCO;
            machine.cpu.pc = BASE;
            machine.system_instruction(word).unwrap();
            assert_eq!((machine.cpu.pc, machine.cpu.pstate.tco), (BASE + 4, tco));
        }
        assert_eq!(machine.cpu.state.x[5], TCO);
        // Exception entry sets it, keeping the old value in SPSR_EL1;
        // ERET restores it.
        machine.cpu.pstate.tco = false;
        machine.cpu.pc = BASE;
        machine.system_instruction(SVC).unwrap();
        assert!(machine.cpu.pstate.tco);
        assert_eq!(machine.cpu.read(SystemRegister::SPSR_EL1) & TCO, 0);
        let spsr = machine.cpu.read(SystemRegister::SPSR_EL1);
        machine
            .cpu
            .registers
            .set(SystemRegister::SPSR_EL1, 0, spsr | TCO);
        machine.cpu.pstate.tco = false;
        machine.system_instruction(ERET).unwrap();
        assert!(machine.cpu.pstate.tco && machine.cpu.pstate.el == 0);
    }
    // The M4 has none of it; GMID_EL1 is then an unimplemented ID
    // register, whose access traps with EC 0x18 (FEAT_IDST).
    let mut machine = tagged(Chip::AppleM4, &[], false);
    for word in [MSR_TCO_1, MRS_TCO, MRS_GCR] {
        run(&mut machine, 1, word);
        assert_eq!(
            fault(&machine).map(|fault| fault.0),
            Some(UNDEFINED),
            "{word:#x}"
        );
    }
    run(&mut machine, 1, MRS_GMID);
    assert_eq!(class(&machine, SystemRegister::ESR_EL1), 0x18);
    assert_eq!(read(&mut machine, 1, MRS_CTR) >> 32, 0);
}
