//! EL0 blocks check access addresses one-sided, against the frame's end of
//! the native lower range (`RangeCheck::one_sided`); EL1 keeps the
//! two-sided check. An EL0 access to the upper range takes the fault its
//! translation gives, or, mapped for EL0, runs its page with the two-sided
//! check; the tagged variant combines with it; a TCR change recompiles
//! nothing.
use super::tagged::{ADD, DATA, LDR, LOWER_STRIP, TAG, TCR_TBI0, end, fault, run, taken};
use super::*;
use crate::machine::{exception::Pstate, mmu};
use stela_compiler::block::RecoverySiteKind;
use stela_compiler::x86_64::{RangeCheck, TopByte};

/// TTBR1_EL1 at 47 bits with a 4 KiB granule: L0 entry 0, then a 1 GiB
/// block of L1 entry 0, maps the upper half's first GiB to RAM; TTBR0 as
/// `normal_memory` maps it, TBI0 when asked.
const LEVEL0: u64 = 0xd000;
const LEVEL1: u64 = 0xe000;
const TCR: u64 =
    25 | 1 << 8 | 1 << 10 | 3 << 12 | 17 << 16 | 1 << 24 | 1 << 26 | 3 << 28 | 0b10 << 30 | 5 << 32;
const UPPER: u64 = mmu::placement::UPPER_HALF + 0x100;
/// AP[1]: the upper block is EL0's too.
const AP_EL0: u64 = 1 << 6;
const LIMIT: u64 = 1 << 48;

/// `cmp rax,[rdi+lower_limit]`.
fn compare_bytes() -> Vec<u8> {
    let mut bytes = vec![0x48, 0x3b, 0x87];
    bytes.extend((core::mem::offset_of!(GuestState, lower_limit) as u32).to_le_bytes());
    bytes
}

fn contains(code: &[u8], bytes: &[u8]) -> bool {
    code.windows(bytes.len()).any(|window| window == bytes)
}

/// Whether `code` compares any GPR with `[rdi+lower_limit]`: RAX, or a
/// pinned base the check reads in place.
fn compares_with_the_limit(code: &[u8]) -> bool {
    let offset = (core::mem::offset_of!(GuestState, lower_limit) as u32).to_le_bytes();
    code.windows(7).any(|window| {
        matches!(window[0], 0x48 | 0x4c)
            && window[1] == 0x3b
            && window[2] & 0xc7 == 0x87
            && window[3..] == offset
    })
}

/// Back at EL0, as the exception handler would return.
fn at_el0(machine: &mut Machine<FakeHost, NoDevices>) {
    machine.cpu.set_pstate(Pstate {
        sp: false,
        ..Pstate::reset(1)
    });
    machine.cpu.pstate.el = 0;
    machine.translations_changed();
    machine.derived_changed();
}

/// LDR and ADD at BASE at `el`, both halves mapped (the upper one for EL0
/// if `upper_el0`), after one native run that installs their block.
fn setup(el: u8, upper_el0: bool, tbi0: bool) -> Machine<FakeHost, NoDevices> {
    let mut machine = machine(&[LDR, ADD]);
    // EL0-writable memory is never EL1-executable: EL0's alone.
    normal_memory(&mut machine, el == 0);
    let table = |machine: &mut Machine<FakeHost, NoDevices>, at: u64, entry: u64| {
        let at = at as usize;
        machine.host.ram[at..at + 8].copy_from_slice(&entry.to_le_bytes());
    };
    table(&mut machine, LEVEL0, (BASE + LEVEL1) | 0b11);
    let ap = if upper_el0 { AP_EL0 } else { 0 };
    table(&mut machine, LEVEL1, BASE | 1 << 10 | 3 << 8 | ap | 0b01);
    let registers = &mut machine.cpu.registers;
    registers.set(SystemRegister::TTBR1_EL1, 0, BASE + LEVEL0);
    let tbi = if tbi0 { TCR_TBI0 } else { 0 };
    registers.set(SystemRegister::TCR_EL1, 0, TCR | tbi);
    machine.cpu.set_pstate(Pstate {
        sp: el != 0,
        ..Pstate::reset(el.max(1))
    });
    machine.cpu.pstate.el = el;
    machine.translations_changed();
    machine.derived_changed();
    run(&mut machine, DATA, vec![end(BASE + 8)]);
    machine
}

/// The block at BASE: its range check, top byte, access fault offset and
/// installed code.
fn block(machine: &mut Machine<FakeHost, NoDevices>) -> (RangeCheck, TopByte, usize, Vec<u8>) {
    let offset = native_fault_site(machine, BASE, RecoverySiteKind::GuestAccess);
    let Ok(Fetched::Block(index)) = machine.fetch_block(BASE, false) else {
        panic!("block")
    };
    let code =
        machine.host.installed[machine.code.blocks[index].code.0 / NATIVE_CODE_STRIDE - 1].clone();
    let checks = machine.block_variant(index).checks;
    (checks.range, checks.top_byte, offset, code)
}

#[test]
fn el0_blocks_check_one_sided_against_the_frame_and_el1_blocks_two_sided() {
    let mut machine = setup(0, false, false);
    let (range, _, _, code) = block(&mut machine);
    assert!(range.one_sided);
    assert_eq!(range.lower_limit(), LIMIT);
    assert!(compares_with_the_limit(&code));
    // The entry put the placement's limit in the frame.
    assert_eq!(machine.cpu.state.lower_limit.0, LIMIT);
    let mut kernel = setup(1, false, false);
    let (range, _, _, code) = block(&mut kernel);
    assert!(!range.one_sided);
    assert!(!compares_with_the_limit(&code));
}

/// The upper range fails the one-sided check; an EL1-only page there gives
/// EL0 the Permission fault the engine's own walk gives, with its FAR, and
/// the page keeps the one-sided check.
#[test]
fn an_el0_access_to_the_upper_range_faults_as_its_translation_says() {
    let mut machine = setup(0, false, false);
    let (_, _, offset, _) = block(&mut machine);
    let expected = match machine.translate_data(UPPER, mmu::Access::Read) {
        mmu::Outcome::Fault(fault) => machine.data_abort_exception(UPPER, fault, false, false),
        _ => panic!("EL1's page faults at EL0"),
    };
    run(
        &mut machine,
        UPPER,
        vec![fault(offset, FaultCause::NonCanonical, 0)],
    );
    assert_eq!(taken(&machine), (expected.syndrome, UPPER));
    assert_eq!(expected.syndrome >> 26, 0x24, "a Data Abort from EL0");
    assert_eq!(machine.statistics.two_sided_pages, 0);
    at_el0(&mut machine);
    let (range, _, _, _) = block(&mut machine);
    assert!(range.one_sided);
}

/// A page EL0 may reach in the upper range: the instruction runs again
/// with its page two-sided, natively, and other pages stay one-sided.
#[test]
fn an_el0_access_to_a_mapped_upper_page_runs_its_page_two_sided() {
    let mut machine = setup(0, true, false);
    let (_, _, offset, _) = block(&mut machine);
    run(
        &mut machine,
        UPPER,
        vec![fault(offset, FaultCause::NonCanonical, 0)],
    );
    assert_eq!(machine.cpu.pc, BASE, "not retired, no exception");
    assert_eq!(machine.cpu.pstate.el, 0);
    assert_eq!(machine.statistics.two_sided_pages, 1);
    let (range, _, _, code) = block(&mut machine);
    assert!(!range.one_sided);
    assert!(!compares_with_the_limit(&code));
    run(&mut machine, UPPER, vec![end(BASE + 8)]);
    assert_eq!(machine.cpu.pc, BASE + 8);
    let current = machine.current_variant(false, false);
    assert!(
        machine
            .page_variant(current, BASE + FETCH_PAGE)
            .checks
            .range
            .one_sided
    );
}

/// A tagged lower-half pointer at EL0 with TBI0: its page goes to the
/// tagged variant, whose strip comes right before the one-sided compare.
#[test]
fn the_tagged_variant_strips_before_the_one_sided_check() {
    let mut machine = setup(0, false, true);
    let (_, _, offset, _) = block(&mut machine);
    run(
        &mut machine,
        DATA | TAG,
        vec![fault(offset, FaultCause::NonCanonical, 0), end(BASE + 4)],
    );
    assert_eq!(machine.statistics.tagged_pages, 1);
    let (range, top_byte, _, code) = block(&mut machine);
    assert!(range.one_sided);
    assert_eq!(top_byte, TopByte::Lower);
    assert!(contains(
        &code,
        &[LOWER_STRIP.to_vec(), compare_bytes()].concat()
    ));
    run(&mut machine, DATA | TAG, vec![end(BASE + 8)]);
    assert_eq!(machine.cpu.pc, BASE + 8);
    assert_eq!(machine.cpu.state.x[1], DATA | TAG);
}

/// The limit is the host's, not the guest's: a TCR change keeps the
/// variant and the block, and the frame's limit.
#[test]
fn a_tcr_change_recompiles_nothing() {
    let mut machine = setup(0, false, false);
    let (range, _, _, _) = block(&mut machine);
    let compiled = machine.statistics.fetches[4];
    let checks = machine.current_variant(false, false).checks;
    // T1SZ 17 -> 18: a 46-bit TTBR1 range.
    machine
        .cpu
        .registers
        .set(SystemRegister::TCR_EL1, 0, TCR + (1 << 16));
    machine.translations_changed();
    assert_eq!(machine.current_variant(false, false).checks, checks);
    let (after, _, _, _) = block(&mut machine);
    assert_eq!(after, range);
    assert_eq!(machine.statistics.fetches[4], compiled);
    run(&mut machine, DATA, vec![end(BASE + 8)]);
    assert_eq!(machine.cpu.state.lower_limit.0, LIMIT);
}
