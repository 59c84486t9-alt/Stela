//! Tagged pointers in native code: an access whose base holds a top byte
//! the regime ignores (TCR_EL1.TBI0) retries once, then its page runs in
//! the tagged variant, whose accesses clear that byte and stay native.
//! Faults keep the guest's tagged address.
use super::*;
use crate::machine::mmu;
use stela_compiler::block::{ExitKind, RecoverySiteKind};
use stela_compiler::x86_64::TopByte;

const LDR: u32 = 0xf940_0020; // ldr x0, [x1]
const ADD: u32 = 0x9100_0400; // add x0, x0, #1
const TCR_TBI0: u64 = 1 << 37;
const DATA: u64 = BASE + 0x1000;
const TAG: u64 = 0x5a << 56;
/// Past the 1 GiB block `normal_memory` maps: a level 1 Translation fault.
const UNMAPPED: u64 = BASE + 0x4000_0010;
/// A Data Abort at the current EL, read, Translation fault at level 1.
const TRANSLATION_L1_READ: u64 = 0x9600_0005;
/// `mov rcx,rax; shl rcx,8; sar rcx,8; and rax,rcx`: TBI0's strip.
const LOWER_STRIP: [u8; 14] = [
    0x48, 0x89, 0xc1, 0x48, 0xc1, 0xe1, 8, 0x48, 0xc1, 0xf9, 8, 0x48, 0x21, 0xc8,
];

/// LDR and ADD at BASE at EL1, RAM identity-mapped, with TBI0 if `tbi0`,
/// after one native run that installs their block.
fn setup(tbi0: bool) -> Machine<FakeHost, NoDevices> {
    let mut machine = machine(&[LDR, ADD]);
    normal_memory(&mut machine, false);
    if tbi0 {
        let tcr = machine.cpu.registers.get(SystemRegister::TCR_EL1, 0);
        machine
            .cpu
            .registers
            .set(SystemRegister::TCR_EL1, 0, tcr | TCR_TBI0);
        machine.translations_changed();
    }
    run(&mut machine, DATA, vec![end(BASE + 8)]);
    machine
}

fn end(next_pc: u64) -> NativeExit {
    NativeExit::Exit {
        next_pc,
        kind: ExitKind::Fallthrough as u64,
    }
}

/// The native fault of the access at `offset` of the block at BASE.
fn fault(offset: usize, cause: FaultCause, address: u64) -> NativeExit {
    NativeExit::Fault(NativeFault {
        origin: crate::machine::NativeFaultOrigin::Exception,
        trap: if matches!(cause, FaultCause::NonCanonical) {
            13
        } else {
            14
        },
        error_code: 0,
        spills: stela_compiler::block::HostSpillSnapshot::new(),
        registers: stela_compiler::block::HostGprSnapshot::legacy([0; 16]),
        offset,
        address,
        write: false,
        cause,
    })
}

/// Run from BASE with X1 = `base`, the host answering with `exits`, all of
/// which the step must take.
fn run(machine: &mut Machine<FakeHost, NoDevices>, base: u64, exits: Vec<NativeExit>) {
    machine.cpu.pc = BASE;
    machine.cpu.state.x[1] = base;
    machine.host.exits = exits;
    machine.step().unwrap();
    assert!(machine.host.exits.is_empty(), "every exit taken");
}

/// The block at BASE, its variant's top byte, its access's fault offset and
/// its installed code.
fn block_at_base(machine: &mut Machine<FakeHost, NoDevices>) -> (TopByte, usize, Vec<u8>) {
    let offset = native_fault_site(machine, BASE, RecoverySiteKind::GuestAccess);
    let Ok(Fetched::Block(index)) = machine.fetch_block(BASE, false) else {
        panic!("block")
    };
    let code =
        machine.host.installed[machine.code.blocks[index].code.0 / NATIVE_CODE_STRIDE - 1].clone();
    (machine.block_variant(index).checks.top_byte, offset, code)
}

fn has_strip(code: &[u8]) -> bool {
    code.windows(LOWER_STRIP.len())
        .any(|bytes| bytes == LOWER_STRIP)
}

/// The syndrome and fault address of the exception the last step took.
fn taken(machine: &Machine<FakeHost, NoDevices>) -> (u64, u64) {
    (
        machine.cpu.read(SystemRegister::ESR_EL1),
        machine.cpu.read(SystemRegister::FAR_EL1),
    )
}

/// One retry learns the page; later runs of a tagged base stay native, the
/// base keeps its tag, and only that page changes variant. Without TBI0 the
/// page goes back to the plain variant's checks.
#[test]
fn a_tagged_base_runs_its_page_in_the_tagged_variant_after_one_retry() {
    let mut machine = setup(true);
    let (top_byte, offset, code) = block_at_base(&mut machine);
    assert_eq!(top_byte, TopByte::Kept);
    assert!(!has_strip(&code));
    // The check fails; the retry runs LDR alone, untagged.
    run(
        &mut machine,
        DATA | TAG,
        vec![fault(offset, FaultCause::NonCanonical, 0), end(BASE + 4)],
    );
    assert_eq!(machine.cpu.pc, BASE + 4);
    assert_eq!(machine.cpu.state.x[1], DATA | TAG);
    assert_eq!(machine.statistics.tagged_pages, 1);
    let (top_byte, _, code) = block_at_base(&mut machine);
    assert_eq!(top_byte, TopByte::Lower);
    assert!(has_strip(&code));
    // Native now: one run, no retry, no new page.
    run(&mut machine, DATA | TAG, vec![end(BASE + 8)]);
    assert_eq!(machine.cpu.pc, BASE + 8);
    assert_eq!(machine.cpu.state.x[1], DATA | TAG);
    assert_eq!(machine.statistics.tagged_pages, 1);
    let current = machine.current_variant(false, false);
    assert_eq!(
        machine.page_variant(current, BASE + FETCH_PAGE).checks,
        current.checks
    );
    // TBI0 off: the learnt page compiles as every other page.
    let tcr = machine.cpu.registers.get(SystemRegister::TCR_EL1, 0);
    machine
        .cpu
        .registers
        .set(SystemRegister::TCR_EL1, 0, tcr & !TCR_TBI0);
    machine.translations_changed();
    let current = machine.current_variant(false, false);
    assert_eq!(machine.page_variant(current, BASE).checks, current.checks);
    assert_eq!(current.checks.top_byte, TopByte::Kept);
}

/// Without TBI0 a tagged address is a Translation fault the engine takes
/// with the tagged FAR, and no page learns anything.
#[test]
fn without_tbi_a_tagged_base_faults_and_teaches_nothing() {
    let mut machine = setup(false);
    let (_, offset, _) = block_at_base(&mut machine);
    let expected = match machine.translate_data(DATA | TAG, mmu::Access::Read) {
        mmu::Outcome::Fault(fault) => machine.data_abort_exception(DATA | TAG, fault, false, false),
        _ => panic!("a tagged address without TBI faults"),
    };
    run(
        &mut machine,
        DATA | TAG,
        vec![fault(offset, FaultCause::NonCanonical, 0)],
    );
    let (esr, far) = taken(&machine);
    assert_eq!(far, DATA | TAG);
    assert_eq!(esr >> 26, 0x25, "a Data Abort at EL1");
    assert_eq!(esr, expected.syndrome);
    assert_eq!(machine.statistics.tagged_pages, 0);
}

/// A tagged address that does not translate faults with the same syndrome
/// and tagged FAR from the tagged variant (whose host access ran stripped)
/// as from the engine's own check of an unlearnt page.
#[test]
fn a_faulting_tagged_access_reports_its_tagged_address_in_both_variants() {
    // Unlearnt: the check fails, and the engine's walk faults.
    let mut plain = setup(true);
    let (_, offset, _) = block_at_base(&mut plain);
    run(
        &mut plain,
        UNMAPPED | TAG,
        vec![fault(offset, FaultCause::NonCanonical, 0)],
    );
    assert_eq!(taken(&plain), (TRANSLATION_L1_READ, UNMAPPED | TAG));
    // Learnt: the stripped host access faults in the shadow.
    let mut machine = setup(true);
    let (_, offset, _) = block_at_base(&mut machine);
    run(
        &mut machine,
        DATA | TAG,
        vec![fault(offset, FaultCause::NonCanonical, 0), end(BASE + 4)],
    );
    let (top_byte, offset, _) = block_at_base(&mut machine);
    assert_eq!(top_byte, TopByte::Lower);
    let mmu::Outcome::Fault(guest) = machine.translate_data(UNMAPPED, mmu::Access::Read) else {
        panic!("unmapped")
    };
    run(
        &mut machine,
        UNMAPPED | TAG,
        vec![fault(offset, FaultCause::Guest(guest), UNMAPPED)],
    );
    assert_eq!(taken(&machine), (TRANSLATION_L1_READ, UNMAPPED | TAG));
    assert_eq!(machine.cpu.state.x[1], UNMAPPED | TAG);
}

/// The retry that puts BASE's page in the board's tagged set.
fn learn(machine: &mut Machine<FakeHost, NoDevices>) {
    let (_, offset, _) = block_at_base(machine);
    run(
        machine,
        DATA | TAG,
        vec![fault(offset, FaultCause::NonCanonical, 0), end(BASE + 4)],
    );
}

/// A host fault address below the access in its first page, as a
/// translation helper names the page it missed, still reports the
/// guest's tagged address.
#[test]
fn a_fault_named_by_its_page_reports_the_tagged_access_address() {
    let mut machine = setup(true);
    learn(&mut machine);
    let (top_byte, offset, _) = block_at_base(&mut machine);
    assert_eq!(top_byte, TopByte::Lower);
    let mmu::Outcome::Fault(guest) = machine.translate_data(UNMAPPED, mmu::Access::Read) else {
        panic!("unmapped")
    };
    let page = UNMAPPED & !(FETCH_PAGE - 1);
    run(
        &mut machine,
        UNMAPPED | TAG,
        vec![fault(offset, FaultCause::Guest(guest), page)],
    );
    assert_eq!(taken(&machine), (TRANSLATION_L1_READ, UNMAPPED | TAG));
}

/// The board holds one tagged set: a page learnt once is tagged for every
/// PE of the board, and a later retry forgets the page's blocks again only
/// when it came from a plain block (one compiled before the set took it).
#[test]
fn the_board_learns_a_page_once_for_every_pe() {
    let mut machine = setup(true);
    learn(&mut machine);
    assert!(machine.code.tagged.contains(BASE));
    block_at_base(&mut machine);
    let compiled = machine.statistics.fetches[4];
    // Another PE's retry from a tagged block of the page forgets nothing.
    machine.learn_tagged_page(BASE, false);
    let (top_byte, _, _) = block_at_base(&mut machine);
    assert_eq!(top_byte, TopByte::Lower);
    assert_eq!(machine.statistics.fetches[4], compiled);
    assert_eq!(machine.statistics.tagged_pages, 1);
    // A retry from a plain block of the learnt page forgets it.
    machine.learn_tagged_page(BASE, true);
    block_at_base(&mut machine);
    assert!(machine.statistics.fetches[4] > compiled);
    assert_eq!(machine.statistics.tagged_pages, 1);
    // Another PE of the board compiles the page tagged without a retry.
    let mut other = setup(true);
    let current = other.current_variant(false, false);
    assert_eq!(
        other.page_variant(current, BASE).checks.top_byte,
        TopByte::Kept
    );
    other.code = alloc::sync::Arc::clone(&machine.code);
    assert_eq!(
        other.page_variant(current, BASE).checks.top_byte,
        TopByte::Lower
    );
    assert_eq!(other.statistics.tagged_pages, 0);
}
