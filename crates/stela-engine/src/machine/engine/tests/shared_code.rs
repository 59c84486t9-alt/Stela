//! Host model of a launch storm's shared code: processes, each its own
//! ASID, map the same frames (the dyld shared cache, one copy of every
//! system framework) at the same VAs, as every process of one boot does,
//! and run the same blocks. A block's key is its PC, its frame and its
//! variant, with no address space in it, so the board compiles each block
//! once for all of them. The same frames mapped at another VA are compiled
//! again: a block's meaning depends on its PC (ADR, ADRP, BL targets and
//! return addresses), so that is required, not lost sharing.

use super::*;

const MSR_TTBR0_EL1_X0: u32 = 0xd518_2000;
const RET: u32 = 0xd65f_03c0;
const PAGE: u64 = 0x1000;
/// Shared pages every process runs, and blocks in each.
const PAGES: u64 = 4;
const BLOCKS: u64 = 8;
const PROCESSES: u64 = 32;

/// Fetch every block of the shared pages from `base`.
fn run_shared(machine: &mut Machine<FakeHost, NoDevices>, base: u64) {
    for page in 0..PAGES {
        for block in 0..BLOCKS {
            let pc = base + page * PAGE + 4 * block;
            assert!(matches!(
                machine.fetch_block(pc, false),
                Ok(Fetched::Block(_))
            ));
        }
    }
}

/// Blocks compiled so far: fetches that found no block.
fn compiled(machine: &Machine<FakeHost, NoDevices>) -> u64 {
    machine.statistics.fetches[4]
}

#[test]
fn processes_mapping_shared_code_at_one_address_compile_it_once() {
    let mut machine = machine(&[RET; (PAGES * PAGE / 4) as usize]);
    let frames: Vec<u64> = (0..PAGES).map(|page| BASE + page * PAGE).collect();
    paged_space(&mut machine, 0, &frames);
    let ttbr0 = machine.cpu.read(SystemRegister::TTBR0_EL1);
    let mut per_process = Vec::new();
    for process in 0..PROCESSES {
        // Another process: another ASID, the same mappings.
        machine.cpu.state.x[0] = ttbr0 & !(0xff << 48) | process << 48;
        machine.system_instruction(MSR_TTBR0_EL1_X0).unwrap();
        let before = compiled(&machine);
        run_shared(&mut machine, BASE);
        per_process.push(compiled(&machine) - before);
    }
    assert_eq!(per_process[0], PAGES * BLOCKS, "the first process compiles");
    assert!(
        per_process[1..].iter().all(|&count| count == 0),
        "later processes compile nothing: {per_process:?}"
    );
    assert_eq!(machine.code.blocks.live() as u64, PAGES * BLOCKS);

    // The same frames at another VA (2 MiB up) in another table: each
    // block is compiled again for its own PC, and only once.
    let [_, l2, l3] = SPACES_TABLES[1];
    paged_space(&mut machine, 1, &frames);
    write_entry(&mut machine, l2 + 8, (BASE + l3) | 0b11);
    let moved = BASE + (1 << 21);
    let before = compiled(&machine);
    run_shared(&mut machine, moved);
    assert_eq!(compiled(&machine) - before, PAGES * BLOCKS);
    let before = compiled(&machine);
    run_shared(&mut machine, moved);
    run_shared(&mut machine, BASE);
    assert_eq!(compiled(&machine), before);
    assert_eq!(machine.code.blocks.live() as u64, 2 * PAGES * BLOCKS);
}
