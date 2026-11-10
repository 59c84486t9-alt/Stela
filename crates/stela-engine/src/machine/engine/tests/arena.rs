//! The board's code arena ([`board::Arena`]): a host's whole code window
//! that the engine allocates itself, which every machine of a board shares.
use super::super::board;
use super::super::parallel::{Hub, Kick};
use super::*;

const RET: u32 = 0xd65f_03c0;
const ADD: u32 = 0x9100_0400; // add x0, x0, #1
/// A window of four parts of a page each: a few blocks fill a part.
const WINDOW: usize = 4 * 4096;

struct NoKick;
impl Kick for NoKick {
    fn kick(&self, _pe: usize) {}
}

/// Memory a test's window lies in. Tests run no native code, so it needs
/// no execute permission: its two views are one.
fn window(memory: &mut [u8]) -> CodeWindow {
    let address = memory.as_mut_ptr() as usize;
    CodeWindow {
        exec: address,
        write: address,
        bytes: memory.len(),
    }
}

/// A machine of RET instructions over four pages whose code goes to the
/// window over `memory`, alone.
fn arena_machine(memory: &mut [u8]) -> Machine<FakeHost, NoDevices> {
    arena_machine_of(&vec![RET; 4 * FETCH_PAGE as usize / 4], memory)
}

/// A machine of `words` whose code goes to the window over `memory`.
fn arena_machine_of(words: &[u32], memory: &mut [u8]) -> Machine<FakeHost, NoDevices> {
    let mut machine = machine(words);
    machine.code = Arc::new(board::Code::new(
        board::slot_capacity(Some(WINDOW)),
        chain::MIN_LOOKUP_ENTRIES,
        Some(window(memory)),
    ));
    machine
}

/// Each live block's code address: none is shared, as a part is reused only
/// after its blocks went.
fn live_codes(machine: &Machine<FakeHost, NoDevices>) -> Vec<usize> {
    let blocks = &machine.code.blocks;
    let mut codes: Vec<usize> = (0..blocks.len())
        .filter_map(|slot| blocks.installed(slot))
        .map(|block| block.code.0)
        .collect();
    codes.sort_unstable();
    codes
}

/// The ring's current generation: parts filled so far.
fn generation(machine: &Machine<FakeHost, NoDevices>) -> u32 {
    machine
        .code
        .arena
        .as_ref()
        .expect("an arena")
        .ring
        .generation()
}

#[test]
fn the_serial_lane_installs_into_its_arena_and_retires_parts_in_turn() {
    let mut memory = vec![0u8; WINDOW];
    let range = memory.as_ptr() as usize..memory.as_ptr() as usize + WINDOW;
    let mut machine = arena_machine(&mut memory);
    let base = machine.cpu.pc;
    let mut fetched = 0;
    while generation(&machine) < 8 {
        assert!(fetched < 20_000, "the ring goes round");
        let pc = base + 4 * (fetched % 4096);
        let Ok(Fetched::Block(slot)) = machine.fetch_block(pc, false) else {
            panic!("a block at {pc:#x}")
        };
        let block = machine.code.blocks.installed(slot).expect("a live block");
        assert!(range.contains(&block.code.0));
        fetched += 1;
    }
    assert!(machine.statistics.code_evictions >= 4);
    // Every byte went to the window, none to the host's arena.
    assert!(machine.host.installed.is_empty());
    assert_eq!(machine.statistics.code_discards.iter().sum::<u64>(), 0);
    // No two live blocks share code: a retired part's blocks went first.
    let codes = live_codes(&machine);
    assert!(codes.windows(2).all(|pair| pair[0] != pair[1]));
    // Retired slots served later blocks.
    assert!(machine.code.blocks.len() < fetched as usize);
    // Every indexed block is live.
    let cache = machine.code.cache();
    assert!(
        cache
            .index
            .sweep(None)
            .all(|(_, slot)| machine.code.blocks.record(slot).live())
    );
}

/// Two machines of one board: the second joins the first's code.
fn shared_pair(
    memory: &mut [u8],
) -> (
    Machine<FakeHost, NoDevices>,
    Machine<FakeHost, NoDevices>,
    Arc<Hub>,
) {
    let hub = Hub::new(2, NoKick);
    let mut first = arena_machine(memory);
    let mut second = machine(&vec![RET; 4 * FETCH_PAGE as usize / 4]);
    second.code = Arc::clone(&first.code);
    // A board's machines share their numbering ([`numbering`]).
    second.variants = Arc::clone(&first.variants);
    second.stored_reads = Arc::clone(&first.stored_reads);
    second.stored_writes = Arc::clone(&first.stored_writes);
    first.code_hub = Some(Arc::clone(&hub));
    second.code_hub = Some(Arc::clone(&hub));
    (first, second, hub)
}

#[test]
fn a_block_one_pe_installed_runs_on_another_and_the_first_install_wins() {
    let mut memory = vec![0u8; WINDOW];
    let (mut first, mut second, _hub) = shared_pair(&mut memory);
    let pc = first.cpu.pc;
    let Ok(Fetched::Block(slot)) = first.fetch_block(pc, false) else {
        panic!("a block")
    };
    // The other PE finds it in the board's index or table and compiles
    // nothing.
    let Ok(Fetched::Block(found)) = second.fetch_block(pc, false) else {
        panic!("a block")
    };
    assert_eq!(found, slot);
    assert_eq!(second.statistics.compiled, 0);
    assert_eq!(second.statistics.fetches[4], 0);
    // A PE that compiled the block too, as it would have racing the
    // first, keeps the first's: its own slot goes back, its code stays
    // unreachable until its part goes.
    let block = &first.code.blocks[slot];
    let (physical, variant) = (block.physical, first.block_variant(slot));
    let Ok(Fetched::Block(raced)) = second.compile(pc, physical, variant) else {
        panic!("a block")
    };
    assert_eq!(raced, slot);
    assert_eq!(second.statistics.lost_installs, 1);
    assert_eq!(first.code.blocks.live(), 1);
    assert_eq!(first.code.cache().index.len(), 1);
}

#[test]
fn a_part_is_reused_only_after_every_pe_left_its_section() {
    let mut memory = vec![0u8; WINDOW];
    let (mut first, _second, hub) = shared_pair(&mut memory);
    // PE 1 runs native code: inside its section, where it may hold any
    // code address it read.
    hub.board.grace.enter(1);
    // The counter moves on with each read, so each wait round ends soon;
    // PE 1 leaves at the 50th turn of waiting.
    first.host.counter_step = first.profile.counter_frequency / 50;
    let leaver = Arc::clone(&hub);
    first.host.on_relax = Some(Box::new(move |turns| {
        if turns == 50 {
            leaver.board.grace.leave(1);
        }
    }));
    let base = first.cpu.pc;
    let mut fetched = 0;
    // The ring goes round once while PE 1 is inside: the first part
    // retired after PE 1 entered is the first reuse that waits.
    while generation(&first) < 8 {
        assert!(fetched < 20_000, "the ring goes round");
        let pc = base + 4 * (fetched % 4096);
        let Ok(Fetched::Block(_)) = first.fetch_block(pc, false) else {
            panic!("a block at {pc:#x}")
        };
        fetched += 1;
    }
    // The reuse waited for PE 1 to leave, through overdue rounds, which the
    // board reported once.
    assert!(first.host.relaxes >= 50);
    assert!(!hub.board.overdue(), "the overrun was reported before");
    let reported = first.take_unmodeled();
    assert_eq!(reported.len(), 1);
    let codes = live_codes(&first);
    assert!(codes.windows(2).all(|pair| pair[0] != pair[1]));
}

#[test]
fn an_invalidated_page_leaves_every_pe_and_its_code_stays_until_its_part_goes() {
    let mut memory = vec![0u8; WINDOW];
    let (mut first, mut second, hub) = shared_pair(&mut memory);
    let pc = first.cpu.pc;
    let Ok(Fetched::Block(slot)) = first.fetch_block(pc, false) else {
        panic!("a block")
    };
    assert!(matches!(second.fetch_block(pc, false), Ok(Fetched::Block(found)) if found == slot));
    // PE 1 runs the block while PE 0 posts an IC IVAU of its page; each
    // applies it to its own caches, the board's index forgets the page once.
    hub.board.grace.enter(1);
    let physical = first.code.blocks[slot].physical;
    first.invalidate_code_page(physical);
    second.invalidate_code_page(physical);
    assert_eq!(first.statistics.code_invalidations, 1);
    assert_eq!(second.statistics.code_invalidations, 1);
    assert_eq!(first.code.cache().index.len(), 0);
    // The running block's code is not taken away.
    assert!(first.code.blocks.record(slot).live());
    // Both PEs compile the page again; the second finds the first's.
    let Ok(Fetched::Block(again)) = first.fetch_block(pc, false) else {
        panic!("a block")
    };
    assert_ne!(again, slot);
    assert!(matches!(second.fetch_block(pc, false), Ok(Fetched::Block(found)) if found == again));
    hub.board.grace.leave(1);
}

#[test]
fn a_posted_invalidation_takes_away_a_block_published_after_the_posters_forget() {
    let mut memory = vec![0u8; WINDOW];
    let (mut first, mut second, _hub) = shared_pair(&mut memory);
    let pc = first.cpu.pc;
    let Ok(Fetched::Block(slot)) = first.fetch_block(pc, false) else {
        panic!("a block")
    };
    let physical = first.code.blocks[slot].physical;
    // PE 0 writes the page and forgets it on the board at its IC IVAU.
    // PE 1 read the old bytes before the write and publishes their block
    // only now, as a compile outside its section may.
    first.invalidate_code_page(physical);
    assert_eq!(first.code.cache().index.len(), 0);
    let variant = first.block_variant(slot);
    let Ok(Fetched::Block(stale)) = second.compile(pc, physical, variant) else {
        panic!("a block")
    };
    first.host.ram[0..4].copy_from_slice(&ADD.to_le_bytes());
    assert_eq!(first.code.cache().index.page(physical).count(), 1);
    assert_eq!(first.stale_code().stale, 1);
    // PE 1 applies the post after it published: the block goes.
    second.invalidate_posted_code_page(physical);
    assert_eq!(first.code.cache().index.page(physical).count(), 0);
    assert!(first.code.blocks.record(stale).live(), "its code stays");
    assert_eq!(first.stale_code().stale, 0);
    assert_eq!(second.statistics.code_invalidations, 1);
}

/// A guest access fault at `offset` of a block's native code.
fn access_fault(offset: usize) -> NativeFault {
    NativeFault {
        origin: crate::machine::NativeFaultOrigin::Exception,
        trap: 13,
        error_code: 0,
        spills: stela_compiler::block::HostSpillSnapshot::new(),
        registers: stela_compiler::block::HostGprSnapshot::legacy([0; 16]),
        offset,
        address: 0x7a_80d4_0000,
        write: true,
        cause: FaultCause::NonCanonical,
    }
}

#[test]
fn a_pe_faults_in_a_block_another_pe_retired_and_still_finds_its_rows() {
    let mut memory = vec![0u8; WINDOW];
    let (mut first, mut second, hub) = shared_pair(&mut memory);
    let pc = first.cpu.pc;
    let Ok(Fetched::Block(slot)) = first.fetch_block(pc, false) else {
        panic!("a block")
    };
    // PE 0 runs the block, inside its section, while PE 1 takes the
    // block's part away as the ring retires it.
    hub.board.grace.enter(0);
    let code = first.code.blocks[slot].code.0;
    let arena = first.code.arena.as_ref().expect("an arena");
    let part = (code - arena.window.exec) / arena.part_bytes;
    let range = arena.window.exec + part * arena.part_bytes
        ..arena.window.exec + (part + 1) * arena.part_bytes;
    second.evict_code(range);
    assert!(!first.code.blocks.record(slot).live());
    // The slot still holds the block, and its rows, until PE 0 passes.
    assert!(first.code.blocks.get(slot).is_some());
    assert!(first.code.cache().recovery.get(&slot).is_some());
    let step = first.native_fault(slot, access_fault(0), 0, None);
    assert!(
        !matches!(&step, Err(Stop::NativeFailure(failure))
            if failure.reason == NativeFailureReason::UnknownCode),
        "{step:?}"
    );
    hub.board.grace.leave(0);
}

#[test]
fn a_lost_install_says_so_and_holds_no_rows() {
    let mut memory = vec![0u8; WINDOW];
    let (mut first, mut second, _hub) = shared_pair(&mut memory);
    let pc = first.cpu.pc;
    let Ok(Fetched::Block(slot)) = first.fetch_block(pc, false) else {
        panic!("a block")
    };
    let (physical, variant) = (first.code.blocks[slot].physical, first.block_variant(slot));
    let lost = first.code.blocks.len();
    second.current = 1;
    let Ok(Fetched::Block(held)) = second.compile(pc, physical, variant) else {
        panic!("a block")
    };
    assert_eq!(held, slot);
    let report = second.board_slot(lost);
    assert!(report.lost && !report.live && !report.rows, "{report:?}");
    assert_eq!(report.installer, 1);
}

#[test]
fn a_device_stub_one_pe_learnt_is_a_stub_on_every_pe() {
    const LDR: u32 = 0xb940_0016; // ldr w22, [x0]
    let mut memory = vec![0u8; WINDOW];
    let (mut first, mut second, _hub) = shared_pair(&mut memory);
    let pc = first.cpu.pc;
    let Ok(Fetched::Block(slot)) = first.fetch_block(pc, false) else {
        panic!("a block")
    };
    let physical = first.code.blocks[slot].physical;
    first.host.ram[0..4].copy_from_slice(&LDR.to_le_bytes());
    second.host.ram[0..4].copy_from_slice(&LDR.to_le_bytes());
    // PE 0 met a device at the load: the page compiles again, the load's
    // block a stub whose System exit is the site's access.
    first.learn_device_site(physical);
    let Ok(Fetched::Block(stub)) = first.fetch_block(pc, false) else {
        panic!("a stub")
    };
    assert!(first.device_stub(stub, pc));
    // PE 1 never met the device and runs PE 0's stub: its exit is the
    // site's access there too, not a System instruction.
    let Ok(Fetched::Block(found)) = second.fetch_block(pc, false) else {
        panic!("a block")
    };
    assert_eq!(found, stub);
    assert!(!second.device_site(physical));
    assert!(second.device_stub(found, pc));
}

#[test]
fn a_pe_that_joins_the_board_reads_the_count_natively_as_its_compiler_does() {
    const MRS_CNTVCT: u32 = 0xd53b_e04a; // mrs x10, cntvct_el0
    let words = [ADD, MRS_CNTVCT, RET];
    let mut memory = vec![0u8; WINDOW];
    let hub = Hub::new(2, NoKick);
    let mut first = arena_machine_of(&words, &mut memory);
    first.host.tsc_counter = Some((5, 7));
    let pc = first.cpu.pc;
    let Ok(Fetched::Block(slot)) = first.fetch_block(pc, false) else {
        panic!("a block")
    };
    // Its count read completes in a thunk that reads the PE's clock
    // reader, which compiling it set up on PE 0.
    assert!(!first.code.blocks[slot].successors.is_empty());
    assert!(first.clock.reads_natively());
    hub.share_code(&first.code);
    // PE 1 starts on the board's code and compiles nothing: it runs PE 0's
    // thunk, which must find a reader that follows the host counter.
    let mut second = machine(&words);
    second.host.tsc_counter = Some((5, 7));
    second.code = Arc::clone(&first.code);
    second.variants = Arc::clone(&first.variants);
    assert!(!second.clock.reads_natively());
    second.join_code(&hub);
    let Ok(Fetched::Block(found)) = second.fetch_block(pc, false) else {
        panic!("a block")
    };
    assert_eq!(found, slot);
    assert_eq!(second.statistics.compiled, 0);
    assert!(second.clock.reads_natively());
    assert!(second.count_reads_natively());
}

#[test]
fn a_hub_notes_the_pages_of_blocks_compiled_before_it() {
    let mut memory = vec![0u8; WINDOW];
    let mut first = arena_machine(&mut memory);
    let pc = first.cpu.pc;
    let Ok(Fetched::Block(slot)) = first.fetch_block(pc, false) else {
        panic!("a block")
    };
    let physical = first.code.blocks[slot].physical;
    let hub = Hub::new(2, NoKick);
    assert!(!hub.has_code(physical));
    hub.note_code(&first.code);
    assert!(hub.has_code(physical));
}

#[test]
fn a_word_admitted_as_udf_is_no_stale_code() {
    const UNALLOCATED: u32 = 0xe7ff_deff; // admitted as UDF
    let mut memory = vec![0u8; WINDOW];
    let mut machine = arena_machine_of(&[ADD, UNALLOCATED], &mut memory);
    let pc = machine.cpu.pc;
    let Ok(Fetched::Block(slot)) = machine.fetch_block(pc, false) else {
        panic!("a block")
    };
    assert_eq!(machine.code.blocks[slot].instructions, 2);
    assert_ne!(
        machine.host.ram[4..8],
        machine.admit(UNALLOCATED).to_le_bytes()
    );
    let report = machine.stale_code();
    assert_eq!((report.stale, report.admitted), (0, 1), "{report:?}");
}

/// A machine alone or one of a pair whose board gives only `slots` block
/// slots: the slots run out long before the window does.
fn starved(machine: &mut Machine<FakeHost, NoDevices>, memory: &mut [u8], slots: u32) {
    machine.code = Arc::new(board::Code::new(
        slots,
        chain::MIN_LOOKUP_ENTRIES,
        Some(window(memory)),
    ));
}

#[test]
fn a_board_out_of_slots_moves_its_ring_on_instead_of_stopping() {
    let mut memory = vec![0u8; WINDOW];
    let mut machine = arena_machine(&mut memory);
    starved(&mut machine, &mut memory, 8);
    let hub = Hub::new(2, NoKick);
    machine.code_hub = Some(Arc::clone(&hub));
    let base = machine.cpu.pc;
    for fetched in 0..64 {
        let pc = base + 4 * fetched;
        let Ok(Fetched::Block(slot)) = machine.fetch_block(pc, false) else {
            panic!("a block at {pc:#x}")
        };
        assert!(machine.code.blocks.installed(slot).is_some());
    }
    let report = machine.code.report();
    assert!(report.forced > 0, "{report:?}");
    assert_eq!(report.forced, report.retired);
    assert!(machine.code.blocks.len() <= 8);
    // Nothing was discarded: the ring gave the slots back.
    assert_eq!(machine.statistics.code_discards.iter().sum::<u64>(), 0);
    let codes = live_codes(&machine);
    assert!(codes.windows(2).all(|pair| pair[0] != pair[1]));
    let cache = machine.code.cache();
    assert!(
        cache
            .index
            .sweep(None)
            .all(|(_, slot)| machine.code.blocks.record(slot).live())
    );
}
