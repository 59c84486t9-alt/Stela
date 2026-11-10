//! Host timing of the engine's fetch and exit path on PEs of one board that
//! run the same blocks: what each operation costs as threads are added. A
//! path that writes a line every PE's operations write (a shared count, an
//! `Arc`'s count) costs more with each thread; one that writes only the
//! PE's own state costs the same. The manual test prints nanoseconds per
//! round for 1, 4 and 8 threads, with the shared writes the path made up
//! to build 44 put back (`legacy`) and without; the other checks that the
//! counts the path keeps per PE reach the board's.

use super::super::board;
use super::super::parallel::{Hub, Kick};
use super::*;

const RET: u32 = 0xd65f_03c0;
const B8: u32 = 0x1400_0002; // b .+8
/// Hot two-block groups every thread runs.
const GROUPS: u64 = 8;

struct NoKick;
impl Kick for NoKick {
    fn kick(&self, _pe: usize) {}
}

/// Groups of a block ending in a direct branch to a RET block.
fn words() -> Vec<u32> {
    [B8, 0, RET, 0]
        .iter()
        .copied()
        .cycle()
        .take(FETCH_PAGE as usize / 4)
        .collect()
}

/// One machine of a board of `pes` over a window of `memory`, and the
/// board's other machines' maker.
struct Board {
    hub: Arc<Hub>,
    code: Arc<board::Code>,
    variants: Arc<numbering::Registry<Variant>>,
    reads: Arc<numbering::Registry<Encoding>>,
    writes: Arc<numbering::Registry<Encoding>>,
}

impl Board {
    fn new(pes: usize, memory: &mut [u8]) -> Self {
        let address = memory.as_mut_ptr() as usize;
        let mut template = machine(&words());
        template.code = Arc::new(board::Code::new(
            board::slot_capacity(Some(memory.len())),
            chain::MIN_LOOKUP_ENTRIES,
            Some(CodeWindow {
                exec: address,
                write: address,
                bytes: memory.len(),
            }),
        ));
        Self {
            hub: Hub::new(pes, NoKick),
            code: Arc::clone(&template.code),
            variants: Arc::clone(&template.variants),
            reads: Arc::clone(&template.stored_reads),
            writes: Arc::clone(&template.stored_writes),
        }
    }

    fn machine(&self, pe: usize) -> Machine<FakeHost, NoDevices> {
        let mut machine = machine(&words());
        machine.code = Arc::clone(&self.code);
        machine.variants = Arc::clone(&self.variants);
        machine.stored_reads = Arc::clone(&self.reads);
        machine.stored_writes = Arc::clone(&self.writes);
        machine.code_hub = Some(Arc::clone(&self.hub));
        machine.current = pe;
        machine
    }
}

/// One round on `machine`: for each hot group, the fetch of its first
/// block, the System-exit word count at its end, the direct exit's link
/// attempt, the fetch of its RET block and the return's dispatcher
/// attempt. With `legacy`, the shared writes the path made before: a
/// clone of the board's `Arc` at each link attempt, a count on the
/// block's record at each exit and on its ring part at each fetch.
fn round(machine: &mut Machine<FakeHost, NoDevices>, base: u64, legacy: bool) {
    for group in 0..GROUPS {
        let pc = base + 16 * group;
        for (pc, exit) in [(pc, ExitKind::Direct), (pc + 8, ExitKind::Return)] {
            let Ok(Fetched::Block(slot)) = machine.fetch_block(pc, false) else {
                panic!("a block at {pc:#x}");
            };
            let terminal = machine.code.blocks[slot].terminal_pc();
            machine.exit_word(slot, terminal).unwrap();
            match exit {
                ExitKind::Direct => {
                    machine.link(slot, pc + 8, ExitKind::Direct);
                }
                _ => machine.link_dynamic(slot, 0),
            }
            if legacy {
                let code = Arc::clone(&machine.code);
                let record = code.blocks.record(slot);
                record.taken.fetch_add(1, Ordering::Relaxed);
                if let Some(arena) = &code.arena
                    && let Some(part) = arena.part_of(code.blocks[slot].code.0)
                {
                    arena.ring.entered(part);
                }
                drop(core::hint::black_box(code));
            }
        }
    }
}

/// Nanoseconds per round on each of `threads` PEs running the same blocks.
fn per_round(threads: usize, legacy: bool) -> u64 {
    const ROUNDS: u64 = 20_000;
    let mut memory = vec![0u8; 16 * 4096];
    let board = Board::new(threads, &mut memory);
    let base = board.machine(0).cpu.pc;
    let barrier = std::sync::Barrier::new(threads);
    let times: Vec<u64> = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..threads)
            .map(|pe| {
                let (board, barrier) = (&board, &barrier);
                scope.spawn(move || {
                    let mut machine = board.machine(pe);
                    for _ in 0..ROUNDS / 10 {
                        round(&mut machine, base, legacy);
                    }
                    barrier.wait();
                    let started = std::time::Instant::now();
                    for _ in 0..ROUNDS {
                        round(&mut machine, base, legacy);
                    }
                    let elapsed = started.elapsed().as_nanos() as u64 / ROUNDS;
                    machine.flush_exits();
                    machine.flush_entered();
                    elapsed
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect()
    });
    times.iter().sum::<u64>() / threads as u64
}

/// `cargo test -p stela-engine --release --lib shared_path_scaling --
/// --ignored --nocapture`
#[test]
#[ignore = "manual: opt-in timing"]
fn shared_path_scaling() {
    for threads in [1, 4, 8] {
        let before = per_round(threads, true);
        let after = per_round(threads, false);
        std::println!(
            "SHARING threads={threads} ns_per_round legacy={before} now={after} \
             ops_per_round={}",
            GROUPS * 2
        );
    }
}

/// The counts a PE keeps for itself reach the board's records and ring:
/// every exit at a block's last instruction counts once in the exit words,
/// and every fetch of a block once in its ring part, after the PE flushes.
#[test]
fn kept_counts_reach_the_board() {
    let mut memory = vec![0u8; 16 * 4096];
    let board = Board::new(2, &mut memory);
    let base = board.machine(0).cpu.pc;
    let mut machines = [board.machine(0), board.machine(1)];
    let rounds = 37;
    for _ in 0..rounds {
        for machine in &mut machines {
            round(machine, base, false);
        }
    }
    // Kept or added, the words count every exit.
    let words = machines[0].exit_words();
    let pending: u64 = machines[1]
        .exit_pending
        .iter()
        .map(|held| u64::from(held.count))
        .sum();
    let exits = 2 * rounds * GROUPS;
    assert_eq!(
        words.get(&B8).copied().unwrap_or(0) + words.get(&RET).copied().unwrap_or(0) + pending,
        2 * exits
    );
    for machine in &mut machines {
        machine.flush_exits();
        machine.flush_entered();
        assert_eq!(machine.entered_total, 0);
    }
    let words = machines[0].exit_words();
    assert_eq!(words.get(&B8), Some(&exits));
    assert_eq!(words.get(&RET), Some(&exits));
}
