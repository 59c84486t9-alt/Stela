//! Native fast-IPI writes (`x86_64::register_read::fast_ipi_request_thunk`,
//! `fast_ipi_status_thunk`) run on the machine's own frame and mirrors
//! against the engine's reference send (`fast_ipi::Table::send`), each over
//! a board of its own: every outcome and every word they leave agree.

use super::super::transitions::tests::run_native;
use super::*;
use crate::machine::fast_ipi::{Register, Sent, Table, Word};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering::SeqCst};

/// One CPU's words as a board holds them.
#[derive(Default)]
struct Cpu {
    status: AtomicU64,
    armed: AtomicBool,
    lines: AtomicU64,
    interrupt: AtomicU64,
    sleeping: AtomicBool,
}

/// Four CPUs in two clusters of two, of which PEs 0 to 2 run, and the
/// table over them.
struct Board {
    cpus: Vec<Cpu>,
    table: Table,
}

/// A CPU's (status, armed, lines, interrupt, sleeping).
type Words = (u64, bool, u64, u64, bool);

impl Board {
    fn new() -> alloc::boxed::Box<Self> {
        let cpus: Vec<Cpu> = (0..4).map(|_| Cpu::default()).collect();
        let words: Vec<Word> = (0..4)
            .map(|n| Word {
                cluster: (n / 2) as u8,
                cpu: (n % 2) as u8,
                status: cpus[n].status.as_ptr() as u64,
                armed: cpus[n].armed.as_ptr() as u64,
            })
            .collect();
        let table = Table::new(&words, 3, |pe| {
            (
                cpus[pe].lines.as_ptr() as u64,
                cpus[pe].interrupt.as_ptr() as u64,
                cpus[pe].sleeping.as_ptr() as u64,
            )
        });
        alloc::boxed::Box::new(Self { cpus, table })
    }

    fn words(&self) -> Vec<Words> {
        self.cpus
            .iter()
            .map(|cpu| {
                (
                    cpu.status.load(SeqCst),
                    cpu.armed.load(SeqCst),
                    cpu.lines.load(SeqCst),
                    cpu.interrupt.load(SeqCst),
                    cpu.sleeping.load(SeqCst),
                )
            })
            .collect()
    }

    fn set(&self, n: usize, status: u64, armed: bool, interrupt: u64, sleeping: bool) {
        let cpu = &self.cpus[n];
        cpu.status.store(status, SeqCst);
        cpu.armed.store(armed, SeqCst);
        cpu.interrupt.store(interrupt, SeqCst);
        cpu.sleeping.store(sleeping, SeqCst);
    }
}

/// PE `pe` at EL2 whose mirrors name `board`'s table and whose fast-IPI
/// writes complete natively in its state.
fn sender(board: &Board, pe: usize) -> Machine<FakeHost, NoDevices> {
    let mut machine = machine(&[]);
    machine.cpu.pstate = Pstate::reset(2);
    machine.derived_changed();
    let cluster = board.table.cluster_of(pe).unwrap();
    let own = (0..board.table.cpus())
        .find_map(|cpu| {
            board
                .table
                .target(cluster, cpu as u8)
                .filter(|target| target.pe == pe as u64)
        })
        .unwrap();
    machine.mirrors.fast_ipi = register_read::FastIpi {
        base: board.table.base(),
        clusters: u64::from(board.table.clusters()),
        cpus: u64::from(board.table.cpus()),
        cluster: u64::from(cluster),
        pe: pe as u64,
        status: own.status,
        wakes: 0,
        target: 0,
    };
    let state = machine.mirror_state();
    machine.mirrors.transition(state);
    machine.mirrors[FAST_IPI_WRITES].readable = 1;
    machine
}

/// The write natively with X5 `value`, as the reference's outcome, and
/// whether this PE's own interruption epoch moved.
fn native(
    machine: &mut Machine<FakeHost, NoDevices>,
    register: Register,
    value: u64,
) -> (Sent, bool) {
    let pc = GuestAddress(BASE);
    let thunk = match register {
        Register::RequestLocal => register_read::fast_ipi_request_thunk(pc, 5, false, FAST_IPI),
        Register::RequestGlobal => register_read::fast_ipi_request_thunk(pc, 5, true, FAST_IPI),
        _ => register_read::fast_ipi_status_thunk(pc, 5, FAST_IPI),
    };
    machine.cpu.state.x[5] = value;
    let epoch = machine.chain.snapshot().interrupt_epoch;
    let exit = run_native(machine, &thunk.code);
    let moved = machine.chain.snapshot().interrupt_epoch != epoch;
    let sent = match exit {
        (pc, kind) if pc == BASE && kind == ExitKind::System as u64 => Sent::Exit,
        (pc, kind) => {
            assert_eq!((pc, kind), (BASE + 4, ExitKind::Fallthrough as u64));
            match core::mem::take(&mut machine.mirrors.fast_ipi.wakes) {
                0 => Sent::Done,
                wakes => {
                    assert_eq!(wakes.count_ones(), 1);
                    Sent::Wake(wakes.trailing_zeros() as usize)
                }
            }
        }
    };
    (sent, moved)
}

/// Every request outcome, from every start a target's words can hold, by
/// two senders in different clusters: the thunk and the reference agree on
/// the outcome and on every word; only a wake moves the sender's own epoch,
/// so its run ends for the engine to wake the target.
#[test]
fn native_requests_agree_with_the_reference_send_on_every_outcome() {
    let starts = [
        (0, false, 0, false),
        (1, false, 0, false),
        (0, true, 0, false),
        (0, false, 0, true),
        (0, false, u64::MAX, true),
        (1, false, 7, true),
        (0, false, u64::MAX, false),
    ];
    let requests = [
        (Register::RequestLocal, 0),
        (Register::RequestLocal, 1),
        (Register::RequestLocal, 2),
        (Register::RequestLocal, 1 << 16 | 1),
        (Register::RequestLocal, 1 << 28 | 1),
        (Register::RequestLocal, 1 << 8 | 1),
        (Register::RequestLocal, 1 << 40 | 1),
        (Register::RequestGlobal, 0),
        (Register::RequestGlobal, 1),
        (Register::RequestGlobal, 1 << 16),
        (Register::RequestGlobal, 1 << 16 | 1),
        (Register::RequestGlobal, 2 << 16),
        (Register::RequestGlobal, 0xff << 16 | 0xff),
        (Register::RequestGlobal, 3 << 28 | 1 << 16),
        (Register::RequestGlobal, 1 << 24 | 1 << 16),
    ];
    let mut outcomes = alloc::collections::BTreeSet::new();
    for sender_pe in [0, 2] {
        for &(status, armed, interrupt, sleeping) in &starts {
            for &(register, value) in &requests {
                let (ours, reference) = (Board::new(), Board::new());
                for board in [&ours, &reference] {
                    for n in 0..4 {
                        board.set(n, status, armed, interrupt, sleeping);
                    }
                }
                let mut machine = sender(&ours, sender_pe);
                let (sent, moved) = native(&mut machine, register, value);
                let expected = reference.table.send(sender_pe, register, value);
                let case = (
                    sender_pe, status, armed, interrupt, sleeping, register, value,
                );
                assert_eq!(sent, expected, "{case:?}");
                assert_eq!(ours.words(), reference.words(), "{case:?}");
                assert_eq!(moved, matches!(sent, Sent::Wake(_)), "{case:?}");
                outcomes.insert(match sent {
                    Sent::Exit => 0,
                    Sent::Done => 1,
                    Sent::Wake(_) => 2,
                });
            }
        }
    }
    assert_eq!(outcomes.len(), 3, "every outcome reached");
}

/// IPI_SR: 1 clears this PE's PENDING and closes the native ISR_EL1 read,
/// 0 changes nothing, any other value exits; a closed cell exits.
#[test]
fn native_status_writes_clear_pending_and_close_the_isr_read() {
    let board = Board::new();
    let mut machine = sender(&board, 1);
    board.set(1, 1, false, 0, false);
    machine.mirrors.interrupt_status.readable = u64::MAX;
    assert_eq!(
        native(&mut machine, Register::Status, 2),
        (Sent::Exit, false)
    );
    assert_eq!(board.cpus[1].status.load(SeqCst), 1);
    assert_eq!(
        native(&mut machine, Register::Status, 0),
        (Sent::Done, false)
    );
    assert_eq!(board.cpus[1].status.load(SeqCst), 1);
    assert_eq!(machine.mirrors.interrupt_status.readable, u64::MAX);
    assert_eq!(
        native(&mut machine, Register::Status, 1),
        (Sent::Done, false)
    );
    assert_eq!(board.cpus[1].status.load(SeqCst), 0);
    assert_eq!(machine.mirrors.interrupt_status.readable, 0);
    assert_eq!(board.cpus[0].status.load(SeqCst), 0, "only its own");
    machine.mirrors[FAST_IPI_WRITES].readable = 0;
    board.set(1, 1, false, 0, false);
    assert_eq!(
        native(&mut machine, Register::Status, 1),
        (Sent::Exit, false)
    );
    assert_eq!(board.cpus[1].status.load(SeqCst), 1);
}
