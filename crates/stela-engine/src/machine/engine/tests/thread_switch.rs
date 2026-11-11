//! Native MSR TPIDR_EL1 (`register_read::thread_switch_thunk`) against the
//! engine path: the register, its read cells in every state and the
//! suspended threads end up as the engine's MSR leaves them.

use super::*;

const MSR: u32 = 0xd518_d089; // msr tpidr_el1, x9
const MRS: u32 = 0xd538_d088; // mrs x8, tpidr_el1

/// A machine at EL2 whose TPIDR_EL1 read cell is open there and in GL2,
/// and whose write cell a first engine-path write of `first` opened.
fn opened(first: u64) -> Machine<FakeHost, NoDevices> {
    let mut machine = machine(&[MRS, MSR]);
    machine.cpu.pstate = Pstate::reset(2);
    machine.derived_changed();
    let base = machine.cpu.pc;
    machine.system_instruction(MRS).unwrap();
    // A read in GL2 opened its cell there too (`Mirrors::update` keeps it).
    machine.mirrors.banks[mirror_state(2, true)][THREAD_POINTER_MIRROR] =
        machine.mirrors[THREAD_POINTER_MIRROR];
    machine.cpu.state.x[9] = first;
    machine.system_instruction(MSR).unwrap();
    let cell = machine.mirrors[written_cell(THREAD_POINTER_WRITE)];
    assert_eq!(cell.readable, 1, "a plain write opens the cell");
    assert_eq!(
        Some(cell.value),
        machine.cpu.registers.address(SystemRegister::TPIDR_EL1, 0)
    );
    machine.cpu.pc = base + 4;
    machine
}

/// What a write changes, for comparison: of the cells, which are open and
/// TPIDR_EL1's reads (other cells hold addresses of each machine's own).
fn observed(machine: &Machine<FakeHost, NoDevices>) -> alloc::string::String {
    let suspended: Vec<_> = machine.suspended().iter().collect();
    let open: Vec<Vec<u64>> = machine
        .mirrors
        .banks
        .iter()
        .map(|cells| cells.iter().map(|cell| cell.readable).collect())
        .collect();
    let reads: Vec<_> = machine
        .mirrors
        .banks
        .iter()
        .map(|cells| cells[THREAD_POINTER_MIRROR])
        .collect();
    alloc::format!(
        "pc={:#x} tpidr={:#x} x={:?} open={open:?} reads={reads:?} suspended={suspended:?} log={:?}",
        machine.cpu.pc,
        machine.cpu.registers.get(SystemRegister::TPIDR_EL1, 0),
        machine.cpu.state.x,
        machine.mirrors.switches,
    )
}

#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
#[test]
fn native_thread_switches_match_the_engine_path() {
    use super::super::transitions::tests::run_native;
    let (mut engine, mut native) = (opened(0x1000), opened(0x1000));
    let pc = engine.cpu.pc;
    assert_eq!(written_register(pc, MSR), Some((THREAD_POINTER_WRITE, 9)));
    let cell = cell_place(written_cell(THREAD_POINTER_WRITE));
    let thunk = register_read::thread_switch_thunk(GuestAddress(pc), 9, cell, &THREAD_SWITCH);
    assert_eq!(observed(&engine), observed(&native));
    // Switches to other threads, back to an earlier one, and to the same
    // thread, with the frame and link of each: one log's worth, then one
    // more, which the full log leaves to the engine.
    let values = [
        0x2000, 0x3000, 0x3000, 0x1000, 0x4000, 0, 0x5000, 0x2000, 0x6000, 0x7000,
    ];
    let mut exited = 0;
    for (turn, &value) in values.iter().enumerate() {
        for machine in [&mut engine, &mut native] {
            machine.cpu.pc = pc;
            machine.cpu.state.x[9] = value;
            machine.cpu.state.x[29] = 0xffff_fe00_0000_2900 + turn as u64 * 16;
            machine.cpu.state.x[30] = 0xffff_fe00_0000_3000 + turn as u64 * 4;
        }
        engine.system_instruction(MSR).unwrap();
        let (next, kind) = run_native(&mut native, &thunk.code);
        if kind == ExitKind::System as u64 {
            // The log is full: the engine takes it first, as `execute`
            // does when native code returns, then the exit.
            assert_eq!(native.mirrors.switches.len, register_read::SWITCHES as u64);
            assert_eq!(next, pc);
            native.take_thread_switches();
            native.system_instruction(MSR).unwrap();
            exited += 1;
        } else {
            assert_eq!((next, kind), (pc + 4, ExitKind::Fallthrough as u64));
            native.cpu.pc = next;
        }
    }
    assert_eq!(exited, 1, "only the write after a full log exits");
    native.take_thread_switches();
    assert_eq!(observed(&engine), observed(&native));
    let gl2 = native.mirrors.banks[mirror_state(2, true)][THREAD_POINTER_MIRROR];
    assert_eq!((gl2.readable, gl2.value), (1, 0x7000));
    assert!(native.suspended().contains_key(&0x6000));
}
