use super::super::tests::{BASE, board, installed_code, native_fault_site_in_entry};
use super::*;
use stela_compiler::block::RecoverySiteKind;

/// Registers that read their PA's low 16 bits with the top bit set,
/// recording every access in order.
#[derive(Default)]
struct Registers {
    accesses: Vec<(u64, u8, Option<u64>)>,
}

impl Devices for Registers {
    fn read(&mut self, _: usize, physical: u64, bytes: u8, _: u64) -> Result<u64, DeviceError> {
        self.accesses.push((physical, bytes, None));
        Ok(0x8000_0000 | (physical & 0xffff))
    }
    fn write(
        &mut self,
        _: usize,
        physical: u64,
        bytes: u8,
        value: u64,
        _: u64,
    ) -> Result<(), DeviceError> {
        self.accesses.push((physical, bytes, Some(value)));
        Ok(())
    }
    fn lines(&mut self, _: usize, _: u64) -> Lines {
        Lines::default()
    }
}

const DEVICE: u64 = 0x2_3b3c_0a00;

fn device_fault(offset: usize, address: u64, write: bool) -> NativeExit {
    NativeExit::Fault(NativeFault {
        origin: crate::machine::NativeFaultOrigin::Exception,
        trap: 14,
        error_code: 0,
        spills: stela_compiler::block::HostSpillSnapshot::new(),
        registers: stela_compiler::block::HostGprSnapshot::legacy([0; 16]),
        offset,
        address,
        write,
        cause: FaultCause::Device { physical: address },
    })
}

fn exit(next_pc: u64, kind: ExitKind) -> NativeExit {
    NativeExit::Exit {
        next_pc,
        kind: kind as u64,
    }
}

#[test]
fn a_device_site_faults_once_then_completes_without_a_fault() {
    // add x3, x3, #1; ldr w0, [x1]; add x2, x2, #1; ret
    let words = [0x9100_0463, 0xb940_0020, 0x9100_0442, 0xd65f_03c0];
    let mut machine = board(&words, Registers::default(), Vec::new());
    machine.cpu.state.x[1] = DEVICE;
    let (_, offset) =
        native_fault_site_in_entry(&mut machine, BASE, BASE + 4, RecoverySiteKind::GuestAccess);
    // The first access faults, completes and is learned.
    machine.host.exits.push(device_fault(offset, DEVICE, false));
    machine.step().unwrap();
    assert_eq!(machine.devices.accesses, [(DEVICE, 4, None)]);
    assert_eq!(machine.cpu.state.x[0], 0x8000_0a00);
    assert_eq!(machine.cpu.pc, BASE + 8);
    assert!(machine.device_site(BASE + 4));
    assert!(machine.page_has_device_sites(BASE));
    // The page compiles again: the block at BASE ends before the site.
    machine.cpu.pc = BASE;
    let Ok(Fetched::Block(first)) = machine.fetch_block(BASE, false) else {
        panic!("a block");
    };
    assert_eq!(machine.blocks[first].instructions, 1);
    machine
        .host
        .exits
        .push(exit(BASE + 4, ExitKind::Fallthrough));
    machine.step().unwrap();
    assert_eq!(machine.cpu.pc, BASE + 4);
    // The site's block is a stub that exits to the engine, which completes
    // the access exactly, with no fault.
    let Ok(Fetched::Block(stub)) = machine.fetch_block(BASE + 4, false) else {
        panic!("a stub");
    };
    let code = installed_code(&mut machine, stub, 0, chain::DIRECT_EXIT_BYTES);
    assert_eq!(
        code,
        chain::direct_exit(GuestAddress(BASE + 4), ExitKind::System)
    );
    let retired = machine.cpu.retired;
    for round in 0..3 {
        machine.cpu.pc = BASE + 4;
        machine.host.exits.push(exit(BASE + 4, ExitKind::System));
        machine.step().unwrap();
        assert!(machine.host.exits.is_empty());
        assert_eq!(machine.devices.accesses.len(), 2 + round);
        assert_eq!(machine.devices.accesses[1 + round], (DEVICE, 4, None));
        assert_eq!(machine.cpu.pc, BASE + 8);
    }
    assert_eq!(machine.cpu.retired, retired + 3);
    // Blocks of the page are neither stored nor taken from a store.
    assert!(machine.before_device_site(BASE, 16) == Some(4));
}

#[test]
fn a_device_sites_exits_are_timed_apart_from_system_instructions() {
    // add x3, x3, #1; ldr w0, [x1]; add x2, x2, #1; ret
    let words = [0x9100_0463, 0xb940_0020, 0x9100_0442, 0xd65f_03c0];
    let mut machine = board(&words, Registers::default(), Vec::new());
    machine.cpu.state.x[1] = DEVICE;
    let (_, offset) =
        native_fault_site_in_entry(&mut machine, BASE, BASE + 4, RecoverySiteKind::GuestAccess);
    machine.host.exits.push(device_fault(offset, DEVICE, false));
    machine.step().unwrap();
    assert!(machine.device_site(BASE + 4));
    machine.set_step_timing(true);
    machine.cpu.pc = BASE + 4;
    machine.host.exits.push(exit(BASE + 4, ExitKind::System));
    machine.step().unwrap();
    assert_eq!(machine.cpu.pc, BASE + 8);
    let timing = machine.step_timing().unwrap();
    assert_eq!(timing.exits[step_timing::DEVICE_SITE_SLOT].0, 1);
    assert_eq!(timing.exits[ExitKind::System as usize].0, 0);
    let exits = machine.take_system_exits();
    let keys: Vec<_> = exits.counted().map(|exit| (exit.key, exit.count)).collect();
    assert_eq!(keys, [(step_timing::DEVICE_SITE_KEY, 1)]);
    // The access is charged to its device page too, with no lock to wait.
    let pages: Vec<_> = exits
        .devices
        .counted()
        .map(|exit| (exit.page, exit.count, exit.waited))
        .collect();
    assert_eq!(pages, [(step_timing::device_page(DEVICE), 1, 0)]);
    assert_eq!(exits.devices.forwarded, 0);
}

#[test]
fn a_device_site_that_reaches_ram_runs_natively_and_keeps_writeback_and_size() {
    // strb w0, [x1], #1; ret
    let words = [0x3800_1420, 0xd65f_03c0];
    let mut machine = board(&words, Registers::default(), Vec::new());
    machine.cpu.state.x[0] = 0x1234_5678;
    machine.cpu.state.x[1] = DEVICE;
    let (_, offset) =
        native_fault_site_in_entry(&mut machine, BASE, BASE, RecoverySiteKind::GuestAccess);
    machine.host.exits.push(device_fault(offset, DEVICE, true));
    machine.step().unwrap();
    assert_eq!(machine.devices.accesses, [(DEVICE, 1, Some(0x1234_5678))]);
    assert_eq!(
        (machine.cpu.state.x[1], machine.cpu.pc),
        (DEVICE + 1, BASE + 4)
    );
    // The stub completes the next store and its writeback, a byte wide (the
    // register takes the value's low byte, as from the fault path).
    machine.cpu.pc = BASE;
    machine.host.exits.push(exit(BASE, ExitKind::System));
    machine.step().unwrap();
    assert_eq!(
        machine.devices.accesses[1],
        (DEVICE + 1, 1, Some(0x1234_5678))
    );
    assert_eq!(
        (machine.cpu.state.x[1], machine.cpu.pc),
        (DEVICE + 2, BASE + 4)
    );
    // An access to RAM from the site runs as a block of its own, natively.
    machine.cpu.state.x[1] = BASE + 0x800;
    machine.cpu.pc = BASE;
    machine.host.exits.push(exit(BASE, ExitKind::System));
    machine
        .host
        .exits
        .push(exit(BASE + 4, ExitKind::Fallthrough));
    machine.step().unwrap();
    assert!(machine.host.exits.is_empty());
    assert_eq!(machine.devices.accesses.len(), 2);
    assert_eq!(machine.cpu.pc, BASE + 4);
    assert!(
        machine
            .blocks
            .iter()
            .any(|block| block.pc == BASE && machine.variants[block.variant.0 as usize].single)
    );
}
