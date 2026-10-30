//! Shared AHCI disk and register fixtures.
use super::*;
use crate::bus::dma::RegionAllocator;
use alloc::boxed::Box;
use core::cell::{Cell, RefCell};
use identify_fixture::identify_page;

/// How the disk answers the next issued command.
#[derive(Clone, Copy)]
enum Fault {
    /// TFES with this taskfile (status | error << 8).
    TaskFile(u32),
    /// The command never completes.
    Timeout,
    /// An interface fatal error with an unrecovered data SError.
    Interface,
    /// The disk leaves: PhyRdy changes and the link stays down.
    Gone,
    /// The command completes.
    Complete,
}

/// A port and link that answer engine, COMRESET and command register
/// writes like an AHCI port with one ATA disk.
struct Link {
    registers: RefCell<[u32; 32]>,
    faults: RefCell<alloc::collections::VecDeque<Fault>>,
    writes: RefCell<Vec<(usize, u32)>>,
    issued: Cell<usize>,
    present: Cell<bool>,
    /// The disk's fastest SPD.
    fastest: Cell<u32>,
}

const READY: u32 = 0x50;

impl Link {
    fn new(faults: &[Fault]) -> Self {
        let mut registers = [0u32; 32];
        registers[PORT_COMMAND / 4] =
            COMMAND_START | COMMAND_LIST_RUNNING | COMMAND_FIS_RECEIVE | COMMAND_FIS_RUNNING;
        registers[PORT_TASK_FILE / 4] = READY;
        registers[PORT_SATA_STATUS / 4] = 0x123;
        registers[PORT_SATA_CONTROL / 4] = 0x300;
        registers[PORT_SIGNATURE / 4] = SIGNATURE_ATA;
        Self {
            registers: RefCell::new(registers),
            faults: RefCell::new(faults.iter().copied().collect()),
            writes: RefCell::new(Vec::new()),
            issued: Cell::new(0),
            present: Cell::new(true),
            fastest: Cell::new(2),
        }
    }

    fn writes_to(&self, offset: usize) -> Vec<u32> {
        self.writes
            .borrow()
            .iter()
            .filter(|(at, _)| *at == offset)
            .map(|(_, value)| *value)
            .collect()
    }
}

impl CommandPort for Link {
    fn read32(&self, offset: usize) -> u32 {
        self.registers.borrow()[offset / 4]
    }
    fn write32(&self, offset: usize, value: u32) {
        self.writes.borrow_mut().push((offset, value));
        let mut registers = self.registers.borrow_mut();
        match offset {
            PORT_INTERRUPTS | PORT_SATA_ERROR => registers[offset / 4] &= !value,
            PORT_SATA_ACTIVE => registers[offset / 4] |= value,
            PORT_COMMAND => {
                let mut command = value & !(COMMAND_LIST_RUNNING | COMMAND_FIS_RUNNING);
                if value & COMMAND_START != 0 {
                    command |= COMMAND_LIST_RUNNING;
                } else {
                    // Clearing ST clears PxCI and PxSACT.
                    registers[PORT_ISSUE / 4] = 0;
                    registers[PORT_SATA_ACTIVE / 4] = 0;
                }
                if value & COMMAND_FIS_RECEIVE != 0 {
                    command |= COMMAND_FIS_RUNNING;
                }
                registers[PORT_COMMAND / 4] = command;
            }
            PORT_SATA_CONTROL => {
                registers[offset / 4] = value;
                match value & SATA_CONTROL_DETECTION {
                    SATA_CONTROL_RESET => {
                        registers[PORT_SATA_STATUS / 4] = 0;
                        registers[PORT_TASK_FILE / 4] = 0x80;
                    }
                    // The link comes up at the fastest speed both allow.
                    0 if self.present.get() => {
                        let limit = (value >> SPEED_SHIFT) & 0xf;
                        let fastest = self.fastest.get();
                        let speed = if limit == 0 {
                            fastest
                        } else {
                            limit.min(fastest)
                        };
                        registers[PORT_SATA_STATUS / 4] = 0x103 | speed << SPEED_SHIFT;
                        registers[PORT_TASK_FILE / 4] = READY;
                    }
                    0 => {}
                    // Phy offline.
                    _ => registers[PORT_SATA_STATUS / 4] = 4,
                }
            }
            PORT_ISSUE => {
                assert_ne!(registers[PORT_COMMAND / 4] & COMMAND_LIST_RUNNING, 0);
                self.issued.set(self.issued.get() + 1);
                match self.faults.borrow_mut().pop_front() {
                    None | Some(Fault::Complete) => {
                        registers[PORT_TASK_FILE / 4] = READY;
                        registers[PORT_SATA_ACTIVE / 4] &= !value;
                    }
                    Some(fault) => {
                        registers[PORT_ISSUE / 4] |= value;
                        match fault {
                            Fault::TaskFile(task_file) => {
                                registers[PORT_TASK_FILE / 4] = task_file;
                                registers[PORT_INTERRUPTS / 4] |= INTERRUPT_TASK_FILE_ERROR;
                            }
                            Fault::Timeout => registers[PORT_TASK_FILE / 4] = 0xd0,
                            Fault::Interface => {
                                registers[PORT_INTERRUPTS / 4] |= INTERRUPT_INTERFACE_FATAL;
                                registers[PORT_SATA_ERROR / 4] |= SERROR_DATA;
                            }
                            Fault::Complete => unreachable!(),
                            Fault::Gone => {
                                self.present.set(false);
                                registers[PORT_INTERRUPTS / 4] |= INTERRUPT_PHY_READY_CHANGE;
                                registers[PORT_SATA_ERROR / 4] |= SERROR_PHY_READY_CHANGE;
                                registers[PORT_SATA_STATUS / 4] = 0;
                            }
                        }
                    }
                }
            }
            _ => registers[offset / 4] = value,
        }
    }
}

/// A disk identified from `identify_page`, answering revalidation with
/// `page`, on a virtual one-tick-per-microsecond clock.
fn recovering(page: [u8; 512]) -> (Fixture, crate::test_clock::Guard) {
    recovering_with(page, 0)
}

/// [`recovering`] with `slots` more command slots.
fn recovering_with(page: [u8; 512], slots: usize) -> (Fixture, crate::test_clock::Guard) {
    let clock = crate::test_clock::virtualize();
    let mut fixture = Fixture::with_slots(slots);
    let found = identify(&identify_page("S1", 1024)).unwrap();
    fixture.disk.identity.model = found.model;
    fixture.disk.identity.serial = found.serial;
    fixture.disk.identity.blocks = found.blocks;
    fixture.disk.transfer = found.transfer;
    fixture.disk.clock = Clock {
        ticks_per_microsecond: 1,
    };
    fixture.disk.table.bytes_mut()[IDENTIFY_DATA..IDENTIFY_DATA + 512].copy_from_slice(&page);
    (fixture, clock)
}

struct Fixture {
    disk: AhciDisk,
    _registers: Box<[u64]>,
    _memory: Vec<u64>,
}

impl Fixture {
    fn new() -> Self {
        Self::with_slots(0)
    }

    /// With `slots` more command slots for queued commands.
    fn with_slots(slots: usize) -> Self {
        let mut registers = vec![0u64; 16].into_boxed_slice();
        let mut memory = vec![0u64; 32768 * (1 + slots)];
        let start = memory.as_mut_ptr() as u64;
        // SAFETY: stable fixture allocations outlive the disk and all
        // register/DMA operations; there is no physical device.
        let (port, mut dma) = unsafe {
            (
                Mmio::new(registers.as_mut_ptr() as u64),
                RegionAllocator::new(start..start + (memory.len() * 8) as u64),
            )
        };
        let mut disk = AhciDisk {
            port,
            commands: dma
                .allocate(COMMAND_LIST_BYTES + RECEIVED_FIS_BYTES, COMMAND_LIST_BYTES)
                .unwrap(),
            table: dma
                .allocate(COMMAND_TABLE_BYTES, COMMAND_TABLE_ALIGN)
                .unwrap(),
            bounce: dma.allocate(BOUNCE_BYTES, 4096).unwrap(),
            identity: Identity {
                transport: Transport::Ahci,
                location: "fixture".into(),
                model: "fixture".into(),
                serial: "fixture".into(),
                blocks: 1024,
                block_size: 512,
                read_only: false,
                features: Features::default(),
            },
            clock: Clock {
                ticks_per_microsecond: 1000,
            },
            command_timeout_us: 1000,
            fault: None,
            flush: Some(ATA_FLUSH_CACHE_EXT),
            errors: ErrorRing::default(),
            dubious: false,
            speed_limit: u32::MAX,
            speed: 2,
            sense_reporting: true,
            transfer: Transfer::default(),
            // As configured: PIO 0-4 and UDMA 0-6.
            pio_mask: 0x1f,
            udma_mask: 0x7f,
            mode: 0x46,
            step_downs: 0,
            locked: false,
            lpm: Lpm::default(),
            ncq: Ncq::default(),
            log_dma: false,
            no_dma_log: false,
            quirks: 0,
            devslp: false,
            slots: Vec::new(),
            running: Vec::new(),
            next_tag: 0,
            looks: 0,
        };
        for _ in 0..slots {
            disk.slots.push(Slot {
                table: dma
                    .allocate(COMMAND_TABLE_BYTES, COMMAND_TABLE_ALIGN)
                    .unwrap(),
                bounce: dma.allocate(BOUNCE_BYTES, 4096).unwrap(),
            });
        }
        Self {
            disk,
            _registers: registers,
            _memory: memory,
        }
    }
}

/// Port command engines that stop only when their own enable clears.
struct Engines {
    command: Cell<u32>,
    writes: RefCell<Vec<u32>>,
}

impl CommandPort for Engines {
    fn read32(&self, offset: usize) -> u32 {
        assert_eq!(offset, PORT_COMMAND);
        self.command.get()
    }
    fn write32(&self, offset: usize, value: u32) {
        assert_eq!(offset, PORT_COMMAND);
        self.writes.borrow_mut().push(value);
        let mut running = value;
        if value & COMMAND_START == 0 {
            running &= !COMMAND_LIST_RUNNING;
        }
        if value & COMMAND_FIS_RECEIVE == 0 {
            running &= !COMMAND_FIS_RUNNING;
        }
        self.command.set(running);
    }
}

mod identify_fixture;
mod lifecycle;
mod modes;
mod power;
mod queue;
mod recovery;
mod sense_completion;
mod sense_tables;
