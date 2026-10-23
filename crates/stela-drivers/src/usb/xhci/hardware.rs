// SPDX-License-Identifier: GPL-2.0-only
// Halt/reset/save/restore adapted from pinned Linux xhci.c.
// Copyright (C) 2008 Intel Corp. Author: Sarah Sharp.
//! Controller state transitions retain all DMA allocations and public identities.
//! Reset is not a claim that an old endpoint or class handle became usable.
use super::*;

const INTERRUPT_ENABLES: u32 = (1 << 2) | (1 << 3);
const SAVE: u32 = 1 << 8;
const RESTORE: u32 = 1 << 9;
const SAVE_ERROR: u32 = 1 << 10;
const CSS: u32 = 1 << 8;
const CRS: u32 = 1 << 9;
const SAVE_US: u64 = 20_000;
const RESTORE_US: u64 = 100_000;
const RESUME_READY_US: u64 = 10_000_000;
const DNCTRL: usize = 0x14;
const IMOD: usize = 0x24;
const U3: u32 = 3;

pub(super) struct Policy {
    pub dma: dma::Profile,
    pub streams: streams::Policy,
    pub quirks: quirks::Profile,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            dma: dma::Profile::SPEC,
            streams: streams::Policy::Unknown,
            quirks: quirks::Profile::default(),
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct Snapshot {
    command: u32,
    notification: u32,
    dcbaa: u64,
    config: u32,
    erst_size: u32,
    erst_base: u64,
    erst_dequeue: u64,
    moderation: u32,
}
#[derive(Clone, Copy, Default)]
pub(super) enum State {
    #[default]
    Running,
    Suspended(Snapshot),
    #[cfg(test)]
    Stopped,
    Failed,
}
impl State {
    pub fn ready(self) -> Result<(), BlockError> {
        match self {
            Self::Running => Ok(()),
            Self::Suspended(_) => Err(BlockError::Unsupported("xHCI controller is suspended")),
            #[cfg(test)]
            Self::Stopped => Err(BlockError::Unsupported("xHCI controller is stopped")),
            Self::Failed => Err(BlockError::Unsupported(
                "xHCI hardware transition unresolved",
            )),
        }
    }
}
fn read64(registers: &mut dyn Registers, at: usize) -> u64 {
    let low = registers.read32(at);
    u64::from(low) | u64::from(registers.read32(at + 4)) << 32
}
fn status(registers: &mut dyn Registers, operational: usize) -> Result<u32, BlockError> {
    match registers.read32(operational + USBSTS) {
        u32::MAX => Err(BlockError::Unsupported("xHCI controller is inaccessible")),
        value => Ok(value),
    }
}
fn handshake(
    registers: &mut dyn Registers,
    clock: Clock,
    operational: usize,
    offset: usize,
    mask: u32,
    wanted: u32,
    timeout: u64,
) -> Result<(), BlockError> {
    let mut removed = false;
    let acknowledged = wait(registers, clock, timeout, |r| {
        let value = r.read32(operational + offset);
        removed |= value == u32::MAX;
        removed || value & mask == wanted
    });
    if removed {
        Err(BlockError::Unsupported(
            "xHCI controller disappeared during handshake",
        ))
    } else if acknowledged {
        Ok(())
    } else {
        Err(BlockError::Timeout)
    }
}

pub(super) fn halt(
    registers: &mut dyn Registers,
    clock: Clock,
    operational: usize,
    timeout: u64,
) -> Result<(), BlockError> {
    status(registers, operational)?;
    let command = registers.read32(operational + USBCMD);
    registers.write32(operational + USBCMD, command & !(RUN | INTERRUPT_ENABLES));
    handshake(registers, clock, operational, USBSTS, HCH, HCH, timeout)
}
pub(super) fn reset(
    registers: &mut dyn Registers,
    clock: Clock,
    operational: usize,
    settle_us: u64,
) -> Result<(), BlockError> {
    if status(registers, operational)? & HCH == 0 {
        return Err(BlockError::Unsupported(
            "xHCI reset requires acknowledged halt",
        ));
    }
    let command = registers.read32(operational + USBCMD);
    registers.write32(operational + USBCMD, command | HCRST);
    clock.delay(settle_us);
    handshake(registers, clock, operational, USBCMD, HCRST, 0, RESET_US)?;
    // CNR is independent of the reset bit. Never publish operational pointers
    // or ring a doorbell between these two acknowledgments.
    handshake(registers, clock, operational, USBSTS, CNR, 0, RESET_US)
}
pub(super) fn start(
    registers: &mut dyn Registers,
    clock: Clock,
    operational: usize,
) -> Result<(), BlockError> {
    let state = status(registers, operational)?;
    if state & (CNR | HSE | HCE | SAVE_ERROR) != 0 {
        return Err(BlockError::Device { status: state });
    }
    let command = registers.read32(operational + USBCMD);
    registers.write32(
        operational + USBCMD,
        command & !(CSS | CRS | INTERRUPT_ENABLES) | RUN,
    );
    handshake(registers, clock, operational, USBSTS, HCH, 0, HALT_US)
}

/// Linux deliberately faults these controllers when clearing stale high pointer
/// halves; doing that requires a retained nonidentity IOMMU domain. This owner
/// has no such authority, so it never attempts the unsafe write sequence.
pub(super) fn pre_reset(
    registers: &mut dyn Registers,
    operational: usize,
    runtime: usize,
    interrupters: usize,
    quirks: quirks::Profile,
) -> Result<(), BlockError> {
    if !quirks.renesas_stale_high {
        return Ok(());
    }
    let mut addresses = vec![operational + DCBAAP, operational + CRCR];
    for index in 0..interrupters {
        addresses.extend([
            runtime + index * 0x20 + ERSTBA,
            runtime + index * 0x20 + ERDP,
        ]);
    }
    if addresses
        .iter()
        .any(|at| registers.size().is_some_and(|size| *at + 8 > size))
    {
        return Err(BlockError::Unsupported(
            "Renesas interrupter register outside BAR",
        ));
    }
    for at in addresses {
        if read64(registers, at) >> 32 != 0 {
            return Err(BlockError::Unsupported(
                "Renesas stale firmware DMA pointers require isolated IOMMU reset authority",
            ));
        }
    }
    Ok(())
}

impl Snapshot {
    fn read(c: &mut Controller) -> Self {
        let r = &mut *c.registers;
        Self {
            command: r.read32(c.operational + USBCMD) & !(RUN | CSS | CRS | INTERRUPT_ENABLES),
            notification: r.read32(c.operational + DNCTRL),
            dcbaa: read64(r, c.operational + DCBAAP),
            config: r.read32(c.operational + CONFIG),
            erst_size: r.read32(c.runtime + ERSTSZ),
            erst_base: read64(r, c.runtime + ERSTBA),
            erst_dequeue: read64(r, c.runtime + ERDP) & !EHB,
            moderation: r.read32(c.runtime + IMOD),
        }
    }
    fn restore(self, c: &mut Controller) {
        c.registers.write32(c.operational + USBCMD, self.command);
        c.registers
            .write32(c.operational + DNCTRL, self.notification);
        c.registers.write64(c.operational + DCBAAP, self.dcbaa);
        c.registers.write32(c.operational + CONFIG, self.config);
        c.registers.write32(c.runtime + ERSTSZ, self.erst_size);
        c.registers.write64(c.runtime + ERSTBA, self.erst_base);
        c.registers.write64(c.runtime + ERDP, self.erst_dequeue);
        // IP is RW1C. Preserve every posted event until normal ring draining.
        c.registers.write32(c.runtime + IMAN, 0);
        c.registers.write32(c.runtime + IMOD, self.moderation);
        c.registers
            .write64(c.operational + CRCR, c.commands.dequeue_pointer());
    }
}
impl Controller {
    /// Requires actual root links to be in U3. The lifecycle owner establishes
    /// USB bus suspend and retains endpoint DMA before calling this boundary.
    /// It cannot authorize suspend by supplying an asserted boolean.
    pub(super) fn suspend_controller(&mut self) -> Result<(), BlockError> {
        self.ready()?;
        if self.quirks.reset_on_resume {
            return Err(BlockError::Unsupported(
                "controller suspend requires reset and device republication on resume",
            ));
        }
        for port in 1..=self.max_ports {
            let at = self.port_offset(port);
            let value = self.registers.read32(at);
            if value == u32::MAX {
                return Err(BlockError::Unsupported(
                    "xHCI root port inaccessible during suspend",
                ));
            }
            if value & (CCS | PED) == (CCS | PED) && value >> PLS_SHIFT & PLS_FIELD != U3 {
                return Err(BlockError::Unsupported(
                    "xHCI suspend requires observed U3 root links",
                ));
            }
        }
        if self.quirks.suspend_delay {
            self.clock.delay(1_000);
        }
        // From this point any failed handshake permanently blocks traffic;
        // neither a late acknowledgment nor an elapsed timeout unpins DMA.
        self.hardware = State::Failed;
        halt(
            &mut *self.registers,
            self.clock,
            self.operational,
            HALT_US * if self.quirks.slow_suspend { 20 } else { 2 },
        )?;
        // Commands are synchronous, ready() rejected any unresolved command.
        // CRCR only accepts a 64-byte-aligned pointer, so restart this empty
        // ring at its base; transfer and event rings keep their exact cursors.
        self.commands.buffer.bytes_mut()[..RING_TRBS * TRB].fill(0);
        let base = self.commands.buffer.physical();
        self.commands.buffer.write((RING_TRBS - 1) * TRB, base);
        self.commands.index = 0;
        self.commands.cycle = true;
        self.registers
            .write64(self.operational + CRCR, self.commands.dequeue_pointer());
        let snapshot = Snapshot::read(self);
        self.registers
            .write32(self.operational + USBSTS, SAVE_ERROR);
        self.registers
            .write32(self.operational + USBCMD, snapshot.command | CSS);
        handshake(
            &mut *self.registers,
            self.clock,
            self.operational,
            USBSTS,
            SAVE,
            0,
            SAVE_US,
        )?;
        let value = status(&mut *self.registers, self.operational)?;
        if value & (SAVE_ERROR | HSE | HCE) != 0 || value & HCH == 0 {
            return Err(BlockError::Device { status: value });
        }
        self.hardware = State::Suspended(snapshot);
        Ok(())
    }

    /// Restore the same hardware context. SRE/HCE, removal or failed handshakes
    /// retain failure and every old DMA owner; no reset/re-enumeration is invented.
    pub(super) fn resume_controller(&mut self) -> Result<(), BlockError> {
        let State::Suspended(snapshot) = self.hardware else {
            return Err(BlockError::Unsupported(
                "xHCI has no acknowledged saved controller state",
            ));
        };
        self.hardware = State::Failed;
        handshake(
            &mut *self.registers,
            self.clock,
            self.operational,
            USBSTS,
            CNR,
            0,
            RESUME_READY_US,
        )?;
        if status(&mut *self.registers, self.operational)? & HCH == 0 {
            return Err(BlockError::Unsupported(
                "xHCI saved controller unexpectedly running",
            ));
        }
        snapshot.restore(self);
        self.registers
            .write32(self.operational + USBCMD, snapshot.command | CRS);
        handshake(
            &mut *self.registers,
            self.clock,
            self.operational,
            USBSTS,
            RESTORE,
            0,
            RESTORE_US,
        )?;
        let value = status(&mut *self.registers, self.operational)?;
        if value & (SAVE_ERROR | HSE | HCE) != 0 {
            return Err(BlockError::Device { status: value });
        }
        start(&mut *self.registers, self.clock, self.operational)?;
        self.hardware = State::Running;
        Ok(())
    }

    /// Terminal stop retains all allocations and permanently blocks old traffic.
    /// HCH alone is not a per-endpoint completion or permission to reuse a slot.
    #[cfg(test)]
    pub(super) fn stop_controller(&mut self) -> Result<(), BlockError> {
        self.hardware = State::Failed;
        halt(&mut *self.registers, self.clock, self.operational, HALT_US)?;
        self.hardware = State::Stopped;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::dma::RegionAllocator;

    struct Model {
        words: Vec<u32>,
        writes: Vec<(usize, u32)>,
        saved: bool,
        fail_save: bool,
        fail_restore: bool,
        removed: bool,
    }
    impl Model {
        fn new() -> Self {
            let mut model = Self {
                words: vec![0; 0x1100 / 4],
                writes: Vec::new(),
                saved: false,
                fail_save: false,
                fail_restore: false,
                removed: false,
            };
            model.words[0] = 0x110_0040;
            model.words[HCSPARAMS1 / 4] = 1 << 24 | 1 << 8 | 8;
            model.words[HCCPARAMS1 / 4] = 1;
            model.words[DBOFF / 4] = 0x1000;
            model.words[RTSOFF / 4] = 0x800;
            model.words[(0x40 + USBSTS) / 4] = HCH;
            model.words[(0x40 + PAGESIZE) / 4] = 1;
            model
        }
    }
    struct Access(Rc<RefCell<Model>>);
    impl Registers for Access {
        fn read32(&mut self, at: usize) -> u32 {
            let m = self.0.borrow();
            if m.removed { u32::MAX } else { m.words[at / 4] }
        }
        fn write32(&mut self, at: usize, value: u32) {
            let mut m = self.0.borrow_mut();
            m.writes.push((at, value));
            if at == 0x40 + USBSTS {
                m.words[at / 4] &= !(value & (SAVE_ERROR | HSE));
            } else if at == 0x40 + USBCMD {
                m.words[at / 4] = value & !(HCRST | CSS | CRS);
                if value & RUN == 0 {
                    m.words[(0x40 + USBSTS) / 4] |= HCH;
                } else {
                    m.words[(0x40 + USBSTS) / 4] &= !HCH;
                }
                if value & CSS != 0 {
                    if m.fail_save {
                        m.words[(0x40 + USBSTS) / 4] |= SAVE_ERROR;
                    } else {
                        m.saved = true;
                    }
                }
                if value & CRS != 0 && (!m.saved || m.fail_restore) {
                    m.words[(0x40 + USBSTS) / 4] |= SAVE_ERROR;
                }
            } else {
                m.words[at / 4] = value;
            }
        }
        fn size(&self) -> Option<usize> {
            Some(0x1100)
        }
    }

    #[test]
    fn actual_save_restore_commands_preserve_dma_cursors_and_block_suspended_mutation() {
        let mut backing = vec![0u64; 32 * 1024];
        let base = backing.as_mut_ptr() as u64;
        let mut dma = unsafe { RegionAllocator::new(base..base + backing.len() as u64 * 8) };
        let model = Rc::new(RefCell::new(Model::new()));
        let mut c = Controller::new(
            Box::new(Access(model.clone())),
            Clock {
                ticks_per_microsecond: 1,
            },
            &mut dma,
            "save model".into(),
        )
        .unwrap();
        let dcbaa = c.dcbaa.physical();
        let events = c.events.physical();
        c.event_index = 17;
        c.event_cycle = true;
        c.registers
            .write64(c.runtime + ERDP, events + 17 * TRB as u64);
        let port = c.port_offset(1);
        c.registers.write32(port, PP | CCS | PED);
        let writes = model.borrow().writes.len();
        assert!(c.suspend_controller().is_err());
        assert_eq!(model.borrow().writes.len(), writes);
        c.registers.write32(port, PP | CCS | PED | U3 << PLS_SHIFT);
        c.suspend_controller().unwrap();
        assert!(model.borrow().saved);
        let writes = model.borrow().writes.len();
        assert!(c.ready().is_err());
        assert!(c.command(0, 0, ENABLE_SLOT << 10).is_err());
        assert_eq!(model.borrow().writes.len(), writes);
        // Simulated retained controller state, lost externally visible pointer
        // registers. Restore must rewrite them, retaining the event cursor.
        for at in [DCBAAP, CRCR, CONFIG] {
            model.borrow_mut().words[(0x40 + at) / 4] = 0;
        }
        c.resume_controller().unwrap();
        assert_eq!(read64(&mut *c.registers, c.operational + DCBAAP), dcbaa);
        assert_eq!(
            read64(&mut *c.registers, c.runtime + ERDP),
            events + 17 * TRB as u64
        );
        assert_eq!((c.event_index, c.event_cycle), (17, true));
        assert!(c.resume_controller().is_err());
        c.stop_controller().unwrap();
        assert!(c.ready().is_err());
    }

    #[test]
    fn actual_zhaoxin_9202_suspend_refuses_before_mutation_and_9203_keeps_saved_context() {
        use crate::bus::pci::{Address, ConfigSpace};
        struct Pci(u16);
        impl ConfigSpace for Pci {
            fn read32(&self, at: u16) -> u32 {
                match at {
                    0 => u32::from(self.0) << 16 | 0x1d17,
                    8 => 0x0c03_3001,
                    _ => 0,
                }
            }
            fn write32(&mut self, _: u16, _: u32) {
                panic!("PCI quirk admission must not mutate configuration");
            }
        }
        for device in [0x9202, 0x9203] {
            let mut function = Function::new(
                Address {
                    segment: 0,
                    bus: 0,
                    device: 1,
                    function: 0,
                },
                Pci(device),
            )
            .unwrap();
            let quirks = quirks::Profile::pci(&mut function).unwrap();
            let mut backing = vec![0u64; 32 * 1024];
            let base = backing.as_mut_ptr() as u64;
            let mut dma = unsafe { RegionAllocator::new(base..base + backing.len() as u64 * 8) };
            let model = Rc::new(RefCell::new(Model::new()));
            let mut c = Controller::with_hardware_profile(
                Box::new(Access(model.clone())),
                Clock {
                    ticks_per_microsecond: 1,
                },
                &mut dma,
                "Zhaoxin controller model".into(),
                Policy {
                    dma: dma::Profile::pci(function.vendor, function.device),
                    quirks,
                    ..Default::default()
                },
                || Ok(()),
            )
            .unwrap();
            if device == 0x9202 {
                let registers = model.borrow().words.clone();
                let writes = model.borrow().writes.len();
                let commands = c.commands.buffer.bytes().to_vec();
                let events = c.events.bytes().to_vec();
                let dcbaa = c.dcbaa.bytes().to_vec();
                assert_eq!(
                    c.suspend_controller(),
                    Err(BlockError::Unsupported(
                        "controller suspend requires reset and device republication on resume"
                    ))
                );
                assert!(matches!(c.hardware, State::Running));
                assert!(!model.borrow().saved);
                assert_eq!(model.borrow().words, registers);
                assert_eq!(model.borrow().writes.len(), writes);
                assert_eq!(c.commands.buffer.bytes(), commands);
                assert_eq!(c.events.bytes(), events);
                assert_eq!(c.dcbaa.bytes(), dcbaa);
                // A refused suspend minted no saved-state proof. Resume cannot
                // restore old identities, nor clear unresolved command poison.
                c.command_poisoned = true;
                assert!(c.resume_controller().is_err());
                assert!(c.command_poisoned);
                assert!(c.ready().is_err());
                assert_eq!(model.borrow().writes.len(), writes);
            } else {
                c.suspend_controller().unwrap();
                assert!(model.borrow().saved);
                assert!(matches!(c.hardware, State::Suspended(_)));
                c.resume_controller().unwrap();
                assert!(matches!(c.hardware, State::Running));
            }
        }
    }

    #[test]
    fn failed_save_restore_and_removed_hardware_never_resume_traffic() {
        for save in [true, false] {
            let mut backing = vec![0u64; 32 * 1024];
            let base = backing.as_mut_ptr() as u64;
            let mut dma = unsafe { RegionAllocator::new(base..base + backing.len() as u64 * 8) };
            let model = Rc::new(RefCell::new(Model::new()));
            let mut c = Controller::new(
                Box::new(Access(model.clone())),
                Clock {
                    ticks_per_microsecond: 1,
                },
                &mut dma,
                "failure model".into(),
            )
            .unwrap();
            if save {
                model.borrow_mut().fail_save = true;
                assert!(c.suspend_controller().is_err());
            } else {
                c.suspend_controller().unwrap();
                model.borrow_mut().fail_restore = true;
                assert!(c.resume_controller().is_err());
            }
            assert!(c.ready().is_err());
            assert!(c.resume_controller().is_err());
            assert!(c.dcbaa.physical() >= base);
        }
        let model = Rc::new(RefCell::new(Model::new()));
        model.borrow_mut().removed = true;
        let mut registers = Access(model.clone());
        assert!(
            halt(
                &mut registers,
                Clock {
                    ticks_per_microsecond: 1
                },
                0x40,
                HALT_US
            )
            .is_err()
        );
        assert!(model.borrow().writes.is_empty());
    }

    #[test]
    fn renesas_high_firmware_pointers_require_real_isolation_without_any_zero_write() {
        let model = Rc::new(RefCell::new(Model::new()));
        let mut registers = Access(model.clone());
        registers.write64(0x40 + DCBAAP, 1u64 << 40);
        let writes = model.borrow().writes.len();
        let quirks = quirks::Profile {
            renesas_stale_high: true,
            ..Default::default()
        };
        assert!(pre_reset(&mut registers, 0x40, 0x800, 1, quirks).is_err());
        assert_eq!(model.borrow().writes.len(), writes);
    }
}
