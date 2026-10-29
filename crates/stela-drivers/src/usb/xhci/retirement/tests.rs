// SPDX-License-Identifier: GPL-2.0-only
//! Actual command/context/event peers; no quiescence receipt is injected.
use super::*;
use crate::bus::dma::RegionAllocator;
use reset::tests::{Fault, Hardware};

fn configured(
    memory: &mut [u64],
    speed: u8,
    context: usize,
) -> (Shared, Device, Rc<RefCell<Hardware>>, RegionAllocator) {
    let (shared, device, hardware, mut dma) = reset::tests::fixture(memory, speed, context, 3);
    let endpoints = interfaces(&device.configuration)[0].endpoints.clone();
    if speed >= SUPER_SPEED {
        shared
            .borrow_mut()
            .configure_streams(device.slot, &endpoints, &[0x82, 0x83, 4], 2, &mut dma)
            .unwrap();
    } else {
        shared
            .borrow_mut()
            .configure(device.slot, &endpoints, None, &mut dma)
            .unwrap();
    }
    (shared, device, hardware, dma)
}

#[test]
fn whole_slot_retirement_stops_actual_ordinary_and_stream_dma_before_disable() {
    for speed in [HIGH_SPEED, SUPER_SPEED] {
        for context in [32, 64] {
            let mut memory = vec![0u64; 512 * 1024];
            let (shared, old, hardware, mut dma) = configured(&mut memory, speed, context);
            let mut command = dma.allocate(512, 512).unwrap();
            let mut payload = dma.allocate(512, 65536).unwrap();
            payload.bytes_mut().fill(0xa5);
            command.bytes_mut()[0] = 1;
            command.bytes_mut()[3] = 1;
            command.bytes_mut()[16] = 0x28;
            command.bytes_mut()[24] = 1;
            hardware.borrow_mut().hang_next = true;
            let ordinary = shared
                .borrow_mut()
                .submit_ticket(old.slot, 2, command.physical(), 32)
                .unwrap();
            let stream = if speed >= SUPER_SPEED {
                Some(
                    shared
                        .borrow_mut()
                        .submit_stream(old.slot, 7, 1, payload.physical(), 512)
                        .unwrap(),
                )
            } else {
                None
            };
            let mut c = shared.borrow_mut();
            let output = c.slot(old.slot).unwrap()._output.physical();
            let control = c.slot(old.slot).unwrap().control.physical();
            let ring = c.slot(old.slot).unwrap().endpoints[2]
                .as_ref()
                .unwrap()
                .ring
                .buffer
                .physical();
            let before = hardware.borrow().commands_seen.len();
            c.disable_slot(old.slot, Ownership::Retired).unwrap();
            // The independent hardware peer requires every actual output
            // endpoint Stopped, no outstanding TD, and the complete ordered
            // event ring consumed when it accepts this Disable Slot command.
            let seen = hardware.borrow().commands_seen[before..].to_vec();
            assert_eq!(seen.last(), Some(&(reset::DISABLE_SLOT, old.slot, 0)));
            for dci in [1, 2, 5, 7, 8] {
                assert!(seen.contains(&(STOP_ENDPOINT, old.slot, dci)));
                let dequeues = seen
                    .iter()
                    .filter(|(kind, slot, endpoint)| {
                        *kind == SET_DEQUEUE && *slot == old.slot && *endpoint == dci
                    })
                    .count();
                let expected = if speed >= SUPER_SPEED && matches!(dci, 5 | 7 | 8) {
                    2
                } else {
                    1
                };
                assert_eq!(dequeues, expected);
            }
            assert_eq!(c.slot_ownership[usize::from(old.slot)], Ownership::Retired);
            assert_eq!(c.dcbaa.read::<u64>(usize::from(old.slot) * 8), 0);
            assert!(
                c.power.retained(old.slot),
                "Disable does not retire current"
            );
            let retained = c.slot(old.slot).unwrap();
            assert!(retained.retiring);
            assert_eq!(retained._output.physical(), output);
            assert_eq!(retained.control.physical(), control);
            assert_eq!(
                retained.endpoints[2]
                    .as_ref()
                    .unwrap()
                    .ring
                    .buffer
                    .physical(),
                ring
            );
            assert_eq!(payload.bytes(), &[0xa5; 512]);
            let accesses = hardware.borrow().accesses;
            assert!(c.device(old.id).is_err());
            assert!(
                c.submit_ticket(old.slot, 2, command.physical(), 32)
                    .is_err()
            );
            assert!(c.completed_ticket(&ordinary).unwrap().is_err());
            if let Some(stream) = stream {
                assert!(c.completed_stream(&stream).unwrap().is_err());
            }
            assert_eq!(hardware.borrow().accesses, accesses);
            assert!(
                !c.pending
                    .iter()
                    .any(|event| { event.kind() == TRANSFER_EVENT && event.slot() == old.slot })
            );
            // The old device's port still holds its current grant, so the ID
            // that comes back stays unaddressed with its retained allocation.
            assert_eq!(c.fresh_slot().unwrap(), 2);
            assert_eq!(c.slot_ownership[1], Ownership::Tombstone);
            assert_eq!(c.slot(old.slot).unwrap()._output.physical(), output);
        }
    }
}

#[test]
fn whole_slot_retirement_quarantines_every_failed_contributor_without_disable() {
    for speed in [HIGH_SPEED, SUPER_SPEED] {
        for dci in [1, 2, 5, 7, 8] {
            for fault in [
                Fault::Stop(dci),
                Fault::SilentStop(dci),
                Fault::Dequeue(dci),
            ] {
                let mut memory = vec![0u64; 512 * 1024];
                let (shared, old, hardware, _dma) = configured(&mut memory, speed, 32);
                hardware.borrow_mut().fault = fault;
                let mut c = shared.borrow_mut();
                let output = c.slot(old.slot).unwrap()._output.physical();
                let before = hardware.borrow().commands_seen.len();
                assert!(c.disable_slot(old.slot, Ownership::Retired).is_err());
                let seen = hardware.borrow().commands_seen[before..].to_vec();
                assert!(!seen.iter().any(|(kind, _, _)| *kind == reset::DISABLE_SLOT));
                assert_eq!(c.slot_ownership[1], Ownership::Enabled);
                assert_eq!(c.dcbaa.read::<u64>(8), output);
                assert!(c.slot(old.slot).unwrap().retiring);
                assert!(c.power.retained(old.slot));
                let accesses = hardware.borrow().accesses;
                assert!(c.device(old.id).is_err());
                assert!(c.current_configuration(old.slot).is_err());
                assert_eq!(hardware.borrow().accesses, accesses);
            }
        }
    }
}

#[test]
fn whole_slot_retirement_keeps_allocations_until_exact_disable_acknowledgment() {
    for fault in [
        Fault::Disable,
        Fault::WrongDisableSlot,
        Fault::SilentDisable,
    ] {
        let mut memory = vec![0u64; 512 * 1024];
        let (shared, old, hardware, _dma) = configured(&mut memory, SUPER_SPEED, 64);
        hardware.borrow_mut().fault = fault;
        let mut c = shared.borrow_mut();
        let output = c.slot(old.slot).unwrap()._output.physical();
        assert!(c.disable_slot(old.slot, Ownership::Retired).is_err());
        assert_eq!(c.slot_ownership[1], Ownership::Enabled);
        assert_eq!(c.dcbaa.read::<u64>(8), output);
        assert_eq!(c.slot(old.slot).unwrap()._output.physical(), output);
        assert!(c.slot(old.slot).unwrap().retiring);
        assert!(c.power.retained(old.slot));
        let commands = hardware.borrow().commands_seen.clone();
        let accesses = hardware.borrow().accesses;
        assert!(c.device(old.id).is_err());
        assert_eq!(hardware.borrow().accesses, accesses);
        // Timeouts and mismatched completions cannot establish fresh command
        // authority even if the hardware physically stopped the old slot.
        if fault != Fault::Disable {
            assert!(c.fresh_slot().is_err());
            assert_eq!(hardware.borrow().commands_seen, commands);
        }
    }
}

#[test]
fn whole_slot_retirement_refuses_published_vacancy_and_invalid_owners_before_mmio() {
    let mut memory = vec![0u64; 512 * 1024];
    let (shared, old, hardware, _dma) = configured(&mut memory, HIGH_SPEED, 32);
    let mut c = shared.borrow_mut();
    let accesses = hardware.borrow().accesses;
    for (slot, ownership) in [
        (0, Ownership::Retired),
        (255, Ownership::Retired),
        (old.slot, Ownership::Enabled),
        (old.slot, Ownership::Tombstone),
        (old.slot, Ownership::Vacant),
    ] {
        assert!(c.disable_slot(slot, ownership).is_err());
        assert_eq!(hardware.borrow().accesses, accesses);
        assert!(!c.slot(old.slot).unwrap().retiring);
        assert_eq!(c.slot_ownership[1], Ownership::Enabled);
    }
}

/// Registers still execute every actual hardware-peer command and payload.
/// Only the device's full descriptor response is corrupted, after its DMA write
/// and before the host observes the real transfer event.
struct InvalidDescriptor {
    inner: Box<dyn Registers>,
    hardware: Rc<RefCell<Hardware>>,
    output: u64,
    context: usize,
    cursor: Option<u64>,
    corrupted: Rc<RefCell<usize>>,
    cleanup_fault: Fault,
    stall: bool,
}

impl Registers for InvalidDescriptor {
    fn read32(&mut self, offset: usize) -> u32 {
        self.inner.read32(offset)
    }

    fn write32(&mut self, offset: usize, value: u32) {
        let data = if offset == 0x1000 + 4 && value == 1 {
            // SAFETY: this is the actual current DCBAA output context and EP0
            // TRB memory retained by the controller under test. No pointer is
            // synthesized as proof of readiness or retirement.
            unsafe {
                let output = (self.output as *const u64).read_volatile();
                let at = self.cursor.get_or_insert_with(|| {
                    ((output + self.context as u64 + 8) as *const u64).read_volatile() & !15
                });
                let mut selected = None;
                let mut descriptor = false;
                loop {
                    let control = ((*at + 12) as *const u32).read_volatile();
                    let parameter = (*at as *const u64).read_volatile();
                    let length = ((*at + 8) as *const u32).read_volatile() as usize;
                    let kind = control >> 10 & 63;
                    if kind == LINK {
                        *at = parameter & !15;
                        continue;
                    }
                    *at += TRB as u64;
                    if kind == SETUP {
                        let request = parameter.to_le_bytes();
                        descriptor = request[1] == GET_DESCRIPTOR
                            && request[3] == DEVICE_DESCRIPTOR
                            && u16::from_le_bytes([request[6], request[7]]) == 18;
                    } else if kind == DATA && descriptor {
                        selected = Some((parameter, length));
                    } else if kind == STATUS {
                        break;
                    }
                }
                selected
            }
        } else {
            None
        };
        self.inner.write32(offset, value);
        if let Some((buffer, length)) = data {
            assert_eq!(length, 18);
            // SAFETY: the actual peer just completed this descriptor DMA. The
            // adversarial device returns an invalid descriptor's bLength byte.
            if self.stall {
                self.hardware.borrow_mut().stall_completed_control(1);
            } else {
                // SAFETY: the pointer addresses this test's own live pages, and the stopped model
                // writes nothing concurrently.
                unsafe { (buffer as *mut u8).write_volatile(0) };
            }
            self.hardware.borrow_mut().fault = self.cleanup_fault;
            *self.corrupted.borrow_mut() += 1;
        }
    }

    fn write64(&mut self, offset: usize, value: u64) {
        self.inner.write64(offset, value);
    }
}

struct Unused;
impl Registers for Unused {
    fn read32(&mut self, _: usize) -> u32 {
        panic!("temporary register owner used")
    }
    fn write32(&mut self, _: usize, _: u32) {
        panic!("temporary register owner used")
    }
}

#[test]
fn failed_real_descriptor_enumeration_stops_ep0_before_returning_unpublished_slot() {
    for speed in [HIGH_SPEED, SUPER_SPEED] {
        for context in [32, 64] {
            let mut memory = vec![0u64; 512 * 1024];
            let (shared, old, hardware, mut dma) =
                reset::tests::fixture(&mut memory, speed, context, 3);
            let mut c = shared.borrow_mut();
            let attachment = c.slot(old.slot).unwrap().attachment;
            c.disable_slot(old.slot, Ownership::Retired).unwrap();
            c.reset_root_device(attachment).unwrap();
            let inner = core::mem::replace(&mut c.registers, Box::new(Unused));
            let corrupted = Rc::new(RefCell::new(0));
            c.registers = Box::new(InvalidDescriptor {
                inner,
                hardware: hardware.clone(),
                output: c.dcbaa.physical() + 8,
                context,
                cursor: None,
                corrupted: corrupted.clone(),
                cleanup_fault: Fault::None,
                stall: false,
            });
            let before = hardware.borrow().commands_seen.len();
            let error = c.identify(attachment, "invalid physical descriptor".into(), &mut dma);
            assert_eq!(
                error.unwrap_err().1,
                BlockError::Unsupported("invalid USB device descriptor/configuration count")
            );
            assert_eq!(*corrupted.borrow(), 1);
            assert_eq!(
                hardware.borrow().commands_seen[before..],
                [
                    (ENABLE_SLOT, 0, 0),
                    (ADDRESS_DEVICE, 1, 0),
                    (STOP_ENDPOINT, 1, 1),
                    (SET_DEQUEUE, 1, 1),
                    (reset::DISABLE_SLOT, 1, 0),
                ]
            );
            assert_eq!(c.slot_ownership[1], Ownership::Vacant);
            assert!(c.slots[1].is_none());
            assert_eq!(c.dcbaa.read::<u64>(8), 0);
            assert!(c.power.retained(1), "physical current survives Disable");
        }
    }
}

#[test]
fn failed_real_descriptor_cleanup_retains_ep0_dma_on_stop_reset_and_dequeue_faults() {
    for (fault, stall) in [
        (Fault::Stop(1), false),
        (Fault::SilentStop(1), false),
        (Fault::Dequeue(1), false),
        (Fault::Stop(1), true),
    ] {
        let mut memory = vec![0u64; 512 * 1024];
        let (shared, old, hardware, mut dma) =
            reset::tests::fixture(&mut memory, HIGH_SPEED, 64, 3);
        let mut c = shared.borrow_mut();
        let attachment = c.slot(old.slot).unwrap().attachment;
        c.disable_slot(old.slot, Ownership::Retired).unwrap();
        c.reset_root_device(attachment).unwrap();
        let inner = core::mem::replace(&mut c.registers, Box::new(Unused));
        let corrupted = Rc::new(RefCell::new(0));
        c.registers = Box::new(InvalidDescriptor {
            inner,
            hardware: hardware.clone(),
            output: c.dcbaa.physical() + 8,
            context: 64,
            cursor: None,
            corrupted: corrupted.clone(),
            cleanup_fault: fault,
            stall,
        });
        let before = hardware.borrow().commands_seen.len();
        assert!(
            c.identify(attachment, "faulting real EP0".into(), &mut dma)
                .is_err()
        );
        assert_eq!(*corrupted.borrow(), 1);
        let seen = hardware.borrow().commands_seen[before..].to_vec();
        assert!(seen.contains(&(if stall { RESET_ENDPOINT } else { STOP_ENDPOINT }, 1, 1)));
        assert!(!seen.iter().any(|(kind, _, _)| *kind == reset::DISABLE_SLOT));
        assert_eq!(c.slot_ownership[1], Ownership::Enabled);
        let output = c.slots[1].as_ref().unwrap()._output.physical();
        let control = c.slots[1].as_ref().unwrap().control.physical();
        assert_ne!(output, 0);
        assert_ne!(control, 0);
        assert_eq!(c.dcbaa.read::<u64>(8), output);
        assert!(c.slots[1].as_ref().unwrap().retiring);
        assert!(
            c.slots[1].as_ref().unwrap().endpoints[1]
                .as_ref()
                .unwrap()
                .poisoned
        );
        assert!(c.power.retained(1));
        let accesses = hardware.borrow().accesses;
        assert!(c.connected(1).is_err());
        assert!(
            c.control(1, setup(0x80, GET_DESCRIPTOR, 1 << 8, 0, 8), &[])
                .is_err()
        );
        assert_eq!(hardware.borrow().accesses, accesses);
    }
}

enum Operation {
    Iso,
    RejectAddress,
    FatalAfterDisable,
}

/// Additional wire operations of the same independent peer. A submitted Isoch
/// TRB remains hardware-owned in its actual pending-TD map until its ordered
/// stopped event; a rejected Address Device never activates EP0.
struct AdditionalOperation {
    inner: Box<dyn Registers>,
    hardware: Rc<RefCell<Hardware>>,
    operation: Operation,
    disable_status_reads: Option<usize>,
}

impl Registers for AdditionalOperation {
    fn read32(&mut self, offset: usize) -> u32 {
        let status = self.inner.read32(offset);
        if offset == 0x40 + USBSTS
            && let Some(reads) = self.disable_status_reads.as_mut()
        {
            *reads += 1;
            // First read receives the real Disable completion. The following
            // post-command readiness read independently reports fatal USBSTS.
            if *reads > 1 {
                return status | HCE;
            }
        }
        status
    }

    fn write32(&mut self, offset: usize, value: u32) {
        if matches!(self.operation, Operation::Iso) && offset == 0x1004 && value == 3 {
            self.hardware.borrow_mut().queue_iso_service(1, 3);
            return;
        }
        if matches!(self.operation, Operation::RejectAddress) && offset == 0x1000 {
            let rejected = self.hardware.borrow_mut().reject_pending_address();
            if rejected {
                return;
            }
        }
        let disable = matches!(self.operation, Operation::FatalAfterDisable)
            && offset == 0x1000
            && self.hardware.borrow().pending_command_kind() == reset::DISABLE_SLOT;
        self.inner.write32(offset, value);
        if disable {
            self.disable_status_reads = Some(0);
        }
    }

    fn write64(&mut self, offset: usize, value: u64) {
        self.inner.write64(offset, value);
    }
}

#[test]
fn whole_slot_retirement_drains_actual_iso_service_and_retains_dma_on_failure() {
    for speed in [HIGH_SPEED, SUPER_SPEED] {
        for context in [32, 64] {
            for fault in [
                Fault::None,
                Fault::Stop(3),
                Fault::SilentStop(3),
                Fault::Dequeue(3),
            ] {
                let mut memory = vec![0u64; 512 * 1024];
                let (shared, device, hardware, mut dma) =
                    reset::tests::fixture(&mut memory, speed, context, 3);
                let mut c = shared.borrow_mut();
                let endpoint = Endpoint {
                    address: 0x81,
                    attributes: 1,
                    max_packet: 1024,
                    interval: 1,
                    companion: (speed >= SUPER_SPEED).then_some(SuperSpeedCompanion {
                        max_burst: 0,
                        attributes: 0,
                        bytes_per_interval: 1024,
                    }),
                };
                c.configure(device.slot, &[endpoint], None, &mut dma)
                    .unwrap();
                let inner = core::mem::replace(&mut c.registers, Box::new(Unused));
                c.registers = Box::new(AdditionalOperation {
                    inner,
                    hardware: hardware.clone(),
                    operation: Operation::Iso,
                    disable_status_reads: None,
                });
                let mut payload = dma.allocate(4096, 4096).unwrap();
                payload.bytes_mut().fill(0xa5);
                let ticket = c
                    .submit_iso(device.slot, 3, payload.physical(), 32)
                    .unwrap();
                hardware.borrow_mut().fault = fault;
                let output = c.slot(device.slot).unwrap()._output.physical();
                let before = hardware.borrow().commands_seen.len();
                assert_eq!(
                    c.disable_slot(device.slot, Ownership::Retired).is_ok(),
                    fault == Fault::None
                );
                let seen = hardware.borrow().commands_seen[before..].to_vec();
                assert!(seen.contains(&(STOP_ENDPOINT, device.slot, 3)));
                if fault == Fault::None {
                    assert_eq!(seen.last(), Some(&(reset::DISABLE_SLOT, device.slot, 0)));
                    assert_eq!(c.dcbaa.read::<u64>(8), 0);
                    assert_eq!(c.slot_ownership[1], Ownership::Retired);
                } else {
                    assert!(!seen.iter().any(|(kind, _, _)| *kind == reset::DISABLE_SLOT));
                    assert_eq!(c.dcbaa.read::<u64>(8), output);
                    assert_eq!(c.slot_ownership[1], Ownership::Enabled);
                }
                assert_eq!(c.slot(device.slot).unwrap()._output.physical(), output);
                assert!(c.power.retained(device.slot));
                assert_eq!(payload.bytes(), &[0xa5; 4096]);
                let accesses = hardware.borrow().accesses;
                assert!(c.completed_iso(&ticket).unwrap().is_err());
                assert!(c.device(device.id).is_err());
                assert_eq!(hardware.borrow().accesses, accesses);
            }
        }
    }
}

#[test]
fn failed_actual_address_device_retires_disabled_ep0_without_illegal_stop_or_dequeue() {
    for context in [32, 64] {
        let mut memory = vec![0u64; 512 * 1024];
        let (shared, old, hardware, mut dma) =
            reset::tests::fixture(&mut memory, HIGH_SPEED, context, 3);
        let mut c = shared.borrow_mut();
        let attachment = c.slot(old.slot).unwrap().attachment;
        c.disable_slot(old.slot, Ownership::Retired).unwrap();
        c.reset_root_device(attachment).unwrap();
        let inner = core::mem::replace(&mut c.registers, Box::new(Unused));
        c.registers = Box::new(AdditionalOperation {
            inner,
            hardware: hardware.clone(),
            operation: Operation::RejectAddress,
            disable_status_reads: None,
        });
        let before = hardware.borrow().commands_seen.len();
        let error = c.identify(attachment, "rejected actual address".into(), &mut dma);
        assert_eq!(error.unwrap_err().1, BlockError::Device { status: 4 });
        assert_eq!(
            hardware.borrow().commands_seen[before..],
            [
                (ENABLE_SLOT, 0, 0),
                (ADDRESS_DEVICE, 1, 0),
                (reset::DISABLE_SLOT, 1, 0),
            ]
        );
        assert_eq!(c.slot_ownership[1], Ownership::Vacant);
        assert!(c.slots[1].is_none());
        assert_eq!(c.dcbaa.read::<u64>(8), 0);
        assert!(c.power.retained(1));
    }
}

#[test]
fn fatal_status_after_actual_disable_ack_preserves_dcbaa_and_retained_allocation() {
    let mut memory = vec![0u64; 512 * 1024];
    let (shared, old, hardware, _dma) = configured(&mut memory, HIGH_SPEED, 32);
    let mut c = shared.borrow_mut();
    let output = c.slot(old.slot).unwrap()._output.physical();
    let inner = core::mem::replace(&mut c.registers, Box::new(Unused));
    c.registers = Box::new(AdditionalOperation {
        inner,
        hardware: hardware.clone(),
        operation: Operation::FatalAfterDisable,
        disable_status_reads: None,
    });
    assert_eq!(
        c.disable_slot(old.slot, Ownership::Retired),
        Err((
            "post-Disable Slot controller status",
            BlockError::Device { status: HCE }
        ))
    );
    assert_eq!(
        hardware.borrow().commands_seen.last(),
        Some(&(reset::DISABLE_SLOT, old.slot, 0))
    );
    assert_eq!(c.slot_ownership[1], Ownership::Enabled);
    assert_eq!(c.dcbaa.read::<u64>(8), output);
    assert_eq!(c.slot(old.slot).unwrap()._output.physical(), output);
    assert!(c.slot(old.slot).unwrap().retiring);
    assert!(c.power.retained(old.slot));
    assert!(c.command_poisoned);
    let accesses = hardware.borrow().accesses;
    assert!(c.device(old.id).is_err());
    assert_eq!(hardware.borrow().accesses, accesses);
}
