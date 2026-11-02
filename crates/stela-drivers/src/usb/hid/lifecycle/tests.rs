use super::*;
use crate::{
    bus::pci::{Address, ConfigSpace, Function},
    usb::xhci::{self, Registers, model},
};
use alloc::{boxed::Box, rc::Rc, vec};
use core::cell::{Cell, RefCell};

struct Config;
impl ConfigSpace for Config {
    fn read32(&self, at: u16) -> core::result::Result<u32, crate::bus::pci::ConfigError> {
        Ok({
            match at {
                0 => 0x0014_1b36,
                8 => 0x0c03_3001,
                _ => 0,
            }
        })
    }
    fn write32(
        &mut self,
        _: u16,
        _: u32,
    ) -> core::result::Result<(), crate::bus::pci::ConfigError> {
        panic!("read-only qualification")
    }

    fn read8(&self, offset: u16) -> core::result::Result<u8, crate::bus::pci::ConfigError> {
        Ok((self.read32(offset & !3)? >> ((offset & 3) * 8)) as u8)
    }
    fn write8(&mut self, _: u16, _: u8) -> core::result::Result<(), crate::bus::pci::ConfigError> {
        panic!("unexpected narrow configuration write")
    }
    fn read16(&self, offset: u16) -> core::result::Result<u16, crate::bus::pci::ConfigError> {
        Ok((self.read32(offset & !3)? >> ((offset & 2) * 8)) as u16)
    }
    fn write16(
        &mut self,
        _: u16,
        _: u16,
    ) -> core::result::Result<(), crate::bus::pci::ConfigError> {
        panic!("unexpected narrow configuration write")
    }
}
struct Trap {
    original: Box<dyn Registers>,
    active: Rc<Cell<bool>>,
}
impl Registers for Trap {
    fn read32(&mut self, at: usize) -> u32 {
        assert!(!self.active.get(), "stale HID reached MMIO read");
        self.original.read32(at)
    }
    fn write32(&mut self, at: usize, value: u32) {
        assert!(!self.active.get(), "stale HID reached MMIO write");
        self.original.write32(at, value);
    }
}

fn fixture(
    dma: &mut dyn DmaAllocator,
) -> (UsbInput, Rc<RefCell<model::CancelModel>>, Rc<Cell<bool>>) {
    let mut function = Function::new(
        Address {
            segment: 0,
            bus: 0,
            device: 1,
            function: 0,
        },
        Config,
    )
    .unwrap();
    let trap = Rc::new(Cell::new(false));
    let (controller, peer) = model::forwarding_fixture(
        dma,
        &[vec![9, 2, 9, 0, 0, 1, 0, 0x80, 50]],
        xhci::FULL_SPEED,
        &mut function,
        |original, _| {
            Box::new(Trap {
                original,
                active: trap.clone(),
            })
        },
    );
    let shared = Rc::new(RefCell::new(controller));
    let mut physical = model::device(Vec::new());
    physical.id = shared.borrow().test_device_id(1).unwrap();
    let endpoint = Endpoint {
        address: 0x81,
        attributes: 3,
        max_packet: 16,
        interval: 1,
        companion: None,
    };
    {
        let mut c = shared.borrow_mut();
        let mut access = c.device(physical.id).unwrap();
        access.set_configuration(1).unwrap();
        access.configure(&[endpoint], None, dma).unwrap();
    }
    let report = &super::super::tests::NUMBERED_KEYBOARD;
    peer.borrow_mut()
        .descriptors
        .push((REPORT_DESCRIPTOR, 0, report.to_vec()));
    let interface = Interface {
        number: 4,
        alternate: 0,
        class: CLASS,
        subclass: BOOT,
        protocol: KEYBOARD,
        endpoints: vec![endpoint],
        extra: vec![vec![
            9,
            HID_DESCRIPTOR,
            0x11,
            1,
            0,
            1,
            REPORT_DESCRIPTOR,
            report.len() as u8,
            0,
        ]],
    };
    let input = UsbInput::new(shared, &physical, &interface, endpoint, dma)
        .unwrap()
        .unwrap();
    (input, peer, trap)
}

#[test]
fn stale_hid_stop_and_cached_stopped_success_preserve_state_before_mmio() {
    for stopped in [false, true] {
        let mut ram = vec![0u64; 512 * 1024];
        let start = ram.as_mut_ptr() as u64;
        // SAFETY: both original addressed controllers keep exclusive live RAM.
        let mut dma = unsafe { model::RegionAllocator::new(start..start + ram.len() as u64 * 8) };
        let (mut previous, old_peer, _) = fixture(&mut dma);
        let (mut current, peer, trap) = fixture(&mut dma);
        assert_eq!(previous.id.hardware_slot(), current.id.hardware_slot());
        assert_ne!(previous.id, current.id);
        let key_report = vec![1, 0, 0, 4, 0, 0, 0, 0, 0];
        old_peer.borrow_mut().push_event(key_report.clone());
        assert_eq!(
            previous.poll_hid().inputs,
            [Input::Key {
                usage: 4,
                pressed: true
            }]
        );
        if stopped {
            assert_eq!(
                previous.stop_hid().unwrap().inputs,
                [Input::Key {
                    usage: 4,
                    pressed: false
                }]
            );
            assert_eq!(previous.state(), State::Stopped);
        }
        assert!(current.poll_hid().reports.is_empty());
        assert!(current.queued.is_some());
        peer.borrow_mut().push_event(key_report);
        peer.borrow_mut().receive(3); // Real DMA data and unread event-ring completion.
        let original = previous.controller.clone();
        previous.controller = current.controller.clone();
        let before_state = (
            previous.state,
            previous.error.clone(),
            previous.queued,
            previous.retry,
            previous.translator.held.clone(),
            previous.translator.buttons,
            previous.translator.position,
            previous.failed,
            previous.translator.dropped,
            previous.translator.last_report.clone(),
        );
        let before = ram.clone();
        trap.set(true);
        assert!(previous.stop_hid().is_err());
        assert!(previous.stop().is_err());
        assert!(previous.restart().is_err());
        assert_eq!(
            (
                previous.state,
                previous.error.clone(),
                previous.queued,
                previous.retry,
                previous.translator.held.clone(),
                previous.translator.buttons,
                previous.translator.position,
                previous.failed,
                previous.translator.dropped,
                previous.translator.last_report.clone()
            ),
            before_state
        );
        assert_eq!(ram, before);
        trap.set(false);
        assert_eq!(
            current.poll_hid().inputs,
            [Input::Key {
                usage: 4,
                pressed: true
            }]
        );
        // Restoring the original controller lets its owner complete
        // lifecycle work. The rejected alias changed neither held keys nor
        // decoder state, so a running owner still emits its real release.
        previous.controller = original;
        let stopped_result = previous.stop_hid().unwrap();
        if stopped {
            assert!(stopped_result.inputs.is_empty());
            assert!(stopped_result.events.is_empty());
        } else {
            assert_eq!(
                stopped_result.inputs,
                [Input::Key {
                    usage: 4,
                    pressed: false
                }]
            );
            assert!(stopped_result.events.contains(&events::Event::Keyboard {
                usage: 4,
                pressed: false
            }));
        }
    }
}
#[test]
fn same_controller_root_reuse_refuses_kept_hid_stop_without_touching_current_dma() {
    for speed in [xhci::HIGH_SPEED, xhci::SUPER_SPEED] {
        for context in [32, 64] {
            for stopped in [false, true] {
                let mut memory = vec![0u64; 512 * 1024];
                let (shared, original, hardware, mut dma) =
                    model::reset_hid_fixture(&mut memory, speed, context, 1);
                let interface =
                    crate::usb::descriptor::interfaces(&original.configuration).remove(0);
                let endpoint = interface.endpoints[0];
                shared
                    .borrow_mut()
                    .device(original.id)
                    .unwrap()
                    .configure(&interface.endpoints, None, &mut dma)
                    .unwrap();
                let mut previous =
                    UsbInput::new(shared.clone(), &original, &interface, endpoint, &mut dma)
                        .unwrap()
                        .unwrap();
                let key_report = vec![0, 0, 4, 0, 0, 0, 0, 0];
                assert!(previous.poll_hid().reports.is_empty());
                hardware
                    .borrow_mut()
                    .feed_hid_report(original.slot, &key_report);
                assert_eq!(
                    previous.poll_hid().inputs,
                    [Input::Key {
                        usage: 4,
                        pressed: true
                    }]
                );
                if stopped {
                    assert_eq!(
                        previous.stop_hid().unwrap().inputs,
                        [Input::Key {
                            usage: 4,
                            pressed: false
                        }]
                    );
                    assert_eq!(previous.state(), State::Stopped);
                }
                // SAFETY: the fixture exclusively owns the original complete
                // leaf inventory; old consumers are exercised only
                // for pure rejection after this acknowledged retirement.
                let mut fresh = unsafe {
                    shared.borrow_mut().reset_and_reuse_root(
                        &original,
                        &interface.endpoints,
                        &mut dma,
                    )
                }
                .unwrap();
                fresh.configuration = fresh.configurations[0].clone();
                assert_eq!(fresh.slot, original.slot);
                assert_ne!(fresh.id, original.id);
                assert_eq!(hardware.borrow().resets, 1);
                assert_eq!(hardware.borrow().enables, [original.slot, fresh.slot]);
                assert!(
                    hardware
                        .borrow()
                        .commands_seen
                        .iter()
                        .any(|(kind, slot, _)| *kind == 10 && *slot == original.slot)
                );
                let interface = crate::usb::descriptor::interfaces(&fresh.configuration).remove(0);
                {
                    let mut c = shared.borrow_mut();
                    let mut access = c.device(fresh.id).unwrap();
                    access
                        .set_configuration(fresh.configuration_value())
                        .unwrap();
                    access
                        .configure(&interface.endpoints, None, &mut dma)
                        .unwrap();
                }
                let mut current = UsbInput::new(
                    shared.clone(),
                    &fresh,
                    &interface,
                    interface.endpoints[0],
                    &mut dma,
                )
                .unwrap()
                .unwrap();
                assert!(Rc::ptr_eq(&previous.controller, &current.controller));
                assert!(current.poll_hid().reports.is_empty());
                hardware
                    .borrow_mut()
                    .feed_hid_report(fresh.slot, &key_report);
                let previous_state = (
                    previous.state,
                    previous.error.clone(),
                    previous.queued,
                    previous.retry,
                    previous.translator.held.clone(),
                    previous.translator.buttons,
                    previous.translator.position,
                    previous.failed,
                    previous.translator.dropped,
                    previous.translator.last_report.clone(),
                );
                let current_ticket = current.queued;
                let accesses = hardware.borrow().accesses;
                let before = memory.clone();
                hardware.borrow_mut().trap_mmio = true;
                assert!(previous.stop_hid().is_err());
                assert!(previous.stop().is_err());
                assert!(previous.restart().is_err());
                assert_eq!(hardware.borrow().accesses, accesses);
                assert_eq!(memory, before);
                assert_eq!(current.queued, current_ticket);
                assert_eq!(
                    (
                        previous.state,
                        previous.error.clone(),
                        previous.queued,
                        previous.retry,
                        previous.translator.held.clone(),
                        previous.translator.buttons,
                        previous.translator.position,
                        previous.failed,
                        previous.translator.dropped,
                        previous.translator.last_report.clone()
                    ),
                    previous_state
                );
                hardware.borrow_mut().trap_mmio = false;
                assert_eq!(
                    current.poll_hid().inputs,
                    [Input::Key {
                        usage: 4,
                        pressed: true
                    }]
                );
                assert_eq!(hardware.borrow().resets, 1);
            }
        }
    }
}
