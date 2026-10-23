// SPDX-License-Identifier: GPL-2.0-only
//! Authored physical register/TRB model checks; UNRUN in the source-only cut.
use super::super::super::Registers as RegisterIo;
use super::*;
use crate::bus::dma::RegionAllocator;
use alloc::collections::BTreeMap;
use hub::model::{Hardware, Node, RegistersModel};

struct Registers {
    bus: RegistersModel,
    state: Rc<RefCell<State>>,
}
#[derive(Default)]
struct State {
    save: usize,
    restore: usize,
    refuse_suspend: bool,
}
impl RegisterIo for Registers {
    fn read32(&mut self, at: usize) -> u32 {
        self.bus.read32(at)
    }
    fn write32(&mut self, at: usize, value: u32) {
        self.bus.write32(at, value);
        if at == 0x440 && value & LINK_STROBE != 0 {
            let mut bus = self.bus.0.borrow_mut();
            let port = bus.root_status.as_mut().unwrap();
            let requested = value & PLS;
            if requested != U3 << PLS_SHIFT || !self.state.borrow().refuse_suspend {
                let previous = *port & PLS;
                *port = *port & !PLS | requested;
                if previous != requested {
                    *port |= LINK_CHANGE;
                }
            }
        }
        if at == 0x40 {
            if value & (1 << 8) != 0 {
                self.state.borrow_mut().save += 1;
            }
            if value & (1 << 9) != 0 {
                let mut state = self.state.borrow_mut();
                assert!(
                    state.save > state.restore,
                    "restore without an acknowledged save request"
                );
                state.restore += 1;
            }
        }
    }
    fn size(&self) -> Option<usize> {
        Some(0x2000)
    }
}

fn fixture(
    memory: &mut [u64],
    speed: u8,
    hub: bool,
) -> (
    Host,
    Vec<Device>,
    Rc<RefCell<Hardware>>,
    Rc<RefCell<State>>,
    RegionAllocator,
) {
    let start = memory.as_mut_ptr() as u64;
    // SAFETY: the caller retains this exclusive backing through every owner.
    let mut dma =
        unsafe { RegionAllocator::new(start..start + core::mem::size_of_val(memory) as u64) };
    let nodes = if hub {
        BTreeMap::from([(0, Node::hub(speed, 1)), (1, Node::leaf(speed))])
    } else {
        BTreeMap::from([(0, Node::leaf(speed))])
    };
    let hardware = Rc::new(RefCell::new(Hardware::new(64, nodes)));
    hardware.borrow_mut().root_status = Some(PP | CCS | PED | u32::from(speed) << PORT_SPEED_SHIFT);
    let state = Rc::new(RefCell::new(State::default()));
    let registers = Registers {
        bus: RegistersModel(hardware.clone()),
        state: state.clone(),
    };
    let mut c = Controller::new(
        Box::new(registers),
        Clock {
            ticks_per_microsecond: 1,
        },
        &mut dma,
        "suspend model".into(),
    )
    .unwrap();
    let mut failures = Vec::new();
    let devices = c.enumerate(&mut dma, &mut failures);
    assert!(failures.is_empty(), "{failures:?}");
    let shared = Rc::new(RefCell::new(c));
    let host = Host::new(shared, &devices, &mut dma, &mut failures);
    assert!(failures.is_empty(), "{failures:?}");
    (host, devices, hardware, state, dma)
}

#[test]
fn topology_suspend_uses_real_hub_links_and_controller_save_then_fresh_owners() {
    for speed in [HIGH_SPEED, SUPER_SPEED] {
        let mut memory = vec![0u64; 1024 * 1024];
        let (mut host, old, hardware, state, mut dma) = fixture(&mut memory, speed, true);
        let removed = host.suspend();
        assert!(
            removed.added.failures.is_empty(),
            "{:?}",
            removed.added.failures
        );
        assert_eq!(removed.removed.len(), old.len());
        assert_eq!(state.borrow().save, 1);
        assert_eq!(
            hardware.borrow().root_status.unwrap() & PLS,
            U3 << PLS_SHIFT
        );
        for old in &old {
            assert!(host.controller.borrow_mut().device(old.id).is_err());
        }
        assert!(
            host.poll(&mut dma, &crate::firmware::HandoffProvider::new(None))
                .added
                .devices
                .is_empty()
        );
        let added = host.resume(&mut dma, &crate::firmware::HandoffProvider::new(None));
        assert!(
            added.added.failures.is_empty(),
            "{:?}",
            added.added.failures
        );
        assert_eq!(state.borrow().restore, 1);
        assert_eq!(added.added.devices.len(), old.len());
        for old in &old {
            assert!(host.controller.borrow_mut().device(old.id).is_err());
        }
        for fresh in &added.added.devices {
            assert!(host.controller.borrow_mut().device(fresh.id).is_ok());
        }
    }
}

#[test]
fn unacknowledged_root_suspend_never_saves_or_revives_consumers() {
    let mut memory = vec![0u64; 512 * 1024];
    let (mut host, old, hardware, state, mut dma) = fixture(&mut memory, HIGH_SPEED, false);
    state.borrow_mut().refuse_suspend = true;
    let removed = host.suspend();
    assert_eq!(removed.removed.len(), old.len());
    assert!(!removed.added.failures.is_empty());
    assert_eq!(state.borrow().save, 0);
    let before = (hardware.borrow().mmio_reads, hardware.borrow().mmio_writes);
    for device in old {
        assert!(host.controller.borrow_mut().device(device.id).is_err());
    }
    assert_eq!(
        (hardware.borrow().mmio_reads, hardware.borrow().mmio_writes),
        before
    );
    let refused = host.resume(&mut dma, &crate::firmware::HandoffProvider::new(None));
    assert!(!refused.added.failures.is_empty());
    assert_eq!(state.borrow().restore, 0);
}
