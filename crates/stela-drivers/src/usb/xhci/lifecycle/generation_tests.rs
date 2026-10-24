// SPDX-License-Identifier: GPL-2.0-only
//! Actual enumerated hub/controller DMA peers. Distinct independent controllers
//! issue genuine identities for identical hardware slot numbers; trap all MMIO
//! when an original topology owner is presented to the replacement generation.
use super::*;
use crate::bus::dma::RegionAllocator;
use alloc::collections::BTreeMap;

// Match the actual PORTSC link handshake used by suspend's existing model.
// Plain hub RegistersModel deliberately models reset/enumeration only.
struct SleepRegisters {
    bus: hub::model::RegistersModel,
    saves: usize,
    restores: usize,
}
impl Registers for SleepRegisters {
    fn read32(&mut self, at: usize) -> u32 {
        self.bus.read32(at)
    }
    fn write32(&mut self, at: usize, value: u32) {
        const ROOT_LINK_STROBE: u32 = 1 << 16;
        const ROOT_LINK_CHANGE: u32 = 1 << 22;
        self.bus.write32(at, value);
        if at == 0x440 && value & ROOT_LINK_STROBE != 0 {
            let mut hardware = self.bus.0.borrow_mut();
            let port = hardware.root_status.as_mut().unwrap();
            let requested = value & PLS;
            if *port & PLS != requested {
                *port |= ROOT_LINK_CHANGE;
            }
            *port = *port & !PLS | requested;
        }
        if at == 0x40 {
            if value & (1 << 8) != 0 {
                self.saves += 1;
            }
            if value & (1 << 9) != 0 {
                assert!(
                    self.saves > self.restores,
                    "restore without acknowledged save"
                );
                self.restores += 1;
            }
        }
    }
    fn size(&self) -> Option<usize> {
        Some(0x2000)
    }
}

fn fixture(dma: &mut dyn DmaAllocator, speed: u8) -> (Host, Shared) {
    let leaf = || {
        let mut node = hub::model::Node::leaf(speed);
        node.interface_class = Some(0xff);
        node
    };
    let nodes = BTreeMap::from([
        (0, hub::model::Node::hub(speed, 2)),
        (1, leaf()),
        (2, leaf()),
    ]);
    let (mut controller, hardware) = hub::tests::controller(dma, 64, nodes);
    let mut failures = Vec::new();
    let devices = controller.enumerate(dma, &mut failures);
    assert!(failures.is_empty(), "{failures:?}");
    assert_eq!(devices.len(), 3);
    hardware.borrow_mut().root_status = Some(PP | CCS | PED | u32::from(speed) << PORT_SPEED_SHIFT);
    controller.registers = Box::new(SleepRegisters {
        bus: hub::model::RegistersModel(hardware),
        saves: 0,
        restores: 0,
    });
    let shared = Rc::new(RefCell::new(controller));
    let host = Host::new(shared.clone(), &devices, dma, &mut failures);
    assert!(failures.is_empty(), "{failures:?}");
    (host, shared)
}

fn trapped(controller: &Shared, operation: impl FnOnce()) {
    struct Trap;
    impl Registers for Trap {
        fn read32(&mut self, _: usize) -> u32 {
            panic!("stale topology reached MMIO read")
        }
        fn write32(&mut self, _: usize, _: u32) {
            panic!("stale topology reached MMIO write")
        }
    }
    let snapshot = |c: &Controller| {
        let slots = c
            .slots
            .iter()
            .enumerate()
            .filter_map(|(slot, state)| {
                state.as_ref().map(|state| {
                    (
                        slot,
                        state.generation,
                        state.parent_id,
                        state.suspended,
                        state.retiring,
                        (
                            state.input.bytes().to_vec(),
                            state._output.bytes().to_vec(),
                            state.control.bytes().to_vec(),
                        ),
                        state.current_configuration,
                        c.slot_ownership[slot],
                        c.power.snapshot(slot as u8),
                        state
                            .endpoints
                            .iter()
                            .flatten()
                            .map(|ep| {
                                (
                                    ep.ring.index,
                                    ep.ring.cycle,
                                    ep.in_flight,
                                    ep.poisoned,
                                    ep.ring.buffer.bytes().to_vec(),
                                )
                            })
                            .collect::<Vec<_>>(),
                    )
                })
            })
            .collect::<Vec<_>>();
        let events = c
            .pending
            .iter()
            .map(|e| (e.parameter, e.status, e.control))
            .collect::<Vec<_>>();
        (
            slots,
            events,
            c.event_index,
            c.event_cycle,
            c.dcbaa.bytes().to_vec(),
        )
    };
    let mut c = controller.borrow_mut();
    let before = snapshot(&c);
    let registers = core::mem::replace(&mut c.registers, Box::new(Trap));
    drop(c);
    operation();
    let mut c = controller.borrow_mut();
    assert_eq!(snapshot(&c), before);
    c.registers = registers;
}

#[test]
fn retained_hub_parent_and_retirement_authority_refuse_same_number_generation_before_effects() {
    for speed in [HIGH_SPEED, SUPER_SPEED] {
        let mut old_memory = vec![0u64; 512 * 1024];
        let mut new_memory = vec![0u64; 512 * 1024];
        let start = old_memory.as_mut_ptr() as u64;
        // SAFETY: both peers retain distinct live DMA arenas through all owners.
        let mut old_dma =
            unsafe { RegionAllocator::new(start..start + old_memory.len() as u64 * 8) };
        let start = new_memory.as_mut_ptr() as u64;
        // SAFETY: every replacement ring/context remains inside this allocation.
        let mut new_dma =
            unsafe { RegionAllocator::new(start..start + new_memory.len() as u64 * 8) };
        let (mut original, _) = fixture(&mut old_dma, speed);
        let (mut current, shared) = fixture(&mut new_dma, speed);
        let old = original.hubs[0].device.id;
        let fresh = current.hubs[0].device.id;
        assert_eq!(old.hardware_slot(), fresh.hardware_slot());
        assert_ne!(old, fresh);
        let old_leaf = original
            .devices
            .iter()
            .find(|d| d.slot != old.hardware_slot())
            .unwrap()
            .id;
        let fresh_leaf = current
            .devices
            .iter()
            .find(|d| d.slot == old_leaf.hardware_slot())
            .unwrap()
            .id;
        assert_ne!(old_leaf, fresh_leaf);
        assert_eq!(
            shared
                .borrow_mut()
                .device(fresh_leaf)
                .unwrap()
                .control(setup(0x80, GET_STATUS, 0, 0, 2), &[])
                .unwrap()
                .len(),
            2
        );
        current
            .hub(0, &mut new_dma, &mut Changes::default())
            .unwrap();
        assert!(current.hubs[0].pending.is_some());
        let current_bitmap = current.hubs[0].bitmap.bytes().to_vec();
        original.controller = shared.clone();
        trapped(&shared, || {
            assert!(
                original
                    .hub(0, &mut old_dma, &mut Changes::default())
                    .is_err()
            );
            assert!(
                original
                    .hub_port(0, 1, &mut old_dma, &mut Changes::default())
                    .is_err()
            );
            assert!(
                original
                    .start_recovery(0, Some(1), &mut Changes::default())
                    .is_err()
            );
            assert!(original.retire(old, &mut Changes::default()).is_err());
            let mut c = shared.borrow_mut();
            assert!(c.device(old_leaf).is_err());
            assert!(c.current_hub_port_reset(old, 1, 1).is_err());
            assert!(c.observe_current_ancestors_for(old, true).is_err());
            assert!(c.superspeed_port_for(old, 1, None).is_err());
            assert!(c.hub_port_for(old, 1).is_err());
            assert!(c.suspend_hub_port_for(old, 1).is_err());
            assert!(c.resume_hub_port_for(old, 1).is_err());
        });
        assert!(current.hubs[0].pending.is_some());
        assert_eq!(current.hubs[0].bitmap.bytes(), current_bitmap);
        assert_eq!(
            shared
                .borrow_mut()
                .device(fresh_leaf)
                .unwrap()
                .control(setup(0x80, GET_STATUS, 0, 0, 2), &[])
                .unwrap()
                .len(),
            2
        );
    }
}

#[test]
fn original_child_identity_cannot_release_current_or_retire_parent_after_parent_seal_changes() {
    let mut memory = vec![0u64; 512 * 1024];
    let mut foreign_memory = vec![0u64; 512 * 1024];
    let start = memory.as_mut_ptr() as u64;
    // SAFETY: all original hardware DMA allocations remain live.
    let mut dma = unsafe { RegionAllocator::new(start..start + memory.len() as u64 * 8) };
    let start = foreign_memory.as_mut_ptr() as u64;
    // SAFETY: independent actual enumeration issues a foreign genuine parent ID.
    let mut foreign_dma =
        unsafe { RegionAllocator::new(start..start + foreign_memory.len() as u64 * 8) };
    let (mut host, shared) = fixture(&mut dma, HIGH_SPEED);
    let (foreign, _) = fixture(&mut foreign_dma, HIGH_SPEED);
    let root = host.hubs[0].device.id;
    let leaf = host
        .devices
        .iter()
        .find(|d| d.location.ends_with(".1"))
        .unwrap()
        .id;
    let foreign_root = foreign.hubs[0].device.id;
    assert_eq!(root.hardware_slot(), foreign_root.hardware_slot());
    assert_ne!(root, foreign_root);
    let original = shared.borrow().slots[usize::from(leaf.hardware_slot())]
        .as_ref()
        .unwrap()
        .parent_id;
    // Hostile retained graph injection keeps the genuine child ID unchanged.
    shared.borrow_mut().slots[usize::from(leaf.hardware_slot())]
        .as_mut()
        .unwrap()
        .parent_id = Some(foreign_root);
    trapped(&shared, || {
        assert!(shared.borrow_mut().device(leaf).is_err());
        assert!(
            shared
                .borrow_mut()
                .current_hub_port_reset(root, 1, 1)
                .is_err()
        );
        assert!(host.retire(root, &mut Changes::default()).is_err());
    });
    // Also corrupt the retained current graph consistently with that same
    // foreign genuine parent. A boolean belongs_to would now skip this child;
    // the fallible complete-root preflight must still reject retirement/release.
    let grant_parent = shared
        .borrow_mut()
        .power
        .inject_parent_identity(leaf.hardware_slot(), Some(foreign_root));
    trapped(&shared, || {
        assert!(
            shared
                .borrow_mut()
                .current_hub_port_reset(root, 1, 1)
                .is_err()
        );
        assert!(host.retire(root, &mut Changes::default()).is_err());
    });
    shared
        .borrow_mut()
        .power
        .inject_parent_identity(leaf.hardware_slot(), grant_parent);
    shared.borrow_mut().slots[usize::from(leaf.hardware_slot())]
        .as_mut()
        .unwrap()
        .parent_id = original;
    assert!(shared.borrow_mut().device(leaf).is_ok());
}

#[test]
fn genuine_recovery_capability_refuses_an_independent_same_slot_hub_without_mutation() {
    let mut old_memory = vec![0u64; 512 * 1024];
    let mut new_memory = vec![0u64; 512 * 1024];
    let start = old_memory.as_mut_ptr() as u64;
    // SAFETY: old quiesced owners retain every original allocation.
    let mut old_dma = unsafe { RegionAllocator::new(start..start + old_memory.len() as u64 * 8) };
    let start = new_memory.as_mut_ptr() as u64;
    // SAFETY: current controller DMA has separate live backing.
    let mut new_dma = unsafe { RegionAllocator::new(start..start + new_memory.len() as u64 * 8) };
    let (mut original, _) = fixture(&mut old_dma, SUPER_SPEED);
    original
        .start_recovery(0, Some(1), &mut Changes::default())
        .unwrap();
    assert!(original.hubs[0].recovery.is_some());
    let (current, shared) = fixture(&mut new_dma, SUPER_SPEED);
    let current_id = current.hubs[0].device.id;
    assert_ne!(original.hubs[0].recovery.as_ref().unwrap().id(), current_id);
    original.controller = shared.clone();
    trapped(&shared, || {
        assert!(
            original
                .recover_hub(0, &mut old_dma, &mut Changes::default())
                .is_err()
        );
    });
    assert!(original.hubs[0].recovery.is_some());
    assert!(shared.borrow_mut().device(current_id).is_ok());
}

#[test]
fn public_resume_rejects_stale_snapshot_before_controller_restore_and_keeps_current_suspend_owner()
{
    let mut old_memory = vec![0u64; 512 * 1024];
    let mut new_memory = vec![0u64; 512 * 1024];
    let start = old_memory.as_mut_ptr() as u64;
    // SAFETY: snapshots retain all canceled original DMA backing.
    let mut old_dma = unsafe { RegionAllocator::new(start..start + old_memory.len() as u64 * 8) };
    let start = new_memory.as_mut_ptr() as u64;
    // SAFETY: current suspended hardware owns independent live DMA backing.
    let mut new_dma = unsafe { RegionAllocator::new(start..start + new_memory.len() as u64 * 8) };
    let (mut original, _) = fixture(&mut old_dma, SUPER_SPEED);
    let removed = original.suspend();
    assert!(
        removed.added.failures.is_empty(),
        "{:?}",
        removed.added.failures
    );
    let (mut current, shared) = fixture(&mut new_dma, SUPER_SPEED);
    let removed = current.suspend();
    assert!(
        removed.added.failures.is_empty(),
        "{:?}",
        removed.added.failures
    );
    original.controller = shared.clone();
    trapped(&shared, || {
        let changes = original.resume(&mut old_dma, &crate::firmware::HandoffProvider::new(None));
        assert_eq!(changes.added.failures.len(), 1);
        assert!(changes.added.devices.is_empty());
        assert!(changes.removed.is_empty());
    });
    assert!(
        shared
            .borrow()
            .slots
            .iter()
            .flatten()
            .all(|state| state.suspended && !state.retiring)
    );
    assert!(matches!(current.sleep, suspend::Sleep::Suspended(_)));
}
