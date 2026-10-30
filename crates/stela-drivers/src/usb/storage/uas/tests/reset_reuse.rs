//! Native UAS reset/owner transfer controls. Source-only until checked.
use super::super::*;
use crate::{
    block::BlockDevice,
    bus::dma::RegionAllocator,
    usb::xhci::{HIGH_SPEED, SUPER_SPEED, model::ResetFault},
};
use alloc::{rc::Rc, vec};
use core::cell::RefCell;

/// No allocation is permitted after the initial native construction.
/// This observes the production path, including its whole controller pool.
struct NoAllocation;
impl DmaAllocator for NoAllocation {
    fn allocate(&mut self, _: usize, _: usize) -> Result<DmaBuffer, BlockError> {
        panic!("UAS reset allocated fresh DMA after initial construction")
    }
}
fn geometry(host: &Host) -> [(u64, usize); 3] {
    [&host.engine.command, &host.engine.status, &host.engine.data]
        .map(|buffer| (buffer.physical(), buffer.len()))
}
fn contents(host: &Host) -> [Vec<u8>; 3] {
    [&host.engine.command, &host.engine.status, &host.engine.data]
        .map(|buffer| buffer.bytes().to_vec())
}
fn empty(host: &Host) {
    assert!(host.requires_rebind());
    assert!(!host.engine.command.present());
    assert!(!host.engine.status.present());
    assert!(!host.engine.data.present());
}
fn native_fixture(
    memory: &mut [u64],
    speed: u8,
    context: usize,
) -> (
    super::super::super::UsbStorage,
    super::super::super::UsbDisk,
    Shared,
    Rc<RefCell<crate::usb::xhci::model::ResetHardware>>,
    RegionAllocator,
) {
    let (controller, device, hardware, mut dma) =
        crate::usb::xhci::model::reset_fixture(memory, speed, context, 1);
    let interface = crate::usb::descriptor::interfaces(&device.configuration).remove(0);
    let mut failures = Vec::new();
    // SAFETY: this fixture exclusively owns the attachment and all DCIs.
    let (storage, mut disks) = unsafe {
        super::super::super::discover_uas_retained(
            controller.clone(),
            &device,
            Binding::new(&device, &interface).unwrap(),
            &mut dma,
            &mut failures,
        )
    }
    .unwrap();
    assert!(failures.is_empty());
    assert_eq!(disks.len(), 1);
    (storage, disks.remove(0), controller, hardware, dma)
}
fn owner(
    storage: &super::super::super::UsbStorage,
) -> Rc<RefCell<super::super::super::media::Owner<Host>>> {
    let super::super::super::media::TransportOwner::Uas(owner) = &storage.owner else {
        panic!("native UAS reset changed transport")
    };
    owner.clone()
}
fn dma_bytes(allocations: &[(u64, usize)]) -> Vec<Vec<u8>> {
    allocations
        .iter()
        .map(|&(address, length)| {
            // SAFETY: geometry comes from the controller owners;
            // exclusive fixture RAM outlives every snapshot and native owner.
            unsafe { core::slice::from_raw_parts(address as *const u8, length) }.to_vec()
        })
        .collect()
}

#[test]
fn native_root_uas_reuses_three_original_owners_across_96_resets_and_real_io() {
    for speed in [HIGH_SPEED, SUPER_SPEED] {
        for context in [32, 64] {
            let mut memory = vec![0u64; 512 * 1024];
            let (mut storage, mut disk, controller, hardware, dma) =
                native_fixture(&mut memory, speed, context);
            let initial = owner(&storage);
            let original = geometry(&initial.borrow().transport);
            assert_eq!(original.map(|(_, length)| length), [512, 512, MAX_TD]);
            let initial_id = initial.borrow().transport.device.id;
            let controller_original = controller
                .borrow()
                .reset_allocation_geometry(initial_id)
                .unwrap();
            let remaining = dma.remaining();
            let mut retired = Vec::new();
            let mut ids = vec![initial_id];
            for epoch in 1..=96 {
                let old = owner(&storage);
                let mut failures = Vec::new();
                let mut fresh = storage
                    .reset_and_rebind(&mut NoAllocation, &mut failures)
                    .unwrap();
                assert!(failures.is_empty());
                assert_eq!(fresh.len(), 1);
                assert_eq!(hardware.borrow().resets, epoch);
                empty(&old.borrow().transport);
                let current = owner(&storage);
                let id = current.borrow().transport.device.id;
                assert!(!ids.contains(&id));
                ids.push(id);
                assert_eq!(geometry(&current.borrow().transport), original);
                assert_eq!(
                    controller.borrow().reset_allocation_geometry(id).unwrap(),
                    controller_original
                );
                let current_bytes = contents(&current.borrow().transport);
                let current_controller_bytes = dma_bytes(&controller_original);
                retired.push((disk, old));
                let accesses = hardware.borrow().accesses;
                hardware.borrow_mut().trap_mmio = true;
                for (disk, old) in &mut retired {
                    let mut poison = [0xb7; 512];
                    assert!(disk.read(7, &mut poison).is_err());
                    assert_eq!(poison, [0xb7; 512]);
                    assert!(disk.write(7, &[0xee; 512]).is_err());
                    assert!(disk.flush_cache().is_err());
                    let mut old = old.borrow_mut();
                    assert!(old.transport.engine.io.ready().is_err());
                    assert!(old.transport.command([0; 8], &[0; 6], Data::None).is_err());
                    assert!(old.transport.reset_and_rebind(&mut NoAllocation).is_err());
                    empty(&old.transport);
                }
                hardware.borrow_mut().trap_mmio = false;
                assert_eq!(hardware.borrow().accesses, accesses);
                assert_eq!(contents(&current.borrow().transport), current_bytes);
                assert_eq!(dma_bytes(&controller_original), current_controller_bytes);
                assert_eq!(dma.remaining(), remaining);
                disk = fresh.remove(0);
                assert_eq!(disk.identity().blocks, 1024 * (epoch as u64 + 1));
                disk.write(7, &[epoch as u8; 512]).unwrap();
                // The unchanged peer advertises write-through. Explicitly issue
                // a real transport SYNCHRONIZE CACHE CDB and consume its
                // matching Status IU rather than crediting a no-op disk flush.
                current
                    .borrow_mut()
                    .transport
                    .command(
                        [0; 8],
                        &super::super::super::scsi::synchronize_cache(),
                        Data::None,
                    )
                    .unwrap();
                let mut actual = [0; 512];
                disk.read(7, &mut actual).unwrap();
                assert_eq!(actual, [epoch as u8; 512]);
                for opcode in [0x28, 0x2a, 0x35] {
                    assert!(hardware.borrow().scsi.contains(&(epoch, opcode)));
                }
                assert_eq!(dma.remaining(), remaining);
            }
            assert_eq!(retired.len(), 96);
        }
    }
}

#[test]
fn native_uas_failed_reset_keeps_all_three_original_owners_and_bytes() {
    for speed in [HIGH_SPEED, SUPER_SPEED] {
        for context in [32, 64] {
            for fault in [
                ResetFault::Stop(2),
                ResetFault::Disable,
                ResetFault::NoResetChange,
                ResetFault::Identity,
                ResetFault::ConfigureAfterReset,
                ResetFault::FatalAfterReset,
                ResetFault::ChangeAfterReset,
                ResetFault::EnableAfterReset,
                ResetFault::AddressAfterReset,
            ] {
                let mut memory = vec![0u64; 512 * 1024];
                let (mut storage, mut disk, controller, hardware, dma) =
                    native_fixture(&mut memory, speed, context);
                let old = owner(&storage);
                let (original, before, id) = {
                    let mut old = old.borrow_mut();
                    old.transport.engine.command.bytes_mut().fill(0xa5);
                    old.transport.engine.status.bytes_mut().fill(0x5a);
                    old.transport.engine.data.bytes_mut().fill(0xc3);
                    (
                        geometry(&old.transport),
                        contents(&old.transport),
                        old.transport.device.id,
                    )
                };
                let remaining = dma.remaining();
                hardware.borrow_mut().fault = fault;
                let mut failures = Vec::new();
                assert!(
                    storage
                        .reset_and_rebind(&mut NoAllocation, &mut failures)
                        .is_err()
                );
                assert!(!failures.is_empty());
                {
                    let old = old.borrow();
                    assert!(old.transport.requires_rebind());
                    assert!(old.transport.engine.buffers_present());
                    assert_eq!(geometry(&old.transport), original);
                    assert_eq!(contents(&old.transport), before);
                }
                // A live identity query bypasses the permanent raw-slot fence.
                // Both old and most recent Enable grant stay unusable.
                let actual_slot = *hardware.borrow().enables.last().unwrap();
                assert!(controller.borrow_mut().device(id).is_err());
                assert!(controller.borrow().test_device_id(actual_slot).is_err());
                let accesses = hardware.borrow().accesses;
                hardware.borrow_mut().trap_mmio = true;
                let mut poison = [0x91; 512];
                assert!(disk.read(0, &mut poison).is_err());
                assert_eq!(poison, [0x91; 512]);
                assert!(disk.write(0, &[0; 512]).is_err());
                assert!(disk.flush_cache().is_err());
                assert!(
                    old.borrow_mut()
                        .transport
                        .command([0; 8], &[0; 6], Data::None)
                        .is_err()
                );
                hardware.borrow_mut().trap_mmio = false;
                assert_eq!(hardware.borrow().accesses, accesses);
                assert_eq!(contents(&old.borrow().transport), before);
                assert_eq!(dma.remaining(), remaining);
            }
        }
    }
}

/// Run real native READ with the Command TD completion unread.
/// The payload and matching Status IU are completed first.
fn read_with_unread_command(host: &mut Host) -> NativeTicket {
    let command = command_iu(1, [0; 8], &[0x28, 0, 0, 0, 0, 0, 0, 0, 1, 0]);
    host.engine.command.bytes_mut().fill(0);
    host.engine.command.bytes_mut()[..command.len()].copy_from_slice(&command);
    let io = &mut host.engine.io;
    let ticket = io
        .submit(
            Pipe::Command,
            1,
            host.engine.command.physical(),
            command.len(),
        )
        .unwrap();
    if io.streams().is_none() {
        let ready = io
            .submit(
                Pipe::Status,
                1,
                host.engine.status.physical(),
                IU_BUFFER_BYTES,
            )
            .unwrap();
        assert_eq!(io.completed(&ready), Some(Ok(4)));
    }
    let status = io
        .submit(
            Pipe::Status,
            1,
            host.engine.status.physical(),
            IU_BUFFER_BYTES,
        )
        .unwrap();
    let data = io
        .submit(Pipe::Input, 1, host.engine.data.physical(), 512)
        .unwrap();
    assert_eq!(io.completed(&data), Some(Ok(512)));
    assert_eq!(io.completed(&status), Some(Ok(16)));
    assert_eq!(&host.engine.data.bytes()[..512], &[0x6d; 512]);
    assert_eq!(host.engine.status.bytes()[0], STATUS_IU);
    assert_eq!(&host.engine.status.bytes()[2..4], &1u16.to_be_bytes());
    ticket
}
fn command_pointer(ticket: &NativeTicket) -> u64 {
    let NativeTicket::Ordinary { trb, .. } = ticket else {
        panic!("UAS Command uses ordinary endpoint")
    };
    *trb
}
#[test]
fn native_uas_old_same_pointer_ticket_cannot_consume_unread_current_completion() {
    for speed in [HIGH_SPEED, SUPER_SPEED] {
        for context in [32, 64] {
            let mut memory = vec![0u64; 512 * 1024];
            let (controller, device, hardware, mut dma) =
                crate::usb::xhci::model::reset_fixture(&mut memory, speed, context, 1);
            let interface = crate::usb::descriptor::interfaces(&device.configuration).remove(0);
            // SAFETY: exclusive fixture attachment and unconfigured DCIs.
            let mut old = unsafe {
                Host::new(
                    controller.clone(),
                    &device,
                    Binding::new(&device, &interface).unwrap(),
                    &mut dma,
                )
            }
            .unwrap();
            let retired_ticket = read_with_unread_command(&mut old);
            let mut fresh = old.reset_and_rebind(&mut NoAllocation).unwrap();
            let current_ticket = read_with_unread_command(&mut fresh);
            assert_eq!(
                command_pointer(&retired_ticket),
                command_pointer(&current_ticket)
            );
            assert_ne!(old.device.id, fresh.device.id);
            empty(&old);
            let before = contents(&fresh);
            let allocations = controller
                .borrow()
                .reset_allocation_geometry(fresh.device.id)
                .unwrap();
            let controller_bytes = dma_bytes(&allocations);
            let accesses = hardware.borrow().accesses;
            hardware.borrow_mut().trap_mmio = true;
            assert!(old.engine.io.completed(&retired_ticket).unwrap().is_err());
            assert!(old.command([0; 8], &[0; 6], Data::None).is_err());
            assert!(old.reset_and_rebind(&mut NoAllocation).is_err());
            hardware.borrow_mut().trap_mmio = false;
            assert_eq!(hardware.borrow().accesses, accesses);
            assert_eq!(contents(&fresh), before);
            assert_eq!(dma_bytes(&allocations), controller_bytes);
            assert_eq!(fresh.engine.io.completed(&current_ticket), Some(Ok(32)));
        }
    }
}
