// SPDX-License-Identifier: GPL-2.0-only
//! Native reset cases.
use super::*;

#[test]
fn native_root_reset_rebind_preserves_old_alias_quarantine_and_reprobes_geometry() {
    use crate::block::BlockDevice;
    for speed in [crate::usb::xhci::HIGH_SPEED, crate::usb::xhci::SUPER_SPEED] {
        let mut memory = vec![0u64; 512 * 1024];
        let (controller, device, hardware, mut dma) =
            crate::usb::xhci::model::reset_fixture(&mut memory, speed, 32, 3);
        let interface = crate::usb::xhci::interfaces(&device.configuration).remove(0);
        let binding = Binding::new(&device, &interface).unwrap();
        let mut failures = Vec::new();
        // SAFETY: This fixture pairs the current controller/device/binding
        // with unused class endpoints. memory is alive and exclusive through
        // old/new alias and reset accesses; the passive model performs DMA
        // only synchronously inside these calls.
        let mut disks = unsafe {
            crate::usb::storage::discover_uas(
                controller.clone(),
                &device,
                binding,
                &mut dma,
                &mut failures,
            )
        }
        .unwrap();
        assert_eq!(disks.len(), 1);
        assert_eq!(disks[0].identity().blocks, 1024);
        let crate::usb::storage::UsbTransport::Uas(unit) = &disks[0].disk else {
            panic!()
        };
        let owner = unit.bot.clone();
        let mut alias = crate::usb::storage::UsbDisk {
            disk: crate::usb::storage::UsbTransport::Uas(crate::usb::storage::Disk {
                bot: owner.clone(),
                lun: unit.lun,
                identity: unit.identity.clone(),
                media: unit.media.clone(),
                running: None,
                next_tag: 0,
                removable: unit.removable,
            }),
        };
        let commands_before_fault = hardware.borrow().scsi.len();
        hardware.borrow_mut().hang_next = true;
        let mut old_read = [0x91; 512];
        assert_eq!(disks[0].read(1, &mut old_read), Err(BlockError::Timeout));
        assert_eq!(old_read, [0x91; 512]);
        assert!(
            hardware.borrow().device_task,
            "endpoint cancellation retired firmware task"
        );
        let original = {
            let host = owner.borrow();
            [
                &host.transport.engine.command,
                &host.transport.engine.status,
                &host.transport.engine.data,
            ]
            .map(|buffer| (buffer.physical(), buffer.len()))
        };
        let mut fresh = disks[0].reset_and_rebind(&mut dma, &mut failures).unwrap();
        assert_eq!(fresh.len(), 1);
        assert_eq!(fresh[0].identity().blocks, 2048);
        assert!(failures.is_empty());
        assert_eq!(hardware.borrow().enables, vec![1, 1]);
        let crate::usb::storage::UsbTransport::Uas(current) = &fresh[0].disk else {
            panic!()
        };
        assert_ne!(current.bot.borrow().transport.device.id, device.id);
        assert_eq!(hardware.borrow().resets, 1);
        assert!(!hardware.borrow().device_task);
        let current_owner = current.bot.clone();
        let current_bytes = {
            let host = current_owner.borrow();
            let buffers = [
                &host.transport.engine.command,
                &host.transport.engine.status,
                &host.transport.engine.data,
            ];
            assert_eq!(
                buffers.map(|buffer| (buffer.physical(), buffer.len())),
                original
            );
            buffers.map(|buffer| buffer.bytes().to_vec())
        };
        let access = hardware.borrow().accesses;
        assert!(alias.read(0, &mut [0; 512]).is_err());
        assert!(disks[0].write(0, &[0; 512]).is_err());
        assert_eq!(hardware.borrow().accesses, access);
        {
            let host = owner.borrow();
            assert!(host.transport.requires_rebind());
            assert!(!host.transport.engine.command.present());
            assert!(!host.transport.engine.status.present());
            assert!(!host.transport.engine.data.present());
        }
        {
            let host = current_owner.borrow();
            assert_eq!(host.transport.engine.command.bytes(), current_bytes[0]);
            assert_eq!(host.transport.engine.status.bytes(), current_bytes[1]);
            assert_eq!(host.transport.engine.data.bytes(), current_bytes[2]);
        }
        fresh[0].write(1500, &[0xa7; 512]).unwrap();
        fresh[0].flush().unwrap();
        let mut bytes = [0; 512];
        fresh[0].read(1500, &mut bytes).unwrap();
        assert_eq!(bytes, [0xa7; 512]);
        let hardware = hardware.borrow();
        assert_eq!(
            hardware.scsi[commands_before_fault..]
                .iter()
                .filter(|(epoch, op)| *epoch == 0 && *op == 0x28)
                .count(),
            1,
            "timed-out read replayed"
        );
        assert!(
            hardware
                .scsi
                .iter()
                .any(|(epoch, op)| *epoch == 1 && *op == 0x12)
        );
        assert!(
            hardware
                .scsi
                .iter()
                .any(|(epoch, op)| *epoch == 1 && *op == 0x25)
        );
        assert!(
            hardware
                .scsi
                .iter()
                .any(|(epoch, op)| *epoch == 1 && *op == 0x1a)
        );
    }
}

#[test]
fn native_reset_identity_or_reconstruction_failure_quarantines_both_epochs() {
    use crate::block::BlockDevice;
    for changed in [false, true] {
        let mut memory = vec![0u64; 512 * 1024];
        let (controller, device, hardware, mut dma) = crate::usb::xhci::model::reset_fixture(
            &mut memory,
            crate::usb::xhci::SUPER_SPEED,
            32,
            3,
        );
        let interface = crate::usb::xhci::interfaces(&device.configuration).remove(0);
        let mut failures = Vec::new();
        // SAFETY: The controller, device and binding name this fixture's
        // current attachment, with no competing UAS endpoint owner. memory
        // remains alive/exclusive through synchronous discovery and resets;
        // fault injection starts only after this initial call returns.
        let mut disks = unsafe {
            crate::usb::storage::discover_uas(
                controller.clone(),
                &device,
                Binding::new(&device, &interface).unwrap(),
                &mut dma,
                &mut failures,
            )
        }
        .unwrap();
        hardware.borrow_mut().fault = if changed {
            crate::usb::xhci::model::ResetFault::Identity
        } else {
            crate::usb::xhci::model::ResetFault::ConfigureAfterReset
        };
        let result = disks[0].reset_and_rebind(&mut dma, &mut failures);
        assert!(result.is_err());
        assert!(!failures.is_empty());
        assert!(
            controller
                .borrow_mut()
                .endpoint_ready(device.slot, 1)
                .is_err()
        );
        let current_slot = *hardware.borrow().enables.last().unwrap();
        assert!(
            controller
                .borrow_mut()
                .endpoint_ready(current_slot, 1)
                .is_err()
        );
        assert!(controller.borrow().test_device_id(current_slot).is_err());
        assert!(controller.borrow_mut().device(device.id).is_err());
        let access = hardware.borrow().accesses;
        assert!(disks[0].read(0, &mut [0; 512]).is_err());
        assert_eq!(hardware.borrow().accesses, access);
    }
}
