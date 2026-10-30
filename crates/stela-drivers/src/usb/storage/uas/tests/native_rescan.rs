// SPDX-License-Identifier: GPL-2.0-only
//! Native rescan cases.
use super::*;

#[test]
fn native_empty_owner_rescans_change_and_reset_without_retargeting_old_disks() {
    use crate::block::BlockDevice;
    use crate::usb::xhci::{self, HIGH_SPEED, SUPER_SPEED};
    for speed in [HIGH_SPEED, SUPER_SPEED] {
        let mut memory = vec![0u64; 512 * 1024];
        let (controller, device, hardware, mut dma) =
            xhci::model::reset_fixture(&mut memory, speed, 32, 3);
        hardware.borrow_mut().empty_media = true;
        let binding = Binding::new(
            &device,
            &crate::usb::descriptor::interfaces(&device.configuration)[0],
        )
        .unwrap();
        let mut failures = Vec::new();
        // SAFETY: This reset fixture supplies the current controller, device
        // and binding with unused UAS endpoint contexts. memory stays alive
        // and exclusive through synchronous discovery, probing and resets;
        // no competing class or firmware actor drives this model.
        let (storage, disks) = unsafe {
            crate::usb::storage::discover_uas_retained(
                controller,
                &device,
                binding,
                &mut dma,
                &mut failures,
            )
        }
        .unwrap();
        assert!(disks.is_empty());
        assert!(
            hardware
                .borrow()
                .scsi
                .iter()
                .all(|(_, op)| !matches!(*op, 0x25 | 0x1a))
        );
        // Mirror normal Found/probe retention after typed disks are drained.
        let mut found = xhci::Found::default();
        found.storage.push(storage);
        let mut probed = crate::probe::Devices::default();
        probed.usb_storage.extend(found.storage);
        let mut storage = probed.usb_storage.remove(0);
        hardware.borrow_mut().empty_media = false;
        let mut disks = storage.rescan(&mut failures).unwrap();
        assert_eq!(disks.len(), 1);
        disks[0].write(1, &[0x44; 512]).unwrap();
        disks[0].flush().unwrap();
        let mut same = storage.rescan(&mut failures).unwrap();
        same[0].read(1, &mut [0; 512]).unwrap();
        // UA while INQUIRY is being retried still invalidates the previous
        // publication even with identical fresh capacity and identifiers.
        hardware.borrow_mut().sense_once = Some((0x12, 0x062800));
        let mut changed = storage.rescan(&mut failures).unwrap();
        assert_eq!(changed.len(), 1);
        let before = hardware.borrow().accesses;
        assert!(disks[0].read(0, &mut [0; 512]).is_err());
        assert!(same[0].flush_cache().is_err());
        assert_eq!(hardware.borrow().accesses, before);
        // CHECK CONDITION can arrive before USB2 READY or before SS data
        // completes. The native contributor cancellation must finish, and
        // neither the failed write nor an old alias may be replayed.
        hardware.borrow_mut().sense_once = Some((0x2a, 0x062800));
        let before_commands = hardware.borrow().scsi.len();
        assert_eq!(
            changed[0].write(1, &[0x55; 512]),
            Err(BlockError::Sense(Sense {
                key: 0x06,
                asc: 0x28,
                ascq: 0x00
            }))
        );
        assert_eq!(
            hardware.borrow().scsi[before_commands..]
                .iter()
                .filter(|(_, op)| *op == 0x2a)
                .count(),
            1
        );
        let mut ready = storage.rescan(&mut failures).unwrap();
        let mut preserved = [0; 512];
        ready[0].read(1, &mut preserved).unwrap();
        assert_eq!(preserved, [0x44; 512], "failed native write was replayed");
        hardware.borrow_mut().sense_once = Some((0, 0x063a00));
        let before_commands = hardware.borrow().scsi.len();
        assert!(storage.rescan(&mut failures).unwrap().is_empty());
        assert!(
            hardware.borrow().scsi[before_commands..]
                .iter()
                .all(|(_, op)| !matches!(*op, 0x25 | 0x1a))
        );
        hardware.borrow_mut().empty_media = true;
        assert!(storage.rescan(&mut failures).unwrap().is_empty());
        let before = hardware.borrow().accesses;
        assert!(changed[0].write(0, &[0; 512]).is_err());
        assert_eq!(hardware.borrow().accesses, before);
        hardware.borrow_mut().empty_media = false;
        let mut inserted = storage.rescan(&mut failures).unwrap();
        // The kept reset variant must return a usable owner even when
        // physical reset succeeds with no media. Old owners stay poisoned.
        hardware.borrow_mut().empty_media = true;
        let (mut rebound, empty) = inserted[0]
            .reset_and_rebind_retained(&mut dma, &mut failures)
            .unwrap();
        assert!(empty.is_empty());
        let before = hardware.borrow().accesses;
        assert!(inserted[0].flush_cache().is_err());
        assert_eq!(hardware.borrow().accesses, before);
        assert!(storage.rescan(&mut failures).is_err());
        hardware.borrow_mut().empty_media = false;
        let mut fresh = rebound.rescan(&mut failures).unwrap();
        assert_eq!(fresh[0].identity().blocks, 2048);
        fresh[0].write(1500, &[0x88; 512]).unwrap();
        fresh[0].flush().unwrap();
        let mut bytes = [0; 512];
        fresh[0].read(1500, &mut bytes).unwrap();
        assert_eq!(bytes, [0x88; 512]);
    }
}
