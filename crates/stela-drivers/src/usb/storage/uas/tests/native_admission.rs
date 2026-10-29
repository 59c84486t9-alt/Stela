// SPDX-License-Identifier: GPL-2.0-only
//! Native admission cases.
use super::*;

#[test]
fn native_uas_admission_rejects_foreign_generation_before_configuration_or_dma() {
    use crate::usb::xhci::{self, HIGH_SPEED, SUPER_SPEED};
    for speed in [HIGH_SPEED, SUPER_SPEED] {
        let mut first_memory = vec![0u64; 512 * 1024];
        let mut second_memory = vec![0u64; 512 * 1024];
        let (first, first_device, first_hardware, mut first_dma) =
            xhci::model::reset_fixture(&mut first_memory, speed, 32, 3);
        let (_second, second_device, second_hardware, _second_dma) =
            xhci::model::reset_fixture(&mut second_memory, speed, 32, 3);
        assert_eq!(first_device.slot, second_device.slot);
        assert_ne!(first_device.id, second_device.id);
        let binding = Binding::new(
            &second_device,
            &xhci::interfaces(&second_device.configuration)[0],
        )
        .unwrap();
        let first_accesses = first_hardware.borrow().accesses;
        let second_accesses = second_hardware.borrow().accesses;
        let remaining = first_dma.remaining();
        // Mismatch two independently valid enumerated owners.
        // The checked setup boundary rejects this before class configuration
        // or DMA; the unsafe Host::new grant requires a matched attachment.
        assert!(
            Host::configure_native(first.clone(), &second_device, &binding, &mut first_dma)
                .is_err()
        );
        assert_eq!(first_hardware.borrow().accesses, first_accesses);
        assert_eq!(second_hardware.borrow().accesses, second_accesses);
        assert_eq!(first_dma.remaining(), remaining);
    }
}
