//! The host's keyboards and pointers, read between engine slices and fed to
//! the native USB peripheral the guest enumerates: virtio-input devices and
//! USB HID devices behind xHCI controllers.
//!
//! Their drivers reach registers and DMA pages through the loader's
//! identity root, as the storage services do, so each poll runs in that
//! root (`storage::RestoreRoot`). The guest sees an input change at
//! its peripheral's next interrupt poll after the slice it arrived in.
use super::storage::{Inputs, RestoreRoot};
use crate::output;
use alloc::vec::Vec;
use stela_drivers::input::Input;
use stela_runtime::machine::apple::AppleDevices;

pub struct HostInput {
    inputs: Inputs,
    /// The first input refusal, reported once.
    refused: bool,
    /// The first USB polling failure, reported once.
    failed: bool,
}

impl HostInput {
    pub fn new(inputs: Inputs) -> Self {
        for device in &inputs.devices {
            output::arguments(format_args!("INPUT host device {:?}\n", device.name));
        }
        for device in &inputs.usb {
            output::arguments(format_args!("INPUT host USB device {}\n", device.name));
        }
        if inputs.devices.is_empty() && inputs.usb.is_empty() {
            output::arguments(format_args!(
                "INPUT no host virtio-input or USB HID device: the peripheral stays idle\n"
            ));
        }
        Self {
            inputs,
            refused: false,
            failed: false,
        }
    }

    fn deliver(&mut self, devices: &mut AppleDevices, input: Input) {
        if let Err(error) = devices.input(input)
            && !core::mem::replace(&mut self.refused, true)
        {
            output::arguments(format_args!("INPUT refused {input:?}: {error}\n"));
        }
    }

    pub fn poll(&mut self, devices: &mut AppleDevices) {
        let mut usb = Vec::new();
        for device in &mut self.inputs.usb {
            {
                // SAFETY: as below, for the device's xHCI controller.
                let _root = unsafe { RestoreRoot::enter(self.inputs.root) };
                usb.extend(device.poll());
            }
            if device.failed() && !core::mem::replace(&mut self.failed, true) {
                output::arguments(format_args!("INPUT USB device {} stopped\n", device.name));
            }
        }
        for input in usb {
            self.deliver(devices, input);
        }
        let mut pending = Vec::new();
        for device in &mut self.inputs.devices {
            let events = {
                // SAFETY: the loader root `storage::open` captured, which
                // maps this device; the engine is serialized.
                let _root = unsafe { RestoreRoot::enter(self.inputs.root) };
                device.poll()
            };
            let inputs: Vec<Input> = events
                .into_iter()
                .filter_map(|event| device.translator.translate(event))
                .collect();
            pending.extend(inputs);
        }
        for input in pending {
            self.deliver(devices, input);
        }
    }
}
