//! The host's keyboards and pointers, read between engine slices and fed to
//! the native USB peripheral the guest enumerates.
//!
//! The virtio-input drivers reach their registers and DMA pages through the
//! loader's identity root, as the storage services do, so each poll runs in
//! that root (`storage::RestoreRoot`). The guest sees an input change at
//! its peripheral's next interrupt poll after the slice it arrived in.
use super::storage::{Inputs, RestoreRoot};
use crate::output;
use stela_runtime::machine::apple::AppleDevices;

pub struct HostInput {
    inputs: Inputs,
    /// The first input refusal, reported once.
    refused: bool,
}

impl HostInput {
    pub fn new(inputs: Inputs) -> Self {
        for device in &inputs.devices {
            output::arguments(format_args!("INPUT host device {:?}\n", device.name));
        }
        if inputs.devices.is_empty() {
            output::arguments(format_args!(
                "INPUT no host virtio-input device: the peripheral stays idle\n"
            ));
        }
        Self {
            inputs,
            refused: false,
        }
    }

    pub fn poll(&mut self, devices: &mut AppleDevices) {
        for device in &mut self.inputs.devices {
            let events = {
                // SAFETY: the loader root `storage::open` captured, which
                // maps this device; the engine is serialized.
                let _root = unsafe { RestoreRoot::enter(self.inputs.root) };
                device.poll()
            };
            for event in events {
                let Some(input) = device.translator.translate(event) else {
                    continue;
                };
                if let Err(error) = devices.input(input)
                    && !core::mem::replace(&mut self.refused, true)
                {
                    output::arguments(format_args!("INPUT refused {input:?}: {error}\n"));
                }
            }
        }
    }
}
