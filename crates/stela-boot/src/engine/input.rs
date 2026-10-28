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
    /// The guest's keyboard LEDs as last sent to the host keyboards.
    leds: Option<u8>,
    /// The guest's keyboard LEDs as the last delivery found them.
    wanted_leds: Option<u8>,
    /// The first LED report failure, reported once.
    led_failed: bool,
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
            leds: None,
            wanted_leds: None,
            led_failed: false,
        }
    }

    fn deliver(&mut self, devices: &mut AppleDevices, input: Input) {
        if let Err(error) = devices.input(input)
            && !core::mem::replace(&mut self.refused, true)
        {
            output::arguments(format_args!("INPUT refused {input:?}: {error}\n"));
        }
    }

    /// Deliver what [`Self::read`] read from the host's devices, and note
    /// the guest's lock-key LEDs for the next read to send.
    pub fn deliver_all(&mut self, devices: &mut AppleDevices, inputs: Vec<Input>) {
        for input in inputs {
            self.deliver(devices, input);
        }
        self.wanted_leds = devices.keyboard_leds();
    }

    /// Read the host's input devices, without the guest's devices: their
    /// USB devices' first, then the others'. The guest's lock-key LEDs
    /// reach each host keyboard first, as Linux `hidinput_led_worker`
    /// sends an input device's LED changes.
    pub fn read(&mut self) -> Vec<Input> {
        if let Some(leds) = self.wanted_leds
            && self.leds != Some(leds)
        {
            self.leds = Some(leds);
            for device in &mut self.inputs.usb {
                // SAFETY: as below, for the device's xHCI controller.
                let _root = unsafe { RestoreRoot::enter(self.inputs.root) };
                if let Err(error) = device.set_leds(u16::from(leds))
                    && !core::mem::replace(&mut self.led_failed, true)
                {
                    output::arguments(format_args!(
                        "INPUT USB device {} LEDs: {error:?}\n",
                        device.name
                    ));
                }
            }
        }
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
        let mut pending = usb;
        for device in &mut self.inputs.devices {
            let events = {
                // SAFETY: the loader root `storage::open` captured, which
                // maps this device.
                let _root = unsafe { RestoreRoot::enter(self.inputs.root) };
                device.poll()
            };
            let inputs: Vec<Input> = events
                .into_iter()
                .filter_map(|event| device.translator.translate(event))
                .collect();
            pending.extend(inputs);
        }
        pending
    }
}
