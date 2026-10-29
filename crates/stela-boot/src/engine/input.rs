//! The host's keyboards and pointers, read between engine slices and fed to
//! the native USB peripheral the guest enumerates: every input device probe
//! found, whatever its transport ([`stela_drivers::input::InputDevice`]).
//!
//! Their drivers reach registers and DMA pages through the loader's
//! identity root, as the storage services do, so each poll runs in that
//! root (`storage::RestoreRoot`). The guest sees an input change at
//! its peripheral's next interrupt poll after the slice it arrived in.
use super::storage::{Inputs, RestoreRoot};
use crate::output;
use alloc::vec::Vec;
use stela_drivers::input::{Input, InputDevice};
use stela_soc::machine::AppleDevices;

pub struct HostInput {
    inputs: Inputs,
    /// The first input refusal, reported once.
    refused: bool,
    /// The first polling failure, reported once.
    failed: bool,
    /// The first device to stop, reported once.
    stopped: bool,
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
            output::arguments(format_args!("INPUT host device {}\n", device.name()));
        }
        if inputs.devices.is_empty() {
            output::arguments(format_args!(
                "INPUT no host keyboard or pointer: the peripheral stays idle\n"
            ));
        }
        Self {
            inputs,
            refused: false,
            failed: false,
            stopped: false,
            leds: None,
            wanted_leds: None,
            led_failed: false,
        }
    }

    /// Read `devices` too from now on: keyboards and pointers that arrived.
    pub fn add(&mut self, devices: Vec<InputDevice>) {
        for device in devices {
            output::arguments(format_args!("INPUT host device {}\n", device.name()));
            self.inputs.devices.push(device);
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

    /// Read the host's input devices, without the guest's devices, in the
    /// order probe found them. The guest's lock-key LEDs reach each host
    /// keyboard first, as Linux `hidinput_led_worker` sends an input
    /// device's LED changes.
    pub fn read(&mut self) -> Vec<Input> {
        if let Some(leds) = self.wanted_leds
            && self.leds != Some(leds)
        {
            self.leds = Some(leds);
            for device in &mut self.inputs.devices {
                // SAFETY: as below, for the device's controller.
                let _root = unsafe { RestoreRoot::enter(self.inputs.root) };
                if let Err(error) = device.set_leds(leds)
                    && !core::mem::replace(&mut self.led_failed, true)
                {
                    output::arguments(format_args!("INPUT {} LEDs: {error}\n", device.name()));
                }
            }
        }
        let mut pending = Vec::new();
        for device in &mut self.inputs.devices {
            let polled = {
                // SAFETY: the loader root `storage::open` captured, which
                // maps this device.
                let _root = unsafe { RestoreRoot::enter(self.inputs.root) };
                device.poll(&mut pending)
            };
            if let Err(error) = polled
                && !core::mem::replace(&mut self.failed, true)
            {
                output::arguments(format_args!("INPUT {}: {error}\n", device.name()));
            }
            if device.stopped() && !core::mem::replace(&mut self.stopped, true) {
                output::arguments(format_args!("INPUT {} stopped\n", device.name()));
            }
        }
        pending
    }
}
