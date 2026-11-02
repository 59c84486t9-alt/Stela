//! Client-local HID projection diagnostics and retained native input ownership.
use super::*;
use crate::{
    bus::pci::owned::OwnedConfig,
    input::Input,
    usb::hid::{ParseError, Translator},
};
use alloc::{string::String, vec::Vec};
use core::mem::ManuallyDrop;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientRefusalCause {
    Descriptor(ParseError),
    /// The HID descriptor remains valid; its fields have no legacy keyboard
    /// or pointer projection. This does not reject a future raw HID consumer.
    NoLegacyProjection,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientRefusal {
    pub device_id: u8,
    pub cause: ClientRefusalCause,
}

/// No legacy input projection was admitted. All per-client diagnostics and the
/// same native owner remain together; abandonment proves no physical detach.
pub struct InputRefusal<
    C: Configuration = OwnedConfig,
    R: Registers = MappedRegisters,
    T: Time = NativeClock,
> {
    native: ManuallyDrop<Native<C, R, T>>,
    clients: Vec<ClientRefusal>,
}
impl<C: Configuration, R: Registers, T: Time> InputRefusal<C, R, T> {
    pub fn native(&self) -> &Native<C, R, T> {
        &self.native
    }
    pub fn clients(&self) -> &[ClientRefusal] {
        &self.clients
    }
}
impl<C: Configuration, R: Registers, T: Time> core::fmt::Debug for InputRefusal<C, R, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("InputRefusal")
            .field("clients", &self.clients)
            .finish_non_exhaustive()
    }
}

/// An ISH whose HID clients include a keyboard or pointer: each client's
/// reports pass through its own HID report translator.
pub struct IshInput<
    C: Configuration = OwnedConfig,
    R: Registers = MappedRegisters,
    T: Time = NativeClock,
> {
    native: ManuallyDrop<Native<C, R, T>>,
    clients: Vec<(u8, Translator)>,
    client_refusals: Vec<ClientRefusal>,
    poll_cleanup_errors: Vec<Error>,
    pub name: String,
}

impl<C: Configuration, R: Registers, T: Time> IshInput<C, R, T> {
    /// Read every client's descriptor, retaining parser failures and legacy
    /// projection refusals independently. Valid clients continue together.
    #[expect(
        clippy::result_large_err,
        reason = "a refusal retains the same native graph without error-path allocation"
    )]
    pub fn new(
        native: Native<C, R, T>,
        name: String,
    ) -> core::result::Result<Self, InputRefusal<C, R, T>> {
        let native = ManuallyDrop::new(native);
        let mut clients = Vec::new();
        let mut client_refusals = Vec::new();
        for device in native.devices() {
            match Translator::describe(&device.report_descriptor) {
                Ok(translator) => {
                    if !translator.is_keyboard_or_pointer() {
                        client_refusals.push(ClientRefusal {
                            device_id: device.id,
                            cause: ClientRefusalCause::NoLegacyProjection,
                        });
                    }
                    clients.push((device.id, translator));
                }
                Err(error) => client_refusals.push(ClientRefusal {
                    device_id: device.id,
                    cause: ClientRefusalCause::Descriptor(error),
                }),
            }
        }
        if !clients
            .iter()
            .any(|(_, translator)| translator.is_keyboard_or_pointer())
        {
            return Err(InputRefusal {
                native,
                clients: client_refusals,
            });
        }
        Ok(Self {
            native,
            clients,
            client_refusals,
            poll_cleanup_errors: Vec::new(),
            name,
        })
    }

    pub fn client_refusals(&self) -> &[ClientRefusal] {
        &self.client_refusals
    }

    /// Append the input changes of the reports the clients have ready.
    pub fn poll(&mut self, inputs: &mut Vec<Input>) -> Result<()> {
        let raw = self.native.poll_inputs();
        let mut events = Vec::new();
        for report in raw.reports {
            if let Some((_, translator)) = self
                .clients
                .iter_mut()
                .find(|(id, _)| *id == report.device_id)
            {
                translator.translate(&report.bytes, &mut events, inputs);
            }
        }
        self.poll_cleanup_errors.extend(raw.later_errors);
        // Completed guest input precedes the exact error from the same pass.
        raw.first_error.map_or(Ok(()), Err)
    }

    /// Exact containment causes retained by the same legacy input owner.
    pub fn poll_cleanup_errors(&self) -> &[Error] {
        &self.poll_cleanup_errors
    }

    /// Send `leds` to each keyboard client's LED output report, as Linux
    /// `hidinput_led_worker` sends it through ishtp-hid's SET_REPORT request.
    pub fn set_leds(&mut self, leds: u16) -> Result<()> {
        for (id, translator) in &self.clients {
            if let Some((_, report)) = translator.led_report(leds) {
                self.native.set_output(*id, &report)?;
            }
        }
        Ok(())
    }

    /// The last report of the first client that sent one, as it arrived,
    /// for diagnostics.
    pub fn last_report(&self) -> &[u8] {
        self.clients
            .iter()
            .map(|(_, translator)| translator.last_report())
            .find(|report| !report.is_empty())
            .unwrap_or(&[])
    }

    /// Whether the ISH failed and is no longer read.
    pub fn stopped(&self) -> bool {
        self.native.failure().is_some()
    }
}
