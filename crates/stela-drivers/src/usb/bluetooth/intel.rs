// SPDX-License-Identifier: MIT
//! Compatibility entry point for the shared Intel Bluetooth initializer.
pub(crate) use crate::bluetooth::intel::SECURE_SEND;
pub(crate) use crate::bluetooth::intel::is_candidate;
pub use crate::bluetooth::intel::*;

use super::{Hci, Io, Packet, State};

/// Initialize identified Intel firmware through the real USB transport.
pub fn initialize<'a, B: Io>(
    hci: &mut Hci<B>,
    provider: &'a dyn crate::firmware::Provider,
) -> Result<Report<'a>, Error> {
    crate::bluetooth::intel::initialize(hci, provider)
}
/// Preserve explicit DSBR capture/default provenance for USB initialization.
pub fn initialize_with_platform<'a, B: Io>(
    hci: &mut Hci<B>,
    provider: &'a dyn crate::firmware::Provider,
    platform: PlatformInputs,
) -> Result<Report<'a>, Error> {
    crate::bluetooth::intel::initialize_with_platform(hci, provider, platform)
}
impl<B: Io> CommandIo for Hci<B> {
    fn identity(&self) -> Result<TransportIdentity, Error> {
        crate::bluetooth::intel::usb_identity(self.binding.device())
    }
    fn now_us(&self) -> u64 {
        self.io.now_us()
    }
    fn submit_command(&mut self, bytes: &[u8]) -> Result<(), Error> {
        Hci::submit_command(self, bytes).map_err(Into::into)
    }
    fn events(&mut self) -> Result<alloc::vec::Vec<alloc::vec::Vec<u8>>, Error> {
        self.poll()?
            .into_iter()
            .map(|packet| match packet {
                Packet::Event(bytes) => Ok(bytes),
                _ => Err(Error::Protocol(
                    "non-event during Intel firmware initialization",
                )),
            })
            .collect()
    }
    fn intel_mode(&mut self, bootloader: bool) -> Result<(), Error> {
        Hci::intel_mode(self, bootloader).map_err(Into::into)
    }
    fn finish_boot(&mut self) -> Result<(), Error> {
        Ok(())
    }
    fn fail(&mut self, cause: Error) -> Error {
        if self.state() == State::Open
            && let Err(cleanup) = self.close()
        {
            return Error::Cleanup {
                cause: alloc::boxed::Box::new(cause),
                cleanup,
            };
        }
        cause
    }
}
