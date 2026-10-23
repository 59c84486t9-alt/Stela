// SPDX-License-Identifier: GPL-2.0-only
//! F11 registration under the shared RMI interrupt and transport owner.
use super::{
    Attention, Device, Error, f11,
    transport::{Transport, buffer},
};
use crate::bus::i2c::Timer;
use alloc::vec::Vec;
impl<X: Transport, A: Attention, T: Timer> Device<X, A, T> {
    pub fn f11_capabilities(&self) -> impl Iterator<Item = &f11::Capabilities> {
        self.f11.iter().map(|engine| &engine.capabilities)
    }
    pub fn initialize_f11(&mut self, configuration: f11::Configuration) -> Result<(), Error> {
        self.configured()?;
        if !self.f11.is_empty() {
            return Err(Error::AlreadyActive);
        }
        let count = self
            .functions
            .iter()
            .filter(|function| function.number == 0x11)
            .count();
        if count == 0 {
            return Err(Error::MissingFunction(0x11));
        }
        let result = (|| {
            let mut engines = Vec::new();
            engines
                .try_reserve_exact(count)
                .map_err(|_| Error::Allocation)?;
            let mut mask = buffer(self.irq_mask.len())?;
            mask.copy_from_slice(&self.irq_mask);
            for function in self
                .functions
                .iter()
                .filter(|function| function.number == 0x11)
            {
                let engine = f11::Engine::configure(&mut self.transport, *function, configuration)?;
                let bit = usize::from(engine.interrupt_bit());
                mask[bit / 8] |= 1 << (bit % 8);
                engines.push(engine);
            }
            let address = Self::register(self.f01.ok_or(Error::MissingF01)?.control, 1)?;
            self.transport.write(address, &mask)?;
            let mut actual = buffer(mask.len())?;
            self.transport.read(address, &mut actual)?;
            if actual != mask {
                return Err(Error::ConfigurationRejected);
            }
            self.irq_mask = mask;
            self.f11 = engines;
            Ok(())
        })();
        self.fault(result)
    }
}
