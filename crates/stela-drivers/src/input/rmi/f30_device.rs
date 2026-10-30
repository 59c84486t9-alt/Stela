// SPDX-License-Identifier: GPL-2.0-only
//! F30 registration under the single RMI attention consumer.
use super::{
    Attention, Device, Error, f30,
    transport::{Transport, buffer},
};
use crate::bus::i2c::Timer;
use alloc::vec::Vec;
impl<X: Transport, A: Attention, T: Timer> Device<X, A, T> {
    pub fn f30_capabilities(&self) -> impl Iterator<Item = &f30::Capabilities> {
        self.f30.iter().map(|engine| &engine.capabilities)
    }
    /// Read F30 query/control banks and reapply their complete image
    /// before enabling GPIO attention. Logical key/trackstick wiring stays with
    /// the platform/frontend owner.
    pub fn initialize_f30(&mut self) -> Result<(), Error> {
        self.configured()?;
        if !self.f30.is_empty() {
            return Err(Error::AlreadyActive);
        }
        let count = self
            .functions
            .iter()
            .filter(|function| function.number == 0x30)
            .count();
        if count == 0 {
            return Err(Error::MissingFunction(0x30));
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
                .filter(|function| function.number == 0x30)
            {
                let engine = f30::Engine::configure(&mut self.transport, *function)?;
                for bit in function.interrupt_start
                    ..function.interrupt_start + u16::from(function.interrupt_count)
                {
                    mask[usize::from(bit / 8)] |= 1 << (bit % 8);
                }
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
            self.f30 = engines;
            Ok(())
        })();
        self.fault(result)
    }
}
