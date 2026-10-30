// SPDX-License-Identifier: GPL-2.0-only
//! F1A registration under the single RMI attention consumer.
use super::{
    Attention, Device, Error, f1a,
    transport::{Transport, buffer},
};
use crate::bus::i2c::Timer;
use alloc::vec::Vec;
impl<X: Transport, A: Attention, T: Timer> Device<X, A, T> {
    pub fn f1a_capabilities(&self) -> impl Iterator<Item = &f1a::Capabilities> {
        self.f1a.iter().map(|engine| &engine.capabilities)
    }
    /// Register discovered F1A functions using a verified platform button
    /// count. This does not infer button wiring or invent logical key mappings.
    pub fn initialize_f1a(&mut self, buttons: u8) -> Result<(), Error> {
        self.configured()?;
        if !self.f1a.is_empty() {
            return Err(Error::AlreadyActive);
        }
        if !(1..=8).contains(&buttons) {
            return Err(Error::InvalidButtonCount(buttons));
        }
        let count = self
            .functions
            .iter()
            .filter(|function| function.number == 0x1a)
            .count();
        if count == 0 {
            return Err(Error::MissingFunction(0x1a));
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
                .filter(|function| function.number == 0x1a)
            {
                let engine = f1a::Engine::configure(*function, buttons)?;
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
            self.f1a = engines;
            Ok(())
        })();
        self.fault(result)
    }
}
