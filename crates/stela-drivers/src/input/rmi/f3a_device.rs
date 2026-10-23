// SPDX-License-Identifier: GPL-2.0-only
//! F3A registration under the single RMI attention consumer.
use super::{
    Attention, Device, Error, f3a,
    transport::{Transport, buffer},
};
use crate::bus::i2c::Timer;
use alloc::vec::Vec;
impl<X: Transport, A: Attention, T: Timer> Device<X, A, T> {
    pub fn f3a_capabilities(&self) -> impl Iterator<Item = &f3a::Capabilities> {
        self.f3a.iter().map(|engine| &engine.capabilities)
    }
    /// Read actual F3A existence/direction bitmaps before enabling input IRQs.
    /// Firmware wiring and logical button/trackstick mapping remain frontend
    /// responsibilities; no F3A direction controls are changed.
    pub fn initialize_f3a(&mut self) -> Result<(), Error> {
        self.configured()?;
        if !self.f3a.is_empty() {
            return Err(Error::AlreadyActive);
        }
        let count = self
            .functions
            .iter()
            .filter(|function| function.number == 0x3a)
            .count();
        if count == 0 {
            return Err(Error::MissingFunction(0x3a));
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
                .filter(|function| function.number == 0x3a)
            {
                let engine = f3a::Engine::configure(&mut self.transport, *function)?;
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
            self.f3a = engines;
            Ok(())
        })();
        self.fault(result)
    }
}
