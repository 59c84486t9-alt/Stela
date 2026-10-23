// SPDX-License-Identifier: GPL-2.0-only
//! F03 passthrough registration and transmit under the RMI device owner.
use super::{
    Attention, Device, Error, Function, f03,
    transport::{Transport, buffer},
};
use crate::bus::i2c::Timer;
use alloc::vec::Vec;
impl<X: Transport, A: Attention, T: Timer> Device<X, A, T> {
    pub fn f03_capabilities(&self) -> impl Iterator<Item = &f03::Capabilities> {
        self.f03.iter().map(|engine| &engine.capabilities)
    }
    /// Read actual queries and drain pending output buffers before enabling
    /// passthrough interrupts. This opens the transport; it does not establish a
    /// PS/2 mouse protocol or acknowledge a PS/2 command on behalf of a device.
    pub fn initialize_f03(&mut self) -> Result<(), Error> {
        self.configured()?;
        if !self.f03.is_empty() {
            return Err(Error::AlreadyActive);
        }
        let count = self
            .functions
            .iter()
            .filter(|function| function.number == 3)
            .count();
        if count == 0 {
            return Err(Error::MissingFunction(3));
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
                .filter(|function| function.number == 3)
            {
                let engine = f03::Engine::configure(&mut self.transport, *function)?;
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
            self.f03 = engines;
            Ok(())
        })();
        self.fault(result)
    }
    /// One physical TX write. The returned success means only bus completion;
    /// command acknowledgements arrive as actual RX records through poll_input.
    pub fn write_f03(&mut self, function: Function, byte: u8) -> Result<(), Error> {
        self.configured()?;
        let engine = self
            .f03
            .iter()
            .find(|engine| engine.capabilities.function == function)
            .ok_or(Error::MissingFunction(3))?;
        let result = engine.write(&mut self.transport, byte);
        self.fault(result)
    }
    /// Disable this function's IRQ sources before retiring the open transport.
    /// Other RMI input engines retain their configured IRQ bits and state.
    pub fn close_f03(&mut self, function: Function) -> Result<(), Error> {
        self.configured()?;
        let index = self
            .f03
            .iter()
            .position(|engine| engine.capabilities.function == function)
            .ok_or(Error::MissingFunction(3))?;
        let result = (|| {
            let mut mask = buffer(self.irq_mask.len())?;
            mask.copy_from_slice(&self.irq_mask);
            for bit in function.interrupt_start
                ..function.interrupt_start + u16::from(function.interrupt_count)
            {
                mask[usize::from(bit / 8)] &= !(1 << (bit % 8));
            }
            let address = Self::register(self.f01.ok_or(Error::MissingF01)?.control, 1)?;
            self.transport.write(address, &mask)?;
            let mut actual = buffer(mask.len())?;
            self.transport.read(address, &mut actual)?;
            if actual != mask {
                return Err(Error::ConfigurationRejected);
            }
            self.irq_mask = mask;
            self.f03.remove(index);
            Ok(())
        })();
        self.fault(result)
    }
}
