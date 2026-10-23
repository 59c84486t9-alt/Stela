// SPDX-License-Identifier: GPL-2.0-only
//! F12 registration and attention dispatch under the RMI device owner.
use super::{
    Attention, Device, Error, F12Poll, f12,
    transport::{Transport, buffer},
};
use crate::bus::i2c;
use alloc::vec::Vec;

impl<X: Transport, A: Attention, T: i2c::Timer> Device<X, A, T> {
    pub fn f12_capabilities(&self) -> impl Iterator<Item = &f12::Capabilities> {
        self.f12.iter().map(|engine| &engine.capabilities)
    }
    /// Configure each actually discovered F12 descriptor/control block before
    /// enabling its absolute-data interrupt. Other function engines stay masked.
    pub fn initialize_f12(&mut self, dribble: Option<bool>) -> Result<(), Error> {
        self.configured()?;
        if !self.f12.is_empty() {
            return Err(Error::AlreadyActive);
        }
        let count = self
            .functions
            .iter()
            .filter(|function| function.number == 0x12)
            .count();
        if count == 0 {
            return Err(Error::MissingFunction(0x12));
        }
        let result = (|| {
            let mut engines = Vec::new();
            engines
                .try_reserve_exact(count)
                .map_err(|_| Error::Allocation)?;
            let mut irq_mask = buffer(self.irq_mask.len())?;
            irq_mask.copy_from_slice(&self.irq_mask);
            for function in self
                .functions
                .iter()
                .filter(|function| function.number == 0x12)
            {
                if function.interrupt_count == 0 {
                    return Err(Error::InterruptLimit);
                }
                let engine = f12::Engine::configure(&mut self.transport, *function, dribble)?;
                let bit = usize::from(function.interrupt_start);
                irq_mask[bit / 8] |= 1 << (bit % 8);
                engines.push(engine);
            }
            let f01 = self.f01.ok_or(Error::MissingF01)?;
            let address = Self::register(f01.control, 1)?;
            self.transport.write(address, &irq_mask)?;
            let mut actual = buffer(irq_mask.len())?;
            self.transport.read(address, &mut actual)?;
            if actual != irq_mask {
                return Err(Error::ConfigurationRejected);
            }
            self.irq_mask = irq_mask;
            self.f12 = engines;
            Ok(())
        })();
        self.fault(result)
    }
    /// A late read failure retains all earlier completed frames and the exact
    /// consumed control status. No partially read frame is published.
    pub fn poll_f12(&mut self) -> F12Poll {
        let mut outcome = F12Poll {
            control: None,
            frames: Vec::new(),
            error: None,
        };
        if let Err(error) = self.configured() {
            outcome.error = Some(error);
            return outcome;
        }
        if !self.f11.is_empty()
            || !self.f1a.is_empty()
            || !self.f03.is_empty()
            || !self.f30.is_empty()
        {
            outcome.error = Some(Error::InputConsumerActive);
            return outcome;
        }
        if self.f12.is_empty() {
            outcome.error = Some(Error::MissingFunction(0x12));
            return outcome;
        }
        let control = match self.poll_attention() {
            Ok(None) => return outcome,
            Ok(Some(control)) => control,
            Err(error) => {
                outcome.error = Some(error);
                return outcome;
            }
        };
        if outcome.frames.try_reserve_exact(self.f12.len()).is_err() {
            outcome.control = Some(control);
            outcome.error = self.fault::<()>(Err(Error::Allocation)).err();
            return outcome;
        }
        let interrupts = &control.interrupts;
        for engine in &self.f12 {
            let bit = usize::from(engine.capabilities.function.interrupt_start);
            if interrupts[bit / 8] & (1 << (bit % 8)) == 0 {
                continue;
            }
            match engine.read(&mut self.transport) {
                Ok(frame) => outcome.frames.push(frame),
                Err(error) => {
                    outcome.error = Some(error);
                    break;
                }
            }
        }
        outcome.control = Some(control);
        if let Some(error) = outcome.error {
            let _ = self.fault::<()>(Err(error));
        }
        outcome
    }
}
