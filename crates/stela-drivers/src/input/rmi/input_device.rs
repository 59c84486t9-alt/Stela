// SPDX-License-Identifier: GPL-2.0-only
//! One attention consumer for all configured RMI function engines.
use super::{Attention, Device, Error, FunctionReport, InputPoll, transport::Transport};
use crate::bus::i2c::Timer;
use alloc::vec::Vec;
impl<X: Transport, A: Attention, T: Timer> Device<X, A, T> {
    pub fn poll_input(&mut self) -> InputPoll {
        let mut outcome = InputPoll {
            control: None,
            reports: Vec::new(),
            error: None,
        };
        if let Err(error) = self.configured() {
            outcome.error = Some(error);
            return outcome;
        }
        let count = self.f11.len() + self.f12.len() + self.f1a.len();
        if count == 0 {
            outcome.error = Some(Error::NotActive);
            return outcome;
        }
        // Allocate before consuming a hardware IRQ, so allocation failure does
        // not retire attention without a place for complete reports.
        if outcome.reports.try_reserve_exact(count).is_err() {
            outcome.error = Some(Error::Allocation);
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
        // PDT/IRQ order is significant for related function reports. Each
        // engine reads only if its actually enabled source bit was observed.
        for function in &self.functions {
            let report = if let Some(engine) = self
                .f11
                .iter()
                .find(|engine| engine.capabilities.function == *function)
            {
                let bit = usize::from(engine.interrupt_bit());
                if control.interrupts[bit / 8] & (1 << (bit % 8)) == 0 {
                    continue;
                }
                engine.read(&mut self.transport).map(FunctionReport::F11)
            } else if let Some(engine) = self
                .f12
                .iter()
                .find(|engine| engine.capabilities.function == *function)
            {
                let bit = usize::from(function.interrupt_start);
                if control.interrupts[bit / 8] & (1 << (bit % 8)) == 0 {
                    continue;
                }
                engine.read(&mut self.transport).map(FunctionReport::F12)
            } else if let Some(engine) = self
                .f1a
                .iter()
                .find(|engine| engine.capabilities.function == *function)
            {
                let active = (function.interrupt_start
                    ..function.interrupt_start + u16::from(function.interrupt_count))
                    .any(|bit| control.interrupts[usize::from(bit / 8)] & (1 << (bit % 8)) != 0);
                if !active {
                    continue;
                }
                engine.read(&mut self.transport).map(FunctionReport::F1A)
            } else {
                continue;
            };
            match report {
                Ok(report) => outcome.reports.push(report),
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
