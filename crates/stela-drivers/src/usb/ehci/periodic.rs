// SPDX-License-Identifier: GPL-2.0-only
//! One exclusively scheduled high-speed interrupt QH. Linux ehci-q.c qh_make
//! and ehci-sched.c qh_link_periodic supply the descriptor/interval reference.
//! No TT, concurrent periodic bandwidth allocator or asynchronous unlink is
//! inferred: the complete periodic engine stops before the arena changes.
use super::*;
use schedule::endpoint_index;

#[derive(Clone, Copy)]
pub(super) struct Recipe {
    pub(super) packet: u16,
    transactions: u8,
    interval: u16,
}
impl Recipe {
    pub(super) fn new(max_packet: u16, interval: u8) -> Result<Self, Error> {
        let packet = max_packet & 0x7ff;
        let transactions = ((max_packet >> 11) & 3) as u8 + 1;
        if !(1..=1024).contains(&packet)
            || transactions > 3
            || max_packet & 0xe000 != 0
            || !(1..=16).contains(&interval)
        {
            return Err(Error::Invalid);
        }
        // A 1024-frame list cannot express a longer exact period. Unlike the
        // Linux URB policy, this owner never silently shortens the descriptor.
        if interval > 14 {
            return Err(Error::Unsupported(
                "EHCI interrupt interval exceeds periodic list",
            ));
        }
        Ok(Self {
            packet,
            transactions,
            interval: 1 << (interval - 1),
        })
    }
    pub(super) fn payload(self) -> usize {
        usize::from(self.packet) * usize::from(self.transactions)
    }
    pub(super) fn frames(self) -> usize {
        usize::from(self.interval).div_ceil(8)
    }
    pub(super) fn info(self) -> u32 {
        let step = usize::from(self.interval).min(8);
        let mask = (0..8).step_by(step).fold(0u32, |mask, bit| mask | 1 << bit);
        u32::from(self.transactions) << 30 | mask
    }
}

impl Controller {
    /// Return the interrupt endpoints from the last successful
    /// SET_CONFIGURATION. An empty list does not manufacture a class binding.
    pub fn interrupt_pipes(&self, id: &DeviceId) -> Result<Vec<InterruptPipe>, Error> {
        let index = self.identity(id)?;
        let device = self.ports[index].as_ref().expect("validated");
        let mut pipes = Vec::new();
        pipes
            .try_reserve_exact(
                device
                    .endpoints
                    .iter()
                    .flatten()
                    .filter(|ep| ep.periodic.is_some())
                    .count(),
            )
            .map_err(|_| Error::Exhausted)?;
        for (endpoint, state) in device.endpoints.iter().enumerate() {
            if let Some(recipe) = state.and_then(|ep| ep.periodic) {
                pipes.push(InterruptPipe {
                    device: id.clone(),
                    configuration: device.configuration,
                    endpoint: (endpoint & 15) as u8 | if endpoint >= 16 { 0x80 } else { 0 },
                    interval_microframes: recipe.interval,
                });
            }
        }
        Ok(pipes)
    }
    fn interrupt_pipe(&self, pipe: &InterruptPipe) -> Result<usize, Error> {
        let index = self.identity(&pipe.device)?;
        let device = self.ports[index].as_ref().expect("validated");
        if device.configuration != pipe.configuration
            || device.endpoints[endpoint_index(pipe.endpoint)]
                .and_then(|ep| ep.periodic)
                .is_none_or(|recipe| recipe.interval != pipe.interval_microframes)
        {
            return Err(Error::Stale);
        }
        Ok(index)
    }
    /// Submit one descriptor-bounded service payload. The sole active request
    /// owns the complete periodic budget; control/bulk cannot run concurrently.
    /// Hardware NAK leaves the exact QH overlay active for the next service.
    pub fn submit_interrupt_in(
        &mut self,
        pipe: &InterruptPipe,
        bytes: usize,
        timeout_us: u64,
    ) -> Result<TransferId, Error> {
        self.interrupt_pipe(pipe)?;
        if pipe.endpoint & 0x80 == 0 {
            return Err(Error::Invalid);
        }
        self.start(
            &pipe.device,
            Some(pipe.endpoint),
            None,
            &[],
            bytes,
            timeout_us,
        )
    }
    pub fn submit_interrupt_out(
        &mut self,
        pipe: &InterruptPipe,
        data: &[u8],
        timeout_us: u64,
    ) -> Result<TransferId, Error> {
        self.interrupt_pipe(pipe)?;
        if pipe.endpoint & 0x80 != 0 {
            return Err(Error::Invalid);
        }
        self.start(&pipe.device, Some(pipe.endpoint), None, data, 0, timeout_us)
    }
    /// Reset only this exact interrupt endpoint's USB halt/toggle after an
    /// CLEAR_FEATURE Status ACK. Failed control preserves the old state.
    pub fn clear_interrupt_halt(&mut self, pipe: &InterruptPipe) -> Result<(), Error> {
        let index = self.interrupt_pipe(pipe)?;
        self.control_internal(&pipe.device, [2, 1, 0, 0, pipe.endpoint, 0, 0, 0], &[], 0)?;
        let endpoint = self.ports[index].as_mut().expect("live").endpoints
            [endpoint_index(pipe.endpoint)]
        .as_mut()
        .ok_or(Error::Stale)?;
        endpoint.toggle = false;
        endpoint.ping = false;
        endpoint.halted = false;
        Ok(())
    }
}
