// SPDX-License-Identifier: GPL-2.0-only
//! One exclusively scheduled interrupt QH. Linux ehci-q.c qh_make and
//! ehci-sched.c qh_link_periodic supply the descriptor/interval reference.
//! A full- or low-speed endpoint behind a hub's transaction translator runs
//! as split transactions: the start-split in microframe 0 and the
//! complete-splits in microframes 2 to 4, the EHCI 1.0 section 4.12.2 layout.
//! With one periodic QH at a time, no TT budget is shared. No concurrent
//! periodic bandwidth allocator or asynchronous unlink is inferred: the
//! complete periodic engine stops before the arena changes.
use super::*;
use schedule::endpoint_index;

#[derive(Clone, Copy)]
pub(super) struct Recipe {
    pub(super) packet: u16,
    transactions: u8,
    /// The period in microframes.
    interval: u16,
    /// Split transactions through a transaction translator.
    split: bool,
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
            split: false,
        })
    }
    /// A full- or low-speed interrupt endpoint's recipe: `interval` is its
    /// bInterval in frames, rounded down to a power of two as Linux
    /// `usb_submit_urb` does for the periodic list.
    pub(super) fn full_speed(max_packet: u16, interval: u8, low: bool) -> Result<Self, Error> {
        if !(1..=if low { 8 } else { 64 }).contains(&max_packet) || interval == 0 {
            return Err(Error::Invalid);
        }
        let frames = 1u16 << (7 - interval.leading_zeros());
        Ok(Self {
            packet: max_packet,
            transactions: 1,
            interval: frames * 8,
            split: true,
        })
    }
    pub(super) fn payload(self) -> usize {
        usize::from(self.packet) * usize::from(self.transactions)
    }
    pub(super) fn frames(self) -> usize {
        usize::from(self.interval).div_ceil(8)
    }
    pub(super) fn info(self) -> u32 {
        if self.split {
            return 1 << 30 | 0x1c << 8 | 1;
        }
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
