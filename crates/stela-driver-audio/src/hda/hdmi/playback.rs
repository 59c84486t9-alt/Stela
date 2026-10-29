// SPDX-License-Identifier: GPL-2.0-only
//! Explicit completed-period playback ownership over the existing HDA coherent
//! boot-lifetime allocation. IOC is set on whole periods, as in pinned
//! sound/hda/core/stream.c; position/elapsed validation follows the donor's
//! period interrupt discipline. BCIS alone never counts wraps or grants RAM.
use super::*;
use crate::hda::registers::*;
use core::sync::atomic::{Ordering, fence};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RefilledPeriod {
    pub sequence: u64,
    pub ring_offset: usize,
    pub bytes: usize,
}
pub(super) struct Progress {
    period: usize,
    ring: usize,
    guard: u64,
    bytes_per_second: u64,
    played: u64,
    completed: u64,
    submitted: u64,
    refilled: u64,
    position: u32,
    time: u64,
}
impl Progress {
    fn new(period: usize, ring: usize, guard: u64, rate: u64, now: u64) -> Result<Self, Error> {
        if period == 0
            || !ring.is_multiple_of(period)
            || ring < period * 3
            || guard >= (ring - period) as u64
        {
            return Err(Error::InvalidBuffer);
        }
        Ok(Self {
            period,
            ring,
            guard,
            bytes_per_second: rate,
            played: 0,
            completed: 0,
            submitted: ring as u64,
            refilled: 0,
            position: 0,
            time: now,
        })
    }
    fn observe(&mut self, position: u32, ioc: bool, now: u64) -> Result<(), Error> {
        let elapsed = now.wrapping_sub(self.time);
        // Refuse ambiguous full laps using an independent monotonic clock.
        // This is conservative if the device temporarily stalled.
        let possible = elapsed
            .saturating_mul(self.bytes_per_second)
            .div_ceil(1_000_000)
            .saturating_add(self.guard);
        if possible >= self.ring as u64 {
            return Err(Error::PlaybackUnderrun);
        }
        if position as usize >= self.ring {
            return Err(Error::InvalidPosition(position));
        }
        let delta =
            (u64::from(position) + self.ring as u64 - u64::from(self.position)) % self.ring as u64;
        if delta > possible {
            return Err(Error::PlaybackUnderrun);
        }
        self.played = self
            .played
            .checked_add(delta)
            .ok_or(Error::PlaybackUnderrun)?;
        self.position = position;
        self.time = now;
        if self.played.saturating_add(self.guard) >= self.submitted {
            return Err(Error::PlaybackUnderrun);
        }
        if ioc {
            self.completed = self.played / self.period as u64 * self.period as u64;
        }
        Ok(())
    }
    fn reusable(&self) -> Result<bool, Error> {
        if self.played.saturating_add(self.guard) >= self.refilled + self.ring as u64 {
            return Err(Error::PlaybackUnderrun);
        }
        Ok(self.completed >= self.refilled + self.period as u64)
    }
}
impl<R: Registers, T: Timer> Controller<R, T> {
    pub(in crate::hda) fn hdmi_before_start(&mut self, id: StreamId) -> Result<(), Error> {
        let Some(index) = self.hdmi_stream_port(id) else {
            return Ok(());
        };
        self.hdmi_runtime(id)?;
        let stream = self.stream(id)?;
        let (period, ring, format, bdl) = (
            stream.period_bytes,
            stream.buffer.len(),
            stream.format,
            stream._bdl.physical(),
        );
        let count = stream.bdl_entries;
        let base = stream_base(id.descriptor_index());
        // Fresh explicit start is a stream descriptor reset, not an
        // assumed zero coordinate or continuation of stale PCM/IOC ownership.
        self.reset_descriptor(id.descriptor_index())?;
        self.registers.write8(base + SD_CTL + 2, id.tag() << 4);
        self.registers.write32(base + SD_CBL, ring as u32);
        self.registers.write16(base + SD_FORMAT, format.encode()?);
        self.registers.write16(base + SD_LVI, count - 1);
        self.registers.write32(base + SD_BDLPL, bdl as u32);
        self.registers.write32(base + SD_BDLPU, (bdl >> 32) as u32);
        let position = self.registers.read32(base + SD_LPIB);
        if position != 0 {
            return Err(Error::InvalidPosition(position));
        }
        let fifo = self.registers.read16(base + 0x10);
        if fifo == u16::MAX {
            return Err(Error::RegisterUnavailable {
                offset: base + 0x10,
            });
        }
        // FIFO capacity plus one complete link packet is excluded from
        // the writable next-lap window. LPIB is the transport coordinate, never
        // a FIFO-corrected audible position used to invent extra free RAM.
        let guard = u64::from(fifo) + 1 + format.packet_bytes()? as u64;
        let progress = Progress::new(
            period,
            ring,
            guard,
            u64::from(format.rate) * format.frame_bytes()? as u64,
            self.timer.now_us(),
        )?;
        self.hdmi_ports[index]
            .as_mut()
            .unwrap()
            .route
            .as_mut()
            .unwrap()
            .progress = Some(progress);
        fence(Ordering::SeqCst);
        Ok(())
    }
    pub(in crate::hda) fn hdmi_progress(
        &mut self,
        id: StreamId,
        position: u32,
        ioc: bool,
    ) -> Result<(), Error> {
        let Some(index) = self.hdmi_stream_port(id) else {
            return Ok(());
        };
        let now = self.timer.now_us();
        let result = self.hdmi_ports[index]
            .as_mut()
            .unwrap()
            .route
            .as_mut()
            .unwrap()
            .progress
            .as_mut()
            .map_or(Ok(()), |p| p.observe(position, ioc, now));
        if let Err(error) = result {
            self.hdmi_record(index, error);
            if let Err(cleanup) = self.hdmi_close_index(index) {
                self.routing_failed = true;
                self.hdmi_record(index, cleanup);
            }
            return Err(error);
        }
        Ok(())
    }
    /// Refill exactly the next completed period while DMA runs. RAM
    /// stays owned by this driver and coherent HDA allocation. No client
    /// pointer, cache-sync-as-ownership or repeated stop/start is used.
    ///
    /// Call often enough to keep unread fresh PCM ahead of the FIFO.
    /// BCIS is coalesced, so elapsed >= one ring, a consumed queue, or hardware
    /// entering the copy window causes PlaybackUnderrun and stop. An
    /// unbounded preemption can permit a partial late device read; failure does
    /// NOT promise rollback, atomic audio or a successfully committed period.
    pub fn refill_hdmi_period(
        &mut self,
        id: StreamId,
        pcm: &[u8],
    ) -> Result<Option<RefilledPeriod>, Error> {
        let index = self.hdmi_stream_port(id).ok_or(Error::InvalidHdmiPort)?;
        if !self.stream(id)?.running {
            return Err(Error::StreamStopped);
        }
        let period = self.stream(id)?.period_bytes;
        if pcm.len() != period {
            return Err(Error::InvalidBuffer);
        }
        self.status(id)?;
        let progress = self.hdmi_ports[index]
            .as_ref()
            .unwrap()
            .route
            .as_ref()
            .unwrap()
            .progress
            .as_ref()
            .ok_or(Error::StreamStopped)?;
        if !progress.reusable()? {
            return Ok(None);
        }
        let start = (progress.refilled % progress.ring as u64) as usize;
        let sequence = progress.refilled / period as u64;
        // Checked aligned volatile words, not a mutable slice alias over active
        // device RAM. Controller::new's coherent RAM grant is mandatory.
        for (word, bytes) in pcm.as_chunks::<4>().0.iter().enumerate() {
            self.streams[usize::from(id.descriptor_index())]
                .as_mut()
                .unwrap()
                .buffer
                .write(start + word * 4, u32::from_le_bytes(*bytes).to_le());
        }
        fence(Ordering::SeqCst);
        self.status(id)?;
        let progress = self.hdmi_ports[index]
            .as_mut()
            .unwrap()
            .route
            .as_mut()
            .unwrap()
            .progress
            .as_mut()
            .unwrap();
        if let Err(error) = progress.reusable() {
            self.hdmi_record(index, error);
            if let Err(cleanup) = self.hdmi_close_index(index) {
                self.routing_failed = true;
                self.hdmi_record(index, cleanup);
            }
            return Err(error);
        }
        progress.refilled = progress
            .refilled
            .checked_add(period as u64)
            .ok_or(Error::PlaybackUnderrun)?;
        progress.submitted = progress
            .submitted
            .checked_add(period as u64)
            .ok_or(Error::PlaybackUnderrun)?;
        Ok(Some(RefilledPeriod {
            sequence,
            ring_offset: start,
            bytes: period,
        }))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ioc_completion_frontier() {
        let mut p = Progress::new(4096, 16384, 132, 192000, 0).unwrap();
        p.observe(8192, false, 45000).unwrap();
        assert!(!p.reusable().unwrap());
        p.observe(8192, true, 45001).unwrap();
        assert!(p.reusable().unwrap());
        p.refilled += 4096;
        p.submitted += 4096;
        assert!(p.reusable().unwrap());
        p.refilled += 4096;
        p.submitted += 4096;
        for n in 3..=24 {
            let pos = (n * 4096 % 16384) as u32;
            p.observe(pos, true, (n * 22000) as u64).unwrap();
            assert!(p.reusable().unwrap());
            p.refilled += 4096;
            p.submitted += 4096;
        }
        assert_eq!(p.played, 24 * 4096);
        assert_eq!(p.refilled, 24 * 4096);
    }
    #[test]
    fn ambiguous_lap_empty_queue_and_midcopy_fifo_entry_are_xrun() {
        let mut p = Progress::new(4096, 16384, 132, 192000, 0).unwrap();
        assert_eq!(p.observe(0, true, 100000), Err(Error::PlaybackUnderrun));
        let mut p = Progress::new(4096, 16384, 132, 192000, 0).unwrap();
        p.observe(4096, true, 22000).unwrap();
        assert!(p.reusable().unwrap());
        assert_eq!(p.observe(16300, true, 86000), Err(Error::PlaybackUnderrun));
    }
}
