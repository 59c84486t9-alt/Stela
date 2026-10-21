//! Exclusive packet effects from the actual installed T6000 SRAM bytes.
//!
//! This owns a frozen decode image, not a hardware trigger or active-engine PC.
//! The mount must separately qualify the real trigger before routing effects.
//! There is no supplied arbitrary PC, completion setter or end-retirement API.
use super::{Controller, Error};
use crate::platform::apple::pmgr::sequencer::{
    self, AddressFormat, PacketCursor, PhysicalWrite, RouteOutcome, WriteClaim, poll,
};
use alloc::vec;

pub struct Effects {
    controller: Controller,
    cursor: PacketCursor,
}
impl Controller {
    /// Claim packet-effect ownership at an actual published group/slot, using
    /// its checked pointer and a supplied, qualified emitted image extent and
    /// address format. No request is selected/acknowledged by this operation.
    ///
    /// Only actual known SRAM bytes are copied into the immutable decode cache.
    /// The same owner then forbids modifying those bytes or their table/slot
    /// routing. Dropping a cursor cannot erase effects or release that lease;
    /// reset, end retirement and native cancellation remain unqualified.
    pub fn native_packet_effects(
        &self,
        group: u8,
        slot: u8,
        bytes: usize,
        format: AddressFormat,
    ) -> Result<Effects, Error> {
        let mut state = self.0.borrow_mut();
        state.accessible().map_err(|_| Error::Paused)?;
        let suspended = state.paused();
        let native = state.native.as_mut().ok_or(Error::Unmounted)?;
        if native.packet_effects_owned {
            return Err(Error::EffectsOwned);
        }
        let entry = native.entry(group, slot)?;
        if bytes == 0 || !bytes.is_multiple_of(4) {
            return Err(Error::Geometry);
        }
        // Check the complete physical extent before allocating the decode copy.
        super::State::byte_extent(entry.pc - super::SRAM_BASE, bytes)?;
        let mut image = vec![0; bytes];
        native.read_bytes(entry.pc - super::SRAM_BASE, &mut image)?;
        let mut cursor = PacketCursor::unknown();
        cursor
            .install_sram(entry.pc, &image, format)
            .map_err(Error::Cursor)?;
        cursor.set_suspended(suspended);
        native.packet_effects_owned = true;
        Ok(Effects {
            controller: self.clone(),
            cursor,
        })
    }
}
impl Effects {
    fn refresh_pause(&mut self) {
        self.cursor
            .set_suspended(self.controller.0.borrow().paused());
    }
    pub fn packet_pc(&self) -> Option<u64> {
        self.cursor.packet_pc()
    }
    pub fn committed_writes(&self) -> u64 {
        self.cursor.committed_writes()
    }
    pub fn committed_reads(&self) -> u64 {
        self.cursor.committed_reads()
    }
    pub fn pending_poll(&self) -> Option<poll::Poll> {
        self.cursor.pending_poll()
    }
    pub fn last_poll_value(&self) -> Option<u64> {
        self.cursor.last_poll_value()
    }
    pub fn uncertain_write(&self) -> Option<PhysicalWrite> {
        self.cursor.uncertain_write()
    }
    pub fn uncertain_read(&self) -> Option<poll::PhysicalRead> {
        self.cursor.uncertain_read()
    }
    pub fn begin_write(&mut self) -> Result<WriteClaim, sequencer::Error> {
        self.refresh_pause();
        self.cursor.begin_write()
    }
    pub fn dispatch_write(
        &mut self,
        claim: &WriteClaim,
    ) -> Result<PhysicalWrite, sequencer::Error> {
        self.refresh_pause();
        self.cursor.dispatch_write(claim)
    }
    pub fn cancel_write(&mut self, claim: &WriteClaim) -> Result<(), sequencer::Error> {
        self.cursor.cancel_claim(claim)
    }
    pub fn finish_write<E>(
        &mut self,
        claim: &WriteClaim,
        outcome: RouteOutcome<E>,
    ) -> Result<(), sequencer::FinishError<E>> {
        self.cursor.finish_write(claim, outcome)
    }
    pub fn begin_read(&mut self) -> Result<poll::ReadClaim, sequencer::Error> {
        self.refresh_pause();
        self.cursor.begin_read()
    }
    pub fn dispatch_read(
        &mut self,
        claim: &poll::ReadClaim,
    ) -> Result<poll::PhysicalRead, sequencer::Error> {
        self.refresh_pause();
        self.cursor.dispatch_read(claim)
    }
    pub fn cancel_read(&mut self, claim: &poll::ReadClaim) -> Result<(), sequencer::Error> {
        self.cursor.cancel_read(claim)
    }
    pub fn finish_read<E>(
        &mut self,
        claim: &poll::ReadClaim,
        outcome: poll::Outcome<E>,
    ) -> Result<bool, poll::FinishError<E>> {
        self.cursor.finish_read(claim, outcome)
    }
}
