//! Exclusive packet effects from the actual installed T6000 SRAM bytes.
//!
//! This owns a frozen decode image, not a hardware trigger or active-engine PC.
//! The mount must separately qualify the real trigger before routing effects.
//! There is no supplied arbitrary PC, completion setter or end-retirement API.
use super::{Controller, Error};
use crate::platform::apple::pmgr::sequencer::{
    self, AddressFormat, PacketCursor, PhysicalWrite, RouteOutcome, WriteClaim, copy, delay, poll,
};
use alloc::{rc::Rc, vec};
use core::cell::RefCell;

pub struct Effects {
    pub(super) controller: Controller,
    pub(super) cursor: Rc<RefCell<PacketCursor>>,
}
impl Controller {
    /// Bind complete actual clock inputs and a separately qualified phase to
    /// this same retained controller. No later call can substitute that clock.
    pub fn bind_native_clock(
        &self,
        image: crate::platform::apple::power::t6000::clock::Image,
        phase: crate::platform::apple::power::t6000::clock::Phase,
    ) -> Result<(), Error> {
        let mut state = self.0.borrow_mut();
        use crate::platform::apple::power::t6000::clock::{Error as ClockError, Phase};
        let at = match phase {
            Phase::Unknown => None,
            Phase::Captured { at, .. } | Phase::DeclaredStela { at, .. } => Some(at),
        };
        if at
            .zip(state.clock_edge_at)
            .is_some_and(|(at, edge)| at < edge)
        {
            return Err(Error::Clock(ClockError::PhaseHistory));
        }
        let native = state.native.as_mut().ok_or(Error::Unmounted)?;
        if native.clock.is_some() {
            return Err(Error::ClockBound);
        }
        let clock = crate::platform::apple::power::t6000::clock::phase::Clock::new(image, phase)
            .map_err(Error::Clock)?;
        native.clock = Some(clock);
        Ok(())
    }
    pub fn native_clock_observations(
        &self,
    ) -> Result<crate::platform::apple::power::t6000::clock::Snapshot, Error> {
        self.0
            .borrow()
            .native
            .as_ref()
            .ok_or(Error::Unmounted)?
            .clock
            .as_ref()
            .map(|clock| clock.snapshot())
            .ok_or(Error::ClockUnbound)
    }
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
        if native.packet_effects_owned || native.engine.is_some() {
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
            cursor: Rc::new(RefCell::new(cursor)),
        })
    }
}
impl Effects {
    pub(super) fn refresh_pause(&mut self) -> Result<(), sequencer::Error> {
        let state = self.controller.0.borrow();
        if state
            .native
            .as_ref()
            .and_then(|native| native.clock.as_ref())
            .is_some_and(|clock| clock.cycles().is_err())
        {
            return Err(sequencer::Error::UnqualifiedClockPhase);
        }
        self.cursor.borrow_mut().set_suspended(state.paused());
        Ok(())
    }
    pub fn packet_pc(&self) -> Option<u64> {
        self.cursor.borrow().packet_pc()
    }
    pub fn packet_kind(&self) -> Result<sequencer::PacketKind, sequencer::Error> {
        self.cursor.borrow().packet_kind()
    }
    pub fn committed_writes(&self) -> u64 {
        self.cursor.borrow().committed_writes()
    }
    pub fn committed_reads(&self) -> u64 {
        self.cursor.borrow().committed_reads()
    }
    pub fn pending_poll(&self) -> Option<poll::Poll> {
        self.cursor.borrow().pending_poll()
    }
    pub fn last_poll_value(&self) -> Option<u64> {
        self.cursor.borrow().last_poll_value()
    }
    pub fn pending_delay(&self) -> Option<u32> {
        self.cursor.borrow().pending_delay()
    }
    /// Earliest actual system-counter sample for the current delay. Unknown
    /// clocks return an error; a stopped clock or suspended service has no
    /// runnable deadline. This does not advance time or execute the packet.
    pub fn delay_deadline(&self) -> Result<Option<u64>, Error> {
        let state = self.controller.0.borrow();
        if state.paused() {
            return Ok(None);
        }
        let clock = state
            .native
            .as_ref()
            .ok_or(Error::Unmounted)?
            .clock
            .as_ref()
            .ok_or(Error::ClockUnbound)?;
        let Some(remaining) = self
            .cursor
            .borrow()
            .remaining_delay_at(clock.cycles().map_err(Error::Clock)?)
            .map_err(Error::Cursor)?
        else {
            return Ok(None);
        };
        clock.deadline(remaining).map_err(Error::Clock)
    }
    /// Join actual 24MHz system time to the separately supplied native clock
    /// frequency/phase. Rail/clock pauses are settled at their real lifecycle
    /// edges. Quiesce blocks instruction service but does not turn that clock
    /// off. A completed wait advances only this packet, never native retirement.
    pub fn advance_delay(&mut self, now: u64) -> Result<delay::Progress, Error> {
        let mut state = self.controller.0.borrow_mut();
        let running = state.clock_running();
        let paused = state.paused();
        let cycles = state
            .native
            .as_mut()
            .ok_or(Error::Unmounted)?
            .clock
            .as_mut()
            .ok_or(Error::ClockUnbound)?
            .observe(now, running)
            .map_err(Error::Clock)?;
        drop(state);
        self.cursor.borrow_mut().set_suspended(paused);
        self.cursor
            .borrow_mut()
            .advance_delay(cycles)
            .map_err(Error::Cursor)
    }
    pub fn uncertain_write(&self) -> Option<PhysicalWrite> {
        self.cursor.borrow().uncertain_write()
    }
    pub fn uncertain_read(&self) -> Option<poll::PhysicalRead> {
        self.cursor.borrow().uncertain_read()
    }
    pub fn begin_write(&mut self) -> Result<WriteClaim, sequencer::Error> {
        self.refresh_pause()?;
        self.cursor.borrow_mut().begin_write()
    }
    pub fn dispatch_write(
        &mut self,
        claim: &WriteClaim,
    ) -> Result<PhysicalWrite, sequencer::Error> {
        self.refresh_pause()?;
        self.cursor.borrow_mut().dispatch_write(claim)
    }
    pub fn cancel_write(&mut self, claim: &WriteClaim) -> Result<(), sequencer::Error> {
        self.cursor.borrow_mut().cancel_claim(claim)
    }
    pub fn finish_write<E>(
        &mut self,
        claim: &WriteClaim,
        outcome: RouteOutcome<E>,
    ) -> Result<(), sequencer::FinishError<E>> {
        self.cursor.borrow_mut().finish_write(claim, outcome)
    }
    pub fn begin_read(&mut self) -> Result<poll::ReadClaim, sequencer::Error> {
        self.refresh_pause()?;
        self.cursor.borrow_mut().begin_read()
    }
    pub fn dispatch_read(
        &mut self,
        claim: &poll::ReadClaim,
    ) -> Result<poll::PhysicalRead, sequencer::Error> {
        self.refresh_pause()?;
        self.cursor.borrow_mut().dispatch_read(claim)
    }
    pub fn cancel_read(&mut self, claim: &poll::ReadClaim) -> Result<(), sequencer::Error> {
        self.cursor.borrow_mut().cancel_read(claim)
    }
    pub fn finish_read<E>(
        &mut self,
        claim: &poll::ReadClaim,
        outcome: poll::Outcome<E>,
    ) -> Result<bool, poll::FinishError<E>> {
        self.cursor.borrow_mut().finish_read(claim, outcome)
    }
    pub fn pending_copy(&self) -> Option<copy::Snapshot> {
        self.cursor.borrow().pending_copy()
    }
    pub fn last_copy(&self) -> Option<copy::Completed> {
        self.cursor.borrow().last_copy()
    }
    pub fn begin_copy_read(&mut self) -> Result<copy::ReadClaim, sequencer::Error> {
        self.refresh_pause()?;
        self.cursor.borrow_mut().begin_copy_read()
    }
    pub fn dispatch_copy_read(
        &mut self,
        claim: &copy::ReadClaim,
    ) -> Result<copy::PhysicalRead, sequencer::Error> {
        self.refresh_pause()?;
        self.cursor.borrow_mut().dispatch_copy_read(claim)
    }
    pub fn cancel_copy_read(&mut self, claim: &copy::ReadClaim) -> Result<(), sequencer::Error> {
        self.cursor.borrow_mut().cancel_copy_read(claim)
    }
    pub fn finish_copy_read<E>(
        &mut self,
        claim: &copy::ReadClaim,
        outcome: copy::ReadOutcome<E>,
    ) -> Result<(), copy::ReadFinishError<E>> {
        self.cursor.borrow_mut().finish_copy_read(claim, outcome)
    }
    pub fn begin_copy_write(&mut self) -> Result<copy::WriteClaim, sequencer::Error> {
        self.refresh_pause()?;
        self.cursor.borrow_mut().begin_copy_write()
    }
    pub fn dispatch_copy_write(
        &mut self,
        claim: &copy::WriteClaim,
    ) -> Result<copy::PhysicalWrite, sequencer::Error> {
        self.refresh_pause()?;
        self.cursor.borrow_mut().dispatch_copy_write(claim)
    }
    pub fn cancel_copy_write(&mut self, claim: &copy::WriteClaim) -> Result<(), sequencer::Error> {
        self.cursor.borrow_mut().cancel_copy_write(claim)
    }
    pub fn finish_copy_write<E>(
        &mut self,
        claim: &copy::WriteClaim,
        outcome: RouteOutcome<E>,
    ) -> Result<(), sequencer::FinishError<E>> {
        self.cursor.borrow_mut().finish_copy_write(claim, outcome)
    }
    pub(super) fn advance_copy_join(&mut self) -> Result<copy::Completed, sequencer::Error> {
        self.refresh_pause()?;
        self.cursor.borrow_mut().advance_copy_join()
    }
}
