// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
//! OS management controls over the sole owning link and bounded notices.
use super::super::super::management::{Received, Session, Transmit};
use super::*;

impl<I: BarIo, Q: QueueIo, C: 'static, S: PageSource + 'static> ManagedLink<I, Q, C, S> {
    /// Install initial association-bound transport keys; never PMF negotiation.
    ///
    /// # Safety
    /// Inherit ManagedClient::install_management_key's authenticated-input and
    /// old hardware/RX/IRQ/work/deferred-key-user drain contract, including
    /// notices already taken by the OS. Empty kept frontend/native queues
    /// are checked but do not establish that independent physical fence.
    pub unsafe fn install_management_key(
        &mut self,
        epoch: u64,
        index: u8,
        material: &[u8],
        receive: PacketNumber,
    ) -> Result<Arc<Session>, LinkControlError>
    where
        C: Send + Sync,
    {
        let s = self.state_mut();
        // Frontend batches must be consumed/drained as well as native
        // queues; never drop observations or silently retag old key users.
        if !s.data.is_empty()
            || !s.notices.is_empty()
            || s.pending.is_some()
            || s.released.is_some()
        {
            return Err(LinkControlError::Backpressure);
        }
        // SAFETY: inherited authentic OS input and independent drain.
        let result = unsafe {
            s.client
                .install_management_key(epoch, index, material, receive)
        };
        Self::reconcile(s);
        Ok(result?)
    }

    /// Install or rotate one secondary link's authenticated IGTK.
    ///
    /// # Safety
    /// Inherit ManagedClient::install_link_management_key's authentic input,
    /// peer-index retirement and independent hardware/RX/IRQ/work/user drain.
    /// This frontend's empty queues do not establish that external fence.
    pub unsafe fn install_link_management_key(
        &mut self,
        link_id: u8,
        index: u8,
        material: &[u8],
        receive: PacketNumber,
    ) -> Result<(), LinkControlError> {
        let s = self.state_mut();
        if !s.data.is_empty()
            || !s.notices.is_empty()
            || s.pending.is_some()
            || s.released.is_some()
        {
            return Err(LinkControlError::Backpressure);
        }
        // SAFETY: inherited authenticated key, peer policy and independent drain.
        let result = unsafe {
            s.client
                .install_link_management_key(link_id, index, material, receive)
        };
        Self::reconcile(s);
        Ok(result?)
    }

    /// Consume a taken ProtectedManagement notice with its original session,
    /// rechecking the current association, keys and policy at the callback.
    pub fn with_management<T>(
        &mut self,
        received: Received,
        consume: impl FnOnce(&Mpdu, &[u8], PacketNumber) -> T,
    ) -> Result<T, LinkControlError> {
        Ok(self.state_mut().client.with_management(received, consume)?)
    }

    /// Publish the OS service's typed protected message under current guards.
    /// Notices must have room before any native producer or allocation effect.
    pub fn transmit_management(
        &mut self,
        session: &Session,
        message: Transmit,
    ) -> Result<Receipt, LinkControlError> {
        let s = self.state_mut();
        if Self::progress(s).backpressured {
            return Err(LinkControlError::Backpressure);
        }
        let result = s.client.transmit_management(session, message, &s.source);
        Self::reconcile(s);
        Ok(result?)
    }
}

impl<I: BarIo, Q: QueueIo, C: 'static, S: PageSource + 'static> ManagedLink<I, Q, C, S> {
    /// Rotate one current IGTK slot after consuming all kept frontend users.
    /// Historical taken envelopes are revoked by the new exact Session.
    ///
    /// # Safety
    /// Inherit ManagedClient::rotate_management_key's authentic OS exchange,
    /// peer same-index retirement and old hardware/RX/IRQ/work/external
    /// deferred-user drain contract, including notices already taken by the OS.
    /// This CPU backpressure check does not prove that independent fence.
    pub unsafe fn rotate_management_key(
        &mut self,
        session: &Session,
        index: u8,
        material: &[u8],
        receive: PacketNumber,
    ) -> Result<Arc<Session>, LinkControlError>
    where
        C: Send + Sync,
    {
        let s = self.state_mut();
        if !s.data.is_empty()
            || !s.notices.is_empty()
            || s.pending.is_some()
            || s.released.is_some()
        {
            return Err(LinkControlError::Backpressure);
        }
        // SAFETY: inherited key exchange, peer policy and drain.
        let result = unsafe {
            s.client
                .rotate_management_key(session, index, material, receive)
        };
        Self::reconcile(s);
        Ok(result?)
    }
}

impl<I: BarIo, Q: QueueIo, C: 'static, S: PageSource + 'static> ManagedLink<I, Q, C, S> {
    /// Consume the original OS-selected protected BA notice.
    ///
    /// # Safety
    /// Inherit ManagedClient::receive_management_block_ack's negotiated
    /// OS policy contract through all deferred responses, timers and teardown.
    pub unsafe fn receive_management_block_ack(
        &mut self,
        received: &mut Option<Received>,
        now: u64,
    ) -> Result<(), LinkControlError> {
        let s = self.state_mut();
        // SAFETY: inherited OS policy; private attachment keeps permission.
        let result = unsafe { s.client.receive_management_block_ack(received, now) };
        Self::reconcile(s);
        Ok(result?)
    }

    /// Begin the real OS's explicitly selected protected BA exchange.
    ///
    /// # Safety
    /// Same negotiated OS policy as receive_management_block_ack; installing
    /// keys does not authorize this or its deferred management effects.
    pub unsafe fn begin_management_block_ack(
        &mut self,
        session: &Arc<Session>,
        tid: u8,
        timeout_tu: u16,
        now: u64,
    ) -> Result<(), LinkControlError> {
        let s = self.state_mut();
        if Self::progress(s).backpressured {
            return Err(LinkControlError::Backpressure);
        }
        // SAFETY: inherited OS policy and sole private native attachment.
        let result = unsafe {
            s.client
                .begin_management_block_ack(session, tid, timeout_tu, now)
        };
        Self::reconcile(s);
        Ok(result?)
    }
}

impl<I: BarIo, Q: QueueIo, C: 'static, S: PageSource + 'static> ManagedLink<I, Q, C, S> {
    /// Progress one separately admitted native BA operation, keeping notices
    /// and packet retirement backpressure before allocating or publishing DMA.
    pub fn progress_block_ack(&mut self, now: u64) -> Result<(), LinkControlError> {
        let s = self.state_mut();
        if Self::progress(s).backpressured {
            return Err(LinkControlError::Backpressure);
        }
        let result = s.client.progress_block_ack(&s.source, now);
        Self::reconcile(s);
        Ok(result?)
    }

    /// Stop BA users while restrictions deny new transmissions.
    pub fn progress_block_ack_stop(&mut self) -> Result<(), LinkControlError> {
        let s = self.state_mut();
        let result = s.client.progress_block_ack_stop();
        Self::reconcile(s);
        Ok(result?)
    }
}

impl<I: BarIo, Q: QueueIo, C: 'static, S: PageSource + 'static> ManagedLink<I, Q, C, S> {
    /// Requested canonical BA timer deadline for the serialized deferred owner.
    pub fn next_transmit_deadline(&self) -> Option<u64> {
        self.state().client.next_transmit_deadline()
    }

    /// Queue restrictive BA timeout handling without publishing a transmission.
    pub fn poll_block_ack_timers(&mut self, now: u64) -> Result<(), LinkControlError> {
        let s = self.state_mut();
        let result = s.client.poll_block_ack_timers(now);
        Self::reconcile(s);
        Ok(result?)
    }
}
