// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
//! OS management controls over the sole owning link and bounded notices.
use super::super::super::management::{Received, Session, Transmit};
use super::*;

impl<I: BarIo, Q: QueueIo, C: 'static, S: PageSource + 'static> ManagedLink<I, Q, C, S> {
    /// Install initial association-bound transport keys; never PMF negotiation.
    ///
    /// # Safety
    /// Inherit ManagedClient::install_management_key's authenticated-input and
    /// actual old hardware/RX/IRQ/work/deferred-key-user drain contract, including
    /// notices already taken by the OS. Empty retained frontend/native queues
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
        // Retained frontend batches must be consumed/drained as well as native
        // queues; never drop observations or silently retag old key users.
        if !s.data.is_empty()
            || !s.notices.is_empty()
            || s.pending.is_some()
            || s.released.is_some()
        {
            return Err(LinkControlError::Backpressure);
        }
        // SAFETY: inherited authentic OS input and independent actual drain.
        let result = unsafe {
            s.client
                .install_management_key(epoch, index, material, receive)
        };
        Self::reconcile(s);
        Ok(result?)
    }

    /// Consume a taken ProtectedManagement notice with its original session,
    /// rechecking the actual current association, keys and policy at the callback.
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
