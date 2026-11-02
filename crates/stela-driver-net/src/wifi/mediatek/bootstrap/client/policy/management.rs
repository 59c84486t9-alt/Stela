// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
//! Management transport through the same sole owning policy attachment.
use super::super::management::{Received, Session, Transmit};
use super::*;

impl<I: BarIo, Q: QueueIo, C: 'static> ManagedClient<I, Q, C> {
    fn management_admission(&mut self) -> Result<reg::AssociationAdmission, PolicyError> {
        self.live()?;
        let context = self
            .client
            .modern_context()
            .ok_or(PolicyError::Bss)?
            .clone();
        self.authority
            .admit_association(
                self.client.station(),
                context,
                reg::AssociationUse::Management,
            )
            .map_err(PolicyError::Regulatory)
    }

    /// Keep current peer/PTK/GTK/IGTK transport for the OS management
    /// service. This supplies neither negotiated PMF nor an OS policy service.
    ///
    /// # Safety
    /// The authenticated OS key exchange supplied this association's
    /// IGTK/IPN. Independently stop/drain all old GTK hardware RX/TX, DMA/IRQ/work
    /// and external deferred key users, including observations already returned
    /// by poll. The native BA/queue checks are necessary, not that fence.
    /// No live IGTK rekey is implemented; uncertain commands keep all owners.
    pub unsafe fn install_management_key(
        &mut self,
        epoch: u64,
        index: u8,
        material: &[u8],
        receive: PacketNumber,
    ) -> Result<Arc<Session>, PolicyError> {
        let admission = self.management_admission()?;
        // SAFETY: permission/controller are the same exclusive private attachment;
        // inherited authentic input and independent old-user drain fence.
        unsafe {
            self.client.install_management_key_modern(
                &mut self.authority,
                admission,
                epoch,
                index,
                material,
                receive,
            )
        }
        .map_err(PolicyError::Client)
    }

    /// Install or rotate a secondary link's IGTK from the authenticated MLO KDE.
    ///
    /// # Safety
    /// Inherit install_management_key's independent hardware/RX/IRQ/work/user
    /// drain and authentic input duties. Same-index replacement additionally
    /// requires peer retirement of the old material.
    pub unsafe fn install_link_management_key(
        &mut self,
        link_id: u8,
        index: u8,
        material: &[u8],
        receive: PacketNumber,
    ) -> Result<(), PolicyError> {
        let admission = self.management_admission()?;
        // SAFETY: same privately retained requester and policy authority;
        // caller supplies the authenticated key, peer retirement and drain.
        unsafe {
            self.client.install_link_management_key_modern(
                &mut self.authority,
                admission,
                link_id,
                index,
                material,
                receive,
            )
        }
        .map_err(PolicyError::Client)
    }

    /// Consume the original authenticated observation under current native and
    /// OS regulatory guards. The OS supplies all negotiated PMF/MLME and
    /// SA Query policy; further deferred effects must revalidate independently.
    pub fn with_management<T>(
        &mut self,
        received: Received,
        consume: impl FnOnce(&Mpdu, &[u8], PacketNumber) -> T,
    ) -> Result<T, PolicyError> {
        let admission = self.management_admission()?;
        // SAFETY: the exclusive private attachment owns both permissions;
        // callback has no raw native escape and receives this original namespace.
        unsafe {
            self.client
                .with_management_modern(&mut self.authority, admission, received, consume)
        }
        .map_err(PolicyError::Client)
    }

    /// Typed protected departure/query transport selected by the real OS service.
    /// This does not itself change local peer state or complete an SA Query.
    pub fn transmit_management(
        &mut self,
        session: &Session,
        message: Transmit,
        source: &dyn PageSource,
    ) -> Result<Receipt, PolicyError> {
        let admission = self.management_admission()?;
        // SAFETY: hardware/OS guards belong to this sole native
        // owner; revocation serializes through its real disconnect/drain path.
        unsafe {
            self.client.transmit_management_modern(
                &mut self.authority,
                admission,
                session,
                message,
                source,
            )
        }
        .map_err(PolicyError::Client)
    }
}

impl<I: BarIo, Q: QueueIo, C: 'static> ManagedClient<I, Q, C> {
    /// Update a current management session through this sole owning
    /// hardware/OS attachment; keeps the other MMIE receive key window.
    ///
    /// # Safety
    /// Inherit Client::rotate_management_key_modern's authenticated exchange,
    /// peer same-index retirement and old hardware/RX/IRQ/deferred-user
    /// drain contract. Physical firmware overlap remains unchecked.
    pub unsafe fn rotate_management_key(
        &mut self,
        session: &Session,
        index: u8,
        material: &[u8],
        receive: PacketNumber,
    ) -> Result<Arc<Session>, PolicyError> {
        let admission = self.management_admission()?;
        // SAFETY: this private attachment keeps the native requester and
        // permissions; caller supplies authentic peer policy and drain.
        unsafe {
            self.client.rotate_management_key_modern(
                &mut self.authority,
                admission,
                session,
                index,
                material,
                receive,
            )
        }
        .map_err(PolicyError::Client)
    }
}

impl<I: BarIo, Q: QueueIo, C: 'static> ManagedClient<I, Q, C> {
    /// Apply the OS service's selected original authenticated BA action.
    ///
    /// # Safety
    /// The real OS authorizes this original unicast action and deferred native
    /// BA responses/timers/DELBA under its negotiated protection policy.
    /// Session/key transport and regulatory admission alone do not establish it.
    pub unsafe fn receive_management_block_ack(
        &mut self,
        received: &mut Option<Received>,
        now: u64,
    ) -> Result<(), PolicyError> {
        let admission = self.management_admission()?;
        // SAFETY: private same-requester permission; caller supplies OS
        // negotiated policy, while Client revalidates original RX/session/keys.
        unsafe {
            self.client
                .receive_management_block_ack(&mut self.authority, admission, received, now)
        }
        .map_err(PolicyError::Client)
    }

    /// Request an explicitly OS-selected protected BA exchange.
    ///
    /// # Safety
    /// Same negotiated OS policy, including deferred responses and teardown,
    /// as receive_management_block_ack. This does not negotiate PMF itself.
    pub unsafe fn begin_management_block_ack(
        &mut self,
        session: &Arc<Session>,
        tid: u8,
        timeout_tu: u16,
        now: u64,
    ) -> Result<(), PolicyError> {
        let admission = self.management_admission()?;
        // SAFETY: sole private native permission plus inherited OS policy.
        unsafe {
            self.client.begin_management_block_ack(
                &mut self.authority,
                admission,
                session,
                tid,
                timeout_tu,
                now,
            )
        }
        .map_err(PolicyError::Client)
    }
}

impl<I: BarIo, Q: QueueIo, C: 'static> ManagedClient<I, Q, C> {
    /// Publish one pending BA operation under freshly acquired guards.
    /// The original OS-selected protected exchange keeps its own Session.
    pub fn progress_block_ack(
        &mut self,
        source: &dyn PageSource,
        now: u64,
    ) -> Result<(), PolicyError> {
        let admission = self.management_admission()?;
        // SAFETY: this sole private attachment keeps both real permissions;
        // pending protected work was explicitly selected through the unsafe OS
        // negotiated-policy boundaries and Client revalidates its owner.
        unsafe {
            self.client
                .progress_block_ack(&mut self.authority, admission, source, now)
        }
        .map_err(PolicyError::Client)
    }

    /// Send the oldest action reply under freshly acquired guards.
    pub fn progress_action_reply(&mut self, source: &dyn PageSource) -> Result<(), PolicyError> {
        let admission = self.management_admission()?;
        // SAFETY: as for progress_block_ack; the reply is the station's own.
        unsafe {
            self.client
                .progress_action_reply(&mut self.authority, admission, source)
        }
        .map_err(PolicyError::Client)
    }

    /// Restriction-compatible disable; no new transmit permission or fallback
    /// unprotected DELBA is introduced when current policy has been revoked.
    pub fn progress_block_ack_stop(&mut self) -> Result<(), PolicyError> {
        self.client
            .progress_block_ack_stop()
            .map_err(PolicyError::Client)
    }
}

impl<I: BarIo, Q: QueueIo, C: 'static> ManagedClient<I, Q, C> {
    /// Requested canonical BA timer deadline; no platform scheduler is installed.
    pub fn next_transmit_deadline(&self) -> Option<u64> {
        self.client.next_transmit_deadline()
    }

    /// Queue a restrictive timeout/stop. Disable and optional local
    /// protected DELBA remain separate drain/ACK/guarded progress operations.
    pub fn poll_block_ack_timers(&mut self, now: u64) -> Result<(), PolicyError> {
        self.client
            .poll_block_ack_timers(now)
            .map_err(PolicyError::Client)
    }
}
