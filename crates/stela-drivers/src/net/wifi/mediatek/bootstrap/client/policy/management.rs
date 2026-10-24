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

    /// Retain actual current peer/PTK/GTK/IGTK transport for the OS management
    /// service. This supplies neither negotiated PMF nor an OS policy service.
    ///
    /// # Safety
    /// The actual authenticated OS key exchange supplied this association's
    /// IGTK/IPN. Independently stop/drain all old GTK hardware RX/TX, DMA/IRQ/work
    /// and external deferred key users, including observations already returned
    /// by poll. The native BA/queue checks are necessary, not that actual fence.
    /// No live IGTK rekey is implemented; uncertain commands retain all owners.
    pub unsafe fn install_management_key(
        &mut self,
        epoch: u64,
        index: u8,
        material: &[u8],
        receive: PacketNumber,
    ) -> Result<Arc<Session>, PolicyError>
    where
        C: Send + Sync,
    {
        let admission = self.management_admission()?;
        // SAFETY: authority/controller are the same exclusive private attachment;
        // inherited authentic input and actual independent old-user drain fence.
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

    /// Consume the original authenticated observation under current native and
    /// OS regulatory guards. The actual OS supplies all negotiated PMF/MLME and
    /// SA Query policy; further deferred effects must revalidate independently.
    pub fn with_management<T>(
        &mut self,
        received: Received,
        consume: impl FnOnce(&Mpdu, &[u8], PacketNumber) -> T,
    ) -> Result<T, PolicyError> {
        let admission = self.management_admission()?;
        // SAFETY: the exclusive private attachment owns both actual authorities;
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
        // SAFETY: actual hardware/OS guards belong to this sole retained native
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
    /// Update a current retained management session through this sole owning
    /// hardware/OS attachment; retains the other MMIE receive key window.
    ///
    /// # Safety
    /// Inherit Client::rotate_management_key_modern's authenticated exchange,
    /// peer same-index retirement and actual old hardware/RX/IRQ/deferred-user
    /// drain contract. Physical firmware overlap remains unqualified.
    pub unsafe fn rotate_management_key(
        &mut self,
        session: &Session,
        index: u8,
        material: &[u8],
        receive: PacketNumber,
    ) -> Result<Arc<Session>, PolicyError>
    where
        C: Send + Sync,
    {
        let admission = self.management_admission()?;
        // SAFETY: this private attachment retains the exact native requester and
        // authorities; caller supplies authentic peer policy and actual drain.
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
