// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
//! OS-facing SAE transport over the sole owning link and its bounded notices.
use super::*;
use station::{external::Session, multi_link::Affiliation, wire::six_ghz::Selection};

impl<I: BarIo, Q: QueueIo, C: 'static, S: PageSource + 'static> ManagedLink<I, Q, C, S> {
    /// Begin against a scan BSS. Authentication observations and
    /// terminal notices are delivered through take_notice with their session.
    /// The link stays down; no OS credential provider is invented here.
    /// With an AP MLD, `multi_link` names the setup link it runs on.
    pub fn begin_external_authentication(
        &mut self,
        bss: BssHandle,
        profile: Profile,
        multi_link: Option<Affiliation>,
        budget: u64,
    ) -> Result<Arc<Session>, LinkControlError> {
        let now = self.now();
        let state = self.state_mut();
        let result = state
            .client
            .begin_external_authentication(bss, profile, multi_link, now, budget);
        Self::reconcile(state);
        Ok(result?)
    }
    /// Begin a 6 GHz SAE exchange against a scan BSS with the OS's
    /// `selection`, its RSNE and RSNXE. Transmission, reception, association
    /// and cancellation then go through the session as on any other band.
    pub fn begin_six_ghz_external_authentication(
        &mut self,
        bss: BssHandle,
        selection: Selection,
        profile: Profile,
        budget: u64,
    ) -> Result<Arc<Session>, LinkControlError> {
        let now = self.now();
        let state = self.state_mut();
        let result = state
            .client
            .begin_six_ghz_external_authentication(bss, selection, profile, now, budget);
        Self::reconcile(state);
        Ok(result?)
    }
    pub fn transmit_external_authentication(
        &mut self,
        session: &Session,
        frame: station::external::Frame<'_>,
    ) -> Result<Receipt, LinkControlError> {
        let now = self.now();
        let state = self.state_mut();
        let result =
            state
                .client
                .transmit_external_authentication(session, frame, now, &state.source);
        Self::reconcile(state);
        Ok(result?)
    }
    /// Associate once the OS's SAE exchange authenticated the station, as
    /// NL80211_CMD_ASSOCIATE does after it.
    pub fn associate_external(
        &mut self,
        session: &Session,
        bss: BssHandle,
        join: Join,
    ) -> Result<(), LinkControlError> {
        if join.policy != station::PortPolicy::Controlled || join.request.key_ciphers().is_none() {
            return Err(LinkControlError::UnsupportedProfile);
        }
        let now = self.now();
        let state = self.state_mut();
        let result = state
            .client
            .associate_external(session, bss, join, now, &state.source);
        Self::reconcile(state);
        Ok(result?)
    }
    pub fn cancel_external_authentication(
        &mut self,
        session: &Session,
    ) -> Result<(), LinkControlError> {
        let state = self.state_mut();
        let result = state.client.cancel_external_authentication(session);
        Self::reconcile(state);
        Ok(result?)
    }
}

#[cfg(test)]
mod tests;
