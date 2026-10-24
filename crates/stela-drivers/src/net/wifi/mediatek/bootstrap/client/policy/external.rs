// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
//! Owning-policy external authentication binds OS commands to actual scan BSS
//! handles and serializes source/OS regulatory guards through real submission.
use super::*;
use station::external::Session;

impl<I: BarIo, Q: QueueIo, C: 'static> ManagedClient<I, Q, C> {
    pub fn begin_external_authentication(
        &mut self,
        handle: BssHandle,
        profile: Profile,
        now: u64,
        budget: u64,
    ) -> Result<Arc<Session>, PolicyError> {
        self.live()?;
        let observed = self
            .observed
            .iter()
            .find(|b| b.handle == handle)
            .ok_or(PolicyError::Bss)?;
        if now
            .checked_sub(observed.seen)
            .is_none_or(|age| age > 30_000_000)
            || observed.bss.channel != profile.channel
            || observed.bss.bssid != profile.peer
            || observed.bss.transmitter != profile.peer
        {
            return Err(PolicyError::Bss);
        }
        let (supported, basic) =
            rates(&observed.bss.elements, profile.channel.band).map_err(PolicyError::Client)?;
        if profile.supported_rates & !supported != 0
            || profile.basic_rates & !basic != 0
            || profile.beacon_interval != observed.bss.beacon_interval
        {
            return Err(PolicyError::Bss);
        }
        let ssid = observed.bss.ssid.as_ref().ok_or(PolicyError::Bss)?.clone();
        let flags = self
            .snapshot
            .get(profile.channel)
            .ok_or(PolicyError::RestrictionMismatch)?
            .flags;
        if flags & (1 << 6) != 0
            && (profile.channel.band != Band::Ghz2 || profile.basic_rates & 15 == 0)
        {
            return Err(PolicyError::RestrictionMismatch);
        }
        let mut check = Check {
            snapshot: &self.snapshot,
            country: &self.country,
            environment: self.environment,
            revoked: false,
            peer: Some(profile.channel),
        };
        let result = self
            .client
            .begin_external_authentication(profile, ssid, now, budget, &mut check)
            .map_err(PolicyError::Client);
        if self.client.phase() != Phase::Idle {
            self.peer = Some(profile.channel);
        }
        result
    }

    #[allow(clippy::too_many_arguments)]
    pub fn transmit_external_authentication(
        &mut self,
        session: &Session,
        transaction: u16,
        status: u16,
        data: &[u8],
        now: u64,
        source: &dyn PageSource,
    ) -> Result<Receipt, PolicyError> {
        self.live()?;
        let mut check = Check {
            snapshot: &self.snapshot,
            country: &self.country,
            environment: self.environment,
            revoked: false,
            peer: self.peer,
        };
        self.client
            .transmit_external_authentication(
                session,
                transaction,
                status,
                data,
                now,
                source,
                &mut check,
            )
            .map_err(PolicyError::Client)
    }

    pub fn cancel_external_authentication(&mut self, session: &Session) -> Result<(), PolicyError> {
        self.client
            .cancel_external_authentication(session)
            .map_err(PolicyError::Client)
    }
}
