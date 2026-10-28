// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
//! The 6 GHz ROC20 reservation, qualified under both held providers before
//! its request publishes. The grant assigns the hardware band, as for
//! reserve_channel; the codec's later requests follow it.
use super::*;

impl<I: BarIo, Q: QueueIo, C: 'static> Client<I, Q, C> {
    pub(super) fn reserve_six_channel(
        s: &mut Owned<I, Q, C>,
        guard: &mut SixGhzAuthenticationGuard<'_>,
        now: u64,
    ) -> Result<(), Error> {
        Self::abort_channel(s)?;
        let token = s.roc_token.checked_add(1).ok_or(Error::NeedsDrain)?;
        let codec = s.six_ghz.as_ref().ok_or(Error::WrongPhase)?.codec();
        let request = codec.roc(token, 1000).map_err(Error::Codec)?;
        let abort = codec.abort_roc(token).map_err(Error::Codec)?;
        let profile = codec.profile();
        Self::qualify_six(s, guard, Use::ReserveChannel, now)?;
        Self::await_grant(s, profile, token, &request, &abort)?;
        let band = s.profile.ok_or(Error::WrongProfile)?.interface.band_index;
        s.six_ghz
            .as_mut()
            .ok_or(Error::WrongPhase)?
            .codec
            .set_band_index(band);
        Ok(())
    }
}
