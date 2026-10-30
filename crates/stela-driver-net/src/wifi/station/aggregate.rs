// SPDX-License-Identifier: GPL-2.0-only
//! Current-association validation before one complete parent's replay update.
use super::{Error, Phase, PortPolicy, Station};
use crate::Mac;
use crate::wifi::security::{
    KeyScope, KeySlot,
    aggregate::{self, OrderedGroup, ReceivedGroup},
};

impl Station {
    /// Validate an owned complete post-order parent. Open traffic
    /// obtains no invented key/PN; protected traffic advances its key's
    /// replay floor once, after checking every constituent. This never opens a
    /// controlled port, parses Ethernet subframes or authorizes their delivery.
    /// That separate data boundary must recheck current association/key/port.
    pub fn receive_ordered_group<'a, C>(
        &self,
        group: &'a OrderedGroup<C>,
        slot: Option<&mut KeySlot>,
    ) -> Result<ReceivedGroup<'a, C>, aggregate::Error> {
        if self.phase != Phase::Associated {
            return Err(Error::NotAssociated.into());
        }
        self.validate_association_context(group.context())?;
        let join = self.join.as_ref().ok_or(Error::NotAssociated)?;
        let channel = self.current_channel().ok_or(Error::NotAssociated)?;
        for frame in group.members() {
            let h = frame.header();
            if !h.data_present() || h.control & 0x0300 != 0x0200 {
                return Err(Error::Unsupported("nonstation FromDS aggregate").into());
            }
            if h.transmitter != Some(join.bssid)
                || (h.receiver != self.local && !h.receiver.is_multicast())
                || (h.receiver.is_multicast()
                    && Mac(frame.bytes()[16..22].try_into().unwrap()) == self.local)
            {
                return Err(Error::Unsupported("aggregate peer/receiver").into());
            }
            if (
                frame.radio.band,
                frame.radio.channel,
                frame.radio.frequency_mhz,
            ) != (channel.band, channel.number, channel.frequency_mhz)
            {
                return Err(Error::WrongChannel.into());
            }
        }
        let candidate = group.checked()?;
        match join.policy {
            PortPolicy::Open => {
                if slot.is_some() {
                    return Err(Error::WrongKey.into());
                }
                candidate.open()
            }
            PortPolicy::Controlled => {
                let slot = slot.ok_or(Error::WrongKey)?;
                let key = slot.installed().ok_or(Error::WrongKey)?;
                let (pairwise, group_cipher) = join.request.key_ciphers().ok_or(Error::WrongKey)?;
                for frame in group.members() {
                    let h = frame.header();
                    let expected = if h.receiver.is_multicast() {
                        KeyScope::Group(join.bssid)
                    } else {
                        KeyScope::Pairwise(join.bssid)
                    };
                    if key.scope() != expected
                        || key.cipher()
                            != if h.receiver.is_multicast() {
                                group_cipher
                            } else {
                                pairwise
                            }
                    {
                        return Err(Error::WrongKey.into());
                    }
                    if matches!(expected, KeyScope::Pairwise(_))
                        && key.index() != 0
                        && !key.cipher().is_wep()
                    {
                        return Err(Error::Unsupported("extended pairwise key ID").into());
                    }
                }
                candidate.protected(slot)
            }
        }
    }
}

#[cfg(test)]
mod tests;
