// SPDX-License-Identifier: GPL-2.0-only
// RSN suite/MFP forms follow Linux include/linux/ieee80211.h and
// net/mac80211/mlme.c. See wifi/THIRD_PARTY.md for the pinned source.
//! Bounded explicit OS-selected PMF profile. This is parsed policy input,
//! never an authenticated handshake, installed key or publication permission.
use super::{Error, elements, take, word};
use alloc::vec::Vec;

const CCMP128: [u8; 4] = [0, 15, 172, 4];
const BIP_CMAC128: [u8; 4] = [0, 15, 172, 6];
const MFPR: u16 = 1 << 6;
const MFPC: u16 = 1 << 7;
const EXTENDED_KEY_ID: u16 = 1 << 13;

/// Original exact selected RSNE and bounded negotiated policy. Only parsing
/// the explicit opt-in constructor creates it. Actual OS authentication and
/// native hardware authority must be reacquired at every consuming effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Selection {
    rsn: Vec<u8>,
    akm: u8,
    required: bool,
}
impl Selection {
    pub fn rsn(&self) -> &[u8] {
        &self.rsn
    }
    pub const fn akm(&self) -> u8 {
        self.akm
    }
    pub const fn required(&self) -> bool {
        self.required
    }
    pub(super) fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let profile = Profile::parse(bytes)?;
        if profile.pairwise != [CCMP128] || profile.akms.len() != 1 {
            return Err(Error::Unsupported("PMF requires one selected cipher/AKM"));
        }
        let akm = profile.akms[0];
        if akm[..3] != [0, 15, 172] || !matches!(akm[3], 1 | 2) {
            return Err(Error::Unsupported("PMF ordinary RSN AKM1/2 only"));
        }
        Ok(Self {
            rsn: bytes.to_vec(),
            akm: akm[3],
            required: profile.capabilities & MFPR != 0,
        })
    }
    /// Bind to the actual retained BSS. A response may omit RSNE, as in Linux;
    /// any supplied RSNE must describe the same selected security profile.
    pub(in crate::net::wifi) fn validate_peer(
        &self,
        beacon: &[u8],
        response: &[u8],
    ) -> Result<(), Error> {
        let advertised = rsne(beacon)?.ok_or(Error::Invalid("AP PMF RSN absent"))?;
        let ap = Profile::parse(advertised)?;
        if !ap.pairwise.contains(&CCMP128) || !ap.akms.contains(&[0, 15, 172, self.akm]) {
            return Err(Error::Invalid("AP does not offer selected PMF suites"));
        }
        if let Some(bytes) = rsne(response)? {
            let selected = Self::parse(bytes)?;
            if selected.akm != self.akm || selected.required != self.required {
                return Err(Error::Invalid("response/request PMF mismatch"));
            }
        }
        Ok(())
    }
}

fn rsne(bytes: &[u8]) -> Result<Option<&[u8]>, Error> {
    let mut found = None;
    for (id, data) in elements(bytes)? {
        match id {
            48 => {
                if found.replace(data).is_some() {
                    return Err(Error::Invalid("duplicate PMF RSN"));
                }
            }
            244 => return Err(Error::Unsupported("PMF RSNX negotiation")),
            221 if data.starts_with(&[0, 0x50, 0xf2, 1]) => {
                return Err(Error::Unsupported("PMF WPA downgrade"));
            }
            _ => (),
        }
    }
    Ok(found)
}
struct Profile {
    pairwise: Vec<[u8; 4]>,
    akms: Vec<[u8; 4]>,
    capabilities: u16,
}
fn suites(bytes: &mut &[u8]) -> Result<Vec<[u8; 4]>, Error> {
    let count = usize::from(word(bytes)?);
    if count == 0 {
        return Err(Error::Invalid("empty PMF suite list"));
    }
    let bytes = take(bytes, count.checked_mul(4).ok_or(Error::Truncated)?)?;
    Ok(bytes
        .chunks_exact(4)
        .map(|v| v.try_into().unwrap())
        .collect())
}
impl Profile {
    fn parse(mut bytes: &[u8]) -> Result<Self, Error> {
        if word(&mut bytes)? != 1 || take(&mut bytes, 4)? != CCMP128 {
            return Err(Error::Unsupported("PMF RSN version/group cipher"));
        }
        let pairwise = suites(&mut bytes)?;
        let akms = suites(&mut bytes)?;
        let capabilities = word(&mut bytes)?;
        if capabilities & MFPC == 0 || capabilities & EXTENDED_KEY_ID != 0 {
            return Err(Error::Unsupported("PMF capability/extended key ID"));
        }
        if !bytes.is_empty() {
            let count = usize::from(word(&mut bytes)?);
            take(&mut bytes, count.checked_mul(16).ok_or(Error::Truncated)?)?;
        }
        // IEEE RSN default management-group suite is BIP-CMAC128 when omitted.
        if !bytes.is_empty() && take(&mut bytes, 4)? != BIP_CMAC128 {
            return Err(Error::Unsupported("PMF BIP-CMAC128 only"));
        }
        if !bytes.is_empty() {
            return Err(Error::Unsupported("trailing PMF RSN fields"));
        }
        Ok(Self {
            pairwise,
            akms,
            capabilities,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn selected() -> Vec<u8> {
        vec![
            1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 2, 0xc0, 0, 0, 0, 0, 15,
            172, 6,
        ]
    }
    fn ie(bytes: &[u8]) -> Vec<u8> {
        [vec![48, bytes.len() as u8], bytes.to_vec()].concat()
    }
    #[test]
    fn exact_pmf_selection_requires_ap_suites_and_preserves_original_rsn() {
        let bytes = selected();
        let selection = Selection::parse(&bytes).unwrap();
        assert_eq!(selection.rsn(), bytes);
        assert_eq!(selection.akm(), 2);
        assert!(selection.required());
        selection.validate_peer(&ie(&bytes), &[]).unwrap();
        selection.validate_peer(&ie(&bytes), &ie(&bytes)).unwrap();
        let mut changed = bytes.clone();
        for offset in [5, 11, 17, 18, 25] {
            changed[offset] = 0;
            assert!(selection.validate_peer(&ie(&changed), &[]).is_err());
            changed.clone_from(&bytes);
        }
        assert!(selection.validate_peer(&[], &[]).is_err());
        assert!(
            selection
                .validate_peer(&[ie(&bytes), ie(&bytes)].concat(), &[])
                .is_err()
        );
        changed[18] = 0x80;
        assert!(selection.validate_peer(&ie(&bytes), &ie(&changed)).is_err());
        let default = Selection::parse(&bytes[..20]).unwrap();
        default.validate_peer(&ie(&bytes[..20]), &[]).unwrap();
        assert!(Selection::parse(&[bytes, vec![0]].concat()).is_err());
    }
}
