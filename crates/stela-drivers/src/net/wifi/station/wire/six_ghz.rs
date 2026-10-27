// SPDX-License-Identifier: GPL-2.0-only
// RSN/RSNX layouts follow pinned Linux IEEE headers; see wifi/THIRD_PARTY.md.
//! Explicit SAE8/H2E/required-PMF selection. Parsed bytes are policy inputs,
//! never authenticated SAE, a key, an associated peer or radio permission.
use super::{Error, elements, take, word};
use alloc::vec::Vec;

const CCMP: [u8; 4] = [0, 15, 172, 4];
const SAE: [u8; 4] = [0, 15, 172, 8];
const BIP: [u8; 4] = [0, 15, 172, 6];
const REQUIRED_PMF: u16 = 0xc0;
const H2E: u8 = 1 << 5;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Selection {
    elements: Vec<u8>,
    rsn: Vec<u8>,
    rsnx: Vec<u8>,
}
impl Selection {
    /// This finite profile selects only CCMP128/SAE8, required PMF and H2E.
    /// FT, PMKSA shortcuts, extended key IDs and other selected RSNX effects
    /// require a separately implemented authentication service/profile.
    pub fn new(bytes: Vec<u8>) -> Result<Self, Error> {
        if bytes.len() > super::MAX_ELEMENTS {
            return Err(Error::Invalid("6GHz selected element bound"));
        }
        let (rsn, rsnx) = security(&bytes, true)?;
        let profile = Profile::parse(rsn)?;
        if profile.pairwise != [CCMP]
            || profile.akms != [SAE]
            || profile.capabilities != REQUIRED_PMF
            || profile.pmkids != 0
            || rsnx != [H2E]
        {
            return Err(Error::Unsupported("6GHz SAE8/H2E/required-PMF profile"));
        }
        Ok(Self {
            rsn: rsn.to_vec(),
            rsnx: rsnx.to_vec(),
            elements: bytes,
        })
    }
    pub fn elements(&self) -> &[u8] {
        &self.elements
    }
    pub fn rsn(&self) -> &[u8] {
        &self.rsn
    }
    pub fn rsnx(&self) -> &[u8] {
        &self.rsnx
    }
    pub(in crate::net::wifi) fn validate_peer(&self, bytes: &[u8]) -> Result<(), Error> {
        let (rsn, rsnx) = security(bytes, false)?;
        let ap = Profile::parse(rsn)?;
        if !ap.pairwise.contains(&CCMP)
            || !ap.akms.contains(&SAE)
            || ap.capabilities & REQUIRED_PMF != REQUIRED_PMF
            || rsnx[0] & H2E == 0
        {
            return Err(Error::Invalid("AP does not offer selected 6GHz security"));
        }
        Ok(())
    }
}
fn security(bytes: &[u8], selected: bool) -> Result<(&[u8], &[u8]), Error> {
    let (mut rsn, mut rsnx) = (None, None);
    for (id, data) in elements(bytes)? {
        match id {
            48 => {
                if rsn.replace(data).is_some() {
                    return Err(Error::Invalid("duplicate 6GHz RSNE"));
                }
            }
            244 => {
                if data.is_empty() || usize::from(data[0] & 15) + 1 != data.len() {
                    return Err(Error::Invalid("RSNX encoded field length"));
                }
                if rsnx.replace(data).is_some() {
                    return Err(Error::Invalid("duplicate 6GHz RSNXE"));
                }
            }
            221 if data.starts_with(&[0, 0x50, 0xf2, 1]) => {
                return Err(Error::Unsupported("WPA downgrade"));
            }
            _ if selected => return Err(Error::Unsupported("selected 6GHz security elements")),
            _ => (),
        }
    }
    Ok((
        rsn.ok_or(Error::Invalid("6GHz RSNE absent"))?,
        rsnx.ok_or(Error::Invalid("6GHz RSNXE absent"))?,
    ))
}
struct Profile {
    pairwise: Vec<[u8; 4]>,
    akms: Vec<[u8; 4]>,
    capabilities: u16,
    pmkids: usize,
}
fn suites(bytes: &mut &[u8]) -> Result<Vec<[u8; 4]>, Error> {
    let count = usize::from(word(bytes)?);
    if count == 0 {
        return Err(Error::Invalid("empty 6GHz suite list"));
    }
    Ok(take(bytes, count.checked_mul(4).ok_or(Error::Truncated)?)?
        .as_chunks::<4>()
        .0
        .to_vec())
}
impl Profile {
    fn parse(mut bytes: &[u8]) -> Result<Self, Error> {
        if word(&mut bytes)? != 1 || take(&mut bytes, 4)? != CCMP {
            return Err(Error::Unsupported("6GHz RSN version/group cipher"));
        }
        let pairwise = suites(&mut bytes)?;
        let akms = suites(&mut bytes)?;
        let capabilities = word(&mut bytes)?;
        let pmkids = if bytes.is_empty() {
            0
        } else {
            let count = usize::from(word(&mut bytes)?);
            take(&mut bytes, count.checked_mul(16).ok_or(Error::Truncated)?)?;
            count
        };
        // Source-defined omitted management-group suite defaults to BIP-CMAC128.
        if !bytes.is_empty() && take(&mut bytes, 4)? != BIP {
            return Err(Error::Unsupported("6GHz BIP-CMAC128 only"));
        }
        if !bytes.is_empty() {
            return Err(Error::Unsupported("trailing 6GHz RSN fields"));
        }
        Ok(Self { pairwise, akms, capabilities, pmkids })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    pub(in crate::net::wifi) fn selected() -> Vec<u8> {
        vec![48, 26, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4,
            1, 0, 0, 15, 172, 8, 0xc0, 0, 0, 0, 0, 15, 172, 6, 244, 1, H2E]
    }
    #[test]
    fn exact_sae_h2e_selection_retains_bytes_and_requires_ap_offer() {
        let bytes = selected();
        let selection = Selection::new(bytes.clone()).unwrap();
        assert_eq!(selection.elements(), bytes);
        assert_eq!(selection.rsn(), &bytes[2..28]);
        assert_eq!(selection.rsnx(), &[H2E]);
        selection.validate_peer(&bytes).unwrap();
        for at in [7, 13, 19, 20, 21, 27, 30] {
            let mut bad = bytes.clone(); bad[at] = 0;
            assert!(Selection::new(bad.clone()).is_err(), "selected {at}");
            assert!(selection.validate_peer(&bad).is_err(), "AP {at}");
        }
        assert!(selection.validate_peer(&[]).is_err());
        assert!(selection.validate_peer(&[bytes.clone(), bytes].concat()).is_err());
    }
    #[test]
    fn all_truncations_duplicate_security_and_selected_extensions_refuse() {
        let bytes = selected();
        for end in 0..bytes.len() { assert!(Selection::new(bytes[..end].to_vec()).is_err()); }
        for extra in [vec![48, 0], vec![244, 1, H2E], vec![244, 2, H2E, 0], vec![1, 1, 12]] {
            assert!(Selection::new([bytes.clone(), extra].concat()).is_err());
        }
        let mut rsnx = bytes.clone(); rsnx[30] |= 1;
        assert!(Selection::new(rsnx).is_err());
        let mut ft = bytes.clone(); ft[19] = 9;
        assert!(Selection::new(ft).is_err());
        let mut extra = bytes.clone(); extra[30] |= 0x40;
        assert!(Selection::new(extra).is_err());
    }
}
