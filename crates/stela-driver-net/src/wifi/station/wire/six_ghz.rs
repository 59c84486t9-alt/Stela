// SPDX-License-Identifier: GPL-2.0-only
// RSN/RSNX layouts follow pinned Linux IEEE headers; see wifi/THIRD_PARTY.md.
//! The OS's 6 GHz SAE selection: any RSN the PMF selection takes with an SAE
//! AKM, and any RSNX it carries, as mac80211 passes the supplicant's elements
//! through. Parsed bytes are policy inputs, never authenticated SAE, a key,
//! an associated peer or radio permission.
use super::{Error, elements, pmf};
use alloc::vec::Vec;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Selection {
    elements: Vec<u8>,
    rsn: Vec<u8>,
    rsnx: Vec<u8>,
}
impl Selection {
    /// The selected elements are the RSNE and an optional RSNXE alone; the
    /// OS's SAE engine owns the H2E and SAE-PK choices they encode.
    pub fn new(bytes: Vec<u8>) -> Result<Self, Error> {
        if bytes.len() > super::MAX_ELEMENTS {
            return Err(Error::Invalid("6GHz selected element bound"));
        }
        let (rsn, rsnx) = security(&bytes, true)?;
        if !pmf::Selection::parse(rsn)?.sae() {
            return Err(Error::Unsupported("6GHz SAE AKM"));
        }
        Ok(Self {
            rsn: rsn.to_vec(),
            rsnx: rsnx.unwrap_or_default().to_vec(),
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
    /// The AP must offer the selected suites, as the PMF selection checks.
    pub(in crate::wifi) fn validate_peer(&self, bytes: &[u8]) -> Result<(), Error> {
        security(bytes, false)?;
        pmf::Selection::parse(&self.rsn)?.validate_peer(bytes, &[])
    }
}
fn security(bytes: &[u8], selected: bool) -> Result<(&[u8], Option<&[u8]>), Error> {
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
    Ok((rsn.ok_or(Error::Invalid("6GHz RSNE absent"))?, rsnx))
}

#[cfg(test)]
pub(in crate::wifi) mod tests {
    use super::*;
    const H2E: u8 = 1 << 5;
    pub(in crate::wifi) fn selected() -> Vec<u8> {
        vec![
            48, 26, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 8, 0xc0, 0, 0, 0,
            0, 15, 172, 6, 244, 1, H2E,
        ]
    }
    #[test]
    fn sae_selection_keeps_bytes_and_requires_ap_offer() {
        let bytes = selected();
        let selection = Selection::new(bytes.clone()).unwrap();
        assert_eq!(selection.elements(), bytes);
        assert_eq!(selection.rsn(), &bytes[2..28]);
        assert_eq!(selection.rsnx(), &[H2E]);
        selection.validate_peer(&bytes).unwrap();
        // Group, pairwise and AKM suites, and the group management cipher.
        for at in [7, 13, 19, 27] {
            let mut bad = bytes.clone();
            bad[at] = 0;
            assert!(Selection::new(bad.clone()).is_err(), "selected {at}");
            assert!(selection.validate_peer(&bad).is_err(), "AP {at}");
        }
        assert!(selection.validate_peer(&[]).is_err());
        assert!(
            selection
                .validate_peer(&[bytes.clone(), bytes].concat())
                .is_err()
        );
    }
    #[test]
    fn any_mt7925_suite_with_an_sae_akm_selects_like_mac80211() {
        // GCMP-256 with SAE-EXT-KEY and BIP-GMAC-256, without an RSNXE.
        let mut gcmp = selected();
        gcmp.truncate(28);
        for at in [7, 13] {
            gcmp[at] = 9;
        }
        gcmp[19] = 24;
        gcmp[27] = 12;
        let selection = Selection::new(gcmp.clone()).unwrap();
        assert!(selection.rsnx().is_empty());
        selection.validate_peer(&gcmp).unwrap();
        // Any RSNX capability the OS sets, SAE-PK among them.
        let mut pk = selected();
        pk[30] |= 1 << 6;
        Selection::new(pk).unwrap();
        // Only an SAE AKM has an exchange to hold: PSK and FT-SAE do not.
        for akm in [2, 9] {
            let mut other = selected();
            other[19] = akm;
            assert!(Selection::new(other).is_err());
        }
    }
    #[test]
    fn all_truncations_duplicate_security_and_selected_extensions_refuse() {
        let bytes = selected();
        for end in 1..bytes.len() {
            if end == 28 {
                continue; // The RSNE alone.
            }
            assert!(Selection::new(bytes[..end].to_vec()).is_err(), "{end}");
        }
        for extra in [
            vec![48, 0],
            vec![244, 1, H2E],
            vec![244, 2, H2E, 0],
            vec![1, 1, 12],
        ] {
            assert!(Selection::new([bytes.clone(), extra].concat()).is_err());
        }
    }
}
