// SPDX-License-Identifier: GPL-2.0-only
// Layouts adapted from Linux include/linux/ieee80211.h and
// net/mac80211/{util.c,mlme.c}; source notices in THIRD_PARTY.md.
//! Single-link open-system/RSN wire forms. Legacy constructors refuse PMF;
//! the explicit modern PMF profile requires separate retained OS authority.

use super::{PortPolicy, phy};
use crate::net::{
    Mac,
    wifi::{Band, frame::Mpdu, security::Cipher},
};
use alloc::{sync::Arc, vec, vec::Vec};

const MAX_ELEMENTS: usize = 2300;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Truncated,
    Invalid(&'static str),
    Unsupported(&'static str),
    Integrity,
    WrongPeer,
}

#[derive(Clone, Debug)]
pub struct AssociationRequest {
    capabilities: u16,
    listen_interval: u16,
    elements: Vec<u8>,
    rsn: Option<(Cipher, Cipher)>,
    legacy_wpa: bool,
    modern: Option<Arc<ModernSelection>>,
    pmf: Option<pmf::Selection>,
}

/// Exact local association advertisement and explicit OS-selected PHY profile.
/// Vendor admission must bind it to the actual retained hardware capabilities.
#[derive(Clone, Debug)]
pub struct ModernSelection {
    pub(crate) capabilities: phy::Capabilities,
    pub(crate) mode: phy::Mode,
    pub(crate) width: phy::Width,
}
impl ModernSelection {
    pub fn capabilities(&self) -> &phy::Capabilities {
        &self.capabilities
    }
    pub fn mode(&self) -> phy::Mode {
        self.mode
    }
    pub fn width(&self) -> phy::Width {
        self.width
    }
}

fn cipher(bytes: &[u8]) -> Result<Cipher, Error> {
    if bytes.len() != 4 || bytes[..3] != [0, 15, 172] {
        return Err(Error::Unsupported("cipher OUI"));
    }
    match bytes[3] {
        2 => Ok(Cipher::Tkip),
        4 => Ok(Cipher::Ccmp128),
        8 => Ok(Cipher::Gcmp128),
        9 => Ok(Cipher::Gcmp256),
        10 => Ok(Cipher::Ccmp256),
        _ => Err(Error::Unsupported("cipher suite")),
    }
}

fn take<'a>(bytes: &mut &'a [u8], count: usize) -> Result<&'a [u8], Error> {
    let result = bytes.get(..count).ok_or(Error::Truncated)?;
    *bytes = &bytes[count..];
    Ok(result)
}

fn word(bytes: &mut &[u8]) -> Result<u16, Error> {
    Ok(u16::from_le_bytes(take(bytes, 2)?.try_into().unwrap()))
}

/// The local capabilities a request selects. A legacy association, as
/// mac80211's IEEE80211_CONN_MODE_LEGACY, advertises no HT, VHT, HE or EHT
/// element and runs at 20 MHz with the advertised rates and any WMM element;
/// any other mode advertises the device's capabilities unchanged.
fn legacy_or_matching(
    local: phy::Capabilities,
    observed: phy::Capabilities,
    mode: phy::Mode,
    width: phy::Width,
) -> Result<phy::Capabilities, Error> {
    if mode != phy::Mode::Legacy {
        return if local.matches_wire_capabilities(&observed) {
            Ok(local)
        } else {
            Err(Error::Invalid("local source/advertisement mismatch"))
        };
    }
    if width != phy::Width::Mhz20
        || observed.ht().is_some()
        || observed.vht().is_some()
        || observed.he().is_some()
        || observed.eht().is_some()
        || observed.he_6ghz().is_some()
    {
        return Err(Error::Invalid("legacy association advertisement"));
    }
    Ok(observed)
}

/// The WPA1 vendor element after its 00:50:F2:1 header, as wpa_supplicant
/// builds it: version 1, a group suite, one pairwise suite and one 802.1X or
/// PSK AKM, all under the WPA OUI.
fn wpa(mut bytes: &[u8]) -> Result<(Cipher, Cipher), Error> {
    let suite = |bytes: &mut &[u8]| -> Result<Cipher, Error> {
        let suite = take(bytes, 4)?;
        match suite {
            [0, 0x50, 0xf2, 2] => Ok(Cipher::Tkip),
            [0, 0x50, 0xf2, 4] => Ok(Cipher::Ccmp128),
            _ => Err(Error::Unsupported("WPA cipher suite")),
        }
    };
    if word(&mut bytes)? != 1 {
        return Err(Error::Unsupported("WPA version"));
    }
    let group = suite(&mut bytes)?;
    if word(&mut bytes)? != 1 {
        return Err(Error::Unsupported("multiple/empty WPA pairwise selection"));
    }
    let pairwise = suite(&mut bytes)?;
    if word(&mut bytes)? != 1 || !matches!(take(&mut bytes, 4)?, [0, 0x50, 0xf2, 1 | 2]) {
        return Err(Error::Unsupported("WPA AKM selection"));
    }
    // Optional capabilities carry no field mac80211 or mt7925 reads.
    if !bytes.is_empty() {
        word(&mut bytes)?;
    }
    if !bytes.is_empty() {
        return Err(Error::Unsupported("trailing WPA fields"));
    }
    Ok((pairwise, group))
}

fn rsn(mut bytes: &[u8]) -> Result<(Cipher, Cipher), Error> {
    if word(&mut bytes)? != 1 {
        return Err(Error::Unsupported("RSN version"));
    }
    let group = cipher(take(&mut bytes, 4)?)?;
    if word(&mut bytes)? != 1 {
        return Err(Error::Unsupported("multiple/empty pairwise selection"));
    }
    let pairwise = cipher(take(&mut bytes, 4)?)?;
    if word(&mut bytes)? != 1 {
        return Err(Error::Unsupported("multiple/empty AKM selection"));
    }
    let akm = take(&mut bytes, 4)?;
    if akm[..3] != [0, 15, 172] || !matches!(akm[3], 1 | 2) {
        return Err(Error::Unsupported("SAE/FT/other AKM authentication"));
    }
    if !bytes.is_empty() {
        let capabilities = word(&mut bytes)?;
        if capabilities & 0x00c0 != 0 {
            return Err(Error::Unsupported("protected management frames"));
        }
        if capabilities & 0x2000 != 0 {
            return Err(Error::Unsupported("extended pairwise key ID"));
        }
    }
    if !bytes.is_empty() {
        let count = usize::from(word(&mut bytes)?);
        take(&mut bytes, count.checked_mul(16).ok_or(Error::Truncated)?)?;
    }
    if !bytes.is_empty() {
        return Err(Error::Unsupported("management cipher/trailing RSN fields"));
    }
    Ok((pairwise, group))
}

pub(super) mod action;
pub mod pmf;
pub mod six_ghz;

fn elements(bytes: &[u8]) -> Result<Vec<(u8, &[u8])>, Error> {
    let mut rest = bytes;
    let mut result = Vec::new();
    while !rest.is_empty() {
        let id = take(&mut rest, 1)?[0];
        let count = usize::from(take(&mut rest, 1)?[0]);
        result.push((id, take(&mut rest, count)?));
    }
    Ok(result)
}

impl AssociationRequest {
    /// Complete frontend-selected IEs, preserved in order and byte-for-byte.
    /// The first native profile is pre-HT single-link 2.4/5GHz with open-system
    /// authentication; advanced capabilities must be negotiated by later code.
    pub fn new(capabilities: u16, listen_interval: u16, bytes: Vec<u8>) -> Result<Self, Error> {
        Self::parse(capabilities, listen_interval, bytes, false)
    }

    /// Explicit modern advertisement, not authorization to use these modes.
    /// The current station modern entry still refuses 6GHz until SAE/PMF and
    /// the genuine OS authentication boundary are implemented.
    pub fn new_modern(
        capabilities: u16,
        listen_interval: u16,
        bytes: Vec<u8>,
        band: Band,
        mode: phy::Mode,
        width: phy::Width,
    ) -> Result<Self, Error> {
        let local = phy::Capabilities::parse(band, phy::Role::Station, &bytes).map_err(
            |error| match error {
                phy::Error::Unsupported(effect) => Error::Unsupported(effect),
                _ => Error::Invalid("local modern capabilities"),
            },
        )?;
        Self::new_modern_with_local(capabilities, listen_interval, bytes, local, mode, width)
    }

    /// Preserve complete local source-capability observations alongside the
    /// exact transmitted advertisement. Actual native-owner binding remains
    /// mandatory; caller-provided source words are not hardware proof.
    pub fn new_modern_with_local(
        capabilities: u16,
        listen_interval: u16,
        bytes: Vec<u8>,
        local: phy::Capabilities,
        mode: phy::Mode,
        width: phy::Width,
    ) -> Result<Self, Error> {
        if local.role() != phy::Role::Station {
            return Err(Error::Invalid("modern local mode/role"));
        }
        let observed = phy::Capabilities::parse(local.band(), phy::Role::Station, &bytes).map_err(
            |error| match error {
                phy::Error::Unsupported(effect) => Error::Unsupported(effect),
                _ => Error::Invalid("local modern capabilities"),
            },
        )?;
        let local = legacy_or_matching(local, observed, mode, width)?;
        let mut request = Self::parse(capabilities, listen_interval, bytes, true)?;
        request.validate_mode(mode)?;
        request.modern = Some(Arc::new(ModernSelection {
            capabilities: local,
            mode,
            width,
        }));
        Ok(request)
    }

    /// Explicit single-link CCMP128/BIP-CMAC128 advertisement selected by the
    /// real OS. Parsing is not authentication or permission to configure native
    /// resources: both current providers must separately qualify this selection.
    pub fn new_modern_with_local_pmf(
        capabilities: u16,
        listen_interval: u16,
        bytes: Vec<u8>,
        local: phy::Capabilities,
        mode: phy::Mode,
        width: phy::Width,
    ) -> Result<Self, Error> {
        if local.role() != phy::Role::Station {
            return Err(Error::Invalid("modern local mode/role"));
        }
        let observed = phy::Capabilities::parse(local.band(), phy::Role::Station, &bytes)
            .map_err(|_| Error::Invalid("local modern capabilities"))?;
        let local = legacy_or_matching(local, observed, mode, width)
            .map_err(|_| Error::Invalid("PMF local source"))?;
        let mut request = Self::parse_inner(capabilities, listen_interval, bytes, true, true)?;
        request.validate_mode(mode)?;
        if request.pmf.is_none() || capabilities & 0x10 == 0 || request.legacy_wpa {
            return Err(Error::Invalid("PMF requires selected RSN"));
        }
        request.modern = Some(Arc::new(ModernSelection {
            capabilities: local,
            mode,
            width,
        }));
        Ok(request)
    }

    /// `ieee80211_determine_our_sta_mode`: a TKIP pairwise cipher limits the
    /// association to legacy mode.
    fn validate_mode(&self, mode: phy::Mode) -> Result<(), Error> {
        if mode != phy::Mode::Legacy
            && self
                .rsn
                .is_some_and(|(pairwise, _)| pairwise == Cipher::Tkip)
        {
            return Err(Error::Unsupported("TKIP pairwise outside legacy mode"));
        }
        Ok(())
    }

    pub fn pmf(&self) -> Option<&pmf::Selection> {
        self.pmf.as_ref()
    }

    pub fn modern(&self) -> Option<&ModernSelection> {
        self.modern.as_deref()
    }

    fn parse(
        capabilities: u16,
        listen_interval: u16,
        bytes: Vec<u8>,
        modern: bool,
    ) -> Result<Self, Error> {
        Self::parse_inner(capabilities, listen_interval, bytes, modern, false)
    }

    fn parse_inner(
        capabilities: u16,
        listen_interval: u16,
        bytes: Vec<u8>,
        modern: bool,
        allow_pmf: bool,
    ) -> Result<Self, Error> {
        if bytes.len() > MAX_ELEMENTS {
            return Err(Error::Invalid("association elements too long"));
        }
        if capabilities & 2 != 0 {
            return Err(Error::Unsupported("IBSS"));
        }
        let mut ssid = false;
        let mut rates = false;
        let mut extended_rates = false;
        let mut selected_rsn = None;
        let mut selected_pmf = None;
        let mut legacy_wpa = false;
        for (id, data) in elements(&bytes)? {
            match id {
                0 => {
                    if ssid || data.len() > 32 {
                        return Err(Error::Invalid("SSID"));
                    }
                    ssid = true;
                }
                1 => {
                    if rates || data.is_empty() || data.len() > 8 {
                        return Err(Error::Invalid("supported rates"));
                    }
                    rates = true;
                }
                50 => {
                    if extended_rates || data.is_empty() {
                        return Err(Error::Invalid("extended rates"));
                    }
                    extended_rates = true;
                }
                48 => {
                    if selected_rsn.is_some() {
                        return Err(Error::Invalid("duplicate RSN/WPA"));
                    }
                    if allow_pmf {
                        let selection = pmf::Selection::parse(data)?;
                        selected_rsn = Some((selection.pairwise(), selection.group()));
                        selected_pmf = Some(selection);
                    } else {
                        selected_rsn = Some(rsn(data)?);
                    }
                }
                221 if data.starts_with(&[0, 0x50, 0xf2, 1]) => {
                    if selected_rsn.is_some() {
                        return Err(Error::Invalid("duplicate RSN/WPA"));
                    }
                    selected_rsn = Some(wpa(&data[4..])?);
                    legacy_wpa = true;
                }
                // Do not advertise modes the current native state machine and
                // actual driver association context cannot configure yet.
                61 | 192 => {
                    return Err(Error::Unsupported("AP operation in station request"));
                }
                45 | 191 if !modern => {
                    return Err(Error::Unsupported("HT/VHT association context"));
                }
                255 if data.first().is_some_and(|id| {
                    matches!(id, 36 | 106 | 107) || (!modern && matches!(id, 35 | 108))
                }) =>
                {
                    return Err(Error::Unsupported("HE/EHT/MLO association context"));
                }
                _ => (),
            }
        }
        if !ssid || (!rates && !modern) {
            return Err(Error::Invalid("missing SSID/rates"));
        }
        Ok(Self {
            capabilities,
            listen_interval,
            elements: bytes,
            rsn: selected_rsn,
            legacy_wpa,
            modern: None,
            pmf: selected_pmf,
        })
    }

    pub fn validate_policy(&self, policy: PortPolicy) -> Result<(), Error> {
        match policy {
            PortPolicy::Open
                if self.capabilities & 0x10 == 0 && self.rsn.is_none() && !self.legacy_wpa =>
            {
                Ok(())
            }
            PortPolicy::Controlled if self.capabilities & 0x10 != 0 && self.rsn.is_some() => Ok(()),
            _ => Err(Error::Invalid("security policy/association mismatch")),
        }
    }

    pub const fn key_ciphers(&self) -> Option<(Cipher, Cipher)> {
        self.rsn
    }

    pub const fn capabilities(&self) -> u16 {
        self.capabilities
    }
    pub const fn listen_interval(&self) -> u16 {
        self.listen_interval
    }
    pub fn elements(&self) -> &[u8] {
        &self.elements
    }

    pub fn encode(&self, local: Mac, bssid: Mac, sequence: u16) -> Result<Vec<u8>, Error> {
        let mut frame = header(0, local, bssid, sequence)?;
        frame.extend_from_slice(&self.capabilities.to_le_bytes());
        frame.extend_from_slice(&self.listen_interval.to_le_bytes());
        frame.extend_from_slice(&self.elements);
        Ok(frame)
    }
}

fn header(control: u16, local: Mac, bssid: Mac, sequence: u16) -> Result<Vec<u8>, Error> {
    if sequence > 0xfff {
        return Err(Error::Invalid("sequence number"));
    }
    let mut frame = vec![0; 24];
    frame[..2].copy_from_slice(&control.to_le_bytes());
    frame[4..10].copy_from_slice(&bssid.0);
    frame[10..16].copy_from_slice(&local.0);
    frame[16..22].copy_from_slice(&bssid.0);
    frame[22..24].copy_from_slice(&(sequence << 4).to_le_bytes());
    Ok(frame)
}

pub fn authentication(local: Mac, bssid: Mac, sequence: u16) -> Result<Vec<u8>, Error> {
    let mut frame = header(0x00b0, local, bssid, sequence)?;
    frame.extend_from_slice(&[0, 0, 1, 0, 0, 0]);
    Ok(frame)
}

pub fn check_peer(frame: &Mpdu, local: Mac, bssid: Mac) -> Result<(), Error> {
    let header = frame.header();
    if header.control & 0x800c != 0 || header.length != 24 {
        return Err(Error::Unsupported("nonordinary management frame"));
    }
    if header.protected() {
        return Err(Error::Unsupported("protected management frame"));
    }
    if header.fragmented() {
        return Err(Error::Unsupported("fragmented management frame"));
    }
    // Non-PMF AP departure frames may address all associated stations. Auth
    // and association responses remain addressed to this station alone.
    let broadcast_departure =
        header.receiver == Mac::BROADCAST && matches!(header.control & 0x00fc, 0x00a0 | 0x00c0);
    if (header.receiver != local && !broadcast_departure)
        || header.transmitter != Some(bssid)
        || frame.bytes()[16..22] != bssid.0
    {
        return Err(Error::WrongPeer);
    }
    Ok(())
}

pub fn authentication_response(frame: &Mpdu) -> Result<u16, Error> {
    if frame.header().control & 0x00fc != 0x00b0 {
        return Err(Error::Invalid("authentication subtype"));
    }
    let mut body = frame.bytes().get(24..).ok_or(Error::Truncated)?;
    if word(&mut body)? != 0 || word(&mut body)? != 2 {
        return Err(Error::Invalid("authentication transaction/algorithm"));
    }
    word(&mut body)
}

#[derive(Clone, Debug)]
pub struct AssociationResponse {
    pub capabilities: u16,
    pub status: u16,
    pub raw_aid: u16,
    pub aid: u16,
    pub power_save_allowed: bool,
    pub elements: Vec<u8>,
}

pub fn association_response(frame: &Mpdu) -> Result<AssociationResponse, Error> {
    if frame.header().control & 0x00fc != 0x0010 {
        return Err(Error::Invalid("association subtype"));
    }
    let mut body = frame.bytes().get(24..).ok_or(Error::Truncated)?;
    let capabilities = word(&mut body)?;
    let status = word(&mut body)?;
    let raw_aid = word(&mut body)?;
    let aid = raw_aid & 0x7ff;
    let power_save_allowed = (1..=2007).contains(&aid);
    let parsed = elements(body)?;
    if status == 0
        && !parsed
            .iter()
            .any(|(id, bytes)| *id == 1 && !bytes.is_empty() && bytes.len() <= 8)
    {
        return Err(Error::Invalid("missing response rates"));
    }
    Ok(AssociationResponse {
        capabilities,
        status,
        raw_aid,
        aid: if power_save_allowed { aid } else { 0 },
        power_save_allowed,
        elements: body.to_vec(),
    })
}

pub fn departure(frame: &Mpdu) -> Result<u16, Error> {
    if !matches!(frame.header().control & 0x00fc, 0x00a0 | 0x00c0) {
        return Err(Error::Invalid("departure subtype"));
    }
    let mut body = frame.bytes().get(24..).ok_or(Error::Truncated)?;
    word(&mut body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn basic() -> Vec<u8> {
        vec![0, 3, 0, b'x', 0xff, 1, 3, 0x8c, 0x98, 0xb0]
    }
    fn selected_rsn() -> Vec<u8> {
        vec![
            1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 2,
        ]
    }
    fn request(rsn_bytes: &[u8]) -> Result<AssociationRequest, Error> {
        let mut bytes = basic();
        bytes.extend_from_slice(&[48, rsn_bytes.len() as u8]);
        bytes.extend_from_slice(rsn_bytes);
        AssociationRequest::new(0x11, 10, bytes)
    }

    #[test]
    fn authentication_matches_original_wire_layout() {
        let local = Mac([2, 1, 2, 3, 4, 5]);
        let ap = Mac([2, 6, 7, 8, 9, 10]);
        let bytes = authentication(local, ap, 0xabc).unwrap();
        assert_eq!(
            bytes,
            &[
                0xb0, 0, 0, 0, 2, 6, 7, 8, 9, 10, 2, 1, 2, 3, 4, 5, 2, 6, 7, 8, 9, 10, 0xc0, 0xab,
                0, 0, 1, 0, 0, 0
            ]
        );
        assert_eq!(
            authentication(local, ap, 0x1000),
            Err(Error::Invalid("sequence number"))
        );
    }

    #[test]
    fn unchanged_linux_auth_builder_matches_all_fixture_addresses() {
        use sha2::{Digest, Sha256};
        // tests/reference/wifi_auth_oracle.py executes the complete unchanged
        // Linux builder with capture-only skb/TX scaffolding under ASan/UBSan.
        let mut digest = Sha256::new();
        for i in 0_u16..1024 {
            let local = Mac([
                2,
                i as u8,
                (i >> 8) as u8,
                i.wrapping_mul(3) as u8,
                (i >> 2) as u8,
                i.wrapping_mul(7) as u8,
            ]);
            let ap = Mac([
                4,
                (i >> 3) as u8,
                (i >> 1) as u8,
                i.wrapping_mul(11) as u8,
                i.wrapping_mul(13) as u8,
                i.wrapping_mul(17) as u8,
            ]);
            digest.update(authentication(local, ap, 0).unwrap());
        }
        assert_eq!(
            digest.finalize().as_slice(),
            &[
                0xee, 0x63, 0x00, 0xd4, 0x3b, 0xe3, 0x3c, 0xde, 0x19, 0xdf, 0x18, 0x84, 0x29, 0xf5,
                0x4a, 0x76, 0xb5, 0xc7, 0x4b, 0x77, 0xf2, 0xc9, 0x50, 0x7d, 0x2f, 0x1d, 0x1d, 0x19,
                0x22, 0xf0, 0xcc, 0x89
            ]
        );
    }

    #[test]
    fn association_preserves_complete_binary_elements_and_capabilities() {
        let mut elements = basic();
        elements.extend_from_slice(&[222, 3, 1, 2, 3]);
        let request = AssociationRequest::new(1, 10, elements.clone()).unwrap();
        request.validate_policy(PortPolicy::Open).unwrap();
        let frame = request.encode(Mac([2; 6]), Mac([4; 6]), 12).unwrap();
        assert_eq!(&frame[24..28], &[1, 0, 10, 0]);
        assert_eq!(&frame[28..], elements);
    }

    #[test]
    fn rsn_selection_is_exact_and_cannot_downgrade_to_open() {
        let request = request(&selected_rsn()).unwrap();
        assert_eq!(
            request.key_ciphers(),
            Some((Cipher::Ccmp128, Cipher::Ccmp128))
        );
        request.validate_policy(PortPolicy::Controlled).unwrap();
        assert!(request.validate_policy(PortPolicy::Open).is_err());
        let no_rsn = AssociationRequest::new(0x11, 10, basic()).unwrap();
        assert!(no_rsn.validate_policy(PortPolicy::Controlled).is_err());
        assert!(no_rsn.validate_policy(PortPolicy::Open).is_err());
        let mut legacy = basic();
        legacy.extend_from_slice(&[221, 4, 0, 0x50, 0xf2, 1]);
        assert!(AssociationRequest::new(1, 10, legacy).is_err());
    }

    #[test]
    fn wpa1_and_tkip_select_like_wpa_supplicant_and_limit_to_legacy_mode() {
        let wpa = [
            221, 22, 0, 0x50, 0xf2, 1, 1, 0, 0, 0x50, 0xf2, 2, 1, 0, 0, 0x50, 0xf2, 2, 1, 0, 0,
            0x50, 0xf2, 2,
        ];
        let mut bytes = basic();
        bytes.extend_from_slice(&wpa);
        let selected = AssociationRequest::new(0x11, 10, bytes.clone()).unwrap();
        assert_eq!(selected.key_ciphers(), Some((Cipher::Tkip, Cipher::Tkip)));
        selected.validate_policy(PortPolicy::Controlled).unwrap();
        assert!(selected.validate_policy(PortPolicy::Open).is_err());
        assert!(
            AssociationRequest::new(0x01, 10, bytes.clone())
                .unwrap()
                .validate_policy(PortPolicy::Open)
                .is_err()
        );
        // Only one of RSN and WPA; every WPA field is checked.
        let mut both = bytes.clone();
        both.extend_from_slice(&[48, 18]);
        both.extend_from_slice(&selected_rsn());
        assert!(AssociationRequest::new(0x11, 10, both).is_err());
        for (at, value) in [(6, 2), (11, 9), (17, 9), (23, 3)] {
            let mut bad = bytes.clone();
            bad[basic().len() + at] = value;
            assert!(AssociationRequest::new(0x11, 10, bad).is_err(), "{at}");
        }
        // A mixed RSN network: CCMP pairwise under a TKIP group.
        let mut mixed = selected_rsn();
        mixed[5] = 2;
        assert_eq!(
            request(&mixed).unwrap().key_ciphers(),
            Some((Cipher::Ccmp128, Cipher::Tkip))
        );
        let mut tkip = selected_rsn();
        tkip[11] = 2;
        let local = phy::Capabilities::parse(Band::Ghz5, phy::Role::Station, &basic()).unwrap();
        let mut elements = basic();
        elements.extend_from_slice(&[48, 18]);
        elements.extend_from_slice(&tkip);
        for (mode, ok) in [(phy::Mode::Legacy, true), (phy::Mode::Ht, false)] {
            let modern = AssociationRequest::new_modern_with_local(
                0x11,
                10,
                elements.clone(),
                local.clone(),
                mode,
                phy::Width::Mhz20,
            );
            assert_eq!(modern.is_ok(), ok, "{mode:?}");
        }
    }

    #[test]
    fn truncated_rsn_counts_and_elements_are_never_read_past_the_packet() {
        let rsn = selected_rsn();
        for length in 0..rsn.len() {
            assert!(request(&rsn[..length]).is_err(), "{length}");
        }
        for tail in [vec![222], vec![222, 2, 1], vec![0, 33], vec![48, 255, 1]] {
            let mut bytes = basic();
            bytes.extend_from_slice(&tail);
            assert!(AssociationRequest::new(1, 10, bytes).is_err());
        }
        let mut count = rsn;
        count[6..8].copy_from_slice(&0xffff_u16.to_le_bytes());
        assert!(request(&count).is_err());
    }

    #[test]
    fn pmf_sae_and_advanced_radio_modes_are_explicitly_unsupported() {
        let mut sae = selected_rsn();
        sae[17] = 8;
        assert!(matches!(request(&sae), Err(Error::Unsupported(_))));
        let mut pmf = selected_rsn();
        pmf.extend_from_slice(&[0x80, 0]);
        assert!(matches!(request(&pmf), Err(Error::Unsupported(_))));
        for extra in [
            vec![45, 1, 0],
            vec![191, 1, 0],
            vec![255, 1, 35],
            vec![255, 1, 107],
        ] {
            let mut bytes = basic();
            bytes.extend_from_slice(&extra);
            assert!(matches!(
                AssociationRequest::new(1, 10, bytes),
                Err(Error::Unsupported(_))
            ));
        }
    }

    #[test]
    fn duplicate_security_and_identity_elements_are_rejected() {
        for extra in [
            vec![0, 1, b'y'],
            vec![1, 1, 0x8c],
            vec![50, 1, 0x0c, 50, 1, 0x18],
        ] {
            let mut bytes = basic();
            bytes.extend_from_slice(&extra);
            assert!(matches!(
                AssociationRequest::new(1, 10, bytes),
                Err(Error::Invalid(_))
            ));
        }
        let mut bytes = basic();
        for _ in 0..2 {
            let data = selected_rsn();
            bytes.extend_from_slice(&[48, 18]);
            bytes.extend_from_slice(&data);
        }
        assert!(matches!(
            AssociationRequest::new(0x11, 10, bytes),
            Err(Error::Invalid("duplicate RSN/WPA"))
        ));
    }
}
