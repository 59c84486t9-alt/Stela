use super::{
    AccessCategory, Band, Capabilities, Eht, Error, He, Ht, LegacyRates, McsMaps, Mode, Role, Vht,
    Width,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NegotiatedHt {
    pub capability: u16,
    /// Peer RX bounded by local TX; matches Linux's link_sta HT RX mask.
    pub peer_rx_mcs: [u8; 10],
    pub local_rx_mcs: [u8; 10],
    /// HT base AF bits; not a complete HE/EHT aggregate byte exponent.
    pub peer_ampdu_base_exponent: u8,
    pub peer_mpdu_spacing: u8,
    pub peer_tx_params: u8,
}

fn ht_rx(local: &Ht, peer: &Ht) -> [u8; 10] {
    let mut result = [0; 10];
    if local.tx_params & 1 == 0 {
        return result;
    }
    let streams = if local.tx_params & 2 != 0 {
        usize::from((local.tx_params >> 2) & 3) + 1
    } else {
        4
    };
    for (i, out) in result.iter_mut().enumerate().take(streams) {
        *out = local.rx_mcs[i] & peer.rx_mcs[i];
    }
    if local.tx_params & 0x10 != 0 {
        for (i, out) in result.iter_mut().enumerate().skip(4) {
            *out = local.rx_mcs[i] & peer.rx_mcs[i];
        }
    }
    result[4] |= local.rx_mcs[4] & peer.rx_mcs[4] & 1;
    result
}

impl NegotiatedHt {
    fn between(local: &Ht, peer: &Ht) -> Self {
        let symmetric = 0x0001 | 0x0002 | 0x0010 | 0x0020 | 0x0040 | 0x1000;
        let mut capability = peer.capability & (local.capability | !symmetric);
        if local.capability & 0x80 == 0 {
            capability &= !0x300;
        }
        if local.capability & 0x300 == 0 {
            capability &= !0x80;
        }
        Self {
            capability,
            peer_rx_mcs: ht_rx(local, peer),
            local_rx_mcs: ht_rx(peer, local),
            peer_ampdu_base_exponent: peer.ampdu_exponent,
            peer_mpdu_spacing: peer.mpdu_spacing,
            peer_tx_params: peer.tx_params,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NegotiatedVht {
    pub capability: u32,
    pub mcs: McsMaps,
    pub peer_rx_highest: u16,
    pub peer_tx_highest: u16,
}
impl NegotiatedVht {
    fn between(local: &Vht, peer: &Vht) -> Result<Self, Error> {
        if (local.capability | peer.capability) & 0xc000_0000 != 0 {
            return Err(Error::Unsupported("VHT extended NSS bandwidth"));
        }
        let own = local.capability;
        let raw = peer.capability;
        let mut capability = raw
            & (0x10
                | 0x0020_0000
                | 0x0040_0000
                | 0x0380_0000
                | 0x0c00_0000
                | 0x1000_0000
                | 0x2000_0000);
        capability |= (raw & 3).min(own & 3);
        capability |= match own & 0xc {
            4 => raw & 4,
            8 => raw & 0xc,
            _ => 0,
        };
        capability |= raw & own & 0x60;
        if own & 0x1000 != 0 {
            capability |= raw & (0x800 | 0x70000);
        }
        if own & 0x800 != 0 {
            capability |= raw & (0x1000 | 0xe000);
        }
        if own & 0x80000 != 0 {
            capability |= raw & 0x100000;
        }
        if own & 0x100000 != 0 {
            capability |= raw & 0x80000;
        }
        if own & 0x80 != 0 {
            capability |= raw & 0x700;
        }
        if own & 0x700 != 0 {
            capability |= raw & 0x80;
        }
        Ok(Self {
            capability,
            mcs: McsMaps::intersect(local.mcs, peer.mcs),
            peer_rx_highest: peer.rx_highest,
            peer_tx_highest: peer.tx_highest & !0x2000,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NegotiatedHe {
    pub mac: [u8; 6],
    pub phy: [u8; 11],
    pub mcs_80: McsMaps,
    pub mcs_160: Option<McsMaps>,
    pub mcs_80p80: Option<McsMaps>,
}
impl NegotiatedHe {
    fn between(local: &He, peer: &He) -> Self {
        let mut phy = peer.phy;
        let mcs_160 = local
            .mcs_160
            .zip(peer.mcs_160)
            .map(|(a, b)| McsMaps::intersect(a, b));
        let mcs_80p80 = local
            .mcs_80p80
            .zip(peer.mcs_80p80)
            .map(|(a, b)| McsMaps::intersect(a, b));
        if mcs_160.is_none() {
            phy[0] &= !8;
        }
        if mcs_80p80.is_none() {
            phy[0] &= !16;
        }
        Self {
            mac: peer.mac,
            phy,
            mcs_80: McsMaps::intersect(local.mcs_80, peer.mcs_80),
            mcs_160,
            mcs_80p80,
        }
    }
}

/// Four actual MCS ranges:0..7,8..9,10..11,12..13. Each octet retains
/// peer RX/local TX in low nibble and peer TX/local RX in high nibble.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NegotiatedEht {
    pub ranges: [u8; 4],
}

fn eht_ranges(cap: &Eht, width: Width) -> Option<[u8; 4]> {
    let map = match width {
        Width::Mhz20 => {
            if let Some(map) = cap.mcs.only_20 {
                return Some(map);
            }
            cap.mcs.bw80?
        }
        Width::Mhz40 | Width::Mhz80 => cap.mcs.bw80?,
        Width::Mhz160 => cap.mcs.bw160?,
        Width::Mhz320 => cap.mcs.bw320?,
        Width::Mhz80P80 => return None,
    };
    Some([map[0], map[0], map[1], map[2]])
}
impl NegotiatedEht {
    fn between(local: &Eht, peer: &Eht, width: Width) -> Result<Self, Error> {
        let own = eht_ranges(local, width).ok_or(Error::Incompatible("local EHT width maps"))?;
        let peer = eht_ranges(peer, width).ok_or(Error::Incompatible("peer EHT width maps"))?;
        let ranges = core::array::from_fn(|i| {
            let rx = (own[i] >> 4).min(peer[i] & 15);
            let tx = (own[i] & 15).min(peer[i] >> 4);
            rx | tx << 4
        });
        Ok(Self { ranges })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NegotiatedWmm {
    pub access_categories: [AccessCategory; 4],
    pub parameter_set_count: u8,
    pub uapsd_queues: u8,
    /// Wire value0=all,1=2,2=4,3=6 service-period frames.
    pub max_service_period: u8,
}

/// Explicit selected family/width with exact local/peer observations retained.
/// This does not choose a country/channel/center frequency, authenticate a peer,
/// install keys or make a vendor's unsupported advanced mode operational.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Negotiated {
    local: Capabilities,
    peer: Capabilities,
    pub mode: Mode,
    pub width: Width,
    pub legacy: LegacyRates,
    pub ht: Option<NegotiatedHt>,
    pub vht: Option<NegotiatedVht>,
    pub he: Option<NegotiatedHe>,
    pub eht: Option<NegotiatedEht>,
    pub wmm: Option<NegotiatedWmm>,
    /// Direction from the local station's point of view, no default on empty maps.
    pub rx_nss: u8,
    pub tx_nss: u8,
    /// Source STA_PHY AF encoding from HT/VHT/HE6. This is only the base:
    /// actual HE MAC3/EHT MAC1 extension effects must also be consumed from
    /// retained peer capabilities by their firmware TLVs/aggregate executor.
    pub peer_ampdu_base_exponent: u8,
    pub peer_mpdu_spacing: u8,
    pub max_tx_amsdu: u16,
    pub max_rx_amsdu: u16,
}

fn ht_nss(map: &[u8; 10], width: Width) -> u8 {
    (0..4)
        .rev()
        .find(|&i| map[i] != 0)
        .map_or(u8::from(width == Width::Mhz40 && map[4] & 1 != 0), |i| {
            i as u8 + 1
        })
}
fn width_supported(cap: &Capabilities, mode: Mode, width: Width) -> bool {
    match mode {
        Mode::Legacy => width == Width::Mhz20,
        Mode::Ht => cap.ht.as_ref().is_some_and(|h| match width {
            Width::Mhz20 => true,
            Width::Mhz40 => h.capability & 2 != 0,
            _ => false,
        }),
        Mode::Vht => {
            cap.band == Band::Ghz5
                && cap.vht.as_ref().is_some_and(|v| match width {
                    Width::Mhz20 | Width::Mhz40 | Width::Mhz80 => true,
                    Width::Mhz160 => v.capability & 0xc != 0,
                    Width::Mhz80P80 => v.capability & 0xc == 8,
                    _ => false,
                })
        }
        Mode::He | Mode::Eht => cap.he.as_ref().is_some_and(|h| match width {
            Width::Mhz20 => true,
            Width::Mhz40 if cap.band == Band::Ghz2 => h.phy[0] & 2 != 0,
            Width::Mhz40 | Width::Mhz80 if cap.band != Band::Ghz2 => h.phy[0] & 4 != 0,
            Width::Mhz160 if cap.band != Band::Ghz2 => h.phy[0] & 8 != 0,
            Width::Mhz80P80 if mode == Mode::He && cap.band != Band::Ghz2 => h.phy[0] & 16 != 0,
            Width::Mhz320 if mode == Mode::Eht && cap.band == Band::Ghz6 => {
                cap.eht.as_ref().is_some_and(|e| e.phy[0] & 2 != 0)
            }
            _ => false,
        }),
    }
}

fn aggregate_limits(cap: &Capabilities, mode: Mode) -> (u8, u8, u16) {
    if mode == Mode::Legacy {
        return (0, 0, 0);
    }
    if let Some(he6) = cap.he_6ghz {
        let amsdu = match (he6 >> 6) & 3 {
            1 => 7991,
            2 => 11454,
            _ => 3895,
        };
        return (((he6 >> 3) & 7) as u8, (he6 & 7) as u8, amsdu);
    }
    let (mut exponent, spacing, mut amsdu) = cap.ht.as_ref().map_or((0, 0, 0), |h| {
        (
            h.ampdu_exponent,
            h.mpdu_spacing,
            if h.capability & 0x800 != 0 {
                7935
            } else {
                3839
            },
        )
    });
    if mode != Mode::Ht
        && let Some(v) = &cap.vht
    {
        exponent = exponent.max(((v.capability >> 23) & 7) as u8);
        amsdu = match v.capability & 3 {
            1 => 7991,
            2 => 11454,
            _ => 3895,
        };
    }
    if mode == Mode::Eht
        && cap.band == Band::Ghz2
        && let Some(e) = &cap.eht
    {
        amsdu = match (e.mac[0] >> 6) & 3 {
            1 => 7991,
            2 => 11454,
            _ => 3895,
        };
    }
    (exponent, spacing, amsdu)
}

impl Negotiated {
    pub fn between(
        local: &Capabilities,
        peer: &Capabilities,
        mode: Mode,
        width: Width,
    ) -> Result<Self, Error> {
        if local.band != peer.band || local.role != Role::Station || peer.role != Role::AccessPoint
        {
            return Err(Error::Incompatible("band or station/AP role"));
        }
        if local.band == Band::Ghz6 && !matches!(mode, Mode::He | Mode::Eht) {
            return Err(Error::Incompatible("6GHz requires HE/EHT"));
        }
        let supported = local.rates.supported & peer.rates.supported;
        if peer.rates.basic & !supported != 0 || (local.band != Band::Ghz6 && supported == 0) {
            return Err(Error::Incompatible("AP basic legacy rates"));
        }
        let implemented = u8::from(local.ht.is_some())
            | u8::from(local.vht.is_some()) << 1
            | u8::from(local.he.is_some()) << 2
            | u8::from(local.eht.is_some()) << 3;
        let selected = match mode {
            Mode::Legacy => 0,
            Mode::Ht => 1,
            Mode::Vht => 3,
            Mode::He => 7,
            Mode::Eht => 15,
        };
        if peer.rates.selectors & 15 & !(implemented & selected) != 0 {
            return Err(Error::Incompatible("required PHY membership selector"));
        }
        if !width_supported(local, mode, width) || !width_supported(peer, mode, width) {
            return Err(Error::Incompatible("selected PHY/width"));
        }
        let ht = if mode != Mode::Legacy {
            local
                .ht
                .as_ref()
                .zip(peer.ht.as_ref())
                .map(|(a, b)| NegotiatedHt::between(a, b))
        } else {
            None
        };
        let vht = if matches!(mode, Mode::Vht | Mode::He | Mode::Eht) {
            local
                .vht
                .as_ref()
                .zip(peer.vht.as_ref())
                .map(|(a, b)| NegotiatedVht::between(a, b))
                .transpose()?
        } else {
            None
        };
        if mode == Mode::Vht {
            let capability = vht.as_ref().ok_or(Error::Missing("VHT"))?.capability;
            let common_width = capability & 0xc;
            if (width == Width::Mhz160 && common_width == 0)
                || (width == Width::Mhz80P80 && common_width != 8)
            {
                return Err(Error::Incompatible("final common VHT width"));
            }
        }
        let he = if matches!(mode, Mode::He | Mode::Eht) {
            local
                .he
                .as_ref()
                .zip(peer.he.as_ref())
                .map(|(a, b)| NegotiatedHe::between(a, b))
        } else {
            None
        };
        let eht = if mode == Mode::Eht {
            Some(NegotiatedEht::between(
                local.eht.as_ref().ok_or(Error::Missing("local EHT"))?,
                peer.eht.as_ref().ok_or(Error::Missing("peer EHT"))?,
                width,
            )?)
        } else {
            None
        };
        let wmm = match (&local.wmm, &peer.wmm) {
            (Some(own), Some(ap)) => Some(NegotiatedWmm {
                access_categories: ap
                    .parameters
                    .ok_or(Error::Missing("AP WMM access parameters"))?,
                parameter_set_count: ap.qos_info & 15,
                uapsd_queues: if ap.qos_info & 0x80 != 0 {
                    own.qos_info & 15
                } else {
                    0
                },
                max_service_period: (own.qos_info >> 5) & 3,
            }),
            _ => None,
        };
        if mode != Mode::Legacy && wmm.is_none() {
            return Err(Error::Missing("negotiated WMM for modern PHY"));
        }
        let (tx_nss, rx_nss) = match mode {
            Mode::Legacy => (1, 1),
            Mode::Ht => {
                let h = ht.as_ref().ok_or(Error::Missing("HT"))?;
                (
                    ht_nss(&h.peer_rx_mcs, width),
                    ht_nss(&h.local_rx_mcs, width),
                )
            }
            Mode::Vht => {
                let v = vht.as_ref().ok_or(Error::Missing("VHT"))?;
                (v.mcs.rx_nss(), v.mcs.tx_nss())
            }
            Mode::He => {
                let h = he.as_ref().ok_or(Error::Missing("HE"))?;
                let map = match width {
                    Width::Mhz160 => h.mcs_160,
                    Width::Mhz80P80 => h.mcs_80p80,
                    _ => Some(h.mcs_80),
                }
                .ok_or(Error::Incompatible("HE width MCS"))?;
                (map.rx_nss(), map.tx_nss())
            }
            Mode::Eht => {
                let ranges = &eht.as_ref().unwrap().ranges;
                (
                    ranges.iter().map(|v| v & 15).max().unwrap(),
                    ranges.iter().map(|v| v >> 4).max().unwrap(),
                )
            }
        };
        if tx_nss == 0 || rx_nss == 0 {
            return Err(Error::Incompatible("no common directional MCS/NSS"));
        }
        let (peer_ampdu_base_exponent, peer_mpdu_spacing, max_tx_amsdu) =
            aggregate_limits(peer, mode);
        let (_, _, max_rx_amsdu) = aggregate_limits(local, mode);
        Ok(Self {
            local: local.clone(),
            peer: peer.clone(),
            mode,
            width,
            legacy: LegacyRates {
                supported,
                basic: peer.rates.basic,
                selectors: peer.rates.selectors,
            },
            ht,
            vht,
            he,
            eht,
            wmm,
            rx_nss,
            tx_nss,
            peer_ampdu_base_exponent,
            peer_mpdu_spacing,
            max_tx_amsdu,
            max_rx_amsdu,
        })
    }
    pub const fn local(&self) -> &Capabilities {
        &self.local
    }
    pub const fn peer(&self) -> &Capabilities {
        &self.peer
    }
    pub fn legacy20_compatible(&self) -> bool {
        self.mode == Mode::Legacy && self.width == Width::Mhz20 && self.wmm.is_none()
    }
}
