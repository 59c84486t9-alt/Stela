use super::{Error, Role};
use crate::bytes::le16;

/// Bounded HE/EHT PPE observation; no allocation on an untrusted IE path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ppe {
    bytes: [u8; 32],
    len: u8,
}
impl Ppe {
    fn new(data: &[u8]) -> Result<Self, Error> {
        if data.len() > 32 {
            return Err(Error::Unsupported("PPE exceeds eight-NSS bound"));
        }
        let mut bytes = [0; 32];
        bytes[..data.len()].copy_from_slice(data);
        Ok(Self {
            bytes,
            len: data.len() as u8,
        })
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
    pub const fn len(&self) -> usize {
        self.len as usize
    }
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

fn exact<const N: usize>(bytes: &[u8]) -> Result<[u8; N], Error> {
    bytes
        .try_into()
        .map_err(|_| Error::Invalid("fixed capability length"))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ht {
    pub capability: u16,
    pub ampdu_exponent: u8,
    pub mpdu_spacing: u8,
    pub rx_mcs: [u8; 10],
    pub rx_highest: u16,
    pub tx_params: u8,
    pub raw: [u8; 26],
}
impl Ht {
    pub(super) fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let raw = exact(bytes)?;
        Ok(Self {
            capability: le16(bytes, 0),
            ampdu_exponent: bytes[2] & 3,
            mpdu_spacing: (bytes[2] >> 2) & 7,
            rx_mcs: bytes[3..13].try_into().unwrap(),
            rx_highest: le16(bytes, 13),
            tx_params: bytes[15],
            raw,
        })
    }
}

/// Directional peer receive/transmit maps. Each 2-bit NSS entry is an MCS
/// ceiling; 3 means unsupported. HE and VHT assign different ceilings to 0..2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct McsMaps {
    pub rx: u16,
    pub tx: u16,
}
impl McsMaps {
    fn parse(bytes: &[u8]) -> Self {
        Self {
            rx: le16(bytes, 0),
            tx: le16(bytes, 2),
        }
    }
    pub const fn rx_nss(self) -> u8 {
        nss(self.rx)
    }
    pub const fn tx_nss(self) -> u8 {
        nss(self.tx)
    }
    /// Result remains peer-oriented: peer RX/local TX, peer TX/local RX.
    pub fn intersect(local: Self, peer: Self) -> Self {
        Self {
            rx: intersect_map(local.tx, peer.rx),
            tx: intersect_map(local.rx, peer.tx),
        }
    }
}
const fn nss(map: u16) -> u8 {
    let mut result = 0;
    let mut index = 0;
    while index < 8 {
        if (map >> (index * 2)) & 3 != 3 {
            result = index + 1;
        }
        index += 1;
    }
    result
}
fn intersect_map(own: u16, peer: u16) -> u16 {
    let mut result = 0;
    for index in 0..8 {
        let a = (own >> (2 * index)) & 3;
        let b = (peer >> (2 * index)) & 3;
        let value = if a == 3 || b == 3 { 3 } else { a.min(b) };
        result |= value << (2 * index);
    }
    result
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vht {
    pub capability: u32,
    pub mcs: McsMaps,
    pub rx_highest: u16,
    pub tx_highest: u16,
    pub raw: [u8; 12],
}
impl Vht {
    pub(super) fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let raw = exact(bytes)?;
        let capability = u32::from_le_bytes(bytes[..4].try_into().unwrap());
        if capability & 3 == 3 || capability & 0xc == 0xc {
            return Err(Error::Invalid("reserved VHT MPDU/width encoding"));
        }
        Ok(Self {
            capability,
            mcs: McsMaps {
                rx: le16(bytes, 4),
                tx: le16(bytes, 8),
            },
            rx_highest: le16(bytes, 6),
            tx_highest: le16(bytes, 10),
            raw,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct He {
    pub mac: [u8; 6],
    pub phy: [u8; 11],
    pub mcs_80: McsMaps,
    pub mcs_160: Option<McsMaps>,
    pub mcs_80p80: Option<McsMaps>,
    pub ppe: Ppe,
}
impl He {
    /// Normal non-STRICT Linux peer HE verification: mandatory actual1SS
    /// RX/TX comes before the zero-Basic compatibility case.
    pub(super) fn peer_meets_basic(&self, required: u16) -> bool {
        self.mcs_80.rx & 3 != 3
            && self.mcs_80.tx & 3 != 3
            && (required == 0 || he_map_meets(required, self.mcs_80))
    }

    pub(super) fn local_meets_basic(
        &self,
        required: u16,
        source: Option<[McsMaps; 3]>,
    ) -> Result<bool, Error> {
        if required == 0 {
            return Ok(true);
        }
        if let Some(source) = source {
            return Ok(source.into_iter().any(|map| he_map_meets(required, map)));
        }
        // A known fitting source slot proves the source helper's early success.
        // None carries no fact about hidden source struct words: never invent
        // zero/ffff. If those unknown slots could affect the result, require them.
        let observed = [Some(self.mcs_80), self.mcs_160, self.mcs_80p80];
        if observed
            .into_iter()
            .flatten()
            .any(|map| he_map_meets(required, map))
        {
            return Ok(true);
        }
        if observed.iter().any(Option::is_none) {
            return Err(Error::Missing("complete local HE source MCS slots"));
        }
        Ok(false)
    }

    pub(super) fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let fixed = bytes.get(..17).ok_or(Error::Truncated)?;
        let mac = fixed[..6].try_into().unwrap();
        let phy: [u8; 11] = fixed[6..].try_into().unwrap();
        let mut offset = 17;
        let mut maps = || -> Result<McsMaps, Error> {
            let data = bytes.get(offset..offset + 4).ok_or(Error::Truncated)?;
            offset += 4;
            Ok(McsMaps::parse(data))
        };
        let mcs_80 = maps()?;
        let mcs_160 = if phy[0] & 8 != 0 { Some(maps()?) } else { None };
        let mcs_80p80 = if phy[0] & 16 != 0 {
            Some(maps()?)
        } else {
            None
        };
        let ppe_len = if phy[6] & 0x80 != 0 {
            let header = *bytes.get(offset).ok_or(Error::Truncated)?;
            he_ppe_len(header)
        } else {
            0
        };
        let ppe = Ppe::new(
            bytes
                .get(offset..offset + ppe_len)
                .ok_or(Error::Truncated)?,
        )?;
        if bytes.len() != offset + ppe_len {
            return Err(Error::Unsupported("trailing HE capability fields"));
        }
        Ok(Self {
            mac,
            phy,
            mcs_80,
            mcs_160,
            mcs_80p80,
            ppe,
        })
    }
}

fn he_map_meets(required: u16, map: McsMaps) -> bool {
    (0..8).all(|n| {
        let r = (required >> (2 * n)) & 3;
        r == 3
            || [map.rx, map.tx].iter().all(|m| {
                let have = (m >> (2 * n)) & 3;
                have != 3 && have >= r
            })
    })
}

pub(super) fn he_ppe_len(header: u8) -> usize {
    (6 * (header & 0x78).count_ones() as usize * (1 + usize::from(header & 7)) + 7).div_ceil(8)
}
pub(super) fn eht_ppe_len(header: u16) -> usize {
    (6 * (header & 0x1f0).count_ones() as usize * (1 + usize::from(header & 15)) + 9).div_ceil(8)
}

/// Raw EHT max-NSS octets: low nibble peer RX, high nibble peer TX. Zero
/// means unsupported. A 20-only STA has four MCS ranges, other layouts three.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EhtMcs {
    pub only_20: Option<[u8; 4]>,
    pub bw80: Option<[u8; 3]>,
    pub bw160: Option<[u8; 3]>,
    pub bw320: Option<[u8; 3]>,
}

/// Exact zero-filled Linux `ieee80211_eht_mcs_nss_supp` union observation.
/// Its first four bytes are the 20-only STA overlay; its three consecutive
/// three-byte blocks are the firmware's BW80/160/320 overlays. These are raw
/// peer capabilities, not local directional intersections or TX authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EhtMcsUnion {
    bytes: [u8; 9],
    wire_len: u8,
}
impl EhtMcsUnion {
    pub fn bytes(&self) -> &[u8; 9] {
        &self.bytes
    }
    pub fn wire_len(&self) -> usize {
        usize::from(self.wire_len)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Eht {
    pub mac: [u8; 2],
    pub phy: [u8; 9],
    pub mcs: EhtMcs,
    pub ppe: Ppe,
    source_mcs_union: EhtMcsUnion,
}

impl Eht {
    pub fn source_mcs_union(&self) -> &EhtMcsUnion {
        &self.source_mcs_union
    }

    // Exact pinned mlme.c get_eht_cap_mcs_nss/verify_sta_eht_mcs_support:
    // requirements apply to every locally supported bandwidth, independently
    // of the selected association width. Unsupported widths return0xff.
    pub(super) fn meets_basic(&self, he: &He, required: [u8; 4]) -> bool {
        let raw = self.source_mcs_union.bytes();
        for (group, required) in required.into_iter().enumerate() {
            for width in 0..3 {
                let index = group.saturating_sub(1);
                let have = if he.phy[0] & 0x1e == 0 {
                    raw[group] //20-only STA has four distinct MCS ranges.
                } else {
                    match width {
                        0 => raw[index],
                        1 if he.phy[0] & 0x18 == 0 => 0xff,
                        1 => raw[3 + index],
                        2 if self.phy[0] & 2 == 0 => 0xff,
                        2 => raw[6 + index],
                        _ => unreachable!(),
                    }
                };
                if (required & 15) > (have & 15) || (required >> 4) > (have >> 4) {
                    return false;
                }
            }
        }
        true
    }

    pub(super) fn parse(bytes: &[u8], he: &He, role: Role) -> Result<Self, Error> {
        let fixed = bytes.get(..11).ok_or(Error::Truncated)?;
        let mac = fixed[..2].try_into().unwrap();
        let phy: [u8; 9] = fixed[2..].try_into().unwrap();
        let mut offset = 11;
        let mut mcs = EhtMcs {
            only_20: None,
            bw80: None,
            bw160: None,
            bw320: None,
        };
        let mut map = || -> Result<[u8; 3], Error> {
            let data = bytes.get(offset..offset + 3).ok_or(Error::Truncated)?;
            offset += 3;
            validate_eht_nss(data)?;
            Ok(data.try_into().unwrap())
        };
        if he.phy[0] & 2 != 0 {
            mcs.bw80 = Some(map()?);
        } else {
            if he.phy[0] & 4 != 0 {
                mcs.bw80 = Some(map()?);
            }
            if he.phy[0] & 8 != 0 {
                mcs.bw160 = Some(map()?);
            }
            if phy[0] & 2 != 0 {
                mcs.bw320 = Some(map()?);
            }
        }
        if mcs.bw80.is_none() && mcs.bw160.is_none() && mcs.bw320.is_none() {
            if role == Role::AccessPoint {
                mcs.bw80 = Some(map()?);
            } else {
                let data = bytes.get(offset..offset + 4).ok_or(Error::Truncated)?;
                validate_eht_nss(data)?;
                mcs.only_20 = Some(data.try_into().unwrap());
                offset += 4;
            }
        }
        // Match the complete Linux EHT-to-station helper: copy the actual
        // contiguous wire maps into a zeroed union, not typed sparse offsets.
        let mut source_mcs_union = EhtMcsUnion {
            bytes: [0; 9],
            wire_len: (offset - 11) as u8,
        };
        source_mcs_union.bytes[..offset - 11].copy_from_slice(&bytes[11..offset]);
        let ppe_len = if phy[5] & 8 != 0 {
            let data = bytes.get(offset..offset + 2).ok_or(Error::Truncated)?;
            let header = le16(data, 0);
            if header & 15 > 7 {
                return Err(Error::Unsupported("EHT PPE above eight NSS"));
            }
            eht_ppe_len(header)
        } else {
            0
        };
        let ppe = Ppe::new(
            bytes
                .get(offset..offset + ppe_len)
                .ok_or(Error::Truncated)?,
        )?;
        if bytes.len() != offset + ppe_len {
            return Err(Error::Unsupported("trailing EHT capability fields"));
        }
        Ok(Self {
            mac,
            phy,
            mcs,
            ppe,
            source_mcs_union,
        })
    }
}

fn validate_eht_nss(bytes: &[u8]) -> Result<(), Error> {
    if bytes.iter().any(|value| value & 15 > 8 || value >> 4 > 8) {
        return Err(Error::Invalid("EHT NSS exceeds eight"));
    }
    Ok(())
}

#[cfg(test)]
mod basic_tests {
    use super::*;
    use alloc::format;
    use sha2::{Digest, Sha256};

    #[test]
    fn all_local_width_basic_requirements_match_full_unchanged_linux_helpers() {
        let mut hash = Sha256::new();
        let mut cases = 0;
        for flags in (0..32).step_by(2) {
            for wide in [false, true] {
                let mut he = He {
                    mac: [0; 6],
                    phy: [0; 11],
                    mcs_80: McsMaps { rx: 0, tx: 0 },
                    mcs_160: None,
                    mcs_80p80: None,
                    ppe: Ppe::new(&[]).unwrap(),
                };
                he.phy[0] = flags;
                // Direct source-struct fixture, never an admitted advertisement,
                // current association or physical local-capability claim.
                let mut eht = Eht {
                    mac: [0; 2],
                    phy: [0; 9],
                    mcs: EhtMcs {
                        only_20: None,
                        bw80: None,
                        bw160: None,
                        bw320: None,
                    },
                    ppe: Ppe::new(&[]).unwrap(),
                    source_mcs_union: EhtMcsUnion {
                        bytes: [0x88; 9],
                        wire_len: 9,
                    },
                };
                eht.phy[0] = if wide { 2 } else { 0 };
                for group in 0_usize..4 {
                    for bw in 0..3 {
                        for have in 0..9 {
                            for required in 0..9 {
                                for direction in 0..2 {
                                    eht.source_mcs_union.bytes.fill(0x88);
                                    let idx = if flags & 0x1e == 0 {
                                        group
                                    } else {
                                        bw * 3 + group.saturating_sub(1)
                                    };
                                    eht.source_mcs_union.bytes[idx] = if direction == 0 {
                                        have | 0x80
                                    } else {
                                        8 | (have << 4)
                                    };
                                    let mut basic = [0; 4];
                                    basic[group] = if direction == 0 {
                                        required
                                    } else {
                                        required << 4
                                    };
                                    hash.update([u8::from(eht.meets_basic(&he, basic))]);
                                    cases += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(cases, 62208);
        assert_eq!(
            format!("{:x}", hash.finalize()),
            "4e172241fdaa7984005b2a209956aafc2dd9c0c0d7b2533adf9bc37ad82f69d6"
        );
    }
}

#[cfg(test)]
mod he_basic_tests {
    use super::*;
    use alloc::format;
    use sha2::{Digest, Sha256};
    fn he() -> He {
        He {
            mac: [0; 6],
            phy: [0; 11],
            mcs_80: McsMaps {
                rx: 0xfffe,
                tx: 0xfffe,
            },
            mcs_160: None,
            mcs_80p80: None,
            ppe: Ppe::new(&[]).unwrap(),
        }
    }
    #[test]
    fn normal_he_basic_rules_match_complete_unchanged_peer_and_local_helpers() {
        let mut hash = Sha256::new();
        let mut cases = 0;
        let local = he();
        let mut peer = he();
        for nss in 0..8 {
            for req in 0..4 {
                for rx in 0..4 {
                    for tx in 0..4 {
                        for peer_rx in 0..4 {
                            for peer_tx in 0..4 {
                                for width in 0..3 {
                                    for zero in [false, true] {
                                        let shift = nss * 2;
                                        let mask = !(3_u16 << shift);
                                        let basic = mask | (req << shift);
                                        let mut source = [McsMaps {
                                            rx: if zero { 0 } else { 0xffff },
                                            tx: if zero { 0 } else { 0xffff },
                                        };
                                            3];
                                        source[width] = McsMaps {
                                            rx: mask | (rx << shift),
                                            tx: mask | (tx << shift),
                                        };
                                        peer.mcs_80 = McsMaps {
                                            rx: (0xfffc & mask) | (peer_rx << shift),
                                            tx: (0xfffc & mask) | (peer_tx << shift),
                                        };
                                        hash.update([
                                            u8::from(peer.peer_meets_basic(basic)),
                                            u8::from(
                                                local
                                                    .local_meets_basic(basic, Some(source))
                                                    .unwrap(),
                                            ),
                                        ]);
                                        cases += 1;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        for rx in 0..4 {
            for tx in 0..4 {
                peer.mcs_80 = McsMaps {
                    rx: 0xfffc | rx,
                    tx: 0xfffc | tx,
                };
                hash.update([
                    u8::from(peer.peer_meets_basic(0)),
                    u8::from(
                        local
                            .local_meets_basic(
                                0,
                                Some(
                                    [McsMaps {
                                        rx: 0xffff,
                                        tx: 0xffff,
                                    }; 3],
                                ),
                            )
                            .unwrap(),
                    ),
                ]);
                cases += 1;
            }
        }
        assert_eq!(cases, 49168);
        assert_eq!(
            format!("{:x}", hash.finalize()),
            "01c1fb901513cd4690b019125b5366862b63d3b33dd0bbc9a060792bb5745425"
        );
    }
}
