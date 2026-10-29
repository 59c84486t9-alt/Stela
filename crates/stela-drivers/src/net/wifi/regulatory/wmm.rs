// SPDX-License-Identifier: GPL-2.0-only
// Station queue clamp follows pinned Linux net/mac80211/util.c.
// Copyright 2002-2005 Instant802 Networks, Inc.; 2005-2006 Devicescape Software;
// 2006-2007 Jiri Benc; 2007 Johannes Berg;
// 2013-2014 Intel Mobile Communications GmbH; 2015-2017 Intel Deutschland GmbH;
// 2018-2026 Intel Corporation. See THIRD_PARTY.md.
//! Effective local queue parameters, separate from unchanged AP negotiation
//! observations. Pure clamping is not native publication or radio permission.
use super::database::Wmm;
use crate::net::wifi::station::phy::AccessCategory;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Category,
    Contention,
}

/// Apply ieee80211_regulatory_limit_wmm_params to a station's four queues.
/// The caller supplies the current control-channel rule, as the source does;
/// it must install the resulting native EDCA command before use.
pub fn station(
    parameters: &[AccessCategory; 4],
    limit: Option<&Wmm>,
) -> Result<[AccessCategory; 4], Error> {
    let mut seen = 0u8;
    let mut result = *parameters;
    for ac in &mut result {
        if ac.aci >= 4 || seen & (1 << ac.aci) != 0 {
            return Err(Error::Category);
        }
        seen |= 1 << ac.aci;
        if ac.ecw_min > ac.ecw_max || ac.ecw_max > 15 {
            return Err(Error::Contention);
        }
        let Some(wmm) = limit else {
            continue;
        };
        // Source regulatory/mac80211 order VO/VI/BE/BK; on-air ACI BE/BK/VI/VO.
        let w = wmm.client[[2, 3, 1, 0][usize::from(ac.aci)]];
        if w.cw_min >= w.cw_max
            || w.cw_max > 32767
            || !(u32::from(w.cw_min) + 1).is_power_of_two()
            || !(u32::from(w.cw_max) + 1).is_power_of_two()
            || w.aifsn == 0
        {
            return Err(Error::Contention);
        }
        ac.ecw_min = ac.ecw_min.max((u32::from(w.cw_min) + 1).ilog2() as u8);
        ac.ecw_max = ac.ecw_max.max((u32::from(w.cw_max) + 1).ilog2() as u8);
        ac.aifsn = ac.aifsn.max(w.aifsn);
        // Source u16 COT assignment/truncation is already kept by db.
        ac.txop_32us = ac.txop_32us.min(w.cot_us / 32);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::wifi::regulatory::database::WmmAc;
    use sha2::{Digest, Sha256};
    #[test]
    fn complete_source_station_queue_clamp_matches_16384_queue_results() {
        let mut digest = Sha256::new();
        for i in 0u32..4096 {
            let parameters = core::array::from_fn(|aci| {
                let lo = (i + aci as u32) % 16;
                let hi = lo + (i / 16) % (16 - lo);
                AccessCategory {
                    aci: aci as u8,
                    admission_control: !(i + aci as u32).is_multiple_of(2),
                    ecw_min: lo as u8,
                    ecw_max: hi as u8,
                    aifsn: (2 + (i + aci as u32) % 14) as u8,
                    txop_32us: ((i * 37 + aci as u32 * 101) % 65536) as u16,
                }
            });
            let client = core::array::from_fn(|j| {
                let lo = (i + 5 * j as u32) % 15;
                WmmAc {
                    cw_min: ((1u32 << lo) - 1) as u16,
                    cw_max: ((1u32 << (lo + 1)) - 1) as u16,
                    aifsn: (1 + (i + 31 * j as u32) % 255) as u8,
                    cot_us: ((i * 997 + j as u32 * 1237) % 65536) as u16,
                }
            });
            let wmm = Wmm { client, ap: client };
            let effective = station(&parameters, (i % 5 == 4).then_some(&wmm)).unwrap();
            for ac in effective {
                digest.update([ac.aci, u8::from(ac.admission_control)]);
                digest.update(((1u16 << ac.ecw_min) - 1).to_le_bytes());
                digest.update(((1u16 << ac.ecw_max) - 1).to_le_bytes());
                digest.update([ac.aifsn]);
                digest.update(ac.txop_32us.to_le_bytes());
            }
        }
        assert_eq!(
            alloc::format!("{:x}", digest.finalize()),
            "4ae60a269f0fdd581c23d88a8ce4899a91998c6cc6009a722b81e1f273a4b756"
        );
    }
    #[test]
    fn unrepresentable_contention_and_duplicate_queue_refuse() {
        let mut parameters = core::array::from_fn(|aci| AccessCategory {
            aci: aci as u8,
            admission_control: false,
            ecw_min: 3,
            ecw_max: 4,
            aifsn: 2,
            txop_32us: 94,
        });
        parameters[1].aci = 0;
        assert_eq!(station(&parameters, None), Err(Error::Category));
        parameters[1].aci = 1;
        parameters[1].ecw_max = 16;
        assert_eq!(station(&parameters, None), Err(Error::Contention));
    }
}
