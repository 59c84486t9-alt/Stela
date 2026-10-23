// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
// Copyright 2002-2005, Instant802 Networks, Inc.
// Copyright 2005-2006, Devicescape Software, Inc.
// Copyright 2006-2007 Jiri Benc <jbenc@suse.cz>
// Copyright 2007, 2009 Johannes Berg <johannes@sipsolutions.net>
// Copyright 2013-2014 Intel Mobile Communications GmbH
// Copyright (C) 2015-2017 Intel Deutschland GmbH
// Copyright (C) 2018-2026 Intel Corporation
//! Ordinary full source probe IE selection over retained MT7925 capabilities.
use super::{Advertisement, LocalError, extension, ie};
use crate::net::wifi::{Band, mediatek::mcu::domain};
use alloc::vec::Vec;

const CHAN_DISABLED: u32 = 1;
const CHAN_NO_80: u32 = 1 << 7;
const CHAN_NO_HE: u32 = 1 << 13;
const CHAN_NO_EHT: u32 = 1 << 20;

/// Source any-usable-channel decisions over this owner's completed domain.
/// These only select advertised families; they grant no probe permission.
pub(in crate::net::wifi::mediatek::bootstrap::client) struct Selection {
    vht: bool,
    he: bool,
    eht: bool,
    he6: Option<u16>,
}
impl Selection {
    pub(in crate::net::wifi::mediatek::bootstrap::client) fn programmed(
        domain: &domain::Request,
        band: Band,
        he6: u16,
    ) -> Self {
        fn usable(domain: &domain::Request, band: Band, excluded: u32) -> bool {
            let index = match band {
                Band::Ghz2 => 0,
                Band::Ghz5 => 1,
                Band::Ghz6 => 2,
            };
            let counts = domain.counts();
            let first: usize = counts[..index].iter().map(|&n| usize::from(n)).sum();
            domain.body()[16 + first * 8..16 + (first + usize::from(counts[index])) * 8]
                .as_chunks::<8>()
                .0
                .iter()
                .any(|row| {
                    u32::from_le_bytes(row[4..8].try_into().unwrap()) & (CHAN_DISABLED | excluded)
                        == 0
                })
        }
        Self {
            vht: usable(domain, band, CHAN_NO_80),
            he: usable(domain, band, CHAN_NO_HE),
            eht: usable(domain, band, CHAN_NO_HE | CHAN_NO_EHT),
            he6: (he6 != 0 && usable(domain, Band::Ghz6, CHAN_NO_HE)).then_some(he6),
        }
    }
}

/// Source mac80211 ordinary full probe contents. Reuse this retained device's
/// independently source-checked capability issuer, omitting association WMM and
/// placing HE6 after EHT as ieee80211_put_preq_ies_band does. Probe SMPS is OFF.
/// No custom PHY IE may supply capabilities on behalf of this actual device.
pub(in crate::net::wifi::mediatek::bootstrap::client) fn elements(
    advertisement: &Advertisement,
    selection: Selection,
) -> Result<Vec<u8>, LocalError> {
    let mut out = Vec::new();
    out.try_reserve_exact(advertisement.elements.len() + 15)
        .map_err(|_| LocalError::NoMemory)?;
    // mt76_init_sband_6g retains the OFDM rate table, even though the
    // association advertisement correctly has no legacy 6GHz rate element.
    if advertisement.capabilities.band() == Band::Ghz6 {
        ie(&mut out, 1, &[12, 18, 24, 36, 48, 72, 96, 108]);
    }

    let mut rest = advertisement.elements();
    while !rest.is_empty() {
        let id = rest[0];
        let length = usize::from(*rest.get(1).ok_or(LocalError::WrongAdvertisement)?);
        let bytes = rest
            .get(2..2 + length)
            .ok_or(LocalError::WrongAdvertisement)?;
        match (id, bytes.first()) {
            (221, _) => (),
            (255, Some(59)) => (),
            (191, _) if !selection.vht => (),
            (255, Some(35)) if !selection.he => (),
            (255, Some(108)) if !selection.eht => (),
            _ => ie(&mut out, id, bytes),
        }
        rest = &rest[2 + length..];
    }
    const HE6_SMPS_MASK: u16 = 0x0600;
    const HE6_SMPS_DISABLED: u16 = 0x0600;
    if let Some(he6) = selection.he6 {
        extension(
            &mut out,
            59,
            &((he6 & !HE6_SMPS_MASK) | HE6_SMPS_DISABLED).to_le_bytes(),
        );
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::super::{MloObservations, make};
    use super::*;
    use crate::net::{
        Mac,
        wifi::{
            Channel,
            mediatek::mcu::{client as wire, device::Context},
            scan::Request,
            station::phy::Width,
        },
    };

    #[test]
    fn source_usable_band_union_never_turns_flags_into_probe_authority() {
        use crate::net::wifi::mediatek::identity::Chip;
        let blocked = domain::Channel {
            hardware_value: 1,
            flags: CHAN_NO_80 | CHAN_NO_HE | CHAN_NO_EHT,
        };
        let allowed = domain::Channel {
            hardware_value: 5,
            flags: 0,
        };
        let rows = [blocked, allowed];
        let programmed = domain::Request::build(
            Chip::Mt7925,
            domain::Inputs {
                alpha2: *b"US",
                channels_2ghz: &[],
                channels_5ghz: &rows,
                channels_6ghz: &[blocked],
            },
        )
        .unwrap();
        let selected = Selection::programmed(&programmed, Band::Ghz5, 0x30b8);
        assert!(selected.vht && selected.he && selected.eht);
        assert_eq!(selected.he6, None);
        let selected = Selection::programmed(&programmed, Band::Ghz6, 0x30b8);
        assert!(!selected.vht && !selected.he && !selected.eht);
        assert_eq!(selected.he6, None);
    }

    #[test]
    #[ignore = "requires complete unchanged source mac80211 probe writers"]
    fn full_source_probe_ies_and_firmware_commands_match_all_bands_streams_and_widths() {
        let root = std::path::PathBuf::from(std::env::var_os("STELA_MT7925_PROBE_ORACLE").unwrap());
        let trace = std::fs::read(root.join("client.trace")).unwrap();
        let mut at = 0;
        let mut count = 0;
        for band in [Band::Ghz2, Band::Ghz5, Band::Ghz6] {
            for nss in 1..=4 {
                for (wi, width) in [Width::Mhz20, Width::Mhz40, Width::Mhz80, Width::Mhz160]
                    .into_iter()
                    .enumerate()
                {
                    if band == Band::Ghz2 && wi > 1 {
                        continue;
                    }
                    for enabled in [false, true] {
                        for flags in [
                            0,
                            CHAN_NO_80,
                            CHAN_NO_HE,
                            CHAN_NO_EHT,
                            CHAN_NO_80 | CHAN_NO_HE | CHAN_NO_EHT,
                        ] {
                            let a = make(
                                band,
                                (1 << nss) - 1,
                                (1 << nss) - 1,
                                width,
                                enabled,
                                *b"US",
                                MloObservations {
                                    flags: None,
                                    eml: None,
                                },
                            )
                            .unwrap();
                            let rows = [domain::Channel {
                                hardware_value: 1,
                                flags,
                            }];
                            let domain = domain::Request::build(
                                crate::net::wifi::mediatek::identity::Chip::Mt7925,
                                domain::Inputs {
                                    alpha2: *b"US",
                                    channels_2ghz: &rows,
                                    channels_5ghz: &rows,
                                    channels_6ghz: &rows,
                                },
                            )
                            .unwrap();
                            let selected =
                                elements(&a, Selection::programmed(&domain, band, 0x30b8)).unwrap();
                            let code = match band {
                                Band::Ghz2 => 0,
                                Band::Ghz5 => 1,
                                Band::Ghz6 => 3,
                            };
                            assert_eq!(
                                &trace[at..at + 4],
                                &[code, nss, wi as u8, u8::from(enabled)],
                                "case{count}"
                            );
                            at += 4;
                            let length = usize::from(u16::from_le_bytes(
                                trace[at..at + 2].try_into().unwrap(),
                            ));
                            at += 2;
                            assert_eq!(
                                selected,
                                trace[at..at + length],
                                "source probe case{count}"
                            );
                            at += length;
                            let mut all = [Vec::new(), Vec::new(), Vec::new()];
                            all[match band {
                                Band::Ghz2 => 0,
                                Band::Ghz5 => 1,
                                Band::Ghz6 => 2,
                            }] = selected;
                            let request = Request::new(
                                vec![Channel {
                                    band,
                                    number: if band == Band::Ghz5 { 36 } else { 1 },
                                    frequency_mhz: match band {
                                        Band::Ghz2 => 2412,
                                        Band::Ghz5 => 5180,
                                        Band::Ghz6 => 5955,
                                    },
                                }],
                                vec![],
                                vec![],
                            )
                            .unwrap();
                            let encoded = wire::scan_with_elements(
                                Context {
                                    bss_index: 0,
                                    omac_index: 0,
                                    band_index: 255,
                                    wmm_index: 0,
                                    link_index: 0,
                                    broadcast_wcid: 19,
                                    address: Mac([2; 6]),
                                },
                                1,
                                &request,
                                Some(&all),
                            )
                            .unwrap();
                            assert_eq!(trace[at], 0x16);
                            at += 1;
                            let length = usize::from(u16::from_le_bytes(
                                trace[at..at + 2].try_into().unwrap(),
                            ));
                            at += 2;
                            assert_eq!(
                                encoded.body(),
                                &trace[at..at + length],
                                "source firmware scan case{count}"
                            );
                            at += length;
                            count += 1;
                        }
                    }
                }
            }
        }
        assert_eq!(count, 400);
        assert_eq!(at, trace.len());
    }
}
