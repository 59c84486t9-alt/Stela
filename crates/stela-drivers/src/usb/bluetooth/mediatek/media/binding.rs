// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2005-2008 Marcel Holtmann <marcel@holtmann.org>
//! MT7925 class-interface selection, adapted from pinned btusb_work and
//! __set_mtk_intr_interface. No interface label or USB ID infers live silicon.
use super::{Error, Result};
use crate::usb::{
    bluetooth::Binding,
    descriptor::{Endpoint, Interface},
    xhci::{FULL_SPEED, HIGH_SPEED},
};
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AirMode {
    Cvsd,
    Transparent,
}
/// Host-stack SCO connection/voice observations, not guessed link state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Voice {
    pub connections: u8,
    pub air_mode: AirMode,
    pub voice_setting: u16,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pair {
    pub interface: u8,
    pub alternate: u8,
    pub input: Endpoint,
    pub output: Endpoint,
}
impl Pair {
    pub fn endpoints(self) -> [Endpoint; 2] {
        [self.input, self.output]
    }
}
/// Exact descriptor plans for this PC's source-supported USB function. A plan
/// neither initializes firmware nor claims any endpoint or DMA ownership.
#[derive(Clone, Debug)]
pub struct Bindings {
    pub(super) iso: Option<Pair>,
    pub(super) sco: Vec<Interface>,
    pub(super) speed: u8,
    use_alt3_for_wbs: bool,
}
impl Bindings {
    pub fn new(binding: &Binding) -> Result<Self> {
        let device = binding.device();
        let d = &device.descriptor;
        if d[8..14] != [0xd3, 0x13, 0x02, 0x36, 0x00, 0x01] || binding.interface() != 0 {
            return Err(Error::Unsupported(
                "exact MT7925 USB 13d3:3602:0100 interface0",
            ));
        }
        let interfaces = crate::usb::descriptor::interfaces(&device.configuration);
        let iso: Vec<_> = interfaces.iter().filter(|i| i.number == 2).collect();
        let alternate = if iso.len() > 1 { 1 } else { 0 };
        let selected = iso
            .iter()
            .find(|i| i.alternate == alternate)
            .ok_or(Error::Descriptor(
                "MediaTek ISO interface2 source-selected alternate",
            ))?;
        let iso = pair(selected, device.speed, 3)?;
        let sco: Vec<_> = interfaces.into_iter().filter(|i| i.number == 1).collect();
        if !sco
            .iter()
            .any(|i| i.alternate == 0 && i.endpoints.is_empty())
        {
            return Err(Error::Descriptor("SCO interface1 empty alternate0"));
        }
        // Interface ownership must never alias ACL/event or the third interface.
        let base = [
            binding.events.dci(),
            binding.input.dci(),
            binding.output.dci(),
        ];
        if iso.endpoints().iter().any(|ep| base.contains(&ep.dci())) {
            return Err(Error::Descriptor("MediaTek ISO endpoint aliases base HCI"));
        }
        for setting in &sco {
            for ep in &setting.endpoints {
                if base.contains(&ep.dci()) || iso.endpoints().iter().any(|i| i.dci() == ep.dci()) {
                    return Err(Error::Descriptor("SCO endpoint aliases another interface"));
                }
            }
        }
        Ok(Self {
            iso: Some(iso),
            sco,
            speed: device.speed,
            use_alt3_for_wbs: false,
        })
    }
    pub fn iso(&self) -> Pair {
        self.iso.expect("MT7925 third-interface plan")
    }
    pub(in crate::usb::bluetooth) fn has_iso(&self) -> bool {
        self.iso.is_some()
    }
    /// Source ordinary USB2 SCO plan, without MediaTek's third interface.
    pub(in crate::usb::bluetooth) fn realtek_sco(binding: &Binding) -> Result<Self> {
        let device = binding.device();
        if !super::super::super::realtek::is_candidate(device) || binding.interface() != 0 {
            return Err(Error::Unsupported("exact initialized Realtek USB profile"));
        }
        Self::standard_sco(binding, true)
    }
    pub(in crate::usb::bluetooth) fn qca_sco(binding: &Binding) -> Result<Self> {
        if !super::super::super::qca::is_candidate(binding.device()) || binding.interface() != 0 {
            return Err(Error::Unsupported("exact initialized QCA USB profile"));
        }
        Self::standard_sco(binding, false)
    }
    fn standard_sco(binding: &Binding, use_alt3_for_wbs: bool) -> Result<Self> {
        let device = binding.device();
        let interfaces = crate::usb::descriptor::interfaces(&device.configuration);
        let sco: Vec<_> = interfaces
            .iter()
            .filter(|i| i.number == 1)
            .cloned()
            .collect();
        if !sco
            .iter()
            .any(|i| i.alternate == 0 && i.endpoints.is_empty())
            || sco
                .iter()
                .any(|i| (i.class, i.subclass, i.protocol) != (0xe0, 1, 1))
        {
            return Err(Error::Descriptor(
                "standard SCO interface1 with empty alternate0",
            ));
        }
        // The function owns only interface1. No alternate may alias any other
        // interface, including an unclaimed composite sibling.
        for setting in &sco {
            for endpoint in &setting.endpoints {
                if interfaces
                    .iter()
                    .filter(|i| i.number != 1)
                    .flat_map(|i| &i.endpoints)
                    .any(|ep| ep.dci() == endpoint.dci())
                {
                    return Err(Error::Descriptor("SCO endpoint aliases another interface"));
                }
            }
        }
        Ok(Self {
            iso: None,
            sco,
            speed: device.speed,
            use_alt3_for_wbs,
        })
    }
    pub(in crate::usb::bluetooth) fn accepts_sco(&self, pair: Pair) -> bool {
        self.sco
            .iter()
            .any(|i| super::binding::pair(i, self.speed, 1) == Ok(pair))
    }
    /// The caller supplies current voice state. Missing/malformed
    /// source-selected alternates refuse, with no invented bandwidth fallback.
    pub fn sco(&self, voice: Voice) -> Result<Option<Pair>> {
        if voice.connections == 0 {
            return Ok(None);
        }
        if voice.connections > 3 {
            return Err(Error::Unsupported("at most3 source SCO links"));
        }
        let alternate = match voice.air_mode {
            AirMode::Cvsd if voice.voice_setting & 0x20 != 0 => {
                [2, 4, 5][usize::from(voice.connections - 1)]
            }
            AirMode::Cvsd => voice.connections,
            // This MediaTek tuple has WIDEBAND_SPEECH, not USE_ALT3_FOR_WBS.
            AirMode::Transparent if self.iso.is_some() => {
                if self.sco.iter().any(|i| i.alternate == 6) {
                    6
                } else {
                    1
                }
            }
            AirMode::Transparent => return Err(Error::Unsupported("Realtek wideband SCO policy")),
        };
        let selected = self
            .sco
            .iter()
            .find(|i| i.alternate == alternate)
            .ok_or(Error::Descriptor("source-selected SCO alternate missing"))?;
        pair(selected, self.speed, 1).map(Some)
    }
    pub(in crate::usb::bluetooth) fn wideband_sco(
        &self,
        connections: u8,
        mtu: u16,
    ) -> Result<Option<Pair>> {
        if self.has_iso() || connections > 3 || mtu == 0 {
            return Err(Error::Unsupported("Realtek wideband voice/MTU profile"));
        }
        if connections == 0 {
            return Ok(None);
        }
        let alternate = if self.sco.iter().any(|i| i.alternate == 6) {
            6
        } else if self.use_alt3_for_wbs && mtu >= 72 && self.sco.iter().any(|i| i.alternate == 3) {
            3
        } else {
            1
        };
        let selected = self
            .sco
            .iter()
            .find(|i| i.alternate == alternate)
            .ok_or(Error::Descriptor("source wideband SCO alternate missing"))?;
        let selected = pair(selected, self.speed, 1)?;
        // Source alt6 pacing is in milliseconds: six/seven empty services plus
        // one <=63-byte HCI packet. An arbitrary interval cannot encode it.
        if alternate == 6
            && (service_bytes(selected.output) != 63
                || selected.output.interval != if self.speed == FULL_SPEED { 1 } else { 4 })
        {
            return Err(Error::Descriptor(
                "wideband alternate6 requires 63-byte 1ms output",
            ));
        }
        Ok(Some(selected))
    }
}
pub(in crate::usb::bluetooth) fn service_bytes(endpoint: Endpoint) -> usize {
    usize::from(endpoint.max_packet & 0x7ff) * (usize::from((endpoint.max_packet >> 11) & 3) + 1)
}
fn pair(interface: &Interface, speed: u8, kind: u8) -> Result<Pair> {
    if interface.endpoints.len() != 2 {
        return Err(Error::Descriptor("exact duplex media endpoint pair"));
    }
    let mut input = None;
    let mut output = None;
    for ep in &interface.endpoints {
        let packet = ep.max_packet & 0x7ff;
        let extra = (ep.max_packet >> 11) & 3;
        if ep.address & 0x70 != 0
            || ep.address & 15 == 0
            || ep.companion.is_some()
            || ep.kind() != kind
            || ep.max_packet & 0xe000 != 0
            || extra == 3
            || !(1..=16).contains(&ep.interval)
        {
            return Err(Error::Descriptor("media endpoint encoding"));
        }
        if (kind == 3 && ep.attributes & !3 != 0) || (kind == 1 && ep.attributes & 0xf0 != 0) {
            return Err(Error::Descriptor("media endpoint attributes"));
        }
        match speed {
            FULL_SPEED
                if extra == 0 && packet > 0 && packet <= if kind == 1 { 1023 } else { 64 } => {}
            HIGH_SPEED if (1..=1024).contains(&packet) => {}
            _ => return Err(Error::Descriptor("media speed/packet/transactions")),
        }
        let role = if ep.is_in() { &mut input } else { &mut output };
        if role.replace(*ep).is_some() {
            return Err(Error::Descriptor("duplicate media endpoint direction"));
        }
    }
    Ok(Pair {
        interface: interface.number,
        alternate: interface.alternate,
        input: input.unwrap(),
        output: output.unwrap(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usb::bluetooth::mediatek::media::tests::binding;
    #[test]
    fn selects_same_device_alternates_and_source_voice_policy() {
        let binding = binding();
        let b = Bindings::new(&binding).unwrap();
        assert_eq!(
            (
                b.iso().interface,
                b.iso().alternate,
                b.iso().input.address,
                b.iso().output.address
            ),
            (2, 1, 0x85, 5)
        );
        for (links, bits, expected) in [
            (1, 0, 1),
            (2, 0, 2),
            (3, 0, 3),
            (1, 0x20, 2),
            (2, 0x20, 4),
            (3, 0x20, 5),
        ] {
            let p = b
                .sco(Voice {
                    connections: links,
                    air_mode: AirMode::Cvsd,
                    voice_setting: bits,
                })
                .unwrap()
                .unwrap();
            assert_eq!(p.alternate, expected);
            assert_eq!((p.input.address, p.output.address), (0x83, 3));
        }
        let transparent = Voice {
            connections: 1,
            air_mode: AirMode::Transparent,
            voice_setting: 0,
        };
        assert_eq!(b.sco(transparent).unwrap().unwrap().alternate, 6);
        let mut no6 = b.clone();
        no6.sco.retain(|i| i.alternate != 6);
        assert_eq!(no6.sco(transparent).unwrap().unwrap().alternate, 1);
        no6.sco.retain(|i| i.alternate != 1);
        assert!(no6.sco(transparent).is_err()); // Not an invented alt3 fallback.
        assert!(
            b.sco(Voice {
                connections: 0,
                ..transparent
            })
            .unwrap()
            .is_none()
        );
        assert!(
            b.sco(Voice {
                connections: 4,
                ..transparent
            })
            .is_err()
        );
    }
    #[test]
    fn refuses_wrong_device_aliases_and_unusable_selected_endpoint_without_fallback() {
        let mut binding = binding();
        binding.device.descriptor[12] ^= 1;
        assert!(Bindings::new(&binding).is_err());
        let mut b = Bindings::new(&super::super::tests::binding()).unwrap();
        for index in 0..2 {
            let old = b.sco[1].endpoints[index];
            for (packet, interval, attrs) in [
                (0, 1, 1),
                (0x1801, 1, 1),
                (17, 0, 1),
                (17, 17, 1),
                (17, 1, 0x11),
                (17, 1, 3),
            ] {
                b.sco[1].endpoints[index].max_packet = packet;
                b.sco[1].endpoints[index].interval = interval;
                b.sco[1].endpoints[index].attributes = attrs;
                assert!(
                    b.sco(Voice {
                        connections: 1,
                        air_mode: AirMode::Cvsd,
                        voice_setting: 0
                    })
                    .is_err()
                );
            }
            b.sco[1].endpoints[index] = old;
        }
        let mut binding = super::super::tests::binding();
        let config = &mut binding.device.configuration;
        let n = config.len();
        config[n - 5] = 0x82; // interface2 OUT aliases ACL IN.
        assert!(Bindings::new(&binding).is_err());
    }
}
