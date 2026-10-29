// SPDX-License-Identifier: GPL-2.0-only
//! Exact CEA allocations and channel slot programming from Linux
//! sound/hda/core/hdmi_chmap.c at a804c5742bff224d4cb4d25dd383554d598be32b.
use crate::audio::Error;
use alloc::vec::Vec;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Speaker {
    Fl,
    Fr,
    Fc,
    Lfe,
    Rl,
    Rr,
    Rc,
    Flc,
    Frc,
    Rlc,
    Rrc,
    Flw,
    Frw,
    Flh,
    Frh,
    Fch,
    Tc,
}
use Speaker::*;
struct Allocation {
    ca: u8,
    slots: [Option<Speaker>; 8],
}
const ALLOCATIONS: &[Allocation] = &[
    Allocation {
        ca: 0x00,
        slots: [Some(Fl), Some(Fr), None, None, None, None, None, None],
    },
    Allocation {
        ca: 0x01,
        slots: [Some(Fl), Some(Fr), Some(Lfe), None, None, None, None, None],
    },
    Allocation {
        ca: 0x02,
        slots: [Some(Fl), Some(Fr), None, Some(Fc), None, None, None, None],
    },
    Allocation {
        ca: 0x08,
        slots: [
            Some(Fl),
            Some(Fr),
            None,
            None,
            Some(Rl),
            Some(Rr),
            None,
            None,
        ],
    },
    Allocation {
        ca: 0x09,
        slots: [
            Some(Fl),
            Some(Fr),
            Some(Lfe),
            None,
            Some(Rl),
            Some(Rr),
            None,
            None,
        ],
    },
    Allocation {
        ca: 0x0a,
        slots: [
            Some(Fl),
            Some(Fr),
            None,
            Some(Fc),
            Some(Rl),
            Some(Rr),
            None,
            None,
        ],
    },
    Allocation {
        ca: 0x0b,
        slots: [
            Some(Fl),
            Some(Fr),
            Some(Lfe),
            Some(Fc),
            Some(Rl),
            Some(Rr),
            None,
            None,
        ],
    },
    Allocation {
        ca: 0x0f,
        slots: [
            Some(Fl),
            Some(Fr),
            Some(Lfe),
            Some(Fc),
            Some(Rl),
            Some(Rr),
            Some(Rc),
            None,
        ],
    },
    Allocation {
        ca: 0x13,
        slots: [
            Some(Fl),
            Some(Fr),
            Some(Lfe),
            Some(Fc),
            Some(Rl),
            Some(Rr),
            Some(Rlc),
            Some(Rrc),
        ],
    },
    Allocation {
        ca: 0x03,
        slots: [
            Some(Fl),
            Some(Fr),
            Some(Lfe),
            Some(Fc),
            None,
            None,
            None,
            None,
        ],
    },
    Allocation {
        ca: 0x04,
        slots: [Some(Fl), Some(Fr), None, None, Some(Rc), None, None, None],
    },
    Allocation {
        ca: 0x05,
        slots: [
            Some(Fl),
            Some(Fr),
            Some(Lfe),
            None,
            Some(Rc),
            None,
            None,
            None,
        ],
    },
    Allocation {
        ca: 0x06,
        slots: [
            Some(Fl),
            Some(Fr),
            None,
            Some(Fc),
            Some(Rc),
            None,
            None,
            None,
        ],
    },
    Allocation {
        ca: 0x07,
        slots: [
            Some(Fl),
            Some(Fr),
            Some(Lfe),
            Some(Fc),
            Some(Rc),
            None,
            None,
            None,
        ],
    },
    Allocation {
        ca: 0x0c,
        slots: [
            Some(Fl),
            Some(Fr),
            None,
            None,
            Some(Rl),
            Some(Rr),
            Some(Rc),
            None,
        ],
    },
    Allocation {
        ca: 0x0d,
        slots: [
            Some(Fl),
            Some(Fr),
            Some(Lfe),
            None,
            Some(Rl),
            Some(Rr),
            Some(Rc),
            None,
        ],
    },
    Allocation {
        ca: 0x0e,
        slots: [
            Some(Fl),
            Some(Fr),
            None,
            Some(Fc),
            Some(Rl),
            Some(Rr),
            Some(Rc),
            None,
        ],
    },
    Allocation {
        ca: 0x10,
        slots: [
            Some(Fl),
            Some(Fr),
            None,
            None,
            Some(Rl),
            Some(Rr),
            Some(Rlc),
            Some(Rrc),
        ],
    },
    Allocation {
        ca: 0x11,
        slots: [
            Some(Fl),
            Some(Fr),
            Some(Lfe),
            None,
            Some(Rl),
            Some(Rr),
            Some(Rlc),
            Some(Rrc),
        ],
    },
    Allocation {
        ca: 0x12,
        slots: [
            Some(Fl),
            Some(Fr),
            None,
            Some(Fc),
            Some(Rl),
            Some(Rr),
            Some(Rlc),
            Some(Rrc),
        ],
    },
    Allocation {
        ca: 0x14,
        slots: [
            Some(Fl),
            Some(Fr),
            None,
            None,
            None,
            None,
            Some(Flc),
            Some(Frc),
        ],
    },
    Allocation {
        ca: 0x15,
        slots: [
            Some(Fl),
            Some(Fr),
            Some(Lfe),
            None,
            None,
            None,
            Some(Flc),
            Some(Frc),
        ],
    },
    Allocation {
        ca: 0x16,
        slots: [
            Some(Fl),
            Some(Fr),
            None,
            Some(Fc),
            None,
            None,
            Some(Flc),
            Some(Frc),
        ],
    },
    Allocation {
        ca: 0x17,
        slots: [
            Some(Fl),
            Some(Fr),
            Some(Lfe),
            Some(Fc),
            None,
            None,
            Some(Flc),
            Some(Frc),
        ],
    },
    Allocation {
        ca: 0x18,
        slots: [
            Some(Fl),
            Some(Fr),
            None,
            None,
            Some(Rc),
            None,
            Some(Flc),
            Some(Frc),
        ],
    },
    Allocation {
        ca: 0x19,
        slots: [
            Some(Fl),
            Some(Fr),
            Some(Lfe),
            None,
            Some(Rc),
            None,
            Some(Flc),
            Some(Frc),
        ],
    },
    Allocation {
        ca: 0x1a,
        slots: [
            Some(Fl),
            Some(Fr),
            None,
            Some(Fc),
            Some(Rc),
            None,
            Some(Flc),
            Some(Frc),
        ],
    },
    Allocation {
        ca: 0x1b,
        slots: [
            Some(Fl),
            Some(Fr),
            Some(Lfe),
            Some(Fc),
            Some(Rc),
            None,
            Some(Flc),
            Some(Frc),
        ],
    },
    Allocation {
        ca: 0x1c,
        slots: [
            Some(Fl),
            Some(Fr),
            None,
            None,
            Some(Rl),
            Some(Rr),
            Some(Flc),
            Some(Frc),
        ],
    },
    Allocation {
        ca: 0x1d,
        slots: [
            Some(Fl),
            Some(Fr),
            Some(Lfe),
            None,
            Some(Rl),
            Some(Rr),
            Some(Flc),
            Some(Frc),
        ],
    },
    Allocation {
        ca: 0x1e,
        slots: [
            Some(Fl),
            Some(Fr),
            None,
            Some(Fc),
            Some(Rl),
            Some(Rr),
            Some(Flc),
            Some(Frc),
        ],
    },
    Allocation {
        ca: 0x1f,
        slots: [
            Some(Fl),
            Some(Fr),
            Some(Lfe),
            Some(Fc),
            Some(Rl),
            Some(Rr),
            Some(Flc),
            Some(Frc),
        ],
    },
    Allocation {
        ca: 0x20,
        slots: [
            Some(Fl),
            Some(Fr),
            None,
            Some(Fc),
            Some(Rl),
            Some(Rr),
            Some(Fch),
            None,
        ],
    },
    Allocation {
        ca: 0x21,
        slots: [
            Some(Fl),
            Some(Fr),
            Some(Lfe),
            Some(Fc),
            Some(Rl),
            Some(Rr),
            Some(Fch),
            None,
        ],
    },
    Allocation {
        ca: 0x22,
        slots: [
            Some(Fl),
            Some(Fr),
            None,
            Some(Fc),
            Some(Rl),
            Some(Rr),
            None,
            Some(Tc),
        ],
    },
    Allocation {
        ca: 0x23,
        slots: [
            Some(Fl),
            Some(Fr),
            Some(Lfe),
            Some(Fc),
            Some(Rl),
            Some(Rr),
            None,
            Some(Tc),
        ],
    },
    Allocation {
        ca: 0x24,
        slots: [
            Some(Fl),
            Some(Fr),
            None,
            None,
            Some(Rl),
            Some(Rr),
            Some(Flh),
            Some(Frh),
        ],
    },
    Allocation {
        ca: 0x25,
        slots: [
            Some(Fl),
            Some(Fr),
            Some(Lfe),
            None,
            Some(Rl),
            Some(Rr),
            Some(Flh),
            Some(Frh),
        ],
    },
    Allocation {
        ca: 0x26,
        slots: [
            Some(Fl),
            Some(Fr),
            None,
            None,
            Some(Rl),
            Some(Rr),
            Some(Flw),
            Some(Frw),
        ],
    },
    Allocation {
        ca: 0x27,
        slots: [
            Some(Fl),
            Some(Fr),
            Some(Lfe),
            None,
            Some(Rl),
            Some(Rr),
            Some(Flw),
            Some(Frw),
        ],
    },
    Allocation {
        ca: 0x28,
        slots: [
            Some(Fl),
            Some(Fr),
            None,
            Some(Fc),
            Some(Rl),
            Some(Rr),
            Some(Rc),
            Some(Tc),
        ],
    },
    Allocation {
        ca: 0x29,
        slots: [
            Some(Fl),
            Some(Fr),
            Some(Lfe),
            Some(Fc),
            Some(Rl),
            Some(Rr),
            Some(Rc),
            Some(Tc),
        ],
    },
    Allocation {
        ca: 0x2a,
        slots: [
            Some(Fl),
            Some(Fr),
            None,
            Some(Fc),
            Some(Rl),
            Some(Rr),
            Some(Rc),
            Some(Fch),
        ],
    },
    Allocation {
        ca: 0x2b,
        slots: [
            Some(Fl),
            Some(Fr),
            Some(Lfe),
            Some(Fc),
            Some(Rl),
            Some(Rr),
            Some(Rc),
            Some(Fch),
        ],
    },
    Allocation {
        ca: 0x2c,
        slots: [
            Some(Fl),
            Some(Fr),
            None,
            Some(Fc),
            Some(Rl),
            Some(Rr),
            Some(Fch),
            Some(Tc),
        ],
    },
    Allocation {
        ca: 0x2d,
        slots: [
            Some(Fl),
            Some(Fr),
            Some(Lfe),
            Some(Fc),
            Some(Rl),
            Some(Rr),
            Some(Fch),
            Some(Tc),
        ],
    },
    Allocation {
        ca: 0x2e,
        slots: [
            Some(Fl),
            Some(Fr),
            None,
            Some(Fc),
            Some(Rl),
            Some(Rr),
            Some(Flh),
            Some(Frh),
        ],
    },
    Allocation {
        ca: 0x2f,
        slots: [
            Some(Fl),
            Some(Fr),
            Some(Lfe),
            Some(Fc),
            Some(Rl),
            Some(Rr),
            Some(Flh),
            Some(Frh),
        ],
    },
    Allocation {
        ca: 0x30,
        slots: [
            Some(Fl),
            Some(Fr),
            None,
            Some(Fc),
            Some(Rl),
            Some(Rr),
            Some(Flw),
            Some(Frw),
        ],
    },
    Allocation {
        ca: 0x31,
        slots: [
            Some(Fl),
            Some(Fr),
            Some(Lfe),
            Some(Fc),
            Some(Rl),
            Some(Rr),
            Some(Flw),
            Some(Frw),
        ],
    },
];
fn supported(speaker: Speaker, speakers: u8) -> bool {
    let bit = match speaker {
        Fl | Fr => 0,
        Lfe => 1,
        Fc => 2,
        Rl | Rr => 3,
        Rc => 4,
        Flc | Frc => 5,
        Rlc | Rrc => 6,
        _ => return false,
    };
    speakers & (1 << bit) != 0
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelMap {
    pub(crate) allocation: u8,
    pub(crate) slots: [u8; 8],
    pub(crate) order: Vec<Speaker>,
}
impl ChannelMap {
    pub fn allocation(&self) -> u8 {
        self.allocation
    }
    pub fn speakers(&self) -> &[Speaker] {
        &self.order
    }
    pub(crate) fn choose(
        channels: u8,
        advertised: u8,
        custom: Option<&[Speaker]>,
    ) -> Result<Self, Error> {
        if !matches!(channels, 2 | 4 | 6 | 8) {
            return Err(Error::InvalidFormat);
        }
        if let Some(order) = custom
            && (order.len() != usize::from(channels)
                || order
                    .iter()
                    .enumerate()
                    .any(|(i, s)| order[..i].contains(s))
                || (channels == 2 && order != [Fl, Fr]))
        {
            return Err(Error::InvalidChannelMap);
        }
        // FL/FR is the source's basic stereo configuration. An absent
        // multichannel speaker block is not a grant to invent extra speakers.
        let available = advertised | 1;
        for entry in ALLOCATIONS {
            let speakers: Vec<_> = entry.slots.iter().flatten().copied().collect();
            if speakers.len() != usize::from(channels)
                || speakers.iter().any(|s| !supported(*s, available))
            {
                continue;
            }
            let order = if let Some(custom) = custom {
                if custom.iter().any(|s| !speakers.contains(s)) {
                    continue;
                }
                custom.to_vec()
            } else {
                let preferred = if entry.ca == 0x13 {
                    [
                        Fl, Fr, Rlc, Rrc, Fc, Lfe, Rl, Rr, Rc, Flc, Frc, Flw, Frw, Flh, Frh, Fch,
                        Tc,
                    ]
                } else {
                    [
                        Fl, Fr, Rl, Rr, Fc, Lfe, Rc, Flc, Frc, Rlc, Rrc, Flw, Frw, Flh, Frh, Fch,
                        Tc,
                    ]
                };
                preferred
                    .into_iter()
                    .filter(|s| speakers.contains(s))
                    .collect()
            };
            let slots = core::array::from_fn(|slot| {
                let channel = entry.slots[slot]
                    .and_then(|s| order.iter().position(|v| *v == s))
                    .unwrap_or(15) as u8;
                (channel << 4) | slot as u8
            });
            return Ok(Self {
                allocation: entry.ca,
                slots,
                order,
            });
        }
        Err(Error::InvalidChannelMap)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_source_stereo_51_and_71_slots() {
        assert_eq!(
            ChannelMap::choose(2, 0, None).unwrap().slots,
            [0x00, 0x11, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7]
        );
        let six = ChannelMap::choose(6, 0x0f, None).unwrap();
        assert_eq!(six.allocation, 0x0b);
        assert_eq!(six.slots, [0x00, 0x11, 0x52, 0x43, 0x24, 0x35, 0xf6, 0xf7]);
        let eight = ChannelMap::choose(8, 0x4f, None).unwrap();
        assert_eq!(eight.allocation, 0x13);
        assert_eq!(
            eight.slots,
            [0x00, 0x11, 0x52, 0x43, 0x64, 0x75, 0x26, 0x37]
        );
    }
    #[test]
    fn no_invented_speaker_or_duplicate_or_stereo_remap() {
        assert_eq!(
            ChannelMap::choose(8, 0, None),
            Err(Error::InvalidChannelMap)
        );
        assert_eq!(
            ChannelMap::choose(2, 1, Some(&[Fr, Fl])),
            Err(Error::InvalidChannelMap)
        );
        assert_eq!(
            ChannelMap::choose(4, 0x0f, Some(&[Fl, Fr, Rl, Rl])),
            Err(Error::InvalidChannelMap)
        );
    }
}
