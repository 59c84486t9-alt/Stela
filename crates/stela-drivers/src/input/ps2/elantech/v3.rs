// SPDX-License-Identifier: GPL-2.0-only
// Original notices are retained in ../elantech.rs and input/THIRD_PARTY.md.
use super::*;

impl Engine {
    pub(super) fn report_v3(&mut self, inputs: &mut Vec<Input>) -> Result<(), ErrorKind> {
        let c = self.capabilities.as_ref().unwrap();
        let p = self.packet;
        let debounce = p == [0xc4, 0xff, 0xff, 2, 0xff, 0xff];
        let head = if c.crc_enabled {
            match p[3] & 9 {
                8 => Some(true),
                9 => Some(false),
                _ => None,
            }
        } else if p[0] & 12 == 4 && p[3] & 0xcf == 2 {
            Some(true)
        } else if p[0] & 12 == 12 && p[3] & 0xce == 12 {
            Some(false)
        } else {
            None
        };
        if !debounce && head.is_none() {
            self.last_fault = Some((p, 6));
            return Err(ErrorKind::Elantech(Error::Packet));
        }
        let sequence = self.sequence;
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(ErrorKind::Elantech(Error::SequenceExhausted))?;
        let fingers = p[0] >> 6;
        let point = (
            i32::from((u16::from(p[1] & 15) << 8) | u16::from(p[2])),
            i32::from(c.bounds.maximum.1)
                - i32::from((u16::from(p[4] & 15) << 8) | u16::from(p[5])),
        );
        let report = if debounce {
            Report::Debounce
        } else if fingers == 2 && head == Some(true) {
            self.head = Some((sequence, point));
            Report::Head { point }
        } else {
            let (primary, secondary, head_sequence) = if fingers == 2 {
                (
                    self.head.map(|(_, point)| point),
                    Some(point),
                    self.head.map(|(sequence, _)| sequence),
                )
            } else {
                ((fingers != 0).then_some(point), None, None)
            };
            let buttons = if c.buttonpad {
                u8::from(p[0] & 3 != 0)
            } else {
                p[0] & 3
            };
            if buttons != self.buttons {
                self.buttons = buttons;
                inputs.push(Input::Buttons(buttons));
            }
            // Original semi-MT initializes its cached coordinates to zero.
            // Compatibility input follows that software default; the raw
            // contact retains None and no head sequence until one is observed.
            if let Some((x, y)) = primary.or_else(|| (fingers == 2).then_some((0, 0))) {
                let scale = |value: i32, high: u16| {
                    (value.clamp(0, i32::from(high)) as u32 * u32::from(crate::input::POINTER_MAX)
                        / u32::from(high)) as u16
                };
                inputs.push(Input::Move {
                    x: scale(x, c.bounds.maximum.0),
                    y: scale(y, c.bounds.maximum.1),
                });
            }
            Report::Contacts(Contact {
                fingers,
                primary,
                secondary,
                head_sequence,
                buttons,
                pressure: Some(Pressure::Observed {
                    pressure: (p[1] & 0xf0) | ((p[4] & 0xf0) >> 4),
                    width: ((p[0] & 0x30) >> 2) | ((p[3] & 0x30) >> 4),
                }),
            })
        };
        self.frames.push_back(Frame {
            raw: p,
            length: 6,
            native_sequence: sequence,
            report,
        });
        self.position = 0;
        Ok(())
    }
}
