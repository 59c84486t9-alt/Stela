// SPDX-License-Identifier: GPL-2.0-only
// Original notices are held in ../elantech.rs and input/THIRD_PARTY.md.
// Input Multitouch Library: Copyright (c) 2008-2010 Henrik Rydberg.
//! V4 contact state and the source input-MT flags=0 pointer policy.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct V4Info {
    pub pattern: u8,
    pub ic_body: Option<[u8; 3]>,
    pub ic_version: u16,
    pub product_id: u16,
    pub resolution: [u8; 3],
    pub counts_per_mm: (u16, u16),
    /// Reported bus metadata; this does not grant access to another bus.
    pub bus: u8,
    pub traces: (u8, u8),
    pub trace_width: u16,
    pub middle_button: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct V4Slot {
    /// Software identity from the source 16-bit tracking counter, not a device ID.
    pub tracking_id: Option<u16>,
    /// Source unsigned accumulation. Motion can update an inactive/default slot.
    pub position: (u32, u32),
    pub pressure: u8,
    pub touch_major: u16,
    /// Most recent absolute head for this slot, absent before any head.
    pub head_sequence: Option<u64>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct V4State {
    pub slots: [V4Slot; 5],
    /// Source software counter. Assigned contact IDs use its low sixteen bits.
    pub next_tracking_id: u32,
    pub fingers: u8,
    /// Source advertised one/two/three/four-finger keys; five has no tool key.
    pub tools: u8,
    pub buttons: u8,
    /// Source compatibility axes, kept when no slot is active.
    pub pointer: (i32, i32),
    pub pressure: u8,
    pub width: u8,
}
impl Default for V4State {
    fn default() -> Self {
        Self {
            slots: [V4Slot {
                tracking_id: None,
                position: (0, 0),
                pressure: 0,
                touch_major: 0,
                head_sequence: None,
            }; 5],
            next_tracking_id: 0,
            fingers: 0,
            tools: 0,
            buttons: 0,
            pointer: (0, 0),
            pressure: 0,
            width: 0,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum V4Update {
    Status {
        present_mask: u8,
    },
    Head {
        wire_id: u8,
    },
    Motion {
        wire_id: u8,
        secondary_id: u8,
        weight: u8,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct V4Frame {
    pub update: V4Update,
    /// False for a source-ignored invalid primary/head slot; no input sync occurs.
    pub synchronized: bool,
    pub state: V4State,
}
impl V4State {
    pub(super) fn release(&mut self) {
        for slot in &mut self.slots {
            slot.tracking_id = None;
        }
        self.fingers = 0;
        self.tools = 0;
        self.buttons = 0;
        self.pressure = 0;
    }
    fn pointer_emulation(&mut self) -> bool {
        let mut oldest = None;
        let mut old_id = self.next_tracking_id as u16;
        let mut pressure = 0;
        self.fingers = 0;
        for (index, slot) in self.slots.iter().enumerate() {
            let Some(id) = slot.tracking_id else { continue };
            if id.wrapping_sub(old_id) & 0x8000 != 0 {
                oldest = Some(index);
                old_id = id;
            }
            if old_id == id {
                pressure = slot.pressure;
            }
            self.fingers += 1;
        }
        self.tools = if (1..=4).contains(&self.fingers) {
            1 << (self.fingers - 1)
        } else {
            0
        };
        if let Some(index) = oldest {
            let p = self.slots[index].position;
            self.pointer = (p.0 as i32, p.1 as i32);
            self.pressure = pressure;
        } else {
            self.pressure = 0;
        }
        oldest.is_some()
    }
}
impl Engine {
    pub(super) fn report_v4(&mut self, inputs: &mut Vec<Input>) -> Result<(), ErrorKind> {
        let c = self.capabilities.as_ref().unwrap();
        let p = self.packet;
        let valid = if c.crc_enabled {
            p[3] & 8 == 0
        } else if (c.firmware >> 16) & 15 == 7 && c.samples.unwrap()[1] == 0x2a {
            p[3] & 0x1c == 0x10
        } else {
            p[0] & 8 == 0 && p[3] & 0x1c == 0x10
        };
        if !valid || p[3] & 3 == 3 {
            self.last_fault = Some((p, 6));
            return Err(ErrorKind::Elantech(Error::Packet));
        }
        let sequence = self.sequence;
        self.sequence = sequence
            .checked_add(1)
            .ok_or(ErrorKind::Elantech(Error::SequenceExhausted))?;
        let state = &mut self.multitouch;
        let index = |id: u8| (1..=5).contains(&id).then(|| usize::from(id - 1));
        let mut synchronized = true;
        let update = match p[3] & 3 {
            0 => {
                let present_mask = p[1] & 31;
                for (i, slot) in state.slots.iter_mut().enumerate() {
                    if present_mask & (1 << i) == 0 {
                        slot.tracking_id = None;
                    }
                }
                V4Update::Status { present_mask }
            }
            1 => {
                let wire_id = p[3] >> 5;
                if let Some(i) = index(wire_id) {
                    let slot = &mut state.slots[i];
                    slot.position = (
                        u32::from((u16::from(p[1] & 15) << 8) | u16::from(p[2])),
                        u32::from(c.bounds.maximum.1)
                            .wrapping_sub(u32::from((u16::from(p[4] & 15) << 8) | u16::from(p[5]))),
                    );
                    if slot.tracking_id.is_none() {
                        slot.tracking_id = Some(state.next_tracking_id as u16);
                        state.next_tracking_id = state.next_tracking_id.wrapping_add(1);
                    }
                    slot.pressure = (p[1] & 0xf0) | (p[4] >> 4);
                    state.width = p[0] >> 4;
                    slot.touch_major = u16::from(state.width) * c.v4.unwrap().trace_width;
                    slot.head_sequence = Some(sequence);
                } else {
                    synchronized = false;
                }
                V4Update::Head { wire_id }
            }
            _ => {
                let wire_id = p[0] >> 5;
                let secondary_id = p[3] >> 5;
                let weight = if p[0] & 0x10 != 0 { 5 } else { 1 };
                if let Some(i) = index(wire_id) {
                    let motion = |slot: &mut V4Slot, x: u8, y: u8| {
                        slot.position.0 = slot
                            .position
                            .0
                            .wrapping_add((i32::from(x as i8) * i32::from(weight)) as u32);
                        slot.position.1 = slot
                            .position
                            .1
                            .wrapping_sub((i32::from(y as i8) * i32::from(weight)) as u32);
                    };
                    motion(&mut state.slots[i], p[1], p[2]);
                    if let Some(j) = index(secondary_id) {
                        motion(&mut state.slots[j], p[4], p[5]);
                    }
                } else {
                    synchronized = false;
                }
                V4Update::Motion {
                    wire_id,
                    secondary_id,
                    weight,
                }
            }
        };
        if synchronized {
            state.buttons = if c.buttonpad {
                u8::from(p[0] & 3 != 0)
            } else {
                p[0] & if c.v4.unwrap().middle_button { 7 } else { 3 }
            };
            if state.buttons != self.buttons {
                self.buttons = state.buttons;
                inputs.push(Input::Buttons(self.buttons));
            }
            if state.pointer_emulation() {
                let scale = |value: i32, high: u16| {
                    (value.clamp(0, i32::from(high)) as u32 * u32::from(crate::input::POINTER_MAX)
                        / u32::from(high)) as u16
                };
                inputs.push(Input::Move {
                    x: scale(state.pointer.0, c.bounds.maximum.0),
                    y: scale(state.pointer.1, c.bounds.maximum.1),
                });
            }
        }
        self.frames.push_back(Frame {
            raw: p,
            length: 6,
            native_sequence: sequence,
            report: Report::Multitouch(V4Frame {
                update,
                synchronized,
                state: *state,
            }),
        });
        self.position = 0;
        Ok(())
    }
}
