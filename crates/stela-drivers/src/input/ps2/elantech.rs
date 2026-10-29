// SPDX-License-Identifier: GPL-2.0-only
// Elantech source: Copyright (C) 2007-2009 Arjan Opmeer.
// Trademarks are the property of their respective owners.
//! Elantech v1-v4 PS/2 configuration and input under the i8042 owner.
//! Queried v3/v4 pointing sticks share this owner; an optional attachment can
//! require their presence. Board overrides and guest device binding are separate.
//! Raw reports, accumulated positions and software tracking remain distinct.
use super::*;
mod controls;
mod device;
mod trackpoint;
pub use controls::RegisterControl;
pub use trackpoint::{ReportIdChange, TrackpointReport};
mod v3;
mod v4;
pub use v4::{V4Frame, V4Info, V4Slot, V4State, V4Update};
const FRAME_LIMIT: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Knock([u8; 3]),
    Signature(u32),
    Version(u32),
    IdentityChanged,
    Trackpoint,
    TrackpointAbsent,
    TrackpointHardware(u8),
    ReportId([u8; 3]),
    BrokenAbsolute,
    Geometry,
    Register(u8),
    Readback { expected: u8, observed: u8 },
    Packet,
    SequenceExhausted,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryKind {
    Knock,
    FirmwareProbe,
    Firmware,
    Capabilities,
    Samples,
    FirmwareId,
    RangeSamples,
    IcBody,
    Resolution,
    ReportId,
    Register(u8),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Query {
    pub kind: QueryKind,
    pub bytes: [u8; 3],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueryProgress {
    pub kind: QueryKind,
    pub bytes: [u8; 3],
    pub received: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RangeSource {
    NominalV1,
    NominalV2,
    CapabilityTraces,
    FixedDpi,
    FirmwareCorrection,
    FirmwareQuery,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bounds {
    pub minimum: (u16, u16),
    pub maximum: (u16, u16),
    pub source: RangeSource,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegisterWrite {
    pub address: u8,
    pub requested: u8,
    pub acknowledged: bool,
    pub readback: Option<[u8; 3]>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capabilities {
    pub firmware: u32,
    pub hardware: u8,
    pub capabilities: [u8; 3],
    pub samples: Option<[u8; 3]>,
    pub firmware_id: Option<[u8; 3]>,
    pub bounds: Bounds,
    pub reports_pressure: bool,
    pub jumpy_cursor: bool,
    pub crc_enabled: bool,
    pub buttonpad: bool,
    pub trackpoint: bool,
    pub v4: Option<V4Info>,
    pub registers: Vec<RegisterWrite>,
    /// Source initialization criterion passed. V2/v3 require a successful read,
    /// without claiming that its returned byte echoes the programmed value.
    pub mode_accepted: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pressure {
    Observed {
        pressure: u8,
        width: u8,
    },
    /// Source values when no pressure is encoded:0/0 on absence,127/7 for two fingers.
    SourceFallback {
        pressure: u8,
        width: u8,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Contact {
    pub fingers: u8,
    /// Source coordinates, including Y inversion, before compatibility clamping.
    pub primary: Option<(i32, i32)>,
    /// Present only when a separate second coordinate is encoded.
    pub secondary: Option<(i32, i32)>,
    /// V3 two-finger primary references this observed head. Source
    /// reconnect keeps its historical cache; this sequence never implies a
    /// fresh coordinate was encoded in the tail. None also covers a missing head.
    pub head_sequence: Option<u64>,
    /// Advertised left/right/back/forward; parity bits do not invent middle keys.
    pub buttons: u8,
    pub pressure: Option<Pressure>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Report {
    Trackpoint(TrackpointReport),
    Multitouch(V4Frame),
    Contacts(Contact),
    Debounce,
    StartupSuppressed,
    /// First half of a v3 two-finger report; source emits no input yet.
    Head {
        point: (i32, i32),
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame {
    pub raw: [u8; 6],
    pub length: u8,
    pub native_sequence: u64,
    pub report: Report,
}
impl Frame {
    pub fn bytes(&self) -> &[u8] {
        &self.raw[..usize::from(self.length)]
    }
}
#[derive(Debug, PartialEq, Eq)]
pub struct Poll {
    pub inputs: Vec<Input>,
    pub frames: Vec<Frame>,
}
#[derive(Default)]
pub(super) struct Engine {
    capabilities: Option<Capabilities>,
    queries: Vec<Query>,
    query: Option<QueryProgress>,
    packet: [u8; 6],
    position: usize,
    start: u64,
    last_fault: Option<([u8; 6], usize)>,
    frames: VecDeque<Frame>,
    sequence: u64,
    buttons: u8,
    single_finger_reports: u8,
    head: Option<(u64, (i32, i32))>,
    multitouch: V4State,
    controls: Vec<RegisterControl>,
    trackpoint_required: bool,
    trackpoint_buttons: u8,
    report_id: Option<ReportIdChange>,
}
impl Engine {
    pub(super) fn backpressured(&self) -> bool {
        self.frames.len() >= FRAME_LIMIT
    }
    pub(super) fn input_byte(&self, byte: u8) -> bool {
        self.position != 0 || !matches!(byte, ACK | RESEND | 0xfc | 0xfd)
    }
    pub(super) fn expire(&mut self, now: u64, timeout: u64) -> Result<(), ErrorKind> {
        if self.position != 0 && now.wrapping_sub(self.start) >= timeout {
            self.last_fault = Some((self.packet, self.position));
            return Err(ErrorKind::PacketTimeout(Port::Mouse));
        }
        Ok(())
    }
    pub(super) fn release(&mut self, inputs: &mut Vec<Input>) {
        self.position = 0;
        self.single_finger_reports = 0;
        self.multitouch.release();
        if self.trackpoint_buttons != 0 {
            self.trackpoint_buttons = 0;
            inputs.push(Input::MouseButtons(0));
        }
        if self.buttons != 0 {
            self.buttons = 0;
            inputs.push(
                if self
                    .capabilities
                    .as_ref()
                    .is_some_and(|c| c.firmware < 0x020000 && c.capabilities[0] & 4 != 0)
                {
                    Input::MouseButtons(0)
                } else {
                    Input::Buttons(0)
                },
            );
        }
    }
    pub(super) fn feed(
        &mut self,
        byte: u8,
        now: u64,
        timeout: u64,
        inputs: &mut Vec<Input>,
    ) -> Result<(), ErrorKind> {
        self.expire(now, timeout)?;
        if self.frames.len() >= FRAME_LIMIT + QUEUE_LIMIT {
            return Err(ErrorKind::QueueFull);
        }
        let c = self
            .capabilities
            .as_ref()
            .ok_or(ErrorKind::NotInitialized)?;
        if self.position == 0 {
            self.start = now;
            self.packet = [0; 6];
        }
        self.packet[self.position] = byte;
        self.position += 1;
        if self.position == 2 && self.packet[..2] == [BAT_OK, 0] {
            self.last_fault = Some((self.packet, self.position));
            return Err(ErrorKind::DeviceReset(Port::Mouse));
        }
        let length = if c.hardware == 1 { 4 } else { 6 };
        if self.position != length {
            return Ok(());
        }
        let p = self.packet;
        if c.trackpoint && p[3] & 15 == 6 && (c.hardware == 4 || c.hardware == 3 && !c.crc_enabled)
        {
            return self.report_trackpoint(inputs);
        }
        if c.hardware == 3 {
            return self.report_v3(inputs);
        }
        if c.hardware == 4 {
            return self.report_v4(inputs);
        }
        let debounce = c.hardware == 2 && p == [0x84, 0xff, 0xff, 0x02, 0xff, 0xff];
        let valid = if c.hardware == 1 {
            let parity = |value: u8| u8::from(value.count_ones().is_multiple_of(2));
            let (p1, p2) = if c.firmware < 0x020000 {
                ((p[0] >> 5) & 1, (p[0] >> 4) & 1)
            } else {
                ((p[0] >> 4) & 1, (p[0] >> 5) & 1)
            };
            parity(p[1]) == p1 && parity(p[2]) == p2 && parity(p[3]) == (p[0] >> 2) & 1
        } else if c.reports_pressure {
            (p[0] & 0x0c) == 4 && (p[3] & 15) == 2
        } else if p[0] & 0xc0 == 0x80 {
            p[0] & 0x0c == 0x0c && p[3] & 0x0e == 8
        } else {
            p[0] & 0x3c == 0x3c && p[1] & 0xf0 == 0 && p[3] & 0x3e == 0x38 && p[4] & 0xf0 == 0
        };
        if !debounce && !valid {
            self.last_fault = Some((p, length));
            return Err(ErrorKind::Elantech(Error::Packet));
        }
        let sequence = self.sequence;
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(ErrorKind::Elantech(Error::SequenceExhausted))?;
        let report = if debounce {
            Report::Debounce
        } else {
            let mut fingers = if c.hardware == 1 && c.firmware < 0x020000 {
                ((p[1] & 0x80) >> 7) + ((p[1] & 0x30) >> 4)
            } else {
                p[0] >> 6
            };
            if c.hardware == 2 && fingers == 3 && p[3] & 0x80 != 0 {
                fingers = 4;
            }
            let suppressed = if c.jumpy_cursor && fingers == 1 && self.single_finger_reports < 2 {
                self.single_finger_reports += 1;
                true
            } else {
                if fingers != 1 {
                    self.single_finger_reports = 0;
                }
                false
            };
            if suppressed {
                Report::StartupSuppressed
            } else {
                let rocker = c.hardware == 1 && c.firmware < 0x020000 && c.capabilities[0] & 4 != 0;
                let buttons = (p[0] & 3)
                    | if rocker {
                        ((p[0] & 0x40) >> 2) | ((p[0] & 0x80) >> 4)
                    } else {
                        0
                    };
                let (primary, secondary, pressure) = if fingers == 0 {
                    (
                        None,
                        None,
                        if c.reports_pressure {
                            Some(Pressure::SourceFallback {
                                pressure: 0,
                                width: 0,
                            })
                        } else {
                            None
                        },
                    )
                } else if c.hardware == 1 {
                    (
                        Some((
                            i32::from((u16::from(p[1] & 12) << 6) | u16::from(p[2])),
                            i32::from(c.bounds.maximum.1)
                                - i32::from((u16::from(p[1] & 3) << 8) | u16::from(p[3])),
                        )),
                        None,
                        None,
                    )
                } else if fingers == 2 {
                    (
                        Some((
                            i32::from(((u16::from(p[0] & 0x10) << 4) | u16::from(p[1])) << 2),
                            i32::from(c.bounds.maximum.1)
                                - i32::from(((u16::from(p[0] & 0x20) << 3) | u16::from(p[2])) << 2),
                        )),
                        Some((
                            i32::from(((u16::from(p[3] & 0x10) << 4) | u16::from(p[4])) << 2),
                            i32::from(c.bounds.maximum.1)
                                - i32::from(((u16::from(p[3] & 0x20) << 3) | u16::from(p[5])) << 2),
                        )),
                        c.reports_pressure.then_some(Pressure::SourceFallback {
                            pressure: 127,
                            width: 7,
                        }),
                    )
                } else {
                    (
                        Some((
                            i32::from((u16::from(p[1] & 15) << 8) | u16::from(p[2])),
                            i32::from(c.bounds.maximum.1)
                                - i32::from((u16::from(p[4] & 15) << 8) | u16::from(p[5])),
                        )),
                        None,
                        c.reports_pressure.then_some(Pressure::Observed {
                            pressure: (p[1] & 0xf0) | ((p[4] & 0xf0) >> 4),
                            width: ((p[0] & 0x30) >> 2) | ((p[3] & 0x30) >> 4),
                        }),
                    )
                };
                if buttons != self.buttons {
                    self.buttons = buttons;
                    inputs.push(if rocker {
                        Input::MouseButtons(buttons)
                    } else {
                        Input::Buttons(buttons)
                    });
                }
                if let Some((x, y)) = primary {
                    let scale = |value: i32, low: u16, high: u16| {
                        ((value - i32::from(low)).clamp(0, i32::from(high - low)) as u32
                            * u32::from(crate::input::POINTER_MAX)
                            / u32::from(high - low)) as u16
                    };
                    inputs.push(Input::Move {
                        x: scale(x, c.bounds.minimum.0, c.bounds.maximum.0),
                        y: scale(y, c.bounds.minimum.1, c.bounds.maximum.1),
                    });
                }
                Report::Contacts(Contact {
                    fingers,
                    primary,
                    secondary,
                    head_sequence: None,
                    buttons,
                    pressure,
                })
            }
        };
        self.frames.push_back(Frame {
            raw: p,
            length: length as u8,
            native_sequence: sequence,
            report,
        });
        self.position = 0;
        Ok(())
    }
}
impl<R: Registers, T: Timer> Controller<R, T> {
    /// Explicit ordinary Elantech attachment under the same native i8042 grant.
    /// Firmware selects v1-v4 and queried v3/v4 pointing-stick presence.
    /// Older integrated/board override profiles remain explicit unsupported
    /// operations, never silently generic mice.
    pub fn new_elantech(registers: R, timer: T, config: Config) -> Result<Self, super::Error> {
        if !config.mouse {
            return Err(ErrorKind::InvalidConfiguration.into());
        }
        timer.check_duration(500_000).map_err(ErrorKind::Clock)?;
        let mut controller = Self::new(registers, timer, config)?;
        controller.elantech = Some(Engine::default());
        Ok(controller)
    }
    pub fn elantech_capabilities(&self) -> Option<&Capabilities> {
        self.elantech.as_ref()?.capabilities.as_ref()
    }
    /// Source software MT state. Tracking IDs and accumulated/default coordinates
    /// are separate from absolute-head provenance in each slot.
    pub fn elantech_multitouch(&self) -> Option<&V4State> {
        let engine = self.elantech.as_ref()?;
        (engine.capabilities.as_ref()?.hardware == 4).then_some(&engine.multitouch)
    }
    pub fn elantech_queries(&self) -> Option<&[Query]> {
        Some(&self.elantech.as_ref()?.queries)
    }
    pub fn drain_elantech_queries(&mut self) -> Vec<Query> {
        self.elantech
            .as_mut()
            .map_or_else(Vec::new, |e| core::mem::take(&mut e.queries))
    }
    pub fn elantech_query_progress(&self) -> Option<&QueryProgress> {
        self.elantech.as_ref()?.query.as_ref()
    }
    pub fn elantech_fragment(&self) -> Option<&[u8]> {
        self.elantech.as_ref().map(|e| {
            if let Some((raw, len)) = &e.last_fault {
                &raw[..*len]
            } else {
                &e.packet[..e.position]
            }
        })
    }
    pub fn drain_elantech_frames(&mut self) -> Vec<Frame> {
        self.elantech
            .as_mut()
            .map_or_else(Vec::new, |e| e.frames.drain(..).collect())
    }
    pub fn poll_elantech(&mut self) -> Result<Poll, super::Error> {
        self.ready()?;
        if self.elantech.is_none() {
            return Err(ErrorKind::NotInitialized.into());
        }
        let inputs = self.poll()?;
        Ok(Poll {
            inputs,
            frames: self.drain_elantech_frames(),
        })
    }
}
