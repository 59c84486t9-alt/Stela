// SPDX-License-Identifier: GPL-2.0-only
// Linux Synaptics reference: Copyright (c) 1997 C. Scott Ananian;
// 1998-2000 Bruce Kalk; 2001 Stefan Gmeiner; 2003 Peter Osterlund,
// Dmitry Torokhov. Source identities and scope: input/THIRD_PARTY.md.
//! Conventional Synaptics absolute PS/2 operation under the existing i8042 owner.
//! Firmware queries and six-byte packets keep their bytes, including
//! acknowledged advanced/image-mode secondary-contact/count records.
//! Four/extended-button records keep their targets and validity. Physical
//! passthrough commands and wrapped records preserve parent acknowledgements;
//! One ordinary physical mouse child is negotiated and keeps its
//! own input. Vendor children, guest binding and DMI policy remain separate.
//! ForcePad timing requires a matched native firmware identifier.
use super::*;
pub mod agm;
pub mod board;
pub mod buttons;
pub mod child;
mod forcepad;
pub mod passthrough;

const EXTENDED: u32 = 1 << 23;
const AGM_CAPABILITIES: u32 = (1 << 19) | (1 << 11);
const FRAME_LIMIT: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Identity(u32),
    Capabilities(u32),
    Unsupported { query: u8, bits: u32 },
    Geometry,
    IdentityChanged,
    SequenceExhausted,
    NoPassthrough,
    ForcepadFormat,
    ChildReply(u8),
    ChildUnsolicited,
    ChildReset([u8; 2]),
    ChildIdentityChanged,
    ChildActive,
    ChildScrollUnsupported,
    Packet { index: u8, byte: u8 },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Query {
    pub id: u8,
    pub bytes: [u8; 3],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueryProgress {
    pub id: u8,
    pub bytes: [u8; 3],
    pub received: u8,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capabilities {
    pub queries: Vec<Query>,
    pub identity: u32,
    pub model: u32,
    pub firmware: u32,
    pub capabilities: u32,
    pub extended: u32,
    pub extended_0c: u32,
    pub extended_10: u32,
    pub board: Option<u16>,
    pub resolution: Option<(u8, u8)>,
    /// Observed firmware bounds; None keeps the donor's documented nominal
    /// coordinate range, never an invented queried hardware value.
    pub minimum: Option<(u16, u16)>,
    pub maximum: Option<(u16, u16)>,
    /// Source PnP/board software correction, never a replacement firmware query.
    pub coordinate_quirk: Option<board::Bounds>,
    /// Present only after the complete SET_MODE2 sequence is acknowledged.
    pub mode: Option<u8>,
    /// Set only after the separate source advanced-mode command is acknowledged.
    pub advanced_mode: bool,
}
impl Capabilities {
    fn extended(&self) -> bool {
        self.capabilities & EXTENDED != 0
    }
    fn new_absolute(&self) -> bool {
        self.model & 0x80 != 0
    }
    fn image_sensor(&self) -> bool {
        self.extended_0c & (1 << 11) != 0
    }
    /// Effective configured bounds: selected source quirk, otherwise
    /// observed firmware bounds or the documented nominal fallback.
    pub fn bounds(&self) -> ((u16, u16), (u16, u16)) {
        if let Some(quirk) = self.coordinate_quirk {
            return (quirk.minimum, quirk.maximum);
        }
        (
            self.minimum.unwrap_or((1472, 1408)),
            self.maximum.unwrap_or((5472, 4448)),
        )
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame {
    pub raw: [u8; 6],
    /// Host ordering shared with AGM records; never a device scan timestamp.
    pub native_sequence: u64,
    /// Source wrap/edge conversion, before pointer-range normalization.
    pub x: i16,
    pub y: i16,
    pub pressure: u8,
    /// Raw protocol W encoding, not an inferred physical contact width.
    pub width: u8,
    /// Finger-count encoding; this does not supply separate coordinates.
    pub fingers: Option<u8>,
    pub touching: Option<bool>,
    /// Source decoded left/right/middle/back/forward bits. Clickpad compatibility
    /// publishes its advertised left button only; raw right remains observable.
    pub buttons: u8,
    /// None is no source update, including firmware8.1/8.2 clear-ExtBit packets.
    pub extended_buttons: Option<buttons::Extended>,
    /// Source middle-button scroll record, kept independently of position.
    pub scroll: i8,
}
#[derive(Debug, Default)]
pub struct Poll {
    pub inputs: Vec<Input>,
    pub frames: Vec<Frame>,
    pub advanced: Vec<agm::Record>,
    pub passthrough: Vec<passthrough::Record>,
    pub child_inputs: Vec<Input>,
    pub child_horizontal: Vec<i8>,
}
pub(super) struct Engine {
    pub(super) high_rate: bool,
    pub(super) capabilities: Option<Capabilities>,
    forcepad: Option<forcepad::State>,
    child: Option<child::Mouse>,
    firmware_id: Option<alloc::string::String>,
    packet: [u8; 6],
    position: usize,
    start: u64,
    relaxed: Option<bool>,
    buttons: u8,
    touching: bool,
    frames: VecDeque<Frame>,
    advanced: VecDeque<agm::Record>,
    passthrough: VecDeque<passthrough::Record>,
    format_transition: bool,
    sequence: u64,
    count_observation: Option<(u64, u8)>,
    queries: Vec<Query>,
    query: Option<QueryProgress>,
}
impl Engine {
    fn new(high_rate: bool) -> Self {
        Self {
            high_rate,
            capabilities: None,
            forcepad: None,
            child: None,
            firmware_id: None,
            packet: [0; 6],
            position: 0,
            start: 0,
            relaxed: None,
            buttons: 0,
            touching: false,
            frames: VecDeque::new(),
            advanced: VecDeque::new(),
            passthrough: VecDeque::new(),
            format_transition: false,
            sequence: 0,
            count_observation: None,
            queries: Vec::new(),
            query: None,
        }
    }
    /// An engine for the touchpad `firmware_id` names: a `PNP:` identifier
    /// selects its ForcePad and board coordinate profiles.
    pub(super) fn for_firmware(high_rate: bool, firmware_id: Option<&str>) -> Self {
        let mut engine = Self::new(high_rate);
        if let Some(firmware_id) = firmware_id.filter(|id| id.starts_with("PNP: ")) {
            engine.firmware_id = Some(alloc::string::String::from(firmware_id));
            if forcepad::matches(firmware_id) {
                engine.forcepad = Some(forcepad::State::default());
            }
        }
        engine
    }
    pub(super) fn backpressured(&self) -> bool {
        self.frames.len() + self.advanced.len() + self.passthrough.len() >= FRAME_LIMIT
            || self.child.as_ref().is_some_and(child::Mouse::backpressured)
    }
    pub(super) fn input_byte(&self, byte: u8) -> bool {
        self.position != 0
            || !matches!(byte, ACK | RESEND | 0xfc | 0xfd)
                && self.capabilities.as_ref().is_some_and(|c| {
                    if c.new_absolute() {
                        byte & 0xc0 == 0x80
                    } else {
                        byte & 0xc0 == 0xc0
                    }
                })
    }
    pub(super) fn expire(&self, now: u64, timeout: u64) -> Result<(), ErrorKind> {
        if self.position != 0 && now.wrapping_sub(self.start) >= timeout {
            return Err(ErrorKind::PacketTimeout(Port::Mouse));
        }
        Ok(())
    }
    pub(super) fn release(&mut self, inputs: &mut Vec<Input>) {
        self.position = 0;
        self.touching = false;
        if let Some(child) = &mut self.child {
            child.release();
        }
        if let Some(state) = &mut self.forcepad {
            *state = forcepad::State::default();
        }
        if self.buttons != 0 {
            self.buttons = 0;
            inputs.push(
                if self
                    .capabilities
                    .as_ref()
                    .is_some_and(|c| c.capabilities & 8 != 0)
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
        if self.frames.len() + self.advanced.len() + self.passthrough.len()
            == FRAME_LIMIT + QUEUE_LIMIT
        {
            return Err(ErrorKind::QueueFull);
        }
        let c = self
            .capabilities
            .as_ref()
            .ok_or(ErrorKind::NotInitialized)?;
        if self.position == 0 {
            self.start = now;
        }
        let index = self.position;
        self.packet[index] = byte;
        self.position += 1;
        if self.position == 2 && self.packet[..2] == [0xaa, 0] {
            return Err(ErrorKind::DeviceReset(Port::Mouse));
        }
        let strict_mask = if c.new_absolute() {
            [0xc8, 0, 0, 0xc8, 0, 0]
        } else {
            [0xc0, 0x60, 0, 0xc0, 0x60, 0]
        };
        let relaxed_mask = [0xc0, 0, 0, 0xc0, 0, 0];
        let mask = if c.new_absolute() && self.relaxed != Some(false) {
            relaxed_mask[index]
        } else {
            strict_mask[index]
        };
        let expected = if c.new_absolute() {
            [0x80, 0, 0, 0xc0, 0, 0]
        } else {
            [0xc0, 0, 0, 0x80, 0, 0]
        };
        if byte & mask != expected[index] {
            return Err(ErrorKind::Synaptics(Error::Packet {
                index: index as u8,
                byte,
            }));
        }
        if self.position != 6 {
            return Ok(());
        }
        if c.new_absolute() && self.relaxed.is_none() {
            self.relaxed = Some((0..5).any(|i| self.packet[i] & strict_mask[i] != expected[i]));
        }
        let p = self.packet;
        let native_sequence = self.sequence;
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(ErrorKind::Synaptics(Error::SequenceExhausted))?;
        if c.capabilities & 0x80 != 0 && passthrough::is_packet(p) {
            let mode = c.mode.ok_or(ErrorKind::NotInitialized)?;
            let programmed_format = if self.format_transition {
                None
            } else {
                Some(if mode & 2 != 0 {
                    passthrough::Format::Four
                } else {
                    passthrough::Format::Three
                })
            };
            let record = passthrough::Record {
                raw: p,
                native_sequence,
                programmed_format,
            };
            self.passthrough.push_back(record);
            self.position = 0;
            if let Some(child) = &mut self.child {
                child.receive(record, now, timeout)?;
            }
            return Ok(());
        }
        let (x, y, pressure, width) = if c.new_absolute() {
            (
                ((u16::from(p[3] & 0x10)) << 8) | (u16::from(p[1] & 15) << 8) | u16::from(p[4]),
                ((u16::from(p[3] & 0x20)) << 7) | (u16::from(p[1] & 0xf0) << 4) | u16::from(p[5]),
                p[2],
                ((p[0] & 0x30) >> 2) | ((p[0] & 4) >> 1) | ((p[3] & 4) >> 2),
            )
        } else {
            (
                (u16::from(p[1] & 31) << 8) | u16::from(p[2]),
                (u16::from(p[4] & 31) << 8) | u16::from(p[5]),
                ((p[0] & 0x30) << 2) | (p[3] & 0x3f),
                ((p[1] & 0x80) >> 4) | ((p[0] & 4) >> 1),
            )
        };
        if c.new_absolute() && c.advanced_mode && width == 2 {
            let record = agm::decode(p, native_sequence);
            if let agm::Data::Count(count) = record.data {
                self.count_observation = Some((native_sequence, count));
            }
            self.advanced.push_back(record);
            self.position = 0;
            return Ok(());
        }
        let coordinate = |v: u16| {
            if v > 8176 {
                v as i16 - 8192
            } else if v == 8176 {
                6143
            } else {
                v as i16
            }
        };
        let (x, y) = (coordinate(x), coordinate(y));
        let clickpad = c.new_absolute() && c.extended_0c & (1 << 20) != 0;
        let middle = c.capabilities & (1 << 18) != 0;
        let is_forcepad = self.forcepad.is_some();
        let mut buttons = if let Some(state) = &mut self.forcepad {
            u8::from(state.update(pressure, width, (p[0] ^ p[3]) & 1 != 0, now)) | (p[0] & 2)
        } else if clickpad {
            ((p[0] ^ p[3]) & 1) | (p[0] & 2)
        } else {
            (p[0] & 3)
                | if c.new_absolute() && middle {
                    ((p[0] ^ p[3]) & 1) << 2
                } else {
                    0
                }
        };
        let four = c.new_absolute() && c.capabilities & 8 != 0;
        if four {
            buttons |= ((p[0] ^ p[3]) & 1) << 4;
            buttons |= ((p[0] ^ p[3]) & 2) << 2;
        }
        let scroll = if c.new_absolute() && middle && !clickpad && !is_forcepad && width == 2 {
            p[1] as i8
        } else {
            0
        };
        let fingers = if c.image_sensor() {
            if pressure == 0 {
                0
            } else if width >= 4 {
                1
            } else if width == 0 {
                2
            } else if width == 1 {
                self.count_observation
                    .map(|(_, count)| count)
                    .filter(|count| *count != 0)
                    .unwrap_or(3)
            } else {
                4
            }
        } else if pressure == 0 || x <= 1 {
            0
        } else if c.extended() && (c.capabilities & 2 != 0 || c.advanced_mode) && width <= 1 {
            width + 2
        } else {
            1
        };
        if scroll != 0 {
            self.frames.push_back(Frame {
                raw: p,
                native_sequence,
                x,
                y,
                pressure,
                width,
                fingers: None,
                touching: None,
                buttons,
                extended_buttons: None,
                scroll,
            });
            self.position = 0;
            return Ok(());
        }
        if c.image_sensor() {
            self.touching = fingers != 0;
        } else if pressure > 30 {
            self.touching = true;
        } else if pressure < 25 {
            self.touching = false;
        }
        self.frames.push_back(Frame {
            raw: p,
            native_sequence,
            x,
            y,
            pressure,
            width,
            fingers: Some(fingers),
            touching: Some(self.touching),
            buttons,
            extended_buttons: buttons::decode(c, p),
            scroll,
        });
        self.position = 0;
        if let Some(buttons::Extended {
            target: buttons::Target::Trackstick(buttons),
            ..
        }) = self.frames.back().unwrap().extended_buttons
            && let Some(child) = &mut self.child
        {
            child.external_buttons(buttons)?;
        }
        let buttons = if clickpad { buttons & !2 } else { buttons };
        if buttons != self.buttons {
            self.buttons = buttons;
            inputs.push(if four {
                Input::MouseButtons(buttons)
            } else {
                Input::Buttons(buttons)
            });
        }
        if fingers != 0 {
            let (min, max) = c.bounds();
            let scale = |v: i16, low: u16, high: u16| {
                ((i32::from(v) - i32::from(low)).clamp(0, i32::from(high - low)) as u32
                    * u32::from(crate::input::POINTER_MAX)
                    / u32::from(high - low)) as u16
            };
            inputs.push(Input::Move {
                x: scale(x, min.0, max.0),
                y: crate::input::POINTER_MAX - scale(y, min.1, max.1),
            });
        }
        Ok(())
    }
}
impl<R: Registers, T: Timer> Controller<R, T> {
    /// Explicit ordinary touchpad attachment. The platform must establish the
    /// same native i8042 grant as `new`, select a conventional non-ForcePad
    /// profile and resolve board quirks separately. High rate selects the source
    /// 80pps mode; false selects 40pps. Identity/capabilities are queried.
    pub fn new_synaptics(
        registers: R,
        timer: T,
        config: Config,
        high_rate: bool,
    ) -> Result<Self, super::Error> {
        if !config.mouse {
            return Err(ErrorKind::InvalidConfiguration.into());
        }
        timer.check_duration(50_001).map_err(ErrorKind::Clock)?;
        let mut controller = Self::new(registers, timer, config)?;
        controller.synaptics = Some(Engine::new(high_rate));
        Ok(controller)
    }
    /// ForcePad attachment selected by the native firmware identifier.
    /// Only the pinned source's PNP SYN300D/SYN3014 profiles are admitted.
    /// The caller still owns the i8042 grant and remaining board validation.
    pub fn new_synaptics_forcepad(
        registers: R,
        timer: T,
        config: Config,
        high_rate: bool,
        firmware_id: &str,
    ) -> Result<Self, super::Error> {
        if !forcepad::matches(firmware_id) {
            return Err(ErrorKind::InvalidConfiguration.into());
        }
        Self::new_synaptics_pnp(registers, timer, config, high_rate, firmware_id)
    }
    /// Attach using the native firmware PnP identifier. Source-listed
    /// ForcePad and queried-board coordinate quirks are selected from that
    /// identifier; other platform/board obligations remain explicit.
    pub fn new_synaptics_pnp(
        registers: R,
        timer: T,
        config: Config,
        high_rate: bool,
        firmware_id: &str,
    ) -> Result<Self, super::Error> {
        if !firmware_id.starts_with("PNP: ") {
            return Err(ErrorKind::InvalidConfiguration.into());
        }
        let mut controller = Self::new_synaptics(registers, timer, config, high_rate)?;
        controller.synaptics = Some(Engine::for_firmware(high_rate, Some(firmware_id)));
        Ok(controller)
    }
    pub fn synaptics_capabilities(&self) -> Option<&Capabilities> {
        self.synaptics.as_ref()?.capabilities.as_ref()
    }
    /// Exact partial/rejected bytes remain in their owner after a framing fault.
    pub fn synaptics_fragment(&self) -> Option<&[u8]> {
        self.synaptics.as_ref().map(|e| &e.packet[..e.position])
    }
    pub fn synaptics_queries(&self) -> Option<&[Query]> {
        self.synaptics.as_ref().map(|e| e.queries.as_slice())
    }
    pub fn synaptics_query_progress(&self) -> Option<&QueryProgress> {
        self.synaptics.as_ref()?.query.as_ref()
    }
    pub fn drain_synaptics_frames(&mut self) -> Vec<Frame> {
        self.synaptics
            .as_mut()
            .map_or_else(Vec::new, |e| e.frames.drain(..).collect())
    }
    pub fn drain_synaptics_advanced(&mut self) -> Vec<agm::Record> {
        self.synaptics
            .as_mut()
            .map_or_else(Vec::new, |e| e.advanced.drain(..).collect())
    }
    pub fn drain_synaptics_passthrough(&mut self) -> Vec<passthrough::Record> {
        self.synaptics
            .as_mut()
            .map_or_else(Vec::new, |e| e.passthrough.drain(..).collect())
    }
    /// Last count packet in the current acknowledged mode epoch.
    pub fn synaptics_count_observation(&self) -> Option<(u64, u8)> {
        self.synaptics.as_ref()?.count_observation
    }
    pub fn poll_synaptics(&mut self) -> Result<Poll, super::Error> {
        if self.synaptics.is_none() {
            return Err(ErrorKind::NotInitialized.into());
        }
        let inputs = self.poll()?;
        Ok(Poll {
            inputs,
            frames: self.drain_synaptics_frames(),
            advanced: self.drain_synaptics_advanced(),
            passthrough: self.drain_synaptics_passthrough(),
            child_inputs: self.drain_synaptics_child_inputs(),
            child_horizontal: self.drain_synaptics_child_horizontal(),
        })
    }
    fn synaptics_sliced(&mut self, value: u8) -> Result<(), ErrorKind> {
        self.sliced_command(value)
    }
    fn synaptics_query(&mut self, queries: &mut Vec<Query>, id: u8) -> Result<u32, ErrorKind> {
        self.synaptics.as_mut().unwrap().query = Some(QueryProgress {
            id,
            bytes: [0; 3],
            received: 0,
        });
        self.synaptics_sliced(id)?;
        self.device_command(Port::Mouse, GET_INFO, &[])?;
        let start = self.timer.start();
        let mut bytes = [0; 3];
        for (index, byte) in bytes.iter_mut().enumerate() {
            let result = self.response(Port::Mouse, start, self.config.command_timeout_us);
            // A late read is a failed response but still consumed its
            // byte. Keep that observation with this query before propagating.
            if let Some(observed) = self.observed_response {
                *byte = observed.data;
            }
            let progress = self.synaptics.as_mut().unwrap().query.as_mut().unwrap();
            if self.observed_response.is_some() {
                progress.bytes[index] = *byte;
                progress.received += 1;
            }
            result?;
            if self.expired(start, self.config.command_timeout_us) {
                return Err(ErrorKind::Timeout(Phase::Response));
            }
        }
        queries.push(Query { id, bytes });
        self.synaptics
            .as_mut()
            .unwrap()
            .queries
            .push(Query { id, bytes });
        Ok(u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]))
    }
    pub(super) fn initialize_synaptics(&mut self) -> Result<(), ErrorKind> {
        self.synaptics.as_mut().unwrap().queries.clear();
        let mut queries = Vec::new();
        let identity = self.synaptics_query(&mut queries, 0)?;
        if identity & 0xff00 != 0x4700 {
            return Err(ErrorKind::Synaptics(Error::Identity(identity)));
        }
        let major = identity & 15;
        let version = (major << 8) | (identity >> 16);
        let model = self.synaptics_query(&mut queries, 3)?;
        let firmware = self.synaptics_query(&mut queries, 10)?;
        let mut c = Capabilities {
            queries: Vec::new(),
            identity,
            model,
            firmware,
            capabilities: 0,
            extended: 0,
            extended_0c: 0,
            extended_10: 0,
            board: None,
            resolution: None,
            minimum: None,
            maximum: None,
            coordinate_quirk: None,
            mode: None,
            advanced_mode: false,
        };
        if version >= 0x705 {
            let modes = self.synaptics_query(&mut queries, 1)?;
            c.board = Some((((modes >> 16) as u16 & 0xfc) << 6) | ((modes >> 8) as u16 & 255));
            if modes & (2 << 16) != 0 {
                c.extended_10 = self.synaptics_query(&mut queries, 16)?;
            }
        }
        let capabilities = self.synaptics_query(&mut queries, 2)?;
        if version < 0x705 && capabilities & 0xff00 != 0x4700 {
            return Err(ErrorKind::Synaptics(Error::Capabilities(capabilities)));
        }
        c.capabilities = if capabilities & EXTENDED != 0 {
            capabilities
        } else {
            0
        };
        let requests = (c.capabilities >> 20) & 7;
        if requests >= 1 {
            c.extended = self.synaptics_query(&mut queries, 9)?;
        }
        if requests >= 4 {
            c.extended_0c = self.synaptics_query(&mut queries, 12)?;
        }
        if major >= 4 {
            let resolution = self.synaptics_query(&mut queries, 8)?.to_be_bytes();
            if resolution[1] != 0 && resolution[2] & 0x80 != 0 && resolution[3] != 0 {
                c.resolution = Some((resolution[1], resolution[3]));
            }
            let coords = |v: u32| {
                (
                    (((v >> 16) as u16) << 5) | ((v as u16 >> 8 & 15) << 1),
                    ((v as u16 & 255) << 5) | ((v as u16 >> 8 & 0xf0) >> 3),
                )
            };
            if requests >= 5 && c.extended_0c & (1 << 17) != 0 {
                c.maximum = Some(coords(self.synaptics_query(&mut queries, 13)?));
            }
            if (requests >= 7 || version == 0x801) && c.extended_0c & (1 << 13) != 0 {
                c.minimum = Some(coords(self.synaptics_query(&mut queries, 15)?));
            }
        }
        // Query everything required by this identity before mode mutation.
        if self.synaptics.as_ref().unwrap().forcepad.is_some() && !c.new_absolute() {
            return Err(ErrorKind::Synaptics(Error::ForcepadFormat));
        }
        let unsupported = [
            (
                2,
                if c.new_absolute() {
                    0
                } else {
                    c.capabilities & (0x80 | 8)
                },
            ),
            (
                9,
                if c.new_absolute() && ((c.extended >> 12) & 15) <= 8 {
                    0
                } else {
                    c.extended & 0xf000
                },
            ),
            (
                12,
                if c.new_absolute() {
                    0
                } else {
                    c.extended_0c & AGM_CAPABILITIES
                },
            ),
        ];
        for (query, bits) in unsupported {
            if bits != 0 {
                return Err(ErrorKind::Synaptics(Error::Unsupported { query, bits }));
            }
        }
        if let Some(firmware_id) = &self.synaptics.as_ref().unwrap().firmware_id {
            c.coordinate_quirk = board::bounds(firmware_id, c.board);
        }
        let (min, max) = c.bounds();
        if min.0 >= max.0 || min.1 >= max.1 {
            return Err(ErrorKind::Synaptics(Error::Geometry));
        }
        let engine = self.synaptics.as_ref().unwrap();
        if let Some(old) = &engine.capabilities
            && (old.identity != c.identity
                || old.model != c.model
                || old.firmware != c.firmware
                || old.capabilities != c.capabilities
                || old.extended != c.extended
                || old.extended_0c != c.extended_0c
                || old.extended_10 != c.extended_10
                || old.board != c.board
                || old.resolution != c.resolution
                || old.minimum != c.minimum
                || old.maximum != c.maximum
                || old.coordinate_quirk != c.coordinate_quirk)
        {
            return Err(ErrorKind::Synaptics(Error::IdentityChanged));
        }
        let mode = 0x80
            | if engine.high_rate { 0x40 } else { 0 }
            | if major >= 4 { 4 } else { 0 }
            | u8::from(c.extended());
        c.queries = queries;
        // Keep identity/query observations even if mode's ACK fails.
        self.synaptics.as_mut().unwrap().capabilities = Some(c);
        self.synaptics_sliced(mode)?;
        self.device_command(Port::Mouse, SET_RATE, &[0x14])?;
        let advanced = {
            let engine = self.synaptics.as_mut().unwrap();
            let c = engine.capabilities.as_mut().unwrap();
            c.mode = Some(mode);
            engine.position = 0;
            engine.relaxed = None;
            engine.touching = false;
            if let Some(state) = &mut engine.forcepad {
                *state = forcepad::State::default();
            }
            engine.format_transition = false;
            engine.count_observation = None;
            c.extended_0c & AGM_CAPABILITIES != 0
        };
        if advanced {
            self.synaptics_sliced(3)?;
            self.device_command(Port::Mouse, SET_RATE, &[0xc8])?;
            self.synaptics
                .as_mut()
                .unwrap()
                .capabilities
                .as_mut()
                .unwrap()
                .advanced_mode = true;
        }
        Ok(())
    }
    fn require_synaptics_passthrough(&self) -> Result<(), super::Error> {
        self.ready()?;
        if !self
            .synaptics_capabilities()
            .is_some_and(|c| c.capabilities & 0x80 != 0)
        {
            return Err(ErrorKind::Synaptics(Error::NoPassthrough).into());
        }
        Ok(())
    }
    /// Select the source's 40pps (<80) or 80pps (>=80) rate. Reporting
    /// disable, mode and reporting-enable acknowledgements are required. Other
    /// accepted mode bits and existing temporal/contact state remain intact.
    pub fn set_synaptics_rate(&mut self, requested: u32) -> Result<u16, super::Error> {
        self.ready()?;
        let mode = self
            .synaptics_capabilities()
            .and_then(|c| c.mode)
            .ok_or_else(|| super::Error::from(ErrorKind::NotInitialized))?;
        let high_rate = requested >= 80;
        let mode = if high_rate { mode | 0x40 } else { mode & !0x40 };
        let result = (|| {
            self.device_command(Port::Mouse, DISABLE_REPORTING, &[])?;
            self.synaptics_sliced(mode)?;
            self.device_command(Port::Mouse, SET_RATE, &[0x14])?;
            let engine = self.synaptics.as_mut().unwrap();
            engine.capabilities.as_mut().unwrap().mode = Some(mode);
            engine.high_rate = high_rate;
            self.device_command(Port::Mouse, ENABLE_REPORTING, &[])
        })();
        result.map_err(|kind| self.fail(kind))?;
        Ok(if high_rate { 80 } else { 40 })
    }
    /// Program the source firmware-relative mode0 and stop native ports. The
    /// i8042 owner and kept observations remain here; this does not grant a
    /// firmware/OS ownership handoff. Every disable/mode/inhibition step must
    /// succeed before held input is retired. Uncertain effects cannot replay.
    pub fn cleanup_synaptics(&mut self) -> Result<Vec<Input>, super::Error> {
        self.ready()?;
        if self.synaptics_capabilities().is_none() {
            return Err(ErrorKind::NotInitialized.into());
        }
        self.observed_response = None;
        let result = (|| {
            if self.config.keyboard {
                self.device_command(Port::Keyboard, DISABLE_REPORTING, &[])?;
            }
            if !self.stop_synaptics_mouse_inner()? {
                self.device_command(Port::Mouse, DISABLE_REPORTING, &[])?;
            }
            self.synaptics.as_mut().unwrap().format_transition = true;
            self.synaptics_sliced(0)?;
            self.device_command(Port::Mouse, SET_RATE, &[0x14])?;
            let engine = self.synaptics.as_mut().unwrap();
            let cap = engine.capabilities.as_mut().unwrap();
            cap.mode = Some(0);
            cap.advanced_mode = false;
            engine.format_transition = false;
            engine.count_observation = None;
            self.disable_ports()?;
            while let Some(byte) = self.pending.pop_front() {
                self.decode(byte)?;
            }
            Ok(())
        })();
        match result {
            Ok(()) => {
                self.state = State::Stopped;
                Ok(self.release_inputs())
            }
            Err(kind) => Err(self.fail(kind)),
        }
    }
    /// Send one child-port byte using sliced encoding and CLIENT_CMD.
    /// Success covers parent ACKs only. A child ACK/response remains a
    /// wrapped input record; no child identity, activation or owner is invented.
    pub fn write_synaptics_passthrough(&mut self, byte: u8) -> Result<(), super::Error> {
        self.require_synaptics_passthrough()?;
        if self
            .synaptics
            .as_ref()
            .unwrap()
            .child
            .as_ref()
            .is_some_and(|c| c.active)
        {
            return Err(ErrorKind::Synaptics(Error::ChildActive).into());
        }
        let result = self
            .synaptics_sliced(byte)
            .and_then(|()| self.device_command(Port::Mouse, SET_RATE, &[0x28]));
        result.map_err(|kind| self.fail(kind))
    }
    /// Acknowledge parent reporting-disable, source client-format mode and
    /// reporting-enable. The child owner must select its protocol and
    /// remain in command mode; this method never negotiates or activates it.
    /// Packets observed while the setting is uncertain keep format=None.
    pub fn configure_synaptics_passthrough(
        &mut self,
        format: passthrough::Format,
    ) -> Result<(), super::Error> {
        self.require_synaptics_passthrough()?;
        if self
            .synaptics
            .as_ref()
            .unwrap()
            .child
            .as_ref()
            .is_some_and(|c| c.active)
        {
            return Err(ErrorKind::Synaptics(Error::ChildActive).into());
        }
        let mode = self
            .synaptics_capabilities()
            .and_then(|c| c.mode)
            .ok_or_else(|| super::Error::from(ErrorKind::NotInitialized))?;
        let mode = match format {
            passthrough::Format::Three => mode & !2,
            passthrough::Format::Four => mode | 2,
        };
        let result = (|| {
            self.device_command(Port::Mouse, DISABLE_REPORTING, &[])?;
            self.synaptics.as_mut().unwrap().format_transition = true;
            self.synaptics_sliced(mode)?;
            self.device_command(Port::Mouse, SET_RATE, &[0x14])?;
            let engine = self.synaptics.as_mut().unwrap();
            engine.capabilities.as_mut().unwrap().mode = Some(mode);
            engine.format_transition = false;
            self.device_command(Port::Mouse, ENABLE_REPORTING, &[])
        })();
        result.map_err(|kind| self.fail(kind))
    }
}
