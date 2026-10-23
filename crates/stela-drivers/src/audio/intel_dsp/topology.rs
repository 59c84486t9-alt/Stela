// SPDX-License-Identifier: GPL-2.0-only
//! Bounded original ALSA ABI5 topology admission for direct SOF DMIC capture.
//! The selected pipeline must contain HOST, BUFFER, DMIC DAI and SCHEDULER,
//! joined by actual topology edges. Unsupported processing, UUID, multi-core,
//! runtime controls and other DAI types refuse before any IPC or DMA effect.
//! Structs/tokens adapt pinned Linux asoc.h, sof/{topology,dai-intel}.h and
//! ipc3-topology.c. Copyright(c) 2018 Intel Corporation
//! Copyright (C) 2012 Texas Instruments Inc.; (C) 2015 Intel Corporation.
use super::{
    Controller, Error, Registers, State,
    dma::Stream,
    ipc::{put, word},
    registers::*,
};
use crate::{
    audio::{Direction, PcmFormat},
    bus::{
        dma::{mapping::DmaDomain, memory::PageSource},
        i2c::Timer,
    },
    firmware::Image,
};
use alloc::sync::Arc;
use alloc::{
    string::{String, ToString},
    vec,
    vec::Vec,
};

struct Widget<'a> {
    name: &'a str,
    sname: &'a str,
    kind: u32,
    tokens: Vec<Token<'a>>,
    id: u32,
}
#[derive(Clone, Copy)]
enum Value<'a> {
    Word(u32),
    String(&'a str),
}
struct Token<'a> {
    id: u32,
    value: Value<'a>,
}
fn text(bytes: &[u8]) -> Result<&str, Error> {
    let end = bytes.iter().position(|b| *b == 0).ok_or(Error::Topology)?;
    core::str::from_utf8(&bytes[..end]).map_err(|_| Error::Topology)
}
fn tokens(mut bytes: &[u8]) -> Result<Vec<Token<'_>>, Error> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let size = word(bytes, 0)? as usize;
        let kind = word(bytes, 4)?;
        let count = word(bytes, 8)? as usize;
        let stride = match kind {
            1 => 48,
            2..=5 => 8,
            _ => return Err(Error::UnsupportedTopology),
        };
        if count > 512
            || size != 12 + stride * count
            || size > bytes.len()
            || out.len() + count > 512
        {
            return Err(Error::Topology);
        }
        for index in 0..count {
            let at = 12 + index * stride;
            out.push(Token {
                id: word(bytes, at)?,
                value: if kind == 1 {
                    Value::String(text(&bytes[at + 4..at + 48])?)
                } else {
                    Value::Word(word(bytes, at + 4)?)
                },
            });
        }
        bytes = &bytes[size..];
    }
    Ok(out)
}
fn number(tokens: &[Token<'_>], id: u32, default: Option<u32>) -> Result<u32, Error> {
    let mut found = None;
    for token in tokens.iter().filter(|token| token.id == id) {
        let Value::Word(value) = token.value else {
            return Err(Error::Topology);
        };
        if found.replace(value).is_some() {
            return Err(Error::Topology);
        }
    }
    found.or(default).ok_or(Error::Topology)
}
fn string<'a>(tokens: &'a [Token<'a>], id: u32) -> Result<&'a str, Error> {
    let mut found = None;
    for token in tokens.iter().filter(|token| token.id == id) {
        let Value::String(value) = token.value else {
            return Err(Error::Topology);
        };
        if found.replace(value).is_some() {
            return Err(Error::Topology);
        }
    }
    found.ok_or(Error::Topology)
}
fn known(tokens: &[Token<'_>], allowed: &[u32]) -> Result<(), Error> {
    if tokens.iter().any(|t| !allowed.contains(&t.id)) {
        return Err(Error::UnsupportedTopology);
    }
    Ok(())
}
fn command(size: usize, code: u32) -> Vec<u8> {
    let mut bytes = vec![0; size];
    put(&mut bytes, 0, size as u32);
    put(&mut bytes, 4, code);
    bytes
}
fn component(
    widget: &Widget<'_>,
    pipeline: u32,
    kind: u32,
    size: usize,
    frame: u32,
) -> Result<Vec<u8>, Error> {
    if number(&widget.tokens, 404, Some(0))? != 0 {
        return Err(Error::UnsupportedTopology);
    }
    let mut message = command(size, if kind == 12 { 0x30200000 } else { 0x30010000 });
    put(&mut message, 8, widget.id);
    put(&mut message, 12, kind);
    put(&mut message, 16, pipeline);
    if kind != 12 {
        put(&mut message, 28, 36);
        put(&mut message, 36, number(&widget.tokens, 400, Some(0))?);
        put(&mut message, 40, number(&widget.tokens, 401, Some(0))?);
        put(&mut message, 48, frame);
    }
    Ok(message)
}

/// Keeps the original topology identity and actual firmware-table bytes.
/// It is a DMIC graph capability, never evidence that physical audio ran.
pub struct DmicTopology {
    messages: Vec<Vec<u8>>,
    host: u32,
    pipeline: u32,
    format: PcmFormat,
    sha256: [u8; 32],
    board: String,
    nhlt: Vec<u8>,
    hardware: String,
}
pub(super) struct Installed {
    pub host: u32,
    pub format: PcmFormat,
    pub sha256: [u8; 32],
    pub board: String,
    pub nhlt: Vec<u8>,
}
impl DmicTopology {
    /// Parse only a direct capture pipeline from the original catalog topology.
    ///
    /// # Safety
    /// `nhlt` is the retained, unmodified ACPI NHLT table of this controller's
    /// actual machine. `board` is the exact board key selected using actual
    /// firmware/machine identity, with the catalog topology chosen by that
    /// machine policy. Platform pin/clock/power ownership excludes firmware,
    /// OEM/AML and other drivers for these microphones. A matching string,
    /// PCI ID, forged table or successful DSP firmware boot supplies none of
    /// these electrical grants. No DMI-only fallback is implemented.
    pub unsafe fn from_firmware(
        image: Image<'_>,
        nhlt: &[u8],
        board: &str,
        pipeline: u32,
    ) -> Result<Self, Error> {
        if image.target().driver != "intel-dsp-topology"
            || image.target().revision != "cavs2.5-ipc3"
            || image.target().board != Some(board)
            || board.is_empty()
        {
            return Err(Error::Topology);
        }
        let (messages, host, format) = parse(image.bytes(), pipeline)?;
        validate_nhlt(nhlt, format)?;
        Ok(Self {
            messages,
            host,
            pipeline,
            format,
            sha256: image.sha256(),
            board: board.to_string(),
            nhlt: nhlt.to_vec(),
            hardware: image.target().hardware.to_string(),
        })
    }
    pub fn format(&self) -> PcmFormat {
        self.format
    }
    pub fn sha256(&self) -> [u8; 32] {
        self.sha256
    }
    pub fn pipeline(&self) -> u32 {
        self.pipeline
    }
}

fn parse(bytes: &[u8], pipeline: u32) -> Result<(Vec<Vec<u8>>, u32, PcmFormat), Error> {
    if bytes.len() > 4 * 1024 * 1024 || pipeline == 0 || pipeline > 65535 {
        return Err(Error::Topology);
    }
    let mut rest = bytes;
    let mut widgets = Vec::new();
    let mut routes = Vec::new();
    let mut links = Vec::new();
    let mut next_id = 1u32;
    while !rest.is_empty() {
        if word(rest, 0)? != 0x41536f43 || word(rest, 4)? != 5 || word(rest, 16)? != 36 {
            return Err(Error::Topology);
        }
        let kind = word(rest, 12)?;
        let size = word(rest, 24)? as usize;
        let index = word(rest, 28)?;
        let count = word(rest, 32)? as usize;
        if count > 4096 {
            return Err(Error::Topology);
        }
        let payload = rest
            .get(36..36usize.checked_add(size).ok_or(Error::Topology)?)
            .ok_or(Error::Topology)?;
        match kind {
            5 => {
                let mut data = payload;
                for _ in 0..count {
                    if word(data, 0)? != 132 {
                        return Err(Error::Topology);
                    }
                    let private = word(data, 128)? as usize;
                    let controls = word(data, 124)? as usize;
                    let end = 132usize
                        .checked_add(private)
                        .filter(|end| *end <= data.len())
                        .ok_or(Error::Topology)?;
                    if index == pipeline {
                        if controls != 0 || widgets.len() >= 4 {
                            return Err(Error::UnsupportedTopology);
                        }
                        widgets.push(Widget {
                            name: text(&data[8..52])?,
                            sname: text(&data[52..96])?,
                            kind: word(data, 4)?,
                            tokens: tokens(&data[132..end])?,
                            id: next_id,
                        });
                    }
                    data = &data[end..];
                    if controls > 64 {
                        return Err(Error::Topology);
                    }
                    for _ in 0..controls {
                        // Common 204-byte ctl header precedes each ctl-specific
                        // size; the final word of that extent is private size.
                        let fixed = word(data, 204)? as usize;
                        if fixed < 212 || fixed > data.len() {
                            return Err(Error::Topology);
                        }
                        let extra = word(data, fixed - 4)? as usize;
                        data = data
                            .get(fixed.checked_add(extra).ok_or(Error::Topology)?..)
                            .ok_or(Error::Topology)?;
                    }
                    next_id = next_id.checked_add(1).ok_or(Error::Topology)?;
                }
                if !data.is_empty() {
                    return Err(Error::Topology);
                }
            }
            4 => {
                if payload.len() != count * 132 {
                    return Err(Error::Topology);
                }
                for route in payload.as_chunks::<132>().0 {
                    routes.push((
                        text(&route[88..132])?,
                        text(&route[..44])?,
                        text(&route[44..88])?,
                    ));
                }
            }
            10 => {
                let mut data = payload;
                for _ in 0..count {
                    if word(data, 0)? != 1656 {
                        return Err(Error::UnsupportedTopology);
                    }
                    let extra = word(data, 1652)? as usize;
                    let end = 1656usize
                        .checked_add(extra)
                        .filter(|end| *end <= data.len())
                        .ok_or(Error::Topology)?;
                    links.push((text(&data[8..52])?, word(data, 1636)?, &data[1656..end]));
                    data = &data[end..];
                }
                if !data.is_empty() {
                    return Err(Error::Topology);
                }
            }
            // Metadata and unselected FE descriptions carry no effects here.
            7 | 8 | 12 => (),
            _ => return Err(Error::UnsupportedTopology),
        }
        rest = &rest[36 + size..];
    }
    if widgets.len() != 4 {
        return Err(Error::UnsupportedTopology);
    }
    for (i, widget) in widgets.iter().enumerate() {
        if widget.name.is_empty() || widgets[..i].iter().any(|other| other.name == widget.name) {
            return Err(Error::Topology);
        }
    }
    let host = widgets
        .iter()
        .find(|w| w.kind == 12)
        .ok_or(Error::UnsupportedTopology)?;
    let buffer = widgets
        .iter()
        .find(|w| w.kind == 16)
        .ok_or(Error::UnsupportedTopology)?;
    let dai = widgets
        .iter()
        .find(|w| matches!(w.kind, 13 | 14))
        .ok_or(Error::UnsupportedTopology)?;
    let sched = widgets
        .iter()
        .find(|w| w.kind == 17)
        .ok_or(Error::UnsupportedTopology)?;
    if sched.sname != dai.name {
        return Err(Error::UnsupportedTopology);
    }
    known(&host.tokens, &[353, 400, 401, 402, 404])?;
    known(&buffer.tokens, &[100, 101, 102, 404])?;
    known(&dai.tokens, &[154, 155, 156, 400, 401, 402, 404])?;
    known(&sched.tokens, &[200, 201, 202, 203, 204, 205, 206])?;
    if string(&dai.tokens, 154)? != "DMIC"
        || number(&dai.tokens, 156, None)? != 1
        || number(&dai.tokens, 155, None)? > 1
        || number(&sched.tokens, 203, Some(0))? != 0
        || number(&sched.tokens, 206, Some(0))? != 0
    {
        return Err(Error::UnsupportedTopology);
    }
    let frame = match string(&host.tokens, 402)? {
        "s16le" => 0,
        "s24le" => 1,
        "s32le" => 2,
        _ => return Err(Error::UnsupportedTopology),
    };
    if string(&host.tokens, 402)? != string(&dai.tokens, 402)? {
        return Err(Error::UnsupportedTopology);
    }
    let link = links
        .iter()
        .filter(|(name, _, _)| *name == dai.sname)
        .collect::<Vec<_>>();
    if link.len() != 1 || link[0].1 != 1 {
        return Err(Error::UnsupportedTopology);
    }
    let dmic = tokens(link[0].2)?;
    let (dai_message, format) = dmic_config(&dmic, number(&dai.tokens, 155, None)?, frame)?;
    let mut host_message = component(host, pipeline, 1, 76, frame)?;
    put(&mut host_message, 64, 1);
    put(&mut host_message, 72, number(&host.tokens, 353, Some(0))?);
    let mut dai_comp = component(dai, pipeline, 2, 80, frame)?;
    put(&mut dai_comp, 64, 1);
    put(&mut dai_comp, 68, number(&dai.tokens, 155, None)?);
    put(&mut dai_comp, 72, 2);
    let mut buffer_message = component(buffer, pipeline, 12, 44, frame)?;
    let buffer_bytes = number(&buffer.tokens, 100, None)?;
    let caps = number(&buffer.tokens, 101, None)?;
    if buffer_bytes == 0
        || buffer_bytes > 1024 * 1024
        || caps & !0x1ff != 0
        || caps & 0x21 != 0x21
        || number(&buffer.tokens, 102, Some(0))? != 0
    {
        return Err(Error::UnsupportedTopology);
    }
    put(&mut buffer_message, 28, buffer_bytes);
    put(&mut buffer_message, 32, caps);
    let mut pipe = command(48, 0x30100000);
    for (offset, value) in [
        (8, sched.id),
        (12, pipeline),
        (16, dai.id),
        (24, number(&sched.tokens, 200, None)?),
        (28, number(&sched.tokens, 201, Some(0))?),
        (32, number(&sched.tokens, 202, Some(0))?),
        (36, number(&sched.tokens, 204, None)?),
        (44, number(&sched.tokens, 205, Some(0))?),
    ] {
        put(&mut pipe, offset, value);
    }
    let period = word(&pipe, 24)?;
    if period == 0
        || period > 100_000
        || word(&pipe, 28)? > 10
        || word(&pipe, 44)? != 0
        || u64::from(period) * u64::from(format.rate) != u64::from(word(&pipe, 36)?) * 1_000_000
    {
        return Err(Error::UnsupportedTopology);
    }
    let selected_routes: Vec<_> = routes
        .iter()
        .filter(|(source, sink, _)| widgets.iter().any(|w| w.name == *source || w.name == *sink))
        .collect();
    if selected_routes.len() != 2
        || !selected_routes.iter().any(|&&(source, sink, control)| {
            source == dai.name && sink == buffer.name && control.is_empty()
        })
        || !selected_routes.iter().any(|&&(source, sink, control)| {
            source == buffer.name && sink == host.name && control.is_empty()
        })
    {
        return Err(Error::UnsupportedTopology);
    }
    let mut messages = vec![host_message, buffer_message, dai_comp, pipe];
    for (source, sink) in [(dai.id, buffer.id), (buffer.id, host.id)] {
        let mut edge = command(16, 0x30030000);
        put(&mut edge, 8, source);
        put(&mut edge, 12, sink);
        messages.push(edge);
    }
    messages.push(dai_message);
    let mut complete = command(12, 0x30130000);
    put(&mut complete, 8, sched.id);
    messages.push(complete);
    Ok((messages, host.id, format))
}

fn dmic_config(
    tokens: &[Token<'_>],
    index: u32,
    frame: u32,
) -> Result<(Vec<u8>, PcmFormat), Error> {
    known(
        tokens,
        &[
            154, 600, 601, 602, 603, 604, 605, 608, 609, 610, 700, 701, 702, 703, 704, 705, 706,
        ],
    )?;
    if string(tokens, 154)? != "DMIC" {
        return Err(Error::UnsupportedTopology);
    }
    let mut message = command(216, 0x80010000);
    put(&mut message, 8, 2);
    put(&mut message, 12, index);
    for (id, offset) in [
        (600, 56),
        (601, 60),
        (602, 64),
        (608, 68),
        (605, 84),
        (610, 96),
    ] {
        put(
            &mut message,
            offset,
            number(tokens, id, if id == 610 { Some(0) } else { None })?,
        );
    }
    let bits = number(tokens, 609, None)?;
    let duty_min = number(tokens, 603, None)?;
    let duty_max = number(tokens, 604, None)?;
    if !matches!(bits, 16 | 32)
        || (frame == 0 && bits != 16)
        || (frame != 0 && bits != 32)
        || !(20..=80).contains(&duty_min)
        || duty_max < duty_min
        || duty_max > 80
        || word(&message, 56)? != 1
        || word(&message, 60)? < 100_000
        || word(&message, 64)? < word(&message, 60)?
        || word(&message, 64)? > 19_200_000
        || word(&message, 68)? != 48_000
    {
        return Err(Error::UnsupportedTopology);
    }
    message[76..78].copy_from_slice(&(bits as u16).to_le_bytes());
    message[80..82].copy_from_slice(&(duty_min as u16).to_le_bytes());
    message[82..84].copy_from_slice(&(duty_max as u16).to_le_bytes());
    let count = word(&message, 84)? as usize;
    if !(1..=4).contains(&count) {
        return Err(Error::Topology);
    }
    let mut pdm = None;
    let mut active = 0;
    let mut channels = 0;
    let mut used = [false; 4];
    let mut fields = [0u8; 4];
    for token in tokens {
        if !(700..=706).contains(&token.id) {
            continue;
        }
        let Value::Word(value) = token.value else {
            return Err(Error::Topology);
        };
        if token.id == 700 {
            if value > 3 || active >= count || used[value as usize] {
                return Err(Error::Topology);
            }
            used[value as usize] = true;
            pdm = Some(active);
            active += 1;
        }
        let position = pdm.ok_or(Error::Topology)?;
        let field = 1u8 << (token.id - 700);
        if fields[position] & field != 0 {
            return Err(Error::Topology);
        }
        fields[position] |= field;
        if token.id != 700 && value > if token.id == 706 { 15 } else { 1 } {
            return Err(Error::Topology);
        }
        if matches!(token.id, 701 | 702) {
            channels += value;
        }
        let offset = 120 + position * 24 + 4 + (token.id as usize - 700) * 2;
        message[offset..offset + 2].copy_from_slice(&(value as u16).to_le_bytes());
    }
    if active != count
        || channels == 0
        || channels > 8
        || fields[..count].iter().any(|bits| bits & 7 != 7)
    {
        return Err(Error::Topology);
    }
    Ok((
        message,
        PcmFormat {
            rate: 48_000,
            bits: match frame {
                0 => 16,
                1 => 24,
                _ => 32,
            },
            channels: channels as u8,
        },
    ))
}

fn validate_nhlt(bytes: &[u8], format: PcmFormat) -> Result<(), Error> {
    if bytes.len() < 37
        || bytes.len() > 1024 * 1024
        || &bytes[..4] != b"NHLT"
        || word(bytes, 4)? as usize != bytes.len()
        || bytes.iter().fold(0u8, |sum, &b| sum.wrapping_add(b)) != 0
    {
        return Err(Error::Topology);
    }
    let mut rest = &bytes[37..];
    let mut matched = false;
    for _ in 0..bytes[36] {
        let size = word(rest, 0)? as usize;
        if size < 24 || size > rest.len() {
            return Err(Error::Topology);
        }
        let endpoint = &rest[..size];
        let caps = word(endpoint, 19)? as usize;
        let formats_at = 23usize
            .checked_add(caps)
            .filter(|at| *at < size)
            .ok_or(Error::Topology)?;
        let mut formats = &endpoint[formats_at + 1..];
        for _ in 0..endpoint[formats_at] {
            let extra = word(formats, 40)? as usize;
            let next = 44usize
                .checked_add(extra)
                .filter(|end| *end <= formats.len())
                .ok_or(Error::Topology)?;
            if endpoint[4] == 2
                && endpoint[16] == 1
                && endpoint[17] == 1
                && formats[..2] == [0xfe, 0xff]
                && formats[16..18] == [22, 0]
                && formats[24..40]
                    == [
                        1, 0, 0, 0, 0, 0, 0x10, 0, 0x80, 0, 0, 0xaa, 0, 0x38, 0x9b, 0x71,
                    ]
                && u16::from_le_bytes([formats[2], formats[3]]) == u16::from(format.channels)
                && word(formats, 4)? == format.rate
                && u16::from_le_bytes([formats[14], formats[15]])
                    == if format.bits == 16 { 16 } else { 32 }
                && u16::from_le_bytes([formats[18], formats[19]]) == u16::from(format.bits)
            {
                matched = true;
            }
            formats = &formats[next..];
        }
        rest = &rest[size..];
    }
    if !matched {
        return Err(Error::Topology);
    }
    Ok(())
}

impl<R: Registers, T: Timer> Controller<R, T> {
    pub fn install_dmic(&mut self, topology: DmicTopology) -> Result<(), Error> {
        self.guard(&[State::Firmware])?;
        if self.graph.is_some() {
            return Err(Error::Busy);
        }
        if topology.hardware != self.identity.hardware() {
            return Err(Error::Topology);
        }
        // Retain exact board evidence before the first potentially partial IPC.
        self.graph = Some(Installed {
            host: topology.host,
            format: topology.format,
            sha256: topology.sha256,
            board: topology.board,
            nhlt: topology.nhlt,
        });
        let result = (|| {
            let mut reply = [0u8; 384];
            for message in topology.messages {
                self.exchange(&message, &mut reply)?;
            }
            Ok(())
        })();
        self.finish(result)
    }
    pub fn topology_identity(&self) -> Option<([u8; 32], &str, &[u8])> {
        self.graph
            .as_ref()
            .map(|g| (g.sha256, g.board.as_str(), g.nhlt.as_slice()))
    }
    pub fn prepare_capture(
        &mut self,
        pages: &dyn PageSource,
        domain: Arc<dyn DmaDomain>,
        ring_bytes: usize,
        period_bytes: usize,
    ) -> Result<(), Error> {
        self.guard(&[State::Firmware])?;
        let graph = self.graph.as_ref().ok_or(Error::State)?;
        let format = graph.format;
        let host = graph.host;
        if self.pcm.is_some()
            || ring_bytes < 4096
            || ring_bytes & 4095 != 0
            || period_bytes == 0
            || !period_bytes.is_multiple_of(format.frame_bytes().map_err(|_| Error::Buffer)?)
        {
            return Err(Error::Buffer);
        }
        let mut stream = Stream::allocate(
            pages,
            domain,
            ring_bytes,
            self.limit,
            0,
            1,
            Direction::Capture,
        )?;
        stream.format = format.encode().map_err(|_| Error::Buffer)?;
        stream.descriptors(period_bytes)?;
        self.pcm = Some(stream);
        let result = (|| {
            self.program_stream(false, false)?;
            let mut params = command(108, 0x60010000);
            put(&mut params, 8, host);
            put(&mut params, 12, 1);
            put(&mut params, 24, 84);
            put(&mut params, 28, 28);
            put(&mut params, 36, (ring_bytes / 4096) as u32);
            put(&mut params, 40, ring_bytes as u32);
            put(&mut params, 56, 1);
            put(
                &mut params,
                60,
                match format.bits {
                    16 => 0,
                    24 => 1,
                    _ => 2,
                },
            );
            put(&mut params, 68, format.rate);
            params[72..74].copy_from_slice(&1u16.to_le_bytes());
            params[74..76].copy_from_slice(&u16::from(format.channels).to_le_bytes());
            params[76..78].copy_from_slice(&(u16::from(format.bits) / 8).to_le_bytes());
            params[78..80]
                .copy_from_slice(&(if format.bits == 16 { 2u16 } else { 4u16 }).to_le_bytes());
            put(&mut params, 80, period_bytes as u32);
            params[84] = 1;
            let mut reply = [0; 20];
            if self.exchange(&params, &mut reply)? != 20 || word(&reply, 12)? != host {
                return Err(Error::IpcReply);
            }
            self.state = State::Prepared;
            Ok(())
        })();
        self.finish(result)
    }
    pub fn start_capture(&mut self) -> Result<(), Error> {
        self.guard(&[State::Prepared, State::Stopped])?;
        let host = self.graph.as_ref().ok_or(Error::State)?.host;
        let command_id = if self.state == State::Stopped {
            0x60070000
        } else {
            0x60040000
        };
        let result = (|| {
            self.stream_run(false, false, true)?;
            let mut message = command(12, command_id);
            put(&mut message, 8, host);
            self.exchange(&message, &mut [0; 12])?;
            self.state = State::Running;
            Ok(())
        })();
        self.finish(result)
    }
    pub fn stop_capture(&mut self) -> Result<(), Error> {
        self.guard(&[State::Running])?;
        let host = self.graph.as_ref().ok_or(Error::State)?.host;
        let result = (|| {
            let mut message = command(12, 0x60060000);
            put(&mut message, 8, host);
            self.exchange(&message, &mut [0; 12])?;
            self.stream_run(false, false, false)?;
            self.complete_stopped_dma()?;
            self.state = State::Stopped;
            Ok(())
        })();
        self.finish(result)
    }
    /// CPU copies require DSP pause, all SD_RUN bits clear, acknowledged native
    /// BME containment and original-domain payload completion before CPU sync.
    pub fn read_capture(&mut self, offset: usize, bytes: &mut [u8]) -> Result<(), Error> {
        self.guard(&[State::Stopped])?;
        self.pcm
            .as_mut()
            .ok_or(Error::State)?
            .copy_from(offset, bytes)
    }
    pub fn capture_position(&mut self) -> Result<usize, Error> {
        self.guard(&[State::Running])?;
        let result = (|| {
            let stream = self.pcm.as_ref().ok_or(Error::State)?;
            let index = stream.index;
            let bytes = stream.bytes;
            let status = self.registers.read8(Bar::Hda, stream_base(index) + STS)?;
            if self.registers.read8(Bar::Hda, stream_base(index))? & RUN == 0 {
                return Err(Error::Rejected(Bar::Hda, stream_base(index)));
            }
            if status & (FIFO_ERROR | DESC_ERROR) != 0 {
                return Err(Error::StreamFault(status));
            }
            let notification = self.read(Bar::Dsp, IPC_NOTIFY)?;
            if notification & BUSY != 0 {
                return Err(Error::FirmwarePanic(notification));
            }
            // Default cAVS decoupled VC0 host position is the vendor DPIB
            // register; SD_LPIB tracks the independent link DMA position.
            let position =
                self.read(Bar::Hda, DPIB_BASE + usize::from(index) * DPIB_STRIDE)? as usize;
            if position >= bytes {
                return Err(Error::Buffer);
            }
            if status & 4 != 0 {
                self.registers
                    .write8(Bar::Hda, stream_base(index) + STS, 4)?;
            }
            Ok(position)
        })();
        self.finish(result)
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    fn values(entries: &[(u32, u32)]) -> Vec<u8> {
        let mut data = vec![0; 12 + entries.len() * 8];
        let size = data.len() as u32;
        put(&mut data, 0, size);
        put(&mut data, 4, 4);
        put(&mut data, 8, entries.len() as u32);
        for (index, &(id, value)) in entries.iter().enumerate() {
            put(&mut data, 12 + index * 8, id);
            put(&mut data, 16 + index * 8, value);
        }
        data
    }
    fn strings(entries: &[(u32, &str)]) -> Vec<u8> {
        let mut data = vec![0; 12 + entries.len() * 48];
        let size = data.len() as u32;
        put(&mut data, 0, size);
        put(&mut data, 4, 1);
        put(&mut data, 8, entries.len() as u32);
        for (index, &(id, value)) in entries.iter().enumerate() {
            let at = 12 + index * 48;
            put(&mut data, at, id);
            data[at + 4..at + 4 + value.len()].copy_from_slice(value.as_bytes());
        }
        data
    }
    fn widget(kind: u32, name: &str, sname: &str, tuples: &[u8]) -> Vec<u8> {
        let mut data = vec![0; 132];
        put(&mut data, 0, 132);
        put(&mut data, 4, kind);
        data[8..8 + name.len()].copy_from_slice(name.as_bytes());
        data[52..52 + sname.len()].copy_from_slice(sname.as_bytes());
        put(&mut data, 128, tuples.len() as u32);
        data.extend_from_slice(tuples);
        data
    }
    fn block(kind: u32, count: u32, payload: &[u8]) -> Vec<u8> {
        let mut data = vec![0; 36];
        for (offset, value) in [
            (0, 0x41536f43),
            (4, 5),
            (12, kind),
            (16, 36),
            (24, payload.len() as u32),
            (28, 7),
            (32, count),
        ] {
            put(&mut data, offset, value);
        }
        data.extend_from_slice(payload);
        data
    }
    pub(in crate::audio::intel_dsp) fn fixture() -> (Vec<u8>, Vec<u8>) {
        let mut widgets = Vec::new();
        widgets.extend(widget(12, "host", "capture", &strings(&[(402, "s32le")])));
        widgets.extend(widget(
            16,
            "buffer",
            "",
            &values(&[(100, 4096), (101, 0x21)]),
        ));
        let mut dai_tokens = strings(&[(154, "DMIC"), (402, "s32le")]);
        dai_tokens.extend(values(&[(155, 0), (156, 1)]));
        widgets.extend(widget(13, "dmic", "DMIC01", &dai_tokens));
        widgets.extend(widget(
            17,
            "schedule",
            "dmic",
            &values(&[(200, 1000), (204, 48)]),
        ));
        let mut topology = block(5, 4, &widgets);
        let mut graph = vec![0; 264];
        for (index, (source, sink)) in [("dmic", "buffer"), ("buffer", "host")]
            .into_iter()
            .enumerate()
        {
            let at = index * 132;
            graph[at..at + sink.len()].copy_from_slice(sink.as_bytes());
            graph[at + 88..at + 88 + source.len()].copy_from_slice(source.as_bytes());
        }
        topology.extend(block(4, 2, &graph));
        let mut link_tokens = strings(&[(154, "DMIC")]);
        link_tokens.extend(values(&[
            (600, 1),
            (601, 1_000_000),
            (602, 3_200_000),
            (603, 48),
            (604, 52),
            (605, 1),
            (608, 48000),
            (609, 32),
            (700, 0),
            (701, 1),
            (702, 1),
        ]));
        let mut link = vec![0; 1656];
        put(&mut link, 0, 1656);
        link[8..14].copy_from_slice(b"DMIC01");
        put(&mut link, 1636, 1);
        put(&mut link, 1652, link_tokens.len() as u32);
        link.extend(link_tokens);
        topology.extend(block(10, 1, &link));
        let mut nhlt = vec![0; 105];
        nhlt[..4].copy_from_slice(b"NHLT");
        put(&mut nhlt, 4, 105);
        nhlt[36] = 1;
        let endpoint = &mut nhlt[37..];
        put(endpoint, 0, 68);
        endpoint[4] = 2;
        endpoint[16] = 1;
        endpoint[17] = 1;
        endpoint[23] = 1;
        let format = &mut endpoint[24..];
        format[..4].copy_from_slice(&[0xfe, 0xff, 2, 0]);
        put(format, 4, 48_000);
        put(format, 8, 384_000);
        format[12..20].copy_from_slice(&[8, 0, 32, 0, 22, 0, 32, 0]);
        format[24..40].copy_from_slice(&[
            1, 0, 0, 0, 0, 0, 0x10, 0, 0x80, 0, 0, 0xaa, 0, 0x38, 0x9b, 0x71,
        ]);
        nhlt[9] = 0u8.wrapping_sub(nhlt.iter().fold(0u8, |s, b| s.wrapping_add(*b)));
        (topology, nhlt)
    }
    pub(in crate::audio::intel_dsp) fn topology() -> DmicTopology {
        let (wire, nhlt) = fixture();
        let (messages, host, format) = parse(&wire, 7).unwrap();
        validate_nhlt(&nhlt, format).unwrap();
        DmicTopology {
            messages,
            host,
            pipeline: 7,
            format,
            sha256: [0x7a; 32],
            board: "isolated-model".into(),
            nhlt,
            hardware: "8086:a0c8".into(),
        }
    }
    #[test]
    fn original_abi5_direct_graph_and_nhlt_convert_to_exact_ipc3_layouts() {
        let topology = topology();
        assert_eq!(
            topology.format,
            PcmFormat {
                rate: 48000,
                bits: 32,
                channels: 2
            }
        );
        let messages = &topology.messages;
        assert_eq!(
            messages.iter().map(Vec::len).collect::<Vec<_>>(),
            [76, 44, 80, 48, 16, 16, 216, 12]
        );
        assert_eq!(word(&messages[0], 64).unwrap(), 1);
        assert_eq!(word(&messages[2], 72).unwrap(), 2);
        assert_eq!(word(&messages[3], 16).unwrap(), 3);
        assert_eq!(word(&messages[3], 24).unwrap(), 1000);
        assert_eq!(word(&messages[6], 68).unwrap(), 48000);
        assert_eq!(&messages[6][124..130], &[0, 0, 1, 0, 1, 0]);
    }
    #[test]
    fn malformed_unknown_processing_or_board_evidence_never_grants_a_dmic_graph() {
        let (wire, nhlt) = fixture();
        for end in [0, 3, 35, 36, 100, wire.len() - 1] {
            assert!(parse(&wire[..end], 7).is_err());
        }
        let mut bad = wire.clone();
        put(&mut bad, 36 + 4, 4);
        assert!(matches!(parse(&bad, 7), Err(Error::UnsupportedTopology)));
        let mut bad = wire.clone();
        put(&mut bad, 36 + 124, 1);
        assert!(matches!(parse(&bad, 7), Err(Error::UnsupportedTopology)));
        let mut bad = nhlt.clone();
        bad[9] ^= 1;
        assert!(validate_nhlt(&bad, topology().format).is_err());
        let mut bad = nhlt;
        bad[37 + 17] = 0;
        bad[9] = 0;
        bad[9] = 0u8.wrapping_sub(bad.iter().fold(0u8, |s, b| s.wrapping_add(*b)));
        assert!(validate_nhlt(&bad, topology().format).is_err());
    }
}
