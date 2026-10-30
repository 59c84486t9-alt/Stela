// SPDX-License-Identifier: GPL-2.0-or-later
//! CX11880/SN6140 cold recognition and explicitly polled jack updates adapted
//! from Linux sound/hda/codecs/conexant.c at a804c5742bff224d4cb4d25dd383554d598be32b.
//! Copyright (c) 2006 Pototskiy Akex, Takashi Iwai and Tobin Davis.
use super::super::Vref;
use super::*;
use crate::Phase;

const MIC: u8 = 0x19;
const HEADPHONE: u8 = 0x16;
const VENDOR: u8 = 0x1c;
const GET_SENSE: u16 = 0xf09;
const SET_PIN: u16 = 0x707;
const GET_PIN: u16 = 0xf07;
const GET_DETECTION: u16 = 0xca0;
const GET_TYPE: u16 = 0xcb0;
const DETECT_DONE: u32 = 0x80;
const TYPE_CTIA: u32 = 0x800;
const TYPE_OMTP: u32 = 0x400;
const MIC_CAPABILITIES: u32 = (1 << 5) | (1 << 8) | (1 << 12);
const DETECTION_READS: usize = 3;
const PRESENCE: u32 = 1 << 31;
const MIC_OFF: u8 = 0x20;
const MIC_ON: u8 = 0x24;
const DETECTION_INTERVAL_US: u64 = 20_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConexantHeadsetKind {
    Disconnected,
    /// Cold initialization applies bias from presence without detecting type.
    Unclassified,
    Headphone,
    Ctia,
    Omtp,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConexantHeadsetReport {
    pub sense: u32,
    pub kind: ConexantHeadsetKind,
    pub detection_status: Option<u32>,
    pub type_status: Option<u32>,
    pub microphone_control: u8,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConexantHeadsetInitialization {
    pub codec: ConexantReport,
    pub headset: ConexantHeadsetReport,
}
#[derive(Clone)]
pub(super) struct State {
    microphone_control: u8,
}
pub(in crate::hda) fn is_profile(id: u32) -> bool {
    matches!(id, 0x14f1_1f86 | 0x14f1_1f87)
}
pub(super) fn route_options(
    state: &State,
    route: &AnalogRoute,
    options: PinOptions,
) -> Result<(), Error> {
    if route.pin() == MIC {
        let PinOptions::Capture { vref } = options else {
            return Err(Error::InvalidPinControl);
        };
        let control = match vref {
            Vref::HighImpedance => MIC_OFF,
            Vref::EightyPercent => MIC_ON,
            _ => return Err(Error::InvalidPinControl),
        };
        if control != state.microphone_control {
            return Err(Error::InvalidPinControl);
        }
    }
    if route.pin() == HEADPHONE
        && !matches!(
            options,
            PinOptions::Playback {
                headphone: true,
                ..
            }
        )
    {
        return Err(Error::InvalidPinControl);
    }
    Ok(())
}
impl<R: Registers, T: Timer> Controller<R, T> {
    fn conexant_headset_preflight(graph: &CodecGraph) -> Result<(), Error> {
        if !is_profile(graph.vendor_id) {
            return Err(Error::UnsupportedTopology);
        }
        let groups: Vec<_> = graph
            .groups
            .iter()
            .filter(|group| group.function_type & 255 == 1)
            .collect();
        let [group] = groups.as_slice() else {
            return Err(Error::UnsupportedTopology);
        };
        let mic = group
            .widgets
            .iter()
            .find(|widget| widget.node == MIC)
            .ok_or(Error::InvalidCodecGraph)?;
        // The fixed source protocol needs microphone input, Hi-Z and
        // 80% VREF. The live identity walk validates these cached capabilities
        // and proves both fixed nodes lie in the audio function group.
        if mic.kind != WidgetKind::Pin
            || mic
                .pin_capabilities
                .is_none_or(|caps| caps == u32::MAX || caps & MIC_CAPABILITIES != MIC_CAPABILITIES)
            || !group.widgets.iter().any(|widget| widget.node == VENDOR)
        {
            return Err(Error::UnsupportedTopology);
        }
        Ok(())
    }
    fn conexant_microphone_sense(&mut self, address: u8) -> Result<u32, Error> {
        let sense = self.verb(Verb::short(address, MIC, GET_SENSE, 0)?)?;
        if sense == u32::MAX {
            return Err(Error::RouteRejected);
        }
        Ok(sense)
    }
    fn conexant_microphone_control(&mut self, address: u8, present: bool) -> Result<u8, Error> {
        let control = if present { MIC_ON } else { MIC_OFF };
        self.route_control(address, MIC, SET_PIN, GET_PIN, control)?;
        Ok(control)
    }
    /// Initialize the real fixed-node vendor trim and microphone bias before
    /// exposing either headset codec to standard route configuration. This is
    /// cold held-D0 ownership; S3/S4 power and unsolicited dispatch are separate.
    pub fn initialize_conexant_headset_codec(
        &mut self,
        graph: &CodecGraph,
    ) -> Result<ConexantHeadsetInitialization, Error> {
        self.conexant_guard(graph)?;
        Self::conexant_headset_preflight(graph)?;
        let codec = self.initialize_conexant_common(graph)?;
        let result = (|| {
            // snd_hdac_make_cmd encodes (0x3b0 << 8) | 0xe10 = 0x3be10.
            // This vendor command overlaps the normal short-verb payload;
            // encode its exact wire bits as a long verb, without truncation.
            // The donor specifies no trim readback verb: the command response
            // acknowledges transport, while subsequent bias is read back.
            if self.verb(Verb::long(graph.address, VENDOR, 3, 0xbe10)?)? == u32::MAX {
                return Err(Error::RouteRejected);
            }
            let sense = self.conexant_microphone_sense(graph.address)?;
            let present = sense & PRESENCE != 0;
            let control = self.conexant_microphone_control(graph.address, present)?;
            Ok(ConexantHeadsetReport {
                sense,
                kind: if present {
                    ConexantHeadsetKind::Unclassified
                } else {
                    ConexantHeadsetKind::Disconnected
                },
                detection_status: None,
                type_status: None,
                microphone_control: control,
            })
        })();
        match result {
            Ok(headset) => {
                self.conexant_codecs
                    .iter_mut()
                    .find(|s| s.address == graph.address)
                    .ok_or(Error::NeedsReset)?
                    .headset = Some(State {
                    microphone_control: headset.microphone_control,
                });
                Ok(ConexantHeadsetInitialization { codec, headset })
            }
            Err(error) => {
                self.routing_failed = true;
                Err(error)
            }
        }
    }
    /// Poll the donor's fixed microphone sense/type protocol explicitly. This
    /// may update bias during live capture, as its jack callback does. At most
    /// three ready reads with 20ms intervals are allowed; incomplete detection
    /// refuses instead of interpreting an unfinished type register as success.
    pub fn poll_conexant_headset(
        &mut self,
        graph: &CodecGraph,
    ) -> Result<ConexantHeadsetReport, Error> {
        self.conexant_guard(graph)?;
        if !is_profile(graph.vendor_id) {
            return Err(Error::UnsupportedTopology);
        }
        if self.streams.iter().flatten().any(|s| s.poisoned) {
            return Err(Error::NeedsReset);
        }
        let state = self.conexant_active(graph)?;
        if state.headset.is_none() {
            return Err(Error::NeedsReset);
        }
        let result = (|| {
            let sense = self.conexant_microphone_sense(graph.address)?;
            let present = sense & PRESENCE != 0;
            let (kind, detection_status, type_status) = if present {
                let mut status = None;
                for _ in 0..DETECTION_READS {
                    let value = self.verb(Verb::short(graph.address, VENDOR, GET_DETECTION, 0)?)?;
                    if value == u32::MAX {
                        return Err(Error::RouteRejected);
                    }
                    if value & DETECT_DONE != 0 {
                        status = Some(value);
                        break;
                    }
                    self.delay(DETECTION_INTERVAL_US);
                }
                let status = status.ok_or(Error::Timeout(Phase::CodecHeadsetDetection))?;
                let kind = self.verb(Verb::short(graph.address, VENDOR, GET_TYPE, 0)?)?;
                if kind == u32::MAX {
                    return Err(Error::RouteRejected);
                }
                // The detection helper writes VREF for a recognized headset;
                // the outer callback repeats it below. Preserve both
                // transactions rather than assuming duplicate writes are inert.
                if kind & (TYPE_CTIA | TYPE_OMTP) != 0 {
                    self.conexant_microphone_control(graph.address, true)?;
                }
                // Preserve the donor's precedence if both type bits are set.
                let decoded = if kind & TYPE_CTIA != 0 {
                    ConexantHeadsetKind::Ctia
                } else if kind & TYPE_OMTP != 0 {
                    ConexantHeadsetKind::Omtp
                } else {
                    ConexantHeadsetKind::Headphone
                };
                (decoded, Some(status), Some(kind))
            } else {
                (ConexantHeadsetKind::Disconnected, None, None)
            };
            let control = self.conexant_microphone_control(graph.address, present)?;
            Ok(ConexantHeadsetReport {
                sense,
                kind,
                detection_status,
                type_status,
                microphone_control: control,
            })
        })();
        match result {
            Ok(report) => {
                self.conexant_codecs
                    .iter_mut()
                    .find(|s| s.address == graph.address)
                    .ok_or(Error::NeedsReset)?
                    .headset = Some(State {
                    microphone_control: report.microphone_control,
                });
                Ok(report)
            }
            Err(error) => {
                self.routing_failed = true;
                Err(error)
            }
        }
    }
}
