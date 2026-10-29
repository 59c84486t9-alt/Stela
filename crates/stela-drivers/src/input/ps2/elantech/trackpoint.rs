// SPDX-License-Identifier: GPL-2.0-only
// Original notices are held in ../elantech.rs and input/THIRD_PARTY.md.
//! Integrated pointing-stick I/O under the shared native byte owner.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrackpointReport {
    Motion {
        buttons: u8,
        dx: i16,
        dy: i16,
    },
    /// Classified child packet ignored by source; no held-key or motion update.
    Ignored,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReportIdChange {
    pub requested: [u8; 2],
    pub write_acknowledged: bool,
    pub readback: Option<[u8; 3]>,
    pub verified: bool,
}
impl Engine {
    pub(super) fn report_trackpoint(&mut self, inputs: &mut Vec<Input>) -> Result<(), ErrorKind> {
        let p = self.packet;
        let sequence = self.sequence;
        self.sequence = sequence
            .checked_add(1)
            .ok_or(ErrorKind::Elantech(Error::SequenceExhausted))?;
        let prefix = u32::from_le_bytes([p[0], p[1], p[2], p[3]]) & !7;
        let accepted = matches!(prefix, 0x06000030 | 0x16008020 | 0x26800010 | 0x36808000)
            && p[4] != 0x80
            && p[5] != 0x80
            && p[1] >> 7 != p[4] >> 7
            && p[2] >> 7 != p[5] >> 7;
        let report = if accepted {
            let buttons = p[0] & 7;
            let dx = i16::from(p[4]) - (i16::from(p[1] ^ 0x80) << 1);
            let dy = (i16::from(p[2] ^ 0x80) << 1) - i16::from(p[5]);
            if self.trackpoint_buttons != buttons {
                self.trackpoint_buttons = buttons;
                inputs.push(Input::MouseButtons(buttons));
            }
            if dx != 0 || dy != 0 {
                inputs.push(Input::Motion { dx, dy });
            }
            TrackpointReport::Motion { buttons, dx, dy }
        } else {
            TrackpointReport::Ignored
        };
        self.frames.push_back(Frame {
            raw: p,
            length: 6,
            native_sequence: sequence,
            report: Report::Trackpoint(report),
        });
        self.position = 0;
        Ok(())
    }
}
impl<R: Registers, T: Timer> Controller<R, T> {
    /// Require a present integrated v3/v4 pointing stick. Ordinary
    /// attachment already admits a queried child under this same native grant;
    /// this variant additionally refuses absence. A firmware identity never
    /// grants another transport or a competing byte owner.
    pub fn new_elantech_trackpoint(
        registers: R,
        timer: T,
        config: Config,
    ) -> Result<Self, super::super::Error> {
        let mut controller = Self::new_elantech(registers, timer, config)?;
        controller.elantech.as_mut().unwrap().trackpoint_required = true;
        Ok(controller)
    }
    pub fn elantech_trackpoint_buttons(&self) -> Option<u8> {
        let engine = self.elantech.as_ref()?;
        engine
            .capabilities
            .as_ref()?
            .trackpoint
            .then_some(engine.trackpoint_buttons)
    }
    pub fn elantech_report_id_change(&self) -> Option<&ReportIdChange> {
        self.elantech.as_ref()?.report_id.as_ref()
    }
}
