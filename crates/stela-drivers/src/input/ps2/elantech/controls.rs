// SPDX-License-Identifier: GPL-2.0-only
// Original notices are held in ../elantech.rs and input/THIRD_PARTY.md.
//! Protected hardware-register mutation for the source exposed controls.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegisterControl {
    pub address: u8,
    pub requested: u8,
    /// Source v1 forces absolute/4-byte mode bits in the written value.
    pub effective: u8,
    pub quiesced: bool,
    /// Every byte service and final write acknowledgement completed on time.
    pub acknowledged: bool,
    pub reporting_resumed: bool,
}

impl<R: Registers, T: Timer> Controller<R, T> {
    pub fn elantech_register_controls(&self) -> Option<&[RegisterControl]> {
        Some(&self.elantech.as_ref()?.controls)
    }
    pub fn drain_elantech_register_controls(&mut self) -> Vec<RegisterControl> {
        self.elantech
            .as_mut()
            .map_or_else(Vec::new, |e| core::mem::take(&mut e.controls))
    }
    /// Write one hardware register exposed by the source driver. The source v1
    /// absolute and four-byte bits remain forced. This writes a real device;
    /// ACKs do not invent readback or imply that arbitrary firmware values
    /// preserve the selected report mode. Mode-register changes invalidate the
    /// initialization criterion until a fresh stop/initialize operation.
    ///
    /// An uncertain write/resume keeps its request/progress and quarantines
    /// the owner without replay. The source sysfs leaf's masked error byte count
    /// is not an acknowledgement from this native operation.
    pub fn write_elantech_register(
        &mut self,
        address: u8,
        requested: u8,
    ) -> Result<RegisterControl, super::super::Error> {
        self.ready()?;
        let hardware = self
            .elantech_capabilities()
            .ok_or_else(|| super::super::Error::from(ErrorKind::NotInitialized))?
            .hardware;
        if !matches!(address, 7 | 0x10 | 0x11 | 0x20..=0x26) {
            return Err(ErrorKind::Elantech(Error::Register(address)).into());
        }
        let engine = self.elantech.as_ref().unwrap();
        if engine.backpressured() || engine.controls.len() >= 32 {
            return Err(ErrorKind::QueueFull.into());
        }
        let effective = requested
            | if hardware == 1 {
                match address {
                    0x10 => 4,
                    0x11 => 2,
                    _ => 0,
                }
            } else {
                0
            };
        self.elantech
            .as_mut()
            .unwrap()
            .controls
            .push(RegisterControl {
                address,
                requested,
                effective,
                quiesced: false,
                acknowledged: false,
                reporting_resumed: false,
            });
        let result = (|| {
            self.device_command(Port::Mouse, DISABLE_REPORTING, &[])?;
            let engine = self.elantech.as_mut().unwrap();
            engine.controls.last_mut().unwrap().quiesced = true;
            if address == if hardware == 4 { 7 } else { 0x10 } || (hardware == 1 && address == 0x11)
            {
                engine.capabilities.as_mut().unwrap().mode_accepted = false;
            }
            self.elan_write_bytes(address, effective, hardware)?;
            self.elantech
                .as_mut()
                .unwrap()
                .controls
                .last_mut()
                .unwrap()
                .acknowledged = true;
            self.device_command(Port::Mouse, ENABLE_REPORTING, &[])?;
            let control = self.elantech.as_mut().unwrap().controls.last_mut().unwrap();
            control.reporting_resumed = true;
            Ok(*control)
        })();
        result.map_err(|kind| self.fail(kind))
    }
}
