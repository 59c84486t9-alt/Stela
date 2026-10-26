// SPDX-License-Identifier: GPL-2.0-only
// Original Elantech notices are retained in ../elantech.rs and input/THIRD_PARTY.md.
use super::*;
impl<R: Registers, T: Timer> Controller<R, T> {
    fn elan_register_command(&mut self, byte: u8) -> Result<(), ErrorKind> {
        for attempt in 0..3 {
            match self.device_command(Port::Mouse, byte, &[]) {
                Ok(()) => return Ok(()),
                Err(error @ ErrorKind::ResendLimit { .. }) => {
                    // Source retries this single-byte service after500ms.
                    // Only actual RESEND rejection proves this byte did not
                    // apply. Timeout/unknown effects must never replay.
                    let start = self.timer.start();
                    while !self.expired(start, 500_000) {
                        if let Some(byte) = self.read_byte()? {
                            self.queue(byte)?;
                        } else {
                            self.timer.relax();
                        }
                    }
                    if attempt == 2 {
                        return Err(error);
                    }
                }
                Err(error) => return Err(error),
            }
        }
        unreachable!()
    }
    fn elan_reply(&mut self, kind: QueryKind) -> Result<[u8; 3], ErrorKind> {
        self.elantech.as_mut().unwrap().query = Some(QueryProgress {
            kind,
            bytes: [0; 3],
            received: 0,
        });
        if matches!(kind, QueryKind::ReportId)
            || (matches!(kind, QueryKind::Register(_))
                && self
                    .elantech_capabilities()
                    .is_some_and(|c| c.hardware >= 2))
        {
            self.elan_register_command(0xe9)?;
        } else {
            self.device_command(Port::Mouse, 0xe9, &[])?;
        }
        let start = self.timer.start();
        let mut bytes = [0; 3];
        for (index, byte) in bytes.iter_mut().enumerate() {
            let result = self.response(Port::Mouse, start, self.config.command_timeout_us);
            if let Some(observed) = self.observed_response {
                *byte = observed.data;
                let progress = self.elantech.as_mut().unwrap().query.as_mut().unwrap();
                progress.bytes[index] = *byte;
                progress.received += 1;
            }
            result?;
        }
        self.elantech
            .as_mut()
            .unwrap()
            .queries
            .push(Query { kind, bytes });
        Ok(bytes)
    }
    fn elan_query(&mut self, id: u8, kind: QueryKind) -> Result<[u8; 3], ErrorKind> {
        self.elantech.as_mut().unwrap().query = Some(QueryProgress {
            kind,
            bytes: [0; 3],
            received: 0,
        });
        self.sliced_command(id)?;
        self.elan_reply(kind)
    }
    fn elan_info(&mut self, id: u8, kind: QueryKind, hardware: u8) -> Result<[u8; 3], ErrorKind> {
        if hardware < 3 {
            return self.elan_query(id, kind);
        }
        self.elantech.as_mut().unwrap().query = Some(QueryProgress {
            kind,
            bytes: [0; 3],
            received: 0,
        });
        // Fast queries use plain source command services, not the separate
        // retrying register service. Firmware identification remains sliced.
        self.device_command(Port::Mouse, 0xf8, &[])?;
        self.device_command(Port::Mouse, id, &[])?;
        self.elan_reply(kind)
    }
    fn elan_read(&mut self, reg: u8, hardware: u8) -> Result<[u8; 3], ErrorKind> {
        self.elantech.as_mut().unwrap().query = Some(QueryProgress {
            kind: QueryKind::Register(reg),
            bytes: [0; 3],
            received: 0,
        });
        if hardware == 1 {
            self.sliced_command(0x10)?;
            self.sliced_command(reg)?;
        } else {
            for byte in [0xf8, if hardware == 2 { 0x10 } else { 0 }, 0xf8, reg] {
                self.elan_register_command(byte)?;
            }
        }
        self.elan_reply(QueryKind::Register(reg))
    }
    fn elan_write(&mut self, reg: u8, value: u8, hardware: u8) -> Result<(), ErrorKind> {
        self.elantech
            .as_mut()
            .unwrap()
            .capabilities
            .as_mut()
            .unwrap()
            .registers
            .push(RegisterWrite {
                address: reg,
                requested: value,
                acknowledged: false,
                readback: None,
            });
        self.elan_write_bytes(reg, value, hardware)?;
        self.elantech
            .as_mut()
            .unwrap()
            .capabilities
            .as_mut()
            .unwrap()
            .registers
            .last_mut()
            .unwrap()
            .acknowledged = true;
        Ok(())
    }
    pub(super) fn elan_write_bytes(
        &mut self,
        reg: u8,
        value: u8,
        hardware: u8,
    ) -> Result<(), ErrorKind> {
        if hardware == 1 {
            for byte in [0x11, reg, value] {
                self.sliced_command(byte)?;
            }
        } else {
            let bytes: &[u8] = if hardware == 4 {
                &[0xf8, 0, 0xf8, reg, 0xf8, 0, 0xf8, value]
            } else {
                &[
                    0xf8,
                    if hardware == 2 { 0x11 } else { 0 },
                    0xf8,
                    reg,
                    0xf8,
                    value,
                ]
            };
            for &byte in bytes {
                self.elan_register_command(byte)?;
            }
        }
        if hardware >= 2 {
            self.elan_register_command(SCALE_ONE_TO_ONE)?;
        } else {
            self.device_command(Port::Mouse, SCALE_ONE_TO_ONE, &[])?;
        }
        Ok(())
    }
    fn elan_change_report_id(&mut self) -> Result<(), ErrorKind> {
        self.elantech.as_mut().unwrap().report_id = Some(ReportIdChange {
            requested: [0x10, 3],
            write_acknowledged: false,
            readback: None,
            verified: false,
        });
        // Source elantech_write_reg_params uses both literal parameter bytes.
        for byte in [0xf8, 0, 0xf8, 7, 0xf8, 0x10, 0xf8, 3, SCALE_ONE_TO_ONE] {
            self.elan_register_command(byte)?;
        }
        self.elantech
            .as_mut()
            .unwrap()
            .report_id
            .as_mut()
            .unwrap()
            .write_acknowledged = true;
        for byte in [0xf8, 0, 0xf8, 7] {
            self.elan_register_command(byte)?;
        }
        let observed = self.elan_reply(QueryKind::ReportId)?;
        let change = self.elantech.as_mut().unwrap().report_id.as_mut().unwrap();
        change.readback = Some(observed);
        if observed[..2] != [0x10, 3] {
            return Err(ErrorKind::Elantech(Error::ReportId(observed)));
        }
        change.verified = true;
        Ok(())
    }
    pub(in crate::input::ps2) fn initialize_elantech(&mut self) -> Result<(), ErrorKind> {
        self.elantech.as_mut().unwrap().queries.clear();
        self.elantech.as_mut().unwrap().report_id = None;
        if let Some(c) = &mut self.elantech.as_mut().unwrap().capabilities {
            c.mode_accepted = false;
        }
        self.device_command(Port::Mouse, DEFAULTS, &[])?;
        self.device_command(Port::Mouse, DISABLE_REPORTING, &[])?;
        for _ in 0..3 {
            self.device_command(Port::Mouse, SCALE_ONE_TO_ONE, &[])?;
        }
        let knock = self.elan_reply(QueryKind::Knock)?;
        if knock[..2] != [0x3c, 3] || !matches!(knock[2], 0xc8 | 0) {
            return Err(ErrorKind::Elantech(Error::Knock(knock)));
        }
        let probe = self.elan_query(1, QueryKind::FirmwareProbe)?;
        let firmware = u32::from_be_bytes([0, probe[0], probe[1], probe[2]]);
        let valid = probe[0] != 0
            && (probe[1] == 0
                || ((probe[0] & 15) >= 6 && (probe[1] & 0xaf) == 15 && probe[2] < 40)
                || ![200, 100, 80, 60, 40, 20, 10].contains(&probe[2]));
        if !valid {
            return Err(ErrorKind::Elantech(Error::Signature(firmware)));
        }
        let identity = self.elan_query(1, QueryKind::Firmware)?;
        if identity != probe {
            return Err(ErrorKind::Elantech(Error::IdentityChanged));
        }
        let hardware = if firmware < 0x020030 || firmware == 0x020600 {
            1
        } else {
            match (firmware >> 16) & 15 {
                2 | 4 => 2,
                5 => 3,
                6..=15 => 4,
                _ => return Err(ErrorKind::Elantech(Error::Version(firmware))),
            }
        };
        let capabilities = self.elan_info(2, QueryKind::Capabilities, hardware)?;
        let trackpoint = capabilities[0] & 0x80 != 0;
        let integrated = self.elantech.as_ref().unwrap().trackpoint_required;
        if integrated && !trackpoint {
            return Err(ErrorKind::Elantech(Error::TrackpointAbsent));
        }
        if trackpoint && hardware < 3 {
            return Err(ErrorKind::Elantech(if integrated {
                Error::TrackpointHardware(hardware)
            } else {
                Error::Trackpoint
            }));
        }
        let samples = if hardware > 1 {
            Some(self.elan_info(3, QueryKind::Samples, hardware)?)
        } else {
            None
        };
        if hardware == 3 && samples.is_some_and(|sample| sample[1] == 0x74) {
            return Err(ErrorKind::Elantech(Error::BrokenAbsolute));
        }
        let pattern = if (firmware >> 16) & 15 == 15 && firmware as u8 <= 2 {
            firmware as u8
        } else {
            0
        };
        let ic_body = if pattern != 0 {
            Some(self.elan_info(5, QueryKind::IcBody, hardware)?)
        } else {
            None
        };
        let ic_version = ic_body.map_or(((firmware >> 16) & 15) as u16, |v| {
            u16::from_be_bytes([v[0], v[1]])
        });
        let product = samples.map_or(0, |v| u16::from_be_bytes([v[0], v[1]]));
        let product_id = if pattern == 0 { product & 255 } else { product };
        if self.elantech_capabilities().is_some_and(|old| {
            old.firmware != firmware
                || old.capabilities != capabilities
                || old.samples != samples
                || old.v4.is_some_and(|info| info.ic_body != ic_body)
        }) {
            return Err(ErrorKind::Elantech(Error::IdentityChanged));
        }
        if trackpoint && ic_version == 0x11 && matches!(product_id, 8 | 9 | 0x0d | 0x0e) {
            self.elan_change_report_id()?;
        }
        let resolution = if hardware == 4 {
            Some(self.elan_info(4, QueryKind::Resolution, hardware)?)
        } else {
            None
        };
        let mut firmware_id = None;
        let bounds = if hardware == 1 {
            Bounds {
                minimum: (32, 32),
                maximum: (544, 352),
                source: RangeSource::NominalV1,
            }
        } else if hardware >= 3 {
            let id = self.elan_info(0, QueryKind::FirmwareId, hardware)?;
            firmware_id = Some(id);
            Bounds {
                minimum: (0, 0),
                maximum: (
                    (u16::from(id[0] & 15) << 8) | u16::from(id[1]),
                    (u16::from(id[0] & 0xf0) << 4) | u16::from(id[2]),
                ),
                source: RangeSource::FirmwareQuery,
            }
        } else if matches!(firmware, 0x020800 | 0x020b00 | 0x020030) {
            Bounds {
                minimum: (0, 0),
                maximum: (1152, 768),
                source: RangeSource::NominalV2,
            }
        } else {
            let id = self.elan_query(0, QueryKind::FirmwareId)?;
            firmware_id = Some(id);
            let factor = if firmware > 0x020800 && firmware < 0x020900 {
                1
            } else {
                2
            };
            let traces = || -> Result<(u16, u16), ErrorKind> {
                Ok((
                    u16::from(
                        capabilities[1]
                            .checked_sub(factor)
                            .filter(|x| *x != 0)
                            .ok_or(ErrorKind::Elantech(Error::Geometry))?,
                    ),
                    u16::from(
                        capabilities[2]
                            .checked_sub(factor)
                            .filter(|x| *x != 0)
                            .ok_or(ErrorKind::Elantech(Error::Geometry))?,
                    ),
                ))
            };
            let (maximum, source) = if firmware >> 16 == 0x14 && id[1] & 0x10 != 0 {
                let sample = self.elan_query(3, QueryKind::RangeSamples)?;
                let (x, y) = traces()?;
                (
                    (x * u16::from(sample[1]) / 2, y * u16::from(sample[2]) / 2),
                    RangeSource::FixedDpi,
                )
            } else if firmware == 0x040216 {
                ((819, 405), RangeSource::FirmwareCorrection)
            } else if matches!(firmware, 0x040219 | 0x040215) {
                ((900, 500), RangeSource::FirmwareCorrection)
            } else {
                let (x, y) = traces()?;
                ((x * 64, y * 64), RangeSource::CapabilityTraces)
            };
            Bounds {
                minimum: (0, 0),
                maximum,
                source,
            }
        };
        if bounds.minimum.0 >= bounds.maximum.0 || bounds.minimum.1 >= bounds.maximum.1 {
            return Err(ErrorKind::Elantech(Error::Geometry));
        }
        let c = Capabilities {
            firmware,
            hardware,
            capabilities,
            samples,
            firmware_id,
            bounds,
            reports_pressure: hardware > 1 && firmware >= 0x020800,
            jumpy_cursor: matches!(firmware, 0x020022 | 0x020600),
            crc_enabled: firmware & 0x4000 != 0,
            buttonpad: hardware >= 3 && firmware & 0x1000 != 0,
            trackpoint,
            v4: if let Some(resolution) = resolution {
                let x_traces = capabilities[1];
                if x_traces < 2 || u16::from(x_traces) > bounds.maximum.0 {
                    return Err(ErrorKind::Elantech(Error::Geometry));
                }
                let y_traces = capabilities[2];
                let convert_res = |v: u8| (u16::from(v) * 10 + 790) * 10 / 254;
                let product = u16::from_be_bytes([samples.unwrap()[0], samples.unwrap()[1]]);
                Some(V4Info {
                    pattern,
                    ic_body,
                    ic_version: ic_body.map_or(((firmware >> 16) & 15) as u16, |v| {
                        u16::from_be_bytes([v[0], v[1]])
                    }),
                    product_id: if pattern == 0 { product & 255 } else { product },
                    resolution,
                    counts_per_mm: (
                        convert_res(resolution[1] & 15),
                        convert_res(resolution[1] >> 4),
                    ),
                    bus: resolution[2],
                    traces: (
                        x_traces,
                        if y_traces >= 2 && u16::from(y_traces) <= bounds.maximum.1 {
                            y_traces
                        } else {
                            0
                        },
                    ),
                    trace_width: bounds.maximum.0 / u16::from(x_traces - 1),
                    middle_button: firmware & 0x0f2000 == 0x0f2000
                        && firmware & 255 != 0
                        && firmware & 0x1000 == 0,
                })
            } else {
                None
            },
            registers: Vec::new(),
            mode_accepted: false,
        };
        if let Some(old) = &self.elantech.as_ref().unwrap().capabilities
            && (old.firmware != c.firmware
                || old.hardware != c.hardware
                || old.capabilities != c.capabilities
                || old.samples != c.samples
                || old.firmware_id != c.firmware_id
                || old.v4 != c.v4
                || old.bounds != c.bounds)
        {
            return Err(ErrorKind::Elantech(Error::IdentityChanged));
        }
        self.elantech.as_mut().unwrap().capabilities = Some(c);
        let registers: &[(u8, u8)] = if hardware == 1 {
            &[(0x10, 0x16), (0x11, 0x8f)]
        } else if hardware == 2 {
            &[(0x10, 0x54), (0x11, 0x88), (0x21, 0x60)]
        } else if hardware == 3 {
            &[(0x10, 0x0b)]
        } else {
            &[(0x07, 1)]
        };
        for &(reg, value) in registers {
            self.elan_write(reg, value, hardware)?;
        }
        if hardware != 4 {
            let readback = self.elan_read(0x10, hardware)?;
            self.elantech
                .as_mut()
                .unwrap()
                .capabilities
                .as_mut()
                .unwrap()
                .registers[0]
                .readback = Some(readback);
            if hardware == 1 && readback[0] & 4 == 0 {
                return Err(ErrorKind::Elantech(Error::Readback {
                    expected: 0x16,
                    observed: readback[0],
                }));
            }
        }
        let engine = self.elantech.as_mut().unwrap();
        engine.capabilities.as_mut().unwrap().mode_accepted = true;
        engine.position = 0;
        engine.last_fault = None;
        engine.single_finger_reports = 0;
        Ok(())
    }
    pub(in crate::input::ps2) fn begin_elantech_rate_change(&mut self) {
        if let Some(c) = self.elantech.as_mut().and_then(|e| e.capabilities.as_mut())
            && c.firmware == 0x381f17
        {
            // This firmware loses reg07 on a rate change. The earlier mode ACK
            // cannot establish its current state after an uncertain rate write.
            c.mode_accepted = false;
        }
    }
    pub(in crate::input::ps2) fn restore_elantech_rate_mode(&mut self) -> Result<(), ErrorKind> {
        if self
            .elantech_capabilities()
            .is_some_and(|c| c.firmware == 0x381f17)
        {
            self.elan_write(7, 1, 4)?;
            self.elantech
                .as_mut()
                .unwrap()
                .capabilities
                .as_mut()
                .unwrap()
                .mode_accepted = true;
        }
        Ok(())
    }
    /// Read a genuine source-qualified register while reporting is quiesced.
    /// Full raw reply bytes survive read/resume failure. Successful observations
    /// follow source register-read admission without inventing an echo check.
    pub fn read_elantech_register(&mut self, address: u8) -> Result<[u8; 3], super::super::Error> {
        self.ready()?;
        let hardware = self
            .elantech_capabilities()
            .ok_or_else(|| super::super::Error::from(ErrorKind::NotInitialized))?
            .hardware;
        if !(0x07..=0x11).contains(&address) && !(0x20..=0x26).contains(&address) {
            return Err(ErrorKind::Elantech(Error::Register(address)).into());
        }
        let engine = self.elantech.as_ref().unwrap();
        if engine.backpressured() || engine.queries.len() >= 32 {
            return Err(ErrorKind::QueueFull.into());
        }
        let result = (|| {
            self.device_command(Port::Mouse, DISABLE_REPORTING, &[])?;
            let bytes = self.elan_read(address, hardware)?;
            let cap = self
                .elantech
                .as_mut()
                .unwrap()
                .capabilities
                .as_mut()
                .unwrap();
            if let Some(register) = cap.registers.iter_mut().find(|r| r.address == address) {
                register.readback = Some(bytes);
            }
            self.device_command(Port::Mouse, ENABLE_REPORTING, &[])?;
            Ok(bytes)
        })();
        result.map_err(|kind| self.fail(kind))
    }
}
