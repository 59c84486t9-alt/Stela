// SPDX-License-Identifier: GPL-2.0-only
//! Actual little-endian ELAN command, report and device lifecycle transactions.
use super::*;
use crate::bus::i2c::Operation;
const STAND: u16 = 0x0005;
const RESET: u16 = 0x0100;
const WAKE: u16 = 0x0800;
const SLEEP: u16 = 0x0801;
const POWER: u16 = 0x0307;
const SET_MODE: u16 = 0x0300;
const ENABLE_ABSOLUTE: u16 = 1;
const DEVICE_DESCRIPTOR: u16 = 0x0001;
const REPORT_DESCRIPTOR: u16 = 0x0002;
const PATTERN: u16 = 0x0100;
const PRODUCT_ID: u16 = 0x0101;
const FIRMWARE_VERSION: u16 = 0x0102;
const SAMPLE_OR_IC_TYPE: u16 = 0x0103;
const NEW_SAMPLE_VERSION: u16 = 0x0104;
const TRACE_COUNTS: u16 = 0x0105;
const MAXIMUM_X: u16 = 0x0106;
const MAXIMUM_Y: u16 = 0x0107;
const RESOLUTION: u16 = 0x0108;
const PRESSURE_FORMAT: u16 = 0x010a;
const IAP_VERSION_OR_LEGACY_IC: u16 = 0x0110;
const LEGACY_IAP_VERSION: u16 = 0x0111;
const FIRMWARE_CHECKSUM: u16 = 0x030f;
const IAP_CONTROL: u16 = 0x0310;
const MAIN_FIRMWARE: u16 = 1 << 9;
const RESET_DELAY_US: u64 = 100_000;
const EARLY_WAKE_DELAY_US: u64 = 200_000;

impl<B: Bus, I: Interrupt, T: Timer> I2cDevice<B, I, T> {
    fn wait(&self, delay: u64) {
        let start = self.timer.now_us();
        while self.timer.now_us().wrapping_sub(start) < delay {
            self.timer.relax();
        }
    }
    fn read(&mut self, register: u16, bytes: &mut [u8]) -> Result<(), ErrorKind> {
        self.bus
            .transaction(
                self.address,
                &mut [
                    Operation::Write(&register.to_le_bytes()),
                    Operation::Read(bytes),
                ],
            )
            .map_err(ErrorKind::Bus)
    }
    fn value(&mut self, register: u16) -> Result<[u8; 2], ErrorKind> {
        let mut bytes = [0; 2];
        self.read(register, &mut bytes)?;
        Ok(bytes)
    }
    fn write(&mut self, register: u16, value: u16) -> Result<(), ErrorKind> {
        let address = register.to_le_bytes();
        let data = value.to_le_bytes();
        self.bus
            .transaction(
                self.address,
                &mut [Operation::Write(&[
                    address[0], address[1], data[0], data[1],
                ])],
            )
            .map_err(ErrorKind::Bus)
    }
    fn raw(&mut self, bytes: &mut [u8]) -> Result<(), ErrorKind> {
        self.bus
            .transaction(self.address, &mut [Operation::Read(bytes)])
            .map_err(ErrorKind::Bus)
    }
    fn quarantine<V>(&mut self, result: Result<V, ErrorKind>) -> Result<V, Error> {
        result.map_err(|kind| {
            self.state = State::Uncertain;
            let recovery = if self.interrupt.mask_and_drain().is_ok() {
                Recovery::IrqMasked
            } else {
                Recovery::MaskFailed
            };
            Error { kind, recovery }
        })
    }
    fn ready(&self) -> Result<(), Error> {
        match self.state {
            State::Ready => Ok(()),
            State::Uncertain => Err(ErrorKind::NeedsReset.into()),
            _ => Err(ErrorKind::NotReady.into()),
        }
    }
    fn power(&mut self, enabled: bool) -> Result<(), ErrorKind> {
        let value = u16::from_le_bytes(self.value(POWER)?);
        self.write(POWER, if enabled { value & !1 } else { value | 1 })
    }
    fn query(&mut self, reset: bool) -> Result<Capabilities, ErrorKind> {
        if reset {
            self.write(STAND, RESET)?;
            self.wait(RESET_DELAY_US);
            let mut response = [0xff; 2];
            self.raw(&mut response)?;
            if response != [0, 0] {
                return Err(ErrorKind::ResetResponse(response));
            }
        }
        let (descriptor, report_descriptor) = if reset {
            let mut descriptor = [0; 30];
            let mut report_descriptor = [0; 158];
            self.read(DEVICE_DESCRIPTOR, &mut descriptor)?;
            self.read(REPORT_DESCRIPTOR, &mut report_descriptor)?;
            (descriptor, report_descriptor)
        } else {
            // The exact quick-wakeup profile skips the reset/descriptor phase.
            // These remain the actual bytes from the last completed reset.
            let previous = self.capabilities.as_ref().ok_or(ErrorKind::NotReady)?;
            (previous.descriptor, previous.report_descriptor)
        };
        let product_id = u16::from_le_bytes(self.value(PRODUCT_ID)?);
        let raw_pattern = self.value(PATTERN)?;
        let pattern = if raw_pattern == [255, 255] {
            0
        } else {
            raw_pattern[1]
        };
        let sample = self.value(SAMPLE_OR_IC_TYPE)?;
        let ic_type = if pattern == 0 {
            u16::from(self.value(IAP_VERSION_OR_LEGACY_IC)?[0])
        } else {
            u16::from_be_bytes(sample)
        };
        let nsm = self.value(NEW_SAMPLE_VERSION)?;
        let sample_version = if pattern == 0 { sample[0] } else { nsm[1] };
        let clickpad = nsm[0] & 16 != 0;
        let mode = u16::from_le_bytes(self.value(IAP_CONTROL)?);
        if mode & MAIN_FIRMWARE == 0 {
            return Err(ErrorKind::FirmwareMode(mode));
        }
        let wake_first = (ic_type == 0x0e && matches!(product_id, 5..=7 | 9 | 0x13))
            || (ic_type == 8 && product_id == 0x26);
        if wake_first {
            self.write(STAND, WAKE)?;
            self.wait(EARLY_WAKE_DELAY_US);
        }
        self.write(SET_MODE, ENABLE_ABSOLUTE)?;
        if !wake_first {
            self.write(STAND, WAKE)?;
        }
        let firmware_version = self.value(FIRMWARE_VERSION)?[0];
        let firmware_checksum = u16::from_le_bytes(self.value(FIRMWARE_CHECKSUM)?);
        let iap_data = self.value(if pattern == 0 {
            LEGACY_IAP_VERSION
        } else {
            IAP_VERSION_OR_LEGACY_IC
        })?;
        let iap_version = iap_data[usize::from(pattern != 0)];
        let pressure_adjustment = if self.value(PRESSURE_FORMAT)?[0] & 16 != 0 {
            0
        } else {
            25
        };
        let maximum = (
            u16::from_le_bytes(self.value(MAXIMUM_X)?),
            u16::from_le_bytes(self.value(MAXIMUM_Y)?),
        );
        let traces = self.value(TRACE_COUNTS)?;
        let raw_resolution = self.value(RESOLUTION)?;
        if maximum.0 == 0 || maximum.1 == 0 || traces[0] == 0 || traces[1] == 0 {
            return Err(ErrorKind::InvalidGeometry);
        }
        let mut resolutions = [0; 2];
        for (output, raw) in resolutions.iter_mut().zip(raw_resolution) {
            let value = i32::from(raw as i8);
            let dpi = if pattern <= 1 {
                value * 10 + 790
            } else {
                (value + 3) * 100
            };
            if dpi <= 0 {
                return Err(ErrorKind::InvalidGeometry);
            }
            *output = (dpi * 10 / 254) as u32;
            if *output == 0 {
                return Err(ErrorKind::InvalidGeometry);
            }
        }
        let quick_wakeup = matches!(
            (ic_type, product_id),
            (0x0d, 0xc2 | 0xb8) | (0x10, 0xbf) | (0x14, 0x120 | 0x121)
        ) || (ic_type >= 0x0d && product_id >= 0x123);
        Ok(Capabilities {
            descriptor,
            report_descriptor,
            product_id,
            pattern,
            ic_type,
            sample_version,
            clickpad,
            firmware_version,
            firmware_checksum,
            iap_version,
            maximum,
            traces: (traces[0], traces[1]),
            raw_resolution: (raw_resolution[0], raw_resolution[1]),
            resolution_per_mm: (resolutions[0], resolutions[1]),
            pressure_adjustment,
            quick_wakeup,
        })
    }
    /// Explicitly reset and configure; failed/uncertain commands are never
    /// automatically retried. Only completely queried capabilities become ready.
    pub fn initialize(&mut self) -> Result<(), Error> {
        if matches!(
            self.state,
            State::Starting | State::Ready | State::Sleeping | State::PoweredDown
        ) {
            return Err(ErrorKind::AlreadyActive.into());
        }
        let uncertain = self.state == State::Uncertain;
        let needs_power = matches!(self.state, State::Stopped | State::Uncertain);
        self.state = State::Starting;
        let result = (|| {
            self.interrupt
                .mask_and_drain()
                .map_err(ErrorKind::Interrupt)?;
            // A prior reset may have taken effect before its transfer failed.
            // Explicit recovery waits out that operation before a fresh sequence.
            if uncertain {
                self.wait(RESET_DELAY_US);
            }
            if needs_power {
                self.power(true)?;
            }
            self.query(true)
        })();
        let capability = self.quarantine(result)?;
        self.capabilities = Some(capability);
        self.state = State::Ready;
        Ok(())
    }
    pub fn poll(&mut self) -> Result<Option<Frame>, Error> {
        self.ready()?;
        let result = (|| {
            if !self.interrupt.asserted().map_err(ErrorKind::Interrupt)? {
                return Ok(None);
            }
            let length = self
                .capabilities
                .as_ref()
                .ok_or(ErrorKind::NotReady)?
                .report_length();
            let raw = if length == report::STANDARD_REPORT_BYTES {
                let mut bytes = [0; report::STANDARD_REPORT_BYTES];
                self.raw(&mut bytes)?;
                Packet::Standard(bytes)
            } else {
                let mut bytes = [0; report::EXTENDED_REPORT_BYTES];
                self.raw(&mut bytes)?;
                Packet::Extended(bytes)
            };
            report::decode(
                raw,
                self.capabilities
                    .as_ref()
                    .ok_or(ErrorKind::NotReady)?
                    .into(),
            )
            .map(Some)
        })();
        self.quarantine(result)
    }
    pub fn sleep(&mut self) -> Result<(), Error> {
        self.ready()?;
        let result = self
            .interrupt
            .mask_and_drain()
            .map_err(ErrorKind::Interrupt)
            .and_then(|()| self.write(STAND, SLEEP));
        self.quarantine(result)?;
        self.state = State::Sleeping;
        Ok(())
    }
    /// Disable device power through its actual register. The platform still
    /// owns supply rails; this does not claim an external regulator transition.
    pub fn power_down(&mut self) -> Result<(), Error> {
        self.ready()?;
        let result = self
            .interrupt
            .mask_and_drain()
            .map_err(ErrorKind::Interrupt)
            .and_then(|()| self.power(false));
        self.quarantine(result)?;
        self.state = State::PoweredDown;
        Ok(())
    }
    pub fn wake(&mut self) -> Result<(), Error> {
        if !matches!(self.state, State::Sleeping | State::PoweredDown) {
            return Err(if self.state == State::Uncertain {
                ErrorKind::NeedsReset
            } else {
                ErrorKind::NotReady
            }
            .into());
        }
        let reset = !self.capabilities.as_ref().is_some_and(|c| c.quick_wakeup);
        let result = (|| {
            self.interrupt
                .mask_and_drain()
                .map_err(ErrorKind::Interrupt)?;
            self.power(true)?;
            let capabilities = self.query(reset)?;
            if self.capabilities.as_ref() != Some(&capabilities) {
                return Err(ErrorKind::IdentityChanged);
            }
            Ok(capabilities)
        })();
        self.capabilities = Some(self.quarantine(result)?);
        self.state = State::Ready;
        Ok(())
    }
    pub fn stop(&mut self) -> Result<(), Error> {
        if self.state == State::Ready {
            self.sleep()?;
        }
        if !matches!(self.state, State::Sleeping | State::PoweredDown) {
            return Err(if self.state == State::Uncertain {
                ErrorKind::NeedsReset
            } else {
                ErrorKind::NotReady
            }
            .into());
        }
        let result = self
            .interrupt
            .mask_and_drain()
            .map_err(ErrorKind::Interrupt);
        self.quarantine(result)?;
        self.state = State::Stopped;
        Ok(())
    }
}
