// SPDX-License-Identifier: GPL-2.0-only
//! Real SMBus send-byte/block commands, query lengths and lifecycle ownership.
use super::*;
const SET_MODE: u8 = 0;
const ENABLE: u8 = 0x20;
const SLEEP: u8 = 0x21;
const RANGE: u8 = 0xa0;
const FIRMWARE: u8 = 0xa1;
const TRACES: u8 = 0xa2;
const PRODUCT_AND_SAMPLE: u8 = 0xa3;
const RESOLUTION: u8 = 0xa4;
const HELLO: u8 = 0xa7;
const REPORT: u8 = 0xa8;
const IAP_VERSION: u8 = 0xac;
const IAP_CONTROL: u8 = 0xad;
// The donor get_checksum(false) selects this address, despite its IAP name.
const IAP_CHECKSUM: u8 = 0xae;
const IAP_MODE: u16 = 1 << 6;
const EARLY_WAKE_DELAY_US: u64 = 200_000;

impl<B: Bus, I: Interrupt, T: Timer> Device<B, I, T> {
    fn transaction(&mut self, operation: Transaction<'_>) -> Result<(), ErrorKind> {
        self.bus
            .transaction(self.address, operation, false)
            .map_err(ErrorKind::Smbus)
    }
    fn block(&mut self, command: u8, minimum: usize, maximum: usize) -> Result<Block, ErrorKind> {
        let mut block = Block::default();
        self.transaction(Transaction::ReadBlock {
            command,
            data: &mut block,
        })?;
        let actual = block.as_slice().len();
        if !(minimum..=maximum).contains(&actual) {
            return Err(ErrorKind::BlockLength {
                command,
                minimum,
                maximum,
                actual,
            });
        }
        Ok(block)
    }
    fn send(&mut self, value: u8) -> Result<(), ErrorKind> {
        self.transaction(Transaction::SendByte(value))
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
    fn query(&mut self) -> Result<Capabilities, ErrorKind> {
        let hello = self.block(HELLO, 5, 5)?;
        if hello.as_slice() != [0x55; 5] {
            return Err(ErrorKind::HelloPacket);
        }
        self.send(ENABLE)?;
        let product = self.block(PRODUCT_AND_SAMPLE, 2, 32)?;
        let sample = self.block(PRODUCT_AND_SAMPLE, 2, 32)?;
        let product_id = u16::from_be_bytes([product.as_slice()[0], product.as_slice()[1]]);
        let ic_type = sample.as_slice()[1];
        let sample_version = sample.as_slice()[0];
        // Source sleep_control(false) is a no-op. Actual wake here is the
        // acknowledged ENABLE above; we do not claim power or reset effects.
        if (ic_type == 0x0e && matches!(product_id, 5..=7 | 9 | 0x13))
            || (ic_type == 8 && product_id == 0x26)
        {
            let start = self.timer.start();
            while self.timer.elapsed_us(start) < EARLY_WAKE_DELAY_US {
                self.timer.relax();
            }
        }
        self.transaction(Transaction::WriteBlock {
            command: SET_MODE,
            data: &[0, 7, 0, 1],
        })?;
        let firmware = self.block(FIRMWARE, 3, 32)?;
        let checksum = self.block(IAP_CHECKSUM, 2, 32)?;
        let iap_version = self.block(IAP_VERSION, 3, 32)?;
        let iap_control = self.block(IAP_CONTROL, 2, 32)?;
        let control = u16::from_be_bytes([iap_control.as_slice()[0], iap_control.as_slice()[1]]);
        if control & IAP_MODE != 0 {
            return Err(ErrorKind::FirmwareMode(control));
        }
        let range = self.block(RANGE, 3, 3)?;
        let traces = self.block(TRACES, 3, 3)?;
        let resolution = self.block(RESOLUTION, 3, 3)?;
        let maximum = (
            (u16::from(range.as_slice()[0] & 15) << 8) | u16::from(range.as_slice()[1]),
            (u16::from(range.as_slice()[0] & 0xf0) << 4) | u16::from(range.as_slice()[2]),
        );
        let trace_counts = (traces.as_slice()[1], traces.as_slice()[2]);
        if maximum.0 == 0 || maximum.1 == 0 || trace_counts.0 == 0 || trace_counts.1 == 0 {
            return Err(ErrorKind::InvalidGeometry);
        }
        let raw_resolution = (resolution.as_slice()[1] & 15, resolution.as_slice()[1] >> 4);
        let convert = |raw: u8| (u32::from(raw) * 10 + 790) * 10 / 254;
        Ok(Capabilities {
            product_id,
            ic_type,
            sample_version,
            clickpad: sample_version & 0x10 != 0,
            firmware_version: firmware.as_slice()[2],
            firmware_checksum: u16::from_be_bytes([checksum.as_slice()[0], checksum.as_slice()[1]]),
            iap_version: iap_version.as_slice()[2],
            maximum,
            traces: trace_counts,
            raw_resolution,
            resolution_per_mm: (convert(raw_resolution.0), convert(raw_resolution.1)),
            queries: Queries {
                hello,
                product,
                sample,
                firmware,
                checksum,
                iap_version,
                iap_control,
                range,
                traces,
                resolution,
            },
        })
    }
    /// Perform the source hello/enable/mode handshake. It is not a peripheral
    /// reset: pending reports retain their actual hardware queue semantics.
    /// Uncertain ownership requires a platform reset and a new owner.
    pub fn initialize(&mut self) -> Result<(), Error> {
        self.timer
            .check_duration(EARLY_WAKE_DELAY_US)
            .map_err(ErrorKind::Clock)?;
        if self.state == State::Uncertain {
            return Err(ErrorKind::NeedsReset.into());
        }
        if self.state != State::Fresh {
            return Err(ErrorKind::AlreadyActive.into());
        }
        self.state = State::Starting;
        let result = self
            .interrupt
            .mask_and_drain()
            .map_err(ErrorKind::Interrupt)
            .and_then(|()| self.query());
        let capabilities = self.quarantine(result)?;
        self.capabilities = Some(capabilities);
        self.state = State::Ready;
        Ok(())
    }
    pub fn poll(&mut self) -> Result<Option<Frame>, Error> {
        self.ready()?;
        let result = (|| {
            if !self.interrupt.asserted().map_err(ErrorKind::Interrupt)? {
                return Ok(None);
            }
            let block = self.block(REPORT, 1, 32)?;
            let bytes = block.as_slice();
            let expected = if bytes[0] == 0x5f { 7 } else { 32 };
            if bytes.len() != expected {
                return Err(ErrorKind::BlockLength {
                    command: REPORT,
                    minimum: expected,
                    maximum: expected,
                    actual: bytes.len(),
                });
            }
            // The donor's SMBus get_pattern always selects 0. The source's
            // high-precision width tail is absent from this 32-byte transport.
            if bytes[0] == 0x60 {
                return Err(ErrorKind::ReportId(0x60));
            }
            let c = self.capabilities.as_ref().ok_or(ErrorKind::NotReady)?;
            report::decode(Packet::Smbus(block), c.geometry()).map(Some)
        })();
        self.quarantine(result)
    }
    pub fn sleep(&mut self) -> Result<(), Error> {
        self.ready()?;
        let result = self
            .interrupt
            .mask_and_drain()
            .map_err(ErrorKind::Interrupt)
            .and_then(|()| self.send(SLEEP));
        self.quarantine(result)?;
        self.state = State::Sleeping;
        Ok(())
    }
    /// Resume through a real acknowledged ENABLE and complete re-query. The
    /// source's quick no-op wake shortcut is not used on this transport.
    pub fn wake(&mut self) -> Result<(), Error> {
        if self.state == State::Uncertain {
            return Err(ErrorKind::NeedsReset.into());
        }
        if self.state != State::Sleeping {
            return Err(ErrorKind::NotReady.into());
        }
        self.state = State::Starting;
        let result = (|| {
            self.interrupt
                .mask_and_drain()
                .map_err(ErrorKind::Interrupt)?;
            let c = self.query()?;
            if !self
                .capabilities
                .as_ref()
                .ok_or(ErrorKind::NotReady)?
                .same_identity(&c)
            {
                return Err(ErrorKind::IdentityChanged);
            }
            Ok(c)
        })();
        let capabilities = self.quarantine(result)?;
        self.capabilities = Some(capabilities);
        self.state = State::Ready;
        Ok(())
    }
    pub fn stop(&mut self) -> Result<(), Error> {
        self.sleep()?;
        self.state = State::Stopped;
        Ok(())
    }
}
