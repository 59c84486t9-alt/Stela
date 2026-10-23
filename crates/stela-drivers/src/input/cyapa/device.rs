// SPDX-License-Identifier: GPL-2.0-only
//! Actual Gen3 register transactions, firmware launch and power settling.
use super::*;
const DATA: u8 = 0;
const POWER: u8 = 0x29;
const QUERY: u8 = 0x2a;
const POWER_MASK: u8 = 0xfc;
const FULL: u8 = 0xfc;
const SLEEP: u8 = 0x14;
const BUTTONS_ONLY: u8 = 4;
const OFF: u8 = 0;
const POLL_INTERVAL_US: u64 = 100_000;
const DEACTIVATE: [u8; 11] = [0, 0xff, 0x3b, 0, 1, 2, 3, 4, 5, 6, 7];
const LAUNCH: [u8; 11] = [0, 0xff, 0xa5, 0, 1, 2, 3, 4, 5, 6, 7];

pub(super) fn classify(raw: [u8; 3]) -> HardwareState {
    if raw[0] == 0 && raw[2] == 0 && matches!(raw[1], 0x10 | 0x11) {
        HardwareState::BootloaderIdle
    } else if raw[0] == 0 && raw[1] & 0x10 != 0 {
        if raw[1] & 0x80 != 0 {
            HardwareState::BootloaderBusy
        } else if raw[2] & 0x20 != 0 {
            HardwareState::BootloaderActive
        } else {
            HardwareState::BootloaderIdle
        }
    } else if raw[0] & 0x80 != 0 && raw[1] & 8 != 0 {
        if (raw[1] >> 4) & 7 <= 5 {
            HardwareState::Operational
        } else {
            HardwareState::Unknown
        }
    } else if raw[0] == 0x0c && raw[1] == 8 {
        HardwareState::Operational
    } else if raw[1] & 0x90 != 0 {
        HardwareState::BootloaderBusy
    } else {
        HardwareState::Unknown
    }
}
pub(super) fn power_wait_ms(raw: u8) -> u64 {
    let encoded = (raw & POWER_MASK) >> 2;
    match encoded {
        0 | 1 | 63 => 20,
        2..=9 => u64::from(encoded) * 10 + 50,
        _ => u64::from(encoded - 5) * 20 + 50,
    }
}
impl<B: RegisterAccess, I: Interrupt, T: Timer> Device<B, I, T> {
    fn wait(&self, micros: u64) {
        let start = self.timer.now_us();
        while self.timer.now_us().wrapping_sub(start) < micros {
            self.timer.relax();
        }
    }
    fn read(&mut self, register: u8, bytes: &mut [u8]) -> Result<(), ErrorKind> {
        self.bus
            .read_register(self.address, register, bytes, || true)
    }
    fn write_byte(&mut self, register: u8, value: u8) -> Result<(), ErrorKind> {
        self.bus.write_register(self.address, register, &[value])
    }
    fn boot_command(&mut self, command: &[u8; 11]) -> Result<(), ErrorKind> {
        self.bus.write_register(self.address, DATA, command)
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
    fn poll_state(&mut self, timeout_us: u64) -> Result<(HardwareState, [u8; 3]), ErrorKind> {
        let start = self.timer.now_us();
        loop {
            if self.timer.now_us().wrapping_sub(start) >= timeout_us {
                return Err(ErrorKind::Timeout(
                    self.last_status.map_or(HardwareState::Unknown, classify),
                ));
            }
            let mut raw = [0; 3];
            let timer = &self.timer;
            self.bus.read_register(self.address, DATA, &mut raw, || {
                timer.now_us().wrapping_sub(start) < timeout_us
            })?;
            self.last_status = Some(raw);
            let state = classify(raw);
            if self.timer.now_us().wrapping_sub(start) >= timeout_us {
                return Err(ErrorKind::Timeout(state));
            }
            if !matches!(
                state,
                HardwareState::BootloaderBusy | HardwareState::Unknown
            ) {
                return Ok((state, raw));
            }
            self.wait(POLL_INTERVAL_US);
        }
    }
    fn launch(&mut self) -> Result<(), ErrorKind> {
        let (mut state, mut raw) = self.poll_state(4_000_000)?;
        if state == HardwareState::BootloaderActive {
            self.boot_command(&DEACTIVATE)?;
            self.wait(100_000);
            (state, raw) = self.poll_state(500_000)?;
            if state != HardwareState::BootloaderIdle {
                return Err(ErrorKind::HardwareState { state, raw });
            }
        }
        if state == HardwareState::BootloaderIdle {
            if raw[1] & 1 == 0 {
                return Err(ErrorKind::InvalidFirmware(raw));
            }
            self.boot_command(&LAUNCH)?;
            self.wait(50_000);
            (state, raw) = self.poll_state(4_000_000)?;
        }
        if state != HardwareState::Operational {
            return Err(ErrorKind::HardwareState { state, raw });
        }
        Ok(())
    }
    fn power(&mut self, requested: u8) -> Result<(), ErrorKind> {
        let mut original = [0];
        self.read(POWER, &mut original)?;
        if original[0] & POWER_MASK != requested {
            let next = (original[0] & !POWER_MASK) | requested;
            self.write_byte(POWER, next)?;
            self.wait(power_wait_ms(original[0]) * 1000);
            let mut actual = [0];
            self.read(POWER, &mut actual)?;
            if actual[0] != next {
                return Err(ErrorKind::PowerReadback {
                    expected: next,
                    actual: actual[0],
                });
            }
        }
        Ok(())
    }
    fn query(&mut self) -> Result<Capabilities, ErrorKind> {
        let mut query = [0; 27];
        self.read(QUERY, &mut query)?;
        let generation = query[20] & 15;
        if generation != 3 {
            return Err(ErrorKind::UnsupportedGeneration(generation));
        }
        if &query[..5] != b"CYTRA" {
            return Err(ErrorKind::UnsupportedProduct);
        }
        let pair = |high: u8, low_x: u8, low_y: u8| {
            (
                (u16::from(high & 0xf0) << 4) | u16::from(low_x),
                (u16::from(high & 15) << 8) | u16::from(low_y),
            )
        };
        let maximum = pair(query[21], query[22], query[23]);
        let physical_size = pair(query[24], query[25], query[26]);
        if maximum.0 == 0 || maximum.1 == 0 || physical_size.0 == 0 || physical_size.1 == 0 {
            return Err(ErrorKind::InvalidGeometry);
        }
        let mut product_id = [0; 15];
        product_id[..5].copy_from_slice(&query[..5]);
        product_id[5] = b'-';
        product_id[6..12].copy_from_slice(&query[5..11]);
        product_id[12] = b'-';
        product_id[13..].copy_from_slice(&query[11..13]);
        Ok(Capabilities {
            query,
            product_id,
            firmware_version: (query[15], query[16]),
            button_capabilities: query[19] & 0x38,
            maximum,
            physical_size,
        })
    }
    /// Real bootloader deactivation/valid-firmware launch, full power before
    /// querying, and complete query verification. This never flashes firmware.
    pub fn initialize(&mut self) -> Result<(), Error> {
        if self.state == State::Uncertain {
            return Err(ErrorKind::NeedsReset.into());
        }
        if self.state != State::Fresh {
            return Err(ErrorKind::AlreadyActive.into());
        }
        self.state = State::Starting;
        let result = (|| {
            self.interrupt
                .mask_and_drain()
                .map_err(ErrorKind::Interrupt)?;
            self.launch()?;
            self.power(FULL)?;
            self.query()
        })();
        let c = self.quarantine(result)?;
        self.capabilities = Some(c);
        self.state = State::Ready;
        Ok(())
    }
    pub fn poll(&mut self) -> Result<Option<Frame>, Error> {
        self.ready()?;
        let result = (|| {
            if !self.interrupt.asserted().map_err(ErrorKind::Interrupt)? {
                return Ok(None);
            }
            let mut raw = [0; report::REPORT_BYTES];
            self.read(DATA, &mut raw)?;
            report::decode(raw, self.capabilities.as_ref().ok_or(ErrorKind::NotReady)?).map(Some)
        })();
        self.quarantine(result)
    }
    fn suspend(&mut self, power: u8, state: State) -> Result<(), Error> {
        self.ready()?;
        let result = self
            .interrupt
            .mask_and_drain()
            .map_err(ErrorKind::Interrupt)
            .and_then(|()| self.power(power));
        self.quarantine(result)?;
        self.state = state;
        Ok(())
    }
    /// Source's 50ms scan-interval suspend mode; supply rails remain powered.
    pub fn sleep(&mut self) -> Result<(), Error> {
        self.suspend(SLEEP, State::Sleeping)
    }
    pub fn buttons_only(&mut self) -> Result<(), Error> {
        self.suspend(BUTTONS_ONLY, State::ButtonsOnly)
    }
    /// Actual peripheral power register OFF, retaining I2C command access.
    pub fn power_down(&mut self) -> Result<(), Error> {
        self.suspend(OFF, State::PoweredDown)
    }
    pub fn wake(&mut self) -> Result<(), Error> {
        if self.state == State::Uncertain {
            return Err(ErrorKind::NeedsReset.into());
        }
        if !matches!(
            self.state,
            State::Sleeping | State::ButtonsOnly | State::PoweredDown
        ) {
            return Err(ErrorKind::NotReady.into());
        }
        self.state = State::Starting;
        let result = (|| {
            self.interrupt
                .mask_and_drain()
                .map_err(ErrorKind::Interrupt)?;
            self.launch()?;
            self.power(FULL)?;
            let c = self.query()?;
            let old = self.capabilities.as_ref().ok_or(ErrorKind::NotReady)?;
            if c.product_id != old.product_id
                || c.firmware_version != old.firmware_version
                || c.button_capabilities != old.button_capabilities
                || c.maximum != old.maximum
                || c.physical_size != old.physical_size
            {
                return Err(ErrorKind::IdentityChanged);
            }
            Ok(c)
        })();
        let c = self.quarantine(result)?;
        self.capabilities = Some(c);
        self.state = State::Ready;
        Ok(())
    }
    pub fn stop(&mut self) -> Result<(), Error> {
        self.suspend(OFF, State::Stopped)
    }
}
