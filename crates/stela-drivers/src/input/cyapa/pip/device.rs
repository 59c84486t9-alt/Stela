// SPDX-License-Identifier: GPL-2.0-only
//! Complete FIFO transfers and serialized actual command/reply ownership.
use super::*;
const IDLE_HEADERS: usize = 6;
const DRAIN_PACKETS: usize = 8;
const POLL_US: u64 = 3000;
const POWER_COMMAND: u8 = 8;
const ACTIVE_POWER: u8 = 1;
const BUTTON_POWER: u8 = 5;
const PROXIMITY_COMMAND: u8 = 0x49;
const DESCRIPTOR_COMMAND: [u8; 2] = [1, 0];
const SYSTEM_INFO: [u8; 7] = [4, 0, 5, 0, 0x2f, 0, 2];
const BOOT_INFO: [u8; 13] = [4, 0, 0x0b, 0, 0x40, 0, 1, 0x38, 0, 0, 0x70, 0x9e, 0x17];
const BOOT_EXIT: [u8; 13] = [4, 0, 0x0b, 0, 0x40, 0, 1, 0x3b, 0, 0, 0x20, 0xc7, 0x17];
#[derive(Clone, Copy)]
enum Reply {
    Descriptor,
    App { command: u8, minimum: usize },
    Deep(u8),
    Launch,
    BootInfo,
}
impl<B: Bus, I: Interrupt, T: Timer> Device<B, I, T> {
    fn wait(&self, micros: u64) {
        let start = self.timer.now_us();
        while self.timer.now_us().wrapping_sub(start) < micros {
            self.timer.relax();
        }
    }
    fn raw_read(&mut self, output: &mut [u8]) -> Result<(), ErrorKind> {
        self.bus
            .transaction(self.address, &mut [Operation::Read(output)])
            .map_err(ErrorKind::Bus)
    }
    fn raw_write(&mut self, bytes: &[u8]) -> Result<(), ErrorKind> {
        self.bus
            .transaction(self.address, &mut [Operation::Write(bytes)])
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
    fn packet(&mut self, deadline: Option<(u64, u64)>) -> Result<Option<Packet>, ErrorKind> {
        let mut header = [0; 2];
        self.raw_read(&mut header)?;
        let length = u16::from_le_bytes(header);
        let mut packet = Packet {
            bytes: [0; MAX_PACKET],
            received: 2,
        };
        packet.bytes[..2].copy_from_slice(&header);
        // Only completed reads have observable bytes; a late peek leaves its body queued.
        if deadline.is_some_and(|(start, limit)| self.timer.now_us().wrapping_sub(start) >= limit) {
            self.failed_packet = Some(packet);
            return Err(ErrorKind::Timeout);
        }
        if length == 2 {
            return Ok(None);
        }
        if length == 0 {
            return Ok(Some(packet));
        }
        if !(3..=MAX_PACKET as u16).contains(&length) {
            self.failed_packet = Some(packet);
            return Err(ErrorKind::Length(length));
        }
        // Preserve only the actually completed peek if the full transfer fails.
        self.failed_packet = Some(packet.clone());
        self.raw_read(&mut packet.bytes[..usize::from(length)])?;
        packet.received = length;
        if deadline.is_some_and(|(start, limit)| self.timer.now_us().wrapping_sub(start) >= limit) {
            self.failed_packet = Some(packet);
            return Err(ErrorKind::Timeout);
        }
        let actual = packet.declared_length();
        if actual != length {
            self.failed_packet = Some(packet);
            return Err(ErrorKind::ChangedLength {
                peek: length,
                actual,
            });
        }
        self.failed_packet = None;
        Ok(Some(packet))
    }
    fn retain(&mut self, packet: Packet) -> Result<(), ErrorKind> {
        if self.pending.len() >= MAX_PENDING {
            self.failed_packet = Some(packet);
            return Err(ErrorKind::QueueFull);
        }
        self.pending.push_back(packet);
        Ok(())
    }
    fn drain(&mut self) -> Result<(), ErrorKind> {
        let mut idle = 0;
        let mut packets = 0;
        for _ in 0..64 {
            if let Some(packet) = self.packet(None)? {
                if packet.declared_length() == 0 && self.state == State::Ready {
                    self.failed_packet = Some(packet);
                    return Err(ErrorKind::UnexpectedReset);
                }
                self.retain(packet)?;
                idle = 0;
                packets += 1;
                if packets >= DRAIN_PACKETS {
                    return Err(ErrorKind::DrainLimit);
                }
            } else {
                idle += 1;
                if idle >= IDLE_HEADERS {
                    return Ok(());
                }
            }
        }
        Err(ErrorKind::DrainLimit)
    }
    fn request(
        &mut self,
        command: &[u8],
        reply: Reply,
        timeout_us: u64,
    ) -> Result<Packet, ErrorKind> {
        // Old responses cannot acknowledge the command about to be sent.
        self.drain()?;
        self.raw_write(command)?;
        let start = self.timer.now_us();
        loop {
            self.wait(POLL_US);
            if self.timer.now_us().wrapping_sub(start) >= timeout_us {
                return Err(ErrorKind::Timeout);
            }
            if let Some(packet) = self.packet(Some((start, timeout_us)))? {
                let bytes = packet.as_bytes();
                let matched = match reply {
                    Reply::Launch => {
                        packet.declared_length() == 0 || bytes.len() >= 11 && bytes[2] == 0x30
                    }
                    Reply::BootInfo => bytes.len() >= 11 && bytes[2..5] == [0x30, 0, 1],
                    Reply::Descriptor => bytes.len() == 32 && matches!(bytes[2], 0xf7 | 0xff),
                    Reply::Deep(state) => {
                        if bytes.len() == 5 && bytes[2] == 0xf0 && bytes[4] & 15 == 8 {
                            let actual = bytes[3] & 3;
                            if actual != state {
                                self.failed_packet = Some(packet);
                                return Err(ErrorKind::CommandStatus {
                                    command: 8,
                                    status: actual,
                                });
                            }
                            true
                        } else {
                            false
                        }
                    }
                    Reply::App { command, minimum } => {
                        if bytes.len() >= 6
                            && bytes[2] == 0x1f
                            && bytes[3] == 0
                            && bytes[4] & 0x7f == 0
                            && bytes[5] == command
                        {
                            self.failed_packet = Some(packet);
                            return Err(ErrorKind::UnsupportedCommand(command));
                        }
                        let header = bytes.len() >= 5
                            && bytes[2] == 0x1f
                            && bytes[3] == 0
                            && bytes[4] & 0x7f == command;
                        if header && bytes.len() < minimum {
                            let actual = bytes.len() as u16;
                            self.failed_packet = Some(packet);
                            return Err(ErrorKind::ReportLength { id: 0x1f, actual });
                        }
                        header
                    }
                };
                if matched {
                    return Ok(packet);
                }
                if packet.declared_length() == 0 {
                    self.failed_packet = Some(packet);
                    return Err(ErrorKind::UnexpectedReset);
                }
                self.retain(packet)?;
            }
            if self.timer.now_us().wrapping_sub(start) >= timeout_us {
                return Err(ErrorKind::Timeout);
            }
        }
    }
    fn descriptor(&mut self) -> Result<([u8; 32], bool), ErrorKind> {
        let packet = self.request(&DESCRIPTOR_COMMAND, Reply::Descriptor, 300_000)?;
        let bytes = packet.as_bytes();
        let maximum = u16::from_le_bytes([bytes[16], bytes[17]]);
        let bootloader = bytes[2] == 0xff;
        if maximum != if bootloader { 0x100 } else { 0xfe } {
            self.failed_packet = Some(packet);
            return Err(ErrorKind::Descriptor);
        }
        let mut descriptor = [0; 32];
        descriptor.copy_from_slice(bytes);
        Ok((descriptor, bootloader))
    }
    fn app_status(&mut self, command: &[u8], code: u8) -> Result<(), ErrorKind> {
        let packet = self.request(
            command,
            Reply::App {
                command: code,
                minimum: 6,
            },
            500_000,
        )?;
        let status = packet.as_bytes()[5];
        if packet.as_bytes().len() != 6 {
            let actual = packet.as_bytes().len() as u16;
            self.failed_packet = Some(packet);
            return Err(ErrorKind::ReportLength { id: 0x1f, actual });
        }
        if status != 0 {
            self.failed_packet = Some(packet);
            return Err(ErrorKind::CommandStatus {
                command: code,
                status,
            });
        }
        Ok(())
    }
    fn deep(&mut self, sleeping: bool) -> Result<(), ErrorKind> {
        let state = u8::from(sleeping);
        self.request(&[5, 0, state, 8], Reply::Deep(state), 500_000)?;
        Ok(())
    }
    fn change_power(&mut self, state: u8) -> Result<(), ErrorKind> {
        self.app_status(&[4, 0, 6, 0, 0x2f, 0, POWER_COMMAND, state], POWER_COMMAND)
    }
    fn qualify(&mut self, family: u8, silicon_high: u8, packet: Packet) -> Result<(), ErrorKind> {
        if (family, silicon_high) != (0x91, 0x02) {
            self.failed_packet = Some(packet);
            return Err(ErrorKind::UnsupportedGeneration {
                family,
                silicon_high,
            });
        }
        Ok(())
    }
    fn qualify_bootloader(&mut self) -> Result<(), ErrorKind> {
        let packet = self.request(&BOOT_INFO, Reply::BootInfo, 2_000_000)?;
        let bytes = packet.as_bytes();
        if bytes.len() < 19 {
            let actual = bytes.len() as u16;
            self.failed_packet = Some(packet);
            return Err(ErrorKind::ReportLength { id: 0x30, actual });
        }
        self.qualify(bytes[8], bytes[11], packet)
    }
    fn query(&mut self, descriptor: [u8; 32]) -> Result<Capabilities, ErrorKind> {
        let packet = self.request(
            &SYSTEM_INFO,
            Reply::App {
                command: 2,
                minimum: 71,
            },
            2_000_000,
        )?;
        let bytes = packet.as_bytes();
        if bytes.len() != 71 {
            let actual = bytes.len() as u16;
            self.failed_packet = Some(packet);
            return Err(ErrorKind::ReportLength { id: 0x1f, actual });
        }
        self.qualify(bytes[19], bytes[22], packet.clone())?;
        let word = |offset: usize| u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
        let family = word(7);
        if family & 0xf000 != 0x1000 {
            self.failed_packet = Some(packet);
            return Err(ErrorKind::ProductFamily(family));
        }
        let platform_version = (bytes[49] >> 4) & 15;
        let firmware_version = if platform_version < 2 {
            (bytes[15], bytes[16])
        } else {
            (bytes[9], bytes[10])
        };
        let electrodes = (bytes[52], bytes[53]);
        let physical_size_mm = (word(54) / 100, word(56) / 100);
        let maximum = (word(58), word(60));
        let maximum_z = word(62);
        if electrodes.0 == 0
            || electrodes.1 == 0
            || physical_size_mm.0 == 0
            || physical_size_mm.1 == 0
            || maximum.0 == 0
            || maximum.1 == 0
            || maximum_z == 0
        {
            self.failed_packet = Some(packet);
            return Err(ErrorKind::InvalidGeometry);
        }
        let mut product_id = [0; 15];
        product_id[..5].copy_from_slice(&bytes[33..38]);
        product_id[5] = b'-';
        product_id[6..12].copy_from_slice(&bytes[38..44]);
        product_id[12] = b'-';
        product_id[13..].copy_from_slice(&bytes[44..46]);
        if &product_id[..5] != b"CYTRA" {
            self.failed_packet = Some(packet);
            return Err(ErrorKind::UnsupportedProduct);
        }
        let mut system_info = [0; 71];
        system_info.copy_from_slice(bytes);
        let c = Capabilities {
            descriptor,
            system_info,
            product_id,
            platform_version,
            firmware_version,
            electrodes,
            physical_size_mm,
            maximum,
            maximum_z,
            origins: (bytes[64] & 1 != 0, bytes[65] & 1 != 0),
            button_capabilities: (bytes[70] << 3) & 0x38,
        };
        Ok(c)
    }
    fn configure(&mut self, c: &Capabilities) -> Result<(), ErrorKind> {
        self.change_power(ACTIVE_POWER)?;
        if c.platform_version >= 2 {
            self.app_status(
                &[4, 0, 6, 0, 0x2f, 0, PROXIMITY_COMMAND, 1],
                PROXIMITY_COMMAND,
            )?;
        }
        Ok(())
    }
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
            let (mut descriptor, bootloader) = self.descriptor()?;
            if bootloader {
                self.qualify_bootloader()?;
                let packet = self.request(&BOOT_EXIT, Reply::Launch, 5_000_000)?;
                if packet.declared_length() != 0 {
                    self.failed_packet = Some(packet);
                    return Err(ErrorKind::FirmwareLaunch);
                }
                let (app, still_bootloader) = self.descriptor()?;
                if still_bootloader {
                    return Err(ErrorKind::FirmwareLaunch);
                }
                descriptor = app;
            }
            self.deep(false)?;
            let c = self.query(descriptor)?;
            self.configure(&c)?;
            Ok(c)
        })();
        let c = self.quarantine(result)?;
        self.capabilities = Some(c);
        self.state = State::Ready;
        Ok(())
    }
    pub fn poll(&mut self) -> Result<Option<Frame>, Error> {
        self.ready()?;
        let result = (|| {
            let packet = if let Some(packet) = self.pending.pop_front() {
                packet
            } else {
                if !self.interrupt.asserted().map_err(ErrorKind::Interrupt)? {
                    return Ok(None);
                }
                let Some(packet) = self.packet(None)? else {
                    return Ok(None);
                };
                if packet.declared_length() == 0 {
                    self.failed_packet = Some(packet);
                    return Err(ErrorKind::UnexpectedReset);
                }
                packet
            };
            match report::decode(
                packet.clone(),
                self.capabilities.as_ref().ok_or(ErrorKind::NotReady)?,
            ) {
                Ok(frame) => Ok(Some(frame)),
                Err(error) => {
                    self.failed_packet = Some(packet);
                    Err(error)
                }
            }
        })();
        self.quarantine(result)
    }
    pub fn deep_sleep(&mut self) -> Result<(), Error> {
        self.ready()?;
        let result = self
            .interrupt
            .mask_and_drain()
            .map_err(ErrorKind::Interrupt)
            .and_then(|()| self.deep(true));
        self.quarantine(result)?;
        self.state = State::DeepSleep;
        Ok(())
    }
    pub fn buttons_only(&mut self) -> Result<(), Error> {
        self.ready()?;
        let result = self
            .interrupt
            .mask_and_drain()
            .map_err(ErrorKind::Interrupt)
            .and_then(|()| self.change_power(BUTTON_POWER));
        self.quarantine(result)?;
        self.state = State::ButtonsOnly;
        Ok(())
    }
    pub fn wake(&mut self) -> Result<(), Error> {
        if self.state == State::Uncertain {
            return Err(ErrorKind::NeedsReset.into());
        }
        if !matches!(self.state, State::DeepSleep | State::ButtonsOnly) {
            return Err(ErrorKind::NotReady.into());
        }
        self.state = State::Starting;
        let result = (|| {
            self.interrupt
                .mask_and_drain()
                .map_err(ErrorKind::Interrupt)?;
            self.deep(false)?;
            let (descriptor, bootloader) = self.descriptor()?;
            if bootloader {
                return Err(ErrorKind::FirmwareLaunch);
            }
            let c = self.query(descriptor)?;
            let old = self.capabilities.as_ref().ok_or(ErrorKind::NotReady)?;
            if c.product_id != old.product_id
                || c.platform_version != old.platform_version
                || c.firmware_version != old.firmware_version
                || c.electrodes != old.electrodes
                || c.physical_size_mm != old.physical_size_mm
                || c.maximum != old.maximum
                || c.maximum_z != old.maximum_z
                || c.origins != old.origins
                || c.button_capabilities != old.button_capabilities
            {
                return Err(ErrorKind::IdentityChanged);
            }
            self.configure(&c)?;
            Ok(c)
        })();
        let c = self.quarantine(result)?;
        self.capabilities = Some(c);
        self.state = State::Ready;
        Ok(())
    }
    pub fn stop(&mut self) -> Result<(), Error> {
        self.deep_sleep()?;
        self.state = State::Stopped;
        Ok(())
    }
}
