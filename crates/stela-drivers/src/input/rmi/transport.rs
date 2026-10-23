// SPDX-License-Identifier: GPL-2.0-only
//! RMI paged I2C and SMBus 2/3 mapping-table transports. Linux retained notices
//! and exact pinned donor hashes are in input/THIRD_PARTY.md.
use super::{Error, State};
use crate::bus::{i2c, smbus};
use alloc::vec::Vec;

/// Exclusive transport ownership includes the page/map state. No mutable bus
/// escape is provided: another owner must not invalidate the device's cache.
pub trait Transport {
    fn activate(&mut self) -> Result<(), Error>;
    fn read(&mut self, address: u16, output: &mut [u8]) -> Result<(), Error>;
    fn write(&mut self, address: u16, data: &[u8]) -> Result<(), Error>;
    fn reset(&mut self, command_address: u16) -> Result<(), Error>;
    fn deactivate(&mut self) -> Result<(), Error>;
}

pub(crate) fn buffer(length: usize) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| Error::Allocation)?;
    bytes.resize(length, 0);
    Ok(bytes)
}
fn range(address: u16, length: usize) -> Result<(), Error> {
    if length == 0 || length > 0x10000 - usize::from(address) {
        return Err(Error::AddressRange { address, length });
    }
    Ok(())
}
fn active(state: State) -> Result<(), Error> {
    match state {
        State::Active => Ok(()),
        State::Faulted => Err(Error::NeedsReset),
        _ => Err(Error::NotActive),
    }
}

pub struct I2c<B> {
    bus: B,
    address: i2c::Address,
    page: Option<u8>,
    state: State,
}
impl<B: i2c::Bus> I2c<B> {
    pub fn new(bus: B, address: i2c::Address) -> Result<Self, Error> {
        if !matches!(
            address,
            i2c::Address::SevenBit(0x08..=0x77) | i2c::Address::TenBit(0..=0x3ff)
        ) {
            return Err(Error::InvalidAddress);
        }
        Ok(Self {
            bus,
            address,
            page: None,
            state: State::Fresh,
        })
    }
    fn select(&mut self, page: u8) -> Result<(), Error> {
        if self.page != Some(page) {
            self.bus
                .transaction(self.address, &mut [i2c::Operation::Write(&[0xff, page])])
                .map_err(Error::I2c)?;
            self.page = Some(page);
        }
        Ok(())
    }
    fn packet(address: u16, length: usize, maximum: usize) -> Result<(), Error> {
        // A function data register may be a streaming window. Linux sends one
        // complete burst after selecting its starting page; do not invent page
        // splits or infer linear register overflow from the payload size.
        if address as u8 == 0xff || length == 0 || length > maximum {
            return Err(Error::AddressRange { address, length });
        }
        Ok(())
    }
    fn finish<R>(&mut self, result: Result<R, Error>) -> Result<R, Error> {
        if result.is_err() {
            self.page = None;
            self.state = State::Faulted;
        }
        result
    }
}
impl<B: i2c::Bus> Transport for I2c<B> {
    fn activate(&mut self) -> Result<(), Error> {
        if !matches!(self.state, State::Fresh | State::Stopped) {
            return Err(if self.state == State::Faulted {
                Error::NeedsReset
            } else {
                Error::AlreadyActive
            });
        }
        self.page = None;
        let result = self.select(0);
        self.finish(result)?;
        self.state = State::Active;
        Ok(())
    }
    fn read(&mut self, address: u16, output: &mut [u8]) -> Result<(), Error> {
        active(self.state)?;
        Self::packet(address, output.len(), 65535)?;
        // Commit caller data only after the whole transaction succeeds.
        let mut temporary = buffer(output.len())?;
        let result = (|| {
            self.select((address >> 8) as u8)?;
            self.bus
                .transaction(
                    self.address,
                    &mut [
                        i2c::Operation::Write(&[address as u8]),
                        i2c::Operation::Read(&mut temporary[..output.len()]),
                    ],
                )
                .map_err(Error::I2c)
        })();
        self.finish(result)?;
        output.copy_from_slice(&temporary[..output.len()]);
        Ok(())
    }
    fn write(&mut self, address: u16, data: &[u8]) -> Result<(), Error> {
        active(self.state)?;
        Self::packet(address, data.len(), 65534)?;
        let mut temporary = buffer(data.len() + 1)?;
        temporary[0] = address as u8;
        temporary[1..=data.len()].copy_from_slice(data);
        let result = (|| {
            self.select((address >> 8) as u8)?;
            self.bus
                .transaction(
                    self.address,
                    &mut [i2c::Operation::Write(&temporary[..data.len() + 1])],
                )
                .map_err(Error::I2c)
        })();
        self.finish(result)
    }
    fn reset(&mut self, command_address: u16) -> Result<(), Error> {
        self.write(command_address, &[1])?;
        self.page = None;
        Ok(())
    }
    fn deactivate(&mut self) -> Result<(), Error> {
        active(self.state)?;
        // The controller owns power/sleep. This transport owns only page state.
        self.page = None;
        self.state = State::Stopped;
        Ok(())
    }
}

/// The SMBus RMI sensor shares physical state with its PS/2 companion. The
/// platform must own both transports and actually reset the companion before
/// activation, then restore its known PS/2 state on detach. An AML identity or
/// a local flag cannot implement these physical effects.
pub trait Companion {
    fn reset_for_smbus(&mut self) -> Result<(), CompanionError>;
    fn restore_ps2(&mut self) -> Result<(), CompanionError>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompanionError {
    Unavailable,
    Hardware(u32),
}
#[derive(Clone, Copy, Debug)]
struct Mapping {
    address: u16,
    length: u8,
    writable: bool,
}
pub struct Smbus<B, C, T> {
    bus: B,
    companion: C,
    timer: T,
    reset_delay_us: u64,
    address: smbus::Address,
    mapping: [Option<Mapping>; 8],
    next: usize,
    version: Option<u8>,
    state: State,
}
impl<B: smbus::Bus, C: Companion, T: i2c::Timer> Smbus<B, C, T> {
    /// `reset_delay_us` is the actual platform-qualified companion firmware
    /// settling time (Linux default100ms). It runs before every mode/version
    /// read, independently of the controller's later F01 settling interval.
    pub fn new(
        bus: B,
        address: smbus::Address,
        companion: C,
        timer: T,
        reset_delay_us: u64,
    ) -> Result<Self, Error> {
        if reset_delay_us == 0 {
            return Err(Error::InvalidConfiguration);
        }
        Ok(Self {
            bus,
            companion,
            timer,
            reset_delay_us,
            address,
            mapping: [None; 8],
            next: 0,
            version: None,
            state: State::Fresh,
        })
    }
    pub fn version(&self) -> Option<u8> {
        self.version
    }
    fn enable(&mut self) -> Result<(), Error> {
        self.mapping = [None; 8];
        self.next = 0;
        self.version = None;
        self.companion.reset_for_smbus().map_err(Error::Companion)?;
        let start = self.timer.now_us();
        while self.timer.now_us().wrapping_sub(start) < self.reset_delay_us {
            self.timer.relax();
        }
        // Reading this byte actually switches the device into SMBus mode.
        let mut version = 0;
        self.bus
            .transaction(
                self.address,
                smbus::Transaction::ReadByte {
                    command: 0xfd,
                    data: &mut version,
                },
                false,
            )
            .map_err(Error::Smbus)?;
        if !matches!(version, 1 | 2) {
            return Err(Error::SmbusVersion(u16::from(version) + 1));
        }
        self.version = Some(version + 1);
        Ok(())
    }
    fn command(&mut self, address: u16, length: usize, read: bool) -> Result<u8, Error> {
        if let Some(index) = self.mapping.iter().position(|entry| {
            entry.is_some_and(|entry| {
                entry.address == address
                    && if read {
                        usize::from(entry.length) == length
                    } else {
                        entry.writable
                    }
            })
        }) {
            return Ok(index as u8);
        }
        let index = self.next;
        let mapping = Mapping {
            address,
            length: length as u8,
            writable: !read,
        };
        let bytes = [
            address as u8,
            (address >> 8) as u8,
            length as u8,
            u8::from(!read),
        ];
        // Commit the software cache only once the actual map write is accepted.
        self.bus
            .transaction(
                self.address,
                smbus::Transaction::WriteBlock {
                    command: index as u8 + 0x80,
                    data: &bytes,
                },
                false,
            )
            .map_err(Error::Smbus)?;
        self.mapping[index] = Some(mapping);
        self.next = (index + 1) % self.mapping.len();
        Ok(index as u8)
    }
    fn finish<R>(&mut self, result: Result<R, Error>) -> Result<R, Error> {
        if result.is_err() {
            self.mapping = [None; 8];
            self.version = None;
            self.state = State::Faulted;
        }
        result
    }
}
impl<B: smbus::Bus, C: Companion, T: i2c::Timer> Transport for Smbus<B, C, T> {
    fn activate(&mut self) -> Result<(), Error> {
        if !matches!(self.state, State::Fresh | State::Stopped) {
            return Err(if self.state == State::Faulted {
                Error::NeedsReset
            } else {
                Error::AlreadyActive
            });
        }
        let result = self.enable();
        self.finish(result)?;
        self.state = State::Active;
        Ok(())
    }
    fn read(&mut self, address: u16, output: &mut [u8]) -> Result<(), Error> {
        active(self.state)?;
        range(address, output.len())?;
        let mut temporary = buffer(output.len())?;
        let result = (|| {
            let mut offset = 0;
            for chunk in temporary.chunks_mut(smbus::MAX_BLOCK) {
                let command = self.command(address + offset as u16, chunk.len(), true)?;
                let mut block = smbus::Block::default();
                self.bus
                    .transaction(
                        self.address,
                        smbus::Transaction::ReadBlock {
                            command,
                            data: &mut block,
                        },
                        false,
                    )
                    .map_err(Error::Smbus)?;
                if block.as_slice().len() != chunk.len() {
                    return Err(Error::BlockLength {
                        expected: chunk.len(),
                        actual: block.as_slice().len(),
                    });
                }
                chunk.copy_from_slice(block.as_slice());
                offset += chunk.len();
            }
            Ok(())
        })();
        self.finish(result)?;
        output.copy_from_slice(&temporary);
        Ok(())
    }
    fn write(&mut self, address: u16, data: &[u8]) -> Result<(), Error> {
        active(self.state)?;
        range(address, data.len())?;
        let result = (|| {
            let mut offset = 0;
            for chunk in data.chunks(smbus::MAX_BLOCK) {
                let command = self.command(address + offset as u16, chunk.len(), false)?;
                self.bus
                    .transaction(
                        self.address,
                        smbus::Transaction::WriteBlock {
                            command,
                            data: chunk,
                        },
                        false,
                    )
                    .map_err(Error::Smbus)?;
                offset += chunk.len();
            }
            Ok(())
        })();
        self.finish(result)
    }
    fn reset(&mut self, _command_address: u16) -> Result<(), Error> {
        active(self.state)?;
        // Linux intentionally omits the RMI software RESET on SMBus: only the
        // exclusive PS/2 companion may reset this shared physical device.
        let result = self.enable();
        self.finish(result)
    }
    fn deactivate(&mut self) -> Result<(), Error> {
        active(self.state)?;
        let result = self.companion.restore_ps2().map_err(Error::Companion);
        self.finish(result)?;
        self.mapping = [None; 8];
        self.version = None;
        self.state = State::Stopped;
        Ok(())
    }
}
