// SPDX-License-Identifier: GPL-2.0-only
//! Source Gen3 encoded SMBus operations and distinct raw bootloader I2C blocks.
use super::{Address, Error, ErrorKind, Interrupt, RegisterAccess, State, Timer};
use crate::bus::smbus::{self, Block, I2cBlockBus, Transaction};

/// The complete Gen3 lifecycle and physical reports, backed by SMBus
/// transactions. Boot status/security operations require real fixed I2C blocks.
pub type Device<B, I, T> = super::Device<Registers<B>, I, T>;

pub struct Registers<B> {
    bus: B,
    probe_notice: Option<smbus::Error>,
    last_block: Option<Block>,
}
impl<B: I2cBlockBus> Registers<B> {
    fn address(address: Address) -> Result<smbus::Address, ErrorKind> {
        match address {
            Address::SevenBit(value @ 0x08..=0x77) if value & 1 != 0 => {
                smbus::Address::new(value).map_err(ErrorKind::Smbus)
            }
            Address::SevenBit(value) => Err(ErrorKind::UnsupportedSmbusAddress(value)),
            _ => Err(ErrorKind::InvalidAddress),
        }
    }
    fn counted(
        &mut self,
        address: smbus::Address,
        command: u8,
        bytes: &mut [u8],
    ) -> Result<(), ErrorKind> {
        let mut actual = Block::default();
        self.bus
            .transaction(
                address,
                Transaction::ReadBlock {
                    command,
                    data: &mut actual,
                },
                false,
            )
            .map_err(ErrorKind::Smbus)?;
        let length = actual.as_slice().len();
        if length == bytes.len() {
            bytes.copy_from_slice(actual.as_slice());
        }
        self.last_block = Some(actual);
        if length != bytes.len() {
            return Err(ErrorKind::BlockLength {
                command,
                expected: bytes.len(),
                actual: length,
            });
        }
        Ok(())
    }
    fn recovered_probe(error: smbus::Error) -> bool {
        matches!(
            error.kind,
            smbus::ErrorKind::Device | smbus::ErrorKind::Timeout(_)
        ) && matches!(
            error.recovery,
            smbus::Recovery::Cleared | smbus::Recovery::Killed
        )
    }
}
impl<B: I2cBlockBus> RegisterAccess for Registers<B> {
    fn read_register(
        &mut self,
        address: Address,
        register: u8,
        bytes: &mut [u8],
        allow_fallback: impl Fn() -> bool,
    ) -> Result<(), ErrorKind> {
        let address = Self::address(address)?;
        match (register, bytes.len()) {
            (0, 3) => match self.bus.read_i2c_block(address, 0, bytes) {
                Ok(()) => Ok(()),
                Err(error) if Self::recovered_probe(error) => {
                    // Pinned cyapa_get_state's odd-address ENXIO/ETIMEDOUT path.
                    // With PEC off, I801 DEV_ERR maps to ENXIO; keep the original
                    // probe outcome before requiring a real exact-count reply.
                    self.probe_notice = Some(error);
                    if !allow_fallback() {
                        return Err(ErrorKind::Smbus(error));
                    }
                    self.counted(address, 0xc1, bytes)
                }
                Err(error) => Err(ErrorKind::Smbus(error)),
            },
            (0, 27) => self.counted(address, 0x81, bytes),
            (0x2a, 27) => self.counted(address, 0x99, bytes),
            (0x29, 1) => self
                .bus
                .transaction(
                    address,
                    Transaction::ReadByte {
                        command: 3,
                        data: &mut bytes[0],
                    },
                    false,
                )
                .map_err(ErrorKind::Smbus),
            _ => Err(ErrorKind::RegisterTransfer {
                register,
                length: bytes.len(),
                write: false,
            }),
        }
    }
    fn write_register(
        &mut self,
        address: Address,
        register: u8,
        bytes: &[u8],
    ) -> Result<(), ErrorKind> {
        let address = Self::address(address)?;
        match (register, bytes.len()) {
            (0x29, 1) => self
                .bus
                .transaction(
                    address,
                    Transaction::WriteByte {
                        command: 2,
                        data: bytes[0],
                    },
                    false,
                )
                .map_err(ErrorKind::Smbus),
            (0, 11) => self
                .bus
                .write_i2c_block(address, 0, bytes)
                .map_err(ErrorKind::Smbus),
            _ => Err(ErrorKind::RegisterTransfer {
                register,
                length: bytes.len(),
                write: true,
            }),
        }
    }
}
impl<B: I2cBlockBus, I: Interrupt, T: Timer> super::Device<Registers<B>, I, T> {
    /// Grants powered exclusive bus/IRQ ownership. The source Gen3 SMBus
    /// fallback contract applies to odd seven-bit addresses; even-address and
    /// unrelated protocols are explicitly unsupported. No firmware pages are written.
    pub fn new_smbus(
        bus: B,
        interrupt: I,
        timer: T,
        address: smbus::Address,
    ) -> Result<Self, Error> {
        let address = Address::SevenBit(address.get());
        timer.check_duration(4_000_000).map_err(ErrorKind::Clock)?;
        Registers::<B>::address(address)?;
        Ok(Self {
            bus: Registers {
                bus,
                probe_notice: None,
                last_block: None,
            },
            interrupt,
            timer,
            address,
            state: State::Fresh,
            capabilities: None,
            last_status: None,
        })
    }
    /// Most recent recovered raw-status probe that required encoded fallback.
    /// A following exact-count status response is independently mandatory.
    pub fn take_probe_notice(&mut self) -> Option<smbus::Error> {
        self.bus.probe_notice.take()
    }
    /// Most recent complete count-bearing response, including malformed
    /// counts/bodies. A failed transfer does not invent a replacement block.
    pub fn take_last_block(&mut self) -> Option<Block> {
        self.bus.last_block.take()
    }
}

#[cfg(test)]
mod tests;
