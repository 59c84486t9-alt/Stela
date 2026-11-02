// SPDX-License-Identifier: GPL-2.0-or-later
// I801 fixed-length I2C block sequencing adapted from Linux i2c-i801.c.
// Copyright (c) 1998-2002 Frodo Looijaard, Philip Edelbrock,
// Mark D. Studebaker; (c) 2007-2014 Jean Delvare; (c) 2010 Intel Corporation,
// David Woodhouse. See bus/THIRD_PARTY.md.
//! Fixed-length I²C blocks with kept PCI host-configuration permission.
use super::*;
use crate::bus::{
    pci::{ConfigSpace, Function},
    smbus::I2cBlockBus,
};

const PCI_HOST_CONFIGURATION: u16 = 0x40;
const SPD_WRITE_DISABLE: u8 = 1 << 4;
const PROTOCOL_I2C_BLOCK: u8 = 0x18;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigurationError {
    IdentityChanged,
    Config(crate::bus::pci::ConfigError),
    Unavailable,
}
impl From<crate::bus::pci::ConfigError> for ConfigurationError {
    fn from(error: crate::bus::pci::ConfigError) -> Self {
        Self::Config(error)
    }
}
/// Function configuration, kept through every temporary mode change.
/// # Safety
/// The provider exclusively owns the same PCI function/reset epoch and
/// host-configuration byte as the I801 register owner. Accesses are ordered and
/// byte-width; errors can follow effects. It keeps native root/mapping/firmware
/// arbitration leases when leaked and cannot borrow an ephemeral owner.
pub unsafe trait HostConfiguration {
    fn device_id(&self) -> u16;
    fn read(&mut self) -> Result<u8, ConfigurationError>;
    fn write(&mut self, value: u8) -> Result<(), ConfigurationError>;
}
/// Concrete PCI function and platform/root ownership guard.
pub struct OwnedConfiguration<C: ConfigSpace, G> {
    function: Function<C>,
    _guard: G,
}
impl<C: ConfigSpace, G> OwnedConfiguration<C, G> {
    /// # Safety
    /// Function and guard carry exclusive, powered configuration/root
    /// ownership for the full host lifetime. The same guard also excludes
    /// firmware/AML/SMM host accesses. This is not an identity-only grant.
    pub unsafe fn claim(function: Function<C>, guard: G) -> Result<Self, (Function<C>, G)> {
        if ControllerInfo::from_pci_id(function.vendor, function.device).is_none() {
            return Err((function, guard));
        }
        Ok(Self {
            function,
            _guard: guard,
        })
    }
    fn identity(&mut self) -> Result<(), ConfigurationError> {
        let expected = u32::from(self.function.vendor) | u32::from(self.function.device) << 16;
        if self.function.config().read32(0)? == expected {
            Ok(())
        } else {
            Err(ConfigurationError::IdentityChanged)
        }
    }
}
// SAFETY: construction keeps the Function/guard under its explicit
// exclusive native permission contract. ConfigSpace requires narrow real writes.
unsafe impl<C: ConfigSpace + 'static, G: 'static> HostConfiguration for OwnedConfiguration<C, G> {
    fn device_id(&self) -> u16 {
        self.function.device
    }
    fn read(&mut self) -> Result<u8, ConfigurationError> {
        self.identity()?;
        self.function
            .config()
            .read8(PCI_HOST_CONFIGURATION)
            .map_err(ConfigurationError::from)
    }
    fn write(&mut self, value: u8) -> Result<(), ConfigurationError> {
        self.identity()?;
        self.function
            .config()
            .write8(PCI_HOST_CONFIGURATION, value)
            .map_err(ConfigurationError::from)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigurationPhase {
    Before,
    Enable,
    Restore,
    Unquiesced,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfigurationFailure {
    pub phase: ConfigurationPhase,
    pub expected: u8,
    pub observed: Option<u8>,
    pub error: Option<ConfigurationError>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Failure {
    pub transfer: Option<Error>,
    pub configuration: Option<ConfigurationFailure>,
}
/// Sole owner of the ordinary SMBus engine and PCI mode permission.
/// Uncertain restoration or KILL poisons both I²C-block and normal SMBus entry
/// points; Drop then keeps the owners for platform reset/retirement.
pub struct Controller<R: Registers + 'static, T: Timer + 'static, C: HostConfiguration + 'static> {
    owners: Option<(I801<R, T>, C)>,
    original: u8,
    active: bool,
    failure: Option<Failure>,
}
impl<R: Registers + 'static, T: Timer + 'static, C: HostConfiguration + 'static>
    Controller<R, T, C>
{
    /// # Safety
    /// Host and configuration refer to the same exclusively owned, powered real
    /// function with firmware/AML/SMM/IRQ exclusion. Their static native owners
    /// remain valid when quarantined. Host has no in-flight operation.
    #[allow(
        clippy::type_complexity,
        reason = "Failed block-mode claim returns both the actual SMBus host and original PCI configuration owner"
    )]
    pub unsafe fn claim(
        host: I801<R, T>,
        mut configuration: C,
    ) -> Result<Self, (ErrorKind, (I801<R, T>, C))> {
        if !host.ready || host.locked || host.info.device != configuration.device_id() {
            return Err((ErrorKind::InvalidConfiguration, (host, configuration)));
        }
        let original = match configuration.read() {
            Ok(original) => original,
            Err(error) => return Err((ErrorKind::Configuration(error), (host, configuration))),
        };
        let kind = if original & HOST_ENABLED == 0 {
            Some(ErrorKind::HostDisabled)
        } else if original & HOST_SMI != 0 {
            Some(ErrorKind::FirmwareSmi)
        } else if original & HOST_I2C != 0 {
            Some(ErrorKind::WrongProtocolMode)
        } else {
            None
        };
        if let Some(kind) = kind {
            return Err((kind, (host, configuration)));
        }
        Ok(Self {
            owners: Some((host, configuration)),
            original,
            active: false,
            failure: None,
        })
    }
    pub fn failure(&self) -> Option<Failure> {
        self.failure
    }
    fn fault(
        &mut self,
        transfer: Option<Error>,
        configuration: Option<ConfigurationFailure>,
    ) -> Error {
        self.failure.get_or_insert(Failure {
            transfer,
            configuration,
        });
        let mut error = transfer.unwrap_or_else(|| {
            configuration
                .and_then(|failure| failure.error)
                .map_or(ErrorKind::InvalidConfiguration, ErrorKind::Configuration)
                .into()
        });
        error.recovery = Recovery::Failed;
        error
    }
    fn check(
        &mut self,
        expected: u8,
        phase: ConfigurationPhase,
    ) -> Result<(), ConfigurationFailure> {
        match self.owners.as_mut().unwrap().1.read() {
            Ok(observed) if observed == expected => Ok(()),
            Ok(observed) => Err(ConfigurationFailure {
                phase,
                expected,
                observed: Some(observed),
                error: None,
            }),
            Err(error) => Err(ConfigurationFailure {
                phase,
                expected,
                observed: None,
                error: Some(error),
            }),
        }
    }
    fn change(
        &mut self,
        expected: u8,
        phase: ConfigurationPhase,
    ) -> Result<(), ConfigurationFailure> {
        if let Err(error) = self.owners.as_mut().unwrap().1.write(expected) {
            return Err(ConfigurationFailure {
                phase,
                expected,
                observed: None,
                error: Some(error),
            });
        }
        self.check(expected, phase)
    }
    fn ready(&mut self) -> Result<(), Error> {
        if self.failure.is_some() {
            return Err(ErrorKind::NeedsReset.into());
        }
        if let Err(failure) = self.check(self.original, ConfigurationPhase::Before) {
            return Err(self.fault(None, Some(failure)));
        }
        Ok(())
    }
    fn deadline(&self, start: u64) -> Result<(), Error> {
        let host = &self.owners.as_ref().unwrap().0;
        if host.expired(start, host.config.timeout_us) {
            Err(ErrorKind::Timeout(Phase::Completion).into())
        } else {
            Ok(())
        }
    }
    fn complete(
        &mut self,
        transfer: Result<(), Error>,
        restore: bool,
        start: u64,
    ) -> Result<(), Error> {
        if !self.owners.as_ref().unwrap().0.ready {
            let failure = ConfigurationFailure {
                phase: ConfigurationPhase::Unquiesced,
                expected: self.original,
                observed: None,
                error: None,
            };
            return Err(self.fault(transfer.err(), Some(failure)));
        }
        let configuration = if restore {
            self.change(self.original, ConfigurationPhase::Restore)
        } else {
            self.check(self.original, ConfigurationPhase::Restore)
        };
        if let Err(failure) = configuration {
            return Err(self.fault(transfer.err(), Some(failure)));
        }
        self.active = false;
        // Preserve the original transfer failure while always restoring
        // configuration. Successful hardware cleanup and its final observation
        // are part of the transaction bound; the bounded private CPU copy is not.
        transfer?;
        self.deadline(start).map_err(|mut error| {
            error.recovery = Recovery::Cleared;
            error
        })
    }
    fn fixed_block(
        &mut self,
        address: Address,
        command: u8,
        write: Option<&[u8]>,
        length: usize,
    ) -> Result<[u8; MAX_BLOCK], Error> {
        if !(1..=MAX_BLOCK).contains(&length) {
            return Err(ErrorKind::InvalidBlockLength(length).into());
        }
        if self.failure.is_some() {
            return Err(ErrorKind::NeedsReset.into());
        }
        let host = &self.owners.as_ref().unwrap().0;
        // All source profiles support writes; ICH5+ adds native block reads.
        if write.is_none() && (!host.info.block_buffer || host.info.device == 0x24c3) {
            return Err(ErrorKind::UnsupportedTransaction.into());
        }
        let start = self.owners.as_ref().unwrap().0.timer.start();
        self.ready()?;
        self.deadline(start)?;
        self.active = true;
        if let Err(error) = self.owners.as_mut().unwrap().0.prepare() {
            self.active = false;
            return Err(error);
        }
        if write.is_some()
            && let Err(failure) = self.change(self.original | HOST_I2C, ConfigurationPhase::Enable)
        {
            // No START was sent. Do not repeat an uncertain config write or
            // grant the host to another user in an unknown timing mode.
            return Err(self.fault(None, Some(failure)));
        }
        if let Err(error) = self.deadline(start) {
            let finished = self.owners.as_mut().unwrap().0.finish(Some(error));
            self.complete(finished, write.is_some(), start)?;
            unreachable!("a pre-START timeout remains an error after cleanup");
        }
        let mut output = [0; MAX_BLOCK];
        let host = &mut self.owners.as_mut().unwrap().0;
        let read = write.is_none();
        host.registers.write8(
            HOST_ADDRESS,
            address.get() << 1 | u8::from(read && self.original & SPD_WRITE_DISABLE != 0),
        );
        host.registers
            .write8(if read { HOST_DATA1 } else { HOST_COMMAND }, command);
        let protocol = if read {
            PROTOCOL_I2C_BLOCK
        } else {
            PROTOCOL_BLOCK
        };
        if let Some(bytes) = write {
            host.registers.write8(HOST_DATA0, length as u8);
            host.registers.write8(BLOCK_DATA, bytes[0]);
        }
        let transfer = (|| {
            host.start_transfer(
                protocol | if read && length == 1 { LAST_BYTE } else { 0 },
                start,
            )?;
            for index in 0..length {
                host.wait(start, Phase::ByteDone)?;
                if let Some(bytes) = write {
                    if index + 1 < length {
                        host.registers.write8(BLOCK_DATA, bytes[index + 1]);
                    }
                } else {
                    output[index] = host.registers.read8(BLOCK_DATA);
                    if index + 2 == length {
                        host.registers.write8(HOST_CONTROL, protocol | LAST_BYTE);
                    }
                }
                host.registers.write8(HOST_STATUS, BYTE_DONE);
            }
            host.wait(start, Phase::Completion).map(|_| ())
        })();
        let finished = host.finish(transfer.err());
        self.complete(finished, write.is_some(), start)?;
        Ok(output)
    }
    fn ordinary(
        &mut self,
        address: Address,
        transaction: Transaction<'_>,
        pec: bool,
    ) -> Result<(), Error> {
        // PEC is admitted only by this configuration owner.
        // Unsupported protocols/profiles refuse before configuration or host I/O.
        if pec {
            if self.failure.is_some() {
                return Err(ErrorKind::NeedsReset.into());
            }
            self.owners
                .as_ref()
                .unwrap()
                .0
                .pec_supported(&transaction)?;
        }
        let start = self.owners.as_ref().unwrap().0.timer.start();
        self.ready()?;
        self.deadline(start)?;
        self.active = true;
        let result = if pec {
            self.owners
                .as_mut()
                .unwrap()
                .0
                .pec_transaction_until(address, transaction, start)
        } else {
            self.owners
                .as_mut()
                .unwrap()
                .0
                .transaction_until(address, transaction, pec, start)
        };
        self.complete(result, false, start)
    }
    /// One count-prefixed SMBus block process call, with no intermediate STOP.
    /// Request and reply counts are independently 1..=32. This requires source-
    /// listed ICH5+ block-process capability and enabled E32B policy; no byte-
    /// handshake fallback or automatic replay exists. The reply remains private
    /// through CRC/mode cleanup, the PCI guard and the final deadline.
    pub fn process_block(
        &mut self,
        address: Address,
        command: u8,
        request: &[u8],
        response: &mut Block,
        pec: bool,
    ) -> Result<(), Error> {
        if self.failure.is_some() {
            return Err(ErrorKind::NeedsReset.into());
        }
        let host = &self.owners.as_ref().unwrap().0;
        if !host.info.has_block_process_call() || !host.config.use_block_buffer {
            return Err(ErrorKind::UnsupportedTransaction.into());
        }
        if !(1..=MAX_BLOCK).contains(&request.len()) {
            return Err(ErrorKind::InvalidBlockLength(request.len()).into());
        }
        let start = host.timer.start();
        self.ready()?;
        self.deadline(start)?;
        self.active = true;
        match self
            .owners
            .as_mut()
            .unwrap()
            .0
            .block_process_until(address, command, request, pec, start)
        {
            Ok(bytes) => {
                self.complete(Ok(()), false, start)?;
                *response = bytes;
                Ok(())
            }
            Err(error) => self.complete(Err(error), false, start),
        }
    }

    /// SMBus Quick: one address/direction and ACK, with no command, payload or
    /// PEC. This is not an arbitrary empty I²C transfer. Completion still passes
    /// the original host cleanup, PCI guard and whole-operation deadline.
    pub fn quick(&mut self, address: Address, read: bool) -> Result<(), Error> {
        if self.failure.is_some() {
            return Err(ErrorKind::NeedsReset.into());
        }
        let start = self.owners.as_ref().unwrap().0.timer.start();
        self.ready()?;
        self.deadline(start)?;
        self.active = true;
        let result = self
            .owners
            .as_mut()
            .unwrap()
            .0
            .quick_until(address, read, start);
        self.complete(result, false, start)
    }

    /// [`I801::enable_host_notify`] on the kept host.
    pub fn enable_host_notify(&mut self) -> Result<(), Error> {
        if self.failure.is_some() {
            return Err(ErrorKind::NeedsReset.into());
        }
        self.owners.as_mut().unwrap().0.enable_host_notify()
    }

    /// [`I801::take_host_notify`] on the kept host.
    pub fn take_host_notify(&mut self) -> Result<Option<u8>, Error> {
        if self.failure.is_some() {
            return Err(ErrorKind::NeedsReset.into());
        }
        self.owners.as_mut().unwrap().0.take_host_notify()
    }

    #[expect(
        clippy::result_large_err,
        reason = "failed release retains the original controller and client without allocating"
    )]
    pub fn release(mut self) -> Result<(I801<R, T>, C), Self> {
        if self.active
            || self.failure.is_some()
            || self
                .owners
                .as_ref()
                .is_some_and(|(host, _)| !host.ready || host.locked)
        {
            return Err(self);
        }
        Ok(self.owners.take().unwrap())
    }
}
impl<R: Registers + 'static, T: Timer + 'static, C: HostConfiguration + 'static> I2cBlockBus
    for Controller<R, T, C>
{
    fn read_i2c_block(
        &mut self,
        address: Address,
        command: u8,
        bytes: &mut [u8],
    ) -> Result<(), Error> {
        let result = self.fixed_block(address, command, None, bytes.len())?;
        bytes.copy_from_slice(&result[..bytes.len()]);
        Ok(())
    }
    fn write_i2c_block(
        &mut self,
        address: Address,
        command: u8,
        bytes: &[u8],
    ) -> Result<(), Error> {
        self.fixed_block(address, command, Some(bytes), bytes.len())
            .map(|_| ())
    }
}
impl<R: Registers + 'static, T: Timer + 'static, C: HostConfiguration + 'static> Bus
    for Controller<R, T, C>
{
    fn transaction(
        &mut self,
        address: Address,
        transaction: Transaction<'_>,
        pec: bool,
    ) -> Result<(), Error> {
        // Stage all native read outputs until the PCI guard succeeds.
        match transaction {
            Transaction::ReceiveByte(output) => {
                let mut value = 0;
                self.ordinary(address, Transaction::ReceiveByte(&mut value), pec)?;
                *output = value;
            }
            Transaction::ReadByte { command, data } => {
                let mut value = 0;
                self.ordinary(
                    address,
                    Transaction::ReadByte {
                        command,
                        data: &mut value,
                    },
                    pec,
                )?;
                *data = value;
            }
            Transaction::ReadWord { command, data } => {
                let mut value = 0;
                self.ordinary(
                    address,
                    Transaction::ReadWord {
                        command,
                        data: &mut value,
                    },
                    pec,
                )?;
                *data = value;
            }
            Transaction::ProcessCall {
                command,
                request,
                response,
            } => {
                let mut value = 0;
                self.ordinary(
                    address,
                    Transaction::ProcessCall {
                        command,
                        request,
                        response: &mut value,
                    },
                    pec,
                )?;
                *response = value;
            }
            Transaction::ReadBlock { command, data } => {
                let mut value = Block::default();
                self.ordinary(
                    address,
                    Transaction::ReadBlock {
                        command,
                        data: &mut value,
                    },
                    pec,
                )?;
                *data = value;
            }
            transaction => self.ordinary(address, transaction, pec)?,
        }
        Ok(())
    }
}
impl<R: Registers + 'static, T: Timer + 'static, C: HostConfiguration + 'static> Drop
    for Controller<R, T, C>
{
    fn drop(&mut self) {
        if (self.active
            || self.failure.is_some()
            || self
                .owners
                .as_ref()
                .is_some_and(|(h, _)| !h.ready || h.locked))
            && let Some(owners) = self.owners.take()
        {
            core::mem::forget(owners);
        }
    }
}

#[cfg(test)]
mod tests;
