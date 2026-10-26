// SPDX-License-Identifier: GPL-2.0-or-later
// I801 fixed-length I2C block sequencing adapted from Linux i2c-i801.c.
// Copyright (c) 1998-2002 Frodo Looijaard, Philip Edelbrock,
// Mark D. Studebaker; (c) 2007-2014 Jean Delvare; (c) 2010 Intel Corporation,
// David Woodhouse. See bus/THIRD_PARTY.md.
//! Fixed-length I²C blocks with actual retained PCI host-configuration authority.
use super::*;
use crate::bus::{
    pci::{ConfigSpace, Function},
    smbus::I2cBlockBus,
};

const PCI_HOST_CONFIGURATION: u16 = 0x40;
const SPD_WRITE_DISABLE: u8 = 1 << 4;
const PROTOCOL_I2C_BLOCK: u8 = 0x18;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfigurationError;
/// Actual function configuration, retained through every temporary mode change.
/// # Safety
/// The provider exclusively owns the same actual PCI function/reset epoch and
/// host-configuration byte as the I801 register owner. Accesses are ordered and
/// byte-width; errors can follow effects. It retains native root/mapping/firmware
/// arbitration leases when leaked and cannot borrow an ephemeral owner.
pub unsafe trait HostConfiguration {
    fn device_id(&self) -> u16;
    fn read(&mut self) -> Result<u8, ConfigurationError>;
    fn write(&mut self, value: u8) -> Result<(), ConfigurationError>;
}
/// Concrete PCI function and actual platform/root ownership guard.
pub struct OwnedConfiguration<C: ConfigSpace, G> {
    function: Function<C>,
    _guard: G,
}
impl<C: ConfigSpace, G> OwnedConfiguration<C, G> {
    /// # Safety
    /// Function and guard carry actual exclusive, powered configuration/root
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
        if self.function.config().read32(0) == expected {
            Ok(())
        } else {
            Err(ConfigurationError)
        }
    }
}
// SAFETY: construction retains the actual Function/guard under its explicit
// exclusive native authority contract. ConfigSpace requires narrow real writes.
unsafe impl<C: ConfigSpace + 'static, G: 'static> HostConfiguration for OwnedConfiguration<C, G> {
    fn device_id(&self) -> u16 {
        self.function.device
    }
    fn read(&mut self) -> Result<u8, ConfigurationError> {
        self.identity()?;
        Ok(self.function.config().read8(PCI_HOST_CONFIGURATION))
    }
    fn write(&mut self, value: u8) -> Result<(), ConfigurationError> {
        self.identity()?;
        self.function.config().write8(PCI_HOST_CONFIGURATION, value);
        Ok(())
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
    pub access_failed: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Failure {
    pub transfer: Option<Error>,
    pub configuration: Option<ConfigurationFailure>,
}
/// Sole owner of the ordinary SMBus engine and actual PCI mode authority.
/// Uncertain restoration or KILL poisons both I²C-block and normal SMBus entry
/// points; Drop then retains the actual owners for platform reset/retirement.
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
    #[allow(clippy::type_complexity)]
    pub unsafe fn claim(
        host: I801<R, T>,
        mut configuration: C,
    ) -> Result<Self, (ErrorKind, (I801<R, T>, C))> {
        if !host.ready || host.locked || host.info.device != configuration.device_id() {
            return Err((ErrorKind::InvalidConfiguration, (host, configuration)));
        }
        let Ok(original) = configuration.read() else {
            return Err((ErrorKind::InvalidConfiguration, (host, configuration)));
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
        let mut error = transfer.unwrap_or_else(|| ErrorKind::InvalidConfiguration.into());
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
                access_failed: false,
            }),
            Err(_) => Err(ConfigurationFailure {
                phase,
                expected,
                observed: None,
                access_failed: true,
            }),
        }
    }
    fn change(
        &mut self,
        expected: u8,
        phase: ConfigurationPhase,
    ) -> Result<(), ConfigurationFailure> {
        if self.owners.as_mut().unwrap().1.write(expected).is_err() {
            return Err(ConfigurationFailure {
                phase,
                expected,
                observed: None,
                access_failed: true,
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
                access_failed: false,
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
        // Preserve the original transfer failure while always restoring actual
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
        // PEC is admitted only by this retained actual configuration owner.
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
    /// through CRC/mode cleanup, the actual PCI guard and the final deadline.
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
    /// the original host cleanup, actual PCI guard and whole-operation deadline.
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
        // Stage all native read outputs until the actual PCI guard succeeds.
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
mod tests {
    use super::*;
    use alloc::{rc::Rc, vec, vec::Vec};
    use core::cell::{Cell, RefCell};

    #[derive(Clone)]
    struct Time(Rc<Cell<u64>>);
    impl Timer for Time {
        fn now_us(&self) -> u64 {
            self.0.get()
        }
        fn relax(&self) {
            self.0.set(self.0.get().wrapping_add(1));
        }
    }
    struct Lease(Rc<Cell<usize>>);
    impl Drop for Lease {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    struct Hardware {
        bytes: [u8; 32],
        status: u8,
        configuration: u8,
        time: Time,
        active: bool,
        block: bool,
        read: bool,
        simple: bool,
        done: bool,
        index: usize,
        length: usize,
        last: bool,
        last_index: Option<usize>,
        staged: Option<u8>,
        due: u64,
        received: Vec<u8>,
        starts: Vec<(u8, u8, u8, u8)>,
        config_log: Vec<(bool, u8)>,
        control_writes: Vec<u8>,
        read_counts: [usize; 32],
        read_jump: Option<(u8, usize, u64)>,
        config_jump: Option<(usize, u64)>,
        write_jump: Option<(u8, u64)>,
        config_count: usize,
        config_fault: Option<(usize, bool)>,
        ignore_mode: bool,
        kill_stuck: bool,
        hang: bool,
        error: bool,
    }
    impl Hardware {
        fn status(&mut self) -> u8 {
            if self.active && self.time.now_us().wrapping_sub(self.due) < (1u64 << 63) && !self.hang
            {
                if self.error {
                    self.status |= DEV_ERR;
                } else if self.simple || self.done {
                    self.active = false;
                    self.status = (self.status & INUSE) | INTR;
                    self.bytes[5] = 0x21;
                    self.bytes[6] = 0x39;
                } else {
                    self.status |= BYTE_DONE;
                    if !self.read && self.received.len() == self.index {
                        let byte = self
                            .staged
                            .take()
                            .expect("next output byte must precede byte done");
                        self.received.push(byte);
                    }
                }
            }
            let old = self.status;
            self.status |= INUSE;
            old
        }
    }
    struct Regs {
        state: Rc<RefCell<Hardware>>,
        _lease: Lease,
    }
    impl Registers for Regs {
        fn read8(&mut self, offset: u8) -> u8 {
            let mut h = self.state.borrow_mut();
            h.read_counts[usize::from(offset)] += 1;
            let value = match offset {
                HOST_STATUS => h.status(),
                BLOCK_DATA => {
                    assert!(h.read && h.status & BYTE_DONE != 0);
                    (h.index as u8).wrapping_mul(7).wrapping_add(0x31)
                }
                _ => h.bytes[usize::from(offset)],
            };
            if let Some((reg, count, delta)) = h.read_jump
                && reg == offset
                && count == h.read_counts[usize::from(offset)]
            {
                h.time.0.set(h.time.now_us().wrapping_add(delta));
            }
            value
        }
        fn write8(&mut self, offset: u8, value: u8) {
            let mut h = self.state.borrow_mut();
            if let Some((reg, delta)) = h.write_jump
                && reg == offset
            {
                h.time.0.set(h.time.now_us().wrapping_add(delta));
                h.write_jump = None;
            }
            if offset == HOST_STATUS {
                if value & BYTE_DONE != 0 && h.status & BYTE_DONE != 0 {
                    h.status &= !BYTE_DONE;
                    if h.read && h.last_index == Some(h.index) || !h.read && h.index + 1 == h.length
                    {
                        assert_eq!(
                            h.index + 1,
                            h.length,
                            "LAST_BYTE controls the real last transfer"
                        );
                        h.done = true;
                    } else {
                        h.index += 1;
                    }
                    h.due = h.time.now_us().wrapping_add(1);
                }
                h.status &= !(value & (INUSE | STATUS_FLAGS));
                return;
            }
            if offset == BLOCK_DATA {
                h.staged = Some(value);
                h.bytes[7] = value;
                return;
            }
            if offset == HOST_CONTROL {
                h.control_writes.push(value);
                if value & KILL != 0 {
                    if !h.kill_stuck {
                        h.active = false;
                        h.status = (h.status & INUSE) | FAILED;
                    }
                } else if value & START != 0 {
                    let protocol = value & 0x1c;
                    h.block = matches!(protocol, PROTOCOL_BLOCK | PROTOCOL_I2C_BLOCK);
                    h.simple = !h.block;
                    h.read = if protocol == PROTOCOL_I2C_BLOCK {
                        true
                    } else {
                        h.bytes[4] & 1 != 0
                    };
                    h.index = 0;
                    h.done = false;
                    h.last = value & LAST_BYTE != 0;
                    h.last_index = h.last.then_some(0);
                    h.received.clear();
                    h.active = true;
                    h.status |= HOST_BUSY;
                    h.due = h.time.now_us().wrapping_add(1);
                    let address = h.bytes[4];
                    let command = h.bytes[3];
                    let data1 = h.bytes[6];
                    let mode = h.configuration;
                    h.starts.push((protocol, address, command, data1));
                    if h.block {
                        assert_eq!(
                            h.bytes[13] & AUX_BUFFER,
                            0,
                            "I2C blocks cannot use SMBus block buffer"
                        );
                        if h.read {
                            assert_eq!(address & 1, u8::from(mode & SPD_WRITE_DISABLE != 0));
                            assert_eq!(data1, 0xa7);
                            assert_eq!(mode & HOST_I2C, 0);
                        } else {
                            assert_ne!(mode & HOST_I2C, 0);
                            assert_eq!(command, 0xa7);
                            assert_eq!(usize::from(h.bytes[5]), h.length);
                        }
                        assert_eq!(h.last, h.read && h.length == 1);
                    }
                } else if value & LAST_BYTE != 0 {
                    // After BYTE_DONE, the source LAST_BYTE write applies to the
                    // next read byte; the initial START|LAST applies to byte zero.
                    h.last = true;
                    h.last_index = Some(h.index + 1);
                }
                h.bytes[2] = value;
                return;
            }
            h.bytes[usize::from(offset)] = value;
        }
    }
    struct Config {
        state: Rc<RefCell<Hardware>>,
        device: u16,
        _lease: Lease,
    }
    // SAFETY: fixture's actual function/configuration is shared for inspection only;
    // the controller owns the sole native configuration lease and host engine.
    unsafe impl HostConfiguration for Config {
        fn device_id(&self) -> u16 {
            self.device
        }
        fn read(&mut self) -> Result<u8, ConfigurationError> {
            let mut h = self.state.borrow_mut();
            h.config_count += 1;
            let n = h.config_count;
            if let Some((count, delta)) = h.config_jump
                && count == n
            {
                h.time.0.set(h.time.now_us().wrapping_add(delta));
            }
            if h.config_fault == Some((n, false)) {
                return Err(ConfigurationError);
            }
            let value = h.configuration;
            h.config_log.push((false, value));
            if h.config_fault == Some((n, true)) {
                Err(ConfigurationError)
            } else {
                Ok(value)
            }
        }
        fn write(&mut self, value: u8) -> Result<(), ConfigurationError> {
            let mut h = self.state.borrow_mut();
            h.config_count += 1;
            let n = h.config_count;
            if let Some((count, delta)) = h.config_jump
                && count == n
            {
                h.time.0.set(h.time.now_us().wrapping_add(delta));
            }
            if h.config_fault == Some((n, false)) {
                return Err(ConfigurationError);
            }
            assert!(
                !h.active,
                "configuration cannot be restored on an unquiesced host"
            );
            h.config_log.push((true, value));
            if !h.ignore_mode {
                h.configuration = value;
            }
            if h.config_fault == Some((n, true)) {
                Err(ConfigurationError)
            } else {
                Ok(())
            }
        }
    }
    type Host = Controller<Regs, Time, Config>;
    struct Fixture {
        host: Host,
        state: Rc<RefCell<Hardware>>,
        register_drop: Rc<Cell<usize>>,
        config_drop: Rc<Cell<usize>>,
    }
    fn fixture(device: u16, spd: bool) -> Fixture {
        let time = Time(Rc::new(Cell::new(u64::MAX - 30)));
        let configuration = HOST_ENABLED | if spd { SPD_WRITE_DISABLE } else { 0 };
        let state = Rc::new(RefCell::new(Hardware {
            bytes: [0; 32],
            status: 0,
            configuration,
            time: time.clone(),
            active: false,
            block: false,
            read: false,
            simple: false,
            done: false,
            index: 0,
            length: 1,
            last: false,
            last_index: None,
            staged: None,
            due: 0,
            received: Vec::new(),
            starts: Vec::new(),
            config_log: Vec::new(),
            control_writes: Vec::new(),
            read_counts: [0; 32],
            read_jump: None,
            config_jump: None,
            write_jump: None,
            config_count: 0,
            config_fault: None,
            ignore_mode: false,
            kill_stuck: false,
            hang: false,
            error: false,
        }));
        let register_drop = Rc::new(Cell::new(0));
        let config_drop = Rc::new(Cell::new(0));
        let registers = Regs {
            state: state.clone(),
            _lease: Lease(register_drop.clone()),
        };
        let cfg = Config {
            state: state.clone(),
            device,
            _lease: Lease(config_drop.clone()),
        };
        let host = I801::new(
            registers,
            time,
            ControllerInfo::from_pci_id(0x8086, device).unwrap(),
            configuration,
            ConfigDefaults::default(),
        )
        .ok()
        .unwrap();
        // SAFETY: fixture's actual powered/exclusive host and actual configuration
        // use the same hardware and own distinct real register/config guards.
        let host = unsafe { Controller::claim(host, cfg) }.ok().unwrap();
        state.borrow_mut().config_count = 0;
        state.borrow_mut().config_log.clear();
        Fixture {
            host,
            state,
            register_drop,
            config_drop,
        }
    }
    // Avoid confusing the independent PCI Config provider with host settings.
    use super::super::Config as ConfigDefaults;
    fn address() -> Address {
        Address::new(0x2c).unwrap()
    }
    fn input(length: usize) -> Vec<u8> {
        (0..length)
            .map(|i| (i as u8).wrapping_mul(19).wrapping_add(3))
            .collect()
    }

    #[test]
    fn fixed_length_wire_has_no_count_prefix_all_lengths_both_spd_policies_and_old_writes() {
        for device in [0x2413, 0x24c3, 0x24d3, 0x7e22] {
            for spd in [false, true] {
                let mut f = fixture(device, spd);
                for length in 1..=MAX_BLOCK {
                    f.state.borrow_mut().length = length;
                    f.host
                        .write_i2c_block(address(), 0xa7, &input(length))
                        .unwrap();
                    assert_eq!(f.state.borrow().received, input(length));
                    assert_eq!(
                        f.state.borrow().configuration,
                        HOST_ENABLED | if spd { SPD_WRITE_DISABLE } else { 0 }
                    );
                    if matches!(device, 0x24d3 | 0x7e22) {
                        let mut out = vec![0xa5; length];
                        f.host.read_i2c_block(address(), 0xa7, &mut out).unwrap();
                        assert_eq!(
                            out,
                            (0..length)
                                .map(|i| (i as u8).wrapping_mul(7).wrapping_add(0x31))
                                .collect::<Vec<_>>()
                        );
                    }
                }
                assert!(f.host.failure().is_none());
                let owners = f.host.release().ok().unwrap();
                drop(owners);
                assert_eq!(f.register_drop.get(), 1);
                assert_eq!(f.config_drop.get(), 1);
            }
        }
    }
    #[test]
    fn invalid_lengths_and_unsupported_old_reads_touch_neither_controller_nor_configuration() {
        let mut f = fixture(0x24c3, false);
        for length in [0, 33] {
            assert_eq!(
                f.host
                    .write_i2c_block(address(), 0xa7, &vec![0; length])
                    .unwrap_err()
                    .kind,
                ErrorKind::InvalidBlockLength(length)
            );
            assert_eq!(
                f.host
                    .read_i2c_block(address(), 0xa7, &mut vec![0; length])
                    .unwrap_err()
                    .kind,
                ErrorKind::InvalidBlockLength(length)
            );
        }
        let mut out = [0xa5; 3];
        assert_eq!(
            f.host
                .read_i2c_block(address(), 0xa7, &mut out)
                .unwrap_err()
                .kind,
            ErrorKind::UnsupportedTransaction
        );
        assert_eq!(out, [0xa5; 3]);
        assert!(f.state.borrow().starts.is_empty());
        assert_eq!(f.state.borrow().config_count, 0);
    }
    #[test]
    fn before_and_after_each_config_access_preserve_caller_outputs_and_actual_owners() {
        for write in [false, true] {
            let total = if write { 5 } else { 2 };
            for index in 1..=total {
                for after in [false, true] {
                    let mut f = fixture(0x7e22, false);
                    f.state.borrow_mut().length = 3;
                    f.state.borrow_mut().config_fault = Some((index, after));
                    let mut out = [0xa5; 3];
                    let error = if write {
                        f.host.write_i2c_block(address(), 0xa7, &input(3))
                    } else {
                        f.host.read_i2c_block(address(), 0xa7, &mut out)
                    }
                    .unwrap_err();
                    assert_eq!(error.recovery, Recovery::Failed);
                    assert_eq!(out, [0xa5; 3]);
                    let first = f.host.failure().unwrap();
                    let count = f.state.borrow().config_count;
                    let starts = f.state.borrow().starts.len();
                    assert_eq!(
                        f.host
                            .transaction(address(), Transaction::ReceiveByte(&mut out[0]), false)
                            .unwrap_err()
                            .kind,
                        ErrorKind::NeedsReset
                    );
                    assert_eq!(
                        f.host
                            .write_i2c_block(address(), 0xa7, &[1])
                            .unwrap_err()
                            .kind,
                        ErrorKind::NeedsReset
                    );
                    assert_eq!(f.host.failure(), Some(first));
                    assert_eq!(f.state.borrow().config_count, count);
                    assert_eq!(f.state.borrow().starts.len(), starts);
                    drop(f.host);
                    assert_eq!(f.register_drop.get(), 0);
                    assert_eq!(f.config_drop.get(), 0);
                }
            }
        }
    }
    #[test]
    fn rejected_mode_never_starts_and_failed_kill_never_restores_mode_or_releases_owners() {
        let mut f = fixture(0x7e22, false);
        f.state.borrow_mut().ignore_mode = true;
        let error = f
            .host
            .write_i2c_block(address(), 0xa7, &input(3))
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::InvalidConfiguration);
        assert!(f.state.borrow().starts.is_empty());
        assert_eq!(
            f.host.failure().unwrap().configuration.unwrap().observed,
            Some(HOST_ENABLED)
        );
        let mut f = fixture(0x7e22, false);
        f.state.borrow_mut().length = 3;
        f.state.borrow_mut().hang = true;
        f.state.borrow_mut().kill_stuck = true;
        f.host.owners.as_mut().unwrap().0.config.timeout_us = 5;
        f.host.owners.as_mut().unwrap().0.config.recovery_timeout_us = 5;
        let error = f
            .host
            .write_i2c_block(address(), 0xa7, &input(3))
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Timeout(Phase::ByteDone));
        assert_eq!(error.recovery, Recovery::Failed);
        assert_eq!(
            f.host.failure().unwrap().configuration.unwrap().phase,
            ConfigurationPhase::Unquiesced
        );
        assert_eq!(f.state.borrow().configuration, HOST_ENABLED | HOST_I2C);
        assert_eq!(
            f.state
                .borrow()
                .config_log
                .iter()
                .filter(|(w, _)| *w)
                .count(),
            1
        );
        drop(f.host);
        assert_eq!(f.register_drop.get(), 0);
        assert_eq!(f.config_drop.get(), 0);
    }
    #[test]
    fn original_device_error_survives_failed_configuration_cleanup_and_known_error_does_not_retry()
    {
        let mut f = fixture(0x7e22, false);
        f.state.borrow_mut().length = 3;
        f.state.borrow_mut().error = true;
        f.state.borrow_mut().config_fault = Some((4, true));
        let error = f
            .host
            .write_i2c_block(address(), 0xa7, &input(3))
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Device);
        assert_eq!(error.recovery, Recovery::Failed);
        let failure = f.host.failure().unwrap();
        assert_eq!(failure.transfer.unwrap().kind, ErrorKind::Device);
        assert_eq!(
            failure.configuration.unwrap().phase,
            ConfigurationPhase::Restore
        );
        assert_eq!(f.state.borrow().starts.len(), 1);
        let mut f = fixture(0x7e22, false);
        f.state.borrow_mut().length = 3;
        f.state.borrow_mut().error = true;
        assert_eq!(
            f.host
                .write_i2c_block(address(), 0xa7, &input(3))
                .unwrap_err()
                .kind,
            ErrorKind::Device
        );
        assert!(f.host.failure().is_none());
        assert_eq!(f.state.borrow().configuration, HOST_ENABLED);
        f.state.borrow_mut().error = false;
        f.host.write_i2c_block(address(), 0xa7, &input(3)).unwrap();
        assert_eq!(f.state.borrow().starts.len(), 2);
    }
    #[test]
    fn ordinary_smbus_read_is_published_only_after_the_configuration_guard() {
        let mut f = fixture(0x7e22, false);
        let mut word = 0xa5a5;
        f.host
            .transaction(
                address(),
                Transaction::ReadWord {
                    command: 0x11,
                    data: &mut word,
                },
                false,
            )
            .unwrap();
        assert_eq!(word, 0x3921);
        f.state.borrow_mut().config_count = 0;
        f.state.borrow_mut().config_fault = Some((2, true));
        word = 0xa5a5;
        assert_eq!(
            f.host
                .transaction(
                    address(),
                    Transaction::ReadWord {
                        command: 0x11,
                        data: &mut word
                    },
                    false
                )
                .unwrap_err()
                .recovery,
            Recovery::Failed
        );
        assert_eq!(word, 0xa5a5);
    }

    #[test]
    fn actual_function_provider_uses_narrow_writes_and_retains_its_root_guard() {
        struct NativeSpace {
            id: Rc<Cell<u32>>,
            byte: Rc<Cell<u8>>,
            writes: Rc<Cell<usize>>,
        }
        impl ConfigSpace for NativeSpace {
            fn read32(&self, offset: u16) -> u32 {
                match offset {
                    0 => self.id.get(),
                    8 => 0x0c05_0000,
                    _ => 0,
                }
            }
            fn write32(&mut self, _: u16, _: u32) {
                panic!("configuration byte requires a narrow actual store")
            }
            fn read8(&self, offset: u16) -> u8 {
                assert_eq!(offset, PCI_HOST_CONFIGURATION);
                self.byte.get()
            }
            fn write8(&mut self, offset: u16, value: u8) {
                assert_eq!(offset, PCI_HOST_CONFIGURATION);
                self.writes.set(self.writes.get() + 1);
                self.byte.set(value);
            }
        }
        let id = Rc::new(Cell::new(0x7e22_8086));
        let byte = Rc::new(Cell::new(HOST_ENABLED));
        let writes = Rc::new(Cell::new(0));
        let drops = Rc::new(Cell::new(0));
        let space = NativeSpace {
            id: id.clone(),
            byte: byte.clone(),
            writes: writes.clone(),
        };
        let function = Function::new(
            crate::bus::pci::Address {
                segment: 0,
                bus: 0,
                device: 31,
                function: 4,
            },
            space,
        )
        .unwrap();
        // SAFETY: native configuration model and its actual retained root lease
        // are exclusively owned by this provider; no bus request is pending.
        let mut cfg = unsafe { OwnedConfiguration::claim(function, Lease(drops.clone())) }
            .ok()
            .unwrap();
        assert_eq!(cfg.read(), Ok(HOST_ENABLED));
        cfg.write(HOST_ENABLED | HOST_I2C).unwrap();
        assert_eq!(cfg.read(), Ok(HOST_ENABLED | HOST_I2C));
        cfg.write(HOST_ENABLED).unwrap();
        assert_eq!(writes.get(), 2);
        assert_eq!(byte.get(), HOST_ENABLED);
        assert_eq!(drops.get(), 0);
        id.set(u32::MAX);
        assert_eq!(cfg.read(), Err(ConfigurationError));
        assert_eq!(cfg.write(HOST_ENABLED), Err(ConfigurationError));
        assert_eq!(writes.get(), 2);
        drop(cfg);
        assert_eq!(drops.get(), 1);
    }
    #[test]
    fn invalid_composite_claim_returns_actual_host_and_configuration_without_writes() {
        let f = fixture(0x7e22, false);
        let (host, mut cfg) = f.host.release().ok().unwrap();
        cfg.device = 0x24d3;
        // SAFETY: same retained real resources as fixture; wrong scalar pairing
        // must return those actual owners without attempting hardware changes.
        let (kind, (host, cfg)) = unsafe { Controller::claim(host, cfg) }.err().unwrap();
        assert_eq!(kind, ErrorKind::InvalidConfiguration);
        assert_eq!(f.state.borrow().config_count, 0);
        assert_eq!(f.register_drop.get(), 0);
        assert_eq!(f.config_drop.get(), 0);
        drop((host, cfg));
        assert_eq!(f.register_drop.get(), 1);
        assert_eq!(f.config_drop.get(), 1);
    }
    #[test]
    fn completion_at_the_expired_deadline_preserves_raw_status_and_caller_output() {
        for block in [false, true] {
            let mut f = fixture(0x7e22, false);
            f.state.borrow().time.0.set(u64::MAX);
            f.state.borrow_mut().length = 3;
            f.host.owners.as_mut().unwrap().0.config.timeout_us = 1;
            let mut bytes = [0xa5; 3];
            let mut word = 0xa5a5;
            let error = if block {
                f.host.read_i2c_block(address(), 0xa7, &mut bytes)
            } else {
                f.host.transaction(
                    address(),
                    Transaction::ReadWord {
                        command: 0x11,
                        data: &mut word,
                    },
                    false,
                )
            }
            .unwrap_err();
            assert_eq!(
                error.kind,
                ErrorKind::Timeout(if block {
                    Phase::ByteDone
                } else {
                    Phase::Completion
                })
            );
            assert_ne!(error.status & if block { BYTE_DONE } else { INTR }, 0);
            assert_eq!(bytes, [0xa5; 3]);
            assert_eq!(word, 0xa5a5);
            assert!(f.host.failure().is_none());
            assert_eq!(f.state.borrow().configuration, HOST_ENABLED);
        }
    }
    #[test]
    fn final_data_cleanup_and_configuration_reads_cannot_publish_after_the_deadline() {
        for block in [false, true] {
            for stage in 0..3 {
                let mut f = fixture(0x7e22, false);
                f.state.borrow_mut().length = 3;
                if stage == 2 {
                    f.state.borrow_mut().config_jump = Some((2, 200_000));
                } else {
                    let offset = if stage == 1 {
                        AUX_CONTROL
                    } else if block {
                        BLOCK_DATA
                    } else {
                        HOST_DATA1
                    };
                    let count = if stage == 1 {
                        // prepare reads twice; cleanup reads the actual modes
                        // while verifying quiescence before final config read.
                        f.state.borrow().read_counts[usize::from(offset)] + 4
                    } else if block {
                        3
                    } else {
                        1
                    };
                    f.state.borrow_mut().read_jump = Some((offset, count, 200_000));
                }
                let mut bytes = [0xa5; 3];
                let mut word = 0xa5a5;
                let result = if block {
                    f.host.read_i2c_block(address(), 0xa7, &mut bytes)
                } else {
                    f.host.transaction(
                        address(),
                        Transaction::ReadWord {
                            command: 0x11,
                            data: &mut word,
                        },
                        false,
                    )
                };
                assert!(
                    matches!(result.unwrap_err().kind, ErrorKind::Timeout(_)),
                    "block={block}, stage={stage}"
                );
                assert_eq!(bytes, [0xa5; 3]);
                assert_eq!(word, 0xa5a5);
                assert_eq!(f.state.borrow().configuration, HOST_ENABLED);
                assert!(f.host.failure().is_none());
                assert!(f.host.release().is_ok());
            }
        }
        for config_access in [1, 2, 3, 4, 5] {
            let mut f = fixture(0x7e22, false);
            f.state.borrow_mut().config_jump = Some((config_access, 200_000));
            let result = f.host.write_i2c_block(address(), 0xa7, &[3]);
            assert!(matches!(result.unwrap_err().kind, ErrorKind::Timeout(_)));
            assert_eq!(f.state.borrow().configuration, HOST_ENABLED);
            if config_access <= 3 {
                assert!(f.state.borrow().starts.is_empty());
            }
            assert!(f.host.release().is_ok());
        }
    }
    #[test]
    fn late_target_payload_and_ordinary_prepare_never_issue_start() {
        for block in [false, true] {
            for offset in [HOST_ADDRESS, HOST_COMMAND, HOST_DATA0, BLOCK_DATA] {
                if !block && offset == BLOCK_DATA {
                    continue;
                }
                let mut f = fixture(0x7e22, false);
                f.state.borrow_mut().write_jump = Some((offset, 200_000));
                let result = if block {
                    f.host.write_i2c_block(address(), 0xa7, &[3])
                } else {
                    f.host.transaction(
                        address(),
                        Transaction::WriteWord {
                            command: 0xa7,
                            data: 3,
                        },
                        false,
                    )
                };
                assert!(matches!(result.unwrap_err().kind, ErrorKind::Timeout(_)));
                assert!(f.state.borrow().starts.is_empty());
                assert_eq!(f.state.borrow().configuration, HOST_ENABLED);
                assert!(f.host.release().is_ok());
            }
        }
        for offset in [HOST_STATUS, AUX_CONTROL] {
            let mut f = fixture(0x7e22, false);
            let count = f.state.borrow().read_counts[usize::from(offset)] + 1;
            f.state.borrow_mut().read_jump = Some((offset, count, 200_000));
            let result = f
                .host
                .transaction(address(), Transaction::SendByte(1), false);
            assert!(matches!(result.unwrap_err().kind, ErrorKind::Timeout(_)));
            assert!(f.state.borrow().starts.is_empty());
            assert!(f.host.release().is_ok());
        }
    }
    #[test]
    #[ignore = "requires fresh unchanged Linux fixed-block oracle trace"]
    fn unchanged_linux_fixed_block_wire_and_return_classes() {
        extern crate std;
        let trace = std::fs::read_to_string(
            std::env::var("STELA_I801_I2C_BLOCK_ORACLE").expect("oracle trace path"),
        )
        .unwrap();
        let mut cases = 0;
        for line in trace.lines() {
            let fields: Vec<_> = line.split(',').collect();
            let number = |n: usize| fields[n].parse::<i32>().unwrap();
            let capable = number(0) != 0;
            let spd = number(1) != 0;
            let read = number(2) != 0;
            let length = number(3) as usize;
            let mut f = fixture(if capable { 0x24d3 } else { 0x24c3 }, spd);
            f.state.borrow_mut().length = length;
            f.state.borrow_mut().control_writes.clear();
            let mut output = [0xa5; 33];
            let result = if read {
                f.host
                    .read_i2c_block(address(), 0xa7, &mut output[..length])
            } else {
                f.host.write_i2c_block(address(), 0xa7, &input(length))
            };
            assert_eq!(result.is_ok(), number(4) == 0);
            if result.is_ok() {
                let h = f.state.borrow();
                let (protocol, address, command, data1) = *h.starts.last().unwrap();
                assert_eq!(i32::from(address), number(5));
                assert_eq!(i32::from(command), number(6));
                assert_eq!(i32::from(data1), number(7));
                assert_eq!(
                    protocol,
                    if read {
                        PROTOCOL_I2C_BLOCK
                    } else {
                        PROTOCOL_BLOCK
                    }
                );
                let started = *h.control_writes.iter().find(|c| **c & START != 0).unwrap();
                assert_eq!(i32::from(started), number(8));
                assert_eq!(number(9), if read { length as i32 - 1 } else { 255 });
                assert_eq!(i32::from(h.configuration), number(10));
                assert_eq!(
                    h.config_log.iter().filter(|(w, _)| *w).count() as i32,
                    number(11)
                );
                let hex = |text: &str| -> Vec<u8> {
                    text.as_bytes()
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|pair| {
                            u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap()
                        })
                        .collect()
                };
                if read {
                    assert_eq!(&output[..32], hex(fields[12]).as_slice());
                } else {
                    assert_eq!(h.received, hex(fields[13]));
                }
            } else {
                assert!(f.state.borrow().starts.is_empty());
                assert_eq!(f.state.borrow().config_count, 0);
            }
            cases += 1;
        }
        assert_eq!(cases, 272);
    }
}
