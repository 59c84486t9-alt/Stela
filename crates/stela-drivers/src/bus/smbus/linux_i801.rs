//! Direct upstream-C alternative to [`super::i801`], behind `linux-i801`.
//!
//! Uses the same exclusively owned register/timer interface and SMBus Bus API.
//! The complete upstream translation unit is compiled in place, with the
//! recorded bounded-recovery patch. Experimental; not selected by the mount.
//! This adapter exposes its polled byte/word/process-call/block engine; platform attachment,
//! IRQ, Host Notify, PEC, arbitrary I2C and power transitions remain outside it.
use super::i801::{ControllerInfo, PortIo, Registers};
use super::{Address, Block, Bus, Error, ErrorKind, Phase, Recovery, Transaction};
use crate::{Clock, bus::i2c::Timer};
use alloc::{boxed::Box, rc::Rc};
use core::{ffi::c_void, marker::PhantomData, ptr::NonNull};

const HOST_STATUS: u8 = 0;
const HOST_CONTROL: u8 = 2;
const HOST_DATA0: u8 = 5;
const AUX_STATUS: u8 = 12;
const AUX_CONTROL: u8 = 13;
const AUX_CRC: u8 = 1;
const AUX_BUFFER: u8 = 1 << 1;
const HOST_BUSY: u8 = 1;
const FAILED: u8 = 1 << 4;
const INUSE: u8 = 1 << 6;
const ERROR_FLAGS: u8 = 0x1c;
const STATUS_FLAGS: u8 = 0x9e;
const KILL: u8 = 1 << 1;
const HOST_ENABLED: u8 = 1;
const HOST_SMI: u8 = 1 << 1;
const HOST_I2C: u8 = 1 << 2;
// Linux's I2C_SMBUS_* operation selectors (distinct from I801 wire encodings).
const BYTE: i32 = 1;
const BYTE_DATA: i32 = 2;
const WORD_DATA: i32 = 3;
const PROCESS_CALL: i32 = 4;
const BLOCK_DATA: i32 = 5;

#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// Linux's per-wait bound, rounded up to milliseconds. Each block byte,
    /// completion and KILL recovery gets a fresh bound; not a transfer deadline.
    pub timeout_us: u32,
    pub use_block_buffer: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            timeout_us: 200_000,
            use_block_buffer: true,
        }
    }
}

#[repr(C)]
struct Io {
    read8: unsafe extern "C" fn(*mut c_void, u8) -> u8,
    write8: unsafe extern "C" fn(*mut c_void, u8, u8),
    now_us: unsafe extern "C" fn(*mut c_void) -> u64,
    delay_us: unsafe extern "C" fn(*mut c_void, u32),
}

unsafe extern "C" {
    fn stela_i801_create(
        io: *const Io,
        context: *mut c_void,
        device: u16,
        host_configuration: u8,
        timeout_us: u32,
        buffer: i32,
    ) -> *mut c_void;
    fn stela_i801_destroy(native: *mut c_void);
    fn stela_i801_transfer(
        native: *mut c_void,
        address: u8,
        read: u8,
        command: u8,
        protocol: i32,
        bytes: *mut u8,
        length: *mut u8,
    ) -> i32;
}

struct Context<R, T> {
    registers: R,
    timer: T,
    status: u8,
    data0: u8,
    error_status: u8,
    kill_started: bool,
    kill_acknowledged: bool,
}

// Every callback receives this instance's pinned Box. The native caller holds
// Stela's common Linux execution owner, and never stores a callback elsewhere.
unsafe extern "C" fn read8<R: Registers, T>(context: *mut c_void, offset: u8) -> u8 {
    // SAFETY: callback lifetime and concrete type are fixed at construction.
    let context = unsafe { &mut *context.cast::<Context<R, T>>() };
    let value = context.registers.read8(offset);
    if offset == HOST_DATA0 {
        context.data0 = value;
    }
    if offset == HOST_STATUS {
        context.status = value;
        if value & ERROR_FLAGS != 0 {
            context.error_status = value;
        }
        if context.kill_started && value & (HOST_BUSY | FAILED) == FAILED {
            context.kill_acknowledged = true;
        }
    }
    value
}
unsafe extern "C" fn write8<R: Registers, T>(context: *mut c_void, offset: u8, value: u8) {
    // SAFETY: same constructor-bound Box and serialized native call.
    let context = unsafe { &mut *context.cast::<Context<R, T>>() };
    if offset == HOST_CONTROL && value & KILL != 0 {
        context.kill_started = true;
    }
    context.registers.write8(offset, value);
}
unsafe extern "C" fn now_us<R, T: Timer>(context: *mut c_void) -> u64 {
    // SAFETY: same constructor-bound Box, no mutable borrow escapes a callback.
    unsafe { &*context.cast::<Context<R, T>>() }.timer.now_us()
}
unsafe extern "C" fn delay_us<R, T: Timer>(context: *mut c_void, minimum: u32) {
    // SAFETY: same constructor-bound Box and serialized native call.
    let context = unsafe { &*context.cast::<Context<R, T>>() };
    let start = context.timer.now_us();
    while context.timer.now_us().wrapping_sub(start) < u64::from(minimum) {
        context.timer.relax();
    }
}

/// Alternate engine; selection is explicit, so the old driver stays available.
pub struct LinuxI801<R = PortIo, T = Clock> {
    native: NonNull<c_void>,
    context: Box<Context<R, T>>,
    ready: bool,
    _serialized: PhantomData<Rc<()>>,
}

impl<R: Registers, T: Timer> LinuxI801<R, T> {
    /// Requires the same platform ownership and current SMBHSTCFG observation
    /// as the Rust engine. It never enables PCI, takes over firmware or probes
    /// the physical machine. Clock/delay and register callbacks may not reenter
    /// any Linux-backed driver while this transfer is executing. Requires an
    /// ICH4-or-later ID with auxiliary registers; older IDs are refused.
    pub fn new(
        registers: R,
        timer: T,
        info: ControllerInfo,
        host_configuration: u8,
        config: Config,
    ) -> Result<Self, Error> {
        if config.timeout_us == 0 {
            return Err(ErrorKind::InvalidConfiguration.into());
        }
        // Upstream access() touches AUXCTL even without FEATURE_BLOCK_BUFFER.
        // Keep pre-ICH4 controllers on the Rust engine's 8-byte-only path.
        if !info.has_block_buffer() {
            return Err(ErrorKind::UnsupportedTransaction.into());
        }
        if host_configuration & HOST_ENABLED == 0 {
            return Err(ErrorKind::HostDisabled.into());
        }
        if host_configuration & HOST_SMI != 0 {
            return Err(ErrorKind::FirmwareSmi.into());
        }
        if host_configuration & HOST_I2C != 0 {
            return Err(ErrorKind::WrongProtocolMode.into());
        }
        let mut context = Box::new(Context {
            registers,
            timer,
            status: 0,
            data0: 0,
            error_status: 0,
            kill_started: false,
            kill_acknowledged: false,
        });
        let io = Io {
            read8: read8::<R, T>,
            write8: write8::<R, T>,
            now_us: now_us::<R, T>,
            delay_us: delay_us::<R, T>,
        };
        // SAFETY: C copies Io and retains only the pinned Box's pointer; both
        // remain live until destroy, with no asynchronous/IRQ callback enabled.
        let native = unsafe {
            stela_i801_create(
                &io,
                (&mut *context as *mut Context<R, T>).cast(),
                info.device_id(),
                host_configuration,
                config.timeout_us,
                i32::from(config.use_block_buffer && info.has_block_buffer()),
            )
        };
        let native = NonNull::new(native).ok_or(ErrorKind::AllocationFailed)?;
        Ok(Self {
            native,
            context,
            ready: true,
            _serialized: PhantomData,
        })
    }

    pub fn needs_reset(&self) -> bool {
        !self.ready
    }
}

impl<R: Registers, T: Timer> Bus for LinuxI801<R, T> {
    fn transaction(
        &mut self,
        address: Address,
        transaction: Transaction<'_>,
        pec: bool,
    ) -> Result<(), Error> {
        if !self.ready {
            return Err(ErrorKind::NeedsReset.into());
        }
        if pec {
            return Err(ErrorKind::UnsupportedPec.into());
        }
        let mut bytes = [0; 32];
        let (read, command, protocol, mut length) = match &transaction {
            Transaction::SendByte(value) => (0, *value, BYTE, 0),
            Transaction::ReceiveByte(_) => (1, 0, BYTE, 0),
            Transaction::WriteByte { command, data } => {
                bytes[0] = *data;
                (0, *command, BYTE_DATA, 0)
            }
            Transaction::ReadByte { command, .. } => (1, *command, BYTE_DATA, 0),
            Transaction::WriteWord { command, data } => {
                bytes[..2].copy_from_slice(&data.to_le_bytes());
                (0, *command, WORD_DATA, 0)
            }
            Transaction::ReadWord { command, .. } => (1, *command, WORD_DATA, 0),
            Transaction::ProcessCall {
                command, request, ..
            } => {
                bytes[..2].copy_from_slice(&request.to_le_bytes());
                (0, *command, PROCESS_CALL, 0)
            }
            Transaction::WriteBlock { command, data } => {
                if data.is_empty() || data.len() > 32 {
                    return Err(ErrorKind::InvalidBlockLength(data.len()).into());
                }
                bytes[..data.len()].copy_from_slice(data);
                (0, *command, BLOCK_DATA, data.len() as u8)
            }
            Transaction::ReadBlock { command, .. } => (1, *command, BLOCK_DATA, 0),
        };
        // Platform ownership is Stela's obligation: the Linux engine assumes
        // its kernel has already arbitrated firmware users. Respect the
        // read-to-acquire semaphore before letting it publish a request.
        let status = self.context.registers.read8(HOST_STATUS);
        if status & INUSE != 0 {
            return Err(Error {
                kind: ErrorKind::Busy,
                status,
                recovery: Recovery::NotAttempted,
            });
        }
        if status & HOST_BUSY != 0 {
            self.context.registers.write8(HOST_STATUS, INUSE);
            return Err(Error {
                kind: ErrorKind::Busy,
                status,
                recovery: Recovery::NotAttempted,
            });
        }
        self.context
            .registers
            .write8(HOST_STATUS, status & STATUS_FLAGS);
        let remaining = self.context.registers.read8(HOST_STATUS);
        if remaining & STATUS_FLAGS != 0 {
            self.context.registers.write8(HOST_STATUS, INUSE);
            return Err(Error {
                kind: ErrorKind::StatusStuck,
                status: remaining,
                recovery: Recovery::NotAttempted,
            });
        }
        let auxiliary = self.context.registers.read8(AUX_CONTROL);
        self.context
            .registers
            .write8(AUX_CONTROL, auxiliary & !(AUX_CRC | AUX_BUFFER));
        self.context.registers.write8(AUX_STATUS, AUX_CRC);
        if self.context.registers.read8(AUX_CONTROL) & (AUX_CRC | AUX_BUFFER) != 0 {
            self.context.registers.write8(HOST_STATUS, INUSE);
            return Err(Error {
                kind: ErrorKind::BufferModeRejected,
                status,
                recovery: Recovery::NotAttempted,
            });
        }
        self.context.error_status = 0;
        self.context.kill_started = false;
        self.context.kill_acknowledged = false;
        // SAFETY: unique live native object, bounded input/output buffers, and
        // no callback can outlive this synchronous invocation.
        let result = unsafe {
            stela_i801_transfer(
                self.native.as_ptr(),
                address.get(),
                read,
                command,
                protocol,
                bytes.as_mut_ptr(),
                &mut length,
            )
        };
        // Linux clears completion flags without checking that W1C stuck. Do
        // not report a reusable controller when the actual hardware disagrees.
        let remaining = self.context.registers.read8(HOST_STATUS);
        self.context.registers.write8(HOST_STATUS, INUSE);
        let settled = remaining & (STATUS_FLAGS | HOST_BUSY) == 0;
        if result != 0 {
            let status = if self.context.error_status != 0 {
                self.context.error_status
            } else {
                self.context.status
            };
            let (kind, mut recovery) = match result {
                -16 => (ErrorKind::Busy, Recovery::NotAttempted),
                -6 => (ErrorKind::Device, Recovery::Cleared),
                -11 => (ErrorKind::ArbitrationLost, Recovery::Cleared),
                -5 => (ErrorKind::Failed, Recovery::Cleared),
                -71 => (
                    ErrorKind::InvalidBlockLength(usize::from(self.context.data0)),
                    Recovery::Cleared,
                ),
                -110 => {
                    self.ready = self.context.kill_acknowledged;
                    (
                        ErrorKind::Timeout(Phase::Completion),
                        if self.ready {
                            Recovery::Killed
                        } else {
                            Recovery::Failed
                        },
                    )
                }
                _ => (ErrorKind::UnsupportedTransaction, Recovery::NotAttempted),
            };
            if !settled {
                self.ready = false;
                recovery = Recovery::Failed;
            }
            return Err(Error {
                kind,
                status,
                recovery,
            });
        }
        if !settled {
            self.ready = false;
            return Err(Error {
                kind: ErrorKind::StatusStuck,
                status: remaining,
                recovery: Recovery::Failed,
            });
        }
        match transaction {
            Transaction::ReceiveByte(data) | Transaction::ReadByte { data, .. } => *data = bytes[0],
            Transaction::ReadWord { data, .. }
            | Transaction::ProcessCall { response: data, .. } => {
                *data = u16::from_le_bytes([bytes[0], bytes[1]])
            }
            Transaction::ReadBlock { data, .. } => {
                if length == 0 || length > 32 {
                    self.ready = false;
                    return Err(ErrorKind::UnexpectedCompletion.into());
                }
                *data = Block { bytes, length };
            }
            _ => {}
        }
        Ok(())
    }
}

impl<R, T> Drop for LinuxI801<R, T> {
    fn drop(&mut self) {
        // SAFETY: the unique native object has no queued/IRQ/deferred users;
        // its callbacks' Box is still live while the C allocation is released.
        unsafe {
            stela_i801_destroy(self.native.as_ptr());
        }
    }
}
