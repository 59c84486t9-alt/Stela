// SPDX-License-Identifier: MIT
// Copyright (C) The Asahi Linux Contributors
//! Source-ported Broadcom 4377/4378/4387/4388 PCIe IPC transport.
//! Firmware/RTI/ring acknowledgments are distinct from HCI command completion.
//! This library requires kept PCI/reset/coherent-DMA/MSI ownership;
//! Source controller setup uses real board-bound properties and HCI events;
//! native provisioning and guest/radio services remain separate.
mod boot;
mod identity;
mod initialize;
pub mod memory;
pub mod native;
mod ring;
pub use crate::usb::bluetooth::FirmwareReceipt;
use crate::{
    bus::dma::{mapping::DmaError, memory::MemoryError},
    firmware::Provider,
};
use alloc::{boxed::Box, vec::Vec};
pub use identity::{Board, BoardSource, Chip, Identity, PciIdentity};
pub use initialize::{
    CommandReceipt, Initialization, InitializationStage, PropertyDiagnostic, PropertyReceipt,
    PtbDisposition, Quirks, Report,
};
use memory::{CoherentAllocator, CoherentBuffer};
use ring::{Completion, Transfer};

const BOOT_STAGE: u32 = 0x200454;
const RTI_STATUS: u32 = 0x20045c;
const SLEEP: u32 = 0x150;
const DOORBELL: u32 = 0x174;
const FIRMWARE_BYTES: usize = 4 * 1024 * 1024;
const OBSERVATION_BYTES: usize = 16 * 1024 * 1024;
const STATE_OFFSET: usize = 128;
const PERIPHERAL_OFFSET: usize = 256;

#[derive(Clone, Copy)]
enum RequestDeadline {
    Hci(u64),
    Control(u64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Space {
    Configuration,
    Bar0,
    Bar2,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported(&'static str),
    Native(native::Error),
    Memory(MemoryError),
    Dma(DmaError),
    Firmware(crate::firmware::Error),
    Io {
        space: Space,
        offset: u32,
        raw: u64,
    },
    Readback {
        space: Space,
        offset: u32,
        observed: u32,
    },
    Protocol {
        requirement: &'static str,
        observed: u64,
    },
    Packet {
        kind: Kind,
        bytes: Vec<u8>,
    },
    Hci {
        requirement: &'static str,
        bytes: Vec<u8>,
    },
    Controller {
        opcode: u16,
        status: u8,
        returned: Vec<u8>,
    },
    State(State),
    Timeout(&'static str),
    QueueFull(u16),
    ObservationLimit,
    Cleanup {
        cause: Box<Self>,
        cleanup: Box<Self>,
    },
}
pub type Result<T> = core::result::Result<T, Error>;
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Broadcom PCIe Bluetooth {self:?}")
    }
}
impl core::error::Error for Error {}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Command,
    Event,
    Acl,
    Sco,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Allocated,
    Configured,
    Firmware,
    Rti,
    Active,
    Closing,
    Closed,
    Failed,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    pub kind: Kind,
    pub bytes: Vec<u8>,
    pub completion: [u8; 16],
    /// Entire completion footer, including original padding.
    pub footer: Vec<u8>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Submission {
    pub ring: u16,
    pub message: u16,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub submission: Submission,
    pub completion: [u8; 16],
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Observations {
    pub packets: Vec<Packet>,
    pub completions: Vec<Receipt>,
    /// Whole-requester retirement ended these submissions without an
    /// observed ACK. This is cancellation evidence, never packet delivery.
    pub retired_without_ack: Vec<Submission>,
}
/// Last read or attempted native write, including late observations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegisterAccess {
    Read {
        space: Space,
        offset: u32,
        width: u8,
        value: u32,
    },
    Write {
        space: Space,
        offset: u32,
        value: u32,
        returned: bool,
    },
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    /// Successful original OTP byte reads, including bytes rejected by parsing.
    pub otp: Vec<u8>,
    pub boot_stage: u32,
    pub rti_status: u32,
    pub peripheral_info: [u8; 32],
    pub ring_state: Vec<u8>,
    pub completion: Option<[u8; 16]>,
    pub completion_footer: Vec<u8>,
    pub firmware_errors: Vec<crate::firmware::Error>,
    pub initialization: Option<Initialization>,
    pub native_access: Option<RegisterAccess>,
}

/// Exclusive Function/BARs/MSI/coherent-domain adapter, or explicit model.
/// # Safety
/// Identity and board observations bind the same requester and
/// reset epoch. Former firmware/driver/CPU owners are independently drained;
/// their DMA/domain/IRQ reservations cannot alias any new allocation. `prepare`
/// performs acknowledged coordinated FLR/isolation, waits
/// at least the donor's 100 ms before BAR accesses, establishes PCI D0/MEM/BM,
/// and disables BCM4377 ASPM including its parent-link policy.
/// `now_us` observes the monotonic microsecond clock; delayed native
/// effects and observations remain inside the same request deadline.
/// Every access has its native width; config word writes never replay
/// adjacent W1C status through a DWORD RMW. BAR0/2 remain reserved UC mappings.
/// CoherentAllocator resources belong to this requester and are fully
/// coherent for source shared-index polling. MSI admission installs exactly one
/// real checked message/callback with every native owner kept; no INTx or
/// MSI-X fallback. `retire` independently stops device DMA/posted writes,
/// drains root/domain/CPU/IRQ/callback/deferred work and excludes future access;
/// ring-destroy replies, SLEEP3 and masking alone are not that proof. An error
/// keeps all uncertain native resources and forbids automatic retry/reopen.
pub unsafe trait Platform: 'static {
    fn identity(&self) -> PciIdentity;
    fn board(&self) -> Board;
    /// Read this requester's firmware-node property. Values
    /// must come from its real bound node and remain immutable through setup;
    /// copied PCI/board labels never authorize another device's calibration.
    /// Returned bytes keep original property order, including BD_ADDR order.
    fn property(&self, _name: &'static str) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }
    fn prepare(&mut self, chip: Chip) -> Result<()>;
    fn read32(&mut self, space: Space, offset: u32) -> Result<u32>;
    fn write32(&mut self, space: Space, offset: u32, value: u32) -> Result<()>;
    fn read8(&mut self, space: Space, offset: u32) -> Result<u8>;
    fn now_us(&self) -> u64;
    /// Serialized process service consumes a callback request before DMA polling.
    fn service_begin(&mut self) -> Result<()> {
        Ok(())
    }
    /// Native preparation can enable BM even before the first IPC publication.
    fn retire_unpublished(&self) -> bool {
        false
    }
    fn arm_msi(&mut self) -> Result<()>;
    fn retire(&mut self) -> Result<()>;
}

pub struct Transport<P: Platform> {
    platform: Option<P>,
    identity: Option<Identity>,
    pci: PciIdentity,
    chip: Chip,
    core: Option<CoherentBuffer>,
    firmware: Option<CoherentBuffer>,
    transfers: [Transfer; 7],
    completions: [Completion; 5],
    state: State,
    fault: Option<Error>,
    snapshot: Snapshot,
    image: Option<FirmwareReceipt>,
    observations: Observations,
    observation_bytes: usize,
    retirement_attempted: bool,
    retirement_error: Option<Error>,
    initialization_deadline: Option<u64>,
    request_deadline: Option<RequestDeadline>,
}
impl<P: Platform> Transport<P> {
    pub fn new(mut platform: P, dma: &mut dyn CoherentAllocator) -> Result<Self> {
        let pci = platform.identity();
        let chip = Chip::select(pci)?;
        Self::validate_pci(&mut platform, pci)?;
        if let Err(error) = platform.prepare(chip) {
            // An effect-then-error reset/isolation attempt has uncertain native
            // ownership. No allocator is touched and no final Drop retries it.
            core::mem::forget(platform);
            return Err(error);
        }
        let core = dma.allocate(4096)?;
        let firmware = dma.allocate(FIRMWARE_BYTES)?;
        let transfers = Transfer::allocate_all(dma)?;
        let completions = Completion::allocate_all(dma)?;
        if core.len() < 4096 || firmware.len() < FIRMWARE_BYTES {
            return Err(Error::Unsupported(
                "complete owned Broadcom DMA allocations",
            ));
        }
        let mut result = Self {
            platform: Some(platform),
            identity: None,
            pci,
            chip,
            core: Some(core),
            firmware: Some(firmware),
            transfers,
            completions,
            state: State::Allocated,
            fault: None,
            snapshot: Snapshot::default(),
            image: None,
            observations: Observations::default(),
            observation_bytes: 0,
            retirement_attempted: false,
            retirement_error: None,
            initialization_deadline: None,
            request_deadline: None,
        };
        result.initialize_context();
        Ok(result)
    }
    pub fn state(&self) -> State {
        self.state
    }
    pub fn identity(&self) -> Option<&Identity> {
        self.identity.as_ref()
    }
    pub fn firmware(&self) -> Option<&FirmwareReceipt> {
        self.image.as_ref()
    }
    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }
    pub fn fault(&self) -> Option<&Error> {
        self.fault.as_ref()
    }
    /// Complete owned observations survive every send/poll/start/cleanup exit.
    /// Draining these bytes never accesses or reopens a closed physical device.
    pub fn take_observations(&mut self) -> Observations {
        self.observation_bytes = 0;
        core::mem::take(&mut self.observations)
    }
    pub fn start(&mut self, provider: &dyn Provider) -> Result<()> {
        if self.state != State::Allocated {
            return Err(Error::State(self.state));
        }
        match self.start_inner(provider) {
            Ok(()) => Ok(()),
            Err(error) => Err(self.fail(error)),
        }
    }
    /// Fresh boot plus source calibration/PTB/address setup over HCI.
    /// Raw inbound observations and the initialization attempt survive failure.
    /// This entry requires the untouched Allocated epoch; an arbitrary live
    /// transport does not grant initial HCI credits or a controller identity.
    pub fn initialize(&mut self, provider: &dyn Provider) -> Result<Report> {
        if self.state != State::Allocated {
            return Err(Error::State(self.state));
        }
        let result = self.initialize_inner(provider);
        // Necessary independent retirement and later ordinary transport close
        // are outside the setup budget; expiry never suppresses cleanup.
        self.initialization_deadline = None;
        self.request_deadline = None;
        match result {
            Ok(report) => Ok(report),
            Err(error) => Err(self.fail(error)),
        }
    }
    fn platform(&mut self) -> &mut P {
        self.platform.as_mut().unwrap()
    }
    fn core(&self) -> &CoherentBuffer {
        self.core.as_ref().unwrap()
    }
    fn core_mut(&mut self) -> &mut CoherentBuffer {
        self.core.as_mut().unwrap()
    }
    fn check_budget(&self) -> Result<()> {
        if self.initialization_deadline.is_none() && self.request_deadline.is_none() {
            return Ok(());
        }
        let now = self.platform.as_ref().unwrap().now_us();
        if self
            .initialization_deadline
            .is_some_and(|deadline| now >= deadline)
        {
            return Err(Error::Timeout(
                "complete Broadcom controller initialization",
            ));
        }
        match self.request_deadline {
            Some(RequestDeadline::Hci(deadline)) if now >= deadline => {
                Err(Error::Timeout("actual Broadcom HCI response or credits"))
            }
            Some(RequestDeadline::Control(deadline)) if now >= deadline => Err(Error::Timeout(
                "actual Broadcom control-ring acknowledgment",
            )),
            _ => Ok(()),
        }
    }
    fn publish(&self, buffer: &CoherentBuffer) -> Result<()> {
        self.check_budget()?;
        buffer.publish()?;
        self.check_budget()
    }
    fn read(&mut self, space: Space, offset: u32) -> Result<u32> {
        self.check_budget()?;
        let value = self.platform().read32(space, offset)?;
        self.snapshot.native_access = Some(RegisterAccess::Read {
            space,
            offset,
            width: 4,
            value,
        });
        self.check_budget()?;
        Ok(value)
    }
    fn read_otp(&mut self, offset: u32) -> Result<u8> {
        self.check_budget()?;
        let value = self.platform().read8(Space::Bar0, offset)?;
        self.snapshot.native_access = Some(RegisterAccess::Read {
            space: Space::Bar0,
            offset,
            width: 1,
            value: u32::from(value),
        });
        // Preserve the late byte before the outer deadline can refuse it.
        self.snapshot.otp.push(value);
        self.check_budget()?;
        Ok(value)
    }
    fn write(&mut self, space: Space, offset: u32, value: u32) -> Result<()> {
        self.check_budget()?;
        self.snapshot.native_access = Some(RegisterAccess::Write {
            space,
            offset,
            value,
            returned: false,
        });
        self.platform().write32(space, offset, value)?;
        self.snapshot.native_access = Some(RegisterAccess::Write {
            space,
            offset,
            value,
            returned: true,
        });
        self.check_budget()
    }
    fn bar2(&mut self, offset: u32) -> Result<u32> {
        self.read(Space::Bar2, self.chip.bar2(offset))
    }
    fn write_bar2(&mut self, offset: u32, value: u32) -> Result<()> {
        self.write(Space::Bar2, self.chip.bar2(offset), value)
    }
    fn refresh_snapshot(&mut self) -> Result<()> {
        self.snapshot.boot_stage = self.bar2(BOOT_STAGE)?;
        self.snapshot.rti_status = self.bar2(RTI_STATUS)?;
        self.snapshot.peripheral_info = self.core().read(PERIPHERAL_OFFSET, 32).try_into().unwrap();
        self.snapshot.ring_state = self.core().read(STATE_OFFSET, 60);
        Ok(())
    }
    fn retire_platform(&mut self) -> Result<()> {
        if self.retirement_attempted {
            return self.retirement_error.clone().map_or(Ok(()), Err);
        }
        // Record admission before an effect-then-error root operation. Neither
        // fail nor Drop may retry uncertain reset/drain ownership.
        self.retirement_attempted = true;
        self.retirement_error = Some(Error::Unsupported(
            "interrupted Broadcom platform retirement",
        ));
        match self.platform().retire() {
            Ok(()) => {
                self.retirement_error = None;
                Ok(())
            }
            Err(error) => {
                self.retirement_error = Some(error.clone());
                Err(error)
            }
        }
    }
    fn fail(&mut self, cause: Error) -> Error {
        if let Some(first) = &self.fault {
            return first.clone();
        }
        self.state = State::Failed;
        // Preserve the first diagnostic even if native retirement unwinds.
        self.fault = Some(cause.clone());
        // Device stop is independent of the failing IPC path. A failed close
        // never retries control messages or rewrites live descriptor/payload RAM.
        let result = self.retire_platform();
        let error = match result {
            Ok(()) => cause,
            Err(cleanup) if cause == cleanup => cause,
            Err(cleanup) => Error::Cleanup {
                cause: Box::new(cause),
                cleanup: Box::new(cleanup),
            },
        };
        self.fault = Some(error.clone());
        error
    }
}
impl<P: Platform> Drop for Transport<P> {
    fn drop(&mut self) {
        if self.state != State::Closed {
            // No destructor retries or releases an incomplete physical epoch. Keep
            // terminal DMA bytes and every root/UC/IRQ/domain owner.
            if let Some(platform) = self.platform.take() {
                core::mem::forget(platform);
            }
            if let Some(core) = self.core.take() {
                core::mem::forget(core);
            }
            if let Some(firmware) = self.firmware.take() {
                core::mem::forget(firmware);
            }
            for transfer in &mut self.transfers {
                transfer.retain();
            }
            for completion in &mut self.completions {
                completion.retain();
            }
        }
    }
}

#[cfg(test)]
mod tests;
