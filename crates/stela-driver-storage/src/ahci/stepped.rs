// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright 2004-2005 Red Hat, Inc.
//! A port's disk as a block device, whose libata error handling runs a
//! bounded step per look. Linux runs `ata_scsi_error` in the SCSI error
//! handler's thread while the port's queue is frozen; here the processor
//! that looks for completions takes one step and goes back to its guest,
//! and the commands that wait for the port stay queued in order, as
//! Linux's do. A step is one register poll, one command's launch or look,
//! or one look at a minimum delay: hard resets (10, 10, 35 and 5 s),
//! debounces, internal commands (5 s and up) and engine stops all wait
//! across steps with their own timeouts, retries and order unchanged.
use super::*;
use core::task::Poll;
use stela_driver_base::stepped::Stepped;

/// How long a look waits after a step that found the error handling
/// waiting before it says another would find more ([`AhciDisk::posted`]):
/// a waiting processor that steps the disk takes one step a millisecond,
/// not a spin, while a reset or an internal command runs.
const RECOVERY_LOOK_US: u64 = 1_000;

/// What a failed look left for error handling ([`Disk::launch_and_look`]):
/// the failure, the slots it charges unless the NCQ Command Error log
/// names one, and whether a launched command it reached was I/O.
pub(super) struct Failed {
    pub(super) failure: Failure,
    pub(super) blamed: u32,
    pub(super) io: bool,
}

/// Error handling's end: the disk back, the failure as it analyzed it,
/// and whether it recovered the port.
struct Recovered {
    disk: Box<Disk>,
    failure: Failure,
    result: Result<(), BlockError>,
}

/// Error handling under way: the task that holds the disk, and what the
/// block device says of the disk meanwhile.
struct Recovery {
    task: Stepped<'static, Recovered>,
    blamed: u32,
    identity: Identity,
    depth: usize,
    signals: bool,
    clock: Clock,
    /// Before this a look finds the error handling still waiting.
    quiet: Cell<Option<Deadline>>,
}

/// One AHCI port's ATA disk.
pub struct AhciDisk {
    /// `None` only while a [`Recovery`]'s task holds it.
    disk: Option<Box<Disk>>,
    port: Mmio,
    minimum: Rc<Control>,
    retain: Rc<Cell<bool>>,
    recovery: Option<Recovery>,
}

impl AhciDisk {
    pub(super) fn new(disk: Disk) -> Self {
        Self {
            port: disk.port,
            minimum: disk.minimum.clone(),
            retain: disk.retain.clone(),
            disk: Some(Box::new(disk)),
            recovery: None,
        }
    }

    /// Whether error handling is under way.
    #[cfg(test)]
    pub(super) fn recovering(&self) -> bool {
        self.recovery.is_some()
    }

    /// One look: the error handling's next step while it runs, then the
    /// started commands as far as they go without waiting. A failure they
    /// meet starts error handling, whose first step the next look takes:
    /// a look never waits for the port.
    pub(super) fn look_on<P: CommandPort + Clone + 'static>(&mut self, port: &P) {
        if self.recovery.is_some() && !self.step_recovery() {
            return;
        }
        let Some(disk) = self.disk.as_mut() else {
            return;
        };
        if let Some(failed) = disk.run_stepped(port) {
            self.begin_recovery(port, failed);
        }
    }

    /// Take the disk into a task that recovers its port from `failed`, a
    /// step per look.
    fn begin_recovery<P: CommandPort + Clone + 'static>(&mut self, port: &P, failed: Failed) {
        let Some(disk) = self.disk.take() else {
            return;
        };
        let Failed {
            mut failure,
            blamed,
            io,
        } = failed;
        let identity = disk.identity.clone();
        let depth = disk.depth();
        let signals = disk.signal.is_some();
        let clock = disk.clock;
        let port = port.clone();
        let task = Stepped::new(async move {
            let mut disk = disk;
            let result = disk.recover(&port, &mut failure, io).await;
            Recovered {
                disk,
                failure,
                result,
            }
        });
        self.recovery = Some(Recovery {
            task,
            blamed,
            identity,
            depth,
            signals,
            clock,
            quiet: Cell::new(None),
        });
    }

    /// One step of the error handling under way; whether it ended, its
    /// result then given to the commands the failure reached.
    fn step_recovery(&mut self) -> bool {
        let Some(recovery) = self.recovery.as_mut() else {
            return true;
        };
        let Poll::Ready(Recovered {
            disk,
            failure,
            result,
        }) = self.minimum.stepping(|| recovery.task.step())
        else {
            recovery
                .quiet
                .set(recovery.clock.try_deadline(RECOVERY_LOOK_US).ok());
            return false;
        };
        let blamed = recovery.blamed;
        self.recovery = None;
        self.disk
            .insert(disk)
            .settle_running(blamed, &failure, result);
        true
    }

    /// The disk for a call that waits anyway: error handling under way is
    /// run to its end here first.
    pub(super) fn settled(&mut self) -> &mut Disk {
        while !self.step_recovery() {
            crate::waiting();
            core::hint::spin_loop();
        }
        self.disk
            .as_mut()
            .expect("the disk is back once its error handling ended")
    }

    /// [`BlockDevice::start`] on `port`.
    pub(super) fn start_on<P: CommandPort + Clone + 'static>(
        &mut self,
        port: &P,
        command: Command,
    ) -> Result<u32, BlockError> {
        let Some(disk) = self.disk.as_mut() else {
            return Err(BlockError::Protocol(
                "the SATA port is in error recovery and takes no command",
            ));
        };
        let tag = disk.begin(command)?;
        self.look_on(port);
        Ok(tag)
    }

    /// [`BlockDevice::finish`] on `port`.
    pub(super) fn finish_on<P: CommandPort + Clone + 'static>(
        &mut self,
        port: &P,
        tag: u32,
    ) -> Option<Finished> {
        let pending = match self.disk.as_ref() {
            Some(disk) => {
                let running = disk.running.iter().find(|running| running.tag == tag)?;
                running.result.is_none()
            }
            None => true,
        };
        if pending {
            self.look_on(port);
        }
        let disk = self.disk.as_mut()?;
        let index = disk.running.iter().position(|running| running.tag == tag)?;
        let result = disk.running[index].result.take()?;
        let slot = disk.running.remove(index).slot;
        disk.release(slot);
        Some(result)
    }
}

#[cfg(test)]
impl AhciDisk {
    /// The disk, for a fixture that hands it on as attach does.
    pub(super) fn into_disk(mut self) -> Disk {
        *self.disk.take().expect("no error handling is under way")
    }
}

/// Field access for the fixtures, which build and inspect the disk
/// directly. Product code reaches it only through the block device calls,
/// which never find it inside a recovery's task unawares.
#[cfg(test)]
impl core::ops::Deref for AhciDisk {
    type Target = Disk;
    fn deref(&self) -> &Disk {
        self.disk
            .as_deref()
            .expect("no error handling is under way")
    }
}

#[cfg(test)]
impl core::ops::DerefMut for AhciDisk {
    fn deref_mut(&mut self) -> &mut Disk {
        self.disk
            .as_deref_mut()
            .expect("no error handling is under way")
    }
}

impl Drop for AhciDisk {
    /// A disk dropped while its error handling runs may have an internal
    /// command in flight: its DMA memory stays reserved, as a failed disk's.
    fn drop(&mut self) {
        if self.recovery.is_some() {
            self.retain.set(true);
        }
    }
}

impl BlockDevice for AhciDisk {
    fn identity(&self) -> &Identity {
        match (&self.disk, &self.recovery) {
            (Some(disk), _) => &disk.identity,
            (None, Some(recovery)) => &recovery.identity,
            (None, None) => unreachable!("the disk is out only while its error handling runs"),
        }
    }

    fn read(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        self.settled().read(lba, buffer)
    }

    fn write(&mut self, lba: u64, data: &[u8]) -> Result<(), BlockError> {
        self.settled().write(lba, data)
    }

    fn flush_cache(&mut self) -> Result<(), BlockError> {
        self.settled().flush_cache()
    }

    fn discard(&mut self, lba: u64, blocks: u64) -> Result<(), BlockError> {
        self.settled().discard(lba, blocks)
    }

    fn shutdown(&mut self, power_off: bool) -> Result<(), BlockError> {
        self.settled().shutdown(power_off)
    }

    /// While error handling runs, the depth before it: the commands that
    /// wait stay queued for the port ([`Self::room`]).
    fn depth(&self) -> usize {
        match (&self.disk, &self.recovery) {
            (Some(disk), _) => disk.depth(),
            (None, Some(recovery)) => recovery.depth,
            (None, None) => 0,
        }
    }

    /// None while error handling runs, as Linux's frozen port takes none.
    fn room(&self) -> bool {
        self.disk.as_ref().is_some_and(|disk| disk.room())
    }

    fn start(&mut self, command: Command) -> Result<u32, BlockError> {
        let port = self.port;
        self.start_on(&port, command)
    }

    fn finish(&mut self, tag: u32) -> Option<Finished> {
        let port = self.port;
        self.finish_on(&port, tag)
    }

    /// Whether the port's completions send the HBA's interrupt message.
    fn signals(&self) -> bool {
        match (&self.disk, &self.recovery) {
            (Some(disk), _) => disk.signal.is_some(),
            (None, Some(recovery)) => recovery.signals,
            (None, None) => false,
        }
    }

    /// While error handling runs, whether a millisecond passed since its
    /// last step found it waiting: its waits post nothing to memory.
    fn posted(&self) -> bool {
        match (&self.disk, &self.recovery) {
            (Some(disk), _) => disk.posted(),
            (None, Some(recovery)) => recovery.quiet.get().is_none_or(|quiet| quiet.passed()),
            (None, None) => false,
        }
    }
}
