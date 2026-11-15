// SPDX-License-Identifier: GPL-2.0-only
//! A Bulk-Only disk whose device left the bus after boot and came back.
//! Flaky sticks drop off the bus and come back on the same port. When the
//! device that comes back is the one a published disk's owner was bound
//! to, at the same port path and with the same vendor, product and serial
//! number, it is started again in steps from the guest's service turns, as
//! an input device that arrives is: its settle time, max LUN and each
//! unit's probe end a step at every wait, under the same deadlines as at
//! boot. Identity strings do not tell two sticks of one model apart: many
//! share a fixed serial number, and two of them may be swapped on a port.
//! So each unit's first blocks (`FIRST_BLOCKS`: the protective MBR and GPT
//! header, whose disk GUID and CRCs differ between tables made apart) are
//! read at publication, followed through every write Stela makes to them,
//! and read again in steps from the device that came back. The units that
//! probe with the identity they were published with, capacity included,
//! and hold the same first blocks go on with the fresh transport, as after
//! a port reset (`media::Owner::revalidate`). Any other storage device, this
//! one with another medium, or one whose first blocks did not read or were
//! not known stays unused until the next boot: a disk taken by mistake
//! would get the old disk's writes.
use super::bot::{
    ResumeBuffers, max_lun_answer, max_lun_request, resume_buffers, scan_command_time, scanned,
};
use super::media::{Owner, TransportOwner};
use super::*;
use crate::Clock;
use crate::usb::descriptor::interfaces;
use crate::usb::xhci::Controller;
use stela_driver_base::stepped::{until, yield_now};

/// Times one disk's device may come back and be started again in a boot:
/// each takes a fresh transport's buffers from the drivers' DMA pages,
/// which a device that left keeps. Past it the device stays unused until
/// the next boot.
const RETURNS: u32 = 16;

/// Why the device that came back to a UAS disk's port is not started again.
pub(in crate::usb) const UAS_RETURNED: &str =
    "storage device of a UAS disk in use came back after boot, kept unused until the next boot";
/// Why a device that came back too often is not started again.
pub(in crate::usb) const RETURNED_TOO_OFTEN: &str = "storage device of a disk in use came back after boot too often, kept unused until the next boot";
/// Why a device without its Bulk-Only setting is not started again.
pub(in crate::usb) const RETURNED_CHANGED: &str = "storage device of a disk in use came back after boot without its Bulk-Only interface, kept unused until the next boot";
/// Why a device whose units probed as others is not taken.
pub(in crate::usb) const OTHER_IDENTITY: &str = "storage device came back after boot at the port of a disk in use with another identity, kept unused until the next boot";
/// Why a device whose units hold other first blocks is not taken.
pub(in crate::usb) const OTHER_MEDIUM: &str = "storage device came back after boot at the port of a disk in use with its identity but a different medium (its first blocks differ), kept unused until the next boot";
/// Why a device whose first blocks could not be compared is not taken.
pub(in crate::usb) const UNCHECKED_MEDIUM: &str = "storage device came back after boot at the port of a disk in use, but its medium could not be compared (its first blocks did not read, or a write to them was not seen to complete), kept unused until the next boot";

/// The disk owner a device that came back after boot is started again
/// for, and the Bulk-Only setting it is configured with.
pub(in crate::usb) struct Returning {
    owner: Rc<RefCell<Owner<Bot<Native>>>>,
    pub(in crate::usb) interface: Interface,
    pub(in crate::usb) endpoints: [Endpoint; 2],
}

/// What a storage device that arrived after boot is to the disks in use.
pub(in crate::usb) enum Return {
    /// None of theirs.
    Other,
    /// Theirs, started again.
    Resume(Returning),
    /// Theirs, kept unused, and why.
    Unused(&'static str),
}

/// Whether `device`, which arrived after boot, is the device of one of the
/// `kept` interfaces whose disks are in use: at the same port path, with
/// the same vendor, product and serial number, the old device gone and at
/// least one disk published. A device without a serial number cannot be
/// told apart from another of its model and is never taken.
pub(in crate::usb) fn returning(
    kept: &[UsbStorage],
    controller: &Controller,
    device: &Device,
) -> Return {
    let Some(serial) = device.serial.as_deref() else {
        return Return::Other;
    };
    let same = |old: &Device| {
        old.location == device.location
            && old.serial.as_deref() == Some(serial)
            && old.descriptor[8..12] == device.descriptor[8..12]
            && controller.validate_device_id(old.id).is_err()
    };
    for storage in kept {
        let owner = match &storage.owner {
            TransportOwner::Bot(owner) => owner,
            TransportOwner::Uas(owner) => {
                let owner = owner.borrow();
                if same(owner.transport.device()) && !owner.published().0.is_empty() {
                    return Return::Unused(UAS_RETURNED);
                }
                continue;
            }
            TransportOwner::EhciBot(_) => continue,
        };
        let number = {
            let borrowed = owner.borrow();
            let Some((old, setting)) = borrowed.transport.attached() else {
                continue;
            };
            if !same(old) || borrowed.published().0.is_empty() {
                continue;
            }
            if borrowed.returned() >= RETURNS {
                return Return::Unused(RETURNED_TOO_OFTEN);
            }
            setting.number
        };
        return match setting(device, number) {
            Some((interface, endpoints)) => Return::Resume(Returning {
                owner: owner.clone(),
                interface,
                endpoints,
            }),
            None => Return::Unused(RETURNED_CHANGED),
        };
    }
    Return::Other
}

/// The Bulk-Only setting of interface `number` in `device`'s selected
/// configuration, as the reset path requires it: the device's only
/// interface, with two bulk endpoints its speed takes.
fn setting(device: &Device, number: u8) -> Option<(Interface, [Endpoint; 2])> {
    bot::supported(device).ok()?;
    let all = interfaces(&device.configuration);
    if all.is_empty() || all.iter().any(|interface| interface.number != number) {
        return None;
    }
    all.into_iter().filter(bulk_only).find_map(|interface| {
        let bulk = |input: bool| {
            interface
                .endpoints
                .iter()
                .copied()
                .find(|e| e.kind() == 2 && e.is_in() == input)
        };
        let endpoints = [bulk(true)?, bulk(false)?];
        endpoints
            .iter()
            .all(|e| e.validate_context(device.speed).is_ok())
            .then_some((interface, endpoints))
    })
}

/// Take the transport buffers of a device that came back, in the step that
/// has the drivers' allocator.
pub(in crate::usb) fn buffers(dma: &mut dyn DmaAllocator) -> Result<ResumeBuffers, BlockError> {
    resume_buffers(dma)
}

/// Start `device`, configured with `returning`'s setting, again for its
/// disks, in steps: wait out its settle time (Linux `delay_use`), ask its
/// max LUN, probe each published unit and read its first blocks. How many
/// units go on, or why nothing was taken ([`Owner::resume`]); `Err`
/// where the transport failed, which takes nothing either.
#[expect(
    clippy::result_large_err,
    reason = "The failed operation and its exact cause, as the reset path reports them."
)]
pub(in crate::usb) async fn resume(
    controller: Shared,
    device: &Device,
    returning: Returning,
    buffers: ResumeBuffers,
) -> Result<Result<usize, &'static str>, (String, BlockError)> {
    let Returning {
        owner,
        interface,
        endpoints,
    } = returning;
    let clock = controller.borrow().clock;
    until(clock.deadline(settle::SETTLE_US)).await;
    let command_us = scan_command_time();
    let mut io = Native {
        controller,
        id: device.id,
        endpoints,
        command_us: command_us.clone(),
    };
    let fail = |operation: &str, error| (format!("{operation} after it came back"), error);
    let asks = Bot::asks_max_lun(device).map_err(|error| fail("BOT quirks", error))?;
    let max_lun = if asks {
        io.ready().map_err(|error| fail("BOT readiness", error))?;
        let mut request = io.begin_control(max_lun_request(interface.number));
        let answer = loop {
            yield_now().await;
            if let Some(answer) = io.look(&mut request) {
                break answer;
            }
        };
        match max_lun_answer(answer) {
            Some(max_lun) => max_lun,
            None => {
                io.ready().map_err(|error| fail("BOT GET_MAX_LUN", error))?;
                0
            }
        }
    } else {
        0
    };
    if max_lun != owner.borrow().transport.max_lun() {
        return Ok(Err(OTHER_IDENTITY));
    }
    let mut bot = Bot::resumed(io, device, &interface, buffers, max_lun)
        .map_err(|error| fail("BOT transport", error))?;
    let (units, serial) = owner.borrow().published();
    let mut probed = Vec::new();
    for (lun, location) in units {
        let mut steps = Steps {
            bot: &mut bot,
            clock,
        };
        let identity = probe_with(&mut steps, lun, &location, &serial).await;
        let first = match &identity {
            Ok((identity, _)) => Some(first_blocks_with(&mut steps, lun, identity).await),
            Err(_) => None,
        };
        if bot.poisoned() {
            let error = match (identity, first) {
                (Err(error), _) | (_, Some(Err(error))) => error,
                _ => BlockError::Unsupported("USB storage transport quarantined during its probe"),
            };
            return Err(fail(&format!("{location} probe"), error));
        }
        // A first-blocks read that failed leaves the unit unchecked, never
        // taken.
        probed.push((lun, identity, first.and_then(Result::ok)));
    }
    scanned(&command_us);
    Ok(owner.borrow_mut().resume(bot, probed))
}

/// A fresh Bulk-Only transport whose commands run in steps: each ends a
/// step at every transfer not yet done, and a wait at its deadline.
struct Steps<'a> {
    bot: &'a mut Bot<Native>,
    clock: Clock,
}

impl Commands for Steps<'_> {
    type Lun = u8;
    async fn command(
        &mut self,
        lun: u8,
        cdb: &[u8],
        data: Data<'_>,
    ) -> Result<Vec<u8>, BlockError> {
        // A failed command's reset recovery settles first.
        while self.bot.settling() {
            yield_now().await;
        }
        let result = match self.bot.begin(lun, cdb, data) {
            Ok(()) => loop {
                yield_now().await;
                if let Some(result) = self.bot.end() {
                    break result;
                }
            },
            Err(error) => Err(error),
        };
        while self.bot.resetting() {
            yield_now().await;
        }
        self.bot.minimum_error().map_or(result, Err)
    }
    async fn delay(&mut self, micros: u64) -> Result<(), BlockError> {
        until(self.clock.deadline(micros)).await;
        Ok(())
    }
    async fn read_before_mode_sense(
        &mut self,
        lun: u8,
        block_size: usize,
    ) -> Result<(), BlockError> {
        let initial_read = self.bot.take_initial_read();
        read_block_zero(self, lun, block_size, initial_read).await
    }
    fn poisoned(&self) -> bool {
        self.bot.poisoned()
    }
    fn capacity16_first(&self) -> bool {
        self.bot.capacity16_first()
    }
    fn adjust_capacity(&self, blocks: u64) -> Option<u64> {
        self.bot.capacity(blocks)
    }
    fn max_transfer_bytes(&self) -> usize {
        self.bot.max_transfer_bytes()
    }
    fn write_protect_page(&self) -> Option<u8> {
        Scsi::write_protect_page(&*self.bot)
    }
}
