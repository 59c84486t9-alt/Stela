//! SCSI-transparent USB disks over native BOT and UAS owners. Logical units
//! share their transport's serialized command/tag/DMA and quarantine boundary.
//! Every command carries the actual transport LUN; uncertain DMA prevents
//! publication of any disk belonging to the interface.
// SPDX-License-Identifier: GPL-2.0-only AND GPL-2.0-or-later
// Protocol/SCSI references: Linux usb-storage, Matthew Dharm and contributors;
// see THIRD_PARTY.md for the pinned sources, notices and implementation scope.
use super::xhci::{Device, Endpoint, Interface, MAX_TD, Plan, STALL, Shared, setup};
use crate::{
    block::{BlockDevice, BlockError, Identity, Sense, Transport},
    bus::dma::DmaAllocator,
};
use alloc::{format, rc::Rc, string::String, vec, vec::Vec};
use core::cell::{Cell, RefCell};
mod media;
pub use media::UsbStorage;
mod bot;
mod scsi;
pub mod uas;
use bot::{Bot, Io, Native};
pub const CLASS: u8 = 8;
const SCSI: u8 = 6;
const BULK_ONLY: u8 = 0x50;
const READY_TRIES: usize = 20;
const READY_DELAY_US: u64 = 100_000;

mod binding;
pub use binding::Binding;
pub(super) use binding::discover as discover_binding;

pub(super) fn plan(
    device: &Device,
    interface: &Interface,
    all: &[Interface],
    controller: Option<&super::xhci::Controller>,
) -> Result<Plan, &'static str> {
    binding::select(device, interface, all, controller).map(Plan::Storage)
}

/// Which way a command's data goes.
pub enum Data<'a> {
    None,
    In(usize),
    Out(&'a [u8]),
}

/// How a unit's write cache is found, as Linux `sd_read_cache_type` finds
/// it: from the Caching mode page, or assumed when a transport's devices
/// mishandle that page (`skip_ms_page_8`, with or without `wce_default_on`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Caching {
    Query,
    WriteThrough,
    WriteBack,
}

/// SCSI semantics are shared across BOT and UAS; each transport retains its
/// own framing, LUN address type, command ownership and uncertainty boundary.
trait Scsi {
    type Lun: Copy + Default + PartialEq + core::fmt::Display;
    fn command(
        &mut self,
        lun: Self::Lun,
        cdb: &[u8],
        data: Data<'_>,
    ) -> Result<Vec<u8>, BlockError>;
    fn delay(&self, micros: u64);
    fn poisoned(&self) -> bool;
    fn media_publication(&mut self, _lun: Self::Lun, _valid: Rc<Cell<bool>>) {}
    fn max_lun(&self) -> u8 {
        0
    }
    fn generation(&self) -> u64 {
        0
    }
    fn max_transfer_bytes(&self) -> usize {
        MAX_TD
    }
    fn capacity16_first(&self) -> bool {
        false
    }
    fn adjust_capacity(&self, blocks: u64) -> Option<u64> {
        Some(blocks)
    }
    fn separate_last_sector(&self) -> bool {
        false
    }
    fn read_before_mode_sense(
        &mut self,
        _lun: Self::Lun,
        _block_size: usize,
    ) -> Result<(), BlockError> {
        Ok(())
    }
    /// The mode page that reports write protection, or none when the unit
    /// is assumed writable (Linux `skip_ms_page_3f`).
    fn write_protect_page(&self) -> Option<u8> {
        Some(scsi::ALL_PAGES)
    }
    fn caching(&self) -> Caching {
        Caching::Query
    }
    fn report_luns_permitted(&self) -> bool {
        true
    }
}
impl<I: Io> Scsi for Bot<I> {
    type Lun = u8;
    fn command(&mut self, lun: u8, cdb: &[u8], data: Data<'_>) -> Result<Vec<u8>, BlockError> {
        Bot::command(self, lun, cdb, data)
    }
    fn delay(&self, micros: u64) {
        Bot::delay(self, micros);
    }
    fn poisoned(&self) -> bool {
        Bot::poisoned(self)
    }
    fn max_lun(&self) -> u8 {
        Bot::max_lun(self)
    }
    /// Linux usb-storage skips the Caching page for every disk and assumes
    /// write-through without its `WRITE_CACHE` quirk.
    fn caching(&self) -> Caching {
        if self.write_cache() {
            Caching::WriteBack
        } else {
            Caching::WriteThrough
        }
    }
    fn write_protect_page(&self) -> Option<u8> {
        self.write_protect().then_some(scsi::ALL_PAGES)
    }
    fn generation(&self) -> u64 {
        Bot::generation(self)
    }
    fn max_transfer_bytes(&self) -> usize {
        Bot::max_transfer_bytes(self)
    }
    fn capacity16_first(&self) -> bool {
        Bot::capacity16_first(self)
    }
    fn adjust_capacity(&self, blocks: u64) -> Option<u64> {
        Bot::capacity(self, blocks)
    }
    fn separate_last_sector(&self) -> bool {
        true
    }
    fn read_before_mode_sense(&mut self, lun: u8, block_size: usize) -> Result<(), BlockError> {
        Bot::read_before_mode_sense(self, lun, block_size)
    }
}
impl Scsi for uas::Host {
    type Lun = uas::Lun;
    fn command(
        &mut self,
        lun: uas::Lun,
        cdb: &[u8],
        data: Data<'_>,
    ) -> Result<Vec<u8>, BlockError> {
        uas::Host::command(self, lun.bytes(), cdb, data)
    }
    fn delay(&self, micros: u64) {
        uas::Host::delay(self, micros);
    }
    fn poisoned(&self) -> bool {
        self.requires_rebind()
    }
    fn write_protect_page(&self) -> Option<u8> {
        uas::Host::write_protect_page(self)
    }
    fn caching(&self) -> Caching {
        uas::Host::caching(self)
    }
    fn report_luns_permitted(&self) -> bool {
        uas::Host::report_luns_permitted(self)
    }
    fn max_transfer_bytes(&self) -> usize {
        uas::Host::max_transfer_bytes(self)
    }
    fn read_before_mode_sense(
        &mut self,
        lun: uas::Lun,
        block_size: usize,
    ) -> Result<(), BlockError> {
        uas::Host::read_before_mode_sense(self, lun.bytes(), block_size)
    }
}

/// One logical unit. Its shared owner serializes complete CDBs and sense.
pub struct UsbDisk {
    disk: UsbTransport,
}
enum UsbTransport {
    Bot(Disk<media::Owner<Bot<Native>>>),
    Uas(Disk<media::Owner<uas::Host>>),
}

struct Disk<T: Scsi> {
    bot: Rc<RefCell<T>>,
    lun: T::Lun,
    identity: Identity,
    media: Rc<Cell<bool>>,
    /// The unit caches writes, so a flush sends SYNCHRONIZE CACHE.
    write_cache: bool,
}

pub(super) fn discover_retained(
    controller: Shared,
    device: &Device,
    interface: &Interface,
    endpoints: [Endpoint; 2],
    dma: &mut dyn DmaAllocator,
    failures: &mut Vec<(String, BlockError)>,
) -> Result<(UsbStorage, Vec<UsbDisk>), BlockError> {
    let bot = Bot::native(
        Native {
            controller,
            id: device.id,
            endpoints,
        },
        device,
        interface,
        dma,
    )?;
    let owner = Rc::new(RefCell::new(media::Owner::new(
        bot,
        format!("{} interface {}", device.location, interface.number),
        device.serial.as_deref().unwrap_or(&device.location).into(),
    )));
    let mut storage = UsbStorage {
        owner: media::TransportOwner::Bot(owner),
    };
    let disks = storage.rescan(failures)?;
    Ok((storage, disks))
}

/// Discover block devices through an actual configured UAS interface.
/// Use [`discover_uas_retained`] to keep initially empty interfaces for rescan.
///
/// # Safety
/// The exclusive attachment/configuration/unconfigured endpoint requirements of
/// [`uas::Host::new`] apply.
pub unsafe fn discover_uas(
    controller: Shared,
    device: &Device,
    binding: uas::Binding,
    dma: &mut dyn DmaAllocator,
    failures: &mut Vec<(String, BlockError)>,
) -> Result<Vec<UsbDisk>, BlockError> {
    // SAFETY: this caller grants the identical retained-constructor contract.
    unsafe { discover_uas_retained(controller, device, binding, dma, failures) }
        .map(|(_, disks)| disks)
}

/// Retain a UAS interface independently of the current ready-media inventory.
///
/// # Safety
/// The exclusive attachment/configuration/unconfigured endpoint requirements of
/// [`uas::Host::new`] apply.
pub unsafe fn discover_uas_retained(
    controller: Shared,
    device: &Device,
    binding: uas::Binding,
    dma: &mut dyn DmaAllocator,
    failures: &mut Vec<(String, BlockError)>,
) -> Result<(UsbStorage, Vec<UsbDisk>), BlockError> {
    let prefix = format!("{} interface {}", device.location, binding.interface());
    let serial = device.serial.as_deref().unwrap_or(&device.location).into();
    // SAFETY: caller owns this exact configured interface and epoch.
    let host = unsafe { uas::Host::new(controller, device, binding, dma)? };
    let owner = Rc::new(RefCell::new(media::Owner::new(host, prefix, serial)));
    let mut storage = UsbStorage {
        owner: media::TransportOwner::Uas(owner),
    };
    let disks = storage.rescan(failures)?;
    Ok((storage, disks))
}

fn discover_uas_units<T: Scsi<Lun = uas::Lun>>(
    owner: Rc<RefCell<T>>,
    prefix: &str,
    serial: &str,
    failures: &mut Vec<(String, BlockError)>,
) -> Result<Vec<Disk<T>>, BlockError> {
    let zero = uas::Lun::default();
    let initial = inquiry(&mut *owner.borrow_mut(), zero);
    if owner.borrow().poisoned() {
        return Err(quarantined());
    }
    // The initial INQUIRY establishes the actual ANSI level. Failure to learn
    // it keeps the source's conservative eight-unit sequential fallback.
    let version = initial.as_ref().map_or(0, |bytes| bytes[2] & 0x0f);
    let mut disks = Vec::new();
    // The source scans actual LUN0 before REPORT LUNS. A real attached unit
    // must survive a report that omits zero; an absent unit is never invented.
    let initial_present = initial
        .as_ref()
        .is_ok_and(|bytes| bytes[0] >> 5 != 3 && bytes[0] & 31 != 31);
    if initial_present {
        publish_unit(
            &owner,
            zero,
            initial.clone(),
            prefix,
            serial,
            failures,
            &mut disks,
        )?;
    }
    let reported = if version >= 3 && owner.borrow().report_luns_permitted() {
        report_luns(&mut *owner.borrow_mut())?
    } else {
        None
    };
    if let Some(luns) = reported {
        for lun in luns {
            if lun == zero && initial_present {
                continue;
            }
            let found = if lun == zero {
                initial.clone()
            } else {
                inquiry(&mut *owner.borrow_mut(), lun)
            };
            publish_unit(&owner, lun, found, prefix, serial, failures, &mut disks)?;
        }
    } else {
        let limit = if version >= 3 { 256 } else { 8 };
        for number in 0..limit {
            if number == 0 && initial_present {
                continue;
            }
            let lun = uas::Lun::sequential(number);
            let found = if number == 0 {
                initial.clone()
            } else {
                inquiry(&mut *owner.borrow_mut(), lun)
            };
            if owner.borrow().poisoned() {
                return Err(quarantined());
            }
            // Sequential fallback stops at the first actual absent logical
            // unit, not at a present card-reader slot with no inserted media.
            if found
                .as_ref()
                .is_ok_and(|bytes| bytes[0] >> 5 == 3 || bytes[0] & 31 == 31)
                || matches!(&found, Err(BlockError::Sense(sense))
                    if sense.key == Sense::ILLEGAL_REQUEST && sense.asc == Sense::UNSUPPORTED_UNIT)
            {
                break;
            }
            let failed_inquiry = found.is_err();
            publish_unit(&owner, lun, found, prefix, serial, failures, &mut disks)?;
            if failed_inquiry {
                break;
            }
        }
    }
    Ok(disks)
}

fn quarantined() -> BlockError {
    BlockError::Unsupported("USB storage interface quarantined during discovery")
}

fn publication<T: Scsi>(owner: &Rc<RefCell<T>>, lun: T::Lun, identity: Identity) -> Disk<T> {
    let media = Rc::new(Cell::new(true));
    let write_cache = write_cache(&mut *owner.borrow_mut(), lun);
    owner.borrow_mut().media_publication(lun, media.clone());
    Disk {
        bot: owner.clone(),
        lun,
        identity,
        media,
        write_cache,
    }
}

/// Linux `sd_read_cache_type`: the Caching page's WCE bit, or the
/// transport's assumption; an unreadable page means write-through.
fn write_cache<T: Scsi>(bot: &mut T, lun: T::Lun) -> bool {
    match bot.caching() {
        Caching::WriteThrough => false,
        Caching::WriteBack => true,
        Caching::Query => bot
            .command(
                lun,
                &scsi::mode_sense(scsi::CACHING_PAGE),
                Data::In(scsi::MODE_SENSE_BYTES),
            )
            .ok()
            .and_then(|mode| scsi::write_cache_enabled(&mode))
            .unwrap_or(false),
    }
}

fn publish_unit<T: Scsi>(
    owner: &Rc<RefCell<T>>,
    lun: T::Lun,
    found: Result<Vec<u8>, BlockError>,
    prefix: &str,
    serial: &str,
    failures: &mut Vec<(String, BlockError)>,
    disks: &mut Vec<Disk<T>>,
) -> Result<(), BlockError> {
    let location = format!("{prefix} LUN {lun}");
    let result = found.and_then(|bytes| {
        probe_identified(&mut *owner.borrow_mut(), lun, &bytes, &location, serial)
    });
    match result {
        Ok(identity) => disks.push(publication(owner, lun, identity)),
        Err(error) => failures.push((location, error)),
    }
    if owner.borrow().poisoned() {
        return Err(quarantined());
    }
    Ok(())
}

/// Linux's initial 4 KiB report grows to the actual list extent. Stela's native
/// transfer bound is explicit: an oversized, malformed or unstable list cannot
/// become an apparently complete prefix of disks.
fn report_luns<T: Scsi<Lun = uas::Lun>>(
    owner: &mut T,
) -> Result<Option<Vec<uas::Lun>>, BlockError> {
    let mut allocation = 4096usize;
    for _ in 0..3 {
        let mut cdb = [0u8; 12];
        cdb[0] = scsi::REPORT_LUNS;
        cdb[6..10].copy_from_slice(&(allocation as u32).to_be_bytes());
        let mut received = None;
        for attempt in 0..3 {
            match owner.command(uas::Lun::default(), &cdb, Data::In(allocation)) {
                Ok(bytes) => {
                    received = Some(bytes);
                    break;
                }
                Err(_) if owner.poisoned() => return Err(quarantined()),
                Err(BlockError::Sense(sense))
                    if sense.key == Sense::UNIT_ATTENTION && attempt < 2 =>
                {
                    continue;
                }
                // Source command failures fall back to actual sequential
                // INQUIRY. A poisoned host can never enter this fallback.
                Err(_) => return Ok(None),
            }
        }
        let bytes = received.ok_or(BlockError::Unsupported("REPORT LUNS did not complete"))?;
        if bytes.len() < 8 {
            return Err(BlockError::Unsupported("short REPORT LUNS header"));
        }
        let length = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
        let total = length
            .checked_add(8)
            .ok_or(BlockError::Unsupported("REPORT LUNS length overflow"))?;
        if length & 7 != 0 || total > MAX_TD {
            return Err(BlockError::Unsupported(
                "REPORT LUNS extent outside native bound",
            ));
        }
        if total > allocation {
            allocation = total;
            continue;
        }
        if total > bytes.len() {
            return Err(BlockError::Unsupported("short REPORT LUNS list"));
        }
        let mut luns = Vec::new();
        for address in bytes[8..total].as_chunks::<8>().0 {
            let lun = uas::Lun::from_bytes(*address);
            if luns.contains(&lun) {
                return Err(BlockError::Unsupported("duplicate REPORT LUNS address"));
            }
            luns.push(lun);
        }
        return Ok(Some(luns));
    }
    Err(BlockError::Unsupported(
        "REPORT LUNS list changed repeatedly",
    ))
}

fn discover_units<T: Scsi<Lun = u8>>(
    bot: Rc<RefCell<T>>,
    prefix: &str,
    serial: &str,
    failures: &mut Vec<(String, BlockError)>,
) -> Result<Vec<Disk<T>>, BlockError> {
    let mut disks = Vec::new();
    let max_lun = bot.borrow().max_lun();
    for lun in 0..=max_lun {
        let location = format!("{prefix} LUN {lun}");
        let result = probe(&mut *bot.borrow_mut(), lun, &location, serial);
        match result {
            Ok(identity) => disks.push(publication(&bot, lun, identity)),
            Err(error) => {
                failures.push((location, error));
                // An uncertain interface cannot publish previously found disks
                // as usable: quarantine the entire owner and discard the list.
                if bot.borrow().poisoned() {
                    return Err(BlockError::Unsupported(
                        "USB storage interface quarantined during discovery",
                    ));
                }
            }
        }
    }
    Ok(disks)
}

fn probe<T: Scsi>(
    bot: &mut T,
    lun: T::Lun,
    location: &str,
    serial: &str,
) -> Result<Identity, BlockError> {
    let inquiry = inquiry(bot, lun)?;
    probe_identified(bot, lun, &inquiry, location, serial)
}
fn inquiry<T: Scsi>(bot: &mut T, lun: T::Lun) -> Result<Vec<u8>, BlockError> {
    let mut result = Err(BlockError::Unsupported("INQUIRY did not complete"));
    for _ in 0..3 {
        result = bot.command(lun, &scsi::inquiry(), Data::In(scsi::INQUIRY_BYTES));
        if !matches!(&result, Err(BlockError::Sense(sense)) if sense.key == Sense::UNIT_ATTENTION
            && matches!(sense.asc, Sense::MEDIUM_CHANGED | Sense::RESET_OCCURRED))
        {
            break;
        }
    }
    let bytes = result?;
    if bytes.len() < scsi::INQUIRY_BYTES {
        return Err(BlockError::Unsupported("short INQUIRY data"));
    }
    Ok(bytes)
}
fn probe_identified<T: Scsi>(
    bot: &mut T,
    lun: T::Lun,
    inquiry: &[u8],
    location: &str,
    serial: &str,
) -> Result<Identity, BlockError> {
    if inquiry[0] != 0 {
        return Err(BlockError::Unsupported(
            "USB LUN is not an attached direct-access block device",
        ));
    }
    let text = |bytes: &[u8]| String::from(String::from_utf8_lossy(bytes).trim());
    let mut ready = false;
    let mut started = false;
    for attempt in 0..READY_TRIES {
        match bot.command(lun, &[scsi::TEST_UNIT_READY, 0, 0, 0, 0, 0], Data::None) {
            Ok(_) => {
                ready = true;
                break;
            }
            // No-media must precede the general UA retry: key6/ASC3a also
            // reports absence, and must never lead to capacity/mode queries.
            Err(BlockError::Sense(sense)) if media::no_media(&sense) => {
                return Err(BlockError::Sense(sense));
            }
            // Linux `sd_spinup_disk`: a unit that needs an initializing
            // command gets START STOP UNIT once, then is polled again.
            Err(BlockError::Sense(sense))
                if !started
                    && sense.key == Sense::NOT_READY
                    && sense.asc == Sense::NOT_READY_CAUSE
                    && sense.ascq == Sense::INITIALIZING_COMMAND_REQUIRED =>
            {
                started = true;
                bot.command(lun, &scsi::start_unit(), Data::None)?;
            }
            // The command has already completed same-LUN REQUEST SENSE.
            Err(BlockError::Sense(sense))
                if sense.key == Sense::UNIT_ATTENTION
                    || sense.key == Sense::NOT_READY
                        && sense.asc == Sense::NOT_READY_CAUSE
                        && !matches!(sense.ascq, 3 | 0xb | 0xc | 0x1b | 0x24 | 0x25) =>
            {
                if attempt + 1 < READY_TRIES {
                    bot.delay(READY_DELAY_US);
                }
            }
            Err(error) => return Err(error),
        }
    }
    if !ready {
        return Err(BlockError::Unsupported("USB storage never became ready"));
    }
    let (reported, block_size) = if bot.capacity16_first() {
        capacity16(bot, lun)?
    } else {
        let mut cdb = [0; 10];
        cdb[0] = scsi::READ_CAPACITY_10;
        let capacity = bot.command(lun, &cdb, Data::In(8))?;
        if capacity.len() < 8 {
            return Err(BlockError::Unsupported("short READ CAPACITY data"));
        }
        let last = u32::from_be_bytes(capacity[..4].try_into().unwrap());
        if last == u32::MAX {
            capacity16(bot, lun)?
        } else {
            (
                u64::from(last) + 1,
                u32::from_be_bytes(capacity[4..8].try_into().unwrap()),
            )
        }
    };
    let blocks = bot
        .adjust_capacity(reported)
        .ok_or(BlockError::Unsupported(
            "USB storage invalid adjusted capacity",
        ))?;
    if block_size < 512
        || !block_size.is_power_of_two()
        || block_size as usize > bot.max_transfer_bytes()
        || blocks.checked_mul(u64::from(block_size)).is_none()
    {
        return Err(BlockError::Unsupported(
            "USB storage block size or capacity",
        ));
    }
    bot.read_before_mode_sense(lun, block_size as usize)?;
    let read_only = match bot.write_protect_page() {
        None => false,
        Some(page) => {
            match bot.command(
                lun,
                &scsi::mode_sense(page),
                Data::In(scsi::MODE_SENSE_BYTES),
            ) {
                Ok(mode) => scsi::write_protected(&mode)
                    .ok_or(BlockError::Unsupported("short MODE SENSE data"))?,
                // MODE SENSE is optional only when the unit actually reports an
                // unsupported CDB. USB/transport errors cannot default to writable.
                Err(BlockError::Sense(sense)) if sense.key == Sense::ILLEGAL_REQUEST => false,
                Err(error) => return Err(error),
            }
        }
    };
    Ok(Identity {
        transport: Transport::Usb,
        location: location.into(),
        model: format!("{} {}", text(&inquiry[8..16]), text(&inquiry[16..32]))
            .trim()
            .into(),
        serial: if lun == T::Lun::default() {
            serial.into()
        } else {
            format!("{serial}:lun{lun}")
        },
        blocks,
        block_size,
        read_only,
    })
}

fn capacity16<T: Scsi>(bot: &mut T, lun: T::Lun) -> Result<(u64, u32), BlockError> {
    let mut cdb = [0; 16];
    cdb[0] = scsi::SERVICE_ACTION_IN_16;
    cdb[1] = scsi::READ_CAPACITY_16;
    cdb[13] = 32;
    let bytes = bot.command(lun, &cdb, Data::In(32))?;
    if bytes.len() < 12 {
        return Err(BlockError::Unsupported("short READ CAPACITY (16) data"));
    }
    let blocks = u64::from_be_bytes(bytes[..8].try_into().unwrap())
        .checked_add(1)
        .ok_or(BlockError::Unsupported("USB storage capacity overflow"))?;
    Ok((blocks, u32::from_be_bytes(bytes[8..12].try_into().unwrap())))
}

impl<T: Scsi> Disk<T> {
    /// Execute a SCSI CDB on this unit, including same-LUN auto-sense.
    pub fn command(&mut self, cdb: &[u8], data: Data<'_>) -> Result<Vec<u8>, BlockError> {
        self.check_media()?;
        let result = self.bot.borrow_mut().command(self.lun, cdb, data);
        if matches!(&result, Err(BlockError::Sense(sense)) if media::changed(sense)) {
            self.media.set(false);
        }
        result
    }
    fn check_media(&self) -> Result<(), BlockError> {
        if self.media.get() {
            Ok(())
        } else {
            Err(BlockError::Unsupported(
                "USB storage media publication is stale",
            ))
        }
    }
    /// READ or WRITE of `blocks` at `lba`, (10) when it fits, else (16).
    fn cdb(&self, write: bool, lba: u64, blocks: u32) -> Vec<u8> {
        if lba
            .checked_add(u64::from(blocks))
            .is_some_and(|end| end <= u64::from(u32::MAX) + 1)
            && blocks <= u32::from(u16::MAX)
        {
            let mut cdb = vec![if write { scsi::WRITE_10 } else { scsi::READ_10 }, 0];
            cdb.extend_from_slice(&(lba as u32).to_be_bytes());
            cdb.push(0);
            cdb.extend_from_slice(&(blocks as u16).to_be_bytes());
            cdb.push(0);
            cdb
        } else {
            let mut cdb = vec![if write { scsi::WRITE_16 } else { scsi::READ_16 }, 0];
            cdb.extend_from_slice(&lba.to_be_bytes());
            cdb.extend_from_slice(&blocks.to_be_bytes());
            cdb.extend_from_slice(&[0, 0]);
            cdb
        }
    }
}
impl<T: Scsi> BlockDevice for Disk<T> {
    fn identity(&self) -> &Identity {
        &self.identity
    }

    fn read(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        self.check_media()?;
        self.identity.check(lba, buffer.len())?;
        let size = self.identity.block_size as usize;
        let mut lba = lba;
        let maximum = self.bot.borrow().max_transfer_bytes() / size * size;
        let separate_last = self.bot.borrow().separate_last_sector();
        let mut remaining = buffer;
        while !remaining.is_empty() {
            let mut length = remaining.len().min(maximum);
            if separate_last
                && lba + (length / size) as u64 == self.identity.blocks
                && length > size
            {
                length -= size;
            }
            let (chunk, rest) = remaining.split_at_mut(length);
            remaining = rest;
            let blocks = (chunk.len() / size) as u32;
            let cdb = self.cdb(false, lba, blocks);
            let data = self.command(&cdb, Data::In(chunk.len()))?;
            if data.len() != chunk.len() {
                return Err(BlockError::Protocol("short USB storage read"));
            }
            chunk.copy_from_slice(&data);
            lba += u64::from(blocks);
        }
        Ok(())
    }

    fn write(&mut self, lba: u64, data: &[u8]) -> Result<(), BlockError> {
        self.check_media()?;
        self.identity.check_write(lba, data.len())?;
        let size = self.identity.block_size as usize;
        let mut lba = lba;
        let maximum = self.bot.borrow().max_transfer_bytes() / size * size;
        let separate_last = self.bot.borrow().separate_last_sector();
        let mut remaining = data;
        while !remaining.is_empty() {
            let mut length = remaining.len().min(maximum);
            if separate_last
                && lba + (length / size) as u64 == self.identity.blocks
                && length > size
            {
                length -= size;
            }
            let (chunk, rest) = remaining.split_at(length);
            remaining = rest;
            let blocks = (chunk.len() / size) as u32;
            let cdb = self.cdb(true, lba, blocks);
            self.command(&cdb, Data::Out(chunk))?;
            lba += u64::from(blocks);
        }
        Ok(())
    }

    /// Linux sd flushes only a unit whose write cache is on.
    fn flush(&mut self) -> Result<(), BlockError> {
        if !self.write_cache {
            return self.check_media();
        }
        self.command(&scsi::synchronize_cache(), Data::None)
            .map(|_| ())
    }
}

impl UsbDisk {
    /// Explicit recovery for an exclusively owned root-attached storage device.
    /// All old disk aliases remain quarantined, including on failure. Returned
    /// disks carry fresh INQUIRY/capacity/protection state; no CDB is replayed.
    /// Use [`Self::reset_and_rebind_retained`] to keep an initially empty fresh
    /// interface available for rescan. This does not install a hot-plug scheduler.
    pub fn reset_and_rebind(
        &mut self,
        dma: &mut dyn DmaAllocator,
        failures: &mut Vec<(String, BlockError)>,
    ) -> Result<Vec<UsbDisk>, BlockError> {
        self.reset_and_rebind_retained(dma, failures)
            .map(|(_, disks)| disks)
    }

    /// Execute a SCSI CDB on this unit, including same-LUN auto-sense.
    pub fn command(&mut self, cdb: &[u8], data: Data<'_>) -> Result<Vec<u8>, BlockError> {
        match &mut self.disk {
            UsbTransport::Bot(disk) => disk.command(cdb, data),
            UsbTransport::Uas(disk) => disk.command(cdb, data),
        }
    }
}
impl BlockDevice for UsbDisk {
    fn identity(&self) -> &Identity {
        match &self.disk {
            UsbTransport::Bot(disk) => disk.identity(),
            UsbTransport::Uas(disk) => disk.identity(),
        }
    }
    fn read(&mut self, lba: u64, bytes: &mut [u8]) -> Result<(), BlockError> {
        match &mut self.disk {
            UsbTransport::Bot(disk) => disk.read(lba, bytes),
            UsbTransport::Uas(disk) => disk.read(lba, bytes),
        }
    }
    fn write(&mut self, lba: u64, bytes: &[u8]) -> Result<(), BlockError> {
        match &mut self.disk {
            UsbTransport::Bot(disk) => disk.write(lba, bytes),
            UsbTransport::Uas(disk) => disk.write(lba, bytes),
        }
    }
    fn flush(&mut self) -> Result<(), BlockError> {
        match &mut self.disk {
            UsbTransport::Bot(disk) => disk.flush(),
            UsbTransport::Uas(disk) => disk.flush(),
        }
    }
}
