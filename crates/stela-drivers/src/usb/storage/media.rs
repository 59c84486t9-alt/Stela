//! Retained class lifetime and permanent per-publication media validity.
// SPDX-License-Identifier: GPL-2.0-only
// Linux sd.c::sd_check_events/media_not_present/sd_revalidate_disk and
// scsi_lib.c::scsi_io_completion_action. See THIRD_PARTY.md.
use super::*;

pub(super) fn no_media(status: u32) -> bool {
    matches!(status >> 16, 2 | 6) && (status >> 8) & 255 == 0x3a
}
pub(super) fn changed(status: u32) -> bool {
    status >> 16 == 6 || no_media(status) || status >> 16 == 5 && (status >> 8) & 255 == 0x25
}

pub(super) struct Owner<T: Scsi> {
    pub transport: T,
    prefix: String,
    serial: String,
    units: Vec<Unit<T::Lun>>,
    pending: Vec<(T::Lun, Rc<Cell<bool>>)>,
}
struct Unit<L> {
    lun: L,
    identity: Identity,
    valid: Rc<Cell<bool>>,
}
impl<T: Scsi> Owner<T> {
    pub fn new(transport: T, prefix: String, serial: String) -> Self {
        Self {
            transport,
            prefix,
            serial,
            units: Vec::new(),
            pending: Vec::new(),
        }
    }
    pub fn invalidate(&mut self) {
        for (_, valid) in &self.pending {
            valid.set(false);
        }
        for unit in &self.units {
            unit.valid.set(false);
        }
    }
    fn changed(&mut self, lun: T::Lun) {
        for (unit, valid) in &self.pending {
            if *unit == lun {
                valid.set(false);
            }
        }
        for unit in &self.units {
            if unit.lun == lun {
                unit.valid.set(false);
            }
        }
    }
    fn reconcile(&mut self, disks: &mut [Disk<Self>]) {
        for old in &self.units {
            if let Some(disk) = disks.iter_mut().find(|disk| disk.lun == old.lun) {
                if old.valid.get() && disk.identity == old.identity {
                    disk.media = old.valid.clone();
                } else {
                    old.valid.set(false);
                }
            } else {
                old.valid.set(false);
            }
        }
        self.units = disks
            .iter()
            .map(|disk| Unit {
                lun: disk.lun,
                identity: disk.identity.clone(),
                valid: disk.media.clone(),
            })
            .collect();
    }
}
impl<T: Scsi> Scsi for Owner<T> {
    type Lun = T::Lun;
    fn command(
        &mut self,
        lun: Self::Lun,
        cdb: &[u8],
        data: Data<'_>,
    ) -> Result<Vec<u8>, BlockError> {
        let result = self.transport.command(lun, cdb, data);
        // No retry of data commands. UA identifies an invalidated media view,
        // even when subsequent TUR consumes it and the capacity is unchanged.
        if matches!(result, Err(BlockError::Device { status }) if changed(status))
            || result.is_ok()
                && cdb.first() == Some(&0x1b)
                && cdb.get(4).is_some_and(|flags| flags & 2 != 0)
        {
            self.changed(lun);
        }
        if self.transport.poisoned()
            || matches!(result, Err(BlockError::Device { status: 0x063f0e }))
        {
            self.invalidate();
        }
        result
    }
    fn delay(&self, micros: u64) {
        self.transport.delay(micros);
    }
    fn poisoned(&self) -> bool {
        self.transport.poisoned()
    }
    fn mode_page(&self) -> u8 {
        self.transport.mode_page()
    }
    fn report_luns_permitted(&self) -> bool {
        self.transport.report_luns_permitted()
    }
    fn media_publication(&mut self, lun: Self::Lun, valid: Rc<Cell<bool>>) {
        self.pending.push((lun, valid));
    }
    fn max_lun(&self) -> u8 {
        self.transport.max_lun()
    }
}

fn finish<T: Scsi>(
    owner: &Rc<RefCell<Owner<T>>>,
    result: Result<Vec<Disk<Owner<T>>>, BlockError>,
) -> Result<Vec<Disk<Owner<T>>>, BlockError> {
    match result {
        Ok(mut disks) => {
            let mut owner = owner.borrow_mut();
            owner.reconcile(&mut disks);
            owner.pending.clear();
            Ok(disks)
        }
        Err(error) => {
            let mut owner = owner.borrow_mut();
            owner.invalidate();
            owner.pending.clear();
            Err(error)
        }
    }
}
fn scan<T: Scsi>(
    owner: Rc<RefCell<Owner<T>>>,
    mut discover: impl FnMut() -> Result<Vec<Disk<Owner<T>>>, BlockError>,
) -> Result<Vec<Disk<Owner<T>>>, BlockError> {
    for _ in 0..3 {
        let result = discover();
        if result.is_err() {
            return finish(&owner, result);
        }
        let unstable = owner.borrow().pending.iter().any(|(_, valid)| !valid.get());
        if !unstable {
            return finish(&owner, result);
        }
        // A later command invalidated an already-probed view. Discard every
        // provisional disk and repeat only inventory/readiness/metadata probes.
        let mut owner = owner.borrow_mut();
        for (_, valid) in &owner.pending {
            valid.set(false);
        }
        owner.pending.clear();
    }
    finish(
        &owner,
        Err(BlockError::Unsupported(
            "USB media changed repeatedly during rescan",
        )),
    )
}
pub(super) fn scan_bot<T: Scsi<Lun = u8>>(
    owner: Rc<RefCell<Owner<T>>>,
    failures: &mut Vec<(String, BlockError)>,
) -> Result<Vec<Disk<Owner<T>>>, BlockError> {
    let (prefix, serial) = {
        let o = owner.borrow();
        (o.prefix.clone(), o.serial.clone())
    };
    scan(owner.clone(), || {
        discover_units(owner.clone(), &prefix, &serial, failures)
    })
}
pub(super) fn scan_uas<T: Scsi<Lun = uas::Lun>>(
    owner: Rc<RefCell<Owner<T>>>,
    failures: &mut Vec<(String, BlockError)>,
) -> Result<Vec<Disk<Owner<T>>>, BlockError> {
    let (prefix, serial) = {
        let o = owner.borrow();
        (o.prefix.clone(), o.serial.clone())
    };
    scan(owner.clone(), || {
        discover_uas_units(owner.clone(), &prefix, &serial, failures)
    })
}

/// A configured storage interface retained independently of inserted media.
/// Clones share the same serialized transport and permanent disk validity.
#[derive(Clone)]
pub struct UsbStorage {
    pub(super) owner: TransportOwner,
}
#[derive(Clone)]
pub(super) enum TransportOwner {
    Bot(Rc<RefCell<Owner<Bot<Native>>>>),
    Uas(Rc<RefCell<Owner<uas::Host>>>),
}
impl UsbStorage {
    /// Controller/physical-interface location, including an empty reader.
    pub fn location(&self) -> String {
        match &self.owner {
            TransportOwner::Bot(owner) => owner.borrow().prefix.clone(),
            TransportOwner::Uas(owner) => owner.borrow().prefix.clone(),
        }
    }
    /// Poll actual LUN inventory/readiness and revalidate current media. The
    /// caller replaces its disk inventory with this result. Existing aliases
    /// remain valid only for unchanged media without an observed change event.
    /// This synchronous operation does not install a polling/hotplug scheduler.
    pub fn rescan(
        &mut self,
        failures: &mut Vec<(String, BlockError)>,
    ) -> Result<Vec<UsbDisk>, BlockError> {
        match &self.owner {
            TransportOwner::Bot(owner) => scan_bot(owner.clone(), failures).map(|units| {
                units
                    .into_iter()
                    .map(|disk| UsbDisk {
                        disk: UsbTransport::Bot(disk),
                    })
                    .collect()
            }),
            TransportOwner::Uas(owner) => scan_uas(owner.clone(), failures).map(|units| {
                units
                    .into_iter()
                    .map(|disk| UsbDisk {
                        disk: UsbTransport::Uas(disk),
                    })
                    .collect()
            }),
        }
    }
    /// Actual device reset followed by fresh transport, descriptors and media
    /// probes. This owner retains the new interface even when no LUN is ready.
    /// Other copies of the old owner and all its disks remain quarantined.
    pub fn reset_and_rebind(
        &mut self,
        dma: &mut dyn DmaAllocator,
        failures: &mut Vec<(String, BlockError)>,
    ) -> Result<Vec<UsbDisk>, BlockError> {
        let TransportOwner::Uas(old) = &self.owner else {
            return Err(BlockError::Unsupported(
                "USB reset/rebind currently requires UAS",
            ));
        };
        let result = {
            let mut old = old.borrow_mut();
            old.invalidate();
            old.transport.reset_and_rebind(dma)
        };
        let host = result.map_err(|(operation, error)| {
            failures.push((operation, error.clone()));
            error
        })?;
        let device = host.device();
        let prefix = format!("{} interface {}", device.location, host.interface());
        let serial = String::from(device.serial.as_deref().unwrap_or(&device.location));
        self.owner = TransportOwner::Uas(Rc::new(RefCell::new(Owner::new(host, prefix, serial))));
        let result = self.rescan(failures);
        if result.is_err()
            && let TransportOwner::Uas(owner) = &self.owner
        {
            owner.borrow_mut().transport.quarantine();
        }
        result
    }
}
impl UsbDisk {
    /// Retain the configured interface for later rescan, even after removing
    /// every published disk from the caller's inventory.
    pub fn storage(&self) -> UsbStorage {
        UsbStorage {
            owner: match &self.disk {
                UsbTransport::Bot(disk) => TransportOwner::Bot(disk.bot.clone()),
                UsbTransport::Uas(disk) => TransportOwner::Uas(disk.bot.clone()),
            },
        }
    }
    /// Recovery variant that preserves the fresh owner even with zero disks.
    pub fn reset_and_rebind_retained(
        &mut self,
        dma: &mut dyn DmaAllocator,
        failures: &mut Vec<(String, BlockError)>,
    ) -> Result<(UsbStorage, Vec<UsbDisk>), BlockError> {
        let mut owner = self.storage();
        let disks = owner.reset_and_rebind(dma, failures)?;
        Ok((owner, disks))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "requires pinned unchanged Linux media/readiness helper trace"]
    fn unchanged_linux_media_helpers_match_all_normalized_sense_profiles() {
        extern crate std;
        let trace = std::fs::read(
            std::env::var("STELA_USB_MEDIA_ORACLE").expect("media helper trace path"),
        )
        .unwrap();
        assert_eq!(trace.len(), 131_072 * 10);
        for row in trace.as_chunks::<10>().0 {
            let [
                key,
                asc,
                ascq,
                valid,
                removable,
                present,
                absent,
                removed_changed,
                tur_changed,
                zero,
            ] = *row;
            let status = u32::from(key) << 16 | u32::from(asc) << 8 | u32::from(ascq);
            assert_eq!(absent != 0, valid != 0 && no_media(status));
            assert_eq!(removed_changed != 0, absent != 0 && present != 0);
            assert_eq!(zero != 0, absent != 0 && removable != 0);
            assert_eq!(tur_changed != 0, valid != 0 && removable != 0 && key == 6);
            if valid != 0 && removable != 0 {
                assert_eq!(
                    changed(status),
                    absent != 0 || tur_changed != 0 || key == 5 && asc == 0x25
                );
            }
        }
    }
}
