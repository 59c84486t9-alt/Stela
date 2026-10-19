//! Finding the host disks and selecting the one partition Stela may use.
//!
//! Nothing is guessed: `stela.cfg` names the disk by its serial number and
//! the partition by its unique GPT GUID. Exactly one disk must report that
//! serial and exactly one of its partitions must carry that GUID, and the
//! EFI system partition is refused.
use super::{
    Handoff, ahci,
    block::{BlockDevice, BlockError, Identity},
    dma::DmaAllocator,
    gpt::{self, GptError, Guid, PartitionDevice},
    input, nvme,
    pci::{Address, Function},
    virtio,
    virtio_net::{self, VirtioNet},
    xhci,
};
use crate::platform::net::{Link, Mac, NetError};
use alloc::{boxed::Box, string::String, vec::Vec};
use core::fmt;

/// The disk and partition `stela.cfg` names, as `SERIAL:GUID`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub serial: String,
    pub partition: Guid,
}

impl core::str::FromStr for Target {
    type Err = &'static str;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let (serial, partition) = text
            .rsplit_once(':')
            .ok_or("storage target must be SERIAL:PARTITION-GUID")?;
        if serial.is_empty() {
            return Err("storage target has an empty serial");
        }
        Ok(Self {
            serial: String::from(serial),
            partition: partition.parse()?,
        })
    }
}

/// A host network adapter, as a raw Ethernet link.
pub enum Adapter {
    Virtio(VirtioNet),
    Usb(xhci::ecm::UsbNet),
}

impl Adapter {
    /// Where the adapter is, for logs.
    pub fn location(&self) -> &str {
        match self {
            Self::Virtio(device) => &device.location,
            Self::Usb(device) => &device.location,
        }
    }
}

impl Link for Adapter {
    fn mac(&self) -> Mac {
        match self {
            Self::Virtio(device) => device.mac(),
            Self::Usb(device) => device.mac(),
        }
    }
    fn carrier(&mut self) -> bool {
        match self {
            Self::Virtio(device) => device.carrier(),
            Self::Usb(device) => device.carrier(),
        }
    }
    fn transmit(&mut self, frame: &[u8]) -> Result<(), NetError> {
        match self {
            Self::Virtio(device) => device.transmit(frame),
            Self::Usb(device) => device.transmit(frame),
        }
    }
    fn receive(&mut self) -> Result<Option<Vec<u8>>, NetError> {
        match self {
            Self::Virtio(device) => device.receive(),
            Self::Usb(device) => device.receive(),
        }
    }
}

/// Every block and input device the drivers brought up, and every
/// controller they could not.
#[derive(Default)]
pub struct Disks {
    pub devices: Vec<Box<dyn BlockDevice>>,
    pub inputs: Vec<input::VirtioInput>,
    /// USB keyboards and pointers behind xHCI controllers.
    pub usb_inputs: Vec<xhci::hid::UsbInput>,
    /// Network adapters, as raw Ethernet links.
    pub links: Vec<Adapter>,
    pub failures: Vec<(Address, BlockError)>,
    /// USB devices that failed to enumerate or bind, by location.
    pub usb_failures: Vec<(String, BlockError)>,
    /// USB interfaces no driver here takes, and why.
    pub usb_unused: Vec<(String, &'static str)>,
    /// ECAM windows that were not mapped, and so not scanned.
    pub unmapped: Vec<super::pci::EcamWindow>,
}

/// Enumerate PCI and bring up every virtio-blk, NVMe and AHCI controller,
/// every virtio-input device, every virtio-net adapter, and every xHCI
/// controller with the USB disks, keyboards, pointers and Ethernet
/// adapters on it.
///
/// # Safety
///
/// `handoff` must describe the running machine after ExitBootServices,
/// with its ranges mapped as it says, and nothing else may drive these
/// controllers afterwards.
pub unsafe fn probe(handoff: &Handoff, dma: &mut dyn DmaAllocator) -> Disks {
    let mut disks = Disks::default();
    for window in &handoff.ecam {
        if !handoff.is_mapped(&window.range()) {
            disks.unmapped.push(*window);
            continue;
        }
        // SAFETY: mapped as checked; the caller owns the machine.
        for mut function in unsafe { Function::enumerate(window) } {
            let address = function.address;
            let result = if virtio::matches(&function) {
                virtio::VirtioBlk::new(&mut function, handoff, dma)
                    .map(|device| vec![Box::new(device) as Box<dyn BlockDevice>])
            } else if function.class == nvme::CLASS {
                nvme::attach(&mut function, handoff, dma).map(|namespaces| {
                    namespaces
                        .into_iter()
                        .map(|device| Box::new(device) as Box<dyn BlockDevice>)
                        .collect()
                })
            } else if function.class == xhci::CLASS {
                match xhci::attach(&mut function, handoff, dma) {
                    Ok(found) => {
                        disks.devices.extend(
                            found
                                .disks
                                .into_iter()
                                .map(|d| Box::new(d) as Box<dyn BlockDevice>),
                        );
                        disks.usb_inputs.extend(found.inputs);
                        disks
                            .links
                            .extend(found.links.into_iter().map(Adapter::Usb));
                        disks.usb_failures.extend(found.failures);
                        disks.usb_unused.extend(found.unused);
                    }
                    Err(error) => disks.failures.push((address, error)),
                }
                continue;
            } else if virtio_net::matches(&function) {
                match VirtioNet::new(&mut function, handoff, dma) {
                    Ok(device) => disks.links.push(Adapter::Virtio(device)),
                    Err(error) => disks.failures.push((address, error)),
                }
                continue;
            } else if input::matches(&function) {
                match input::VirtioInput::new(&mut function, handoff, dma) {
                    Ok(device) => disks.inputs.push(device),
                    Err(error) => disks.failures.push((address, error)),
                }
                continue;
            } else if function.class == ahci::CLASS {
                ahci::attach(&mut function, handoff, dma).map(|ports| {
                    ports
                        .into_iter()
                        .map(|device| Box::new(device) as Box<dyn BlockDevice>)
                        .collect()
                })
            } else {
                continue;
            };
            match result {
                Ok(devices) => disks.devices.extend(devices),
                Err(error) => disks.failures.push((address, error)),
            }
        }
    }
    disks
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StorageError {
    NoDisk(String),
    AmbiguousDisk(String, usize),
    Table(GptError),
    NoPartition(Guid),
    AmbiguousPartition(Guid),
    SystemPartition(Guid),
    Device(BlockError),
    Mismatch { offset: usize },
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoDisk(serial) => write!(f, "no disk has serial {serial:?}"),
            Self::AmbiguousDisk(serial, count) => {
                write!(f, "{count} disks have serial {serial:?}")
            }
            Self::Table(error) => error.fmt(f),
            Self::NoPartition(guid) => write!(f, "no partition {guid}"),
            Self::AmbiguousPartition(guid) => write!(f, "several partitions are {guid}"),
            Self::SystemPartition(guid) => {
                write!(f, "partition {guid} is an EFI system partition")
            }
            Self::Device(error) => error.fmt(f),
            Self::Mismatch { offset } => write!(f, "read back differs at byte {offset}"),
        }
    }
}

impl From<BlockError> for StorageError {
    fn from(error: BlockError) -> Self {
        Self::Device(error)
    }
}

/// The index of the one disk in `devices` whose serial is `serial`.
fn find(devices: &[Box<dyn BlockDevice>], serial: &str) -> Result<usize, StorageError> {
    let matching: Vec<usize> = devices
        .iter()
        .enumerate()
        .filter(|(_, device)| device.identity().serial == serial)
        .map(|(index, _)| index)
        .collect();
    match matching[..] {
        [index] => Ok(index),
        [] => Err(StorageError::NoDisk(String::from(serial))),
        _ => Err(StorageError::AmbiguousDisk(
            String::from(serial),
            matching.len(),
        )),
    }
}

/// Take the whole disk with `serial` out of `devices`, as the guest's USB
/// mass storage sees it: every block, its partition table included.
pub fn take(
    devices: &mut Vec<Box<dyn BlockDevice>>,
    serial: &str,
) -> Result<Box<dyn BlockDevice>, StorageError> {
    let index = find(devices, serial)?;
    Ok(devices.swap_remove(index))
}

/// Take the disk with `target`'s serial out of `devices` and confine it to
/// `target`'s partition.
pub fn open(
    devices: &mut Vec<Box<dyn BlockDevice>>,
    target: &Target,
) -> Result<PartitionDevice<Box<dyn BlockDevice>>, StorageError> {
    let index = find(devices, &target.serial)?;
    let table = gpt::read(&mut *devices[index]).map_err(StorageError::Table)?;
    let mut partitions = table
        .partitions
        .into_iter()
        .filter(|partition| partition.unique == target.partition);
    let partition = partitions
        .next()
        .ok_or(StorageError::NoPartition(target.partition))?;
    if partitions.next().is_some() {
        return Err(StorageError::AmbiguousPartition(target.partition));
    }
    if partition.kind == Guid::ESP {
        return Err(StorageError::SystemPartition(target.partition));
    }
    Ok(PartitionDevice::new(devices.swap_remove(index), partition))
}

/// The byte at `offset` of the storage check's pattern.
pub fn pattern(offset: u64) -> u8 {
    let mixed = offset.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ offset >> 7;
    (mixed >> 56) as u8
}

/// Write `bytes` of the pattern at the start of `device`, flush, read them
/// back, compare, and confirm the first block past the end is refused.
/// Returns the SHA-256 of what was read.
pub fn check(device: &mut dyn BlockDevice, bytes: usize) -> Result<String, StorageError> {
    let identity: Identity = device.identity().clone();
    let data: Vec<u8> = (0..bytes as u64).map(pattern).collect();
    device.write(0, &data)?;
    device.flush()?;
    let mut read = vec![0u8; bytes];
    device.read(0, &mut read)?;
    if let Some(offset) = read.iter().zip(&data).position(|(a, b)| a != b) {
        return Err(StorageError::Mismatch { offset });
    }
    let mut block = vec![0u8; identity.block_size as usize];
    match device.read(identity.blocks, &mut block) {
        Err(BlockError::OutOfRange { .. }) => {}
        Ok(()) => {
            return Err(StorageError::Device(BlockError::Unsupported(
                "a read past the partition succeeded",
            )));
        }
        Err(error) => return Err(error.into()),
    }
    Ok(crate::sha256(&read))
}

#[cfg(test)]
mod tests {
    use super::super::{block::tests::RamDisk, gpt::tests as table};
    use super::*;

    const TARGET: &str = "AAAAAAAA-0000-0000-0000-000000000002";

    fn disks() -> Vec<Box<dyn BlockDevice>> {
        let data: Guid = table::DATA.parse().unwrap();
        let layout = [
            table::partition(Guid::ESP, "AAAAAAAA-0000-0000-0000-000000000001", 34, 99),
            table::partition(data, TARGET, 100, 199),
        ];
        vec![
            Box::new(table::formatted("disk-a", &layout)),
            Box::new(table::formatted("disk-b", &layout)),
            Box::new(RamDisk::new("blank", 256, 512)),
        ]
    }

    fn target(text: &str) -> Target {
        text.parse().unwrap()
    }

    #[test]
    fn targets_name_a_serial_and_a_partition_guid() {
        let parsed = target("S4EV:NX0R-1:AAAAAAAA-0000-0000-0000-000000000002");
        assert_eq!(parsed.serial, "S4EV:NX0R-1");
        assert_eq!(parsed.partition, TARGET.parse().unwrap());
        assert!(
            "AAAAAAAA-0000-0000-0000-000000000002"
                .parse::<Target>()
                .is_err()
        );
        assert!(
            ":AAAAAAAA-0000-0000-0000-000000000002"
                .parse::<Target>()
                .is_err()
        );
        assert!("disk:not-a-guid".parse::<Target>().is_err());
    }

    #[test]
    fn selection_requires_one_disk_and_one_non_system_partition() {
        let mut devices = disks();
        let mut device = open(&mut devices, &target(&format!("disk-b:{TARGET}"))).unwrap();
        assert_eq!(devices.len(), 2);
        assert_eq!(device.disk().serial, "disk-b");
        assert_eq!(device.identity().blocks, 100);
        let hash = check(&mut device, 4096).unwrap();
        let expected: Vec<u8> = (0..4096).map(pattern).collect();
        assert_eq!(hash, crate::sha256(&expected));

        let mut devices = disks();
        assert_eq!(
            open(&mut devices, &target(&format!("disk-c:{TARGET}"))).err(),
            Some(StorageError::NoDisk(String::from("disk-c")))
        );
        let esp = "AAAAAAAA-0000-0000-0000-000000000001";
        assert_eq!(
            open(&mut devices, &target(&format!("disk-a:{esp}"))).err(),
            Some(StorageError::SystemPartition(esp.parse().unwrap()))
        );
        let other = "BBBBBBBB-0000-0000-0000-000000000000";
        assert_eq!(
            open(&mut devices, &target(&format!("disk-a:{other}"))).err(),
            Some(StorageError::NoPartition(other.parse().unwrap()))
        );
        assert_eq!(
            open(&mut devices, &target(&format!("blank:{TARGET}"))).err(),
            Some(StorageError::Table(GptError::NoTable))
        );
        devices.push(Box::new(RamDisk::new("disk-a", 8, 512)));
        assert_eq!(
            open(&mut devices, &target(&format!("disk-a:{TARGET}"))).err(),
            Some(StorageError::AmbiguousDisk(String::from("disk-a"), 2))
        );
        assert_eq!(devices.len(), 4);
    }

    #[test]
    fn whole_disks_are_taken_by_one_serial() {
        let mut devices = disks();
        let disk = take(&mut devices, "blank").unwrap();
        assert_eq!((disk.identity().blocks, devices.len()), (256, 2));
        assert!(matches!(
            take(&mut devices, "blank"),
            Err(StorageError::NoDisk(_))
        ));
        devices.push(Box::new(RamDisk::new("disk-a", 8, 512)));
        assert!(matches!(
            take(&mut devices, "disk-a"),
            Err(StorageError::AmbiguousDisk(_, 2))
        ));
    }

    #[test]
    fn the_pattern_is_not_trivially_periodic() {
        let first: Vec<u8> = (0..512).map(pattern).collect();
        let second: Vec<u8> = (512..1024).map(pattern).collect();
        assert_ne!(first, second);
        assert!(first.iter().any(|byte| *byte != first[0]));
    }
}
