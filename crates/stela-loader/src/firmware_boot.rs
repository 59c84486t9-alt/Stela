//! The PC firmware's own boot entries, which the startup menu lists beside
//! Stela's choices so the PC's other systems start from it as from the
//! firmware's boot menu (UEFI 2.10 §3.1.3 `Boot####` load options, §3.3
//! `BootOrder`). `stela.efi` starts one by naming it in `BootNext` and
//! restarting, so the firmware boots it exactly as it would itself.
use crate::Result;
use alloc::{format, string::String, vec::Vec};
use stela_contracts::refuse;

/// `LOAD_OPTION_ACTIVE`: the firmware boots the entry.
const ACTIVE: u32 = 0x1;
/// `LOAD_OPTION_HIDDEN`: the firmware leaves it out of its boot menu.
const HIDDEN: u32 = 0x8;
/// `LOAD_OPTION_CATEGORY`: zero for a boot entry, others are applications.
const CATEGORY: u32 = 0x1f00;
/// Device path node types (§10.3.1).
const MEDIA: u8 = 0x04;
const HARD_DRIVE: u8 = 0x01;
const END: u8 = 0x7f;
/// A hard drive node: header, partition number, start, size, signature,
/// partition format and signature type (§10.3.5.1).
const HARD_DRIVE_BYTES: usize = 42;
const GUID_SIGNATURE: u8 = 0x02;

/// One `Boot####` variable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadOption {
    pub attributes: u32,
    pub description: String,
    /// The file path list's first instance, without its end node.
    pub device_path: Vec<u8>,
}

impl LoadOption {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let attributes = u32::from_le_bytes(
            bytes
                .get(..4)
                .ok_or(refuse!("a boot entry is shorter than its header"))?
                .try_into()
                .unwrap(),
        );
        let list_bytes = u16::from_le_bytes(
            bytes
                .get(4..6)
                .ok_or(refuse!("a boot entry is shorter than its header"))?
                .try_into()
                .unwrap(),
        ) as usize;
        let mut units = Vec::new();
        let mut at = 6;
        loop {
            let unit = bytes
                .get(at..at + 2)
                .ok_or(refuse!("a boot entry's description is not terminated"))?;
            at += 2;
            match u16::from_le_bytes([unit[0], unit[1]]) {
                0 => break,
                unit => units.push(unit),
            }
        }
        let description = char::decode_utf16(units)
            .map(|c| match c {
                Ok(c) if !c.is_control() => c,
                _ => ' ',
            })
            .collect::<String>()
            .trim()
            .into();
        let list = bytes
            .get(at..at + list_bytes)
            .ok_or(refuse!("a boot entry's device path runs past it"))?;
        Ok(Self {
            attributes,
            description,
            device_path: first_instance(list)?.into(),
        })
    }

    /// Whether the firmware's boot menu offers it: an active boot entry
    /// that is not hidden.
    pub fn listed(&self) -> bool {
        self.attributes & ACTIVE != 0 && self.attributes & (HIDDEN | CATEGORY) == 0
    }

    /// Whether it starts from the device whose path is `own`: the same GPT
    /// partition, or a device `own` lies on, as the firmware's entry for a
    /// removable disk names the disk rather than its partition.
    pub fn starts_from(&self, own: &[u8]) -> bool {
        let own = first_instance(own).unwrap_or(own);
        match (partition(&self.device_path), partition(own)) {
            (Some(entry), Some(own)) => entry == own,
            (Some(_), None) => false,
            (None, _) => own.starts_with(&self.device_path),
        }
    }
}

/// `BootOrder`: the entries' numbers, first boot first.
pub fn order(bytes: &[u8]) -> Vec<u16> {
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&n| u16::from_le_bytes(n))
        .collect()
}

/// The variable that holds entry `number`.
pub fn variable(number: u16) -> String {
    format!("Boot{number:04X}")
}

/// A device path's first instance up to its end node; refuses a node
/// shorter than its header or running past the path.
fn first_instance(path: &[u8]) -> Result<&[u8]> {
    let mut at = 0;
    while let Some(header) = path.get(at..at + 4) {
        if header[0] == END {
            return Ok(&path[..at]);
        }
        let length = u16::from_le_bytes([header[2], header[3]]) as usize;
        if length < 4 || at + length > path.len() {
            return Err(refuse!("a boot entry's device path has a malformed node").into());
        }
        at += length;
    }
    Err(refuse!("a boot entry's device path has no end node").into())
}

/// The GPT partition GUID a path's hard drive node names.
fn partition(path: &[u8]) -> Option<[u8; 16]> {
    let mut at = 0;
    while let Some(header) = path.get(at..at + 4) {
        let length = u16::from_le_bytes([header[2], header[3]]) as usize;
        let node = path.get(at..at + length.max(4))?;
        if header[0] == MEDIA && header[1] == HARD_DRIVE && length == HARD_DRIVE_BYTES {
            return (node[41] == GUID_SIGNATURE).then(|| node[24..40].try_into().unwrap());
        }
        at += length.max(4);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn node(kind: u8, subtype: u8, body: &[u8]) -> Vec<u8> {
        let mut node = vec![kind, subtype];
        node.extend(((body.len() + 4) as u16).to_le_bytes());
        node.extend(body);
        node
    }

    fn end() -> Vec<u8> {
        node(END, 0xff, &[])
    }

    /// `PciRoot(0)/Pci(...)/USB(...)`, a disk.
    fn usb() -> Vec<u8> {
        [
            node(2, 1, &[0; 8]),
            node(1, 1, &[0, 0x14]),
            node(3, 5, &[3, 0]),
        ]
        .concat()
    }

    fn hard_drive(guid: u8) -> Vec<u8> {
        let mut body = vec![1, 0, 0, 0];
        body.extend([0; 16]);
        body.extend([guid; 16]);
        body.extend([2, GUID_SIGNATURE]);
        node(MEDIA, HARD_DRIVE, &body)
    }

    fn file(path: &str) -> Vec<u8> {
        let body: Vec<u8> = path
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect();
        node(MEDIA, 4, &body)
    }

    fn entry(attributes: u32, description: &str, path: &[u8]) -> Vec<u8> {
        let mut bytes = attributes.to_le_bytes().to_vec();
        bytes.extend((path.len() as u16).to_le_bytes());
        bytes.extend(
            description
                .encode_utf16()
                .chain([0])
                .flat_map(u16::to_le_bytes),
        );
        bytes.extend(path);
        // Optional data the entry's loader reads.
        bytes.extend(b"WINDOWS");
        bytes
    }

    #[test]
    fn an_entry_reads_with_its_description_and_first_path() {
        // A short-form path, as Windows Boot Manager's entry holds.
        let path = [
            hard_drive(7),
            file("\\EFI\\Microsoft\\Boot\\bootmgfw.efi"),
            end(),
        ]
        .concat();
        let option = LoadOption::parse(&entry(ACTIVE, "Windows Boot Manager", &path)).unwrap();
        assert_eq!(option.description, "Windows Boot Manager");
        assert_eq!(option.device_path, path[..path.len() - 4]);
        assert!(option.listed());
        assert_eq!(order(&[1, 0, 0x10, 0]), [1, 0x10]);
        assert_eq!(variable(0x1a), "Boot001A");
    }

    #[test]
    fn hidden_inactive_and_application_entries_are_not_listed() {
        let path = [file("\\shell.efi"), end()].concat();
        for attributes in [0, ACTIVE | HIDDEN, ACTIVE | 0x100] {
            assert!(
                !LoadOption::parse(&entry(attributes, "x", &path))
                    .unwrap()
                    .listed()
            );
        }
    }

    #[test]
    fn entries_on_stelas_own_disk_are_recognized() {
        let own = [
            usb(),
            hard_drive(1),
            file("\\EFI\\BOOT\\BOOTX64.EFI"),
            end(),
        ]
        .concat();
        let parse = |path: Vec<u8>| LoadOption::parse(&entry(ACTIVE, "x", &path)).unwrap();
        // The same partition, by a short-form path.
        assert!(parse([hard_drive(1), file("\\x.efi"), end()].concat()).starts_from(&own));
        // The firmware's entry for the removable disk itself.
        assert!(parse([usb(), end()].concat()).starts_from(&own));
        // Another disk's partition, and another device.
        assert!(!parse([hard_drive(2), file("\\x.efi"), end()].concat()).starts_from(&own));
        let other = [node(2, 1, &[0; 8]), node(1, 1, &[0, 0x1d]), end()].concat();
        assert!(!parse(other).starts_from(&own));
    }

    #[test]
    fn malformed_entries_are_refused() {
        assert!(LoadOption::parse(&[1, 0, 0]).is_err());
        let unterminated = [1, 0, 0, 0, 4, 0, b'x', 0];
        assert!(LoadOption::parse(&unterminated).is_err());
        let mut short_node = entry(ACTIVE, "x", &[4, 1, 2, 0]);
        short_node.truncate(short_node.len() - 7);
        assert!(LoadOption::parse(&short_node).is_err());
        assert!(LoadOption::parse(&entry(ACTIVE, "x", &[4, 4, 4, 0])).is_err());
    }
}
