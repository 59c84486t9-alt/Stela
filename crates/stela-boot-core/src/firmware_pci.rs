//! UEFI PCI_IO resource observations. Decoding yields DATA, never native
//! mapping, configuration, reset or controller permission.
//! UEFI2.11 tables14.10/14.11 use this QWORD layout and HOST-to-PCI offset.
//! EDK2 reference: tianocore/edk2@4dfdca63a93497203f197ec98ba20e2327e4afe4,
//! MdeModulePkg/Bus/Pci/PciBusDxe/PciIo.c::PciIoGetBarAttributes. Range
//! observation is checked Start+Length; raw maximum is held separately.
use core::ops::Range;
pub const QWORD_BYTES: usize = 46;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DescriptorError {
    Length,
    Tag,
    ResourceType,
    Flags,
    Granularity,
    Range,
    Translation,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BarRegion {
    pub resource_type: u8,
    pub general_flags: u8,
    pub specific_flags: u8,
    pub granularity: u64,
    /// Raw maximum observation. UEFI table14.10 calls this the ending
    /// address; EDK2 PciIoGetBarAttributes exports BAR.Alignment here instead.
    /// Preserve it without turning either interpretation into native permission.
    pub observed_maximum: u64,
    pub host: Range<u64>,
    pub translation: u64,
    pub pci: Range<u64>,
}
fn qword(bytes: &[u8; QWORD_BYTES], offset: usize) -> u64 {
    let mut value = [0; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(value)
}
pub fn decode_qword(bytes: &[u8; QWORD_BYTES]) -> Result<BarRegion, DescriptorError> {
    if bytes[0] != 0x8a {
        return Err(DescriptorError::Tag);
    }
    if u16::from_le_bytes([bytes[1], bytes[2]]) != 43 {
        return Err(DescriptorError::Length);
    }
    if bytes[3] > 2 {
        return Err(DescriptorError::ResourceType);
    }
    if bytes[4] & !15 != 0 {
        return Err(DescriptorError::Flags);
    }
    let granularity = qword(bytes, 6);
    if bytes[3] == 0 && !matches!(granularity, 32 | 64) {
        return Err(DescriptorError::Granularity);
    }
    let start = qword(bytes, 14);
    let maximum = qword(bytes, 22);
    let translation = qword(bytes, 30);
    let length = qword(bytes, 38);
    let end = start
        .checked_add(length)
        .filter(|end| *end > start)
        .ok_or(DescriptorError::Range)?;
    let pci_start = start
        .checked_add(translation)
        .ok_or(DescriptorError::Translation)?;
    let pci_end = pci_start
        .checked_add(length)
        .ok_or(DescriptorError::Translation)?;
    if bytes[3] == 0 && granularity == 32 && pci_end > 1u64 << 32 {
        return Err(DescriptorError::Range);
    }
    Ok(BarRegion {
        resource_type: bytes[3],
        general_flags: bytes[4],
        specific_flags: bytes[5],
        granularity,
        observed_maximum: maximum,
        host: start..end,
        translation,
        pci: pci_start..pci_end,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    fn descriptor(start: u64, length: u64, translation: u64) -> [u8; QWORD_BYTES] {
        let mut value = [0; QWORD_BYTES];
        value[..3].copy_from_slice(&[0x8a, 43, 0]);
        value[6..14].copy_from_slice(&64u64.to_le_bytes());
        value[14..22].copy_from_slice(&start.to_le_bytes());
        value[22..30].copy_from_slice(&(start + length - 1).to_le_bytes());
        value[30..38].copy_from_slice(&translation.to_le_bytes());
        value[38..46].copy_from_slice(&length.to_le_bytes());
        value
    }
    #[test]
    fn host_to_pci_translation_and_full_width_are_preserved() {
        let value = descriptor(1u64 << 32, 4096, 1u64 << 32);
        let decoded = decode_qword(&value).unwrap();
        assert_eq!(decoded.host, (1u64 << 32)..(1u64 << 32) + 4096);
        assert_eq!(decoded.pci, (2u64 << 32)..(2u64 << 32) + 4096);
        assert_eq!(decoded.translation, 1u64 << 32);
    }
    #[test]
    fn incompatible_width_overflow_and_incomplete_ranges_refuse() {
        let original = descriptor(1u64 << 32, 4096, 0);
        let mut value = original;
        value[6..14].copy_from_slice(&32u64.to_le_bytes());
        assert_eq!(decode_qword(&value), Err(DescriptorError::Range));
        value = original;
        value[30..38].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(decode_qword(&value), Err(DescriptorError::Translation));
        value = original;
        value[38..46].fill(0);
        assert_eq!(decode_qword(&value), Err(DescriptorError::Range));
        value = original;
        value[14..22].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(decode_qword(&value), Err(DescriptorError::Range));
    }
    #[test]
    fn raw_maximum_is_preserved_for_both_documented_endpoint_and_edk2_alignment() {
        let mut value = descriptor(1u64 << 32, 4096, 0);
        let ending = decode_qword(&value).unwrap();
        assert_eq!(ending.observed_maximum, ending.host.end - 1);
        value[22..30].copy_from_slice(&4095u64.to_le_bytes());
        let alignment = decode_qword(&value).unwrap();
        assert_eq!(alignment.observed_maximum, 4095);
        assert_eq!(alignment.host, ending.host);
        assert_eq!(alignment.pci, ending.pci);
    }

    #[test]
    fn descriptor_kind_lengths_and_memory_granularity_are_checked() {
        let original = descriptor(4096, 4096, 0);
        for (offset, byte, error) in [
            (0, 0x87, DescriptorError::Tag),
            (1, 42, DescriptorError::Length),
            (3, 3, DescriptorError::ResourceType),
            (4, 0x80, DescriptorError::Flags),
            (6, 0, DescriptorError::Granularity),
        ] {
            let mut value = original;
            value[offset] = byte;
            assert_eq!(decode_qword(&value), Err(error));
        }
        let mut io = original;
        io[3] = 1;
        io[6] = 0;
        assert_eq!(decode_qword(&io).unwrap().granularity, 0);
    }
}
