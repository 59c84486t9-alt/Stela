use super::*;
use alloc::vec::Vec;
use core::{cell::RefCell, pin::pin, ptr};

unsafe extern "C" {
    fn os_pci_read_byte(handle: *mut c_void, offset: u32, value: *mut u8) -> u32;
    fn os_pci_read_word(handle: *mut c_void, offset: u32, value: *mut u16) -> u32;
    fn os_pci_read_dword(handle: *mut c_void, offset: u32, value: *mut u32) -> u32;
    fn os_pci_write_byte(handle: *mut c_void, offset: u32, value: u8) -> u32;
    fn os_pci_write_word(handle: *mut c_void, offset: u32, value: u16) -> u32;
    fn os_pci_write_dword(handle: *mut c_void, offset: u32, value: u32) -> u32;
}

/// PCI command followed by W1C status, with a log of actual bus transaction
/// widths. An ordinary RAM fake cannot detect an accidental dword RMW here.
struct Config {
    bytes: [u8; PCI_CONFIG_BYTES as usize],
    accesses: RefCell<Vec<(bool, u16, usize)>>,
}

impl Config {
    fn new() -> Self {
        let mut bytes = [0xa5; PCI_CONFIG_BYTES as usize];
        // Command=IO enable; status=capability list plus the six W1C errors
        // (bits 15, 14, 13, 12, 11 and 8). Other status bits are read-only.
        bytes[4..8].copy_from_slice(&[0x01, 0x00, 0x10, 0xf9]);
        Self {
            bytes,
            accesses: RefCell::new(Vec::new()),
        }
    }

    fn read(&self, offset: u16, width: usize) -> u32 {
        self.accesses.borrow_mut().push((false, offset, width));
        let mut value = [0; 4];
        value[..width].copy_from_slice(&self.bytes[usize::from(offset)..][..width]);
        u32::from_le_bytes(value)
    }

    fn write(&mut self, offset: u16, width: usize, value: u32) {
        self.accesses.borrow_mut().push((true, offset, width));
        for (index, byte) in value.to_le_bytes().into_iter().take(width).enumerate() {
            let address = usize::from(offset) + index;
            if address == 6 {
                // The low status byte has no W1C bits.
            } else if address == 7 {
                self.bytes[address] &= !(byte & 0xf9);
            } else {
                self.bytes[address] = byte;
            }
        }
    }
}

impl ConfigSpace for Config {
    fn read32(&self, offset: u16) -> u32 {
        self.read(offset, 4)
    }

    fn read16(&self, offset: u16) -> u16 {
        self.read(offset, 2) as u16
    }

    fn read8(&self, offset: u16) -> u8 {
        self.read(offset, 1) as u8
    }

    fn write32(&mut self, offset: u16, value: u32) {
        self.write(offset, 4, value);
    }

    fn write16(&mut self, offset: u16, value: u16) {
        self.write(offset, 2, u32::from(value));
    }

    fn write8(&mut self, offset: u16, value: u8) {
        self.write(offset, 1, u32::from(value));
    }
}

#[test]
fn vendor_c_hooks_preserve_bus_width_and_adjacent_status() {
    let mut config = Config::new();
    {
        let mut handle = pin!(PciHandle::new(&mut config));
        let (mut byte, mut word, mut dword) = (0, 0, 0);
        // SAFETY: handle stays pinned and exclusively borrowed for these
        // synchronous C calls; outputs are live and no callback reenters.
        unsafe {
            let raw = handle.as_mut().as_raw();
            assert_eq!(os_pci_write_word(raw, 4, 0x0406), 0);
            assert_eq!(os_pci_read_word(raw, 6, &mut word), 0);
            assert_eq!(word, 0xf910, "command write must not clear status");
            assert_eq!(os_pci_write_byte(raw, 7, 0x09), 0);
            assert_eq!(os_pci_read_byte(raw, 7, &mut byte), 0);
            assert_eq!(byte, 0xf0, "status byte clears only selected bits");
            assert_eq!(os_pci_read_word(raw, 4, &mut word), 0);
            assert_eq!(word, 0x0406, "status write must not alter command");
            assert_eq!(os_pci_write_dword(raw, 4092, 0x1234_5678), 0);
            assert_eq!(os_pci_read_dword(raw, 4092, &mut dword), 0);
            assert_eq!(dword, 0x1234_5678);
        }
    }
    assert_eq!(config.bytes[6], 0x10, "capability-list bit is read-only");
    assert_eq!(
        *config.accesses.borrow(),
        [
            (true, 4, 2),
            (false, 6, 2),
            (true, 7, 1),
            (false, 7, 1),
            (false, 4, 2),
            (true, 4092, 4),
            (false, 4092, 4),
        ]
    );
}

#[test]
fn invalid_vendor_accesses_fail_without_a_bus_transaction() {
    let mut config = Config::new();
    {
        let mut handle = pin!(PciHandle::new(&mut config));
        // SAFETY: same pinned/exclusive synchronous contract as above. Null
        // arguments are explicitly accepted as errors by the C entry points.
        unsafe {
            let raw = handle.as_mut().as_raw();
            for offset in [4096, 4097, 65536, u32::MAX] {
                let (mut byte, mut word, mut dword) = (0, 0, 0);
                assert_ne!(os_pci_read_byte(raw, offset, &mut byte), 0);
                assert_ne!(os_pci_read_word(raw, offset, &mut word), 0);
                assert_ne!(os_pci_read_dword(raw, offset, &mut dword), 0);
                assert_eq!((byte, word, dword), (u8::MAX, u16::MAX, u32::MAX));
                assert_ne!(os_pci_write_byte(raw, offset, 0), 0);
                assert_ne!(os_pci_write_word(raw, offset, 0), 0);
                assert_ne!(os_pci_write_dword(raw, offset, 0), 0);
            }
            for offset in [1, 3, 4093, 4095] {
                let mut word = 0;
                assert_ne!(os_pci_read_word(raw, offset, &mut word), 0);
                assert_eq!(word, u16::MAX);
                assert_ne!(os_pci_write_word(raw, offset, 0), 0);
            }
            for offset in [1, 2, 3, 4093, 4094, 4095] {
                let mut dword = 0;
                assert_ne!(os_pci_read_dword(raw, offset, &mut dword), 0);
                assert_eq!(dword, u32::MAX);
                assert_ne!(os_pci_write_dword(raw, offset, 0), 0);
            }
            let (mut byte, mut word, mut dword) = (0, 0, 0);
            assert_ne!(os_pci_read_byte(ptr::null_mut(), 0, &mut byte), 0);
            assert_ne!(os_pci_read_word(ptr::null_mut(), 0, &mut word), 0);
            assert_ne!(os_pci_read_dword(ptr::null_mut(), 0, &mut dword), 0);
            assert_eq!((byte, word, dword), (u8::MAX, u16::MAX, u32::MAX));
            assert_ne!(os_pci_write_byte(ptr::null_mut(), 0, 0), 0);
            assert_ne!(os_pci_write_word(ptr::null_mut(), 0, 0), 0);
            assert_ne!(os_pci_write_dword(ptr::null_mut(), 0, 0), 0);
            assert_ne!(os_pci_read_byte(raw, 0, ptr::null_mut()), 0);
            assert_ne!(os_pci_read_word(raw, 0, ptr::null_mut()), 0);
            assert_ne!(os_pci_read_dword(raw, 0, ptr::null_mut()), 0);
        }
    }
    assert!(config.accesses.borrow().is_empty());
    assert_eq!(config.bytes, Config::new().bytes);
}

#[test]
fn the_end_of_config_space_accepts_each_natural_width() {
    let mut config = Config::new();
    {
        let mut handle = pin!(PciHandle::new(&mut config));
        // SAFETY: pinned/exclusive synchronous calls with live outputs.
        unsafe {
            let raw = handle.as_mut().as_raw();
            let (mut byte, mut word, mut dword) = (0, 0, 0);
            assert_eq!(os_pci_write_dword(raw, 4092, 0x1234_5678), 0);
            assert_eq!(os_pci_write_word(raw, 4094, 0xabcd), 0);
            assert_eq!(os_pci_write_byte(raw, 4095, 0xef), 0);
            assert_eq!(os_pci_read_byte(raw, 4095, &mut byte), 0);
            assert_eq!(os_pci_read_word(raw, 4094, &mut word), 0);
            assert_eq!(os_pci_read_dword(raw, 4092, &mut dword), 0);
            assert_eq!((byte, word, dword), (0xef, 0xefcd, 0xefcd_5678));
        }
    }
    assert_eq!(config.accesses.borrow().len(), 6);
}
