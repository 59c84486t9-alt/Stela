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

/// PCI command followed by W1C status, with a log of bus transaction
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
    fn read32(&self, offset: u16) -> Result<u32, crate::bus::pci::ConfigError> {
        Ok(self.read(offset, 4))
    }

    fn read16(&self, offset: u16) -> Result<u16, crate::bus::pci::ConfigError> {
        Ok(self.read(offset, 2) as u16)
    }

    fn read8(&self, offset: u16) -> Result<u8, crate::bus::pci::ConfigError> {
        Ok(self.read(offset, 1) as u8)
    }

    fn write32(&mut self, offset: u16, value: u32) -> Result<(), crate::bus::pci::ConfigError> {
        self.write(offset, 4, value);
        Ok(())
    }

    fn write16(&mut self, offset: u16, value: u16) -> Result<(), crate::bus::pci::ConfigError> {
        self.write(offset, 2, u32::from(value));
        Ok(())
    }

    fn write8(&mut self, offset: u16, value: u8) -> Result<(), crate::bus::pci::ConfigError> {
        self.write(offset, 1, u32::from(value));
        Ok(())
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

unsafe extern "C" {
    fn os_mem_copy(destination: *mut c_void, source: *const c_void, bytes: u32) -> *mut c_void;
    fn os_mem_set(destination: *mut c_void, value: u8, bytes: u32) -> *mut c_void;
    fn os_mem_cmp(left: *const u8, right: *const u8, bytes: u32) -> i32;
    fn os_string_length(string: *const core::ffi::c_char) -> u32;
}

#[test]
fn original_memory_primitives_preserve_returns_bytes_and_untouched_spans() {
    let mut source = [0u8; 4096 + 32];
    for (index, byte) in source.iter_mut().enumerate() {
        *byte = (index.wrapping_mul(37) + 0x80) as u8;
    }
    for size in [
        0, 1, 2, 3, 7, 8, 15, 16, 31, 32, 127, 128, 129, 255, 256, 4096,
    ] {
        for source_offset in 0..16 {
            for destination_offset in 0..16 {
                let mut destination = [0xa5u8; 4096 + 32];
                // SAFETY: real nonoverlapping CPU arrays cover the complete
                // ranges; zero-byte calls also use valid array pointers.
                let pointer = unsafe { destination.as_mut_ptr().add(destination_offset) };
                // SAFETY: the pointer addresses this test's own live pages, and the stopped
                // model writes nothing concurrently.
                let input = unsafe { source.as_ptr().add(source_offset) };
                assert_eq!(
                    // SAFETY: the arguments are live locals sized for the call, and the test
                    // owns any state it touches.
                    unsafe { os_mem_copy(pointer.cast(), input.cast(), size as u32) },
                    pointer.cast()
                );
                for (index, &byte) in destination.iter().enumerate() {
                    let expected = if (destination_offset..destination_offset + size)
                        .contains(&index)
                    {
                        ((source_offset + index - destination_offset).wrapping_mul(37) + 0x80) as u8
                    } else {
                        0xa5
                    };
                    assert_eq!(
                        byte, expected,
                        "copy span: {size}/{source_offset}/{destination_offset}/{index}"
                    );
                }
                // SAFETY: the same full CPU ranges remain readable.
                assert_eq!(unsafe { os_mem_cmp(pointer, input, size as u32) }, 0);
            }
        }
        for offset in 0..16 {
            for value in [0, 0x80, 0xff] {
                let mut destination = [0xa5u8; 4096 + 32];
                // SAFETY: writable CPU array covers this complete span.
                let pointer = unsafe { destination.as_mut_ptr().add(offset) };
                assert_eq!(
                    // SAFETY: the arguments are live locals sized for the call, and the test
                    // owns any state it touches.
                    unsafe { os_mem_set(pointer.cast(), value, size as u32) },
                    pointer.cast()
                );
                for (index, &byte) in destination.iter().enumerate() {
                    assert_eq!(
                        byte,
                        if (offset..offset + size).contains(&index) {
                            value
                        } else {
                            0xa5
                        }
                    );
                }
            }
        }
    }
}

#[test]
fn original_compare_uses_unsigned_first_difference_and_exact_requested_length() {
    for size in [1, 2, 7, 8, 15, 16, 31, 32, 127, 128, 129, 256] {
        for mismatch in 0..size {
            for (left_byte, right_byte) in [(0, 0xff), (0x80, 0x7f), (0xff, 1)] {
                let mut left = [0x6du8; 288];
                let mut right = left;
                left[mismatch] = left_byte;
                right[mismatch] = right_byte;
                // Differences outside the requested span cannot affect results.
                left[size] = 0xff;
                right[size] = 0;
                let expected = (i32::from(left_byte) - i32::from(right_byte)).signum();
                assert_eq!(
                    // SAFETY: both arrays cover the exact requested CPU byte range.
                    unsafe { os_mem_cmp(left.as_ptr(), right.as_ptr(), size as u32) }.signum(),
                    expected
                );
                assert_eq!(
                    // SAFETY: the arguments are live locals sized for the call, and the test
                    // owns any state it touches.
                    unsafe { os_mem_cmp(right.as_ptr(), left.as_ptr(), size as u32) }.signum(),
                    -expected
                );
                assert_eq!(
                    // SAFETY: both slices are live locals at least `mismatch` bytes long.
                    unsafe { os_mem_cmp(left.as_ptr(), right.as_ptr(), mismatch as u32) },
                    0
                );
            }
        }
    }
}

#[test]
fn original_string_length_counts_bytes_until_first_nul() {
    let mut string = [0x80u8; 4096 + 32];
    for offset in 0..16 {
        for length in [0, 1, 2, 7, 8, 15, 16, 31, 32, 127, 128, 129, 4096] {
            string.fill(0x80);
            string[offset + length] = 0;
            // SAFETY: readable real CPU array, bounded terminated C string.
            let pointer = unsafe { string.as_ptr().add(offset) };
            // SAFETY: `pointer` addresses a NUL-terminated string inside the local array.
            assert_eq!(unsafe { os_string_length(pointer.cast()) }, length as u32);
        }
    }
}

unsafe extern "C" {
    fn nvkms_memcpy(destination: *mut c_void, source: *const c_void, bytes: usize) -> *mut c_void;
    fn nvkms_memmove(destination: *mut c_void, source: *const c_void, bytes: usize) -> *mut c_void;
    fn nvkms_memset(destination: *mut c_void, value: u8, bytes: usize) -> *mut c_void;
    fn nvkms_memcmp(left: *const c_void, right: *const c_void, bytes: usize) -> i32;
    fn nvkms_strlen(string: *const core::ffi::c_char) -> usize;
    fn nvlink_memcpy(destination: *mut c_void, source: *const c_void, bytes: u64) -> *mut c_void;
    fn nvlink_memset(destination: *mut c_void, value: i32, bytes: u64) -> *mut c_void;
    fn nvlink_strlen(string: *const core::ffi::c_char) -> u64;
    fn nvswitch_os_memcpy(
        destination: *mut c_void,
        source: *const c_void,
        bytes: u64,
    ) -> *mut c_void;
    fn nvswitch_os_memset(destination: *mut c_void, value: i32, bytes: u64) -> *mut c_void;
    fn nvswitch_os_strlen(string: *const core::ffi::c_char) -> u64;
}

#[test]
fn copy_helpers_match_native_results() {
    let mut source = [0u8; 4096 + 32];
    for (index, byte) in source.iter_mut().enumerate() {
        *byte = (index.wrapping_mul(53) + 0x81) as u8;
    }
    for size in [0, 1, 2, 7, 8, 15, 16, 31, 32, 127, 128, 129, 4096] {
        for source_offset in 0..8 {
            for destination_offset in 0..16 {
                for variant in 0..3 {
                    let mut destination = [0xa5u8; 4096 + 32];
                    // SAFETY: real nonoverlapping CPU arrays cover both spans.
                    let pointer = unsafe { destination.as_mut_ptr().add(destination_offset) };
                    // SAFETY: `source` is a local array long enough for every offset and size.
                    let input = unsafe { source.as_ptr().add(source_offset) };
                    // SAFETY: `pointer` and `input` cover `size` bytes of two local arrays.
                    let returned = unsafe {
                        match variant {
                            0 => nvkms_memcpy(pointer.cast(), input.cast(), size),
                            1 => nvlink_memcpy(pointer.cast(), input.cast(), size as u64),
                            _ => nvswitch_os_memcpy(pointer.cast(), input.cast(), size as u64),
                        }
                    };
                    assert_eq!(returned, pointer.cast());
                    for (index, &byte) in destination.iter().enumerate() {
                        let expected =
                            if (destination_offset..destination_offset + size).contains(&index) {
                                ((source_offset + index - destination_offset).wrapping_mul(53)
                                    + 0x81) as u8
                            } else {
                                0xa5
                            };
                        assert_eq!(byte, expected);
                    }
                }
            }
        }
        for offset in 0..16 {
            for value in [-1i32, 0, 0x80, 0x180, 0x1ff] {
                for variant in 0..3 {
                    let mut destination = [0xa5u8; 4096 + 32];
                    // SAFETY: CPU storage covers the complete span.
                    let pointer = unsafe { destination.as_mut_ptr().add(offset) };
                    // SAFETY: `pointer` covers `size` bytes of the local array.
                    let returned = unsafe {
                        match variant {
                            0 => nvkms_memset(pointer.cast(), value as u8, size),
                            1 => nvlink_memset(pointer.cast(), value, size as u64),
                            _ => nvswitch_os_memset(pointer.cast(), value, size as u64),
                        }
                    };
                    assert_eq!(returned, pointer.cast());
                    for (index, &byte) in destination.iter().enumerate() {
                        assert_eq!(
                            byte,
                            if (offset..offset + size).contains(&index) {
                                value as u8
                            } else {
                                0xa5
                            }
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn original_display_memmove_handles_both_overlap_directions_and_same_range() {
    for size in [0, 1, 2, 7, 8, 15, 16, 31, 127, 128, 129, 256, 4096] {
        for (source_offset, destination_offset) in [(0, 1), (1, 0), (7, 14), (14, 7), (8, 8)] {
            let mut bytes = [0u8; 4096 + 32];
            for (index, byte) in bytes.iter_mut().enumerate() {
                *byte = (index.wrapping_mul(19) + 0x83) as u8;
            }
            // SAFETY: one real CPU allocation covers both full possibly
            // overlapping ranges, which original memmove explicitly permits.
            let source = unsafe { bytes.as_ptr().add(source_offset) };
            // SAFETY: `bytes` is long enough for every offset and size.
            let destination = unsafe { bytes.as_mut_ptr().add(destination_offset) };
            assert_eq!(
                // SAFETY: both ranges lie inside the one local array; memmove permits overlap.
                unsafe { nvkms_memmove(destination.cast(), source.cast(), size) },
                destination.cast()
            );
            for (index, &byte) in bytes.iter().enumerate() {
                let original_index =
                    if (destination_offset..destination_offset + size).contains(&index) {
                        source_offset + index - destination_offset
                    } else {
                        index
                    };
                assert_eq!(byte, (original_index.wrapping_mul(19) + 0x83) as u8);
            }
        }
    }
}

#[test]
fn original_display_compare_and_native_length_returns_use_raw_unsigned_bytes() {
    for size in [1, 2, 7, 8, 15, 16, 31, 127, 128, 129, 256] {
        for mismatch in 0..size {
            let mut left = [0x55u8; 288];
            let mut right = left;
            left[mismatch] = 0x80;
            right[mismatch] = 0x7f;
            left[size] = 0;
            right[size] = 0xff;
            // SAFETY: readable CPU arrays cover the exact requested spans.
            unsafe {
                assert_eq!(
                    nvkms_memcmp(left.as_ptr().cast(), right.as_ptr().cast(), size).signum(),
                    1
                );
                assert_eq!(
                    nvkms_memcmp(right.as_ptr().cast(), left.as_ptr().cast(), size).signum(),
                    -1
                );
                assert_eq!(
                    nvkms_memcmp(left.as_ptr().cast(), right.as_ptr().cast(), mismatch),
                    0
                );
            }
        }
    }
    let mut string = [0x80u8; 4096 + 32];
    for offset in 0..16 {
        for length in [0, 1, 7, 8, 15, 16, 31, 127, 128, 129, 4096] {
            string.fill(0x80);
            string[offset + length] = 0;
            // SAFETY: readable CPU bytes include their terminating NUL.
            let pointer = unsafe { string.as_ptr().add(offset) };
            // SAFETY: `pointer` addresses a NUL-terminated string inside the local array.
            unsafe {
                assert_eq!(nvkms_strlen(pointer.cast()), length);
                assert_eq!(nvlink_strlen(pointer.cast()), length as u64);
                assert_eq!(nvswitch_os_strlen(pointer.cast()), length as u64);
            }
        }
    }
}

#[test]
fn nvlink_c_metadata_keeps_full_payload_and_zero_size_ownership() {
    unsafe extern "C" {
        fn nvlink_malloc(bytes: u64) -> *mut c_void;
        fn nvlink_free(pointer: *mut c_void);
    }
    let sizes = [0, 1, 7, 8, 15, 16, 17, 4095, 4096, 4097, 65537];
    let mut pointers = [ptr::null_mut::<c_void>(); 11];
    for (index, (&bytes, pointer)) in sizes.iter().zip(&mut pointers).enumerate() {
        // SAFETY: this hosted process has a live common heap and no reentry.
        *pointer = unsafe { nvlink_malloc(bytes) };
        assert!(!pointer.is_null());
        assert_eq!(*pointer as usize % 16, 0);
        // SAFETY: the checked allocation owns the complete requested payload.
        unsafe {
            pointer
                .cast::<u8>()
                .write_bytes(index as u8, bytes as usize)
        };
    }
    for (index, (&bytes, &pointer)) in sizes.iter().zip(&pointers).enumerate().rev() {
        assert!(!pointers[..index].contains(&pointer));
        // SAFETY: all allocations are still live and held only by this test.
        let payload = unsafe { core::slice::from_raw_parts(pointer.cast::<u8>(), bytes as usize) };
        assert!(payload.iter().all(|&byte| byte == index as u8));
        // SAFETY: free exactly this allocator's original live pointer once.
        unsafe { nvlink_free(pointer) };
    }
    // SAFETY: the original null-free contract is preserved by the common heap.
    unsafe { nvlink_free(ptr::null_mut()) };
}

#[test]
fn nvlink_c_invalid_native_layouts_return_null_before_allocating() {
    unsafe extern "C" {
        fn nvlink_malloc(bytes: u64) -> *mut c_void;
    }
    for bytes in [u64::MAX, isize::MAX as u64, isize::MAX as u64 - 16] {
        // SAFETY: a scalar request; checked layouts refuse this before the heap.
        assert!(unsafe { nvlink_malloc(bytes) }.is_null());
    }
}

#[test]
fn nvkms_c_metadata_zero_flags_and_native_sizes_use_the_real_common_heap() {
    unsafe extern "C" {
        fn nvkms_alloc(bytes: u64, zero: u8) -> *mut c_void;
        fn nvkms_free(pointer: *mut c_void, bytes: u64);
    }
    let cases = [(0, 255), (1, 1), (15, 2), (16, 255), (17, 0), (4097, 1)];
    let mut pointers = [ptr::null_mut::<c_void>(); 6];
    for (index, (&(bytes, zero), pointer)) in cases.iter().zip(&mut pointers).enumerate() {
        // SAFETY: ordinary hosted process context, live shared heap, no reentry.
        *pointer = unsafe { nvkms_alloc(bytes, zero) };
        assert!(!pointer.is_null());
        assert_eq!(*pointer as usize % 16, 0);
        if zero != 0 {
            // SAFETY: successful allocation initialized the full requested span.
            let payload =
                unsafe { core::slice::from_raw_parts(pointer.cast::<u8>(), bytes as usize) };
            assert!(payload.iter().all(|&byte| byte == 0));
        }
        // SAFETY: uniquely owned complete payload, initialized before reading.
        unsafe {
            pointer
                .cast::<u8>()
                .write_bytes(0x70 + index as u8, bytes as usize)
        };
    }
    for (index, (&(bytes, _), &pointer)) in cases.iter().zip(&pointers).enumerate().rev() {
        assert!(!pointers[..index].contains(&pointer));
        // SAFETY: all allocations are still live and exclusively held here.
        let payload = unsafe { core::slice::from_raw_parts(pointer.cast::<u8>(), bytes as usize) };
        assert!(payload.iter().all(|&byte| byte == 0x70 + index as u8));
        // SAFETY: original pointer and exact size, once, after all access stops.
        unsafe { nvkms_free(pointer, bytes) };
    }
    // SAFETY: original NULL-free contract is valid independently of the size.
    unsafe { nvkms_free(ptr::null_mut(), u64::MAX) };
}

#[test]
fn nvkms_c_invalid_layouts_fail_for_every_original_zero_flag_value() {
    unsafe extern "C" {
        fn nvkms_alloc(bytes: u64, zero: u8) -> *mut c_void;
    }
    for zero in [0, 1, 2, 255] {
        for bytes in [u64::MAX, isize::MAX as u64, isize::MAX as u64 - 16] {
            // SAFETY: invalid scalar layouts are rejected before heap access.
            assert!(unsafe { nvkms_alloc(bytes, zero) }.is_null());
        }
    }
}

// An explicit provider denial is distinct from a successful all-ones read.
// This models only Rust/C status/latch semantics, never physical hardware.
struct Denied<'a> {
    mode: &'a core::cell::Cell<u8>,
    calls: &'a core::cell::Cell<usize>,
}
impl Denied<'_> {
    fn read(&self) -> Result<u32, ConfigError> {
        self.calls.set(self.calls.get() + 1);
        if self.mode.get() == 0 {
            Ok(u32::MAX)
        } else {
            Err(ConfigError::before_effect(
                crate::bus::pci::ConfigFailure::ForeignGrant,
            ))
        }
    }
    fn write(&self, offset: u16, width: u8) -> Result<(), ConfigError> {
        self.calls.set(self.calls.get() + 1);
        Err(ConfigError::write_may_have_applied(
            offset,
            width,
            crate::bus::pci::ConfigFailure::ForeignGrant,
        ))
    }
}
impl ConfigSpace for Denied<'_> {
    fn read8(&self, _: u16) -> Result<u8, ConfigError> {
        self.read().map(|v| v as u8)
    }
    fn read16(&self, _: u16) -> Result<u16, ConfigError> {
        self.read().map(|v| v as u16)
    }
    fn read32(&self, _: u16) -> Result<u32, ConfigError> {
        self.read()
    }
    fn write8(&mut self, o: u16, _: u8) -> Result<(), ConfigError> {
        self.write(o, 1)
    }
    fn write16(&mut self, o: u16, _: u16) -> Result<(), ConfigError> {
        self.write(o, 2)
    }
    fn write32(&mut self, o: u16, _: u32) -> Result<(), ConfigError> {
        self.write(o, 4)
    }
}
#[test]
fn original_pci_prefix_preserves_typed_denial_and_closes_after_uncertain_write() {
    let mode = core::cell::Cell::new(0);
    let calls = core::cell::Cell::new(0);
    let mut config = Denied {
        mode: &mode,
        calls: &calls,
    };
    {
        let mut handle = pin!(PciHandle::new(&mut config));
        // SAFETY: pinned handle, exclusive serialized model, live output.
        let raw = unsafe { handle.as_mut().as_raw() };
        let mut value = 0;
        // SAFETY: serialized pinned CPU-only fixture; output/configuration is live and owned.
        assert_eq!(unsafe { os_pci_read_dword(raw, 0, &mut value) }, 0);
        assert_eq!(value, u32::MAX);
        assert_eq!(handle.failure(), None);
        mode.set(1);
        // SAFETY: serialized pinned CPU-only fixture; output/configuration is live and owned.
        assert_ne!(unsafe { os_pci_read_dword(raw, 0, &mut value) }, 0);
        let error = ConfigError::before_effect(crate::bus::pci::ConfigFailure::ForeignGrant);
        assert_eq!(handle.failure(), Some(error));
        mode.set(0);
        // SAFETY: serialized pinned CPU-only fixture; output/configuration is live and owned.
        assert_ne!(unsafe { os_pci_write_dword(raw, 4, 0) }, 0);
        assert_eq!(calls.get(), 2, "denial closes later bus access");
        assert_eq!(handle.failure(), Some(error));
    }
    let mut handle = pin!(PciHandle::new(&mut config));
    // SAFETY: same exact model/pinning contract, no physical writes.
    let raw = unsafe { handle.as_mut().as_raw() };
    // SAFETY: serialized pinned CPU-only fixture; output/configuration is live and owned.
    assert_ne!(unsafe { os_pci_write_word(raw, 4, 7) }, 0);
    let error =
        ConfigError::write_may_have_applied(4, 2, crate::bus::pci::ConfigFailure::ForeignGrant);
    assert_eq!(handle.failure(), Some(error));
    let before = calls.get();
    let mut value = 0;
    // SAFETY: serialized pinned CPU-only fixture; output/configuration is live and owned.
    assert_ne!(unsafe { os_pci_read_dword(raw, 0, &mut value) }, 0);
    assert_eq!(calls.get(), before);
    assert_eq!(handle.failure(), Some(error));
}
