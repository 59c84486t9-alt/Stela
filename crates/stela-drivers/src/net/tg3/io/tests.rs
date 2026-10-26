// SPDX-License-Identifier: GPL-2.0-only
//! Actual host volatile windows and original owner Drop boundaries. These are
//! isolated RAM/config models and never confer native PCI or DMA authority.
extern crate std;
use super::*;
use crate::bus::pci::Address;
use alloc::{boxed::Box, vec::Vec};
use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicUsize, Ordering},
};
use std::sync::Mutex;

#[derive(Default)]
struct Counts {
    config_drops: AtomicUsize,
    mapping_drops: AtomicUsize,
    reads: AtomicUsize,
    writes: Mutex<Vec<(u16, u8, u32)>>,
}
struct Config {
    counts: Arc<Counts>,
    original: u64,
}
impl ConfigSpace for Config {
    fn read32(&self, at: u16) -> u32 {
        self.counts.reads.fetch_add(1, Ordering::Relaxed);
        match at {
            0 => 0x165f_14e4,
            8 => 0x0200_0000,
            _ => 0,
        }
    }
    fn write32(&mut self, at: u16, value: u32) {
        self.counts.writes.lock().unwrap().push((at, 32, value));
    }
    fn write16(&mut self, at: u16, value: u16) {
        self.counts
            .writes
            .lock()
            .unwrap()
            .push((at, 16, u32::from(value)));
    }
}
impl Drop for Config {
    fn drop(&mut self) {
        self.counts.config_drops.fetch_add(1, Ordering::Relaxed);
    }
}
struct Windows {
    mac: Box<[UnsafeCell<u32>]>,
    ape: Box<[UnsafeCell<u32>]>,
    counts: Arc<Counts>,
}
impl Drop for Windows {
    fn drop(&mut self) {
        self.counts.mapping_drops.fetch_add(1, Ordering::Relaxed);
    }
}
fn windows(counts: Arc<Counts>) -> Arc<Mutex<Windows>> {
    Arc::new(Mutex::new(Windows {
        mac: (0..0x8000 / 4)
            .map(|_| UnsafeCell::new(0))
            .collect::<Vec<_>>()
            .into_boxed_slice(),
        ape: (0..0x8440 / 4)
            .map(|_| UnsafeCell::new(0))
            .collect::<Vec<_>>()
            .into_boxed_slice(),
        counts,
    }))
}
fn function(counts: Arc<Counts>) -> Function<Config> {
    Function::new(
        Address {
            segment: 0,
            bus: 2,
            device: 3,
            function: 0,
        },
        Config {
            counts,
            original: 0x5a1e_75cd,
        },
    )
    .unwrap()
}
fn pointers(owner: &Windows) -> (NonNull<u8>, NonNull<u8>) {
    (
        NonNull::new(owner.mac.as_ptr().cast_mut().cast()).unwrap(),
        NonNull::new(owner.ape.as_ptr().cast_mut().cast()).unwrap(),
    )
}

#[test]
fn invalid_first_or_second_window_returns_both_exact_original_owners_without_effects() {
    for fault in 0..6 {
        let counts = Arc::new(Counts::default());
        let original = function(counts.clone());
        let owner = windows(counts.clone());
        let weak = Arc::downgrade(&owner);
        let (mut mac, mut ape) = pointers(&owner.lock().unwrap());
        let (mut mac_bytes, mut ape_bytes) = (0x8000, 0x8440);
        match fault {
            0 => mac = NonNull::new(mac.as_ptr().wrapping_add(1)).unwrap(),
            1 => mac_bytes -= 1,
            2 => mac_bytes = usize::MAX,
            3 => ape = NonNull::new(ape.as_ptr().wrapping_add(1)).unwrap(),
            4 => ape_bytes -= 1,
            _ => ape_bytes = usize::MAX,
        }
        let before_reads = counts.reads.load(Ordering::Relaxed);
        // SAFETY: isolated retained host RAM; invalid geometry must be refused
        // before any access. This is not an actual native resource producer.
        let (mut original, retained) = match unsafe {
            Mmio::from_owned_windows(original, mac, mac_bytes, ape, ape_bytes, owner)
        } {
            Err((Error::Bounds, original, owner)) => (original, owner),
            _ => panic!("invalid geometry accepted"),
        };
        assert_eq!(original.config().original, 0x5a1e_75cd);
        assert_eq!(original.address.bus, 2);
        assert_eq!(original.address.device, 3);
        assert_eq!(counts.config_drops.load(Ordering::Relaxed), 0);
        assert_eq!(counts.mapping_drops.load(Ordering::Relaxed), 0);
        assert_eq!(counts.reads.load(Ordering::Relaxed), before_reads);
        assert!(counts.writes.lock().unwrap().is_empty());
        assert_eq!(weak.strong_count(), 1);
        let actual = retained
            .downcast_ref::<Mutex<Windows>>()
            .unwrap()
            .lock()
            .unwrap();
        for cell in actual.mac.iter().chain(actual.ape.iter()) {
            assert_eq!(unsafe { cell.get().read_volatile() }, 0);
        }
        drop(actual);
        // The actual caller still owns cleanup. This isolated fixture has no
        // live requester/IRQs and can explicitly drop its returned originals.
        drop(original);
        assert_eq!(counts.config_drops.load(Ordering::Relaxed), 1);
        assert_eq!(counts.mapping_drops.load(Ordering::Relaxed), 0);
        drop(retained);
        assert_eq!(counts.mapping_drops.load(Ordering::Relaxed), 1);
        assert!(weak.upgrade().is_none());
    }
}

#[test]
fn failed_window_can_retry_with_same_originals_and_actual_bounded_volatile_accesses() {
    let counts = Arc::new(Counts::default());
    let original = function(counts.clone());
    let owner = windows(counts.clone());
    let (mac, ape) = pointers(&owner.lock().unwrap());
    // SAFETY: isolated retained host RAM with an intentionally short second
    // window; no native authority or live requester exists in this model.
    let (original, owner) =
        match unsafe { Mmio::from_owned_windows(original, mac, 0x8000, ape, 0x843f, owner) } {
            Err((Error::Bounds, original, owner)) => (original, owner),
            _ => panic!("short APE accepted"),
        };
    // SAFETY: the same original model allocation/configuration, now with exact
    // complete bounds. Every volatile access is serialized on this thread.
    let mut registers =
        match unsafe { Mmio::from_owned_windows(original, mac, 0x8000, ape, 0x8440, owner) } {
            Ok(registers) => registers,
            Err(_) => panic!("original retry refused"),
        };
    for (at, value) in [(0, 0x1234_5678), (0x7ffc, 0x89ab_cdef)] {
        registers.write32(at, value).unwrap();
        assert_eq!(registers.read32(at), Ok(value));
    }
    for (at, value) in [(0x2c, 0x1000), (0x843c, 0xfedc_ba98)] {
        registers.ape_write32(at, value).unwrap();
        assert_eq!(registers.ape_read32(at), Ok(value));
    }
    for at in [1, 0x8000, u32::MAX] {
        assert_eq!(registers.write32(at, 0xaa), Err(Error::Bounds));
    }
    for at in [3, 0x8440, u32::MAX] {
        assert_eq!(registers.ape_write32(at, 0xbb), Err(Error::Bounds));
    }
    registers.config_write16(4, 0x400).unwrap();
    registers.config_write32(0x70, 0x70000).unwrap();
    assert_eq!(
        *counts.writes.lock().unwrap(),
        [(4, 16, 0x400), (0x70, 32, 0x70000)]
    );
    assert_eq!(counts.config_drops.load(Ordering::Relaxed), 0);
    assert_eq!(counts.mapping_drops.load(Ordering::Relaxed), 0);
    // This fixture has only explicit CPU accesses and no device/IRQ lifetime.
    drop(registers);
    assert_eq!(counts.config_drops.load(Ordering::Relaxed), 1);
    assert_eq!(counts.mapping_drops.load(Ordering::Relaxed), 1);
}
