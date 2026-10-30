//! Root enumeration and Bulk-Only binding over the native-layout peer.
use super::*;
use crate::{Clock, bus::dma::RegionAllocator, usb::ehci::host::enumerate};
use alloc::{rc::Rc, string::String};
use core::cell::RefCell;

/// What enumerating the peer's root left unused, and how many failures.
fn enumerated(m: &Arc<Mutex<Shared>>) -> (Vec<(String, &'static str)>, usize) {
    // Room for a 64 KiB-aligned transport buffer wherever the heap puts this.
    let mut backing = vec![0u64; 32_768];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: the backing outlives every buffer, which only the CPU touches.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let controller = Rc::new(RefCell::new(controller(m.clone())));
    let clock = Clock {
        ticks_per_microsecond: 1_000,
    };
    let found = enumerate(&controller, "ehci", clock, &mut dma);
    assert!(found.disks.is_empty());
    (found.unused, found.failures.len())
}

#[test]
fn a_bulk_only_root_is_addressed_configured_and_sent_its_first_command_block() {
    let _time = crate::test_clock::virtualize();
    let m = Arc::new(Mutex::new(Shared::new()));
    let (unused, _) = enumerated(&m);
    let m = m.lock().unwrap();
    assert_eq!(m.addresses[0], Some(1), "the lowest free address");
    assert_eq!(m.configurations[0], 1);
    // The peer answers bulk IN with a pattern, so the INQUIRY's CSW is
    // malformed; its CBW still went out on the OUT pipe.
    assert_eq!(m.received.get(..4), Some(&b"USBC"[..]));
    assert!(unused.is_empty());
}

#[test]
fn a_full_speed_root_is_left_to_the_companion() {
    let _time = crate::test_clock::virtualize();
    let m = Arc::new(Mutex::new(Shared::new()));
    m.lock().unwrap().high_speed = false;
    let (unused, failures) = enumerated(&m);
    assert_eq!(unused.len(), 1);
    assert_eq!(unused[0].0, "ehci port 1");
    assert!(unused[0].1.contains("companion"));
    assert_eq!(failures, 0);
}

#[test]
fn a_root_without_bulk_only_storage_is_addressed_and_left_unconfigured() {
    let _time = crate::test_clock::virtualize();
    let m = Arc::new(Mutex::new(Shared::new()));
    m.lock().unwrap().description[14] = 0xff;
    let (unused, failures) = enumerated(&m);
    let m = m.lock().unwrap();
    assert_eq!(m.addresses[0], Some(1));
    assert_eq!(m.configurations[0], 0);
    assert_eq!(unused.len(), 1);
    assert!(unused[0].1.contains("Bulk-Only"));
    assert_eq!(failures, 0);
}
