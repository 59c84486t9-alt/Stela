extern crate std;

use super::*;
use alloc::rc::Rc;
use core::cell::RefCell;
use std::collections::BTreeMap;

const ROOT: (u8, u8, u8) = (0, 0x1c, 0);
const EXPRESS_AT: u16 = 0x40;

#[derive(Default)]
struct Registers {
    words: BTreeMap<u16, u32>,
    /// Each BAR's size mask; the rest of its word is read-only.
    masks: BTreeMap<u16, u32>,
}

type Location = (u8, u8, u8);

/// Functions by location, as a bus shows them.
#[derive(Clone, Default)]
struct Bus(Rc<RefCell<BTreeMap<Location, Registers>>>);

struct Function(Bus, (u8, u8, u8));

impl ConfigSpace for Function {
    fn read32(&self, offset: u16) -> u32 {
        let functions = self.0.0.borrow();
        let Some(registers) = functions.get(&self.1) else {
            return u32::MAX;
        };
        registers.words.get(&offset).copied().unwrap_or(0)
    }
    fn write32(&mut self, offset: u16, value: u32) {
        let mut functions = self.0.0.borrow_mut();
        let Some(registers) = functions.get_mut(&self.1) else {
            return;
        };
        let word = match registers.masks.get(&offset) {
            Some(mask) => value & mask | registers.words.get(&offset).copied().unwrap_or(0) & !mask,
            None => value,
        };
        registers.words.insert(offset, word);
    }
}

impl Bus {
    fn at(&self) -> impl FnMut(u8, u8, u8) -> Function + use<> {
        let bus = self.clone();
        move |segment, device, function| Function(bus.clone(), (segment, device, function))
    }

    fn function(&self, location: (u8, u8, u8)) -> Function {
        Function(self.clone(), location)
    }

    fn add(&self, location: (u8, u8, u8), header: u8, express_flags: Option<u16>) {
        let bars = if header & HEADER_MASK == HEADER_BRIDGE {
            BRIDGE_BARS
        } else {
            ENDPOINT_BARS
        };
        self.0.borrow_mut().insert(
            location,
            Registers {
                // A BAR reads back as zero until it is given bits.
                masks: (0..bars)
                    .map(|index| (regs::BASE_ADDRESS_0 + 4 * index, 0))
                    .collect(),
                ..Registers::default()
            },
        );
        let mut config = self.function(location);
        config.write32(regs::VENDOR_ID, 0x1234_8086);
        config.write8(regs::HEADER_TYPE, header);
        if let Some(flags) = express_flags {
            config.write16(regs::STATUS, regs::STATUS_CAP_LIST);
            config.write8(regs::CAPABILITY_LIST, EXPRESS_AT as u8);
            config.write32(
                EXPRESS_AT,
                u32::from(CAPABILITY_EXPRESS) | u32::from(flags) << 16,
            );
        }
    }

    /// A 64-bit, or 32-bit, memory BAR of `size` bytes.
    fn bar(&self, location: (u8, u8, u8), index: u16, size: u64, wide: bool, prefetchable: bool) {
        let offset = regs::BASE_ADDRESS_0 + 4 * index;
        let kind =
            if wide { BAR_MEMORY_64 } else { 0 } | if prefetchable { BAR_PREFETCHABLE } else { 0 };
        let mut functions = self.0.borrow_mut();
        let registers = functions.get_mut(&location).unwrap();
        registers.words.insert(offset, kind);
        registers.masks.insert(offset, !(size as u32 - 1) & !0xf);
        if wide {
            registers
                .masks
                .insert(offset + 4, (!(size - 1) >> 32) as u32);
        }
    }

    /// The root port firmware numbered, with a memory and a 64-bit
    /// prefetchable window.
    fn root(&self) {
        self.add(ROOT, 0x81, Some(EXPRESS_ROOT_PORT << EXPRESS_TYPE_SHIFT));
        let mut config = self.function(ROOT);
        config.write32(BUS_NUMBERS, 0x0040_1000);
        config.write32(
            MEMORY_WINDOW,
            window_word(Some(&(0x9000_0000..0xa000_0000))),
        );
        config.write32(
            PREFETCH_WINDOW,
            window_word(Some(&(0x6_0000_0000..0x7_0000_0000))) | PREFETCH_64,
        );
        config.write32(PREFETCH_BASE_UPPER, 6);
        config.write32(PREFETCH_LIMIT_UPPER, 6);
        self.window_type(ROOT);
    }

    /// Make the prefetchable window's type field read-only.
    fn window_type(&self, location: (u8, u8, u8)) {
        let mut functions = self.0.borrow_mut();
        let registers = functions.get_mut(&location).unwrap();
        registers.masks.insert(PREFETCH_WINDOW, !PREFETCH_TYPE);
    }

    /// A PCIe switch's port with a 64-bit prefetchable window.
    fn port(&self, location: (u8, u8, u8), kind: u16) {
        self.add(location, HEADER_BRIDGE, Some(kind << EXPRESS_TYPE_SHIFT));
        self.function(location)
            .write32(PREFETCH_WINDOW, PREFETCH_64);
        self.window_type(location);
    }

    fn base(&self, location: (u8, u8, u8), index: u16) -> u64 {
        let config = self.function(location);
        let offset = regs::BASE_ADDRESS_0 + 4 * index;
        let low = u64::from(config.read32(offset) & !0xf);
        let wide = config.read32(offset) & BAR_MEMORY_TYPE == BAR_MEMORY_64;
        low | if wide {
            u64::from(config.read32(offset + 4)) << 32
        } else {
            0
        }
    }
}

const UPSTREAM: u16 = 5;

#[test]
fn an_endpoint_below_a_root_port_gets_its_windows_share() {
    let bus = Bus::default();
    bus.root();
    bus.add((0x10, 0, 0), 0, Some(0));
    bus.bar((0x10, 0, 0), 0, 0x10_0000, true, false);
    bus.bar((0x10, 0, 0), 2, 0x1000, false, false);
    bus.bar((0x10, 0, 0), 3, 0x2000_0000, true, true);

    let arrivals = adopt(0, ROOT, bus.at()).unwrap();

    assert_eq!(arrivals.functions.len(), 1);
    assert_eq!(bus.base((0x10, 0, 0), 0), 0x9000_0000);
    assert_eq!(bus.base((0x10, 0, 0), 2), 0x9010_0000);
    assert_eq!(bus.base((0x10, 0, 0), 3), 0x6_0000_0000);
    let config = bus.function((0x10, 0, 0));
    assert_eq!(
        config.read16(regs::COMMAND) & regs::COMMAND_MEMORY,
        0,
        "endpoints stay off until a driver claims them"
    );
    let root = bus.function(ROOT);
    assert_ne!(root.read16(regs::COMMAND) & regs::COMMAND_MEMORY, 0);
}

#[test]
fn a_dock_switch_gets_buses_and_nested_windows() {
    let bus = Bus::default();
    bus.root();
    bus.port((0x10, 0, 0), UPSTREAM);
    bus.port((0x11, 0, 0), EXPRESS_DOWNSTREAM);
    bus.port((0x11, 1, 0), EXPRESS_DOWNSTREAM);
    bus.add((0x12, 0, 0), 0, Some(0));
    bus.bar((0x12, 0, 0), 0, 0x4000, true, false);
    bus.add((0x13, 0, 0), 0, Some(0));
    bus.bar((0x13, 0, 0), 0, 0x20_0000, true, false);
    bus.bar((0x13, 0, 0), 2, 0x100_0000, true, true);

    let arrivals = adopt(0, ROOT, bus.at()).unwrap();

    assert_eq!(arrivals.functions.len(), 5);
    assert_eq!(arrivals.functions[0].bus, 0x10);
    let upstream = bus.function((0x10, 0, 0));
    assert_eq!(upstream.read8(SECONDARY_BUS), 0x11);
    assert_eq!(upstream.read8(SUBORDINATE_BUS), 0x13);
    let first = bus.function((0x11, 0, 0));
    assert_eq!(first.read8(SECONDARY_BUS), 0x12);
    assert_eq!(first.read8(SUBORDINATE_BUS), 0x12);
    let second = bus.function((0x11, 1, 0));
    assert_eq!(second.read8(SECONDARY_BUS), 0x13);
    assert_eq!(second.read8(SUBORDINATE_BUS), 0x13);

    // Largest first: the second port's 2 MiB aligns its window to 2 MiB.
    assert_eq!(
        memory_window(&second).unwrap(),
        0x9000_0000..0x9020_0000,
        "a window covers its largest BAR's alignment"
    );
    assert_eq!(memory_window(&first).unwrap(), 0x9020_0000..0x9030_0000);
    assert_eq!(memory_window(&upstream).unwrap(), 0x9000_0000..0x9030_0000);
    assert_eq!(
        prefetch_window(&upstream).unwrap(),
        0x6_0000_0000..0x6_0100_0000
    );
    assert_eq!(prefetch_window(&first), None);
    assert_eq!(bus.base((0x12, 0, 0), 0), 0x9020_0000);
    assert_eq!(bus.base((0x13, 0, 0), 2), 0x6_0000_0000);
    assert_ne!(first.read16(regs::COMMAND) & regs::COMMAND_MASTER, 0);
}

#[test]
fn a_port_scans_only_its_one_device() {
    let bus = Bus::default();
    bus.root();
    bus.add((0x10, 0, 0), 0, Some(0));
    // Below a port a second device number aliases nothing real.
    bus.add((0x10, 1, 0), 0, Some(0));

    assert_eq!(adopt(0, ROOT, bus.at()).unwrap().functions.len(), 1);
}

#[test]
fn every_function_of_a_multifunction_device_arrives() {
    let bus = Bus::default();
    bus.root();
    bus.add((0x10, 0, 0), HEADER_MULTIFUNCTION, Some(0));
    bus.add((0x10, 0, 3), 0, Some(0));
    bus.bar((0x10, 0, 3), 0, 0x1000, false, false);

    let arrivals = adopt(0, ROOT, bus.at()).unwrap();

    assert_eq!(arrivals.functions.len(), 2);
    assert_eq!(bus.base((0x10, 0, 3), 0), 0x9000_0000);
}

#[test]
fn a_narrow_prefetchable_bar_never_lands_above_four_gigabytes() {
    let bus = Bus::default();
    bus.root();
    bus.add((0x10, 0, 0), 0, Some(0));
    bus.bar((0x10, 0, 0), 0, 0x10_0000, false, true);

    adopt(0, ROOT, bus.at()).unwrap();

    assert_eq!(bus.base((0x10, 0, 0), 0), 0x9000_0000);
}

#[test]
fn too_much_for_the_window_is_refused() {
    let bus = Bus::default();
    bus.root();
    bus.add((0x10, 0, 0), 0, Some(0));
    bus.bar((0x10, 0, 0), 0, 0x2000_0000, false, false);

    assert_eq!(adopt(0, ROOT, bus.at()), Err(Error::Windows));
}

#[test]
fn too_few_buses_are_refused() {
    let bus = Bus::default();
    bus.root();
    bus.function(ROOT).write32(BUS_NUMBERS, 0x0010_1000);
    bus.port((0x10, 0, 0), UPSTREAM);

    assert_eq!(adopt(0, ROOT, bus.at()), Err(Error::Buses));
}

#[test]
fn a_bridge_firmware_never_numbered_is_refused() {
    let bus = Bus::default();
    bus.root();
    bus.function(ROOT).write32(BUS_NUMBERS, 0);

    assert_eq!(adopt(0, ROOT, bus.at()), Err(Error::Buses));
}

#[test]
fn what_firmware_placed_is_left_alone() {
    let bus = Bus::default();
    bus.root();
    bus.add((0x10, 0, 0), 0, Some(0));
    bus.bar((0x10, 0, 0), 0, 0x1000, false, false);
    bus.function((0x10, 0, 0))
        .write32(regs::BASE_ADDRESS_0, 0x9800_0000);

    assert_eq!(adopt(0, ROOT, bus.at()), Ok(Arrivals::default()));
    assert_eq!(bus.base((0x10, 0, 0), 0), 0x9800_0000);
}

#[test]
fn an_empty_link_adopts_nothing() {
    let bus = Bus::default();
    bus.root();

    assert_eq!(adopt(0, ROOT, bus.at()), Ok(Arrivals::default()));
}

#[test]
fn a_root_port_lowers_its_payload_to_a_smaller_device() {
    let bus = Bus::default();
    bus.root();
    bus.function(ROOT)
        .write16(EXPRESS_AT + DEVICE_CONTROL, 2 << PAYLOAD_SHIFT);
    bus.add((0x10, 0, 0), 0, Some(0));
    bus.function((0x10, 0, 0))
        .write32(EXPRESS_AT + DEVICE_CAPABILITIES, 1);

    let arrivals = adopt(0, ROOT, bus.at()).unwrap();

    assert!(arrivals.payload_mismatches.is_empty());
    let payload = |location| {
        let control = bus.function(location).read16(EXPRESS_AT + DEVICE_CONTROL);
        (control & PAYLOAD_MASK) >> PAYLOAD_SHIFT
    };
    assert_eq!(payload(ROOT), 1);
    assert_eq!(payload((0x10, 0, 0)), 1);
}

#[test]
fn a_device_takes_its_ports_payload_and_a_switch_reports_what_it_cannot_lower() {
    let bus = Bus::default();
    bus.root();
    bus.function(ROOT)
        .write16(EXPRESS_AT + DEVICE_CONTROL, 1 << PAYLOAD_SHIFT);
    bus.port((0x10, 0, 0), UPSTREAM);
    bus.function((0x10, 0, 0))
        .write32(EXPRESS_AT + DEVICE_CAPABILITIES, 5);
    bus.port((0x11, 0, 0), EXPRESS_DOWNSTREAM);
    bus.function((0x11, 0, 0))
        .write32(EXPRESS_AT + DEVICE_CAPABILITIES, 5);
    bus.add((0x12, 0, 0), 0, Some(0));

    let arrivals = adopt(0, ROOT, bus.at()).unwrap();

    let control = bus
        .function((0x10, 0, 0))
        .read16(EXPRESS_AT + DEVICE_CONTROL);
    assert_eq!((control & PAYLOAD_MASK) >> PAYLOAD_SHIFT, 1);
    assert_eq!(arrivals.payload_mismatches.len(), 1);
    assert_eq!(arrivals.payload_mismatches[0].bus, 0x12);
}

#[test]
fn a_hot_plug_slot_and_its_link_read_from_the_express_capability() {
    let bus = Bus::default();
    bus.root();
    let mut root = bus.function(ROOT);
    assert!(!hot_plug_capable(&root));
    let flags = root.read16(EXPRESS_AT + EXPRESS_FLAGS);
    root.write16(EXPRESS_AT + EXPRESS_FLAGS, flags | EXPRESS_SLOT_IMPLEMENTED);
    assert!(!hot_plug_capable(&root));
    root.write32(EXPRESS_AT + SLOT_CAPABILITIES, SLOT_HOT_PLUG_CAPABLE);
    assert!(hot_plug_capable(&root));
}

#[test]
fn a_link_has_arrived_once_something_unplaced_answers_on_it() {
    let bus = Bus::default();
    bus.root();
    let mut root = bus.function(ROOT);
    let arrived = |root: &Function| super::arrived(root, bus.at());
    bus.add((0x10, 0, 0), 0, Some(0));
    assert!(!arrived(&root), "the link is down");
    root.write16(EXPRESS_AT + LINK_STATUS, LINK_ACTIVE);
    assert!(arrived(&root));
    bus.bar((0x10, 0, 0), 0, 0x1000, false, false);
    adopt(0, ROOT, bus.at()).unwrap();
    assert!(!arrived(&root), "it has its place");
    root.write32(BUS_NUMBERS, 0);
    assert!(arrived(&root), "adopt reports the missing bus");
}
