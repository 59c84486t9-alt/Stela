// SPDX-License-Identifier: GPL-2.0-only
// PCI bus scanning and resource assignment follow Linux drivers/pci/probe.c
// and setup-bus.c, copyright David Mosberger, Martin Mares, Ivan Kokshaysky
// and others; see bus/THIRD_PARTY.md.
//! Functions that arrive below a hot-plug bridge after firmware numbered the
//! buses: Linux's `pci_scan_bridge`, `pbus_size_mem`, `__pci_bus_assign_resources`
//! and `pci_configure_mps`, within the bus range and windows the bridge has.
//!
//! The arrivals are numbered and placed, and the bridges among them forward.
//! Endpoints keep their decode off until a driver claims them. I/O BARs get
//! nothing and each bridge's I/O window stays closed, as PCI Express devices
//! decode memory too. Functions above 7 of an ARI device are not placed.
use super::{
    Address, BAR_IO, BAR_MEMORY_64, BAR_MEMORY_TYPE, BAR_PREFETCHABLE, CAPABILITY_EXPRESS,
    ConfigSpace, EXPRESS_DOWNSTREAM, EXPRESS_FLAGS, EXPRESS_ROOT_PORT, EXPRESS_TYPE_SHIFT,
    HEADER_BRIDGE, SECONDARY_BUS, VENDOR_NOT_READY, regs,
};
use alloc::vec::Vec;
use core::{cmp::Reverse, ops::Range};

const BUS_NUMBERS: u16 = 0x18;
const SUBORDINATE_BUS: u16 = 0x1a;
const IO_WINDOW: u16 = 0x1c;
const MEMORY_WINDOW: u16 = 0x20;
const PREFETCH_WINDOW: u16 = 0x24;
const PREFETCH_BASE_UPPER: u16 = 0x28;
const PREFETCH_LIMIT_UPPER: u16 = 0x2c;
const IO_WINDOW_UPPER: u16 = 0x30;
/// A window's base and limit fields, whose addresses have bits 31:20.
const WINDOW_FIELD: u32 = 0xfff0;
/// A base above its limit, which closes a window.
const WINDOW_CLOSED: u32 = WINDOW_FIELD;
const IO_WINDOW_CLOSED: u16 = 0x00f0;
/// The type field of a prefetchable window, and its 64-bit encoding.
const PREFETCH_TYPE: u32 = 0xf;
const PREFETCH_64: u32 = 1;

const HEADER_MASK: u8 = 0x7f;
const HEADER_MULTIFUNCTION: u8 = 0x80;
const ENDPOINT_BARS: u16 = 6;
const BRIDGE_BARS: u16 = 2;

/// A bridge window's granularity.
const MEGABYTE: u64 = 1 << 20;
const FOUR_GIGABYTES: u64 = 1 << 32;
/// A BAR gets a page of its own, for a mapping of its own.
const PAGE: u64 = 4096;

const EXPRESS_SLOT_IMPLEMENTED: u16 = 1 << 8;
const DEVICE_CAPABILITIES: u16 = 4;
const DEVICE_CONTROL: u16 = 8;
const PAYLOAD_SHIFT: u32 = 5;
const PAYLOAD_MASK: u16 = 7 << PAYLOAD_SHIFT;
const LINK_STATUS: u16 = 0x12;
const LINK_ACTIVE: u16 = 1 << 13;
const SLOT_CAPABILITIES: u16 = 0x14;
const SLOT_HOT_PLUG_CAPABLE: u32 = 1 << 6;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Config(super::ConfigError),
    PciCapability(super::CapabilityError),
    /// The bridge's bus range is empty or too small.
    Buses,
    /// Its memory windows are closed or too small.
    Windows,
}
impl From<super::ConfigError> for Error {
    fn from(error: super::ConfigError) -> Self {
        Self::Config(error)
    }
}
impl From<super::CapabilityError> for Error {
    fn from(error: super::CapabilityError) -> Self {
        Self::PciCapability(error)
    }
}

/// What [`adopt`] numbered and placed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Arrivals {
    /// Each function, bridges before what hangs from them.
    pub functions: Vec<Address>,
    /// Functions whose largest payload is below their link's other end's,
    /// which is no root port to lower: Linux warns of these and goes on.
    pub payload_mismatches: Vec<Address>,
}

/// Where `config`'s PCI Express capability is.
fn express<C: ConfigSpace>(config: &C) -> Result<Option<u16>, Error> {
    for entry in config.capabilities() {
        let entry = entry?;
        if entry.id == CAPABILITY_EXPRESS {
            return Ok(Some(entry.offset));
        }
    }
    Ok(None)
}
fn express_type<C: ConfigSpace>(config: &C, capability: u16) -> Result<u16, Error> {
    Ok((config.read16(capability + EXPRESS_FLAGS)? >> EXPRESS_TYPE_SHIFT) & 15)
}
pub fn hot_plug_capable<C: ConfigSpace>(bridge: &C) -> Result<bool, Error> {
    let Some(capability) = express(bridge)? else {
        return Ok(false);
    };
    Ok(
        bridge.read16(capability + EXPRESS_FLAGS)? & EXPRESS_SLOT_IMPLEMENTED != 0
            && bridge.read32(capability + SLOT_CAPABILITIES)? & SLOT_HOT_PLUG_CAPABLE != 0,
    )
}
fn link_active<C: ConfigSpace>(bridge: &C) -> Result<bool, Error> {
    let Some(capability) = express(bridge)? else {
        return Ok(false);
    };
    Ok(bridge.read16(capability + LINK_STATUS)? & LINK_ACTIVE != 0)
}
pub fn arrived<C: ConfigSpace>(
    bridge: &C,
    at: impl FnOnce(u8, u8, u8) -> C,
) -> Result<bool, Error> {
    let secondary = bridge.read8(SECONDARY_BUS)?;
    if !link_active(bridge)? {
        return Ok(false);
    }
    if secondary == 0 {
        return Ok(true);
    }
    let first = at(secondary, 0, 0);
    Ok(present(&first)? && untouched(&first)?)
}
fn present<C: ConfigSpace>(config: &C) -> Result<bool, Error> {
    Ok(!matches!(
        config.read16(regs::VENDOR_ID)?,
        u16::MAX | VENDOR_NOT_READY
    ))
}
fn untouched<C: ConfigSpace>(config: &C) -> Result<bool, Error> {
    if config.read8(regs::HEADER_TYPE)? & HEADER_MASK == HEADER_BRIDGE {
        return Ok(config.read8(SECONDARY_BUS)? == 0);
    }
    for index in 0..ENDPOINT_BARS {
        if config.read32(regs::BASE_ADDRESS_0 + 4 * index)? & !0xf != 0 {
            return Ok(false);
        }
    }
    Ok(true)
}
#[derive(Clone, Copy, Debug)]
struct Register {
    offset: u16,
    size: u64,
    wide: bool,
    prefetchable: bool,
}

/// A bridge's sized secondary side.
#[derive(Debug)]
struct Below {
    nodes: Vec<Node>,
    /// The address its prefetchable window ends below, if it has one.
    reach: Option<u64>,
}

#[derive(Debug)]
struct Node {
    location: (u8, u8, u8),
    registers: Vec<Register>,
    below: Option<Below>,
}

#[derive(Clone, Copy, Debug)]
enum Target {
    Register(usize, usize),
    Memory(usize),
    Prefetchable(usize),
}

/// One thing a bridge's windows hold.
#[derive(Clone, Copy, Debug)]
struct Item {
    size: u64,
    alignment: u64,
    prefetchable: bool,
    target: Target,
}

/// One window's size and alignment.
#[derive(Clone, Copy, Debug, Default)]
struct Need {
    size: u64,
    alignment: u64,
}

impl Need {
    fn add(&mut self, item: &Item) -> Option<()> {
        let start = self.size.checked_next_multiple_of(item.alignment)?;
        self.size = start.checked_add(item.size)?;
        self.alignment = self.alignment.max(item.alignment);
        Some(())
    }

    fn item(&self, prefetchable: bool, target: Target) -> Option<Item> {
        (self.size != 0).then_some(Item {
            size: self.size.next_multiple_of(MEGABYTE),
            alignment: self.alignment.max(MEGABYTE),
            prefetchable,
            target,
        })
    }
}

/// Whether a bridge with a prefetchable window ending at `end` holds
/// `register` there: a window reaching past 4 GiB holds 64-bit BARs alone.
fn prefetched(register: &Register, end: Option<u64>) -> bool {
    register.prefetchable && end.is_some_and(|end| register.wide || end <= FOUR_GIGABYTES)
}

/// A child bridge's use of the prefetchable window ending at `end`.
fn child_window(below: &Below, end: Option<u64>) -> Option<u64> {
    end.filter(|end| below.reach.is_some_and(|reach| *end <= reach))
}

/// What `nodes` ask of their bridge, whose prefetchable window ends at `end`
/// if it has one, largest alignment first, which leaves no holes.
fn items(nodes: &[Node], end: Option<u64>) -> Option<Vec<Item>> {
    let mut items = Vec::new();
    for (index, node) in nodes.iter().enumerate() {
        for (at, register) in node.registers.iter().enumerate() {
            items.push(Item {
                size: register.size,
                alignment: register.size.max(PAGE),
                prefetchable: prefetched(register, end),
                target: Target::Register(index, at),
            });
        }
        if let Some(below) = &node.below {
            let (memory, prefetchable) = needs(&below.nodes, child_window(below, end))?;
            items.extend(memory.item(false, Target::Memory(index)));
            items.extend(prefetchable.item(true, Target::Prefetchable(index)));
        }
    }
    items.sort_by_key(|item| Reverse(item.alignment));
    Some(items)
}

/// The memory and prefetchable windows `nodes` need.
fn needs(nodes: &[Node], end: Option<u64>) -> Option<(Need, Need)> {
    let (mut memory, mut prefetchable) = (Need::default(), Need::default());
    for item in items(nodes, end)? {
        if item.prefetchable {
            prefetchable.add(&item)?;
        } else {
            memory.add(&item)?;
        }
    }
    Some((memory, prefetchable))
}

/// A bridge's base and limit register pair for `range`.
fn window_word(range: Option<&Range<u64>>) -> u32 {
    range.map_or(WINDOW_CLOSED, |range| {
        let base = (range.start >> 16) as u32 & WINDOW_FIELD;
        let limit = ((range.end - 1) >> 16) as u32 & WINDOW_FIELD;
        base | limit << 16
    })
}

/// The range a base and limit register pair names; `upper` holds the two
/// addresses' bits from 32.
fn window(word: u32, upper: (u64, u64)) -> Option<Range<u64>> {
    let base = upper.0 << 32 | u64::from(word & WINDOW_FIELD) << 16;
    let limit = upper.1 << 32 | u64::from(word >> 16 & WINDOW_FIELD) << 16 | (MEGABYTE - 1);
    (base < limit).then(|| base..limit + 1)
}

/// A bridge's non-prefetchable window, from its registers.
fn memory_window<C: ConfigSpace>(bridge: &C) -> Result<Option<Range<u64>>, Error> {
    Ok(window(bridge.read32(MEMORY_WINDOW)?, (0, 0)))
}
fn prefetch_window<C: ConfigSpace>(bridge: &C) -> Result<Option<Range<u64>>, Error> {
    let word = bridge.read32(PREFETCH_WINDOW)?;
    let upper = if word & PREFETCH_TYPE == PREFETCH_64 {
        (
            u64::from(bridge.read32(PREFETCH_BASE_UPPER)?),
            u64::from(bridge.read32(PREFETCH_LIMIT_UPPER)?),
        )
    } else {
        (0, 0)
    };
    Ok(window(word, upper))
}
/// A bridge's windows, or what is left of them to place in.
#[derive(Debug, Default)]
struct Pools {
    memory: Option<Range<u64>>,
    prefetchable: Option<Range<u64>>,
}

impl Pools {
    fn take(&mut self, item: &Item) -> Result<Range<u64>, Error> {
        let pool = if item.prefetchable {
            &mut self.prefetchable
        } else {
            &mut self.memory
        };
        let pool = pool.as_mut().ok_or(Error::Windows)?;
        let start = pool
            .start
            .checked_next_multiple_of(item.alignment)
            .ok_or(Error::Windows)?;
        let end = start.checked_add(item.size).ok_or(Error::Windows)?;
        if end > pool.end {
            return Err(Error::Windows);
        }
        pool.start = end;
        Ok(start..end)
    }
}

struct Scan<A> {
    at: A,
    segment: u16,
    /// The next bus number free, and the last the range has.
    next: u16,
    limit: u8,
    arrivals: Arrivals,
}

impl<C: ConfigSpace, A: FnMut(u8, u8, u8) -> C> Scan<A> {
    fn address(&self, (bus, device, function): (u8, u8, u8)) -> Address {
        Address {
            segment: self.segment,
            bus,
            device,
            function,
        }
    }

    fn config(&mut self, (bus, device, function): (u8, u8, u8)) -> C {
        (self.at)(bus, device, function)
    }

    /// The first `count` BARs' sizes, with decode off, as `pci_read_bases`.
    fn registers(config: &mut C, count: u16) -> Result<Vec<Register>, Error> {
        let command = config.read16(regs::COMMAND)?;
        config.write16(
            regs::COMMAND,
            command & !(regs::COMMAND_IO | regs::COMMAND_MEMORY),
        )?;
        let mut found = Vec::new();
        let mut index = 0;
        while index < count {
            let offset = regs::BASE_ADDRESS_0 + 4 * index;
            index += 1;
            let low = config.read32(offset)?;
            config.write32(offset, u32::MAX)?;
            let mask = config.read32(offset)? & !0xf;
            config.write32(offset, low)?;
            if low & BAR_IO != 0 {
                continue;
            }
            let wide = low & BAR_MEMORY_TYPE == BAR_MEMORY_64 && index < count;
            let upper = if wide {
                let upper = offset + 4;
                index += 1;
                config.write32(upper, u32::MAX)?;
                let mask = config.read32(upper)?;
                config.write32(upper, 0)?;
                mask
            } else {
                u32::MAX
            };
            let implemented = mask != 0 || (wide && upper != 0);
            let size = (!(u64::from(upper) << 32 | u64::from(mask))).wrapping_add(1);
            if implemented && size.is_power_of_two() {
                found.push(Register {
                    offset,
                    size,
                    wide,
                    prefetchable: low & BAR_PREFETCHABLE != 0,
                });
            }
        }
        config.write16(regs::COMMAND, command)?;
        Ok(found)
    }

    /// The address a bridge's prefetchable window can end below, if it has
    /// one, as `pci_read_bridge_windows` finds out.
    fn reach(config: &mut C) -> Result<Option<u64>, Error> {
        let saved = config.read32(PREFETCH_WINDOW)?;
        config.write32(PREFETCH_WINDOW, WINDOW_FIELD << 16 | WINDOW_FIELD)?;
        let word = config.read32(PREFETCH_WINDOW)?;
        config.write32(PREFETCH_WINDOW, saved)?;
        Ok(
            (word != 0).then_some(if word & PREFETCH_TYPE == PREFETCH_64 {
                u64::MAX
            } else {
                FOUR_GIGABYTES
            }),
        )
    }

    /// Number a bridge and scan what hangs from it, as
    /// `pci_scan_bridge_extend` does for a bridge firmware left alone.
    fn bridge(&mut self, location: (u8, u8, u8), config: &mut C) -> Result<Node, Error> {
        let secondary = u8::try_from(self.next)
            .ok()
            .filter(|secondary| *secondary <= self.limit)
            .ok_or(Error::Buses)?;
        self.next += 1;
        let latency = config.read32(BUS_NUMBERS)? & 0xff00_0000;
        config.write32(
            BUS_NUMBERS,
            latency
                | u32::from(location.0)
                | u32::from(secondary) << 8
                | u32::from(self.limit) << 16,
        )?;
        let registers = Self::registers(config, BRIDGE_BARS)?;
        let reach = Self::reach(config)?;
        let single = match express(config)? {
            Some(capability) => matches!(
                express_type(config, capability)?,
                EXPRESS_ROOT_PORT | EXPRESS_DOWNSTREAM
            ),
            None => false,
        };
        let nodes = self.bus(secondary, single)?;
        config.write8(SUBORDINATE_BUS, (self.next - 1) as u8)?;
        Ok(Node {
            location,
            registers,
            below: Some(Below { nodes, reach }),
        })
    }

    /// The functions on `bus`. A PCI Express port's link holds one device.
    fn bus(&mut self, bus: u8, single: bool) -> Result<Vec<Node>, Error> {
        let mut nodes = Vec::new();
        for device in 0..if single { 1 } else { 32 } {
            for function in 0..8 {
                let location = (bus, device, function);
                let mut config = self.config(location);
                if !present(&config)? {
                    if function == 0 {
                        break;
                    }
                    continue;
                }
                let header = config.read8(regs::HEADER_TYPE)?;
                let address = self.address(location);
                self.arrivals.functions.push(address);
                match header & HEADER_MASK {
                    0 => nodes.push(Node {
                        location,
                        registers: Self::registers(&mut config, ENDPOINT_BARS)?,
                        below: None,
                    }),
                    HEADER_BRIDGE => nodes.push(self.bridge(location, &mut config)?),
                    _ => {}
                }
                if function == 0 && header & HEADER_MULTIFUNCTION == 0 {
                    break;
                }
            }
        }
        Ok(nodes)
    }

    /// Write `node`'s placed windows and open its forwarding.
    fn forward(&mut self, node: &Node, windows: &Pools) -> Result<(), Error> {
        let memory = windows.memory.as_ref();
        let prefetch = windows.prefetchable.as_ref();
        let mut config = self.config(node.location);
        config.write16(IO_WINDOW, IO_WINDOW_CLOSED)?;
        config.write32(IO_WINDOW_UPPER, 0)?;
        config.write32(MEMORY_WINDOW, window_word(memory))?;
        config.write32(PREFETCH_WINDOW, window_word(prefetch))?;
        let upper = |address: u64| (address >> 32) as u32;
        config.write32(
            PREFETCH_BASE_UPPER,
            prefetch.map_or(0, |range| upper(range.start)),
        )?;
        config.write32(
            PREFETCH_LIMIT_UPPER,
            prefetch.map_or(0, |range| upper(range.end - 1)),
        )?;
        let command = config.read16(regs::COMMAND)?;
        config.write16(
            regs::COMMAND,
            command | regs::COMMAND_MEMORY | regs::COMMAND_MASTER,
        )?;
        Ok(())
    }

    /// Give `nodes` their places in `pools`, top down. `end` is what [`items`]
    /// sized them against.
    fn place(&mut self, nodes: &[Node], pools: &mut Pools, end: Option<u64>) -> Result<(), Error> {
        let mut windows: Vec<Pools> = nodes.iter().map(|_| Pools::default()).collect();
        for item in items(nodes, end).ok_or(Error::Windows)? {
            let range = pools.take(&item)?;
            match item.target {
                Target::Register(index, at) => {
                    let register = nodes[index].registers[at];
                    let mut config = self.config(nodes[index].location);
                    let kept = config.read32(register.offset)? & 0xf;
                    config.write32(register.offset, range.start as u32 | kept)?;
                    if register.wide {
                        config.write32(register.offset + 4, (range.start >> 32) as u32)?;
                    }
                }
                Target::Memory(index) => windows[index].memory = Some(range),
                Target::Prefetchable(index) => windows[index].prefetchable = Some(range),
            }
        }
        for (node, mut window) in nodes.iter().zip(windows) {
            if let Some(below) = &node.below {
                self.forward(node, &window)?;
                self.place(&below.nodes, &mut window, child_window(below, end))?;
            }
        }
        Ok(())
    }

    /// Match each arrival's payload size to its link, as `pci_configure_mps`.
    fn payloads(&mut self, parent: (u8, u8, u8), nodes: &[Node]) -> Result<(), Error> {
        for node in nodes {
            let mut above = self.config(parent);
            let mut config = self.config(node.location);
            if let (Some(up), Some(own)) = (express(&above)?, express(&config)?) {
                let control = above.read16(up + DEVICE_CONTROL)?;
                let current = (control & PAYLOAD_MASK) >> PAYLOAD_SHIFT;
                let largest = (config.read32(own + DEVICE_CAPABILITIES)? & 7) as u16;
                let payload = current.min(largest);
                if largest < current {
                    if express_type(&above, up)? == EXPRESS_ROOT_PORT {
                        above.write16(
                            up + DEVICE_CONTROL,
                            control & !PAYLOAD_MASK | payload << PAYLOAD_SHIFT,
                        )?;
                    } else {
                        let address = self.address(node.location);
                        self.arrivals.payload_mismatches.push(address);
                    }
                }
                let control = config.read16(own + DEVICE_CONTROL)? & !PAYLOAD_MASK;
                config.write16(own + DEVICE_CONTROL, control | payload << PAYLOAD_SHIFT)?;
            }
            if let Some(below) = &node.below {
                self.payloads(node.location, &below.nodes)?;
            }
        }
        Ok(())
    }
}

/// Number and place what arrived below the hot-plug `bridge`, within its bus
/// range and windows, with `at` reaching each function's configuration
/// space. What something has numbered or placed already is left alone.
pub fn adopt<C: ConfigSpace>(
    segment: u16,
    bridge: (u8, u8, u8),
    mut at: impl FnMut(u8, u8, u8) -> C,
) -> Result<Arrivals, Error> {
    let mut parent = at(bridge.0, bridge.1, bridge.2);
    let secondary = parent.read8(SECONDARY_BUS)?;
    if secondary == 0 {
        return Err(Error::Buses);
    }
    let first = at(secondary, 0, 0);
    if !present(&first)? || !untouched(&first)? {
        return Ok(Arrivals::default());
    }
    let mut scan = Scan {
        at,
        segment,
        next: u16::from(secondary) + 1,
        limit: parent.read8(SUBORDINATE_BUS)?,
        arrivals: Arrivals::default(),
    };
    let nodes = scan.bus(secondary, true)?;
    let mut pools = Pools {
        memory: memory_window(&parent)?,
        prefetchable: prefetch_window(&parent)?,
    };
    let end = pools.prefetchable.as_ref().map(|range| range.end);
    scan.place(&nodes, &mut pools, end)?;
    let command = parent.read16(regs::COMMAND)?;
    parent.write16(
        regs::COMMAND,
        command | regs::COMMAND_MEMORY | regs::COMMAND_MASTER,
    )?;
    scan.payloads(bridge, &nodes)?;
    Ok(scan.arrivals)
}

#[cfg(test)]
mod tests;
