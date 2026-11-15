//! Which PCI functions can decode the firmware's screen when no function's
//! BAR was matched to it.
//!
//! A laptop with no display mux wires its panel to the integrated GPU, whose
//! firmware framebuffer the GOP names, while the NVIDIA GPU Stela drives has
//! no output connected. When the firmware's BAR descriptors attribute the
//! screen to no function, the bridges still tell where it cannot be: a
//! function decodes a memory address only if every PCI-to-PCI bridge above
//! it forwards that address, so no function below a bridge whose windows
//! forward none of the screen can hold it, and no reset of a function there
//! or of that bridge's bus can end it. Stela never changes those windows
//! (their routing seal holds them as firmware left them), so the answer
//! stays true for the boot. A GPU there leaves the screen to the adapter
//! showing it, which then shows macOS's frames.
use core::ops::{Range, RangeInclusive};

/// The legacy VGA memory a bridge forwards with VGA Enable set.
const VGA_MEMORY: Range<u64> = 0xa_0000..0xc_0000;
/// Bridge Control's VGA Enable, in the dword at 0x3c (control is its upper
/// half; PCI-to-PCI Bridge Architecture 3.2.5.18).
const VGA_ENABLE: u32 = 1 << (16 + 3);
/// Class code of a PCI-to-PCI bridge with subtractive decode, which forwards
/// whatever no other agent on its primary bus claims.
const SUBTRACTIVE_BRIDGE: u32 = 0x06_04_01;

/// A Type 1 header's words that decide which memory it forwards.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BridgeWords {
    /// Class code and revision (0x08).
    pub class_revision: u32,
    /// Primary, secondary and subordinate bus numbers (0x18).
    pub buses: u32,
    /// Memory base and limit (0x20).
    pub memory: u32,
    /// Prefetchable memory base and limit (0x24).
    pub prefetchable: u32,
    /// Prefetchable base and limit, upper 32 bits (0x28, 0x2c).
    pub prefetchable_upper: (u32, u32),
    /// Interrupt line and pin, and Bridge Control (0x3c).
    pub control: u32,
}

/// The memory a PCI-to-PCI bridge forwards to the buses below it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BridgeWindows {
    buses: RangeInclusive<u8>,
    memory: Option<Range<u64>>,
    prefetchable: Option<Range<u64>>,
    subtractive: bool,
    vga: bool,
}

impl BridgeWindows {
    /// The windows of a bridge with `words`, or `None` when it was given no
    /// buses (it then forwards to none).
    pub fn from_words(words: BridgeWords) -> Option<Self> {
        let [_, secondary, subordinate, _] = words.buses.to_le_bytes();
        if secondary == 0 || subordinate < secondary {
            return None;
        }
        // Memory window: 1 MiB granular, 32 bits (bridge spec 3.2.5.8).
        let base = u64::from(words.memory & 0xfff0) << 16;
        let limit = u64::from(words.memory >> 16 & 0xfff0) << 16 | 0xf_ffff;
        let memory = (base <= limit).then(|| base..limit + 1);
        // Prefetchable window: 64 bits when its type field says so (3.2.5.9).
        let wide = words.prefetchable & 0xf == 1;
        let (upper_base, upper_limit) = match wide {
            true => words.prefetchable_upper,
            false => (0, 0),
        };
        let base = u64::from(words.prefetchable & 0xfff0) << 16 | u64::from(upper_base) << 32;
        let limit = u64::from(words.prefetchable >> 16 & 0xfff0) << 16
            | 0xf_ffff
            | u64::from(upper_limit) << 32;
        let prefetchable = (base <= limit).then(|| base..limit.saturating_add(1));
        Some(Self {
            buses: secondary..=subordinate,
            memory,
            prefetchable,
            subtractive: words.class_revision >> 8 == SUBTRACTIVE_BRIDGE,
            vga: words.control & VGA_ENABLE != 0,
        })
    }

    /// The buses below the bridge.
    pub fn buses(&self) -> RangeInclusive<u8> {
        self.buses.clone()
    }

    /// Whether the bridge forwards any byte of `span`.
    pub fn forwards(&self, span: &Range<u64>) -> bool {
        let overlaps = |window: &Range<u64>| window.start < span.end && span.start < window.end;
        self.subtractive
            || self.memory.as_ref().is_some_and(overlaps)
            || self.prefetchable.as_ref().is_some_and(overlaps)
            || (self.vga && overlaps(&VGA_MEMORY))
    }
}

/// The buses of one PCI segment whose functions cannot decode the firmware's
/// screen. Empty, every function may: the old rule, that any GPU may show the
/// screen, then holds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BusesApart {
    segment: u16,
    buses: [u64; 4],
}

impl BusesApart {
    /// No bus is known to be apart.
    pub const fn none() -> Self {
        Self {
            segment: 0,
            buses: [0; 4],
        }
    }

    /// For `segment`, empty until [`Self::mark`] adds buses.
    pub const fn on(segment: u16) -> Self {
        Self {
            segment,
            buses: [0; 4],
        }
    }

    /// Mark `bus` of `segment` apart when any bridge in `upstream`, the
    /// bridges between its root and it, forwards no byte of `screen`. An
    /// empty `screen` or another segment marks nothing.
    pub fn mark<'a>(
        &mut self,
        segment: u16,
        bus: u8,
        upstream: impl IntoIterator<Item = &'a BridgeWindows>,
        screen: &Range<u64>,
    ) {
        if segment != self.segment || screen.start >= screen.end {
            return;
        }
        if upstream.into_iter().any(|bridge| !bridge.forwards(screen)) {
            self.buses[usize::from(bus / 64)] |= 1 << (bus % 64);
        }
    }

    /// Whether functions on `bus` of `segment` cannot decode the screen.
    pub fn holds(&self, segment: u16, bus: u8) -> bool {
        segment == self.segment && self.buses[usize::from(bus / 64)] & 1 << (bus % 64) != 0
    }

    /// How many buses are apart.
    pub fn count(&self) -> u32 {
        self.buses.iter().map(|word| word.count_ones()).sum()
    }
}

/// Whether a GPU claimed at `segment`:`bus` must end the firmware's screen
/// before its BARs are sized and it is reset, when no function's BAR was
/// matched to the screen: unless its bus is apart from the screen, it may be
/// the one showing it.
pub fn gpu_may_show(apart: &BusesApart, segment: u16, bus: u8) -> bool {
    !apart.holds(segment, bus)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A root port to buses `secondary..=subordinate` forwarding memory
    /// `memory` (MiB) and 64-bit prefetchable `prefetchable` (MiB).
    fn port(
        secondary: u8,
        subordinate: u8,
        memory: Option<(u64, u64)>,
        prefetchable: Option<(u64, u64)>,
    ) -> BridgeWords {
        let window = |range: Option<(u64, u64)>| match range {
            Some((base, limit)) => (
                (base << 4) as u32 & 0xfff0 | ((limit << 4) as u32 & 0xfff0) << 16,
                ((base << 20) >> 32) as u32,
                ((limit << 20) >> 32) as u32,
            ),
            // Base above limit: closed.
            None => (0x0000_fff0, 0, 0),
        };
        let (memory, _, _) = window(memory);
        let (prefetchable, upper_base, upper_limit) = window(prefetchable);
        BridgeWords {
            class_revision: 0x0604_0000,
            buses: u32::from_le_bytes([0, secondary, subordinate, 0]),
            memory,
            prefetchable: prefetchable | 1,
            prefetchable_upper: (upper_base, upper_limit),
            control: 0,
        }
    }

    const MIB: u64 = 1 << 20;

    #[test]
    fn windows_decode_memory_and_wide_prefetchable_ranges() {
        let bridge =
            BridgeWindows::from_words(port(1, 3, Some((0xa00, 0xa0f)), Some((0x6_0000, 0x6_0fff))))
                .unwrap();
        assert_eq!(bridge.buses(), 1..=3);
        assert_eq!(bridge.memory, Some(0xa00 * MIB..0xa10 * MIB));
        assert_eq!(bridge.prefetchable, Some(0x6_0000 * MIB..0x6_1000 * MIB));
        assert!(bridge.forwards(&(0xa08 * MIB..0xa09 * MIB)));
        assert!(bridge.forwards(&(0x6_0000 * MIB - 1..0x6_0000 * MIB + 1)));
        assert!(!bridge.forwards(&(0x4_0000 * MIB..0x4_0000 * MIB + 8 * MIB)));
        assert!(!bridge.forwards(&(0xa10 * MIB..0xa20 * MIB)));
    }

    #[test]
    fn closed_windows_unassigned_buses_vga_and_subtractive_decode() {
        let closed = BridgeWindows::from_words(port(2, 2, None, None)).unwrap();
        assert_eq!(
            (closed.memory.clone(), closed.prefetchable.clone()),
            (None, None)
        );
        assert!(!closed.forwards(&(0..u64::MAX)));
        // No buses: it forwards to none, so it says nothing of any bus.
        assert_eq!(BridgeWindows::from_words(port(0, 0, None, None)), None);
        assert_eq!(BridgeWindows::from_words(port(4, 3, None, None)), None);
        // VGA Enable forwards the legacy window only.
        let mut words = port(2, 2, None, None);
        words.control = VGA_ENABLE;
        let vga = BridgeWindows::from_words(words).unwrap();
        assert!(vga.forwards(&(0xb_8000..0xb_9000)));
        assert!(!vga.forwards(&(0xc_0000..0x10_0000)));
        // A subtractive bridge forwards whatever it is not told of.
        let mut words = port(2, 2, None, None);
        words.class_revision = 0x0604_0100;
        assert!(BridgeWindows::from_words(words).unwrap().forwards(&(0..1)));
        // A 32-bit prefetchable window ignores the upper dwords.
        let mut words = port(2, 2, None, Some((0xc00, 0xc0f)));
        words.prefetchable &= !0xf;
        words.prefetchable_upper = (0x40, 0x40);
        let narrow = BridgeWindows::from_words(words).unwrap();
        assert_eq!(narrow.prefetchable, Some(0xc00 * MIB..0xc10 * MIB));
    }

    #[test]
    fn a_bus_below_any_bridge_that_forwards_none_of_the_screen_is_apart() {
        // An integrated GPU's screen at 256 GiB on bus 0; the NVIDIA GPU on
        // bus 2 behind a root port whose windows lie elsewhere.
        let screen = 0x40_0000_0000..0x40_007e_9000;
        let nvidia_port =
            BridgeWindows::from_words(port(2, 2, Some((0xa00, 0xa1f)), Some((0x6_0000, 0x6_1fff))))
                .unwrap();
        let mut apart = BusesApart::on(0);
        apart.mark(0, 2, [&nvidia_port], &screen);
        // Bus 0 has no bridge above it, so it may hold the screen.
        apart.mark(0, 0, [], &screen);
        assert!(apart.holds(0, 2));
        assert!(!apart.holds(0, 0));
        assert!(!apart.holds(1, 2));
        assert_eq!(apart.count(), 1);
        assert!(!gpu_may_show(&apart, 0, 2));
        assert!(gpu_may_show(&apart, 0, 0));
        assert!(gpu_may_show(&apart, 0, 3));
    }

    #[test]
    fn a_screen_inside_the_gpu_ports_window_keeps_the_gpu_its_possible_owner() {
        // A desktop whose screen is in the NVIDIA GPU's BAR, which the
        // firmware's descriptors failed to name: every bridge above it
        // forwards the screen, so the GPU may show it and ends it first.
        let screen = 0x6_0000 * MIB + 0x100_0000..0x6_0000 * MIB + 0x200_0000;
        let switch_up =
            BridgeWindows::from_words(port(1, 4, Some((0xa00, 0xa3f)), Some((0x6_0000, 0x6_3fff))))
                .unwrap();
        let switch_down =
            BridgeWindows::from_words(port(3, 3, Some((0xa00, 0xa0f)), Some((0x6_0000, 0x6_0fff))))
                .unwrap();
        let mut apart = BusesApart::on(0);
        apart.mark(0, 3, [&switch_down, &switch_up], &screen);
        assert!(gpu_may_show(&apart, 0, 3));
        // A sibling below the same upstream port but its own closed port is
        // apart: one bridge on the path that forwards none is enough.
        let closed = BridgeWindows::from_words(port(4, 4, None, None)).unwrap();
        apart.mark(0, 4, [&closed, &switch_up], &screen);
        assert!(apart.holds(0, 4));
        // An empty screen or another segment marks nothing.
        let mut other = BusesApart::on(1);
        other.mark(0, 4, [&closed], &screen);
        other.mark(1, 4, [&closed], &(5..5));
        assert_eq!(other, BusesApart::on(1));
        assert_eq!(BusesApart::none().count(), 0);
        assert!(gpu_may_show(&BusesApart::none(), 0, 4));
    }

    #[test]
    fn every_bus_number_has_its_own_bit() {
        let closed = BridgeWindows::from_words(port(1, 255, None, None)).unwrap();
        let mut apart = BusesApart::on(0);
        for bus in [1, 63, 64, 127, 128, 191, 192, 255] {
            apart.mark(0, bus, [&closed], &(0x1000..0x2000));
        }
        assert_eq!(apart.count(), 8);
        assert!(apart.holds(0, 255) && apart.holds(0, 64) && !apart.holds(0, 65));
    }
}
