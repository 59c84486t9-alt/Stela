// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2020-2023 MediaTek Inc.
//! Serialized chip-register mapping over the owned PCI BAR. Fixed
//! windows and L1 remapping follow mt7921/mt7925 PCI bus operations. The
//! unchecked Connac3 L2 path remains an explicit unsupported requirement.
use super::identity::Chip;
use alloc::sync::Arc;
use core::ptr::NonNull;

mod maps;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Misaligned,
    OutsideBar,
    UnsupportedAddress(u32),
    AccessFailed,
    SelectorReadback { expected: u32, actual: u32 },
    Poisoned,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MediaTek register access: {self:?}")
    }
}
impl core::error::Error for Error {}

/// Exclusive BAR access, with completed volatile CPU MMIO operations.
///
/// # Safety
/// The implementation owns the real selected powered PCI function and its
/// uncached BAR mapping/reservation for this object's entire lifetime. Reads
/// and writes access that function, preserve PCIe ordering and bounds, and
/// exclude competing firmware, OS, IRQ/deferred-worker and reset accesses.
/// A read flushes prior posted writes to this function. An error may be
/// uncertain; it never synthesizes a register observation or successful store.
pub unsafe trait BarIo: 'static {
    fn read32(&mut self, offset: u32) -> Result<u32, Error>;
    fn write32(&mut self, offset: u32, value: u32) -> Result<(), Error>;
}

/// Native volatile BAR operations keeping the PCI claim and mapping.
/// This is a consumer of that claim, rather than a new PCI admission service.
pub struct MmioBar {
    base: NonNull<u8>,
    bytes: usize,
    _owner: Arc<dyn core::any::Any>,
}
impl MmioBar {
    /// # Safety
    /// `base..base+bytes` is the exclusive uncached BAR of the observed
    /// MT7921/22/25 requester. `owner` keeps that real function reservation,
    /// power and mapping through its final Drop. The mapping has no conflicting
    /// aliases or competing MMIO users; the PCIe ordering contract of `BarIo`
    /// holds. An unrelated token does not meet this ownership requirement.
    pub unsafe fn from_owned_window(
        base: NonNull<u8>,
        bytes: usize,
        owner: Arc<dyn core::any::Any>,
    ) -> Result<Self, Error> {
        if base.as_ptr() as usize & 3 != 0 {
            return Err(Error::Misaligned);
        }
        if bytes < 4 || (base.as_ptr() as usize).checked_add(bytes).is_none() {
            return Err(Error::OutsideBar);
        }
        Ok(Self {
            base,
            bytes,
            _owner: owner,
        })
    }
    fn pointer(&self, offset: u32) -> Result<*mut u32, Error> {
        if offset & 3 != 0 {
            return Err(Error::Misaligned);
        }
        let offset = usize::try_from(offset).map_err(|_| Error::OutsideBar)?;
        if offset.checked_add(4).is_none_or(|end| end > self.bytes) {
            return Err(Error::OutsideBar);
        }
        // SAFETY: construction owns this live mapping; the complete aligned
        // u32 access was checked against its bounds above.
        Ok(unsafe { self.base.as_ptr().add(offset).cast() })
    }
}
// SAFETY: the constructor's mapping/PCI ownership contract is held
// by the Arc; each complete volatile access checks its aligned BAR bounds.
unsafe impl BarIo for MmioBar {
    fn read32(&mut self, offset: u32) -> Result<u32, Error> {
        // SAFETY: `pointer` checked the aligned access lies inside the owned BAR.
        Ok(u32::from_le(unsafe {
            self.pointer(offset)?.read_volatile()
        }))
    }
    fn write32(&mut self, offset: u32, value: u32) -> Result<(), Error> {
        // SAFETY: `pointer` checked the aligned access lies inside the owned BAR.
        unsafe { self.pointer(offset)?.write_volatile(value.to_le()) };
        Ok(())
    }
}

pub struct Registers<I: BarIo> {
    chip: Chip,
    io: I,
    backup_l1: Option<u32>,
    poisoned: bool,
}
impl<I: BarIo> Registers<I> {
    /// # Safety
    /// `chip` was obtained from the live PCI identity and hardware
    /// revision of `io`'s exclusively owned requester. No other path may use
    /// its dynamic remap window or directly change the remap registers while
    /// this register file exists. This does not stop DMA or drain IRQ work.
    pub unsafe fn new(chip: Chip, io: I) -> Self {
        Self {
            chip,
            io,
            backup_l1: None,
            poisoned: false,
        }
    }
    pub fn chip(&self) -> Chip {
        self.chip
    }
    #[cfg(test)]
    pub(in crate::net::wifi::mediatek) fn test_io(&mut self) -> &mut I {
        &mut self.io
    }
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }
    fn checked<T>(&mut self, result: Result<T, Error>) -> Result<T, Error> {
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    /// Restore a pending Connac3 L1 remap before another physical mapping or
    /// an explicit controller handoff. The saved value may legitimately be
    /// zero; unlike the donor's zero sentinel, Option preserves that state.
    /// A failed restore keeps its saved value and poisons further accesses.
    pub fn restore_remap(&mut self) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        if let Some(value) = self.backup_l1 {
            let result = self.io.write32(0x155024, value);
            self.checked(result)?;
            // Complete the posted restore before an explicit handoff.
            let result = self.io.read32(0x155024);
            let actual = self.checked(result)?;
            if actual & 0xffff0000 != value & 0xffff0000 {
                self.poisoned = true;
                return Err(Error::SelectorReadback {
                    expected: value,
                    actual,
                });
            }
            self.backup_l1 = None;
        }
        Ok(())
    }
    fn resolve(&mut self, address: u32) -> Result<u32, Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        if address & 3 != 0 {
            return Err(Error::Misaligned);
        }
        let connac3 = self.chip == Chip::Mt7925;
        if address < if connac3 { 0x200000 } else { 0x100000 } {
            return Ok(address);
        }
        if connac3 {
            self.restore_remap()?;
        }
        let fixed = if connac3 {
            maps::CONNAC3
        } else {
            maps::CONNAC2
        };
        for &(physical, mapped, size) in fixed {
            // A full u32 must lie in the window. The donor's `ofs > size`
            // admits one-past-end and can hide the next adjacent mapping.
            if let Some(offset) = address.checked_sub(physical)
                && offset.checked_add(4).is_some_and(|end| end <= size)
            {
                return Ok(mapped + offset);
            }
        }
        if !((0x18000000..0x18c00000).contains(&address)
            || (0x70000000..0x78000000).contains(&address)
            || (0x7c000000..0x7c400000).contains(&address))
        {
            // Connac2 returns BAR offset zero for unknown registers; Connac3
            // uses L2. Neither is silently substituted in this implementation.
            return Err(Error::UnsupportedAddress(address));
        }
        let register = if connac3 { 0x155024 } else { 0xfe24c };
        let result = self.io.read32(register);
        let old = self.checked(result)?;
        if connac3 {
            self.backup_l1 = Some(old);
        }
        // Connac3 first saves the selector, then performs the donor RMW read.
        let old = if connac3 {
            let result = self.io.read32(register);
            self.checked(result)?
        } else {
            old
        };
        let value = if connac3 {
            (old & 0xffff) | (address & 0xffff0000)
        } else {
            (old & 0xffff0000) | (address >> 16)
        };
        let result = self.io.write32(register, value);
        self.checked(result)?;
        // A real read pushes the posted selector write before window access.
        let result = self.io.read32(register);
        let actual = self.checked(result)?;
        let mask = if connac3 { 0xffff0000 } else { 0xffff };
        if actual & mask != value & mask {
            self.poisoned = true;
            return Err(Error::SelectorReadback {
                expected: value,
                actual,
            });
        }
        Ok(if connac3 { 0x130000 } else { 0x40000 } + (address & 0xffff))
    }
    pub fn read32(&mut self, address: u32) -> Result<u32, Error> {
        let offset = self.resolve(address)?;
        let result = self.io.read32(offset);
        self.checked(result)
    }
    pub fn write32(&mut self, address: u32, value: u32) -> Result<(), Error> {
        let offset = self.resolve(address)?;
        let result = self.io.write32(offset, value);
        self.checked(result)
    }
    /// Donor read/modify/write semantics: `(old & !mask) | value`. `value`
    /// may set bits outside `mask` (as mt76_set does).
    pub fn modify32(&mut self, address: u32, mask: u32, value: u32) -> Result<u32, Error> {
        let offset = self.resolve(address)?;
        let result = self.io.read32(offset);
        let old = self.checked(result)?;
        let value = (old & !mask) | value;
        let result = self.io.write32(offset, value);
        self.checked(result)?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{collections::BTreeMap, vec::Vec};
    extern crate std;

    #[derive(Default)]
    struct Model {
        values: BTreeMap<u32, u32>,
        operations: Vec<(u32, u32, u32)>,
        fail_at: Option<usize>,
        ignore_selector_store: bool,
    }
    // SAFETY: this serialized register model owns its state and logs
    // model operations; it makes no physical PCI or power validation claim.
    unsafe impl BarIo for Model {
        fn read32(&mut self, offset: u32) -> Result<u32, Error> {
            let value = self
                .values
                .get(&offset)
                .copied()
                .unwrap_or(offset ^ 0x5aa5c0de);
            self.operations.push((0, offset, value));
            if self.fail_at == Some(self.operations.len()) {
                return Err(Error::AccessFailed);
            }
            Ok(value)
        }
        fn write32(&mut self, offset: u32, value: u32) -> Result<(), Error> {
            self.operations.push((1, offset, value));
            if self.fail_at == Some(self.operations.len()) {
                return Err(Error::AccessFailed);
            }
            if !(self.ignore_selector_store && matches!(offset, 0xfe24c | 0x155024)) {
                self.values.insert(offset, value);
            }
            Ok(())
        }
    }
    fn model(chip: Chip, selector: u32) -> Registers<Model> {
        let mut io = Model::default();
        io.values.insert(
            if chip == Chip::Mt7925 {
                0x155024
            } else {
                0xfe24c
            },
            selector,
        );
        // SAFETY: this register file exclusively owns one chip's modeled BAR.
        unsafe { Registers::new(chip, io) }
    }
    #[test]
    fn direct_fixed_and_full_word_window_bounds_are_explicit() {
        for chip in [Chip::Mt7921, Chip::Mt7922, Chip::Mt7925] {
            let mut r = model(chip, 0);
            assert_eq!(r.read32(0x104), Ok(0x104 ^ 0x5aa5c0de));
            assert_eq!(r.read32(0x54000208), Ok(0x2208 ^ 0x5aa5c0de));
            assert_eq!(r.read32(0x820dfffc), Ok(0x3fffc ^ 0x5aa5c0de));
            assert_eq!(r.read32(0x820d0002), Err(Error::Misaligned));
            assert_eq!(
                r.read32(0x820e0400),
                Err(Error::UnsupportedAddress(0x820e0400))
            );
        }
    }
    #[test]
    fn fixed_adjacent_window_does_not_use_donor_one_past_endpoint() {
        let mut r = model(Chip::Mt7925, 0);
        // At the exact end of PLE, BN1 MUCOP has a different physical map.
        assert_eq!(r.read32(0x820c4000), Ok(0xa8000 ^ 0x5aa5c0de));
        let mut r = model(Chip::Mt7921, 0);
        assert_eq!(
            r.read32(0x820c4000),
            Err(Error::UnsupportedAddress(0x820c4000))
        );
    }
    #[test]
    fn l1_selector_flush_restore_and_zero_backup_preserve_real_state() {
        for old in [0, 0xdec0beef] {
            for chip in [Chip::Mt7921, Chip::Mt7922, Chip::Mt7925] {
                let mut r = model(chip, old);
                let connac3 = chip == Chip::Mt7925;
                let sel = if connac3 { 0x155024 } else { 0xfe24c };
                let window = if connac3 { 0x130140 } else { 0x40140 };
                let value = if connac3 {
                    (old & 0xffff) | 0x18000000
                } else {
                    (old & 0xffff0000) | 0x1800
                };
                assert_eq!(r.read32(0x18000140), Ok(window ^ 0x5aa5c0de));
                assert_eq!(
                    r.io.operations.last(),
                    Some(&(0, window, window ^ 0x5aa5c0de))
                );
                assert!(
                    r.io.operations
                        .windows(2)
                        .any(|v| v == [(1, sel, value), (0, sel, value)])
                );
                let n = r.io.operations.len();
                // Donor direct BAR accesses preserve the pending selection.
                r.read32(0x100).unwrap();
                assert_eq!(r.io.operations.len(), n + 1);
                r.read32(0x54000208).unwrap();
                assert_eq!(r.io.values[&sel], if connac3 { old } else { value });
                assert_eq!(r.backup_l1, None);
            }
        }
    }
    #[test]
    fn unsupported_l2_and_failed_remap_never_alias_bar_zero_or_retry_unknown_state() {
        for chip in [Chip::Mt7921, Chip::Mt7925] {
            let mut r = model(chip, 0xdec0beef);
            assert_eq!(
                r.read32(0xdead0000),
                Err(Error::UnsupportedAddress(0xdead0000))
            );
            assert!(r.io.operations.is_empty());
            for fail_at in 1..=if chip == Chip::Mt7925 { 7 } else { 4 } {
                let mut r = model(chip, 0);
                r.io.fail_at = Some(fail_at);
                let mut result = r.read32(0x18000140).map(|_| ());
                if result.is_ok() {
                    result = r.restore_remap();
                }
                assert_eq!(result, Err(Error::AccessFailed));
                let n = r.io.operations.len();
                assert_eq!(r.read32(0x104), Err(Error::Poisoned));
                assert_eq!(r.restore_remap(), Err(Error::Poisoned));
                assert_eq!(r.io.operations.len(), n);
            }
        }
    }
    #[test]
    fn modify_uses_one_resolved_window_and_donor_unmasked_set_semantics() {
        let mut r = model(Chip::Mt7925, 0xdec0beef);
        r.io.values.insert(0x130140, 0xf0f0);
        assert_eq!(r.modify32(0x18000140, 0xf0, 0x10001), Ok(0x1f001));
        assert_eq!(
            r.io.operations
                .iter()
                .filter(|v| v.0 == 1 && v.1 == 0x155024)
                .count(),
            1
        );
        assert_eq!(r.io.values[&0x130140], 0x1f001);
    }
    #[test]
    fn selector_readback_is_required_without_rejecting_generic_all_ones_data() {
        for chip in [Chip::Mt7921, Chip::Mt7925] {
            let mut r = model(chip, 0);
            r.io.values.insert(0x2208, u32::MAX);
            assert_eq!(r.read32(0x54000208), Ok(u32::MAX));
            r.io.ignore_selector_store = true;
            assert!(matches!(
                r.read32(0x18000140),
                Err(Error::SelectorReadback { .. })
            ));
            assert!(r.is_poisoned());
            assert!(
                !r.io
                    .operations
                    .iter()
                    .any(|v| matches!(v.1, 0x40140 | 0x130140))
            );
        }
        let mut r = model(Chip::Mt7925, 0);
        r.read32(0x18000140).unwrap();
        r.io.ignore_selector_store = true;
        assert!(matches!(
            r.restore_remap(),
            Err(Error::SelectorReadback { .. })
        ));
        assert_eq!(r.backup_l1, Some(0));
        assert!(r.is_poisoned());
    }
    #[test]
    fn native_window_checks_complete_bounds_and_retains_the_real_mapping_owner() {
        let owner = Arc::new(std::sync::Mutex::new([0u32; 4]));
        let weak = Arc::downgrade(&owner);
        let base = {
            let mut bytes = owner.lock().unwrap();
            NonNull::from(&mut *bytes).cast::<u8>()
        };
        // SAFETY: this exclusively accessed RAM fixture models the owned UC
        // BAR lifetime for volatile/bounds testing, not physical validation.
        let mut bar = unsafe { MmioBar::from_owned_window(base, 16, owner) }.unwrap();
        bar.write32(12, 0x12345678).unwrap();
        assert_eq!(bar.read32(12), Ok(0x12345678));
        assert_eq!(bar.write32(13, 0), Err(Error::Misaligned));
        assert_eq!(bar.read32(16), Err(Error::OutsideBar));
        assert_eq!(bar.write32(u32::MAX - 3, 1), Err(Error::OutsideBar));
        assert!(weak.upgrade().is_some());
        drop(bar);
        assert!(weak.upgrade().is_none());
    }
    #[test]
    #[ignore = "oracle: STELA_MT792X_REGISTER_ORACLE"]
    fn unchanged_pinned_register_mapper_matches_valid_windows_and_mmio_operations() {
        let root =
            std::env::var_os("STELA_MT792X_REGISTER_ORACLE").expect("reference trace directory");
        for chip in [Chip::Mt7921, Chip::Mt7922, Chip::Mt7925] {
            let name = match chip {
                Chip::Mt7921 => "7921",
                Chip::Mt7922 => "7922",
                Chip::Mt7925 => "7925",
            };
            let bytes =
                std::fs::read(std::path::Path::new(&root).join(format!("mt{name}.bin"))).unwrap();
            let mut at = 0;
            let word = |at: &mut usize| {
                let result = u32::from_le_bytes(bytes[*at..*at + 4].try_into().unwrap());
                *at += 4;
                result
            };
            let mut records = 0;
            while at < bytes.len() {
                let address = word(&mut at);
                let expected = word(&mut at);
                let count = word(&mut at);
                let mut r = model(chip, 0xdec0beef);
                assert_eq!(
                    r.resolve(address),
                    Ok(expected),
                    "chip {name} address {address:x}"
                );
                let actual = core::mem::take(&mut r.io.operations);
                assert_eq!(actual.len(), count as usize, "address {address:x}");
                for operation in actual {
                    assert_eq!(operation, (word(&mut at), word(&mut at), word(&mut at)));
                }
                records += 1;
            }
            assert!(records >= 150);
        }
    }
}
