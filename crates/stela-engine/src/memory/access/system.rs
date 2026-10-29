//! Source-system SCA reads whose actual canonical host RAM is read/write.
//! The CX16 alternative is never permission to perform a guest write.
use super::{
    AccessError, SCA_BYTES, SCA_OFFSET_MASK, compare_exchange_part, read_part, validate_part,
};
use stela_compiler::TargetCpu;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Recipe {
    Load,
    CompareExchange16,
}

/// A concrete native recipe and exact host footprint. Construction classifies
/// code only; `read` separately requires actual target/mapping/gate authority.
#[derive(Debug, Clone, Copy)]
pub(in crate::memory) struct Read {
    pointer: usize,
    bytes: usize,
    target: TargetCpu,
    recipe: Recipe,
    footprint: (usize, usize),
}
impl Read {
    pub(in crate::memory) fn prepare(
        pointer: usize,
        bytes: usize,
        target: TargetCpu,
    ) -> Result<Self, AccessError> {
        validate_part(pointer, bytes)?;
        match super::read_footprint(pointer, bytes, target) {
            Ok(footprint) => Ok(Self {
                pointer,
                bytes,
                target,
                recipe: Recipe::Load,
                footprint,
            }),
            Err(AccessError::MissingAtomicLoad16) if target.supports(TargetCpu::Cx16) => Ok(Self {
                pointer,
                bytes,
                target,
                recipe: Recipe::CompareExchange16,
                footprint: (pointer & !SCA_OFFSET_MASK, SCA_BYTES),
            }),
            Err(error) => Err(error),
        }
    }

    pub(in crate::memory) fn footprint(self) -> (usize, usize) {
        self.footprint
    }
    pub(in crate::memory) fn writes_back(self) -> bool {
        self.recipe == Recipe::CompareExchange16
    }

    /// # Safety
    /// The actual current host admits `target`. The entire footprint is pinned,
    /// coherent WB, readable native RAM. For `writes_back`, it is also writable,
    /// every touched physical granule is held under the same all-writer gate,
    /// and an unchanged-value host writeback is permitted. Device/external DMA,
    /// host protection changes and racing Rust references are excluded. This
    /// operation neither publishes a source store nor invalidates reservations.
    pub(in crate::memory) unsafe fn read(self) -> Result<u128, AccessError> {
        if self.recipe == Recipe::Load {
            // SAFETY: caller retains the exact readable load footprint/target.
            return unsafe { read_part(self.pointer as *const u8, self.bytes, self.target) };
        }
        // A single locked CMPXCHG16B returns the SCA snapshot. Zero is replaced
        // only by zero; failure writes the observed old value. Host RW rights
        // are required even for a source read-only mapping. No retry or split
        // plain pair load is used, and neighboring bytes are unchanged.
        // SAFETY: Recipe selection checked CX16 and aligned the full SCA footprint.
        // read's caller pins it with read/write rights and holds its all-writer gate.
        let snapshot = unsafe {
            compare_exchange_part(self.footprint.0 as *mut u8, SCA_BYTES, 0, 0, self.target)
        }?;
        let shift = (self.pointer & SCA_OFFSET_MASK) * u8::BITS as usize;
        let mask = u128::MAX >> ((SCA_BYTES - self.bytes) * u8::BITS as usize);
        Ok((snapshot >> shift) & mask)
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::*;
    use core::cell::UnsafeCell;
    #[repr(align(16))]
    struct Storage(UnsafeCell<[u8; 32]>);
    // SAFETY: private test storage has no racing Rust references; native
    // accesses use the monitor's actual physical writer/observer gates.
    unsafe impl Send for Storage {}
    // SAFETY: shared references rely on the same argument as `Send` above.
    unsafe impl Sync for Storage {}

    #[test]
    fn actual_cx16_reads_preserve_every_byte_at_all_supported_offsets_and_widths() {
        let target = TargetCpu::X86_64_V2;
        if !target.supported() {
            return;
        }
        for fill in [0, 0x5a, 0xff] {
            let original = core::array::from_fn(|i| fill ^ i as u8);
            let storage = alloc::sync::Arc::new(Storage(UnsafeCell::new(original)));
            let monitor =
                crate::memory::monitor::MonitorDomain::<Storage, (), ()>::new(64, 4).unwrap();
            let range =
                crate::memory::monitor::WriteRange::new(alloc::sync::Arc::clone(&storage), 0, 32)
                    .unwrap();
            let base = storage.0.get().cast::<u8>() as usize;
            for bytes in [1, 2, 4, 8, 16] {
                for offset in 0..16 {
                    let read = Read::prepare(base + offset, bytes, target);
                    if offset + bytes > 16 {
                        assert!(matches!(read, Err(AccessError::CrossesScaQuantity)));
                        continue;
                    }
                    let read = read.unwrap();
                    assert_eq!(read.writes_back(), offset % 8 + bytes > 8);
                    // SAFETY: private initialized RW storage with no competing
                    // access; this scope owns the whole physical footprint.
                    let actual = monitor
                        .with_observer(&range, || unsafe { read.read() })
                        .unwrap();
                    let mut expected = [0; 16];
                    expected[..bytes].copy_from_slice(&original[offset..offset + bytes]);
                    assert_eq!(actual, u128::from_le_bytes(expected));
                    // SAFETY: no access is in flight, so reading the storage races nothing.
                    assert_eq!(unsafe { *storage.0.get() }, original);
                }
            }
        }
    }

    #[test]
    fn optional_plain_load_keeps_read_only_footprint_and_baseline_never_invents_cx16() {
        assert!(matches!(
            Read::prepare(0x1000, 16, TargetCpu::Baseline),
            Err(AccessError::MissingAtomicLoad16)
        ));
        let plain = Read::prepare(0x1001, 8, TargetCpu::AtomicLoad16).unwrap();
        assert!(!plain.writes_back());
        assert_eq!(plain.footprint(), (0x1000, 16));
        let fallback = Read::prepare(0x1001, 8, TargetCpu::X86_64_V2).unwrap();
        assert!(fallback.writes_back());
        assert_eq!(fallback.footprint(), plain.footprint());
    }
}
