//! The Apple DART revision-1 SMMU state-capture view (`UMMS`).
//!
//! This is not an ARM architectural SMMU programming interface. The 26A434
//! kernel's `_SMMU_BUILD_PARAMS` (file 0x2f1ed30) and SPTM instance validation
//! (file 0xcabb8) read +0; its low 17 bits count capture words. Revision 1
//! selects banks of 2048 words at +0x80 and reads +0x2000..0x3ffc (SPTM
//! 0xc9018..0xc9054, kernel 0x2f1a488..0x2f1a51c). From revision 2.1 the
//! count and access interface instead belong to the paired TRAD instance.
//!
//! `Dart` caches no translations and exposes no hardware state-capture
//! entries. Its paired view therefore reports zero capture words, as a
//! capability of the native model, not a measured register of an Apple chip.
//! No selection or capture data exists; those accesses refuse, as do unknown
//! registers, writes to identification and non-word reads. Supporting cached
//! generations requires a different coherent count, selector and payload
//! implementation. See `docs/research/dart-iommu.md`.
use super::super::bus::{Access, Direction, MmioDevice, MmioError, Width, refuse};

const NAME: &str = "dart-smmu";
const BUILD_PARAMS: u64 = 0;
/// The cacheless DART has no capture store; do not invent empty valid entries.
const CAPTURE_WORDS: u32 = 0;

/// The read-only capture capability of the native cacheless revision-1 DART.
#[derive(Debug, Clone, Copy, Default)]
pub struct SmmuBlock;

impl MmioDevice for SmmuBlock {
    fn name(&self) -> &'static str {
        NAME
    }

    fn read(&mut self, offset: u64, width: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        if offset == BUILD_PARAMS && width == Width::Word {
            Ok(u64::from(CAPTURE_WORDS))
        } else {
            Err(refuse(
                NAME,
                offset,
                width,
                Direction::Read,
                "cacheless DART SMMU has only its 32-bit capture-count identification",
            ))
        }
    }

    fn write(
        &mut self,
        offset: u64,
        width: Width,
        _: u64,
        _: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        Err(refuse(
            NAME,
            offset,
            width,
            Direction::Write,
            "cacheless DART SMMU has no capture selector or writable state",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::interrupt::InterruptLatch;

    #[test]
    fn capture_count_matches_the_absent_store_and_never_fabricates_a_dump() {
        let mut sink = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut sink);
        let mut smmu = SmmuBlock;
        let words = smmu.read(BUILD_PARAMS, Width::Word, &mut access).unwrap() & 0x1ffff;
        assert_eq!(words, 0);
        // SPTM's ceil(count/2048) page bound permits no selector value.
        assert_eq!(words.div_ceil(2048), 0);
        assert!(smmu.write(0x80, Width::Word, 0, &mut access).is_err());
        for offset in [0x2000, 0x2004, 0x3ffc] {
            assert!(smmu.read(offset, Width::Word, &mut access).is_err());
        }
        // Identification is immutable even for a zero write.
        assert!(
            smmu.write(BUILD_PARAMS, Width::Word, 0, &mut access)
                .is_err()
        );
        assert_eq!(smmu.read(BUILD_PARAMS, Width::Word, &mut access), Ok(0));
    }

    #[test]
    fn other_widths_and_generation_views_refuse_by_name() {
        let mut sink = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut sink);
        let mut smmu = SmmuBlock;
        for (offset, width) in [
            (0, Width::Byte),
            (0, Width::Half),
            (0, Width::Double),
            (4, Width::Word),
            (0x18, Width::Word),
            (0x88, Width::Word),
            (0x94, Width::Word),
        ] {
            assert!(matches!(
                smmu.read(offset, width, &mut access),
                Err(MmioError::Unsupported { device: NAME, .. })
            ));
        }
    }
}
