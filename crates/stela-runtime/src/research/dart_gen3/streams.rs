//! Native per-SID enable commands and actual saved enable state.
//!
//! mBoot file158e40..158ec0 selects c00/c20 for set/clear commands.
//! SPTM d02c4..d030c saves c00 words, d037c..d03e8 clears translation
//! streams and cf8a8..cf918 restores by writing the saved words to c00.
//! Readback of c20, physical reset/retention and store completion remain
//! separate requirements; no empty observation is synthesized for them.
use alloc::vec::Vec;

pub const ENABLE: u64 = 0xc00;
pub const DISABLE: u64 = 0xc20;
const REGISTER_WORDS: usize = 8;

pub(super) fn word(offset: u64, base: u64) -> Result<usize, &'static str> {
    let relative = offset
        .checked_sub(base)
        .filter(|relative| *relative < (REGISTER_WORDS * 4) as u64)
        .ok_or("gen3 DART stream register is outside its native word window")?;
    if !relative.is_multiple_of(4) {
        return Err("gen3 DART stream register requires an aligned 32-bit word");
    }
    Ok((relative / 4) as usize)
}

pub(super) fn validate(streams: usize, word: usize, bits: u32) -> Result<(), &'static str> {
    if !(1..=256).contains(&streams) || word >= streams.div_ceil(32) {
        return Err("gen3 DART stream word is outside the actual SID count");
    }
    let count = (streams - word * 32).min(32);
    let valid = u32::MAX >> (32 - count);
    if bits & !valid != 0 {
        return Err("gen3 DART stream command names an out-of-profile SID");
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Command {
    word: usize,
    bits: u32,
    enabled: bool,
}

impl Command {
    /// Decode one 32-bit native command; the register boundary owns access
    /// width and ordering. Applying it validates the receiving SID count.
    pub fn decode(offset: u64, bits: u32) -> Result<Self, &'static str> {
        if !offset.is_multiple_of(4) {
            return Err("gen3 DART stream command requires an aligned 32-bit word");
        }
        let (word, enabled) = match word(offset, ENABLE) {
            Ok(word) => (word, true),
            Err(_) => (word(offset, DISABLE)?, false),
        };
        Ok(Self {
            word,
            bits,
            enabled,
        })
    }

    pub const fn word(self) -> usize {
        self.word
    }

    pub const fn bits(self) -> u32 {
        self.bits
    }

    pub const fn enabled(self) -> bool {
        self.enabled
    }
}

/// Actual enabled bits saved before translation-stream shutdown. There is
/// no default or zero-filled constructor for unavailable observations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    streams: usize,
    words: Vec<u32>,
}

impl Snapshot {
    pub(super) fn new(streams: usize, words: Vec<u32>) -> Self {
        debug_assert_eq!(words.len(), streams.div_ceil(32));
        Self { streams, words }
    }

    pub const fn streams(&self) -> usize {
        self.streams
    }

    pub fn words(&self) -> &[u32] {
        &self.words
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use {
        crate::platform::apple::dart::gen3::fault::Code,
        crate::platform::apple::dart::gen3::fault::Record,
        crate::research::dart_gen3::context::Context, crate::research::dart_gen3::handoff::Handoff,
        crate::research::dart_gen3::tables::Tables, stela_contracts::bus::Access,
        stela_contracts::dma::DmaError, stela_contracts::dma::Iommu, stela_contracts::dma::Memory,
        stela_contracts::dma::Port, stela_contracts::dma::test_support::Ram,
        stela_contracts::interrupt::InterruptLatch,
    };

    const PAGE: u64 = 0x4000;
    const ROOT: u64 = 0x8_0000_0000;
    const LEAF: u64 = ROOT + PAGE;
    const FRAME: u64 = ROOT + 2 * PAGE;
    const IOVA: u64 = 0x10000004000;

    #[test]
    fn native_commands_and_retained_shutdown_drive_actual_dma_without_losing_configuration_or_faults()
     {
        let context = Context::from_vm_range(IOVA, 0xffff0000).unwrap();
        let handoff = Handoff::new(0x300, 1, context).unwrap();
        let indices = context.transfer(IOVA, IOVA + 3).unwrap();
        let mut tables = Tables::new(256).unwrap();
        let mut ram = Ram::new(ROOT, (4 * PAGE) as usize);
        ram.put_u64(ROOT + u64::from(indices.segment()) * 8, LEAF >> 4 | 1);
        let leaf = LEAF + u64::from(indices.page()) * 8;
        ram.put_u64(leaf, FRAME >> 4 | 1 | 0xfff << 40);
        for sid in [0, 31, 32, 34, 255] {
            tables
                .configure_handoff(sid, (ROOT >> 12) as u32 | 1, handoff)
                .unwrap();
        }
        // Untranslated mode is still unqualified. Its enable bit remains
        // independent and is not silently disabled by translation shutdown.
        tables.configure(33, 0, 0).unwrap();
        for (word, bits) in [(0, 0x8000_0001), (1, 3), (7, 1 << 31)] {
            tables
                .stream_command(Command::decode(ENABLE + word * 4, bits).unwrap())
                .unwrap();
        }
        let mut sink = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut sink);
        Port {
            iommu: &mut tables,
            stream: 255,
            memory: &mut ram,
            access: &mut access,
        }
        .write(IOVA, &[1, 2, 3, 4])
        .unwrap();
        ram.put_u64(leaf, FRAME >> 4 | 1 | 0xfff << 40 | 1 << 2);
        assert_eq!(
            tables.translate(&mut ram, 31, IOVA, IOVA + 3, true, &mut access),
            Err(DmaError::Fault(1))
        );
        let fault = tables.faults().record(31).unwrap().unwrap();
        assert!(matches!(
            fault,
            Record {
                code: Code::Write,
                write: true,
                ..
            }
        ));
        // Clearing one stream cannot replace the enable word or clear its
        // pending fault, and setting another does not re-enable it.
        tables
            .stream_command(Command::decode(DISABLE, 1 << 31).unwrap())
            .unwrap();
        tables
            .stream_command(Command::decode(ENABLE, 1).unwrap())
            .unwrap();
        assert_eq!(tables.read_streams(ENABLE), Ok(1));
        assert!(matches!(
            tables.translate(&mut ram, 31, IOVA, IOVA + 3, false, &mut access),
            Err(DmaError::Unsupported(_))
        ));
        assert_eq!(tables.faults().record(31), Ok(Some(fault)));
        tables
            .stream_command(Command::decode(ENABLE, 1 << 31).unwrap())
            .unwrap();
        let snapshot = tables.save_disable_translation();
        assert_eq!(snapshot.streams(), 256);
        assert_eq!(snapshot.words(), &[0x8000_0001, 3, 0, 0, 0, 0, 0, 1 << 31]);
        assert_eq!(tables.read_streams(ENABLE), Ok(0));
        assert_eq!(tables.read_streams(ENABLE + 4), Ok(2));
        assert_eq!(tables.read_streams(ENABLE + 28), Ok(0));
        assert_eq!(tables.faults().record(31), Ok(Some(fault)));
        for sid in [0, 31, 32, 255] {
            for write in [false, true] {
                assert!(matches!(
                    tables.translate(&mut ram, sid, IOVA, IOVA + 3, write, &mut access),
                    Err(DmaError::Unsupported(_))
                ));
            }
        }
        let mut committed = [0; 4];
        assert!(ram.read(FRAME, &mut committed));
        assert_eq!(committed, [1, 2, 3, 4]);
        // Restore is the source's set-side operation. A stream enabled
        // independently after shutdown survives it; no table is rebuilt.
        tables
            .stream_command(Command::decode(ENABLE + 4, 1 << 2).unwrap())
            .unwrap();
        tables.restore_enables(&snapshot).unwrap();
        assert_eq!(tables.read_streams(ENABLE + 4), Ok(7));
        assert_eq!(tables.faults().record(31), Ok(Some(fault)));
        assert_eq!(
            tables.translate(&mut ram, 31, IOVA, IOVA + 3, false, &mut access),
            Ok(FRAME)
        );
        assert_eq!(
            tables.translate(&mut ram, 34, IOVA, IOVA + 3, false, &mut access),
            Ok(FRAME)
        );
        ram.put_u64(leaf, (FRAME + PAGE) >> 4 | 1 | 0xfff << 40);
        assert_eq!(
            tables.translate(&mut ram, 255, IOVA, IOVA + 3, true, &mut access),
            Ok(FRAME + PAGE)
        );
        assert_eq!(tables.faults().pending(0), Ok(1 << 31));
        tables.set_quiesced(true);
        assert!(matches!(
            tables.translate(&mut ram, 34, IOVA, IOVA + 3, false, &mut access),
            Err(DmaError::Unsupported(_))
        ));
        assert_eq!(tables.read_streams(ENABLE + 4), Ok(7));
        tables.set_quiesced(false);
        assert_eq!(
            tables.translate(&mut ram, 34, IOVA, IOVA + 3, false, &mut access),
            Ok(FRAME + PAGE)
        );
    }

    #[test]
    fn stream_commands_validate_the_whole_tail_and_snapshot_geometry_before_mutation() {
        let mut tables = Tables::new(33).unwrap();
        tables
            .stream_command(Command::decode(ENABLE + 4, 1).unwrap())
            .unwrap();
        for base in [ENABLE, DISABLE] {
            let command = Command::decode(base + 4, 1 | 1 << 31).unwrap();
            assert!(tables.stream_command(command).is_err());
            assert_eq!(tables.read_streams(ENABLE + 4), Ok(1));
            assert!(
                tables
                    .stream_command(Command::decode(base + 8, 0).unwrap())
                    .is_err()
            );
        }
        let mut other = Tables::new(34).unwrap();
        let wrong_geometry = other.save_disable_translation();
        assert!(tables.restore_enables(&wrong_geometry).is_err());
        assert_eq!(tables.read_streams(ENABLE + 4), Ok(1));
        for offset in [
            ENABLE - 4,
            DISABLE + 32,
            ENABLE + 1,
            ENABLE + 2,
            DISABLE + 3,
            u64::MAX,
        ] {
            assert!(Command::decode(offset, 0).is_err());
        }
        assert!(tables.read_streams(DISABLE).is_err());
        assert!(tables.read_streams(ENABLE + 8).is_err());
        assert!(tables.read_streams(ENABLE + 1).is_err());
        tables
            .stream_command(Command::decode(DISABLE + 4, 0).unwrap())
            .unwrap();
        assert_eq!(tables.read_streams(ENABLE + 4), Ok(1));
        tables
            .stream_command(Command::decode(DISABLE + 4, 1).unwrap())
            .unwrap();
        assert_eq!(tables.read_streams(ENABLE + 4), Ok(0));
    }
}
