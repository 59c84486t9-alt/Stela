//! The per-core counters of the CLPC samplers, which a PE reads as System
//! registers and the other PEs read through its `cpu-impl-reg`.
//!
//! No public source names them. Every 26A434 CLPC kext (`AppleT8103CLPCv3`
//! through `AppleT8152CLPC`) samples a core's counters itself with MRS and,
//! for another core, with loads from that core's `cpu-impl-reg`, whose
//! placement `CLPC::init` builds from the `ml_topology_cpu` field the
//! topology parser fills from `cpu-impl-reg` (T8112 kernelcache
//! 0xfffffe000bd7e568):
//!
//! - Core performance ("AON") counters. `T8112CLPC::corePerfSamplerConfig`
//!   (0xfffffe0009f78c18) gives a window at +0x4000 with eight slots 0x10
//!   apart; every other kext gives the same addresses, the T6050's and
//!   T8152's as offset 0 plus a first slot at 0x4000 and a second set from
//!   0x3fc0, 8 apart. `SchedulerInterface::sampleCores` reads slot n with a
//!   64-bit load truncated to 32 bits (`readRemoteAONCounter`,
//!   0xfffffe0009f40a28) into the sample slot `CorePerfSampler::sample` fills
//!   from S3_7_C15_C(2n)_3 (0xfffffe0009f39760); the T6050's ninth and tenth
//!   come from 0x3fc0 and 0x3fc8 into the slots it fills from S3_7_C15_C14_0
//!   and C14_1 (kernelcache.release.mac17j 0xfffffe0009c02f44..0xfffffe0009c03158).
//! - Memory-stall counters. Every `coreMemStallSamplerConfig`
//!   (0xfffffe0009f78c60) is {0x6010, 0x20, 8}: a window at +0x6030 with
//!   slots 8 apart. `CoreMemStallSampler::init` takes it whenever
//!   `requiresRemoteIPIMemStallSampling` is false (0 on every SoC; the
//!   T8103's is MIDR_EL1.Variant 0, which this machine's variant 1 is not),
//!   and `sampleRemote` (0xfffffe0009f4192c) reads slot k as the 48-bit
//!   count `CoreMemStallSampler::sample` reads from S3_1_C15_C(8+k)_3
//!   (0xfffffe0009f41868), bit 47 its overflow, which both clear by writing 0.
//!
//! So each counter is one value with two views: this model holds it, and
//! the PE's MRS and MSR of the System register and any PE's 64-bit load or
//! store of the window word reach the same storage (`Devices::system_register`).
//! The counters count only under the samplers' enables and event selectors,
//! whose events are not documented; the core holds those and reports the
//! missing counting once (`machine::impdef`), and the counters hold what
//! software writes, 0 from reset (inference).
use super::bus::{Access, Direction, MmioDevice, MmioError, Width, refuse};
use stela_compiler::aarch64::system::registers::Encoding;

const NAME: &str = "cpu-impl-reg counters";
/// The core performance counters' slots: eight 0x10 apart, then the
/// T6050's two more 8 apart.
const AON: u64 = 0x4000;
const AON_STRIDE: u64 = 0x10;
const AON_SLOTS: usize = 8;
const AON_EXTRA: u64 = 0x3fc0;
const EXTRA_STRIDE: u64 = 8;
/// The memory-stall counters' slots.
const STALL: u64 = 0x6030;
const STALL_STRIDE: u64 = 8;
const STALL_SLOTS: usize = 8;
const EXTRA_SLOTS: usize = 2;
const MAX_AON: usize = AON_SLOTS + EXTRA_SLOTS;

/// How many counters of each kind a SoC's cores have.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    aon: u8,
    stall: u8,
}

/// The counters of the SoC with `chip_id`: the System registers its CLPC's
/// `CorePerfSampler::sample` and `CoreMemStallSampler::sample` read (and,
/// on the Ultras and the T6050, the second CLPC's two more memory-stall
/// counters, S3_1_C15_C14_3 and C15_3: kernelcache.release.mac14j
/// 0xfffffe0009f7c420), recorded per kext in `isa/apple-soc-facts.json`.
pub fn layout(chip_id: u32) -> Option<Layout> {
    let (aon, stall) = match chip_id {
        0x8103 | 0x8112 => (3, 4),
        0x6000 | 0x6001 | 0x6020 | 0x6021 => (4, 6),
        0x6002 | 0x6022 => (4, 8),
        0x8122 => (3, 5),
        0x6030 => (4, 5),
        0x6031 | 0x6034 | 0x6040 | 0x6041 => (5, 6),
        0x6032 => (5, 8),
        0x8132 | 0x8142 | 0x8152 => (5, 5),
        0x6050 => (10, 8),
        _ => return None,
    };
    Some(Layout { aon, stall })
}

impl Layout {
    /// The window ranges a block of this layout maps, as (offset, bytes):
    /// each kind's described slots, from the first to the last.
    pub fn windows(self) -> impl Iterator<Item = (u64, u64)> {
        let aon = usize::from(self.aon);
        [
            (AON, aon.min(AON_SLOTS) as u64 * AON_STRIDE),
            (
                AON_EXTRA,
                aon.saturating_sub(AON_SLOTS) as u64 * EXTRA_STRIDE,
            ),
            (STALL, u64::from(self.stall) * STALL_STRIDE),
        ]
        .into_iter()
        .filter(|&(_, bytes)| bytes != 0)
    }
}

/// One counter: a core performance or a memory-stall slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Counter {
    Aon(usize),
    Stall(usize),
}

/// The counters of one PE's `cpu-impl-reg`.
#[derive(Debug, Clone)]
pub struct CoreCounters {
    layout: Layout,
    aon: [u64; MAX_AON],
    stall: [u64; STALL_SLOTS],
}

impl CoreCounters {
    pub fn new(layout: Layout) -> Self {
        Self {
            layout,
            aon: [0; MAX_AON],
            stall: [0; STALL_SLOTS],
        }
    }

    /// The counter a System register is, on this SoC: S3_7_C15_C(2n)_3 for
    /// core performance counter n < 8, S3_7_C15_C14_0 and C14_1 for the
    /// ninth and tenth, S3_1_C15_C(8+k)_3 for memory-stall counter k.
    fn of_register(&self, encoding: Encoding) -> Option<Counter> {
        let (op1, crm, op2) = (encoding.op1(), encoding.crm(), encoding.op2());
        if encoding.op0() != 3 || encoding.crn() != 15 {
            return None;
        }
        let counter = match (op1, op2) {
            (7, 3) if crm % 2 == 0 => Counter::Aon(usize::from(crm / 2)),
            (7, 0 | 1) if crm == 14 => Counter::Aon(AON_SLOTS + usize::from(op2)),
            (1, 3) if crm >= 8 => Counter::Stall(usize::from(crm - 8)),
            _ => return None,
        };
        self.exists(counter).then_some(counter)
    }

    /// The counter a window word is.
    fn of_offset(&self, offset: u64) -> Option<Counter> {
        let slot = |base: u64, stride: u64, slots: usize| {
            let index = offset.checked_sub(base)?;
            (index % stride == 0 && index / stride < slots as u64)
                .then_some((index / stride) as usize)
        };
        let counter = if let Some(n) = slot(AON, AON_STRIDE, AON_SLOTS) {
            Counter::Aon(n)
        } else if let Some(n) = slot(AON_EXTRA, EXTRA_STRIDE, EXTRA_SLOTS) {
            Counter::Aon(AON_SLOTS + n)
        } else {
            Counter::Stall(slot(STALL, STALL_STRIDE, STALL_SLOTS)?)
        };
        self.exists(counter).then_some(counter)
    }

    fn exists(&self, counter: Counter) -> bool {
        match counter {
            Counter::Aon(n) => n < usize::from(self.layout.aon),
            Counter::Stall(k) => k < usize::from(self.layout.stall),
        }
    }

    fn value(&mut self, counter: Counter) -> &mut u64 {
        match counter {
            Counter::Aon(n) => &mut self.aon[n],
            Counter::Stall(k) => &mut self.stall[k],
        }
    }

    /// An MRS (`write` `None`) or MSR of `encoding` by the PE whose block
    /// this is: `None` for a register that is no counter of this SoC, else
    /// the value read (0 for a write).
    pub fn register(&mut self, encoding: Encoding, write: Option<u64>) -> Option<u64> {
        let counter = self.of_register(encoding)?;
        let value = self.value(counter);
        Some(match write {
            Some(written) => {
                *value = written;
                0
            }
            None => *value,
        })
    }
}

impl MmioDevice for CoreCounters {
    fn name(&self) -> &'static str {
        NAME
    }

    fn read(&mut self, offset: u64, width: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        match self.of_offset(offset).filter(|_| width == Width::Double) {
            Some(counter) => Ok(*self.value(counter)),
            None => Err(refuse(
                NAME,
                offset,
                width,
                Direction::Read,
                "counter slot or width without described meaning on this SoC",
            )),
        }
    }

    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        _: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        match self.of_offset(offset).filter(|_| width == Width::Double) {
            Some(counter) => {
                *self.value(counter) = value;
                Ok(())
            }
            None => Err(refuse(
                NAME,
                offset,
                width,
                Direction::Write,
                "counter slot or width without described meaning on this SoC",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::interrupt::InterruptLatch;

    const AON_1: Encoding = Encoding::new(3, 7, 15, 2, 3);
    const AON_3: Encoding = Encoding::new(3, 7, 15, 6, 3);
    const STALL_0: Encoding = Encoding::new(3, 1, 15, 8, 3);
    const STALL_3: Encoding = Encoding::new(3, 1, 15, 11, 3);
    const STALL_4: Encoding = Encoding::new(3, 1, 15, 12, 3);

    /// A T8112 core's counters read the same through MRS and through its
    /// `cpu-impl-reg` window, and a store of 0 clears either view.
    #[test]
    fn the_register_and_window_views_share_each_counter() {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(1, 0, &mut latch);
        let mut block = CoreCounters::new(layout(0x8112).unwrap());
        assert_eq!(block.register(AON_1, Some(0x1234_5678)), Some(0));
        assert_eq!(
            block.read(AON + AON_STRIDE, Width::Double, &mut access),
            Ok(0x1234_5678)
        );
        block
            .write(
                STALL + 3 * STALL_STRIDE,
                Width::Double,
                1 << 47,
                &mut access,
            )
            .unwrap();
        assert_eq!(block.register(STALL_3, None), Some(1 << 47));
        block
            .write(STALL + 3 * STALL_STRIDE, Width::Double, 0, &mut access)
            .unwrap();
        assert_eq!(block.register(STALL_3, None), Some(0));
        // The T8112 has three core and four memory-stall counters.
        assert_eq!(block.register(AON_3, None), None);
        assert_eq!(block.register(STALL_4, None), None);
        assert!(
            block
                .read(AON + 3 * AON_STRIDE, Width::Double, &mut access)
                .is_err()
        );
        assert!(
            block
                .read(STALL + 4 * STALL_STRIDE, Width::Double, &mut access)
                .is_err()
        );
        // Narrow accesses, gaps and the T6050's extra slots refuse.
        assert!(block.read(AON, Width::Word, &mut access).is_err());
        assert!(block.read(AON + 8, Width::Double, &mut access).is_err());
        assert!(block.read(AON_EXTRA, Width::Double, &mut access).is_err());
    }

    /// The T6050's ninth and tenth core counters are S3_7_C15_C14_0 and
    /// C14_1 at 0x3fc0 and 0x3fc8; it and the Ultras have eight
    /// memory-stall counters.
    #[test]
    fn the_t6050_has_ten_core_counters() {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut block = CoreCounters::new(layout(0x6050).unwrap());
        for (encoding, offset) in [
            (Encoding::new(3, 7, 15, 14, 3), AON + 7 * AON_STRIDE),
            (Encoding::new(3, 7, 15, 14, 0), AON_EXTRA),
            (Encoding::new(3, 7, 15, 14, 1), AON_EXTRA + EXTRA_STRIDE),
            (Encoding::new(3, 1, 15, 15, 3), STALL + 7 * STALL_STRIDE),
        ] {
            block
                .write(offset, Width::Double, offset, &mut access)
                .unwrap();
            assert_eq!(block.register(encoding, None), Some(offset));
        }
        assert_eq!(block.register(STALL_0, None), Some(0));
        assert_eq!(layout(0x6022).unwrap().stall, 8);
        assert_eq!(layout(0x6021).unwrap().stall, 6);
        assert!(layout(0x1234).is_none());
    }

    /// The windows lie inside every SoC's `cpu-impl-reg` (0x9008 bytes at
    /// the least) and clear of its lockdown pair at 0x5000 and the core
    /// energy accumulators at 0x9000.
    #[test]
    fn the_windows_fit_the_block() {
        let all = [
            0x8103, 0x6000, 0x6001, 0x6002, 0x8112, 0x6020, 0x6021, 0x6022, 0x8122, 0x6030, 0x6031,
            0x6032, 0x6034, 0x8132, 0x6040, 0x6041, 0x8142, 0x6050, 0x8152,
        ];
        for chip_id in all {
            for (offset, bytes) in layout(chip_id).unwrap().windows() {
                assert!(offset + bytes <= 0x5000 || offset >= 0x5010);
                assert!(offset + bytes <= 0x9000);
            }
        }
        let t8112: Vec<_> = layout(0x8112).unwrap().windows().collect();
        assert_eq!(t8112, [(AON, 0x30), (STALL, 0x20)]);
        assert_eq!(layout(0x6050).unwrap().windows().count(), 3);
    }
}
