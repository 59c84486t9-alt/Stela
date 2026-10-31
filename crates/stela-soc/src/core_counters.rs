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
//! The samplers read them in bursts on every PE, so a PE reaches its own
//! outside the devices' lock ([`LocalRegisters`]): the storage is atomic.
//! The counters count only under the samplers' enables and event selectors,
//! whose events are not documented; the core holds those and reports the
//! missing counting once (`machine::impdef`), and the counters hold what
//! software writes, 0 from reset (inference). Their hardware widths are not
//! established: software truncates the core counters to 32 bits and masks
//! the memory-stall deltas to 48 bits itself, testing bit 47 for overflow,
//! which a counter that never counts never sets. So each is held as 64 bits
//! (inference).
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering::Relaxed};
use stela_compiler::aarch64::system::registers::Encoding;
use stela_engine::machine::engine::LocalRegisters;
use stela_soc_data::core_counters::{
    AON, AON_EXTRA, AON_SLOTS, AON_STRIDE, EXTRA_SLOTS, EXTRA_STRIDE, MAX_AON, STALL, STALL_SLOTS,
    STALL_STRIDE,
};
use {
    stela_contracts::bus::Access, stela_contracts::bus::Direction,
    stela_contracts::bus::MmioDevice, stela_contracts::bus::MmioError, stela_contracts::bus::Width,
    stela_contracts::bus::refuse,
};

const NAME: &str = "cpu-impl-reg counters";
use stela_soc_data::core_counters::Layout;
#[cfg(test)]
use stela_soc_data::core_counters::layout;

/// One counter: a core performance or a memory-stall slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Counter {
    Aon(usize),
    Stall(usize),
}

/// The counters of one PE's `cpu-impl-reg`.
///
/// A clone reaches the same counters.
#[derive(Debug, Clone)]
pub struct CoreCounters {
    layout: Layout,
    values: Arc<Values>,
}

#[derive(Debug)]
struct Values {
    aon: [AtomicU64; MAX_AON],
    stall: [AtomicU64; STALL_SLOTS],
}

impl CoreCounters {
    pub fn new(layout: Layout) -> Self {
        Self {
            layout,
            values: Arc::new(Values {
                aon: [const { AtomicU64::new(0) }; MAX_AON],
                stall: [const { AtomicU64::new(0) }; STALL_SLOTS],
            }),
        }
    }

    /// The counter a System register is, on this SoC: S3_7_C15_C(2n)_3 for
    /// core performance counter n < 8, S3_7_C15_C14_0 and C14_1 for the
    /// ninth and tenth, S3_1_C15_C(8+k)_3 for memory-stall counter k.
    /// Whether `encoding` is one of these counters' System registers.
    pub fn serves(&self, encoding: Encoding) -> bool {
        self.of_register(encoding).is_some()
    }

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
            Counter::Aon(n) => n < self.layout.aon_slots(),
            Counter::Stall(k) => k < self.layout.stall_slots(),
        }
    }

    fn value(&self, counter: Counter) -> &AtomicU64 {
        match counter {
            Counter::Aon(n) => &self.values.aon[n],
            Counter::Stall(k) => &self.values.stall[k],
        }
    }

    /// An MRS (`write` `None`) or MSR of `encoding` by the PE whose block
    /// this is: `None` for a register that is no counter of this SoC, else
    /// the value read (0 for a write).
    pub fn register(&self, encoding: Encoding, write: Option<u64>) -> Option<u64> {
        let counter = self.of_register(encoding)?;
        let value = self.value(counter);
        Some(match write {
            Some(written) => {
                value.store(written, Relaxed);
                0
            }
            None => value.load(Relaxed),
        })
    }
}

impl LocalRegisters for CoreCounters {
    fn register(&self, encoding: Encoding, write: Option<u64>) -> Option<u64> {
        CoreCounters::register(self, encoding, write)
    }

    fn storage(&self, encoding: Encoding) -> Option<u64> {
        let counter = self.of_register(encoding)?;
        Some(self.value(counter).as_ptr() as u64)
    }
}

impl MmioDevice for CoreCounters {
    fn advance_policy(&self) -> super::bus::AdvancePolicy {
        super::bus::AdvancePolicy::Passive
    }
    fn name(&self) -> &'static str {
        NAME
    }

    fn read(&mut self, offset: u64, width: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        match self.of_offset(offset).filter(|_| width == Width::Double) {
            Some(counter) => Ok(self.value(counter).load(Relaxed)),
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
                self.value(counter).store(value, Relaxed);
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
    use stela_contracts::interrupt::InterruptLatch;

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
        // The handle a PE keeps reaches the same counter, as does a read of
        // its storage.
        assert_eq!(block.clone().register(AON_1, Some(0x1234_5678)), Some(0));
        let storage = LocalRegisters::storage(&block, AON_1).unwrap() as *const u64;
        // SAFETY: the address of a live counter's aligned word.
        assert_eq!(unsafe { storage.read() }, 0x1234_5678);
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

    /// T8140's original CLPC accesses three AON and five stall slots;
    /// selecting the M4 ISA must not substitute T8132's five AON slots.
    #[test]
    fn a18_pro_preserves_its_own_sampler_register_and_mmio_boundaries() {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut block = CoreCounters::new(layout(0x8140).unwrap());
        let aon2 = Encoding::new(3, 7, 15, 4, 3);
        assert_eq!(block.register(aon2, Some(0x1234_5678)), Some(0));
        assert_eq!(
            block.read(AON + 2 * AON_STRIDE, Width::Double, &mut access),
            Ok(0x1234_5678)
        );
        block
            .write(
                STALL + 4 * STALL_STRIDE,
                Width::Double,
                1 << 47,
                &mut access,
            )
            .unwrap();
        assert_eq!(block.register(STALL_4, None), Some(1 << 47));
        assert_eq!(block.register(STALL_4, Some(0)), Some(0));
        assert_eq!(
            block.read(STALL + 4 * STALL_STRIDE, Width::Double, &mut access),
            Ok(0)
        );
        for (encoding, offset) in [
            (AON_3, AON + 3 * AON_STRIDE),
            (Encoding::new(3, 1, 15, 13, 3), STALL + 5 * STALL_STRIDE),
        ] {
            assert_eq!(block.register(encoding, None), None);
            assert!(block.read(offset, Width::Double, &mut access).is_err());
        }
        let m4 = CoreCounters::new(layout(0x8132).unwrap());
        assert_eq!(m4.register(AON_3, None), Some(0));
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
        assert_eq!(layout(0x6022).unwrap().stall_slots(), 8);
        assert_eq!(layout(0x6021).unwrap().stall_slots(), 6);
        assert!(layout(0x1234).is_none());
    }

    /// The windows lie inside every SoC's `cpu-impl-reg` (0x9008 bytes at
    /// the least) and clear of its lockdown pair at 0x5000 and the core
    /// energy accumulators at 0x9000.
    #[test]
    fn the_windows_fit_the_block() {
        let all = [
            0x8103, 0x6000, 0x6001, 0x6002, 0x8112, 0x6020, 0x6021, 0x6022, 0x8122, 0x6030, 0x6031,
            0x6032, 0x6034, 0x8132, 0x6040, 0x6041, 0x8140, 0x8142, 0x6050, 0x8152,
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
