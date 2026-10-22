// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2020-2023 MediaTek Inc.
//! Source-backed PCIe ownership, WFDMA stop and firmware-state polling. These
//! are actual register observations, not a firmware epoch or DMA/IRQ fence.
use super::registers::{self, BarIo, Registers};

pub mod bootstrap;
mod cold_start;
pub mod dma;

// Register names from mt76 `mt792x_regs.h` and `mt7921/regs.h`.
const MT_PCIE_MAC_INT_ENABLE: u32 = 0x10188;
const MT_WFDMA0_RST: u32 = 0xd4100;
const MT_MCU2HOST_SW_INT_ENA: u32 = 0xd41f4;
const MT_WFDMA0_HOST_INT_ENA: u32 = 0xd4204;
const MT_WFDMA0_GLO_CFG: u32 = 0xd4208;
const MT_WFDMA0_RST_DTX_PTR: u32 = 0xd420c;
const MT_WFDMA0_RST_DRX_PTR: u32 = 0xd4280;
const MT_WFDMA0_INT_RX_PRI: u32 = 0xd4298;
const MT_WFDMA0_INT_TX_PRI: u32 = 0xd429c;
const MT_WFDMA0_GLO_CFG_EXT0: u32 = 0xd42b0;
const MT_WFDMA0_PRI_DLY_INT_CFG0: u32 = 0xd42f0;
const MT_TX_RING_BASE: u32 = 0xd4300;
const MT_RX_RING_BASE: u32 = 0xd4500;
const MT_WFDMA0_TX_RING0_EXT_CTRL: u32 = 0xd4600;
const MT_WFDMA0_RX_RING0_EXT_CTRL: u32 = 0xd4680;
const MT_WFDMA_DUMMY_CR: u32 = 0x54000120;
const MT_WFDMA_NEED_REINIT: u32 = 1 << 1;
const MT_UWFDMA0_GLO_CFG_EXT1: u32 = 0x7c0242b4;
const MT_DMASHDL_SW_CONTROL: u32 = 0x7c026004;
const MT_CONN_ON_LPCTL: u32 = 0x7c060010;
const MT_CONN_ON_MISC: u32 = 0x7c0600f0;
const DISABLE: u32 = 1 | (1 << 2) | (1 << 15) | (1 << 28) | (1 << 27) | (1 << 21);
const BUSY: u32 = (1 << 1) | (1 << 3);

/// The registers of WFDMA0 TX ring `n`: base, size, CPU and DMA index.
pub(in crate::net::wifi::mediatek) const fn tx_ring(n: u32) -> u32 {
    MT_TX_RING_BASE + 16 * n
}
/// The registers of WFDMA0 RX ring `n`: base, size, CPU and DMA index.
pub(in crate::net::wifi::mediatek) const fn rx_ring(n: u32) -> u32 {
    MT_RX_RING_BASE + 16 * n
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    ClockUnavailable,
    NotDriverOwned,
    InitialResetRefused,
    DmaNotStopped,
    UnsupportedDmaMode(u32),
    Readback {
        address: u32,
        mask: u32,
        expected: u32,
        actual: u32,
    },
    Register(registers::Error),
    Unavailable {
        address: u32,
    },
    Timeout {
        address: u32,
        mask: u32,
        expected: u32,
        last: u32,
    },
    Poisoned,
}
impl From<registers::Error> for Error {
    fn from(e: registers::Error) -> Self {
        Self::Register(e)
    }
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MediaTek controller: {self:?}")
    }
}
impl core::error::Error for Error {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Observation {
    pub address: u32,
    pub value: u32,
    pub reads: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DriverOwned {
    pub attempts: u8,
    pub status: Observation,
}
/// The donor's DMA-disable sequence reached idle and applied its DMASHDL/reset
/// settings. This receipt is not proof that PCIe writes, IRQ handlers/deferred
/// work or firmware processing have drained; it cannot authorize ring unmap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DmaStopped {
    pub status: Observation,
    pub reset_applied: bool,
}

pub struct Control<I: BarIo> {
    registers: Registers<I>,
    pub(super) clock: crate::Clock,
    driver_owned: bool,
    dma_stopped: bool,
    poisoned: bool,
    initial_reset_attempted: bool,
    #[cfg(test)]
    polls: alloc::vec::Vec<(u32, u32, u32, u64)>,
}
impl<I: BarIo> Control<I> {
    /// # Safety
    /// The clock is actually calibrated for this native execution CPU and the
    /// register file belongs to this exclusive live requester. The caller
    /// serializes all ring/MCU/IRQ/power users against these global ownership
    /// and engine changes, and retains actual DMA pins and requester ownership
    /// until a separately established complete hardware/CPU drain. This object
    /// neither claims the PCI function nor constructs a fresh firmware epoch.
    pub unsafe fn new(registers: Registers<I>, clock: crate::Clock) -> Result<Self, Error> {
        if clock.ticks_per_microsecond == 0 {
            return Err(Error::ClockUnavailable);
        }
        Ok(Self {
            registers,
            clock,
            driver_owned: false,
            dma_stopped: false,
            poisoned: false,
            initial_reset_attempted: false,
            #[cfg(test)]
            polls: alloc::vec::Vec::new(),
        })
    }
    pub fn is_poisoned(&self) -> bool {
        self.poisoned || self.registers.is_poisoned()
    }
    fn guard(&self, require_owned: bool) -> Result<(), Error> {
        if self.is_poisoned() {
            return Err(Error::Poisoned);
        }
        if require_owned && !self.driver_owned {
            return Err(Error::NotDriverOwned);
        }
        Ok(())
    }
    fn finish<T>(&mut self, result: Result<T, Error>) -> Result<T, Error> {
        if result.is_err() {
            self.driver_owned = false;
            self.dma_stopped = false;
            self.poisoned = true;
        }
        result
    }
    fn read_control(&mut self, address: u32) -> Result<u32, Error> {
        let value = self.registers.read32(address)?;
        // Only mandatory power/DMA control observations use this check. It is
        // never applied to arbitrary firmware data registers or memory.
        if value == u32::MAX {
            return Err(Error::Unavailable { address });
        }
        Ok(value)
    }
    fn modify(&mut self, address: u32, mask: u32, value: u32) -> Result<(), Error> {
        let old = self.read_control(address)?;
        self.registers.write32(address, (old & !mask) | value)?;
        Ok(())
    }
    fn poll(
        &mut self,
        address: u32,
        mask: u32,
        expected: u32,
        timeout_us: u64,
    ) -> Result<Observation, Error> {
        #[cfg(test)]
        self.polls.push((address, mask, expected, timeout_us));
        let deadline = self.clock.deadline(timeout_us);
        let mut reads = 0u32;
        loop {
            let value = self.read_control(address)?;
            reads = reads.saturating_add(1);
            if value & mask == expected {
                return Ok(Observation {
                    address,
                    value,
                    reads,
                });
            }
            if deadline.passed() {
                return Err(Error::Timeout {
                    address,
                    mask,
                    expected,
                    last: value,
                });
            }
            // mt76_poll_msec_tick(..., tick=1). State transitions are read
            // from the actual device after each delay, never inferred by time.
            self.clock.delay(1000);
        }
    }
    /// The common MT792xe MT_CONN_ON_LPCTL request retries at most ten 50ms polls. ASPM
    /// requires a minimum 2ms wake delay before each actual status read.
    pub fn driver_own(&mut self, aspm_supported: bool) -> Result<DriverOwned, Error> {
        self.guard(false)?;
        self.driver_owned = false;
        self.dma_stopped = false;
        let result = (|| {
            for attempts in 1..=10 {
                self.registers.write32(MT_CONN_ON_LPCTL, 1 << 1)?;
                if aspm_supported {
                    self.clock.delay(2000);
                }
                match self.poll(MT_CONN_ON_LPCTL, 1 << 2, 0, 50_000) {
                    Ok(status) => return Ok(DriverOwned { attempts, status }),
                    Err(Error::Timeout { .. }) if attempts < 10 => {}
                    Err(error) => return Err(error),
                }
            }
            unreachable!("the final ownership timeout returns above")
        })();
        let receipt = self.finish(result)?;
        self.driver_owned = true;
        Ok(receipt)
    }
    /// Stop WLAN WFDMA0 and optionally toggle only its DMASHDL/logic reset.
    /// This does not issue a WLAN subsystem/combo reset, reset Bluetooth,
    /// release any mapping, or claim a fresh MCU response-sequencing epoch.
    pub fn stop_dma(&mut self, force: bool) -> Result<DmaStopped, Error> {
        self.guard(true)?;
        self.dma_stopped = false;
        let result = (|| {
            self.modify(MT_WFDMA0_GLO_CFG, DISABLE, 0)?;
            let status = self.poll(MT_WFDMA0_GLO_CFG, BUSY, 0, 100_000)?;
            if status.value & DISABLE != 0 {
                return Err(Error::Readback {
                    address: MT_WFDMA0_GLO_CFG,
                    mask: DISABLE,
                    expected: 0,
                    actual: status.value,
                });
            }
            self.modify(MT_WFDMA0_GLO_CFG_EXT0, 1 << 6, 0)?;
            self.modify(MT_DMASHDL_SW_CONTROL, 0, 1 << 28)?;
            if force {
                self.modify(MT_WFDMA0_RST, (1 << 4) | (1 << 5), 0)?;
                self.modify(MT_WFDMA0_RST, 0, (1 << 4) | (1 << 5))?;
            }
            // Push every final posted control write before returning. Idle
            // remains an observation, not a universal transaction-drain fence.
            self.read_control(MT_WFDMA0_RST)?;
            Ok(DmaStopped {
                status,
                reset_applied: force,
            })
        })();
        let receipt = self.finish(result)?;
        self.dma_stopped = true;
        Ok(receipt)
    }
    /// Poll the pre-download power state. Linux warns and continues on this
    /// timeout; Stela reports the unmet requirement rather than downloading
    /// through an unready MCU. This does not itself restart the MCU.
    pub fn poll_firmware_power_on(&mut self) -> Result<Observation, Error> {
        self.guard(true)?;
        let result = self.poll(MT_CONN_ON_MISC, 7, 1, 1_000_000);
        self.finish(result)
    }
    /// Observe N9-ready bits after the caller's actual download/start exchange.
    /// Even success proves only this register state, not which firmware was
    /// loaded, a new command epoch, calibration, regulatory setup or association.
    pub fn poll_n9_ready(&mut self) -> Result<Observation, Error> {
        self.guard(true)?;
        let result = self.poll(MT_CONN_ON_MISC, 3, 3, 1_500_000);
        self.finish(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::wifi::mediatek::identity::Chip;
    use alloc::{collections::BTreeMap, vec::Vec};
    extern crate std;

    struct Model {
        registers: BTreeMap<u32, u32>,
        operations: Vec<(u32, u32, u32)>,
        own_at_attempt: Option<u8>,
        attempts: u8,
        busy_reads: Option<usize>,
        stopping: bool,
        fail_at: Option<usize>,
        ignore_write: Option<u32>,
    }
    impl Default for Model {
        fn default() -> Self {
            Self {
                registers: BTreeMap::from([
                    (0xe0010, 4),
                    (0xe00f0, 1),
                    (MT_WFDMA0_GLO_CFG, 0x5a228055),
                    (MT_WFDMA0_GLO_CFG_EXT0, 0xa5a50040),
                    (0xd6004, 0xaabb0000),
                    (MT_WFDMA0_RST, 0xc0ff00ff),
                ]),
                operations: Vec::new(),
                own_at_attempt: Some(1),
                attempts: 0,
                busy_reads: Some(0),
                stopping: false,
                fail_at: None,
                ignore_write: None,
            }
        }
    }
    // SAFETY: serialized hardware state model; ownership/engine bits change
    // from modeled device acknowledgements, not blind echo of host commands.
    unsafe impl BarIo for Model {
        fn read32(&mut self, offset: u32) -> Result<u32, registers::Error> {
            if offset == 0xe0010 && self.own_at_attempt.is_some_and(|n| self.attempts >= n) {
                *self.registers.get_mut(&offset).unwrap() &= !4;
            }
            if offset == MT_WFDMA0_GLO_CFG
                && self.stopping
                && let Some(left) = self.busy_reads.as_mut()
            {
                if *left == 0 {
                    *self.registers.get_mut(&offset).unwrap() &= !BUSY;
                } else {
                    *left -= 1;
                }
            }
            let value = self.registers.get(&offset).copied().unwrap_or(0);
            self.operations.push((0, offset, value));
            if self.fail_at == Some(self.operations.len()) {
                return Err(registers::Error::AccessFailed);
            }
            Ok(value)
        }
        fn write32(&mut self, offset: u32, value: u32) -> Result<(), registers::Error> {
            self.operations.push((1, offset, value));
            if self.fail_at == Some(self.operations.len()) {
                return Err(registers::Error::AccessFailed);
            }
            if self.ignore_write == Some(offset) {
                return Ok(());
            }
            if offset == 0xe0010 && value == 2 {
                self.attempts += 1;
            } else {
                self.registers.insert(offset, value);
                if offset == MT_WFDMA0_GLO_CFG && value & DISABLE == 0 {
                    self.stopping = true;
                }
            }
            Ok(())
        }
    }
    fn setup(chip: Chip, model: Model) -> Control<Model> {
        // SAFETY: exclusive serialized model; a deliberately compressed local
        // TSC scale bounds fault tests, never qualifies physical timing.
        unsafe {
            Control::new(
                Registers::new(chip, model),
                crate::Clock {
                    ticks_per_microsecond: 10,
                },
            )
        }
        .unwrap()
    }
    #[test]
    fn actual_ownership_ack_and_dma_idle_precede_scheduler_reset_writes() {
        for chip in [Chip::Mt7921, Chip::Mt7922, Chip::Mt7925] {
            for force in [false, true] {
                let mut m = Model::default();
                m.registers.insert(MT_WFDMA0_GLO_CFG, 0x5a228055 | BUSY);
                m.busy_reads = Some(2);
                let mut c = setup(chip, m);
                assert_eq!(c.stop_dma(force), Err(Error::NotDriverOwned));
                assert!(c.registers.test_io().operations.is_empty());
                let own = c.driver_own(false).unwrap();
                assert_eq!(own.attempts, 1);
                assert_eq!(own.status.value & 4, 0);
                let stopped = c.stop_dma(force).unwrap();
                assert!(stopped.status.reads >= 3);
                assert_eq!(stopped.status.value & (DISABLE | BUSY), 0);
                let io = &c.registers.test_io();
                let idle = io
                    .operations
                    .iter()
                    .position(|&(k, a, v)| k == 0 && a == MT_WFDMA0_GLO_CFG && v & BUSY == 0)
                    .unwrap();
                let scheduler = io
                    .operations
                    .iter()
                    .position(|&(k, a, _)| k == 1 && a == MT_WFDMA0_GLO_CFG_EXT0)
                    .unwrap();
                assert!(idle < scheduler);
                assert_eq!(io.registers[&MT_WFDMA0_GLO_CFG_EXT0] & (1 << 6), 0);
                assert_ne!(io.registers[&0xd6004] & (1 << 28), 0);
                let resets = io
                    .operations
                    .iter()
                    .filter(|v| v.0 == 1 && v.1 == MT_WFDMA0_RST)
                    .count();
                assert_eq!(resets, if force { 2 } else { 0 });
                assert_eq!(io.registers[&MT_WFDMA0_RST], 0xc0ff00ff);
            }
        }
    }
    #[test]
    fn ownership_retries_bound_actual_attempts_and_never_proceed_on_timeout() {
        for accept in [Some(3), None] {
            let mut c = setup(
                Chip::Mt7921,
                Model {
                    own_at_attempt: accept,
                    ..Model::default()
                },
            );
            let result = c.driver_own(true);
            if accept.is_some() {
                assert_eq!(result.unwrap().attempts, 3);
            } else {
                assert!(matches!(
                    result,
                    Err(Error::Timeout {
                        address: MT_CONN_ON_LPCTL,
                        mask: 4,
                        expected: 0,
                        ..
                    })
                ));
                assert_eq!(c.registers.test_io().attempts, 10);
                let count = c.registers.test_io().operations.len();
                assert_eq!(c.stop_dma(true), Err(Error::Poisoned));
                assert_eq!(c.driver_own(false), Err(Error::Poisoned));
                assert_eq!(c.registers.test_io().operations.len(), count);
            }
        }
    }
    #[test]
    fn stuck_dma_never_resets_or_releases_unknown_owned_resources() {
        let mut m = Model {
            busy_reads: None,
            ..Model::default()
        };
        m.registers.insert(MT_WFDMA0_GLO_CFG, 0x5a228055 | BUSY);
        let mut c = setup(Chip::Mt7925, m);
        c.driver_own(false).unwrap();
        assert!(matches!(
            c.stop_dma(true),
            Err(Error::Timeout {
                address: MT_WFDMA0_GLO_CFG,
                mask: BUSY,
                ..
            })
        ));
        assert!(
            !c.registers
                .test_io()
                .operations
                .iter()
                .any(|&(k, a, _)| k == 1
                    && matches!(a, MT_WFDMA0_GLO_CFG_EXT0 | MT_WFDMA0_RST | 0xd6004))
        );
        assert!(c.is_poisoned());
    }
    #[test]
    fn every_ownership_and_stop_io_failure_poison_the_control_epoch() {
        let mut good = setup(Chip::Mt7921, Model::default());
        good.driver_own(false).unwrap();
        good.stop_dma(true).unwrap();
        let accesses = good.registers.test_io().operations.len();
        for fail_at in 1..=accesses {
            let mut c = setup(
                Chip::Mt7921,
                Model {
                    fail_at: Some(fail_at),
                    ..Model::default()
                },
            );
            let result = c.driver_own(false).and_then(|_| c.stop_dma(true));
            assert_eq!(
                result,
                Err(Error::Register(registers::Error::AccessFailed)),
                "access {fail_at}"
            );
            assert!(c.is_poisoned());
            let count = c.registers.test_io().operations.len();
            assert_eq!(c.poll_n9_ready(), Err(Error::Poisoned));
            assert_eq!(c.registers.test_io().operations.len(), count);
        }
    }
    #[test]
    fn power_and_n9_observations_do_not_synthesize_ready_from_all_ones_or_elapsed_time() {
        for state in [0, 1, 3, u32::MAX] {
            let mut m = Model::default();
            m.registers.insert(0xe00f0, state);
            let mut c = setup(Chip::Mt7925, m);
            c.driver_own(false).unwrap();
            let ready = c.poll_n9_ready();
            if state == 3 {
                assert_eq!(ready.unwrap().value, 3);
            } else if state == u32::MAX {
                assert_eq!(
                    ready,
                    Err(Error::Unavailable {
                        address: MT_CONN_ON_MISC
                    })
                );
            } else {
                assert!(matches!(
                    ready,
                    Err(Error::Timeout {
                        address: MT_CONN_ON_MISC,
                        expected: 3,
                        ..
                    })
                ));
            }
        }
        let mut c = setup(Chip::Mt7922, Model::default());
        c.driver_own(false).unwrap();
        assert_eq!(c.poll_firmware_power_on().unwrap().value, 1);
        c.registers.test_io().registers.insert(0xe00f0, 3);
        assert!(matches!(
            c.poll_firmware_power_on(),
            Err(Error::Timeout {
                mask: 7,
                expected: 1,
                ..
            })
        ));
    }
    #[test]
    fn unavailable_control_and_zero_clock_fail_before_fabricating_ownership() {
        let mut m = Model::default();
        m.registers.insert(0xe0010, u32::MAX);
        m.own_at_attempt = None;
        let mut c = setup(Chip::Mt7921, m);
        assert_eq!(
            c.driver_own(false),
            Err(Error::Unavailable {
                address: MT_CONN_ON_LPCTL
            })
        );
        // SAFETY: exclusive model register file, rejected before any access.
        let registers = unsafe { Registers::new(Chip::Mt7921, Model::default()) };
        assert!(matches!(
            unsafe {
                Control::new(
                    registers,
                    crate::Clock {
                        ticks_per_microsecond: 0,
                    },
                )
            },
            Err(Error::ClockUnavailable)
        ));
    }
    #[test]
    #[ignore = "requires STELA_MT792X_CONTROL_ORACLE from unchanged pinned ownership/DMA helpers"]
    fn unchanged_pinned_ownership_and_disable_helpers_match_actual_register_effects() {
        let root =
            std::env::var_os("STELA_MT792X_CONTROL_ORACLE").expect("reference trace directory");
        for force in [false, true] {
            let bytes = std::fs::read(std::path::Path::new(&root).join(if force {
                "force.bin"
            } else {
                "stop.bin"
            }))
            .unwrap();
            let mut at = 0;
            let word = |at: &mut usize| {
                let result = u32::from_le_bytes(bytes[*at..*at + 4].try_into().unwrap());
                *at += 4;
                result
            };
            let nops = word(&mut at);
            let npolls = word(&mut at);
            let expected: Vec<_> = (0..nops)
                .map(|_| (word(&mut at), word(&mut at), word(&mut at)))
                .collect();
            let polls: Vec<_> = (0..npolls)
                .map(|_| {
                    let p = (
                        word(&mut at),
                        word(&mut at),
                        word(&mut at),
                        u64::from(word(&mut at)) * 1000,
                    );
                    assert_eq!(word(&mut at), 1); // donor polling tick, milliseconds
                    p
                })
                .collect();
            assert_eq!(at, bytes.len());
            for chip in [Chip::Mt7921, Chip::Mt7922, Chip::Mt7925] {
                let mut c = setup(chip, Model::default());
                c.driver_own(false).unwrap();
                c.stop_dma(force).unwrap();
                assert_eq!(c.polls, polls);
                let mut actual = core::mem::take(&mut c.registers.test_io().operations);
                // Stela additionally flushes the final posted write; this is
                // tested explicitly instead of hidden in donor equivalence.
                assert_eq!(actual.pop(), Some((0, MT_WFDMA0_RST, 0xc0ff00ff)));
                assert_eq!(actual, expected);
            }
        }
    }
    #[test]
    fn polling_start_uses_chip_prefetch_and_index_reset_with_all_irq_sources_masked() {
        for chip in [Chip::Mt7921, Chip::Mt7922, Chip::Mt7925] {
            let mut c = setup(chip, Model::default());
            // SAFETY: isolated register-algorithm fixture, no DMA hardware.
            assert_eq!(unsafe { c.start_dma_polling() }, Err(Error::NotDriverOwned));
            c.driver_own(false).unwrap();
            assert_eq!(unsafe { c.start_dma_polling() }, Err(Error::DmaNotStopped));
            c.stop_dma(true).unwrap();
            let start = c.registers.test_io().operations.len();
            let enabled = unsafe { c.start_dma_polling() }.unwrap();
            assert_eq!(enabled.global_config & 5, 5);
            assert!(enabled.polling_interrupts_masked);
            let io = c.registers.test_io();
            for address in [0xd4204, 0x10188, 0xd41f4] {
                assert_eq!(io.registers[&address], 0);
            }
            assert_eq!(io.registers[&0xd420c], u32::MAX);
            assert_eq!(io.registers[&0xd42f0], 0);
            let count = io.operations[start..]
                .iter()
                .filter(|&&(kind, a, _)| kind == 1 && (0xd4600..0xd46a0).contains(&a))
                .count();
            if chip == Chip::Mt7925 {
                assert_eq!(count, 10);
                assert_eq!(io.registers[&0xd4280], u32::MAX);
                assert_eq!(io.registers[&0xd4600], 0x01000010);
                assert_eq!(io.registers[&0xd463c], 0x05000004);
                assert_eq!(io.registers[&0xd42b4] & (1 << 28), 1 << 28);
                assert_eq!(io.registers[&0xd4298] & 0xf00, 0xf00);
                assert_eq!(io.registers[&0xd429c] & 0x7f00, 0x7f00);
            } else {
                assert_eq!(count, 14);
                assert!(!io.registers.contains_key(&0xd4280));
                assert_eq!(io.registers[&0xd4600], 0x01400004);
                assert_eq!(io.registers[&0xd4644], 0x03800004);
            }
            let writes = io.operations.len();
            assert_eq!(unsafe { c.start_dma_polling() }, Err(Error::DmaNotStopped));
            assert_eq!(c.registers.test_io().operations.len(), writes);
        }
    }
    #[test]
    fn unsupported_dma_mode_and_ignored_control_stores_never_qualify_start() {
        for (address, initial) in [
            (MT_WFDMA0_GLO_CFG, 1 << 26),
            (MT_WFDMA0_GLO_CFG, 1),
            (0xd4204, 1),
        ] {
            let mut c = setup(Chip::Mt7925, Model::default());
            c.driver_own(false).unwrap();
            c.stop_dma(true).unwrap();
            let old = c
                .registers
                .test_io()
                .registers
                .get(&address)
                .copied()
                .unwrap_or(0);
            c.registers
                .test_io()
                .registers
                .insert(address, old | initial);
            if address != MT_WFDMA0_GLO_CFG {
                c.registers.test_io().ignore_write = Some(address);
            }
            assert!(matches!(
                unsafe { c.start_dma_polling() },
                Err(Error::UnsupportedDmaMode(_)) | Err(Error::Readback { .. })
            ));
            assert!(c.is_poisoned());
            assert!(
                !c.registers
                    .test_io()
                    .operations
                    .iter()
                    .any(|&(kind, a, v)| kind == 1 && a == MT_WFDMA0_GLO_CFG && v & 5 == 5)
            );
        }
        let mut c = setup(
            Chip::Mt7921,
            Model {
                ignore_write: Some(MT_WFDMA0_GLO_CFG),
                ..Model::default()
            },
        );
        c.driver_own(false).unwrap();
        assert!(matches!(
            c.stop_dma(true),
            Err(Error::Readback {
                address: MT_WFDMA0_GLO_CFG,
                expected: 0,
                ..
            })
        ));
        assert!(!c.dma_stopped);
        let mut c = setup(Chip::Mt7921, Model::default());
        c.driver_own(false).unwrap();
        c.stop_dma(true).unwrap();
        c.registers.test_io().ignore_write = Some(MT_WFDMA0_GLO_CFG);
        assert!(matches!(
            unsafe { c.start_dma_polling() },
            Err(Error::Readback {
                address: MT_WFDMA0_GLO_CFG,
                ..
            })
        ));
        assert!(c.is_poisoned());
    }
    #[test]
    fn every_dma_start_publication_failure_poison_context_without_retry() {
        for chip in [Chip::Mt7921, Chip::Mt7925] {
            let mut c = setup(chip, Model::default());
            c.driver_own(false).unwrap();
            c.stop_dma(true).unwrap();
            let initial = c.registers.test_io().operations.len();
            unsafe { c.start_dma_polling() }.unwrap();
            let end = c.registers.test_io().operations.len();
            for fail_at in initial + 1..=end {
                let mut c = setup(chip, Model::default());
                c.driver_own(false).unwrap();
                c.stop_dma(true).unwrap();
                c.registers.test_io().fail_at = Some(fail_at);
                assert_eq!(
                    unsafe { c.start_dma_polling() },
                    Err(Error::Register(registers::Error::AccessFailed)),
                    "chip {chip:?} access {fail_at}"
                );
                assert!(c.is_poisoned());
                let count = c.registers.test_io().operations.len();
                assert_eq!(unsafe { c.start_dma_polling() }, Err(Error::Poisoned));
                assert_eq!(c.stop_dma(true), Err(Error::Poisoned));
                assert_eq!(c.registers.test_io().operations.len(), count);
            }
        }
    }
    #[test]
    #[ignore = "requires STELA_MT792X_START_ORACLE from unchanged pinned WFDMA helpers"]
    fn unchanged_pinned_prefetch_and_enable_match_except_explicit_polling_irq_policy() {
        let root =
            std::env::var_os("STELA_MT792X_START_ORACLE").expect("reference trace directory");
        for chip in [Chip::Mt7921, Chip::Mt7922, Chip::Mt7925] {
            let name = if chip == Chip::Mt7925 {
                "7925"
            } else if chip == Chip::Mt7922 {
                "7922"
            } else {
                "7921"
            };
            let bytes =
                std::fs::read(std::path::Path::new(&root).join(format!("mt{name}.bin"))).unwrap();
            let count = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
            assert_eq!(bytes.len(), 4 + 12 * count);
            let mut expected: Vec<_> = bytes[4..]
                .as_chunks::<12>()
                .0
                .iter()
                .map(|b| {
                    (
                        u32::from_le_bytes(b[..4].try_into().unwrap()),
                        u32::from_le_bytes(b[4..8].try_into().unwrap()),
                        u32::from_le_bytes(b[8..].try_into().unwrap()),
                    )
                })
                .collect();
            assert_eq!(
                &expected[count - 3..],
                &[(2, 0, 0x20000300), (0, 0xd41f4, 0), (1, 0xd41f4, 1)]
            );
            expected.truncate(count - 3);
            let mut c = setup(chip, Model::default());
            c.driver_own(false).unwrap();
            c.stop_dma(true).unwrap();
            let initial = c.registers.test_io().operations.len();
            let receipt = unsafe { c.start_dma_polling() }.unwrap();
            let actual = &c.registers.test_io().operations[initial..];
            assert_eq!(
                &actual[..6],
                &[
                    (1, 0xd4204, 0),
                    (1, 0x10188, 0),
                    (1, 0xd41f4, 0),
                    (0, 0xd4204, 0),
                    (0, 0x10188, 0),
                    (0, 0xd41f4, 0)
                ]
            );
            assert_eq!(actual[6], (0, MT_WFDMA0_GLO_CFG, 0x5a228055 & !DISABLE));
            assert_eq!(&actual[7..actual.len() - 4], expected);
            assert_eq!(
                &actual[actual.len() - 4..],
                &[
                    (0, 0xd4204, 0),
                    (0, 0x10188, 0),
                    (0, 0xd41f4, 0),
                    (0, MT_WFDMA0_GLO_CFG, receipt.global_config)
                ]
            );
        }
    }
}
