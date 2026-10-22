// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! Initial RTL8822C native HCI reset/rebinding, before RX/command admission.
//! Reset stores and zero indices are not an acknowledged DMA-stop mechanism.
use super::{
    beacon::{self, Beacon},
    identity::Chip,
    io::{self, Io, NativeIo},
    receive,
    registers::*,
    transmit,
};
use core::sync::atomic::{Ordering, fence};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Hardware(io::Error),
    Beacon(beacon::Error),
    Receive(receive::Error),
    Transmit(transmit::Error),
    IdentityChanged,
    Removed,
    Readback,
}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Hardware(e)
    }
}
impl From<beacon::Error> for Error {
    fn from(e: beacon::Error) -> Self {
        Self::Beacon(e)
    }
}
impl From<receive::Error> for Error {
    fn from(e: receive::Error) -> Self {
        Self::Receive(e)
    }
}
impl From<transmit::Error> for Error {
    fn from(e: transmit::Error) -> Self {
        Self::Transmit(e)
    }
}
struct Attempt<'a, I: Io> {
    io: &'a mut I,
    done: bool,
}
impl<I: Io> Drop for Attempt<'_, I> {
    fn drop(&mut self) {
        if !self.done {
            self.io.quarantine();
        }
    }
}

/// Actual source reset/base/index/tag sequence using all retained native
/// rings after MAC power and again after firmware download, before any raw
/// RX poll or firmware command has been admitted.
///
/// # Safety
/// All queues/domain/claims/BARs belong to `io`'s exact selected requester.
/// Independent actual requester stop/drain, with every IRQ/reset/submission
/// worker stopped throughout the operation. Source CTRL/index/reset stores
/// below do not establish that prerequisite. RAM is actual coherent WB with
/// NoSnoop/ATS disabled. This is initial attachment, not recovery of a live
/// station, outstanding command or security generation. Firmware download has
/// consumed its final beacon payload using actual fresh BCN_VALID if used.
pub unsafe fn setup<B: beacon::Registers, R: receive::Registers, T: transmit::Registers>(
    io: &mut NativeIo<Beacon<B>>,
    rx: &mut receive::Ring<R>,
    tx: &mut transmit::Rings<T>,
) -> Result<(), Error> {
    let profile = io.profile();
    if profile.chip() != Chip::Rtl8822C || tx.profile()? != profile {
        return Err(Error::IdentityChanged);
    }
    let mut a = Attempt { io, done: false };
    let actual = a.io.read32(REG_SYS_CFG1)?;
    if actual == u32::MAX {
        return Err(Error::Removed);
    }
    if actual != profile.observed().sys_cfg1 {
        return Err(Error::IdentityChanged);
    }
    // Actual independent stop owns descriptor CPU visibility. Each component
    // becomes poisoned before its own mutation; uncertainty retains its I/O
    // owner and pins even if another component's preparation later fails.
    let beacon = unsafe { a.io.beacon_queue()?.begin_hci_rebind()? };
    let receive = unsafe { rx.begin_hci_rebind()? };
    let transmit = unsafe { tx.begin_hci_rebind()? };
    fence(Ordering::Release);
    rebind(a.io, beacon, receive, transmit)?;
    rx.initial_indices()?;
    tx.initial_indices()?;
    a.io.beacon_queue()?.finish_hci_rebind();
    rx.finish_hci_rebind();
    tx.finish_hci_rebind();
    a.done = true;
    Ok(())
}
fn read32<I: Io>(io: &mut I, reg: u32) -> Result<u32, Error> {
    let v = io.read32(reg)?;
    if v == u32::MAX {
        Err(Error::Removed)
    } else {
        Ok(v)
    }
}
fn base<I: Io>(io: &mut I, count: u32, n: u16, reg: u32, address: u32) -> Result<(), Error> {
    io.write16(count, n)?;
    io.write32(reg, address)?;
    if io.read16(count)? & 0xfff != n || io.read32(reg)? != address {
        return Err(Error::Readback);
    }
    Ok(())
}
/// Binding addresses are private observations of retained native allocations,
/// never public fabricated IOVAs. This function's caller owns all live pins.
fn rebind<I: Io>(io: &mut I, beacon: u32, receive: u32, tx: [u32; 7]) -> Result<(), Error> {
    let value = io.read8(RTK_PCI_CTRL + 3)?;
    if value == u8::MAX {
        return Err(Error::Removed);
    }
    io.write8(RTK_PCI_CTRL + 3, value | 0xf7)?;
    io.write32(RTK_PCI_TXBD_DESA_BCNQ, beacon)?;
    if io.read32(RTK_PCI_TXBD_DESA_BCNQ)? != beacon {
        return Err(Error::Readback);
    }
    // Actual pinned source order: H2C,BK,BE,VO,VI,management,high,RX.
    base(
        io,
        RTK_PCI_TXBD_NUM_H2CQ,
        128,
        RTK_PCI_TXBD_DESA_H2CQ,
        tx[6],
    )?;
    base(io, RTK_PCI_TXBD_NUM_BKQ, 128, RTK_PCI_TXBD_DESA_BKQ, tx[0])?;
    base(io, RTK_PCI_TXBD_NUM_BEQ, 256, RTK_PCI_TXBD_DESA_BEQ, tx[1])?;
    base(io, RTK_PCI_TXBD_NUM_VOQ, 128, RTK_PCI_TXBD_DESA_VOQ, tx[3])?;
    base(io, RTK_PCI_TXBD_NUM_VIQ, 128, RTK_PCI_TXBD_DESA_VIQ, tx[2])?;
    base(
        io,
        RTK_PCI_TXBD_NUM_MGMTQ,
        128,
        RTK_PCI_TXBD_DESA_MGMTQ,
        tx[4],
    )?;
    base(
        io,
        RTK_PCI_TXBD_NUM_HI0Q,
        128,
        RTK_PCI_TXBD_DESA_HI0Q,
        tx[5],
    )?;
    base(
        io,
        RTK_PCI_RXBD_NUM_MPDUQ,
        512,
        RTK_PCI_RXBD_DESA_MPDUQ,
        receive,
    )?;
    io.write32(RTK_PCI_TXBD_RWPTR_CLR, u32::MAX)?;
    let v = read32(io, REG_H2CQ_CSR)?;
    io.write32(REG_H2CQ_CSR, v | (1 << 16) | (1 << 8))?;
    let v = read32(io, RTK_PCI_CTRL)?;
    io.write32(RTK_PCI_CTRL, v | (1 << 20) | (1 << 15))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::super::{
        beacon::tests::{Domain, Model, Source},
        identity::{Profile, tests::profile},
    };
    use super::*;
    use alloc::{sync::Arc, vec::Vec};
    use core::{cell::UnsafeCell, ptr::NonNull};
    use std::sync::Mutex;
    struct Bar {
        words: UnsafeCell<[u32; 0x1800 / 4]>,
    }
    impl Bar {
        fn pointer(&self) -> NonNull<u8> {
            NonNull::new(self.words.get().cast()).unwrap()
        }
        fn get(&self, reg: u32) -> u32 {
            unsafe {
                self.pointer()
                    .as_ptr()
                    .add(reg as usize)
                    .cast::<u32>()
                    .read_volatile()
            }
        }
        fn set(&self, reg: u32, value: u32) {
            unsafe {
                self.pointer()
                    .as_ptr()
                    .add(reg as usize)
                    .cast::<u32>()
                    .write_volatile(value);
            }
        }
    }
    type Native = NativeIo<Beacon<io::Bar>>;
    type Rx = receive::Ring<io::Bar>;
    type Tx = transmit::Rings<io::Bar>;
    // Native owners intentionally use Arc<dyn Any> without a Send promise.
    // This serialized CPU-affine fixture must not invent Sync for UnsafeCell.
    #[allow(clippy::arc_with_non_send_sync)]
    fn native() -> (Native, Rx, Tx, Arc<Bar>, Arc<Mutex<Model>>) {
        let bar = Arc::new(Bar {
            words: UnsafeCell::new([0; 0x1800 / 4]),
        });
        let memory = Arc::new(Mutex::new(Model::default()));
        let domain = Arc::new(Domain(memory.clone()));
        // SAFETY: synchronous UC-register/DMA model, initial stopped zero
        // indices/tag and real aligned native allocations at distinct IOVAs.
        // No physical bus or calibrated clock proof is claimed/exercised.
        let (io, rx, tx) = unsafe {
            let b = Beacon::install(
                io::Bar::new(bar.pointer(), 0x1800, profile(), bar.clone()).unwrap(),
                &Source,
                domain.clone(),
                beacon::FirmwareBand::Ghz2,
            )
            .unwrap();
            let rx = Rx::install(
                io::Bar::new(bar.pointer(), 0x1800, profile(), bar.clone()).unwrap(),
                &Source,
                domain.clone(),
            )
            .unwrap();
            let tx = Tx::install(
                io::Bar::new(bar.pointer(), 0x1800, profile(), bar.clone()).unwrap(),
                &Source,
                domain,
            )
            .unwrap();
            let io = NativeIo::new(
                bar.pointer(),
                0x1800,
                b,
                bar.clone(),
                crate::Clock {
                    ticks_per_microsecond: 1,
                },
                profile(),
            )
            .unwrap();
            (io, rx, tx)
        };
        (io, rx, tx, bar, memory)
    }
    #[test]
    fn post_power_rebinding_restores_every_actual_native_queue_base_without_unmapping() {
        let (mut io, mut rx, mut tx, bar, memory) = native();
        let regs = [
            0x308, 0x1320, 0x330, 0x328, 0x318, 0x320, 0x310, 0x340, 0x338,
        ];
        let original: Vec<_> = regs.iter().map(|r| bar.get(*r)).collect();
        assert!(original.iter().all(|v| *v != 0));
        assert_eq!(memory.lock().unwrap().mappings.len(), 522);
        // Model loss of actual queue bases/counts through MAC power. Software
        // configured flags survive, but have no authority to prove retention.
        for reg in regs {
            bar.set(reg, 0);
        }
        for reg in [0x380, 0x384, 0x388, 0x38c, 0x1328] {
            bar.set(reg, 0);
        }
        unsafe { setup(&mut io, &mut rx, &mut tx) }.unwrap();
        assert_eq!(
            regs.iter().map(|r| bar.get(*r)).collect::<Vec<_>>(),
            original
        );
        assert_eq!(bar.get(0x1330) & 0x10100, 0x10100);
        assert_eq!(bar.get(0x300) & 0x108000, 0x108000);
        assert_eq!(bar.get(0x39c), u32::MAX);
        assert!(
            !rx.quarantined() && !tx.quarantined() && !io.beacon_queue().unwrap().quarantined()
        );
        assert_eq!(memory.lock().unwrap().mappings.len(), 522);
        // Repeated initial source setup is allowed while no RX/command has
        // been admitted. This exercises post-power and post-download phases.
        unsafe { setup(&mut io, &mut rx, &mut tx) }.unwrap();
        unsafe { rx.release_after_stop() }.unwrap();
        unsafe { tx.release_after_stop() }.unwrap();
        unsafe { io.beacon_queue().unwrap().release_after_stop() }.unwrap();
        drop(io);
        drop(rx);
        drop(tx);
        assert!(memory.lock().unwrap().mappings.is_empty());
    }
    #[test]
    fn live_rx_or_command_generations_and_pending_beacon_cannot_be_reset() {
        for mode in 0..3 {
            let (mut io, mut rx, mut tx, bar, memory) = native();
            if mode == 0 {
                rx.poll(0, |_| panic!()).unwrap();
            }
            if mode == 1 {
                bar.set(REG_MCUFW_CTRL, 0xc078);
                tx.general_info(
                    &Source,
                    super::super::fifo::Geometry::for_profile(profile()).unwrap(),
                )
                .unwrap();
            }
            if mode == 2 {
                io.beacon_queue().unwrap().enqueue(&[0; 8]).unwrap();
            }
            let ptr_clear = bar.get(0x39c);
            assert!(unsafe { setup(&mut io, &mut rx, &mut tx) }.is_err());
            assert_eq!(bar.get(0x39c), ptr_clear);
            assert!(io.beacon_queue().is_err());
            drop(io);
            drop(rx);
            drop(tx);
            assert_eq!(
                memory.lock().unwrap().mappings.len(),
                522 + usize::from(mode == 1)
            );
        }
    }
    #[test]
    fn failed_cpu_visibility_before_rebinding_retains_all_native_resources() {
        for fail in [1, 2, 3, 9] {
            let (mut io, mut rx, mut tx, bar, memory) = native();
            memory.lock().unwrap().fail_cpu_sync_at = Some(fail);
            assert!(unsafe { setup(&mut io, &mut rx, &mut tx) }.is_err());
            assert_eq!(bar.get(0x39c), 0);
            assert!(io.beacon_queue().is_err());
            drop(io);
            drop(rx);
            drop(tx);
            assert_eq!(memory.lock().unwrap().mappings.len(), 522);
        }
    }
    struct Registers {
        bytes: Vec<u8>,
        events: Vec<[u32; 4]>,
        calls: usize,
        fail: Option<usize>,
        quarantined: bool,
        corrupt: Option<u32>,
    }
    impl Registers {
        fn new(case: u32) -> Self {
            Self {
                bytes: (0..0x1400)
                    .map(|r| ((r as u32 * 17 + case * 23) & 255) as u8)
                    .collect(),
                events: Vec::new(),
                calls: 0,
                fail: None,
                quarantined: false,
                corrupt: None,
            }
        }
        fn access(&mut self, reg: u32, width: usize, value: Option<u32>) -> Result<u32, io::Error> {
            self.calls += 1;
            if self.fail == Some(self.calls) {
                return Err(io::Error::Register);
            }
            let range = reg as usize..reg as usize + width;
            if let Some(value) = value {
                self.bytes[range.clone()].copy_from_slice(&value.to_le_bytes()[..width]);
            }
            let mut b = [0; 4];
            b[..width].copy_from_slice(&self.bytes[range]);
            let result = if value.is_none() && self.corrupt == Some(reg) {
                0
            } else {
                u32::from_le_bytes(b)
            };
            // Native independent queue-base readbacks are stricter additional
            // guards. Compare every source operation/access width/value, while
            // retaining the three source RMW reads in the exact original order.
            if value.is_some() || matches!(reg, 0x303 | 0x1330 | 0x300) {
                self.events
                    .push([u32::from(value.is_some()), reg, width as u32, result]);
            }
            Ok(result)
        }
    }
    // SAFETY: bounded serialized native register model; no actual DMA/radio.
    unsafe impl Io for Registers {
        fn profile(&self) -> Profile {
            profile()
        }
        fn read8(&mut self, r: u32) -> Result<u8, io::Error> {
            self.access(r, 1, None).map(|v| v as u8)
        }
        fn read16(&mut self, r: u32) -> Result<u16, io::Error> {
            self.access(r, 2, None).map(|v| v as u16)
        }
        fn read32(&mut self, r: u32) -> Result<u32, io::Error> {
            self.access(r, 4, None)
        }
        fn write8(&mut self, r: u32, v: u8) -> Result<(), io::Error> {
            self.access(r, 1, Some(v.into())).map(|_| ())
        }
        fn write16(&mut self, r: u32, v: u16) -> Result<(), io::Error> {
            self.access(r, 2, Some(v.into())).map(|_| ())
        }
        fn write32(&mut self, r: u32, v: u32) -> Result<(), io::Error> {
            self.access(r, 4, Some(v)).map(|_| ())
        }
        fn delay_us(&mut self, _: u64) {
            panic!("no clock poll in HCI reset");
        }
        fn submit_beacon(&mut self, _: &[u8]) -> Result<(), io::Error> {
            panic!("no submission in HCI reset");
        }
        unsafe fn beacon_consumed(&mut self) -> Result<(), io::Error> {
            panic!("no completion in HCI reset");
        }
        fn quarantine(&mut self) {
            self.quarantined = true;
        }
    }
    fn control(io: &mut Registers) -> Result<(), Error> {
        let mut a = Attempt { io, done: false };
        rebind(
            a.io,
            0x10010000,
            0x10090000,
            [
                0x10020000, 0x10030000, 0x10040000, 0x10050000, 0x10060000, 0x10070000, 0x10080000,
            ],
        )?;
        a.done = true;
        Ok(())
    }
    #[test]
    fn every_uncertain_control_operation_is_terminal_without_a_stop_claim() {
        let mut normal = Registers::new(0);
        control(&mut normal).unwrap();
        for call in 1..=normal.calls {
            let mut m = Registers::new(0);
            m.fail = Some(call);
            assert!(control(&mut m).is_err(), "operation {call}");
            assert!(m.quarantined);
        }
        for reg in [0x303, 0x1330, 0x300] {
            let mut m = Registers::new(0);
            let n = if reg == 0x303 { 1 } else { 4 };
            m.bytes[reg..reg + n].fill(255);
            assert_eq!(control(&mut m), Err(Error::Removed));
            assert!(m.quarantined);
        }
    }
    #[test]
    fn base_readback_and_fresh_post_reset_indices_are_required() {
        for reg in [
            0x308, 0x1328, 0x1320, 0x38a, 0x330, 0x388, 0x328, 0x384, 0x318, 0x386, 0x320, 0x380,
            0x310, 0x38c, 0x340, 0x382, 0x338,
        ] {
            let mut m = Registers::new(0);
            m.corrupt = Some(reg);
            assert_eq!(control(&mut m), Err(Error::Readback));
            assert!(m.quarantined);
        }
        for reg in [0x3b4, 0x132c] {
            let (mut io, mut rx, mut tx, bar, memory) = native();
            // Model a reset store that never produces actual zero indices.
            bar.set(reg, 1 << 16);
            assert!(unsafe { setup(&mut io, &mut rx, &mut tx) }.is_err());
            assert!(rx.quarantined() && tx.quarantined());
            assert!(io.beacon_queue().is_err());
            drop(io);
            drop(rx);
            drop(tx);
            assert_eq!(memory.lock().unwrap().mappings.len(), 522);
        }
    }
    #[test]
    #[ignore = "requires unchanged pinned C HCI reset/base oracle"]
    fn full_source_reset_sequence_and_widths_match_unchanged_c() {
        let trace = std::fs::read(std::env::var("STELA_REALTEK_WIFI_HCI_ORACLE").unwrap()).unwrap();
        let mut actual = Vec::new();
        for case in 0..16 {
            let mut m = Registers::new(case);
            control(&mut m).unwrap();
            for event in m.events {
                for word in event {
                    actual.extend_from_slice(&word.to_le_bytes());
                }
            }
        }
        assert_eq!(actual, trace);
    }
}
