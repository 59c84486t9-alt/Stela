// SPDX-License-Identifier: ISC
// Copyright (C) 2021 MediaTek Inc.
//! btusb_mtk_reset without a reset GPIO: btmtk_usb_subsys_reset through the
//! uhw register window, then usb_queue_reset_device whatever its outcome.
use super::super::{Error, Hci, Io, State};
use crate::{block::BlockError, usb::xhci::setup};

const MISC: u32 = 0x7000_2510;
const SUBSYS_RESET: u32 = 0x7000_2610;
const UDMA_INT_STA_BT: u32 = 0x7400_0024;
const UDMA_INT_STA_BT1: u32 = 0x7400_0308;
const WDT_STATUS: u32 = 0x7400_03a0;
const EP_RESET_OPTION: u32 = 0x7401_1890;
const EP_RESET_IN_OUT: u32 = 0x0001_0001;
const RESET_DONE: u32 = 0x100;
const RESET_CONNV3: u32 = 0x7002_8610;
const DEVICE_ID: u32 = 0x7001_0200;
/// readx_poll_timeout's sleep and timeout for MTK_BT_RST_DONE.
const POLL_US: u64 = 20_000;
const DONE_US: u64 = 1_000_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubsystemError {
    Usb(BlockError),
    /// A register read returned other than four bytes, which
    /// usb_control_msg_recv refuses.
    ShortRead(u32),
    /// MTK_BT_MISC never reported MTK_BT_RST_DONE within one second.
    Timeout,
    /// The device ID register read back zero after the reset.
    NoDevice,
}

/// What one btusb_mtk_reset did. The USB reset is queued even when the
/// subsystem reset failed, as Linux does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reset {
    /// btusb_mtk_release_iso_intf's failed cancellation, when media was open.
    pub media: Option<BlockError>,
    pub subsystem: Result<(), SubsystemError>,
    pub usb: Result<(), Error>,
}

/// Reset the controller identified by its device ID register. The transport
/// is closed afterwards and its USB topology owner rebinds a fresh one.
pub(super) fn run<B: Io>(hci: &mut Hci<B>, device_id: u32, media: Option<BlockError>) -> Reset {
    let subsystem = if hci.state() == State::Open {
        subsystem(&mut hci.io, device_id)
    } else {
        Err(SubsystemError::Usb(BlockError::Unsupported(
            "USB Bluetooth transport closed",
        )))
    };
    Reset {
        media,
        subsystem,
        usb: hci.queue_reset(),
    }
}

fn write<B: Io>(io: &mut B, address: u32, value: u32) -> Result<(), SubsystemError> {
    let request = setup(0x5e, 2, (address >> 16) as u16, address as u16, 4);
    io.control(request, &value.to_le_bytes())
        .map_err(SubsystemError::Usb)
}

fn read<B: Io>(io: &mut B, kind: u8, request: u8, address: u32) -> Result<u32, SubsystemError> {
    let request = setup(kind, request, (address >> 16) as u16, address as u16, 4);
    let bytes = io.control_read(request).map_err(SubsystemError::Usb)?;
    let bytes: [u8; 4] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| SubsystemError::ShortRead(address))?;
    Ok(u32::from_le_bytes(bytes))
}

/// btmtk_usb_uhw_reg_read.
fn uhw<B: Io>(io: &mut B, address: u32) -> Result<u32, SubsystemError> {
    read(io, 0xde, 1, address)
}

fn sleep<B: Io>(io: &B, us: u64) {
    let until = io.now_us().saturating_add(us);
    while io.now_us() < until {
        crate::waiting();
        core::hint::spin_loop();
    }
}

/// btmtk_usb_subsys_reset.
fn subsystem<B: Io>(io: &mut B, device_id: u32) -> Result<(), SubsystemError> {
    match device_id {
        0x7922 => {
            let value = uhw(io, SUBSYS_RESET)?;
            write(io, SUBSYS_RESET, value | 0x2020)?;
            write(io, EP_RESET_OPTION, EP_RESET_IN_OUT)?;
            let value = uhw(io, SUBSYS_RESET)?;
            write(io, SUBSYS_RESET, value | 1)?;
            sleep(io, 100_000);
        }
        0x7925 | 0x6639 => {
            let value = uhw(io, RESET_CONNV3)?;
            write(io, RESET_CONNV3, value | 1 << 5)?;
            let value = uhw(io, RESET_CONNV3)?;
            write(io, RESET_CONNV3, value & 0xffff_00ff | 1 << 13)?;
            write(io, EP_RESET_OPTION, EP_RESET_IN_OUT)?;
            let value = uhw(io, RESET_CONNV3)?;
            write(io, RESET_CONNV3, value | 1)?;
            write(io, UDMA_INT_STA_BT, 0xff)?;
            uhw(io, UDMA_INT_STA_BT)?;
            write(io, UDMA_INT_STA_BT1, 0xff)?;
            uhw(io, UDMA_INT_STA_BT1)?;
            sleep(io, 100_000);
        }
        _ => {
            write(io, EP_RESET_OPTION, EP_RESET_IN_OUT)?;
            uhw(io, WDT_STATUS)?;
            write(io, SUBSYS_RESET, 1)?;
            write(io, UDMA_INT_STA_BT, 0xff)?;
            uhw(io, UDMA_INT_STA_BT)?;
            write(io, UDMA_INT_STA_BT1, 0xff)?;
            uhw(io, UDMA_INT_STA_BT1)?;
            // MT7921 needs 20 ms between toggling the reset bit.
            sleep(io, 20_000);
            write(io, SUBSYS_RESET, 0)?;
            uhw(io, SUBSYS_RESET)?;
        }
    }
    // readx_poll_timeout over btmtk_usb_reset_done, where a failed read
    // counts as not done and one last read follows the deadline.
    let start = io.now_us();
    let done = loop {
        let late = io.now_us().saturating_sub(start) > DONE_US;
        if uhw(io, MISC).is_ok_and(|value| value & RESET_DONE != 0) {
            break true;
        }
        if late {
            break false;
        }
        sleep(io, POLL_US);
    };
    if device_id == 0x7922 {
        write(io, UDMA_INT_STA_BT, 0xff)?;
    }
    // btmtk_usb_id_get uses the ordinary vendor register read.
    if read(io, 0xc0, 0x63, DEVICE_ID)? == 0 && device_id != 0x6639 {
        return Err(SubsystemError::NoDevice);
    }
    if done {
        Ok(())
    } else {
        Err(SubsystemError::Timeout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usb::bluetooth::Pipe;
    use alloc::vec::Vec;
    use core::cell::Cell;

    struct Model {
        registers: Vec<(u32, u32)>,
        writes: Vec<(u32, u32)>,
        reads: Vec<u32>,
        done_after: usize,
        misc_reads: usize,
        time: Cell<u64>,
    }
    fn address(setup: [u8; 8]) -> u32 {
        u32::from(u16::from_le_bytes([setup[2], setup[3]])) << 16
            | u32::from(u16::from_le_bytes([setup[4], setup[5]]))
    }
    impl Io for Model {
        fn validate(&self) -> Result<(), BlockError> {
            Ok(())
        }
        fn control(&mut self, setup: [u8; 8], packet: &[u8]) -> Result<(), BlockError> {
            assert_eq!((setup[0], setup[1], setup[6]), (0x5e, 2, 4));
            let value = u32::from_le_bytes(packet.try_into().unwrap());
            self.writes.push((address(setup), value));
            Ok(())
        }
        fn control_read(&mut self, setup: [u8; 8]) -> Result<alloc::vec::Vec<u8>, BlockError> {
            let at = address(setup);
            self.reads.push(at);
            if at == MISC {
                self.misc_reads += 1;
                let done = self.misc_reads > self.done_after;
                return Ok((u32::from(done) * RESET_DONE).to_le_bytes().to_vec());
            }
            let kind = if at == DEVICE_ID {
                (0xc0, 0x63)
            } else {
                (0xde, 1)
            };
            assert_eq!((setup[0], setup[1]), kind);
            let value = self
                .registers
                .iter()
                .find(|(a, _)| *a == at)
                .map_or(0, |r| r.1);
            Ok(value.to_le_bytes().to_vec())
        }
        fn receive(&mut self, _: Pipe) -> Result<Option<alloc::vec::Vec<u8>>, BlockError> {
            unreachable!()
        }
        fn write_acl(&mut self, _: &[u8]) -> Result<(), BlockError> {
            unreachable!()
        }
        fn quiesce_bulk(&mut self) -> Result<(), BlockError> {
            unreachable!()
        }
        fn close(&mut self) -> Result<(), BlockError> {
            unreachable!()
        }
        fn now_us(&self) -> u64 {
            let now = self.time.get();
            self.time.set(now + 1_000);
            now
        }
    }
    fn model(done_after: usize, device: u32) -> Model {
        Model {
            registers: vec![(RESET_CONNV3, 0x1234_5600), (DEVICE_ID, device)],
            writes: Vec::new(),
            reads: Vec::new(),
            done_after,
            misc_reads: 0,
            time: Cell::new(0),
        }
    }

    #[test]
    fn mt7925_resets_connv3_and_waits_for_reset_done_like_btmtk_usb_subsys_reset() {
        let mut io = model(2, 0x7925);
        assert_eq!(subsystem(&mut io, 0x7925), Ok(()));
        assert_eq!(
            io.writes,
            [
                (RESET_CONNV3, 0x1234_5620),
                (RESET_CONNV3, 0x1234_2000),
                (EP_RESET_OPTION, EP_RESET_IN_OUT),
                (RESET_CONNV3, 0x1234_5601),
                (UDMA_INT_STA_BT, 0xff),
                (UDMA_INT_STA_BT1, 0xff),
            ]
        );
        assert_eq!(io.misc_reads, 3);
        assert_eq!(io.reads.last(), Some(&DEVICE_ID));
        // 100 ms settle, then two 20 ms polls before the done bit.
        assert!(io.time.get() >= 140_000);

        let mut io = model(usize::MAX, 0x7925);
        assert_eq!(subsystem(&mut io, 0x7925), Err(SubsystemError::Timeout));
        assert!(io.time.get() > 1_100_000 && io.reads.last() == Some(&DEVICE_ID));
        let mut io = model(usize::MAX, 0);
        assert_eq!(subsystem(&mut io, 0x7925), Err(SubsystemError::NoDevice));
    }

    #[test]
    fn mt7922_and_mt7961_take_their_own_subsystem_reset_branches() {
        let mut io = model(0, 0x7922);
        assert_eq!(subsystem(&mut io, 0x7922), Ok(()));
        assert_eq!(
            io.writes,
            [
                (SUBSYS_RESET, 0x2020),
                (EP_RESET_OPTION, EP_RESET_IN_OUT),
                (SUBSYS_RESET, 1),
                (UDMA_INT_STA_BT, 0xff),
            ]
        );
        let mut io = model(0, 0x7961);
        assert_eq!(subsystem(&mut io, 0x7961), Ok(()));
        assert_eq!(
            io.writes,
            [
                (EP_RESET_OPTION, EP_RESET_IN_OUT),
                (SUBSYS_RESET, 1),
                (UDMA_INT_STA_BT, 0xff),
                (UDMA_INT_STA_BT1, 0xff),
                (SUBSYS_RESET, 0),
            ]
        );
        assert!(io.reads.contains(&WDT_STATUS));
    }
}
