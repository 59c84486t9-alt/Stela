//! DWC3 offsets and bit encodings from Linux a0ff06b3 `dwc3/core.h`.
pub const GCTL: u64 = 0xc110;
pub const GSNPSID: u64 = 0xc120;
pub const GHWPARAMS: u64 = 0xc140;
pub const GUSB2PHYCFG: u64 = 0xc200;
pub const GUSB3PIPECTL: u64 = 0xc2c0;
pub const GTXFIFOSIZ: u64 = 0xc300;
pub const GRXFIFOSIZ: u64 = 0xc380;
pub const GEVNT: u64 = 0xc400;
pub const DCFG: u64 = 0xc700;
pub const DCTL: u64 = 0xc704;
pub const DEVTEN: u64 = 0xc708;
pub const DSTS: u64 = 0xc70c;
pub const DGCMDPAR: u64 = 0xc710;
pub const DGCMD: u64 = 0xc714;
pub const DALEPENA: u64 = 0xc720;
pub const DEP: u64 = 0xc800;
pub const STRIDE: u64 = 16;
pub const RUN: u32 = 1 << 31;
pub const RESET: u32 = 1 << 30;
pub const CMDACT: u32 = 1 << 10;
pub const CMDIOC: u32 = 1 << 8;
pub const INTMASK: u32 = 1 << 31;
pub const HWO: u32 = 1;
pub const LST: u32 = 1 << 1;
pub const CHN: u32 = 1 << 2;
pub const CSP: u32 = 1 << 3;
pub const ISP: u32 = 1 << 10;
pub const IOC: u32 = 1 << 11;
pub const LENGTH: u32 = 0x00ff_ffff;
pub const XFER_COMPLETE: u32 = 1;
pub const XFER_PROGRESS: u32 = 2;
pub const XFER_NOT_READY: u32 = 3;
pub const CMD_COMPLETE: u32 = 7;
pub const EV_SHORT: u32 = 1 << 1;
pub const EV_IOC: u32 = 1 << 2;
pub const EV_LST: u32 = 1 << 3;
pub const CFG_COMPLETE: u32 = 1 << 8;
pub const CFG_PROGRESS: u32 = 1 << 9;
pub const CFG_NOT_READY: u32 = 1 << 10;
pub const ENDPOINTS: usize = 32;
pub const RINGS: usize = 4;
pub const EVENT_BYTES: u32 = 4;
pub const TRB_BYTES: u64 = 16;

pub fn ep_event(ep: usize, kind: u32, status: u32, parameter: u32) -> u32 {
    (ep as u32) << 1 | kind << 6 | status << 12 | parameter << 16
}

pub fn device_event(kind: u32) -> u32 {
    1 | kind << 8
}
