//! NVMe command effects. Kernel evidence: `AppleNVMeRequest::BuildCommand*`
//! at 26A434 file 0x3deb4f8 (CQ), 0x3deb598 (SQ), 0x3deb56c/0x3deb62c
//! (delete CQ/SQ, CDW10 the queue ID), 0x3deb654 (Identify),
//! 0x3deb7ac..0x3deba30 (flush/read/write), 0x3debb80 (Dataset Management
//! Deallocate, `BuildCommandDeallocate`), 0x3debc88..0x3dec1dc
//! (logs/features), 0x3dec394 (Apple time), 0x3dec794 (namespace records),
//! 0x3dec980 (tunnel, with the tunable tables of [`super::tunables`]), and
//! 0x3dec1e0/0x3dec2ac/0x3dec35c (boot-from-host activate, download and
//! parameters, see [`super::bfh`]). Unknown vendor effects stop before
//! completion.
use super::{
    Ans, COMMAND_BYTES, COMPLETION_BYTES, MODE_RESTORE, NVMMU_PAGE_BYTES, Queue, bfh, die,
    namespace::ReadPlan,
    prp::{MAX_TRANSFER, Prps, dma_error},
    tunables,
};
use alloc::{vec, vec::Vec};
use stela_drivers::block::{BlockError, Finished, Request};
use stela_soc_data::ans::BLOCK_BYTES;
use {crate::platform::apple::sart::Sart, stela_contracts::dma::Port};

pub(super) const IDENTIFY_BYTES: usize = 4096;
/// `AppleANS2NVMeController::AllocateTunnelBuffer` (0x3dbe83c) rounds every
/// tunnel buffer up to 16 KiB (0x3dbe844..0x3dbe84c), `AppleNVMeBuffer::Init`
/// keeps that rounded size (0x3de6318) and `ProcessTunnelCommand`
/// (0x3de8acc..0x3de8b20) sends it as the output length at command +60.
const TUNNEL_PAGE: u32 = 0x4000;

/// The output length a tunnel request of `bytes` carries at command +60.
pub(super) const fn tunnel_buffer(bytes: u32) -> u32 {
    bytes.div_ceil(TUNNEL_PAGE) * TUNNEL_PAGE
}

/// Request type of `AppleEmbeddedNVMeController::SendTimeToDevice`
/// (0x3df6d7c, type stored at 0x3df6e64). It runs only after
/// `InitializeWallTime` (0x3db8020) has waited for IOBSD, stored
/// `kern.monotonicclock` at controller +0x408 and set +0x3f0 bit 2
/// (0x3dfa084), so the first one comes from the hourly housekeeping
/// (`HousekeepingTimerEvent` 0x3de9144, `DoHousekeeping` 0x3db7fa0) or a
/// later controller initialization (0x3db22b4) or format (0x3db5790).
const DEVICE_TIME: u32 = 6;
/// The CDW13 hints of a read or write: access frequency (3:0), priority
/// tier (10:8) and passive I/O (12).
const HINTS: u32 = 1 << 12 | 0x7 << 8 | 0xf;
const APPLE_DEBUG_SERVICE: u8 = 0xc2;

/// The host clocks one device-time tunnel carries (0x3df6e50..0x3df6e78),
/// in a 4 KiB request with no output buffer. The status at +0x4c must be 0
/// (0x3df6e8c); anything else is logged and returned as an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct DeviceTime {
    /// +0x1c, low word of `clock_get_calendar_nanotime`'s seconds
    /// (`UpdateTime` 0x3de9244..0x3de92ac): Unix time.
    pub calendar_seconds: u32,
    /// +0x20, low word of the PRTC counter at controller +0x400: the
    /// boot-time `kern.monotonicclock` plus the calendar seconds since
    /// `kern.boottime` (0x3de92f4..0x3de9304).
    pub prtc_seconds: u32,
    /// +0x24, `mach_absolute_time`.
    pub absolute: u64,
    /// +0x2c, `mach_continuous_time`.
    pub continuous: u64,
}

/// The named refusal for a tunnel request type the 26A434 IONVMeFamily can
/// build but the die does not serve. docs/research/ans2.md owns the census
/// (`Tunnel request census`). Each type below either has a builder that
/// J473AP's boot, restore and recovery paths leave idle, or reaches the
/// controller only through a user client's production tunnel.
fn unserved_tunnel(kind: u32) -> &'static str {
    match kind {
        3 => {
            "ANS QoS-parameter tunnel (type 3) is not modeled: only \
             AppleEmbeddedNVMeController::SetQoSParameters (0x3df71d0) builds it, and the ANS2 \
             controller's override (0x3dbeddc) sends nothing"
        }
        7 => {
            "ANS NAND-qualification tunnel (type 7) is not modeled: SetNANDQual (0x3df6fc8) sends \
             it only for the nand-qual boot-arg, and the die runs no NAND qualification"
        }
        0x22 => {
            "ANS NAND I/O-log tunnel (type 0x22) is not modeled: SetNANDIOLog (0x3e0ade4) sends it \
             only for the enable-IO-log boot-arg, and the die keeps no NAND I/O log"
        }
        0x37 => {
            "ANS legacy NAND geometry tunnel (type 0x37) is not modeled: the ANS2 driver sends it \
             (0x3df75ac) only after the V2 geometry request (type 0xba) fails"
        }
        0x52 => {
            "ANS calendar-time mode tunnel (type 0x52) is not modeled: SetATVMode (0x3df62f8) \
             sends it only with /defaults flash-use-calender-time, and its effect is not recovered"
        }
        0x97 => {
            "ANS BDR-factor tunnel (type 0x97) is not modeled: SetBDRFactor (0x3db7bd4) sends it \
             only with a bdr-factor property on the ANS node, and its effect is not recovered"
        }
        0xb1 => {
            "ANS TT-parameter tunnel (type 0xb1) is not modeled: SetTTParams (0x3dfb1d4) sends it \
             only for the raid or fastbm boot-args, and their effect is not recovered"
        }
        0x309 | 0x30a => {
            "ANS sleep-notice tunnel (types 0x309/0x30a) is not modeled: systemPowerChange \
             (0x3dc1dcc) sends it only after register 0x1314 subscribes, and the die reports no \
             notices"
        }
        0x311 => {
            "ANS virtual-card size tunnel (type 0x311) is not modeled: GetVirtualCardSize \
             (0x3dc2638) asks only from a setProperties call, and the die has no virtual card"
        }
        0x0a..=0x11 | 0x16 | 0x91 | 0xdd => {
            "ANS production tunnel type is not modeled: AppleNVMeUpdateUC permits it without an \
             entitlement (0x3dcb6d4..0x3dcb700), but no driver builds it and its contract is not \
             recovered"
        }
        _ => "ANS tunnel request type or output is not modeled",
    }
}
/// Apple hardware personality (Linux `include/linux/pci_ids.h`). The model
/// identifies its own software as Stela and offers one read-only firmware
/// slot; these are emulated-die choices, not copied Apple firmware data.
const APPLE_VENDOR_ID: u16 = 0x106b;
const READ_ONLY_FIRMWARE_SLOT: u8 = (1 << 1) | 1;
const SUCCESS: u16 = 0;
const INVALID_FIELD: u16 = 2;
const DATA_TRANSFER_ERROR: u16 = 4;
pub(super) const INVALID_NAMESPACE: u16 = 0xb;
/// Command-specific status (SCT 1): Invalid Queue Identifier and Invalid
/// Queue Deletion (NVMe 1.4 figures 145 and 151).
const INVALID_QUEUE: u16 = 0x101;
const INVALID_DELETION: u16 = 0x10c;
const LBA_RANGE: u16 = 0x80;
const WRITE_PROTECTED: u16 = 0x20;
const DELETE_SQ: u8 = 0;
const CREATE_SQ: u8 = 1;
const DELETE_CQ: u8 = 4;
const CREATE_CQ: u8 = 5;
const IDENTIFY: u8 = 6;
const SET_FEATURES: u8 = 9;
const GET_FEATURES: u8 = 0xa;
const FIRMWARE_COMMIT: u8 = 0x10;
const FIRMWARE_DOWNLOAD: u8 = 0x11;
const APPLE_TIME: u8 = 0xc0;
const APPLE_NAMESPACES: u8 = 0xc6;
const APPLE_BFH_PARAMS: u8 = 0xd1;
/// `BuildCommandIdentifyStorageDevice` (0x3dec950): CDW13 the selector and a
/// 4 KiB response whose +0x200 holds the running NAND firmware's UUID.
/// Only `AppleANS2NVMeController::FirmwareVersionCheck` (0x3dc0c68, from
/// user-client selector 12) sends it, on the updater's `--update` path.
const APPLE_IDENTIFY_STORAGE: u8 = 0xc8;
const APPLE_TUNNEL: u8 = 0xd8;
const FLUSH: u8 = 0;
/// CDW12 bit 30 of a read or write.
const FORCE_UNIT_ACCESS: u32 = 1 << 30;
/// Feature 06h, Volatile Write Cache: bit 0 enables it.
pub(super) const VOLATILE_WRITE_CACHE: usize = 6;
const WRITE: u8 = 1;
const READ: u8 = 2;
const COMPARE: u8 = 5;
/// Dataset Management (NVMe 1.4 6.7). `BuildCommandDeallocate` (0x3debb80)
/// puts the namespace in CDW1, the 0's-based range count in CDW10 and
/// [`DEALLOCATE`] in CDW11; its 4 KiB range list is PRP data the device reads.
/// `AppleNVMeNamespaceDevice::unmapBlocks` (0x3dd4400) sends one range, from
/// `AppleNVMeEAN::eanFormat` (0x3dce9e0) and `eraseImage` (0x3dcf860) on the
/// EAN namespace; `IONVMeBlockStorageDevice::doUnmapNVMe` (0x3dee810) sends up
/// to 256 for the block-storage namespaces once ONCS reports the command.
const DATASET_MANAGEMENT: u8 = 9;
/// CDW11 attribute AD (bit 2), the only attribute the builder sets.
const DEALLOCATE: u32 = 1 << 2;
/// One Dataset Management range: context attributes, length, starting LBA.
const RANGE_BYTES: usize = 16;
/// ONCS (Identify controller bytes 520..521): Compare (bit 0) and Dataset
/// Management (bit 2). `IONVMeController::ProcessIdentifyData`
/// (0x3ddc7bc..0x3ddc7c8) keeps bit 2 as `IsDatasetManagementSupported`.
const ONCS: u16 = 1 | (1 << 2);
/// DLFEAT (Identify namespace byte 33) 001b: a deallocated block reads as
/// zeros, which [`super::namespace::Medium::deallocate`] provides and the
/// host keeps past a restart where its Write Zeroes deallocates
/// ([`super::host::HostDisk::deallocates_zeroed`]); 000b otherwise.
const DLFEAT_READ_ZEROS: u8 = 1;

pub(super) struct Command(pub [u8; 64]);
impl Command {
    pub fn opcode(&self) -> u8 {
        self.0[0]
    }
    pub fn cid(&self) -> u16 {
        u16::from_le_bytes(self.0[2..4].try_into().unwrap())
    }
    fn word(&self, offset: usize) -> u32 {
        u32::from_le_bytes(self.0[offset..offset + 4].try_into().unwrap())
    }
    fn long(&self, offset: usize) -> u64 {
        u64::from_le_bytes(self.0[offset..offset + 8].try_into().unwrap())
    }
    fn nsid(&self) -> u32 {
        self.word(4)
    }
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.0[1] != 0 || self.0[8..24].iter().any(|&b| b != 0) {
            return Err("ANS fused, SGL, metadata or reserved command fields are not modeled");
        }
        Ok(())
    }
    pub fn direction(&self, queue: usize) -> Result<u8, &'static str> {
        if queue == 0 {
            match self.opcode() {
                // The builders (0x3deb4f8, 0x3deb598) put the queue base
                // straight into PRP1 and attach no memory descriptor, so the
                // TCB grants no DMA: queue memory is reached physically.
                CREATE_SQ | CREATE_CQ | DELETE_SQ | DELETE_CQ => Ok(0),
                APPLE_TIME => Ok(0),
                APPLE_DEBUG_SERVICE => Ok(0),
                IDENTIFY => Ok(1),
                SET_FEATURES | GET_FEATURES if self.long(24) == 0 => Ok(0),
                APPLE_NAMESPACES => Ok(2),
                FIRMWARE_DOWNLOAD | APPLE_BFH_PARAMS => Ok(2),
                FIRMWARE_COMMIT => Ok(0),
                // Tunnel addresses are in CDW11-14, not the PRPs. It is
                // authorized by SART, with an NVMMU entry but no PRP DMA.
                APPLE_TUNNEL => Ok(0),
                APPLE_IDENTIFY_STORAGE => Err(
                    "ANS Identify Storage Device (0xc8) is not modeled: the die runs no NAND \
                     firmware whose UUID it could report",
                ),
                _ => Err("ANS admin opcode or DMA contract is not modeled"),
            }
        } else {
            match self.opcode() {
                READ => Ok(1),
                // The range list is read by the device, like write data.
                WRITE | COMPARE | DATASET_MANAGEMENT => Ok(2),
                FLUSH => Ok(0),
                _ => Err("ANS I/O opcode is not modeled"),
            }
        }
    }
    fn prps(&self, port: &mut Port<'_, '_>, bytes: usize, page: u64) -> Result<Prps, &'static str> {
        Prps::new(port, self.long(24), self.long(32), bytes, page)
    }
    fn zero_words(&self, from: usize) -> bool {
        self.0[from..].iter().all(|&b| b == 0)
    }
}

pub(super) struct Outcome {
    pub result: u32,
    pub status: u16,
}
impl Outcome {
    fn status(status: u16) -> Self {
        Self { result: 0, status }
    }
    fn result(result: u32) -> Self {
        Self {
            result,
            status: SUCCESS,
        }
    }
}
/// What executing a command left: its outcome, or the host transfer it
/// waits for ([`super::host`]).
pub(super) enum Executed {
    Done(Outcome),
    Host(Wait),
}

/// A test's command, run without a host executor, completes at once.
#[cfg(test)]
impl core::ops::Deref for Executed {
    type Target = Outcome;
    fn deref(&self) -> &Outcome {
        match self {
            Self::Done(outcome) => outcome,
            Self::Host(_) => panic!("a command without a host executor completes at once"),
        }
    }
}

/// What an I/O command does once its host transfer completes
/// ([`Ans::finish`]).
pub(super) enum Wait {
    Read {
        plan: ReadPlan,
        bytes: usize,
        prps: Prps,
    },
    Compare {
        plan: ReadPlan,
        data: Vec<u8>,
    },
    Write {
        nsid: u32,
        lba: u64,
        blocks: u64,
    },
    Flush,
    /// The host's blocks deallocated, or zeroed.
    Deallocate,
}

/// The host's bytes of a read: none for one whose blocks are all erased.
fn host_bytes(done: Option<Finished>) -> Result<Option<Vec<u8>>, BlockError> {
    match done {
        None => Ok(None),
        Some(Ok(Some(data))) => Ok(Some(data)),
        Some(Ok(None)) => Err(BlockError::Protocol("ANS host read returned no data")),
        Some(Err(error)) => Err(error),
    }
}

fn block_result(result: Result<(), BlockError>) -> Outcome {
    Outcome::status(match result {
        Ok(()) => SUCCESS,
        Err(BlockError::ReadOnly) => WRITE_PROTECTED,
        Err(_) => DATA_TRANSFER_ERROR,
    })
}
pub(super) fn put16(data: &mut [u8], offset: usize, value: u16) {
    data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
pub(super) fn put32(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
pub(super) fn put64(data: &mut [u8], offset: usize, value: u64) {
    data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn ascii(data: &mut [u8], value: &[u8]) {
    data.fill(b' ');
    let len = value.len().min(data.len());
    data[..len].copy_from_slice(&value[..len]);
}

impl Ans {
    pub(super) fn execute(
        &mut self,
        queue: usize,
        cmd: &Command,
        port: &mut Port<'_, '_>,
        sart: &mut Sart,
    ) -> Result<Executed, &'static str> {
        if queue != 0 {
            let key = (queue as u32) << 16 | u32::from(cmd.cid());
            return self.io(key, cmd, port);
        }
        self.admin(cmd, port, sart).map(Executed::Done)
    }

    fn admin(
        &mut self,
        cmd: &Command,
        port: &mut Port<'_, '_>,
        sart: &mut Sart,
    ) -> Result<Outcome, &'static str> {
        match cmd.opcode() {
            IDENTIFY => self.identify(cmd, port),
            APPLE_DEBUG_SERVICE => {
                if cmd.nsid() != 0
                    || cmd.long(24) != 0
                    || cmd.long(32) != 0
                    || cmd.word(40) != 0
                    || cmd.word(44) != 0
                    || cmd.word(60) != 0
                {
                    return Err("ANS debug-service DMA or reserved fields are not modeled");
                }
                self.debug
                    .execute(cmd.word(48), cmd.word(52), cmd.word(56))
                    .map(|reply| match reply {
                        super::debug::Reply::Value(value) => Outcome::result(value),
                        super::debug::Reply::InvalidField => Outcome::status(INVALID_FIELD),
                    })
            }
            CREATE_CQ | CREATE_SQ => self.create_queue(cmd),
            DELETE_CQ | DELETE_SQ => self.delete_queue(cmd),
            SET_FEATURES | GET_FEATURES => self.feature(cmd),
            APPLE_TIME => {
                if cmd.nsid() != 0
                    || cmd.long(24) != 0
                    || cmd.long(32) != 0
                    || cmd.word(40) != 0
                    || cmd.word(44) != 0
                    || !cmd.zero_words(56)
                {
                    return Err("ANS Apple time command fields are not modeled");
                }
                self.timestamp = cmd.long(48);
                Ok(Outcome::status(SUCCESS))
            }
            APPLE_NAMESPACES => self.verify_namespaces(cmd, port),
            APPLE_TUNNEL => self.tunnel(cmd, port, sart),
            FIRMWARE_DOWNLOAD | FIRMWARE_COMMIT | APPLE_BFH_PARAMS => {
                self.boot_from_host(cmd, port)
            }
            _ => Err("ANS admin command is not modeled"),
        }
    }

    /// The restore controller's boot-from-host commands ([`bfh`]). Only
    /// MODESEL 4 accepts them: the kernel issues them only while its BFH
    /// flag is set (`IsBFHRequired` 0x3dbe014), the flag that also selects
    /// that mode (`PreCCEnableHook` 0x3dbdfb8). Standard firmware slots
    /// stay read-only and OACS still reports no firmware commands.
    fn boot_from_host(
        &mut self,
        cmd: &Command,
        port: &mut Port<'_, '_>,
    ) -> Result<Outcome, &'static str> {
        if self.modesel != MODE_RESTORE {
            return Err("ANS boot-from-host command outside MODESEL 4");
        }
        if cmd.nsid() != 0 {
            return Err("ANS boot-from-host command names a namespace");
        }
        if cmd.opcode() == FIRMWARE_COMMIT {
            if cmd.long(24) != 0
                || cmd.long(32) != 0
                || cmd.word(40) != bfh::ACTIVATE_SLOT0_REPLACE
                || !cmd.zero_words(44)
            {
                return Err("ANS firmware commit other than slot 0, action 1 is not modeled");
            }
            self.boot_image = Some(self.download.activate()?);
            return Ok(Outcome::status(SUCCESS));
        }
        let bytes = (u64::from(cmd.word(40)) + 1) * 4;
        if bytes > MAX_TRANSFER as u64 {
            return Err("ANS boot-from-host transfer exceeds MDTS");
        }
        let mut data = vec![0; bytes as usize];
        if cmd.opcode() == APPLE_BFH_PARAMS {
            if !cmd.zero_words(44) {
                return Err("ANS BFH parameter command fields are not modeled");
            }
            cmd.prps(port, data.len(), NVMMU_PAGE_BYTES)?
                .read(port, &mut data)?;
            self.download.params(&data)?;
            return Ok(Outcome::status(SUCCESS));
        }
        if cmd.word(48) != 0 || cmd.word(52) != 0 {
            return Err("ANS BFH download CDW12/CDW13 are not modeled");
        }
        cmd.prps(port, data.len(), NVMMU_PAGE_BYTES)?
            .read(port, &mut data)?;
        self.download.chunk(
            cmd.word(56),
            u64::from(cmd.word(44)) * 4,
            &data,
            cmd.word(60),
        )?;
        Ok(Outcome::status(SUCCESS))
    }

    fn identify(
        &mut self,
        cmd: &Command,
        port: &mut Port<'_, '_>,
    ) -> Result<Outcome, &'static str> {
        if cmd.word(40) & !0xff != 0 || !cmd.zero_words(44) {
            return Err("ANS Identify fields are not modeled");
        }
        let mut data = [0; IDENTIFY_BYTES];
        match cmd.word(40) {
            1 if cmd.nsid() == 0 => {
                self.controller_identity(&mut data);
                // IdentifyNamespaces passes NSID 0 to IssueIdentifyCommand
                // (26A434 file 0x3db24c8), which selects CNS 1 at
                // 0x3ddfffc..0x3de0004. Apple's private controller fields
                // therefore extend the standard controller response.
                die::identify(&self.medium, &mut data)?;
                data[260] = READ_ONLY_FIRMWARE_SLOT;
                data[77] = 8; // MDTS: 2^8 * 4 KiB = 1 MiB.
                put16(&mut data, 78, 1); // Controller ID, Stela choice.
                put32(&mut data, 80, super::VERSION as u32);
                data[512] = 0x66;
                data[513] = 0x44; // SQES/CQES max and min.
                put32(&mut data, 516, self.medium.namespaces.len() as u32);
                put16(&mut data, 520, ONCS); // No write zeroes or crypto.
                // VWC: the host disk's own cache. OACS is zero: no
                // downloadable firmware.
                data[525] = u8::from(self.medium.device.write_cache());
            }
            0 => {
                let Some(ns) = self.medium.namespace(cmd.nsid()) else {
                    return Ok(Outcome::status(INVALID_NAMESPACE));
                };
                for offset in [0, 8, 16] {
                    put64(&mut data, offset, ns.blocks);
                }
                data[33] = if self.medium.device.deallocates_zeroed() {
                    DLFEAT_READ_ZEROS
                } else {
                    0
                };
                data[130] = 12; // LBAF0.LBADS; zero metadata, one format.
                data[0x180] = ns.description.kind as u8;
            }
            2 => {
                for (slot, ns) in self
                    .medium
                    .namespaces
                    .iter()
                    .filter(|ns| ns.description.id > cmd.nsid())
                    .enumerate()
                {
                    put32(&mut data, slot * 4, ns.description.id);
                }
            }
            _ => return Err("ANS Identify selector is not modeled"),
        }
        cmd.prps(port, data.len(), NVMMU_PAGE_BYTES)?
            .write(port, &data)?;
        Ok(Outcome::status(SUCCESS))
    }

    /// Common standard identity fields read by both Identify selectors.
    fn controller_identity(&self, data: &mut [u8]) {
        put16(data, 0, APPLE_VENDOR_ID);
        put16(data, 2, APPLE_VENDOR_ID);
        ascii(
            &mut data[4..24],
            self.medium.device.identity().serial.as_bytes(),
        );
        ascii(&mut data[24..64], b"Stela ANS2");
        ascii(&mut data[64..72], b"1.0");
    }

    fn create_queue(&mut self, cmd: &Command) -> Result<Outcome, &'static str> {
        let id = cmd.word(40) & 0xffff;
        let depth = (cmd.word(40) >> 16) + 1;
        if cmd.nsid() != 0
            || cmd.long(32) != 0
            || !cmd.zero_words(48)
            || cmd.long(24) == 0
            || !cmd.long(24).is_multiple_of(self.page())
        {
            return Err("ANS queue creation fields or address are not modeled");
        }
        if id != 1 || depth > u32::from(self.geometry.ring_entries()) {
            return Ok(Outcome::status(INVALID_FIELD));
        }
        let bytes = if cmd.opcode() == CREATE_CQ {
            COMPLETION_BYTES
        } else {
            COMMAND_BYTES
        } * u64::from(depth);
        if cmd.long(24).checked_add(bytes).is_none() {
            return Err("ANS queue creation extent wraps");
        }
        let flags = cmd.word(44);
        if cmd.opcode() == CREATE_CQ {
            if flags & !3 != 0 || flags & 1 == 0 {
                return Err("ANS CQ requires contiguous memory and interrupt vector zero");
            }
            if self.queues[1].cq_enabled {
                return Ok(Outcome::status(INVALID_FIELD));
            }
            self.queues[1] = Queue {
                cq: cmd.long(24),
                cq_entries: depth as u16,
                cq_enabled: true,
                phase: true,
                interrupt: flags & 2 != 0,
                ..Queue::default()
            };
        } else {
            // QPRIO (bits 2:1) is ignored under the round-robin arbitration
            // CC.AMS 0 selects (NVMe 1.4 5.4); the driver sends medium.
            if flags & 1 == 0 || flags & 0xfff8 != 0 || flags >> 16 != 1 {
                return Err("ANS SQ must be contiguous and use CQ 1");
            }
            let q = &mut self.queues[1];
            if q.sq_enabled || !q.cq_enabled {
                return Ok(Outcome::status(INVALID_FIELD));
            }
            q.sq = cmd.long(24);
            q.sq_entries = depth as u16;
            q.sq_enabled = true;
        }
        Ok(Outcome::status(SUCCESS))
    }

    /// `IONVMeController::ShutdownNVMe` deletes the I/O SQ, then its CQ
    /// (`DisableSubmissionQueues` 0x3ddbc78, `DisableCompletionQueue`
    /// 0x3ddbcb4), before the shutdown notification.
    fn delete_queue(&mut self, cmd: &Command) -> Result<Outcome, &'static str> {
        if cmd.nsid() != 0 || cmd.long(24) != 0 || cmd.long(32) != 0 || !cmd.zero_words(44) {
            return Err("ANS queue deletion fields are not modeled");
        }
        let q = &mut self.queues[1];
        if cmd.word(40) != 1 {
            return Ok(Outcome::status(INVALID_QUEUE));
        }
        if cmd.opcode() == DELETE_SQ {
            if !q.sq_enabled {
                return Ok(Outcome::status(INVALID_QUEUE));
            }
            if self.pending.iter().any(|&(queue, _)| queue == 1) {
                return Err("ANS SQ deletion with commands outstanding is not modeled");
            }
            q.sq = 0;
            q.sq_entries = 0;
            q.sq_enabled = false;
        } else {
            if !q.cq_enabled {
                return Ok(Outcome::status(INVALID_QUEUE));
            }
            if q.sq_enabled {
                return Ok(Outcome::status(INVALID_DELETION));
            }
            *q = Queue::default();
        }
        Ok(Outcome::status(SUCCESS))
    }

    fn feature(&mut self, cmd: &Command) -> Result<Outcome, &'static str> {
        let id = cmd.word(40);
        if cmd.nsid() != 0 || cmd.long(32) != 0 || id & !0xff != 0 || !cmd.zero_words(48) {
            return Err("ANS saved/selected or namespace-specific features are not modeled");
        }
        let value = cmd.word(44);
        let setting = cmd.opcode() == SET_FEATURES;
        match id {
            0xc0..=0xc2 if !setting && value == 0 => {
                // Emulated die: Stela's choice, consumed by GetNANDInfo
                // (0x3dbec38/0x3dbec5c) as low/high descriptor words;
                // GetMSPType (0x3dbed48) as MSP code S3E, matching c1c.
                Ok(Outcome::result(match id {
                    0xc0 => die::DESCRIPTOR as u32,
                    0xc1 => (die::DESCRIPTOR >> 32) as u32,
                    _ => 0,
                }))
            }
            7 => Ok(Outcome::result(0)), // Exactly one I/O SQ/CQ, zero based.
            6 if self.medium.device.write_cache() => {
                // The host's cache stays on; with this one off, each write
                // completes once the host has flushed it as well.
                if setting {
                    if value & !1 != 0 {
                        return Err("ANS Volatile Write Cache value is not modeled");
                    }
                    self.features[VOLATILE_WRITE_CACHE] = value;
                }
                Ok(Outcome::result(self.features[VOLATILE_WRITE_CACHE]))
            }
            1 | 2 | 4 | 5 | 6 | 8 | 9 | 10 | 11 => {
                // Round-robin arbitration, power state 0, no volatile cache
                // where the host disk has none,
                // immediate interrupts and no async event source. The
                // temperature threshold/error-recovery limit hold state.
                if setting
                    && match id {
                        1 | 2 | 6 | 8 | 9 | 10 | 11 => value != 0,
                        4 | 5 => value > 0xffff,
                        _ => false,
                    }
                {
                    return Err("ANS feature value requires an unmodeled controller effect");
                }
                if !setting && value != 0 {
                    return Err("ANS Get Features has nonzero CDW11");
                }
                if setting {
                    self.features[id as usize] = value;
                }
                Ok(Outcome::result(self.features[id as usize]))
            }
            _ => Err("ANS feature ID is not modeled"),
        }
    }

    /// I/O command `cmd`, whose host transfer runs under `key`.
    fn io(
        &mut self,
        key: u32,
        cmd: &Command,
        port: &mut Port<'_, '_>,
    ) -> Result<Executed, &'static str> {
        if self.medium.namespace(cmd.nsid()).is_none() {
            return Ok(Executed::Done(Outcome::status(INVALID_NAMESPACE)));
        }
        if cmd.opcode() == FLUSH {
            // CDW10 bit 0 asks for a barrier: IONVMeBlockStorageDevice's
            // synchronize (0x3dee350) sets it from kIOStorageSynchronize-
            // OptionBarrier when the controller supports one. Writes here
            // complete durably in order, so a full flush keeps the barrier.
            if cmd.long(24) != 0
                || cmd.long(32) != 0
                || cmd.word(40) & !1 != 0
                || !cmd.zero_words(44)
            {
                return Err("ANS Flush fields are not modeled");
            }
            return self.host(key, vec![Request::Flush], Wait::Flush, port);
        }
        if cmd.opcode() == DATASET_MANAGEMENT {
            return self.dataset_management(key, cmd, port);
        }
        let controls = cmd.word(48);
        // CDW13 carries hints the controller may ignore, from
        // `AppleNVMeRequest`'s read and write builders (0x3deb7d4, 0x3deb8f4):
        // bits 3:0 NVMe's Dataset Management access frequency, bits 10:8
        // the request's priority tier and bit 12 passive I/O. The writes'
        // bit 11 has no established meaning and refuses.
        if controls & !(FORCE_UNIT_ACCESS | 0xffff) != 0
            || cmd.word(52) & !HINTS != 0
            || !cmd.zero_words(56)
        {
            return Err("ANS protection, encryption, metadata or read/write hints are not modeled");
        }
        let blocks = u64::from((controls & 0xffff) + 1);
        let lba = cmd.long(40);
        if self.medium.address(cmd.nsid(), lba, blocks).is_none() {
            return Ok(Executed::Done(Outcome::status(LBA_RANGE)));
        }
        let bytes = blocks as usize * BLOCK_BYTES as usize;
        if bytes > MAX_TRANSFER {
            return Ok(Executed::Done(Outcome::status(INVALID_FIELD)));
        }
        let prps = cmd.prps(port, bytes, NVMMU_PAGE_BYTES)?;
        let (nsid, range) = (cmd.nsid(), "ANS I/O range was checked");
        match cmd.opcode() {
            READ | COMPARE => {
                let plan = self.medium.plan_read(nsid, lba, blocks).expect(range);
                let request = plan.address.map(|lba| Request::Read { lba, bytes });
                let requests = request.into_iter().collect();
                let wait = if cmd.opcode() == READ {
                    Wait::Read { plan, bytes, prps }
                } else {
                    let mut data = vec![0; bytes];
                    prps.read(port, &mut data)?;
                    Wait::Compare { plan, data }
                };
                self.host(key, requests, wait, port)
            }
            WRITE => {
                let mut data = vec![0; bytes];
                prps.read(port, &mut data)?;
                let address = self.medium.address(nsid, lba, blocks).expect(range);
                // Force Unit Access: this write completes durably whatever
                // the cache. A read returns the same bytes either way.
                let request = Request::Write {
                    lba: address,
                    data,
                    durable: self.write_through() || controls & FORCE_UNIT_ACCESS != 0,
                };
                self.host(key, vec![request], Wait::Write { nsid, lba, blocks }, port)
            }
            _ => Err("ANS I/O command is not modeled"),
        }
    }

    /// Submit an I/O command's host transfers under `key`, none for a read
    /// of erased blocks alone, and finish the command at once unless the
    /// host disk completes them later ([`super::host`]).
    fn host(
        &mut self,
        key: u32,
        requests: Vec<Request>,
        wait: Wait,
        port: &mut Port<'_, '_>,
    ) -> Result<Executed, &'static str> {
        if requests.is_empty() {
            return self.finish(wait, None, port).map(Executed::Done);
        }
        match self.medium.device.submit(key, requests, port.access.now) {
            Some(done) => self.finish(wait, Some(done), port).map(Executed::Done),
            None => Ok(Executed::Host(wait)),
        }
    }

    /// Whether a write completes only once durable: this controller's
    /// cache is off while the host disk's is on.
    fn write_through(&self) -> bool {
        self.medium.device.write_cache() && self.features[VOLATILE_WRITE_CACHE] == 0
    }

    /// An I/O command's outcome once its host transfer is `done`.
    pub(super) fn finish(
        &mut self,
        wait: Wait,
        done: Option<Finished>,
        port: &mut Port<'_, '_>,
    ) -> Result<Outcome, &'static str> {
        Ok(match (wait, done) {
            (Wait::Read { plan, bytes, prps }, done) => match host_bytes(done) {
                Ok(host) => {
                    prps.write(port, &plan.finish(bytes, host))?;
                    Outcome::status(SUCCESS)
                }
                Err(error) => block_result(Err(error)),
            },
            (Wait::Compare { plan, data }, done) => match host_bytes(done) {
                Ok(host) => Outcome::status(if plan.finish(data.len(), host) == data {
                    SUCCESS
                } else {
                    0x285
                }),
                Err(error) => block_result(Err(error)),
            },
            (Wait::Write { nsid, lba, blocks }, Some(result)) => {
                if result.is_ok() {
                    self.medium.written(nsid, lba, blocks);
                }
                block_result(result.map(drop))
            }
            (Wait::Flush | Wait::Deallocate, Some(result)) => block_result(result.map(drop)),
            (Wait::Deallocate, None) => Outcome::status(SUCCESS),
            _ => return Err("ANS host transfer result differs from its command"),
        })
    }

    /// Deallocate every listed range. Ranges are all checked before any
    /// takes effect, so an out-of-range entry fails the whole command (LBA
    /// Out of Range) with nothing deallocated. Integral-dataset hints (IDR,
    /// IDW) and context attributes carry no modeled effect and refuse. The
    /// blocks read as zeros at once; the host's blocks are zeroed with
    /// deallocation where its Write Zeroes deallocates, so they stay zeros,
    /// else discarded where it takes discard, which lets an SSD erase them
    /// ahead of its next write, under `key`.
    fn dataset_management(
        &mut self,
        key: u32,
        cmd: &Command,
        port: &mut Port<'_, '_>,
    ) -> Result<Executed, &'static str> {
        let count = cmd.word(40);
        if count & !0xff != 0 || cmd.word(44) != DEALLOCATE || !cmd.zero_words(48) {
            return Err(
                "ANS Dataset Management is modeled only as Deallocate without hints or reserved fields",
            );
        }
        let ranges = count as usize + 1;
        let mut list = vec![0; ranges * RANGE_BYTES];
        cmd.prps(port, list.len(), NVMMU_PAGE_BYTES)?
            .read(port, &mut list)?;
        let mut extents = vec![];
        for range in list.as_chunks::<RANGE_BYTES>().0 {
            let word = |at: usize| u32::from_le_bytes(range[at..at + 4].try_into().unwrap());
            if word(0) != 0 {
                return Err("ANS Dataset Management context attributes are not modeled");
            }
            let blocks = u64::from(word(4));
            let lba = u64::from_le_bytes(range[8..].try_into().unwrap());
            let fits = lba
                .checked_add(blocks)
                .is_some_and(|end| end <= self.medium.namespace(cmd.nsid()).unwrap().blocks);
            if !fits {
                return Ok(Executed::Done(Outcome::status(LBA_RANGE)));
            }
            extents.push((lba, blocks));
        }
        let zeroed = self.medium.device.deallocates_zeroed();
        let discard = self.medium.device.identity().features.discard.is_some();
        let mut requests = vec![];
        for (lba, blocks) in extents {
            self.medium
                .deallocate(cmd.nsid(), lba, blocks)
                .expect("a checked range");
            let (lba, blocks) = self
                .medium
                .host_extent(cmd.nsid(), lba, blocks)
                .expect("a checked range");
            if blocks == 0 {
                continue;
            }
            if zeroed {
                requests.push(Request::WriteZeroes {
                    lba,
                    blocks,
                    unmap: true,
                });
            } else if discard {
                requests.push(Request::Discard { lba, blocks });
            }
        }
        self.host(key, requests, Wait::Deallocate, port)
    }

    fn verify_namespaces(
        &mut self,
        cmd: &Command,
        port: &mut Port<'_, '_>,
    ) -> Result<Outcome, &'static str> {
        if cmd.nsid() != 0 || cmd.word(40) != 0 || !cmd.zero_words(44) {
            return Err("ANS namespace creation options are not modeled");
        }
        let mut data = [0; IDENTIFY_BYTES];
        cmd.prps(port, data.len(), NVMMU_PAGE_BYTES)?
            .read(port, &mut data)?;
        let count = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize;
        if count != self.medium.namespaces.len() {
            return Err("ANS namespace repartitioning is not modeled");
        }
        for (record, ns) in data[4..4 + count * 12]
            .as_chunks::<12>()
            .0
            .iter()
            .zip(&self.medium.namespaces)
        {
            let expected = ns.description;
            let word = |at| u32::from_le_bytes(record[at..at + 4].try_into().unwrap());
            if word(0) != expected.id
                || word(4) != expected.kind
                || (word(8) != 0 && u64::from(word(8)) != ns.blocks)
            {
                return Err("ANS namespace repartitioning is not modeled");
            }
        }
        if data[4 + count * 12..].iter().any(|&byte| byte != 0) {
            return Err("ANS namespace request extension fields are not modeled");
        }
        // Same-layout formatting drops the growable data extent's mappings.
        // Fixed auxiliary namespaces keep their contents: their services
        // stay attached across doFormatMedia, and eanFormat reuses a valid
        // header instead of formatting it again. Erasing that header here
        // leaves the service's cached formatted state pointing at zero data.
        // Explicit namespace deallocation still applies to every namespace.
        // Other layouts need a recovered ABI.
        // Only doFormatMedia's CDW10 of 0 (0x3dff8a0) gets here; the update
        // client's 1 (0x3dcac64, 0x3dc9cb0) refuses above.
        for id in 1..=count as u32 {
            if self.medium.namespaces[id as usize - 1].description.blocks == 0 {
                self.medium.erase(id).expect("IDs are consecutive from 1");
            }
        }
        Ok(Outcome::status(SUCCESS))
    }

    /// `BuildCommandTunnel` puts selector at CDW10, the request address at
    /// bytes 44..52, response address at 52..60 and response length at 60.
    /// `SendOSBuildStrToDevice` (0x3de51e8) builds request type 0x120 at +12,
    /// a 16-byte OS build at +24 and checks the status at +0x4c afterwards.
    /// The request, output and status buffers are tunnel buffers, reached
    /// through the SART's allow-list. Every request type a 26A434 driver
    /// builds is either served here or refused by name ([`unserved_tunnel`]).
    fn tunnel(
        &mut self,
        cmd: &Command,
        port: &mut Port<'_, '_>,
        sart: &mut Sart,
    ) -> Result<Outcome, &'static str> {
        if cmd.nsid() != 0 || cmd.word(40) != 1 {
            return Err("ANS tunnel selector/output contract is not modeled");
        }
        let port = &mut Port {
            iommu: sart,
            stream: 0,
            memory: &mut *port.memory,
            access: &mut *port.access,
        };
        let address = cmd.long(44);
        if address == 0 {
            return Err("ANS tunnel request address is null");
        }
        let mut request = [0; 80];
        port.read(address, &mut request).map_err(dma_error)?;
        if let Some(submission) = &mut self.last_submission {
            submission.tunnel = Some(request);
        }
        let kind = u32::from_le_bytes(request[12..16].try_into().unwrap());
        if kind == 0xba {
            if cmd.long(52) == 0
                || cmd.word(60) != tunnel_buffer(4096)
                || request[..12]
                    .iter()
                    .chain(&request[16..76])
                    .any(|&b| b != 0)
            {
                return Err("ANS NAND geometry tunnel fields are not modeled");
            }
            let output = cmd.long(52);
            let fields = die::geometry(&self.medium)?;
            // Validate every field address before any DMA effect.
            output
                .checked_add(0x70)
                .ok_or("ANS NAND geometry output wraps")?;
            for (offset, value) in fields {
                port.write(output + offset as u64, &value.to_le_bytes())
                    .map_err(dma_error)?;
            }
            // Emulated die: Stela's choice, consumed at 0x3dfb6a8 and
            // 0x3dfb6c8 as one die on bus zero, attached to MSP zero.
            port.write(output + 0x60, &[1]).map_err(dma_error)?;
            port.write(output + 0x70, &[0]).map_err(dma_error)?;
            port.write(
                address
                    .checked_add(0x4c)
                    .ok_or("ANS tunnel status address wraps")?,
                &0u32.to_le_bytes(),
            )
            .map_err(dma_error)?;
            return Ok(Outcome::status(SUCCESS));
        }
        if kind == 0x38 {
            // Emulated die: Stela's choice, consumed by SetNANDIDProperties
            // (0x3df69c4..0x3df6a20), CopyNANDIDData (0x3dc0088) as
            // eight opaque manufacturer-ID bytes. The chosen ID starts 9b
            // and agrees with the descriptor's YMTC personality. Only the
            // consumed eight bytes have a modeled meaning; no invented
            // geometry is placed in the rest of the 4 KiB output buffer.
            if cmd.long(52) == 0
                || cmd.word(60) != tunnel_buffer(4096)
                || request[..12]
                    .iter()
                    .chain(&request[16..76])
                    .any(|&b| b != 0)
            {
                return Err("ANS NAND-ID tunnel fields are not modeled");
            }
            port.write(cmd.long(52), &die::NAND_ID.to_le_bytes())
                .map_err(dma_error)?;
            port.write(
                address
                    .checked_add(0x4c)
                    .ok_or("ANS tunnel status address wraps")?,
                &0u32.to_le_bytes(),
            )
            .map_err(dma_error)?;
            return Ok(Outcome::status(SUCCESS));
        }
        if kind == 0x0d {
            let output = cmd.long(52);
            if output == 0
                || cmd.word(60) != die::SANITIZE_COUNTER_BYTES
                || request[..12]
                    .iter()
                    .chain(&request[16..76])
                    .any(|&b| b != 0)
            {
                return Err("ANS sanitize-counter tunnel fields are not modeled");
            }
            let bytes = u64::from(die::SANITIZE_COUNTER_BYTES);
            output
                .checked_add(bytes)
                .ok_or("ANS sanitize-counter output wraps")?;
            // The whole output is records, so write all of it: the
            // counters, then empty headers.
            let mut chunk = [0u8; 4096];
            for (i, (key, value)) in die::SANITIZE_COUNTERS.iter().enumerate() {
                let header = u64::from(*key) | 1 << 32;
                chunk[16 * i..16 * i + 8].copy_from_slice(&header.to_le_bytes());
                chunk[16 * i + 8..16 * i + 16].copy_from_slice(&value.to_le_bytes());
            }
            for offset in (0..bytes).step_by(chunk.len()) {
                port.write(output + offset, &chunk).map_err(dma_error)?;
                chunk.fill(0);
            }
            port.write(
                address
                    .checked_add(0x4c)
                    .ok_or("ANS tunnel status address wraps")?,
                &0u32.to_le_bytes(),
            )
            .map_err(dma_error)?;
            return Ok(Outcome::status(SUCCESS));
        }
        if let Some(table) = tunables::classify(kind) {
            table?;
            // `SendANS2Table` (0x3dfbefc): the type alone in a zeroed
            // request, and the table at the start of one zeroed tunnel
            // buffer. A table beyond one 16 KiB buffer is not modeled.
            let output = cmd.long(52);
            if output == 0
                || cmd.word(60) != tunnel_buffer(1)
                || request[..12]
                    .iter()
                    .chain(&request[16..76])
                    .any(|&b| b != 0)
            {
                return Err("ANS tunable-table tunnel fields are not modeled");
            }
            let mut data = vec![0; cmd.word(60) as usize];
            port.read(output, &mut data).map_err(dma_error)?;
            port.write(
                address
                    .checked_add(0x4c)
                    .ok_or("ANS tunnel status address wraps")?,
                &0u32.to_le_bytes(),
            )
            .map_err(dma_error)?;
            self.tunables.record(kind, &data);
            return Ok(Outcome::status(SUCCESS));
        }
        if kind == DEVICE_TIME {
            if cmd.long(52) != 0
                || cmd.word(60) != 0
                || request[..12]
                    .iter()
                    .chain(&request[16..0x1c])
                    .chain(&request[0x34..0x4c])
                    .any(|&b| b != 0)
            {
                return Err("ANS device-time tunnel fields are not modeled");
            }
            let word = |at: usize| u32::from_le_bytes(request[at..at + 4].try_into().unwrap());
            let long = |at: usize| u64::from_le_bytes(request[at..at + 8].try_into().unwrap());
            let time = DeviceTime {
                calendar_seconds: word(0x1c),
                prtc_seconds: word(0x20),
                absolute: long(0x24),
                continuous: long(0x2c),
            };
            port.write(
                address
                    .checked_add(0x4c)
                    .ok_or("ANS tunnel status address wraps")?,
                &0u32.to_le_bytes(),
            )
            .map_err(dma_error)?;
            self.device_time = Some(time);
            return Ok(Outcome::status(SUCCESS));
        }
        if kind != 0x120 {
            return Err(unserved_tunnel(kind));
        }
        if cmd.long(52) != 0 || cmd.word(60) != 0 {
            return Err("ANS tunnel request type or output is not modeled");
        }
        if request[..12]
            .iter()
            .chain(&request[16..24])
            .chain(&request[40..76])
            .any(|&byte| byte != 0)
        {
            return Err("ANS OS-build tunnel extension fields are not modeled");
        }
        let build: [u8; 16] = request[24..40].try_into().unwrap();
        let status = address
            .checked_add(0x4c)
            .ok_or("ANS tunnel status address wraps")?;
        port.write(status, &0u32.to_le_bytes()).map_err(dma_error)?;
        self.os_build = build;
        Ok(Outcome::status(SUCCESS))
    }
}

#[cfg(test)]
mod tests;
