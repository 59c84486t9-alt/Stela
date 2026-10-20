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
    Ans, MODE_RESTORE, QUEUE_ENTRIES, Queue, bfh, die,
    namespace::BLOCK_BYTES,
    prp::{MAX_TRANSFER, Prps, dma_error},
    tunables,
};
use crate::platform::{apple::sart::Sart, dma::Port};
use alloc::vec;
use stela_drivers::block::BlockError;

const IDENTIFY_BYTES: usize = 4096;
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
const INVALID_NAMESPACE: u16 = 0xb;
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
/// zeros, which is what [`super::namespace::Medium::deallocate`] provides.
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
    ) -> Result<Outcome, &'static str> {
        if queue != 0 {
            return self.io(cmd, port);
        }
        match cmd.opcode() {
            IDENTIFY => self.identify(cmd, port),
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
            cmd.prps(port, data.len(), self.page())?
                .read(port, &mut data)?;
            self.download.params(&data)?;
            return Ok(Outcome::status(SUCCESS));
        }
        if cmd.word(48) != 0 || cmd.word(52) != 0 {
            return Err("ANS BFH download CDW12/CDW13 are not modeled");
        }
        cmd.prps(port, data.len(), self.page())?
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
                data[260] = READ_ONLY_FIRMWARE_SLOT;
                data[77] = 8; // MDTS: 2^8 * 4 KiB = 1 MiB.
                put16(&mut data, 78, 1); // Controller ID, Stela choice.
                put32(&mut data, 80, super::VERSION as u32);
                data[512] = 0x66;
                data[513] = 0x44; // SQES/CQES max and min.
                put32(&mut data, 516, self.medium.namespaces.len() as u32);
                put16(&mut data, 520, ONCS); // No write zeroes or crypto.
                // VWC/OACS are zero: no downloadable firmware/cache.
            }
            0 if cmd.nsid() == 0 => {
                self.controller_identity(&mut data);
                die::identify(&self.medium, &mut data)?;
            }
            0 => {
                let Some(ns) = self.medium.namespace(cmd.nsid()) else {
                    return Ok(Outcome::status(INVALID_NAMESPACE));
                };
                for offset in [0, 8, 16] {
                    put64(&mut data, offset, ns.blocks);
                }
                data[33] = DLFEAT_READ_ZEROS;
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
        cmd.prps(port, data.len(), self.page())?
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
        if id != 1 || depth > u32::from(QUEUE_ENTRIES) {
            return Ok(Outcome::status(INVALID_FIELD));
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
            1 | 2 | 4 | 5 | 6 | 8 | 9 | 10 | 11 => {
                // Round-robin arbitration, power state 0, no volatile cache,
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

    fn io(&mut self, cmd: &Command, port: &mut Port<'_, '_>) -> Result<Outcome, &'static str> {
        if self.medium.namespace(cmd.nsid()).is_none() {
            return Ok(Outcome::status(INVALID_NAMESPACE));
        }
        if cmd.opcode() == FLUSH {
            if cmd.long(24) != 0 || cmd.long(32) != 0 || !cmd.zero_words(40) {
                return Err("ANS Flush fields are not modeled");
            }
            return Ok(block_result(self.medium.device.flush()));
        }
        if cmd.opcode() == DATASET_MANAGEMENT {
            return self.dataset_management(cmd, port);
        }
        let controls = cmd.word(48);
        if controls & !0x4000_ffff != 0 || !cmd.zero_words(52) {
            return Err("ANS protection, encryption, metadata or read/write hints are not modeled");
        }
        let blocks = u64::from((controls & 0xffff) + 1);
        let lba = cmd.long(40);
        if self.medium.address(cmd.nsid(), lba, blocks).is_none() {
            return Ok(Outcome::status(LBA_RANGE));
        }
        let bytes = blocks as usize * BLOCK_BYTES as usize;
        if bytes > MAX_TRANSFER {
            return Ok(Outcome::status(INVALID_FIELD));
        }
        let prps = cmd.prps(port, bytes, self.page())?;
        let mut data = vec![0; bytes];
        match cmd.opcode() {
            READ => {
                let result = self.medium.read(cmd.nsid(), lba, &mut data);
                if result.is_ok() {
                    prps.write(port, &data)?;
                }
                Ok(block_result(result))
            }
            WRITE => {
                prps.read(port, &mut data)?;
                let result = self.medium.write(cmd.nsid(), lba, &data);
                if result.is_err() {
                    return Ok(block_result(result));
                }
                // This model has no volatile write cache: every completed
                // write is durable, including writes with FUA clear.
                Ok(block_result(self.medium.device.flush()))
            }
            COMPARE => {
                prps.read(port, &mut data)?;
                let mut media = vec![0; bytes];
                let result = self.medium.read(cmd.nsid(), lba, &mut media);
                if result.is_err() {
                    return Ok(block_result(result));
                }
                Ok(Outcome::status(if data == media { SUCCESS } else { 0x285 }))
            }
            _ => Err("ANS I/O command is not modeled"),
        }
    }

    /// Deallocate every listed range. Ranges are all checked before any
    /// takes effect, so an out-of-range entry fails the whole command (LBA
    /// Out of Range) with nothing deallocated. Integral-dataset hints (IDR,
    /// IDW) and context attributes carry no modeled effect and refuse.
    fn dataset_management(
        &mut self,
        cmd: &Command,
        port: &mut Port<'_, '_>,
    ) -> Result<Outcome, &'static str> {
        let count = cmd.word(40);
        if count & !0xff != 0 || cmd.word(44) != DEALLOCATE || !cmd.zero_words(48) {
            return Err(
                "ANS Dataset Management is modeled only as Deallocate without hints or reserved fields",
            );
        }
        let ranges = count as usize + 1;
        let mut list = vec![0; ranges * RANGE_BYTES];
        cmd.prps(port, list.len(), self.page())?
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
                return Ok(Outcome::status(LBA_RANGE));
            }
            extents.push((lba, blocks));
        }
        for (lba, blocks) in extents {
            self.medium
                .deallocate(cmd.nsid(), lba, blocks)
                .expect("a checked range");
        }
        Ok(Outcome::status(SUCCESS))
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
        cmd.prps(port, data.len(), self.page())?
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
        // Re-creating the provisioned layout re-creates every namespace,
        // and a controller re-creating one drops its FTL mappings: each
        // reads erased until written. Other layouts need a recovered ABI.
        // Only doFormatMedia's CDW10 of 0 (0x3dff8a0) gets here; the update
        // client's 1 (0x3dcac64, 0x3dc9cb0) refuses above.
        for id in 1..=count as u32 {
            self.medium.erase(id).expect("IDs are consecutive from 1");
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
            // consumed eight bytes have a modeled meaning; no fabricated
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
mod tests {
    use super::super::Description;
    use super::*;
    use crate::platform::{
        apple::{
            bus::Access,
            interrupt::InterruptLatch,
            sart::{Bounds, Sart},
        },
        dma::{Physical, tests::Ram},
    };
    use alloc::boxed::Box;
    use stela_drivers::block::RamDisk;

    #[test]
    fn os_build_tunnel_stores_only_the_recovered_message_and_checks_extensions() {
        use crate::platform::apple::bus::{MmioDevice, Width};
        let mut ans = Ans::new(
            Box::new(RamDisk::new("", 4, 4096)),
            &[Description {
                id: 1,
                kind: 1,
                blocks: 0,
            }],
            None,
        )
        .unwrap();
        let mut memory = Ram::new(0x1000, 8192);
        let mut sart = Sart::new(Bounds::Exclusive);
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        for (offset, value) in [(0x40, 1), (0x80, 2), (0, 0xff)] {
            sart.write(offset, Width::Word, value, &mut access).unwrap();
        }
        let mut port = Port {
            iommu: &mut Physical,
            stream: 0,
            memory: &mut memory,
            access: &mut access,
        };
        let mut request = [0; 80];
        request[12..16].copy_from_slice(&0x120u32.to_le_bytes());
        request[24..30].copy_from_slice(b"26A434");
        request[76..80].fill(0xff);
        port.write(0x1000, &request).unwrap();
        let mut command = Command([0; 64]);
        command.0[0] = APPLE_TUNNEL;
        command.0[40] = 1;
        command.0[44..52].copy_from_slice(&0x1000u64.to_le_bytes());
        assert_eq!(
            ans.execute(0, &command, &mut port, &mut sart)
                .unwrap()
                .status,
            SUCCESS
        );
        assert_eq!(&ans.os_build[..6], b"26A434");
        let mut status = [1; 4];
        port.read(0x104c, &mut status).unwrap();
        assert_eq!(status, [0; 4]);
        request[16] = 1;
        request[24..30].fill(b'X');
        port.write(0x1000, &request).unwrap();
        assert!(ans.execute(0, &command, &mut port, &mut sart).is_err());
        assert_eq!(&ans.os_build[..6], b"26A434");
        port.read(0x104c, &mut status).unwrap();
        assert_eq!(status, [0xff; 4]);
        request.fill(0);
        request[12..16].copy_from_slice(&0x38u32.to_le_bytes());
        port.write(0x1000, &request).unwrap();
        port.write(0x2000, &[0xa5; 4096]).unwrap();
        command.0[52..60].copy_from_slice(&0x2000u64.to_le_bytes());
        // The driver's 4 KiB request travels as one 16 KiB tunnel buffer.
        assert_eq!(tunnel_buffer(4096), 0x4000);
        assert_eq!(tunnel_buffer(0x4001), 0x8000);
        command.0[60..64].copy_from_slice(&4096u32.to_le_bytes());
        assert!(ans.execute(0, &command, &mut port, &mut sart).is_err());
        command.0[60..64].copy_from_slice(&tunnel_buffer(4096).to_le_bytes());
        ans.execute(0, &command, &mut port, &mut sart).unwrap();
        let mut output = [0; 16];
        port.read(0x2000, &mut output).unwrap();
        assert_eq!(&output[..8], &die::NAND_ID.to_le_bytes());
        assert_eq!(
            &output[8..],
            &[0xa5; 8],
            "unconsumed fields have no invented content"
        );
        request[12..16].copy_from_slice(&0xbau32.to_le_bytes());
        port.write(0x1000, &request).unwrap();
        port.write(0x2000, &[0xa5; 4096]).unwrap();
        ans.execute(0, &command, &mut port, &mut sart).unwrap();
        let mut geometry = [0; 0x80];
        port.read(0x2000, &mut geometry).unwrap();
        let field = |offset| u32::from_le_bytes(geometry[offset..offset + 4].try_into().unwrap());
        assert_eq!(field(8), 1);
        assert_eq!(field(0x14) << 12, BLOCK_BYTES);
        assert!(u64::from(field(0x10)) * u64::from(field(0x28)) >= ans.medium.namespaces[0].blocks);
        assert_eq!(field(0x38), field(0x10));
        assert_eq!(field(0x18), field(0x24) * field(0x14));
        assert_eq!(field(0x1c), field(0x28) * field(0x14));
        assert_eq!(&geometry[..4], &[0xa5; 4]);
        assert_eq!(&geometry[0x44..0x60], &[0xa5; 28]);
        assert_eq!(&geometry[0x60..0x62], &[1, 0xa5]);
        assert_eq!(&geometry[0x70..0x72], &[0, 0xa5]);
        // Tunnel buffers outside the SART's allow-list refuse.
        sart.write(0, Width::Word, 0, port.access).unwrap();
        assert!(ans.execute(0, &command, &mut port, &mut sart).is_err());
        // An unknown request type refuses and leaves the request it read
        // in the submission record.
        sart.write(0, Width::Word, 0xff, port.access).unwrap();
        request[12..16].copy_from_slice(&0x77u32.to_le_bytes());
        port.write(0x1000, &request).unwrap();
        ans.last_submission = Some(super::super::Submission {
            queue: 0,
            tag: 0,
            command: command.0,
            tcb: [0; 128],
            tunnel: None,
        });
        assert!(ans.execute(0, &command, &mut port, &mut sart).is_err());
        assert_eq!(ans.last_submission.as_ref().unwrap().tunnel, Some(request));
    }

    #[test]
    fn device_time_tunnel_records_the_recovery_request_and_unserved_types_refuse_by_name() {
        use crate::platform::apple::bus::{MmioDevice, Width};
        let mut ans = Ans::new(
            Box::new(RamDisk::new("", 4, 4096)),
            &[Description {
                id: 1,
                kind: 1,
                blocks: 0,
            }],
            None,
        )
        .unwrap();
        // The recoveryOS boot's request buffer: one 16 KiB tunnel buffer.
        const REQUEST: u64 = 0x8_08f8_c000;
        let mut memory = Ram::new(REQUEST, 0x8000);
        let mut sart = Sart::new(Bounds::Exclusive);
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        for (offset, value) in [(0x40, REQUEST >> 12), (0x80, 4), (0, 0xff)] {
            sart.write(offset, Width::Word, value, &mut access).unwrap();
        }
        let mut port = Port {
            iommu: &mut Physical,
            stream: 0,
            memory: &mut memory,
            access: &mut access,
        };
        // Admin SQ tag 8 of the recoveryOS boot, after IONVMeFamily logged
        // the nvram sync system event.
        let mut request = [0u8; 80];
        request[12] = 6;
        request[0x1c..0x24].copy_from_slice(&[0xea, 0xb5, 0xd6, 0x6a, 0x7f, 0, 0, 0]);
        request[0x24..0x2c].copy_from_slice(&[0x71, 0xe0, 0xbc, 0x8f, 0, 0, 0, 0]);
        request[0x2c..0x34].copy_from_slice(&[0x71, 0xe0, 0xbc, 0x8f, 0, 0, 0, 0]);
        request[0x4c..].fill(0xff);
        port.write(REQUEST, &request).unwrap();
        let mut command = Command([0; 64]);
        command.0[..4].copy_from_slice(&[APPLE_TUNNEL, 0, 8, 0]);
        command.0[40] = 1;
        command.0[44..52].copy_from_slice(&REQUEST.to_le_bytes());
        let outcome = ans.execute(0, &command, &mut port, &mut sart).unwrap();
        assert_eq!(outcome.status, SUCCESS);
        let mut status = [1; 4];
        port.read(REQUEST + 0x4c, &mut status).unwrap();
        assert_eq!(status, [0; 4]);
        let recorded = DeviceTime {
            calendar_seconds: 0x6ad6_b5ea,
            prtc_seconds: 0x7f,
            absolute: 0x8fbc_e071,
            continuous: 0x8fbc_e071,
        };
        assert_eq!(ans.device_time, Some(recorded));
        // The request is only read.
        let mut after = [0u8; 0x4c];
        port.read(REQUEST, &mut after).unwrap();
        assert_eq!(after, request[..0x4c]);

        // An output buffer or a nonzero extension field refuses without a
        // status or a new record.
        let refused = |ans: &mut Ans,
                       port: &mut Port<'_, '_>,
                       sart: &mut Sart,
                       request: [u8; 80],
                       command: Command| {
            port.write(REQUEST, &request).unwrap();
            let error = ans.execute(0, &command, port, sart).err().unwrap();
            let mut status = [0; 4];
            port.read(REQUEST + 0x4c, &mut status).unwrap();
            assert_eq!(status, [0xff; 4]);
            assert_eq!(ans.device_time, Some(recorded));
            error
        };
        let mut changed = request;
        changed[0x1c] ^= 1;
        let mut output = Command(command.0);
        output.0[52..60].copy_from_slice(&(REQUEST + 0x4000).to_le_bytes());
        output.0[60..64].copy_from_slice(&tunnel_buffer(1).to_le_bytes());
        let error = refused(&mut ans, &mut port, &mut sart, changed, output);
        assert_eq!(error, "ANS device-time tunnel fields are not modeled");
        for extension in [0, 0x18, 0x34, 0x4b] {
            let mut extended = changed;
            extended[extension] = 1;
            let error = refused(&mut ans, &mut port, &mut sart, extended, Command(command.0));
            assert_eq!(error, "ANS device-time tunnel fields are not modeled");
        }

        // Every census type the die does not serve refuses by its own name
        // before any status write.
        for kind in [
            3u32, 7, 0x0a, 0x0b, 0x0c, 0x0e, 0x11, 0x16, 0x22, 0x37, 0x52, 0x91, 0x97, 0xb1, 0xdd,
            0x309, 0x30a, 0x311,
        ] {
            let mut other = [0u8; 80];
            other[12..16].copy_from_slice(&kind.to_le_bytes());
            other[0x4c..].fill(0xff);
            let error = refused(&mut ans, &mut port, &mut sart, other, Command(command.0));
            assert_eq!(error, unserved_tunnel(kind));
            assert_ne!(
                error,
                unserved_tunnel(0x77),
                "type {kind:#x} has a named refusal"
            );
        }
        assert_eq!(
            unserved_tunnel(0x77),
            "ANS tunnel request type or output is not modeled"
        );
    }

    #[test]
    fn sanitize_counter_tunnel_fills_its_whole_output_with_zero_counters() {
        use crate::platform::apple::bus::{MmioDevice, Width};
        let mut ans = Ans::new(
            Box::new(RamDisk::new("", 4, 4096)),
            &[Description {
                id: 1,
                kind: 1,
                blocks: 0,
            }],
            None,
        )
        .unwrap();
        let bytes = die::SANITIZE_COUNTER_BYTES as usize;
        let mut memory = Ram::new(0x1000, 0x1000 + bytes);
        let mut sart = Sart::new(Bounds::Exclusive);
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        for (offset, value) in [(0x40, 1), (0x80, 0x101), (0, 0xff)] {
            sart.write(offset, Width::Word, value, &mut access).unwrap();
        }
        let mut port = Port {
            iommu: &mut Physical,
            stream: 0,
            memory: &mut memory,
            access: &mut access,
        };
        let mut request = [0; 80];
        request[12] = 0x0d;
        request[0x4c..].fill(0xff);
        port.write(0x1000, &request).unwrap();
        port.write(0x2000, &alloc::vec![0xa5; bytes]).unwrap();
        let mut command = Command([0; 64]);
        command.0[0] = APPLE_TUNNEL;
        command.0[40] = 1;
        command.0[44..52].copy_from_slice(&0x1000u64.to_le_bytes());
        command.0[52..60].copy_from_slice(&0x2000u64.to_le_bytes());
        command.0[60..64].copy_from_slice(&die::SANITIZE_COUNTER_BYTES.to_le_bytes());
        let status = ans.execute(0, &command, &mut port, &mut sart).unwrap();
        assert_eq!(status.status, SUCCESS);
        let mut output = alloc::vec![0xffu8; bytes];
        port.read(0x2000, &mut output).unwrap();
        // Walk the records as ParseSanitizeCounters does.
        let word = |i: usize| u64::from_le_bytes(output[8 * i..8 * i + 8].try_into().unwrap());
        let (mut i, mut found) = (0, alloc::vec::Vec::new());
        while i < bytes / 8 {
            let (key, count) = (word(i) as u32, (word(i) >> 32) as usize);
            for value in 1..=count {
                found.push((key, word(i + value)));
            }
            i += 1 + count;
        }
        assert_eq!(i, bytes / 8);
        assert_eq!(found, die::SANITIZE_COUNTERS);
        let mut status = [1; 4];
        port.read(0x104c, &mut status).unwrap();
        assert_eq!(status, [0; 4]);
        // Another output size refuses.
        command.0[60..64].copy_from_slice(&4096u32.to_le_bytes());
        assert!(ans.execute(0, &command, &mut port, &mut sart).is_err());
    }

    #[test]
    fn tunable_table_tunnel_records_its_buffer_and_refuses_other_shapes() {
        use crate::platform::apple::bus::{MmioDevice, Width};
        let mut ans = Ans::new(
            Box::new(RamDisk::new("", 4, 4096)),
            &[Description {
                id: 1,
                kind: 1,
                blocks: 0,
            }],
            None,
        )
        .unwrap();
        let bytes = tunnel_buffer(1) as usize;
        let mut memory = Ram::new(0x1000, 0x1000 + bytes + 0x1000);
        let mut sart = Sart::new(Bounds::Exclusive);
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        for (offset, value) in [(0x40, 1), (0x80, 6), (0, 0xff)] {
            sart.write(offset, Width::Word, value, &mut access).unwrap();
        }
        let mut port = Port {
            iommu: &mut Physical,
            stream: 0,
            memory: &mut memory,
            access: &mut access,
        };
        // A synthetic 40-byte table at the start of a zeroed buffer, as
        // `SendANS2Table` places it; the type is TT's request type.
        let mut buffer = alloc::vec![0u8; bytes];
        for (i, byte) in buffer[..40].iter_mut().enumerate() {
            *byte = i as u8 ^ 0x5a;
        }
        port.write(0x2000, &buffer).unwrap();
        let mut request = [0; 80];
        request[12..16].copy_from_slice(&110u32.to_le_bytes());
        request[0x4c..].fill(0xff);
        port.write(0x1000, &request).unwrap();
        let mut command = Command([0; 64]);
        command.0[0] = APPLE_TUNNEL;
        command.0[40] = 1;
        command.0[44..52].copy_from_slice(&0x1000u64.to_le_bytes());
        command.0[52..60].copy_from_slice(&0x2000u64.to_le_bytes());
        command.0[60..64].copy_from_slice(&tunnel_buffer(1).to_le_bytes());
        let outcome = ans.execute(0, &command, &mut port, &mut sart).unwrap();
        assert_eq!(outcome.status, SUCCESS);
        let mut status = [1; 4];
        port.read(0x104c, &mut status).unwrap();
        assert_eq!(status, [0; 4]);
        assert_eq!(ans.tunable_tables(), &[(110, bfh::identity(&buffer))]);
        // The table is only read: the buffer is unchanged.
        let mut after = alloc::vec![0u8; bytes];
        port.read(0x2000, &mut after).unwrap();
        assert_eq!(after, buffer);
        // Another length, a request extension field, a V5 kind and a
        // buffer outside the allow-list each refuse without a record.
        let refused = |ans: &mut Ans, port: &mut Port<'_, '_>, sart: &mut Sart, command| {
            assert!(ans.execute(0, &command, port, sart).is_err());
            assert_eq!(ans.tunable_tables().len(), 1);
        };
        let mut other = Command(command.0);
        other.0[60..64].copy_from_slice(&4096u32.to_le_bytes());
        refused(&mut ans, &mut port, &mut sart, other);
        request[20] = 1;
        port.write(0x1000, &request).unwrap();
        refused(&mut ans, &mut port, &mut sart, Command(command.0));
        request[20] = 0;
        request[12..16].copy_from_slice(&332u32.to_le_bytes());
        port.write(0x1000, &request).unwrap();
        refused(&mut ans, &mut port, &mut sart, Command(command.0));
        request[12..16].copy_from_slice(&110u32.to_le_bytes());
        port.write(0x1000, &request).unwrap();
        let mut outside = Command(command.0);
        outside.0[52..60].copy_from_slice(&0x5000u64.to_le_bytes());
        refused(&mut ans, &mut port, &mut sart, outside);
    }

    #[test]
    fn recreating_the_provisioned_layout_erases_every_namespace() {
        let records =
            [(1, 1, 0), (2, 8, 3)].map(|(id, kind, blocks)| Description { id, kind, blocks });
        let mut ans = Ans::new(Box::new(RamDisk::new("", 10, 4096)), &records, None).unwrap();
        let mut memory = Ram::new(0x1000, 0x2000);
        let mut sart = Sart::new(Bounds::Exclusive);
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut port = Port {
            iommu: &mut Physical,
            stream: 0,
            memory: &mut memory,
            access: &mut access,
        };
        let io = |ans: &mut Ans, port: &mut Port<'_, '_>, opcode, nsid: u32, lba: u64| {
            let mut command = Command([0; 64]);
            command.0[0] = opcode;
            command.0[4..8].copy_from_slice(&nsid.to_le_bytes());
            command.0[24..32].copy_from_slice(&0x2000u64.to_le_bytes());
            command.0[40..48].copy_from_slice(&lba.to_le_bytes());
            let mut sart = Sart::new(Bounds::Exclusive);
            ans.execute(1, &command, port, &mut sart).unwrap().status
        };
        let mut block = [0; 4096];
        for (nsid, lba, fill) in [(1, 6, 0x11), (2, 0, 0x22), (2, 2, 0x33)] {
            port.write(0x2000, &[fill; 4096]).unwrap();
            assert_eq!(io(&mut ans, &mut port, WRITE, nsid, lba), SUCCESS);
        }
        let mut create = Command([0; 64]);
        create.0[0] = APPLE_NAMESPACES;
        create.0[24..32].copy_from_slice(&0x1000u64.to_le_bytes());
        // The provisioned layout, the growable namespace sized either as
        // zero (doFormatMedia without a burn-in count) or its extent.
        let request = |sizes: [u32; 2]| {
            let mut data = alloc::vec![0; 4096];
            data[..4].copy_from_slice(&2u32.to_le_bytes());
            for (i, (record, blocks)) in records.iter().zip(sizes).enumerate() {
                for (j, word) in [record.id, record.kind, blocks].into_iter().enumerate() {
                    let at = 4 + 12 * i + 4 * j;
                    data[at..at + 4].copy_from_slice(&word.to_le_bytes());
                }
            }
            data
        };
        // Another layout, or creation options, refuse without an erase.
        for (sizes, cdw10) in [([0, 4], 0), ([6, 4], 0), ([0, 3], 1)] {
            port.write(0x1000, &request(sizes)).unwrap();
            create.0[40] = cdw10;
            assert!(ans.execute(0, &create, &mut port, &mut sart).is_err());
            assert_eq!(ans.medium.erase_pending(), 0);
        }
        create.0[40] = 0;
        for sizes in [[0, 3], [7, 3]] {
            port.write(0x1000, &request(sizes)).unwrap();
            let outcome = ans.execute(0, &create, &mut port, &mut sart).unwrap();
            assert_eq!(outcome.status, SUCCESS);
            assert_eq!(ans.medium.erase_pending(), 10);
        }
        for (nsid, lba) in [(1, 6), (2, 0), (2, 2)] {
            port.write(0x2000, &[0xff; 4096]).unwrap();
            assert_eq!(io(&mut ans, &mut port, READ, nsid, lba), SUCCESS);
            port.read(0x2000, &mut block).unwrap();
            assert_eq!(block, [0; 4096], "namespace {nsid} block {lba}");
        }
        port.write(0x2000, &[0x44; 4096]).unwrap();
        assert_eq!(io(&mut ans, &mut port, WRITE, 2, 1), SUCCESS);
        port.write(0x2000, &[0; 4096]).unwrap();
        assert_eq!(io(&mut ans, &mut port, READ, 2, 1), SUCCESS);
        port.read(0x2000, &mut block).unwrap();
        assert_eq!(block, [0x44; 4096]);
        assert_eq!(ans.zero_erased(u64::MAX), Ok(0));
        for (nsid, lba, fill) in [(2, 0, 0), (2, 1, 0x44), (2, 2, 0)] {
            assert_eq!(io(&mut ans, &mut port, READ, nsid, lba), SUCCESS);
            port.read(0x2000, &mut block).unwrap();
            assert_eq!(block, [fill; 4096]);
        }
    }

    #[test]
    fn dataset_management_deallocates_checked_ranges_and_reads_zero() {
        let records =
            [(1, 1, 0), (2, 0xd, 8)].map(|(id, kind, blocks)| Description { id, kind, blocks });
        let mut ans = Ans::new(Box::new(RamDisk::new("", 16, 4096)), &records, None).unwrap();
        let mut memory = Ram::new(0x1000, 0x3000);
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut port = Port {
            iommu: &mut Physical,
            stream: 0,
            memory: &mut memory,
            access: &mut access,
        };
        let mut sart = Sart::new(Bounds::Exclusive);
        let rw = |ans: &mut Ans, port: &mut Port<'_, '_>, opcode, lba: u64| {
            let mut command = Command([0; 64]);
            command.0[0] = opcode;
            command.0[4..8].copy_from_slice(&2u32.to_le_bytes());
            command.0[24..32].copy_from_slice(&0x3000u64.to_le_bytes());
            command.0[40..48].copy_from_slice(&lba.to_le_bytes());
            let mut sart = Sart::new(Bounds::Exclusive);
            ans.execute(1, &command, port, &mut sart).unwrap().status
        };
        for lba in 0..8 {
            port.write(0x3000, &[0x5a; 4096]).unwrap();
            assert_eq!(rw(&mut ans, &mut port, WRITE, lba), SUCCESS);
        }
        // The range list as `unmapBlocks` and `doUnmapNVMe` fill it.
        let list = |ranges: &[(u32, u32, u64)]| {
            let mut data = alloc::vec![0; 4096];
            for (i, &(context, blocks, lba)) in ranges.iter().enumerate() {
                let at = i * RANGE_BYTES;
                data[at..at + 4].copy_from_slice(&context.to_le_bytes());
                data[at + 4..at + 8].copy_from_slice(&blocks.to_le_bytes());
                data[at + 8..at + 16].copy_from_slice(&lba.to_le_bytes());
            }
            data
        };
        let dsm = |count: u32, attributes: u32| {
            let mut command = Command([0; 64]);
            command.0[0] = DATASET_MANAGEMENT;
            command.0[4..8].copy_from_slice(&2u32.to_le_bytes());
            command.0[24..32].copy_from_slice(&0x2000u64.to_le_bytes());
            command.0[40..44].copy_from_slice(&count.to_le_bytes());
            command.0[44..48].copy_from_slice(&attributes.to_le_bytes());
            command
        };
        assert_eq!(dsm(0, DEALLOCATE).direction(1), Ok(2));
        // A range past the namespace fails the whole command unchanged.
        port.write(0x2000, &list(&[(0, 2, 0), (0, 2, 7)])).unwrap();
        let outcome = ans
            .execute(1, &dsm(1, DEALLOCATE), &mut port, &mut sart)
            .unwrap();
        assert_eq!(outcome.status, LBA_RANGE);
        assert_eq!(ans.erase_pending(), 0);
        // Hints, reserved fields and context attributes refuse.
        for (count, attributes) in [(0, 1 | DEALLOCATE), (0, 0), (0x100, DEALLOCATE)] {
            assert!(
                ans.execute(1, &dsm(count, attributes), &mut port, &mut sart)
                    .is_err()
            );
        }
        port.write(0x2000, &list(&[(1, 1, 0)])).unwrap();
        assert!(
            ans.execute(1, &dsm(0, DEALLOCATE), &mut port, &mut sart)
                .is_err()
        );
        assert_eq!(ans.erase_pending(), 0);
        // eanFormat's whole-namespace range, then two ranges of one command.
        port.write(0x2000, &list(&[(0, 8, 0)])).unwrap();
        let outcome = ans
            .execute(1, &dsm(0, DEALLOCATE), &mut port, &mut sart)
            .unwrap();
        assert_eq!(outcome.status, SUCCESS);
        assert_eq!(ans.erase_pending(), 8);
        let mut block = [0; 4096];
        for lba in [0, 7] {
            port.write(0x3000, &[0xff; 4096]).unwrap();
            assert_eq!(rw(&mut ans, &mut port, READ, lba), SUCCESS);
            port.read(0x3000, &mut block).unwrap();
            assert_eq!(block, [0; 4096]);
        }
        port.write(0x3000, &[0x77; 4096]).unwrap();
        assert_eq!(rw(&mut ans, &mut port, WRITE, 3), SUCCESS);
        assert_eq!(ans.erase_pending(), 7);
        port.write(0x2000, &list(&[(0, 1, 3), (0, 0, 5)])).unwrap();
        let outcome = ans
            .execute(1, &dsm(1, DEALLOCATE), &mut port, &mut sart)
            .unwrap();
        assert_eq!(outcome.status, SUCCESS);
        assert_eq!(ans.erase_pending(), 8);
        assert_eq!(rw(&mut ans, &mut port, READ, 3), SUCCESS);
        port.read(0x3000, &mut block).unwrap();
        assert_eq!(block, [0; 4096]);
        assert_eq!(ans.zero_erased(u64::MAX), Ok(0));
    }

    #[test]
    fn identify_reports_dataset_management_and_zero_reads() {
        let mut ans = Ans::new(
            Box::new(RamDisk::new("", 4, 4096)),
            &[Description {
                id: 1,
                kind: 1,
                blocks: 0,
            }],
            None,
        )
        .unwrap();
        let mut memory = Ram::new(0x1000, 4096);
        let mut sart = Sart::new(Bounds::Exclusive);
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut port = Port {
            iommu: &mut Physical,
            stream: 0,
            memory: &mut memory,
            access: &mut access,
        };
        let mut data = [0; 4096];
        for (cns, nsid) in [(1u8, 0u32), (0, 1)] {
            let mut command = Command([0; 64]);
            command.0[0] = IDENTIFY;
            command.0[4..8].copy_from_slice(&nsid.to_le_bytes());
            command.0[24..32].copy_from_slice(&0x1000u64.to_le_bytes());
            command.0[40] = cns;
            let outcome = ans.execute(0, &command, &mut port, &mut sart).unwrap();
            assert_eq!(outcome.status, SUCCESS);
            port.read(0x1000, &mut data).unwrap();
            if cns == 1 {
                assert_eq!(u16::from_le_bytes([data[520], data[521]]), ONCS);
            } else {
                assert_eq!(data[33], DLFEAT_READ_ZEROS);
            }
        }
    }

    #[test]
    fn firmware_uuid_identify_refuses_by_name() {
        let mut command = Command([0; 64]);
        command.0[0] = APPLE_IDENTIFY_STORAGE;
        let refusal = command.direction(0).unwrap_err();
        assert!(refusal.contains("Identify Storage Device (0xc8)"));
    }

    #[test]
    fn queue_commands_carry_no_nvmmu_dma_permission() {
        for opcode in [CREATE_SQ, CREATE_CQ, DELETE_SQ, DELETE_CQ] {
            let mut command = Command([0; 64]);
            command.0[0] = opcode;
            assert_eq!(command.direction(0), Ok(0));
        }
    }

    #[test]
    fn unknown_vendor_effects_refuse_without_dma() {
        let mut ans = Ans::new(
            Box::new(RamDisk::new("", 4, 4096)),
            &[Description {
                id: 1,
                kind: 1,
                blocks: 0,
            }],
            None,
        )
        .unwrap();
        let mut memory = Ram::new(0x1000, 4096);
        let mut sart = Sart::new(Bounds::Exclusive);
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut port = Port {
            iommu: &mut Physical,
            stream: 0,
            memory: &mut memory,
            access: &mut access,
        };
        let mut command = Command([0; 64]);
        command.0[0] = APPLE_TUNNEL;
        assert!(ans.execute(0, &command, &mut port, &mut sart).is_err());
        assert_eq!(ans.os_build, [0; 16]);
        command.0[0] = 0xc2;
        assert!(ans.execute(0, &command, &mut port, &mut sart).is_err());
    }

    #[test]
    fn queue_count_and_feature_refusals_do_not_fabricate_effects() {
        let mut ans = Ans::new(
            Box::new(RamDisk::new("", 4, 4096)),
            &[Description {
                id: 1,
                kind: 1,
                blocks: 0,
            }],
            None,
        )
        .unwrap();
        let mut command = Command([0; 64]);
        command.0[0] = SET_FEATURES;
        command.0[40] = 7;
        let outcome = ans.feature(&command).unwrap();
        assert_eq!(outcome.result, 0);
        assert_eq!(outcome.status, SUCCESS);
        command.0[40] = 6;
        command.0[44] = 1;
        assert!(ans.feature(&command).is_err());
        assert_eq!(ans.features[6], 0);
        command.0[44] = 0;
        command.0[43] = 0x80;
        assert!(ans.feature(&command).is_err());
        command.0[43] = 0;
        command.0[1] = 0x40;
        assert!(command.validate().is_err());
    }
}
