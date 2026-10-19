//! NVMe command effects. Kernel evidence: `AppleNVMeRequest::BuildCommand*`
//! at 26A434 file 0x3deb4f8 (CQ), 0x3deb598 (SQ), 0x3deb56c/0x3deb62c
//! (delete CQ/SQ, CDW10 the queue ID), 0x3deb654 (Identify),
//! 0x3deb7ac..0x3deba30 (flush/read/write), 0x3debc88..0x3dec1dc
//! (logs/features), 0x3dec394 (Apple time), 0x3dec794 (namespace records),
//! and 0x3dec980 (tunnel). Unknown vendor effects stop before completion.
use super::{
    Ans, QUEUE_ENTRIES, Queue, die,
    namespace::BLOCK_BYTES,
    prp::{MAX_TRANSFER, Prps, dma_error},
};
use crate::platform::{apple::sart::Sart, dma::Port, pc::block::BlockError};
use alloc::vec;

const IDENTIFY_BYTES: usize = 4096;
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
const APPLE_TIME: u8 = 0xc0;
const APPLE_NAMESPACES: u8 = 0xc6;
const APPLE_TUNNEL: u8 = 0xd8;
const FLUSH: u8 = 0;
const WRITE: u8 = 1;
const READ: u8 = 2;
const COMPARE: u8 = 5;

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
                CREATE_SQ | CREATE_CQ => Ok(2),
                DELETE_SQ | DELETE_CQ => Ok(0),
                APPLE_TIME => Ok(0),
                IDENTIFY => Ok(1),
                SET_FEATURES | GET_FEATURES if self.long(24) == 0 => Ok(0),
                APPLE_NAMESPACES => Ok(2),
                // Tunnel addresses are in CDW11-14, not the PRPs. It is
                // authorized by SART, with an NVMMU entry but no PRP DMA.
                APPLE_TUNNEL => Ok(0),
                _ => Err("ANS admin opcode or DMA contract is not modeled"),
            }
        } else {
            match self.opcode() {
                READ => Ok(1),
                WRITE | COMPARE => Ok(2),
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
            _ => Err("ANS admin command is not modeled"),
        }
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
                put16(&mut data, 520, 1); // ONCS: Compare; no deallocate/crypto.
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
            if flags != (1 << 16) | 1 {
                return Err("ANS SQ must be contiguous, round-robin and use CQ 1");
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
        // An idempotent request for the already provisioned layout has the
        // requested effect; destructive changes require a recovered ABI.
        Ok(Outcome::status(SUCCESS))
    }

    /// `BuildCommandTunnel` puts selector at CDW10, the request address at
    /// bytes 44..52, response address at 52..60 and response length at 60.
    /// `SendOSBuildStrToDevice` (0x3de51e8) builds request type 0x120 at +12,
    /// a 16-byte OS build at +24 and checks the status at +0x4c afterwards.
    /// The request, output and status buffers are tunnel buffers, reached
    /// through the SART's allow-list.
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
        let kind = u32::from_le_bytes(request[12..16].try_into().unwrap());
        if kind == 0xba {
            if cmd.long(52) == 0
                || cmd.word(60) != 4096
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
                || cmd.word(60) != 4096
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
        if kind != 0x120 || cmd.long(52) != 0 || cmd.word(60) != 0 {
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
        pc::block::tests::RamDisk,
    };
    use alloc::boxed::Box;

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
        command.0[60..64].copy_from_slice(&4096u32.to_le_bytes());
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
