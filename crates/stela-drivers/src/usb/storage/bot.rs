//! Serialized SCSI-transparent Bulk-Only Transport for all LUNs of one interface.
// SPDX-License-Identifier: GPL-2.0-or-later
// Hardware protocol reference: Linux drivers/usb/storage/transport.c,
// Copyright 1999-2002 Matthew Dharm; 2000 David L. Brown, Jr.;
// 2000 Stephen J. Gowdy; 2002 Alan Stern; 1999 Michael Gee.
use super::super::xhci::{DEVICE_TO_HOST, RECIPIENT_INTERFACE, TYPE_CLASS};
use super::{Data, Endpoint, MAX_TD, Shared, scsi, setup};
use crate::{
    block::{BlockError, Sense},
    bus::dma::{DmaAllocator, DmaBuffer},
};
use alloc::vec::Vec;

const RESET: u8 = 0xff;
const GET_MAX_LUN: u8 = 0xfe;
const CBW_SIGNATURE: u32 = 0x4342_5355;
const CSW_SIGNATURE: u32 = 0x5342_5355;
/// bCSWStatus: Command Failed (BOT 5.2).
const CSW_FAILED: u8 = 1;
const COMMAND_US: u64 = 30_000_000;
const RESET_RECOVERY_US: u64 = 6_000_000;
const MAX_LUN: u8 = 15;
const PROTOCOL_ERROR: BlockError = BlockError::Protocol("malformed Bulk-Only wrapper or transfer");
const SHORT_WRITE: BlockError = BlockError::Protocol("short Bulk-Only write");

/// Private seam: every native transfer returns only after completion or actual
/// xHCI cancellation. An error may leave poison; ready must expose it before
/// the CPU touches either DMA buffer again. No hosted USB API is used.
pub(super) trait Io {
    fn ready(&mut self) -> Result<(), BlockError>;
    fn control(&mut self, request: [u8; 8]) -> Result<Vec<u8>, BlockError>;
    fn clear(&mut self, endpoint: Endpoint) -> Result<(), BlockError>;
    fn bulk(&mut self, endpoint: Endpoint, buffer: u64, length: usize)
    -> Result<usize, BlockError>;
    fn delay(&self, micros: u64);
}

pub(super) struct Native {
    pub controller: Shared,
    pub slot: u8,
    pub endpoints: [Endpoint; 2],
}
impl Io for Native {
    fn ready(&mut self) -> Result<(), BlockError> {
        let mut controller = self.controller.borrow_mut();
        for dci in [1, self.endpoints[0].dci(), self.endpoints[1].dci()] {
            controller.endpoint_ready(self.slot, dci)?;
        }
        Ok(())
    }
    fn control(&mut self, request: [u8; 8]) -> Result<Vec<u8>, BlockError> {
        self.controller
            .borrow_mut()
            .control(self.slot, request, &[])
    }
    fn clear(&mut self, endpoint: Endpoint) -> Result<(), BlockError> {
        self.controller.borrow_mut().clear(self.slot, &endpoint)
    }
    fn bulk(
        &mut self,
        endpoint: Endpoint,
        buffer: u64,
        length: usize,
    ) -> Result<usize, BlockError> {
        self.controller
            .borrow_mut()
            .transfer(self.slot, endpoint.dci(), buffer, length, COMMAND_US)
    }
    fn delay(&self, micros: u64) {
        let clock = self.controller.borrow().clock;
        clock.delay(micros);
    }
}

pub(super) struct Bot<I: Io> {
    pub io: I,
    interface: u8,
    endpoints: [Endpoint; 2],
    buffer: DmaBuffer,
    wrapper: DmaBuffer,
    tag: u32,
    max_lun: u8,
    poisoned: bool,
}
impl<I: Io> Bot<I> {
    pub fn new(
        mut io: I,
        interface: u8,
        endpoints: [Endpoint; 2],
        dma: &mut dyn DmaAllocator,
    ) -> Result<Self, BlockError> {
        io.ready()?;
        let request = setup(
            DEVICE_TO_HOST | TYPE_CLASS | RECIPIENT_INTERFACE,
            GET_MAX_LUN,
            0,
            u16::from(interface),
            1,
        );
        let max_lun = match io.control(request) {
            Ok(bytes) if bytes.len() == 1 && bytes[0] <= MAX_LUN => bytes[0],
            // Linux `usb_stor_Bulk_max_lun`: devices stall this request, send
            // nothing, time out or answer nonsense; all mean one LUN. EP0
            // must still be usable afterwards.
            _ => {
                io.ready()?;
                0
            }
        };
        Ok(Self {
            io,
            interface,
            endpoints,
            buffer: dma.allocate(MAX_TD, MAX_TD)?,
            wrapper: dma.allocate(64, 64)?,
            tag: 0,
            max_lun,
            poisoned: false,
        })
    }
    pub fn max_lun(&self) -> u8 {
        self.max_lun
    }
    pub fn poisoned(&self) -> bool {
        self.poisoned
    }
    pub fn delay(&self, micros: u64) {
        self.io.delay(micros);
    }

    fn ready(&mut self) -> Result<(), BlockError> {
        if self.poisoned {
            return Err(BlockError::Unsupported(
                "USB storage interface requires rebind",
            ));
        }
        if let Err(error) = self.io.ready() {
            self.poisoned = true;
            return Err(error);
        }
        Ok(())
    }
    /// Reset and halt clearing affect *every* LUN. All acknowledgements must
    /// succeed to reuse the shared transport. Unresolved DMA stays in permanent
    /// boot allocations, and the entire interface remains quarantined.
    fn recover(&mut self) {
        self.poisoned = true;
        let result = (|| {
            self.io.ready()?;
            self.io.control(setup(
                TYPE_CLASS | RECIPIENT_INTERFACE,
                RESET,
                0,
                u16::from(self.interface),
                0,
            ))?;
            // Acknowledged class reset is not device-side recovery completion.
            // Match usb_stor_reset_common's HZ*6 settling interval before either
            // CLEAR_FEATURE; controller readiness alone cannot replace it.
            self.io.delay(RESET_RECOVERY_US);
            self.io.ready()?;
            let input = self.io.clear(self.endpoints[0]);
            let output = self.io.clear(self.endpoints[1]);
            input?;
            output?;
            self.io.ready()
        })();
        if result.is_ok() {
            self.poisoned = false;
        }
    }
    fn failed<T>(&mut self, error: BlockError) -> Result<T, BlockError> {
        self.recover();
        Err(error)
    }

    pub fn command(&mut self, lun: u8, cdb: &[u8], data: Data<'_>) -> Result<Vec<u8>, BlockError> {
        let result = self.raw(lun, cdb, data);
        if result == Err(BlockError::CheckCondition) {
            // SCSI auto-sense must use the failing command's LUN, and cannot
            // race a different unit's command while the interface is borrowed.
            let sense = if cdb[0] == scsi::REQUEST_SENSE {
                None
            } else {
                self.raw(lun, &scsi::request_sense(), Data::In(scsi::SENSE_BYTES))
                    .ok()
                    .and_then(|bytes| Sense::parse(&bytes))
            };
            return Err(sense.map_or(BlockError::CheckCondition, BlockError::Sense));
        }
        result
    }

    fn raw(&mut self, lun: u8, cdb: &[u8], data: Data<'_>) -> Result<Vec<u8>, BlockError> {
        if lun > self.max_lun || cdb.is_empty() || cdb.len() > 16 {
            return Err(BlockError::Unsupported(
                "invalid USB storage LUN or command",
            ));
        }
        let (length, is_in) = match &data {
            Data::None => (0, false),
            Data::In(n) => (*n, true),
            Data::Out(b) => (b.len(), false),
        };
        if length > MAX_TD {
            return Err(BlockError::Unsupported("USB storage transfer above 64 KiB"));
        }
        self.ready()?;
        self.tag = self.tag.wrapping_add(1);
        let wrapper = cbw(self.tag, lun, cdb, length, is_in);
        self.wrapper.bytes_mut()[..31].copy_from_slice(&wrapper);
        match self.io.bulk(self.endpoints[1], self.wrapper.physical(), 31) {
            Ok(31) => {}
            Ok(_) => {
                return self.failed(PROTOCOL_ERROR);
            }
            Err(error) => return self.failed(error),
        }
        // No uncertain CBW transfer can be followed by a CPU data write.
        if let Data::Out(bytes) = data {
            self.buffer.bytes_mut()[..length].copy_from_slice(bytes);
        }
        let mut moved = 0;
        if length != 0 {
            let endpoint = self.endpoints[usize::from(!is_in)];
            match self.io.bulk(endpoint, self.buffer.physical(), length) {
                Ok(n) if n <= length => moved = n,
                Ok(_) => {
                    return self.failed(PROTOCOL_ERROR);
                }
                Err(BlockError::Device {
                    status: super::STALL,
                }) => {
                    if let Err(error) = self.io.clear(endpoint) {
                        return self.failed(error);
                    }
                }
                Err(error) => return self.failed(error),
            }
        }
        let input = self.endpoints[0];
        let address = self.wrapper.physical();
        let first = self.io.bulk(input, address, 13);
        let csw = match first {
            Err(BlockError::Device {
                status: super::STALL,
            }) => {
                if let Err(error) = self.io.clear(input) {
                    return self.failed(error);
                }
                self.io.bulk(input, address, 13)
            }
            Ok(0) => self.io.bulk(input, address, 13),
            other => other,
        };
        match csw {
            Ok(13) => {}
            Ok(_) => {
                return self.failed(PROTOCOL_ERROR);
            }
            Err(error) => return self.failed(error),
        }
        let bytes = &self.wrapper.bytes()[..13];
        let residue = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
        let status = bytes[12];
        if u32::from_le_bytes(bytes[..4].try_into().unwrap()) != CSW_SIGNATURE
            || u32::from_le_bytes(bytes[4..8].try_into().unwrap()) != self.tag
            || residue > length
            || status > 1
        {
            return self.failed(PROTOCOL_ERROR);
        }
        if status == CSW_FAILED {
            return Err(BlockError::CheckCondition);
        }
        // A successful CSW does not turn a partial block write into success.
        if !is_in && (moved != length || residue != 0) {
            return Err(SHORT_WRITE);
        }
        Ok(if is_in {
            self.buffer.bytes()[..moved.min(length - residue)].to_vec()
        } else {
            Vec::new()
        })
    }
}

fn cbw(tag: u32, lun: u8, cdb: &[u8], length: usize, is_in: bool) -> [u8; 31] {
    let mut bytes = [0; 31];
    bytes[..4].copy_from_slice(&CBW_SIGNATURE.to_le_bytes());
    bytes[4..8].copy_from_slice(&tag.to_le_bytes());
    bytes[8..12].copy_from_slice(&(length as u32).to_le_bytes());
    bytes[12] = if is_in { 0x80 } else { 0 };
    bytes[13] = lun;
    bytes[14] = cdb.len() as u8;
    bytes[15..15 + cdb.len()].copy_from_slice(cdb);
    bytes
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::dma::RegionAllocator;
    use alloc::{rc::Rc, vec};
    use core::cell::RefCell;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Fault {
        None,
        ShortCbw,
        ShortData,
        DataStall,
        CswStall,
        CswZero,
        WrongTag,
        BadSignature,
        BadResidue,
        Phase,
        Timeout,
        Reset,
        ClearInput,
        ClearOutput,
    }
    #[derive(Clone)]
    struct Unit {
        media: Vec<u8>,
        sense: u32,
        readonly: bool,
        attention: bool,
        huge: bool,
        descriptor_sense: bool,
        /// Spun down until START STOP UNIT starts it.
        stopped: bool,
    }
    struct Command {
        lun: u8,
        cdb: Vec<u8>,
        tag: u32,
        length: usize,
        input: bool,
        payload: Vec<u8>,
        status: u8,
        data_done: bool,
    }
    #[derive(Debug, PartialEq, Eq)]
    enum Order {
        Reset,
        Delay(u64),
        Clear(u8),
        Cbw(u8),
    }
    struct State {
        range: core::ops::Range<u64>,
        max: Result<Vec<u8>, BlockError>,
        units: Vec<Option<Unit>>,
        command: Option<Command>,
        history: Vec<(u8, u32, Vec<u8>)>,
        controls: Vec<[u8; 8]>,
        clears: Vec<u8>,
        fault: Fault,
        override_payload: Vec<(u8, Vec<u8>)>,
        poisoned: bool,
        transfers: usize,
        delays: usize,
        now: u64,
        reset_ready: Option<u64>,
        order: Vec<Order>,
    }
    #[derive(Clone)]
    struct Model(Rc<RefCell<State>>);
    impl Io for Model {
        fn ready(&mut self) -> Result<(), BlockError> {
            if self.0.borrow().poisoned {
                Err(BlockError::Unsupported("model unacknowledged cancellation"))
            } else {
                Ok(())
            }
        }
        fn control(&mut self, request: [u8; 8]) -> Result<Vec<u8>, BlockError> {
            let mut s = self.0.borrow_mut();
            s.controls.push(request);
            match request[1] {
                GET_MAX_LUN => {
                    assert_eq!(request, setup(0xa1, GET_MAX_LUN, 0, 3, 1));
                    s.max.clone()
                }
                RESET => {
                    assert_eq!(request, setup(0x21, RESET, 0, 3, 0));
                    if s.fault == Fault::Reset {
                        Err(BlockError::Timeout)
                    } else {
                        s.command = None;
                        s.reset_ready = Some(s.now + RESET_RECOVERY_US);
                        s.order.push(Order::Reset);
                        Ok(Vec::new())
                    }
                }
                _ => panic!("unexpected control"),
            }
        }
        fn clear(&mut self, endpoint: Endpoint) -> Result<(), BlockError> {
            let mut s = self.0.borrow_mut();
            assert!(
                s.reset_ready.is_none_or(|at| s.now >= at),
                "halt clear before reset settled"
            );
            s.order.push(Order::Clear(endpoint.address));
            s.clears.push(endpoint.address);
            if (s.fault == Fault::ClearInput && endpoint.address == 0x82)
                || (s.fault == Fault::ClearOutput && endpoint.address == 0x02)
            {
                Err(BlockError::Timeout)
            } else {
                Ok(())
            }
        }
        fn delay(&self, micros: u64) {
            assert!(matches!(micros, 100_000 | RESET_RECOVERY_US));
            let mut s = self.0.borrow_mut();
            s.now += micros;
            s.order.push(Order::Delay(micros));
            if micros == 100_000 {
                s.delays += 1;
            }
        }
        fn bulk(
            &mut self,
            endpoint: Endpoint,
            address: u64,
            length: usize,
        ) -> Result<usize, BlockError> {
            let mut s = self.0.borrow_mut();
            s.transfers += 1;
            assert!(
                address >= s.range.start
                    && address.checked_add(length as u64).unwrap() <= s.range.end
            );
            // SAFETY: the test's private DMA allocation is live, within range,
            // and only this synchronous model accesses it during a transfer.
            let bytes = unsafe { core::slice::from_raw_parts_mut(address as *mut u8, length) };
            if s.command.is_none() {
                assert!(!endpoint.is_in());
                assert_eq!(length, 31);
                assert_eq!(
                    u32::from_le_bytes(bytes[..4].try_into().unwrap()),
                    CBW_SIGNATURE
                );
                assert_eq!(bytes[12] & 0x7f, 0);
                assert_eq!(bytes[13] & 0xf0, 0);
                assert!((1..=16).contains(&bytes[14]));
                let lun = bytes[13];
                assert!(
                    s.reset_ready.is_none_or(|at| s.now >= at),
                    "CBW before reset settled"
                );
                s.order.push(Order::Cbw(lun));
                let tag = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
                let cdb = bytes[15..15 + usize::from(bytes[14])].to_vec();
                let requested = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
                let input = bytes[12] & 0x80 != 0;
                s.history.push((lun, tag, cdb.clone()));
                let mut payload = Vec::new();
                let mut status = 0;
                let unit = s.units.get_mut(usize::from(lun)).and_then(Option::as_mut);
                if let Some(u) = unit {
                    match cdb[0] {
                        0x12 => {
                            payload = vec![0; 36];
                            payload[1] = 0x80;
                            payload[4] = 31;
                            payload[8..16].copy_from_slice(b"STELA   ");
                            payload[16..32].copy_from_slice(b"MULTI LUN MODEL ");
                        }
                        op if u.attention && !matches!(op, 0x12 | 0x03) => {
                            u.attention = false;
                            u.sense = 0x062900;
                            status = 1;
                        }
                        0x00 if u.stopped => {
                            // NOT READY: initializing command required.
                            u.sense = 0x020402;
                            status = 1;
                        }
                        0x00 => {}
                        0x1b => u.stopped = cdb[4] & 1 == 0,
                        0x03 => {
                            payload = vec![0; 18];
                            if u.descriptor_sense {
                                payload[0] = 0x72;
                                payload[1] = (u.sense >> 16) as u8;
                                payload[2] = (u.sense >> 8) as u8;
                                payload[3] = u.sense as u8;
                            } else {
                                payload[0] = 0x70;
                                payload[2] = (u.sense >> 16) as u8;
                                payload[7] = 10;
                                payload[12] = (u.sense >> 8) as u8;
                                payload[13] = u.sense as u8;
                            }
                        }
                        0x25 => {
                            payload = vec![0; 8];
                            let last = if u.huge {
                                u32::MAX
                            } else {
                                (u.media.len() / 512 - 1) as u32
                            };
                            payload[..4].copy_from_slice(&last.to_be_bytes());
                            payload[4..8].copy_from_slice(&512u32.to_be_bytes());
                        }
                        0x9e => {
                            payload = vec![0; 32];
                            payload[..8].copy_from_slice(&((1u64 << 32) + 7).to_be_bytes());
                            payload[8..12].copy_from_slice(&4096u32.to_be_bytes());
                        }
                        0x1a => {
                            payload = vec![3, 0, if u.readonly { 0x80 } else { 0 }, 0];
                        }
                        0x28 | 0x88 => {
                            let lba = if cdb[0] == 0x28 {
                                u64::from(u32::from_be_bytes(cdb[2..6].try_into().unwrap()))
                            } else {
                                u64::from_be_bytes(cdb[2..10].try_into().unwrap())
                            };
                            let at = lba as usize * 512;
                            payload = u.media[at..at + requested].to_vec();
                        }
                        0x2a | 0x8a | 0x35 => {}
                        _ => {
                            u.sense = 0x052000;
                            status = 1;
                        }
                    }
                } else {
                    status = 1;
                    if cdb[0] == 0x12 {
                        // Empty reader slots identify normally, but TUR fails.
                        payload = vec![0; 36];
                        payload[1] = 0x80;
                        payload[4] = 31;
                        status = 0;
                    } else if cdb[0] == 3 {
                        payload = vec![0; 18];
                        payload[0] = 0x70;
                        payload[2] = 2;
                        payload[7] = 10;
                        payload[12] = 0x3a;
                        status = 0;
                    }
                }
                if let Some((_, bytes)) = s.override_payload.iter().find(|(op, _)| *op == cdb[0]) {
                    payload = bytes.clone();
                }
                s.command = Some(Command {
                    lun,
                    cdb,
                    tag,
                    length: requested,
                    input,
                    payload,
                    status,
                    data_done: requested == 0,
                });
                if s.fault == Fault::ShortCbw {
                    return Ok(30);
                }
                return Ok(31);
            }
            if s.fault == Fault::Timeout {
                s.poisoned = true;
                return Err(BlockError::Timeout);
            }
            let mut command = s.command.take().unwrap();
            if !command.data_done {
                assert_eq!(command.input, endpoint.is_in());
                assert_eq!(length, command.length);
                command.data_done = true;
                if s.fault == Fault::DataStall {
                    s.command = Some(command);
                    return Err(BlockError::Device {
                        status: super::super::STALL,
                    });
                }
                let count = if s.fault == Fault::ShortData {
                    length - 1
                } else if command.input {
                    length.min(command.payload.len())
                } else {
                    length
                };
                if command.input {
                    bytes[..count].copy_from_slice(&command.payload[..count]);
                } else if command.status == 0 && matches!(command.cdb[0], 0x2a | 0x8a) {
                    let at = if command.cdb[0] == 0x2a {
                        u32::from_be_bytes(command.cdb[2..6].try_into().unwrap()) as usize * 512
                    } else {
                        u64::from_be_bytes(command.cdb[2..10].try_into().unwrap()) as usize * 512
                    };
                    s.units[usize::from(command.lun)].as_mut().unwrap().media[at..at + count]
                        .copy_from_slice(&bytes[..count]);
                }
                s.command = Some(command);
                return Ok(count);
            }
            assert!(endpoint.is_in());
            assert_eq!(length, 13);
            if matches!(s.fault, Fault::CswStall | Fault::CswZero) {
                let fault = s.fault;
                s.fault = Fault::None;
                s.command = Some(command);
                return if fault == Fault::CswZero {
                    Ok(0)
                } else {
                    Err(BlockError::Device {
                        status: super::super::STALL,
                    })
                };
            }
            bytes.fill(0);
            bytes[..4].copy_from_slice(
                &if s.fault == Fault::BadSignature {
                    0
                } else {
                    CSW_SIGNATURE
                }
                .to_le_bytes(),
            );
            bytes[4..8].copy_from_slice(
                &(command.tag + u32::from(s.fault == Fault::WrongTag)).to_le_bytes(),
            );
            bytes[8..12].copy_from_slice(
                &if s.fault == Fault::BadResidue {
                    command.length as u32 + 1
                } else {
                    0
                }
                .to_le_bytes(),
            );
            bytes[12] = if s.fault == Fault::Phase
                || matches!(
                    s.fault,
                    Fault::Reset | Fault::ClearInput | Fault::ClearOutput
                ) {
                2
            } else {
                command.status
            };
            Ok(13)
        }
    }
    fn endpoints() -> [Endpoint; 2] {
        [0x82, 0x02].map(|address| Endpoint {
            address,
            attributes: 2,
            max_packet: 64,
            interval: 0,
            companion: None,
        })
    }
    fn unit(byte: u8) -> Option<Unit> {
        Some(Unit {
            media: vec![byte; 8192],
            sense: 0,
            readonly: false,
            attention: false,
            huge: false,
            descriptor_sense: false,
            stopped: false,
        })
    }
    fn model(start: u64, end: u64, units: Vec<Option<Unit>>) -> Model {
        Model(Rc::new(RefCell::new(State {
            range: start..end,
            max: Ok(vec![(units.len() - 1) as u8]),
            units,
            command: None,
            history: Vec::new(),
            controls: Vec::new(),
            clears: Vec::new(),
            fault: Fault::None,
            override_payload: Vec::new(),
            poisoned: false,
            transfers: 0,
            delays: 0,
            now: 0,
            reset_ready: None,
            order: Vec::new(),
        })))
    }
    fn dma(backing: &mut [u64]) -> RegionAllocator {
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: each caller keeps the exclusive backing alive until all Bot
        // owners and the synchronous private model are dropped.
        unsafe { RegionAllocator::new(start..start + core::mem::size_of_val(backing) as u64) }
    }
    #[test]
    fn all_sixteen_luns_have_independent_media_sense_and_shared_tags() {
        let mut memory = vec![0u64; 32 * 1024];
        let mut dma = dma(&mut memory);
        let start = memory.as_mut_ptr() as u64;
        let io = model(
            start,
            start + memory.len() as u64 * 8,
            (0..16).map(unit).collect(),
        );
        let state = io.0.clone();
        let mut bot = Bot::new(io, 3, endpoints(), &mut dma).unwrap();
        for lun in 0..=bot.max_lun() {
            let identity = super::super::probe(&mut bot, lun, "slot", "serial").unwrap();
            assert_eq!(identity.blocks, 16);
            assert_eq!(
                identity.serial,
                if lun == 0 {
                    "serial".into()
                } else {
                    alloc::format!("serial:lun{lun}")
                }
            );
            let read = bot
                .command(lun, &[0x28, 0, 0, 0, 0, 0, 0, 0, 1, 0], Data::In(512))
                .unwrap();
            assert_eq!(read, vec![lun; 512]);
            let bytes = vec![lun.wrapping_add(40); 512];
            bot.command(lun, &[0x2a, 0, 0, 0, 0, 1, 0, 0, 1, 0], Data::Out(&bytes))
                .unwrap();
            assert_eq!(
                &state.borrow().units[usize::from(lun)]
                    .as_ref()
                    .unwrap()
                    .media[512..1024],
                &bytes
            );
            bot.command(lun, &[0x35, 0, 0, 0, 0, 0, 0, 0, 0, 0], Data::None)
                .unwrap();
        }
        let state = state.borrow();
        assert!(state.history.windows(2).all(|w| w[1].1 == w[0].1 + 1));
        assert_eq!(state.history.len(), 112);
    }
    #[test]
    fn empty_slot_does_not_hide_later_ready_media_and_auto_sense_keeps_lun() {
        let mut memory = vec![0u64; 32 * 1024];
        let start = memory.as_mut_ptr() as u64;
        let mut dma = dma(&mut memory);
        let io = model(
            start,
            start + memory.len() as u64 * 8,
            vec![None, unit(1), None, unit(3)],
        );
        let state = io.0.clone();
        let mut bot = Bot::new(io, 3, endpoints(), &mut dma).unwrap();
        for lun in 0..4 {
            let result = super::super::probe(&mut bot, lun, "slot", "serial");
            assert_eq!(result.is_ok(), lun == 1 || lun == 3);
            assert!(!bot.poisoned());
        }
        let state = state.borrow();
        for w in state.history.windows(2) {
            if w[1].2[0] == 3 {
                assert_eq!(w[0].0, w[1].0);
            }
        }
    }
    #[test]
    fn attention_descriptor_sense_capacity16_and_write_protection_are_real() {
        for descriptor in [false, true] {
            let mut memory = vec![0u64; 32 * 1024];
            let start = memory.as_mut_ptr() as u64;
            let mut dma = dma(&mut memory);
            let mut u = unit(7).unwrap();
            u.attention = true;
            u.descriptor_sense = descriptor;
            u.huge = true;
            u.readonly = true;
            let io = model(start, start + memory.len() as u64 * 8, vec![Some(u)]);
            let state = io.0.clone();
            let mut bot = Bot::new(io, 3, endpoints(), &mut dma).unwrap();
            let identity = super::super::probe(&mut bot, 0, "slot", "serial").unwrap();
            assert_eq!(identity.blocks, (1 << 32) + 8);
            assert_eq!(identity.block_size, 4096);
            assert!(identity.read_only);
            assert_eq!(state.borrow().delays, 1);
        }
    }
    #[test]
    fn a_stopped_unit_is_started_once_and_then_identified() {
        let mut memory = vec![0u64; 32 * 1024];
        let start = memory.as_mut_ptr() as u64;
        let mut dma = dma(&mut memory);
        let mut stopped = unit(0x11).unwrap();
        stopped.stopped = true;
        let io = model(start, start + memory.len() as u64 * 8, vec![Some(stopped)]);
        let state = io.0.clone();
        let mut bot = Bot::new(io, 3, endpoints(), &mut dma).unwrap();
        super::super::probe(&mut bot, 0, "slot", "serial").unwrap();
        assert!(!state.borrow().units[0].as_ref().unwrap().stopped);
    }

    #[test]
    fn get_max_lun_takes_one_bounded_byte_and_otherwise_one_unit() {
        for (response, max_lun) in [
            (Ok(vec![0]), 0),
            (Ok(vec![15]), 15),
            (Ok(vec![]), 0),
            (Ok(vec![16]), 0),
            (Ok(vec![0, 1]), 0),
            (
                Err(BlockError::Device {
                    status: super::super::STALL,
                }),
                0,
            ),
            (Err(BlockError::Timeout), 0),
        ] {
            let mut memory = vec![0u64; 32 * 1024];
            let start = memory.as_mut_ptr() as u64;
            let mut dma = dma(&mut memory);
            let io = model(start, start + memory.len() as u64 * 8, vec![unit(0)]);
            io.0.borrow_mut().max = response;
            assert_eq!(
                Bot::new(io, 3, endpoints(), &mut dma).unwrap().max_lun(),
                max_lun
            );
        }
    }
    #[test]
    fn short_cbw_phase_csw_and_residue_errors_require_interface_reset() {
        for fault in [
            Fault::ShortCbw,
            Fault::WrongTag,
            Fault::BadSignature,
            Fault::BadResidue,
            Fault::Phase,
        ] {
            let mut memory = vec![0u64; 32 * 1024];
            let start = memory.as_mut_ptr() as u64;
            let mut dma = dma(&mut memory);
            let io = model(start, start + memory.len() as u64 * 8, vec![unit(0)]);
            let state = io.0.clone();
            let mut bot = Bot::new(io, 3, endpoints(), &mut dma).unwrap();
            state.borrow_mut().fault = fault;
            assert!(bot.command(0, &[0; 6], Data::None).is_err());
            let state = state.borrow();
            assert_eq!(state.controls.last().unwrap()[1], RESET);
            assert_eq!(state.clears, vec![0x82, 0x02]);
            assert!(!bot.poisoned());
        }
    }
    #[test]
    fn data_stall_reads_csw_and_csw_stall_or_zero_gets_one_retry() {
        for fault in [Fault::DataStall, Fault::CswStall, Fault::CswZero] {
            let mut memory = vec![0u64; 32 * 1024];
            let start = memory.as_mut_ptr() as u64;
            let mut dma = dma(&mut memory);
            let io = model(start, start + memory.len() as u64 * 8, vec![unit(0)]);
            let state = io.0.clone();
            let mut bot = Bot::new(io, 3, endpoints(), &mut dma).unwrap();
            state.borrow_mut().fault = fault;
            let result = bot
                .command(0, &[0x12, 0, 0, 0, 36, 0], Data::In(36))
                .unwrap();
            assert_eq!(result.len(), if fault == Fault::DataStall { 0 } else { 36 });
            assert!(!bot.poisoned());
        }
    }
    #[test]
    fn short_out_cannot_be_reported_as_successful_write() {
        let mut memory = vec![0u64; 32 * 1024];
        let start = memory.as_mut_ptr() as u64;
        let mut dma = dma(&mut memory);
        let io = model(start, start + memory.len() as u64 * 8, vec![unit(0)]);
        let state = io.0.clone();
        let mut bot = Bot::new(io, 3, endpoints(), &mut dma).unwrap();
        state.borrow_mut().fault = Fault::ShortData;
        assert_eq!(
            bot.command(
                0,
                &[0x2a, 0, 0, 0, 0, 0, 0, 0, 1, 0],
                Data::Out(&vec![2; 512])
            ),
            Err(SHORT_WRITE)
        );
    }
    #[test]
    fn failed_reset_clear_or_cancellation_quarantines_every_lun_without_dma_rewrite() {
        for fault in [
            Fault::Reset,
            Fault::ClearInput,
            Fault::ClearOutput,
            Fault::Timeout,
        ] {
            let mut memory = vec![0u64; 32 * 1024];
            let start = memory.as_mut_ptr() as u64;
            let mut dma = dma(&mut memory);
            let io = model(
                start,
                start + memory.len() as u64 * 8,
                vec![unit(0), unit(1)],
            );
            let state = io.0.clone();
            let mut bot = Bot::new(io, 3, endpoints(), &mut dma).unwrap();
            state.borrow_mut().fault = fault;
            assert!(
                bot.command(0, &[0x12, 0, 0, 0, 36, 0], Data::In(36))
                    .is_err()
            );
            assert!(bot.poisoned());
            let wrapper = bot.wrapper.bytes().to_vec();
            let buffer = bot.buffer.bytes().to_vec();
            let transfers = state.borrow().transfers;
            assert!(
                bot.command(
                    1,
                    &[0x2a, 0, 0, 0, 0, 0, 0, 0, 1, 0],
                    Data::Out(&vec![0xa5; 512])
                )
                .is_err()
            );
            assert_eq!(state.borrow().transfers, transfers);
            assert_eq!(bot.wrapper.bytes(), wrapper);
            assert_eq!(bot.buffer.bytes(), buffer);
        }
    }
    #[test]
    fn invalid_lun_cdb_and_lengths_are_rejected_without_touching_dma() {
        let mut memory = vec![0u64; 32 * 1024];
        let start = memory.as_mut_ptr() as u64;
        let mut dma = dma(&mut memory);
        let io = model(start, start + memory.len() as u64 * 8, vec![unit(0)]);
        let state = io.0.clone();
        let mut bot = Bot::new(io, 3, endpoints(), &mut dma).unwrap();
        for (lun, cdb, length) in [
            (1, vec![0; 6], 0),
            (0, vec![], 0),
            (0, vec![0; 17], 0),
            (0, vec![0; 6], MAX_TD + 1),
        ] {
            assert!(bot.command(lun, &cdb, Data::In(length)).is_err());
        }
        assert_eq!(state.borrow().transfers, 0);
        assert_eq!(bot.tag, 0);
    }
    #[test]
    fn native_poison_preflight_preserves_all_buffers() {
        for (dci, halted) in [1, 4, 5]
            .into_iter()
            .flat_map(|dci| [false, true].map(move |halted| (dci, halted)))
        {
            let mut memory = vec![0u64; 64 * 1024];
            let mut dma = dma(&mut memory);
            let mut wrapper = dma.allocate(64, 64).unwrap();
            wrapper.bytes_mut().fill(0xa5);
            let mut buffer = dma.allocate(512, 512).unwrap();
            buffer.bytes_mut().fill(0x5a);
            let controller = super::super::super::xhci::model::controller_with_unresolved_td(
                &mut dma,
                wrapper.physical(),
                wrapper.len(),
                dci,
                halted,
            );
            let mut bot = Bot {
                io: Native {
                    controller,
                    slot: 1,
                    endpoints: endpoints(),
                },
                interface: 3,
                endpoints: endpoints(),
                buffer,
                wrapper,
                tag: 7,
                max_lun: 1,
                poisoned: false,
            };
            assert!(
                bot.command(1, &[0x2a, 0, 0, 0, 0, 0, 0, 0, 1, 0], Data::Out(&[1, 2, 3]))
                    .is_err()
            );
            assert_eq!(bot.tag, 7);
            assert!(bot.wrapper.bytes().iter().all(|b| *b == 0xa5));
            assert!(bot.buffer.bytes().iter().all(|b| *b == 0x5a));
        }
    }
    #[test]
    fn retained_reader_discovers_inserted_media_and_never_revives_removed_aliases() {
        use super::super::media::{Owner, scan_bot};
        use crate::block::BlockDevice;
        let mut memory = vec![0u64; 32 * 1024];
        let start = memory.as_mut_ptr() as u64;
        let io = model(start, start + memory.len() as u64 * 8, vec![None, None]);
        let state = io.0.clone();
        let mut dma = dma(&mut memory);
        let owner = Rc::new(RefCell::new(Owner::new(
            Bot::new(io, 3, endpoints(), &mut dma).unwrap(),
            "reader".into(),
            "serial".into(),
        )));
        let mut failures = Vec::new();
        assert!(scan_bot(owner.clone(), &mut failures).unwrap().is_empty());
        assert!(
            state
                .borrow()
                .history
                .iter()
                .all(|(_, _, cdb)| !matches!(cdb[0], 0x25 | 0x1a))
        );
        state.borrow_mut().units[0] = unit(0x31);
        let mut disks = scan_bot(owner.clone(), &mut failures).unwrap();
        assert_eq!(disks.len(), 1);
        let mut same = scan_bot(owner.clone(), &mut failures).unwrap();
        assert!(Rc::ptr_eq(&disks[0].media, &same[0].media));
        disks[0].write(0, &[0x72; 512]).unwrap();
        disks[0].flush().unwrap();
        let mut data = [0; 512];
        same[0].read(0, &mut data).unwrap();
        assert_eq!(data, [0x72; 512]);
        // A real failed data command returns UA. The target does not commit
        // its payload; the caller must never silently retry it on new media.
        state.borrow_mut().units[0].as_mut().unwrap().attention = true;
        let before = state.borrow().history.len();
        assert_eq!(
            disks[0].write(0, &[0xa4; 512]),
            Err(BlockError::Sense(Sense {
                key: 0x06,
                asc: 0x29,
                ascq: 0x00
            }))
        );
        assert_eq!(
            state.borrow().history[before..]
                .iter()
                .filter(|(_, _, c)| c[0] == 0x2a)
                .count(),
            1
        );
        let before = state.borrow().transfers;
        assert!(same[0].read(0, &mut data).is_err());
        assert!(same[0].read(0, &mut []).is_err());
        assert!(same[0].write(0, &[0; 512]).is_err());
        assert!(same[0].flush().is_err());
        assert!(same[0].command(&[0; 6], super::super::Data::None).is_err());
        assert_eq!(state.borrow().transfers, before);
        let mut current = scan_bot(owner.clone(), &mut failures).unwrap();
        assert!(!Rc::ptr_eq(&current[0].media, &disks[0].media));
        current[0].read(0, &mut data).unwrap();
        assert_eq!(data, [0x72; 512], "failed write was replayed");
        state.borrow_mut().units[0] = None;
        data.fill(0x5a);
        assert_eq!(
            current[0].read(0, &mut data),
            Err(BlockError::Sense(Sense {
                key: 0x02,
                asc: 0x3a,
                ascq: 0x00
            }))
        );
        assert_eq!(data, [0x5a; 512]);
        assert!(scan_bot(owner.clone(), &mut failures).unwrap().is_empty());
        state.borrow_mut().units[0] = unit(0x99);
        let mut inserted = scan_bot(owner, &mut failures).unwrap();
        inserted[0].read(0, &mut data).unwrap();
        assert_eq!(data, [0x99; 512]);
        let before = state.borrow().transfers;
        assert!(current[0].read(0, &mut data).is_err());
        assert!(disks[0].flush().is_err());
        assert_eq!(state.borrow().transfers, before);
        assert_eq!(
            state
                .borrow()
                .controls
                .iter()
                .filter(|c| c[1] == GET_MAX_LUN)
                .count(),
            1
        );
    }

    #[test]
    fn rescan_revalidates_geometry_protection_and_quarantines_all_on_transport_poison() {
        use super::super::media::{Owner, scan_bot};
        use crate::block::BlockDevice;
        let mut memory = vec![0u64; 32 * 1024];
        let start = memory.as_mut_ptr() as u64;
        let io = model(
            start,
            start + memory.len() as u64 * 8,
            vec![unit(0x11), unit(0x22)],
        );
        let state = io.0.clone();
        let mut dma = dma(&mut memory);
        let owner = Rc::new(RefCell::new(Owner::new(
            Bot::new(io, 3, endpoints(), &mut dma).unwrap(),
            "reader".into(),
            "serial".into(),
        )));
        let mut failures = Vec::new();
        let mut old = scan_bot(owner.clone(), &mut failures).unwrap();
        state.borrow_mut().units[0]
            .as_mut()
            .unwrap()
            .media
            .resize(4096, 0x33);
        let mut fresh = scan_bot(owner.clone(), &mut failures).unwrap();
        assert_eq!(fresh[0].identity().blocks, 8);
        assert!(old[0].flush().is_err());
        old[1].read(0, &mut [0; 512]).unwrap();
        state.borrow_mut().units[0].as_mut().unwrap().readonly = true;
        let protected = scan_bot(owner.clone(), &mut failures).unwrap();
        assert!(protected[0].identity().read_only);
        assert!(fresh[0].flush().is_err());
        // Failed revalidation cannot preserve an older apparently usable view.
        state.borrow_mut().override_payload.push((0x25, vec![0; 7]));
        assert!(scan_bot(owner.clone(), &mut failures).unwrap().is_empty());
        assert!(old[1].flush().is_err());
        state.borrow_mut().override_payload.clear();
        let mut ready = scan_bot(owner.clone(), &mut failures).unwrap();
        state.borrow_mut().fault = Fault::Timeout;
        assert!(ready[0].read(0, &mut [0; 512]).is_err());
        let before = state.borrow().transfers;
        assert!(ready[1].flush().is_err());
        assert_eq!(state.borrow().transfers, before);
        assert!(scan_bot(owner, &mut failures).is_err());
    }

    #[test]
    fn real_block_api_chunks_units_checks_bounds_and_never_copies_short_reads() {
        use crate::block::BlockDevice;
        let mut memory = vec![0u64; 32 * 1024];
        let start = memory.as_mut_ptr() as u64;
        let mut dma = dma(&mut memory);
        let mut first = unit(0x22).unwrap();
        first.media = vec![0x22; MAX_TD * 3];
        let mut second = unit(0x44).unwrap();
        second.readonly = true;
        let io = model(
            start,
            start + memory.len() as u64 * 8,
            vec![Some(first), Some(second)],
        );
        let state = io.0.clone();
        let bot = Rc::new(RefCell::new(
            Bot::new(io, 3, endpoints(), &mut dma).unwrap(),
        ));
        let mut disks = Vec::new();
        for lun in 0..2 {
            let identity =
                super::super::probe(&mut *bot.borrow_mut(), lun, "slot", "serial").unwrap();
            disks.push(super::super::Disk {
                bot: bot.clone(),
                lun,
                identity,
                media: Rc::new(core::cell::Cell::new(true)),
                write_cache: true,
            });
        }
        let mut bytes = vec![0; MAX_TD * 2 + 512];
        disks[0].read(0, &mut bytes).unwrap();
        assert!(bytes.iter().all(|b| *b == 0x22));
        disks[0].write(1, &vec![0x66; MAX_TD + 512]).unwrap();
        disks[0].flush().unwrap();
        let before = state.borrow().transfers;
        assert_eq!(disks[1].write(0, &[0; 512]), Err(BlockError::ReadOnly));
        assert!(disks[0].read(u64::MAX, &mut [0; 512]).is_err());
        assert!(disks[0].read(0, &mut [0; 511]).is_err());
        assert_eq!(state.borrow().transfers, before);
        state.borrow_mut().fault = Fault::ShortData;
        let mut untouched = [0xa5; 512];
        assert!(disks[0].read(0, &mut untouched).is_err());
        assert_eq!(untouched, [0xa5; 512]);
        assert_eq!(disks[0].cdb(false, u32::MAX as u64, 1)[0], 0x28);
        assert_eq!(disks[0].cdb(false, u32::MAX as u64, 2)[0], 0x88);
        assert_eq!(disks[0].cdb(true, 1u64 << 32, 1)[0], 0x8a);
    }

    #[test]
    #[ignore = "requires pinned unchanged Linux CBW builder trace"]
    fn unchanged_linux_cbw_builder_matches_all_luns_and_transfer_profiles() {
        extern crate std;
        let path = std::env::var("STELA_USB_BOT_CBW_ORACLE").expect("oracle trace path");
        let bytes = std::fs::read(path).unwrap();
        assert_eq!(&bytes[..8], b"BOTCBW01");
        let records = &bytes[8..];
        assert_eq!(records.len() % 58, 0);
        assert_eq!(records.len() / 58, 6144);
        for record in records.as_chunks::<58>().0 {
            let tag = u32::from_le_bytes(record[..4].try_into().unwrap());
            let lun = record[4];
            let n = usize::from(record[5]);
            let input = record[6] != 0;
            let length = u32::from_le_bytes(record[7..11].try_into().unwrap()) as usize;
            assert_eq!(
                cbw(tag, lun, &record[11..11 + n], length, input).as_slice(),
                &record[27..58]
            );
        }
    }
    #[test]
    fn discovery_reports_empty_slots_and_publishes_only_actual_ready_units() {
        let mut memory = vec![0u64; 32 * 1024];
        let start = memory.as_mut_ptr() as u64;
        let mut dma = dma(&mut memory);
        let io = model(
            start,
            start + memory.len() as u64 * 8,
            vec![None, unit(1), None, unit(3)],
        );
        let bot = Rc::new(RefCell::new(
            Bot::new(io, 3, endpoints(), &mut dma).unwrap(),
        ));
        let mut failures = Vec::new();
        let disks =
            super::super::discover_units(bot, "reader interface 3", "reader-serial", &mut failures)
                .unwrap();
        assert_eq!(disks.iter().map(|d| d.lun).collect::<Vec<_>>(), vec![1, 3]);
        assert_eq!(
            failures,
            vec![
                (
                    "reader interface 3 LUN 0".into(),
                    BlockError::Sense(Sense {
                        key: 0x02,
                        asc: 0x3a,
                        ascq: 0x00
                    })
                ),
                (
                    "reader interface 3 LUN 2".into(),
                    BlockError::Sense(Sense {
                        key: 0x02,
                        asc: 0x3a,
                        ascq: 0x00
                    })
                )
            ]
        );
    }
    #[test]
    fn invalid_identification_capacity_and_mode_never_publish_a_block_device() {
        let mut short_capacity = vec![0; 7];
        short_capacity[0] = 1;
        let mut overflow = vec![0; 32];
        overflow[..8].fill(255);
        overflow[8..12].copy_from_slice(&512u32.to_be_bytes());
        let mut bad_block = vec![0; 8];
        bad_block[4..8].copy_from_slice(&513u32.to_be_bytes());
        for (opcode, payload) in [
            (0x12, vec![0; 35]),
            (0x12, vec![0x20; 36]),
            (0x25, short_capacity),
            (0x25, bad_block),
            (0x9e, overflow),
            (0x1a, vec![0; 4]),
        ] {
            let mut memory = vec![0u64; 32 * 1024];
            let start = memory.as_mut_ptr() as u64;
            let mut dma = dma(&mut memory);
            let mut u = unit(0).unwrap();
            u.huge = opcode == 0x9e;
            let io = model(start, start + memory.len() as u64 * 8, vec![Some(u)]);
            io.0.borrow_mut().override_payload.push((opcode, payload));
            let mut bot = Bot::new(io, 3, endpoints(), &mut dma).unwrap();
            assert!(super::super::probe(&mut bot, 0, "slot", "serial").is_err());
        }
    }
    #[test]
    fn malformed_sense_never_fabricates_a_ready_unit() {
        for bytes in [
            vec![],
            vec![0x70; 13],
            vec![0x72; 7],
            vec![0x71; 8],
            vec![0x75; 18],
        ] {
            assert_eq!(Sense::parse(&bytes), None);
        }
        let mut fixed = vec![0; 18];
        fixed[0] = 0x71;
        fixed[2] = 6;
        fixed[7] = 5;
        assert_eq!(Sense::parse(&fixed), None);
        fixed[7] = 6;
        fixed[12] = 0x29;
        assert_eq!(
            Sense::parse(&fixed),
            Some(Sense {
                key: Sense::UNIT_ATTENTION,
                asc: Sense::RESET_OCCURRED,
                ascq: 0
            })
        );
    }
    #[test]
    fn late_discovery_transport_poison_discards_already_probed_units() {
        struct FailSecond(Model);
        impl Io for FailSecond {
            fn ready(&mut self) -> Result<(), BlockError> {
                self.0.ready()
            }
            fn control(&mut self, r: [u8; 8]) -> Result<Vec<u8>, BlockError> {
                self.0.control(r)
            }
            fn clear(&mut self, e: Endpoint) -> Result<(), BlockError> {
                self.0.clear(e)
            }
            fn delay(&self, m: u64) {
                self.0.delay(m);
            }
            fn bulk(&mut self, e: Endpoint, p: u64, n: usize) -> Result<usize, BlockError> {
                if !e.is_in() && n == 31 {
                    let range = self.0.0.borrow().range.clone();
                    assert!(p >= range.start && p + 31 <= range.end);
                    // SAFETY: same live private DMA range as Model::bulk.
                    if unsafe { (p as *const u8).add(13).read() } == 1 {
                        self.0.0.borrow_mut().fault = Fault::Timeout;
                    }
                }
                self.0.bulk(e, p, n)
            }
        }
        let mut memory = vec![0u64; 32 * 1024];
        let start = memory.as_mut_ptr() as u64;
        let mut dma = dma(&mut memory);
        let io = model(
            start,
            start + memory.len() as u64 * 8,
            vec![unit(0), unit(1), unit(2)],
        );
        let state = io.0.clone();
        let bot = Rc::new(RefCell::new(
            Bot::new(FailSecond(io), 3, endpoints(), &mut dma).unwrap(),
        ));
        let mut failures = Vec::new();
        assert!(
            super::super::discover_units(bot.clone(), "reader", "serial", &mut failures).is_err()
        );
        assert!(bot.borrow().poisoned());
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].0, "reader LUN 1");
        assert!(!state.borrow().history.iter().any(|(lun, _, _)| *lun == 2));
    }
    #[test]
    fn recovery_waits_for_real_reset_settle_before_clears_and_next_lun() {
        let mut memory = vec![0u64; 32 * 1024];
        let start = memory.as_mut_ptr() as u64;
        let mut dma = dma(&mut memory);
        let io = model(
            start,
            start + memory.len() as u64 * 8,
            vec![unit(0), unit(1)],
        );
        let state = io.0.clone();
        let mut bot = Bot::new(io, 3, endpoints(), &mut dma).unwrap();
        state.borrow_mut().fault = Fault::Phase;
        assert!(bot.command(0, &[0; 6], Data::None).is_err());
        assert!(!bot.poisoned());
        state.borrow_mut().fault = Fault::None;
        bot.command(1, &[0; 6], Data::None).unwrap();
        assert_eq!(
            state.borrow().order,
            vec![
                Order::Cbw(0),
                Order::Reset,
                Order::Delay(RESET_RECOVERY_US),
                Order::Clear(0x82),
                Order::Clear(0x02),
                Order::Cbw(1)
            ]
        );
    }
}
