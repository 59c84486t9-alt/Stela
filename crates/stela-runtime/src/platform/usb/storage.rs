//! A native high-speed USB mass storage device: Bulk-Only Transport with
//! the SCSI transparent command set, backed by one host block device.
//!
//! Evidence: USB Mass Storage Class Bulk-Only Transport 1.0 (CBW and CSW,
//! 5.1-5.3; class requests, 3.1-3.2; the thirteen host/device cases, 6.7;
//! reset recovery, 5.3.4 and 6.6.1), SPC-4 (INQUIRY, REQUEST SENSE, MODE
//! SENSE, TEST UNIT READY, sense data in fixed format) and SBC-3 (READ and
//! WRITE 10/12/16, READ CAPACITY 10/16, SYNCHRONIZE CACHE, VERIFY, START
//! STOP UNIT, PREVENT ALLOW MEDIUM REMOVAL). J473 macOS binds
//! `IOUSBMassStorageInterfaceNub` to interface class 8 subclass 6 and
//! `IOUSBMassStorageDriver` (KC `0x45e985c`) to protocol 0x50.
//!
//! One LUN, the whole backing device, not removable, with the device's own
//! logical block size and a write-back cache that SYNCHRONIZE CACHE flushes
//! (the backing device's own `flush`). A command outside this set, a CDB
//! field this device does not implement, or an out-of-range LBA fails with
//! CHECK CONDITION and the sense SPC-4 assigns (ILLEGAL REQUEST with
//! INVALID COMMAND OPERATION CODE, INVALID FIELD IN CDB or LBA OUT OF
//! RANGE); a backing device error is MEDIUM ERROR. A CBW that is not valid
//! and meaningful stalls both bulk endpoints until a Bulk-Only Mass Storage
//! Reset (6.6.1). Transfers where the host's direction or length disagrees
//! with the command follow 6.7: shorter data ends with a short packet or a
//! bulk-in STALL and the residue, and a direction mismatch or a device
//! intending more than the host allows is a phase error.
use super::{
    BusPeer, Function, Reply, Token,
    control::{
        self, CLASS, CLEAR_FEATURE, Control, DEVICE, DEVICE_QUALIFIER, Descriptors, ENDPOINT,
        ENDPOINT_HALT, GET_INTERFACE, GET_STATUS, INTERFACE, Outcome, RECIPIENT_ENDPOINT,
        RECIPIENT_INTERFACE, Requests, SET_FEATURE, SET_INTERFACE, STANDARD, Setup,
    },
};
use crate::platform::pc::block::BlockDevice;
use alloc::{boxed::Box, string::String, vec, vec::Vec};

const BULK_IN: u8 = 0x81;
const BULK_OUT: u8 = 0x02;
const HIGH_SPEED_PACKET: u16 = 512;
const FULL_SPEED_PACKET: u16 = 64;
const RESET: u8 = 0xff;
const GET_MAX_LUN: u8 = 0xfe;
const CBW_SIGNATURE: u32 = 0x4342_5355;
const CSW_SIGNATURE: u32 = 0x5342_5355;
const CBW_BYTES: usize = 31;
const PASSED: u8 = 0;
const FAILED: u8 = 1;
const PHASE_ERROR: u8 = 2;
/// Bytes moved to or from the backing device at a time.
const CHUNK: usize = 64 * 1024;

const TEST_UNIT_READY: u8 = 0x00;
const REQUEST_SENSE: u8 = 0x03;
const INQUIRY: u8 = 0x12;
const MODE_SENSE_6: u8 = 0x1a;
const START_STOP_UNIT: u8 = 0x1b;
const PREVENT_ALLOW: u8 = 0x1e;
const READ_FORMAT_CAPACITIES: u8 = 0x23;
const READ_CAPACITY_10: u8 = 0x25;
const READ_10: u8 = 0x28;
const WRITE_10: u8 = 0x2a;
const VERIFY_10: u8 = 0x2f;
const SYNCHRONIZE_CACHE_10: u8 = 0x35;
const MODE_SENSE_10: u8 = 0x5a;
const READ_16: u8 = 0x88;
const WRITE_16: u8 = 0x8a;
const VERIFY_16: u8 = 0x8f;
const SYNCHRONIZE_CACHE_16: u8 = 0x91;
const SERVICE_ACTION_IN_16: u8 = 0x9e;
const READ_CAPACITY_16: u8 = 0x10;
const READ_12: u8 = 0xa8;
const WRITE_12: u8 = 0xaa;

const CACHING_PAGE: u8 = 0x08;
const ALL_PAGES: u8 = 0x3f;

/// Sense key, additional sense code and qualifier (SPC-4 4.5.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Sense(u8, u8, u8);

const NO_SENSE: Sense = Sense(0, 0, 0);
const INVALID_OPCODE: Sense = Sense(5, 0x20, 0);
const INVALID_FIELD: Sense = Sense(5, 0x24, 0);
const OUT_OF_RANGE: Sense = Sense(5, 0x21, 0);
const WRITE_PROTECTED: Sense = Sense(7, 0x27, 0);
const READ_ERROR: Sense = Sense(3, 0x11, 0);
const WRITE_ERROR: Sense = Sense(3, 0x0c, 0);

/// What a command moves, as the device intends it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Plan {
    None,
    /// Data the device has ready.
    In(Vec<u8>),
    /// Blocks to read from the backing device.
    Read {
        lba: u64,
        blocks: u64,
    },
    /// Blocks to write.
    Write {
        lba: u64,
        blocks: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Phase {
    Command,
    /// Sending: bytes the host still accepts, bytes the device still
    /// intends, buffered bytes not yet sent.
    DataIn {
        host: u32,
        device: u64,
        lba: u64,
        buffer: Vec<u8>,
        failed: bool,
    },
    /// Receiving: bytes the host still sends, bytes the write still takes.
    DataOut {
        host: u32,
        device: u64,
        lba: u64,
        buffer: Vec<u8>,
        failed: bool,
    },
    Status,
}

/// A command's outcome, for its CSW.
#[derive(Debug, Clone, Copy)]
struct Pending {
    tag: u32,
    residue: u32,
    status: u8,
}

struct State {
    device: Box<dyn BlockDevice>,
    phase: Phase,
    pending: Pending,
    sense: Sense,
    halted_in: bool,
    halted_out: bool,
    /// An invalid CBW: both endpoints STALL until a class reset.
    reset_required: bool,
    vendor: [u8; 8],
    product: [u8; 16],
    serial: String,
}

pub struct MassStorage {
    control: Control,
    state: State,
}

fn descriptors(serial: &str) -> Descriptors {
    let device = [
        18,
        DEVICE,
        0x00,
        0x02,
        0,
        0,
        0,
        control::EP0_PACKET as u8,
        0x09,
        0x12,
        0x01,
        0x00,
        0x00,
        0x01,
        1,
        2,
        3,
        1,
    ];
    let configuration = |packet: u16| {
        let [low, high] = packet.to_le_bytes();
        control::configuration(
            1,
            0,
            &[
                &[9, INTERFACE, 0, 0, 2, 8, 6, 0x50, 0],
                &[7, ENDPOINT, BULK_IN, 2, low, high, 0],
                &[7, ENDPOINT, BULK_OUT, 2, low, high, 0],
            ],
        )
    };
    let qualifier = [
        10,
        DEVICE_QUALIFIER,
        0x00,
        0x02,
        0,
        0,
        0,
        control::EP0_PACKET as u8,
        1,
        0,
    ];
    Descriptors {
        device,
        configuration: configuration(HIGH_SPEED_PACKET),
        other_speed: Some((qualifier, configuration(FULL_SPEED_PACKET))),
        strings: vec![
            String::from("Stela"),
            String::from("Stela USB Disk"),
            String::from(serial),
        ],
    }
}

fn padded<const N: usize>(text: &str) -> [u8; N] {
    let mut bytes = [b' '; N];
    for (slot, byte) in bytes
        .iter_mut()
        .zip(text.bytes().filter(|b| (0x20..0x7f).contains(b)))
    {
        *slot = byte;
    }
    bytes
}

impl MassStorage {
    /// The device presenting `device`; `serial` is its iSerialNumber and
    /// unit serial number (12 or more characters per BOT 4.1.1, from
    /// `0-9A-F`), and `model` names it in INQUIRY.
    pub fn new(
        device: Box<dyn BlockDevice>,
        serial: &str,
        model: &str,
    ) -> Result<Self, &'static str> {
        let identity = device.identity();
        if identity.block_size < 512 || !identity.block_size.is_power_of_two() {
            return Err("mass storage block size must be a power of two from 512");
        }
        if identity.blocks == 0 {
            return Err("mass storage backing device is empty");
        }
        if serial.len() < 12
            || !serial
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
        {
            return Err("mass storage serial must be at least 12 characters of 0-9A-F");
        }
        Ok(Self {
            control: Control::new(descriptors(serial)),
            state: State {
                device,
                phase: Phase::Command,
                pending: Pending {
                    tag: 0,
                    residue: 0,
                    status: PASSED,
                },
                sense: NO_SENSE,
                halted_in: false,
                halted_out: false,
                reset_required: false,
                vendor: padded("STELA"),
                product: padded(model),
                serial: String::from(serial),
            },
        })
    }
}

impl MassStorage {
    /// The device presenting `device` under a serial number derived from
    /// the host device's own serial and location, so a disk keeps its
    /// identity across boots, and its model in INQUIRY.
    pub fn of(device: Box<dyn BlockDevice>) -> Result<Self, &'static str> {
        let identity = device.identity();
        let digest = crate::hash::sha256(
            alloc::format!("{}\0{}", identity.serial, identity.location).as_bytes(),
        );
        let serial = digest[..24].to_ascii_uppercase();
        let model = identity.model.clone();
        Self::new(device, &serial, &model)
    }
}

fn be16(cdb: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([cdb[at], cdb[at + 1]])
}
fn be32(cdb: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(cdb[at..at + 4].try_into().unwrap())
}
fn be64(cdb: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(cdb[at..at + 8].try_into().unwrap())
}

impl State {
    fn block_size(&self) -> u64 {
        u64::from(self.device.identity().block_size)
    }

    fn blocks(&self) -> u64 {
        self.device.identity().blocks
    }

    /// The command's plan, or the sense of its CHECK CONDITION.
    fn plan(&mut self, cdb: &[u8]) -> Result<Plan, Sense> {
        let opcode = cdb[0];
        // Commands with an allocation length, whose data the device trims.
        let trimmed = |data: Vec<u8>, allocation: usize| {
            let mut data = data;
            data.truncate(allocation);
            Ok(Plan::In(data))
        };
        let need = |length: usize| {
            if cdb.len() >= length {
                Ok(())
            } else {
                Err(INVALID_FIELD)
            }
        };
        match opcode {
            TEST_UNIT_READY => Ok(Plan::None),
            REQUEST_SENSE => {
                need(6)?;
                if cdb[1] & 1 != 0 {
                    return Err(INVALID_FIELD); // descriptor format
                }
                let Sense(key, code, qualifier) = core::mem::replace(&mut self.sense, NO_SENSE);
                let mut data = vec![0u8; 18];
                data[0] = 0x70;
                data[2] = key;
                data[7] = 10;
                data[12] = code;
                data[13] = qualifier;
                trimmed(data, usize::from(cdb[4]))
            }
            INQUIRY => {
                need(6)?;
                let allocation = usize::from(be16(cdb, 3));
                if cdb[1] & 1 == 0 {
                    if cdb[2] != 0 {
                        return Err(INVALID_FIELD);
                    }
                    let mut data = vec![0u8; 36];
                    data[2] = 6; // SPC-4
                    data[3] = 2; // response data format
                    data[4] = 31;
                    data[8..16].copy_from_slice(&self.vendor);
                    data[16..32].copy_from_slice(&self.product);
                    data[32..36].copy_from_slice(b"1.00");
                    return trimmed(data, allocation);
                }
                let page = match cdb[2] {
                    0x00 => vec![0x00, 0x80, 0x83],
                    0x80 => self.serial.as_bytes().to_vec(),
                    0x83 => {
                        // One T10 vendor ID designator: vendor and serial.
                        let mut id = self.vendor.to_vec();
                        id.extend_from_slice(self.serial.as_bytes());
                        let mut d = vec![0x02, 0x01, 0, id.len() as u8];
                        d.extend_from_slice(&id);
                        d
                    }
                    _ => return Err(INVALID_FIELD),
                };
                let mut data = vec![0, cdb[2]];
                data.extend_from_slice(&(page.len() as u16).to_be_bytes());
                data.extend_from_slice(&page);
                trimmed(data, allocation)
            }
            MODE_SENSE_6 | MODE_SENSE_10 => {
                let ten = opcode == MODE_SENSE_10;
                need(if ten { 10 } else { 6 })?;
                let page = cdb[2] & 0x3f;
                let control = cdb[2] >> 6;
                if cdb[3] != 0 || control == 3 {
                    // Subpages; saved values are not supported (39/00).
                    return Err(if control == 3 {
                        Sense(5, 0x39, 0)
                    } else {
                        INVALID_FIELD
                    });
                }
                let pages = match page {
                    CACHING_PAGE | ALL_PAGES => {
                        let mut caching = vec![0u8; 20];
                        caching[0] = CACHING_PAGE;
                        caching[1] = 18;
                        // Current and default values: write cache on.
                        // Changeable values: nothing can change.
                        if control != 1 {
                            caching[2] = 0x04; // WCE
                        }
                        caching
                    }
                    _ => return Err(INVALID_FIELD),
                };
                let protect = if self.device.identity().read_only {
                    0x80
                } else {
                    0
                };
                let mut data = if ten {
                    let length = (6 + pages.len()) as u16;
                    let mut header = length.to_be_bytes().to_vec();
                    header.extend_from_slice(&[0, protect, 0, 0, 0, 0]);
                    header
                } else {
                    vec![(3 + pages.len()) as u8, 0, protect, 0]
                };
                data.extend_from_slice(&pages);
                let allocation = if ten {
                    usize::from(be16(cdb, 7))
                } else {
                    usize::from(cdb[4])
                };
                trimmed(data, allocation)
            }
            START_STOP_UNIT | PREVENT_ALLOW => Ok(Plan::None),
            READ_FORMAT_CAPACITIES => {
                need(10)?;
                let blocks = u32::try_from(self.blocks()).unwrap_or(u32::MAX);
                let mut data = vec![0, 0, 0, 8];
                data.extend_from_slice(&blocks.to_be_bytes());
                // Descriptor type 2: formatted media; then the block length.
                data.push(2);
                data.extend_from_slice(&(self.block_size() as u32).to_be_bytes()[1..]);
                trimmed(data, usize::from(be16(cdb, 7)))
            }
            READ_CAPACITY_10 => {
                need(10)?;
                let last = u32::try_from(self.blocks() - 1).unwrap_or(u32::MAX);
                let mut data = last.to_be_bytes().to_vec();
                data.extend_from_slice(&(self.block_size() as u32).to_be_bytes());
                Ok(Plan::In(data))
            }
            SERVICE_ACTION_IN_16 if cdb.len() >= 16 && cdb[1] & 0x1f == READ_CAPACITY_16 => {
                let mut data = vec![0u8; 32];
                data[..8].copy_from_slice(&(self.blocks() - 1).to_be_bytes());
                data[8..12].copy_from_slice(&(self.block_size() as u32).to_be_bytes());
                trimmed(data, be32(cdb, 10) as usize)
            }
            READ_10 | READ_12 | READ_16 | WRITE_10 | WRITE_12 | WRITE_16 => {
                let (lba, blocks) = match opcode {
                    READ_10 | WRITE_10 => {
                        need(10)?;
                        (u64::from(be32(cdb, 2)), u64::from(be16(cdb, 7)))
                    }
                    READ_12 | WRITE_12 => {
                        need(12)?;
                        (u64::from(be32(cdb, 2)), u64::from(be32(cdb, 6)))
                    }
                    _ => {
                        need(16)?;
                        (be64(cdb, 2), u64::from(be32(cdb, 10)))
                    }
                };
                // RDPROTECT/WRPROTECT need protection information.
                if cdb[1] & 0xe0 != 0 {
                    return Err(INVALID_FIELD);
                }
                if lba
                    .checked_add(blocks)
                    .is_none_or(|end| end > self.blocks())
                {
                    return Err(OUT_OF_RANGE);
                }
                let write = matches!(opcode, WRITE_10 | WRITE_12 | WRITE_16);
                if write && self.device.identity().read_only {
                    return Err(WRITE_PROTECTED);
                }
                Ok(match (write, blocks) {
                    (_, 0) => Plan::None,
                    (false, _) => Plan::Read { lba, blocks },
                    (true, _) => Plan::Write { lba, blocks },
                })
            }
            VERIFY_10 | VERIFY_16 => {
                let (lba, blocks) = if opcode == VERIFY_10 {
                    need(10)?;
                    (u64::from(be32(cdb, 2)), u64::from(be16(cdb, 7)))
                } else {
                    need(16)?;
                    (be64(cdb, 2), u64::from(be32(cdb, 10)))
                };
                // BYTCHK compares data the host sends: not implemented.
                if cdb[1] & 0x06 != 0 {
                    return Err(INVALID_FIELD);
                }
                if lba
                    .checked_add(blocks)
                    .is_none_or(|end| end > self.blocks())
                {
                    return Err(OUT_OF_RANGE);
                }
                Ok(Plan::None)
            }
            SYNCHRONIZE_CACHE_10 | SYNCHRONIZE_CACHE_16 => match self.device.flush() {
                Ok(()) => Ok(Plan::None),
                Err(_) => Err(WRITE_ERROR),
            },
            _ => Err(INVALID_OPCODE),
        }
    }

    /// A Command Block Wrapper: `false` when it is not valid and
    /// meaningful (5.2).
    fn command(&mut self, cbw: &[u8]) -> bool {
        if cbw.len() != CBW_BYTES
            || u32::from_le_bytes(cbw[..4].try_into().unwrap()) != CBW_SIGNATURE
        {
            return false;
        }
        let tag = u32::from_le_bytes(cbw[4..8].try_into().unwrap());
        let host = u32::from_le_bytes(cbw[8..12].try_into().unwrap());
        let host_in = cbw[12] & 0x80 != 0;
        let (lun, length) = (cbw[13] & 0x0f, usize::from(cbw[14] & 0x1f));
        if cbw[12] & 0x7f != 0 || cbw[13] & 0xf0 != 0 || lun != 0 || !(1..=16).contains(&length) {
            return false;
        }
        let cdb = cbw[15..15 + length].to_vec();
        self.pending = Pending {
            tag,
            residue: host,
            status: PASSED,
        };
        let plan = match self.plan(&cdb) {
            Ok(plan) => plan,
            Err(sense) => {
                self.sense = sense;
                self.pending.status = FAILED;
                Plan::None
            }
        };
        let size = self.block_size();
        let (intends_in, intends_out, intended) = match &plan {
            Plan::None => (false, false, 0),
            Plan::In(data) => (true, false, data.len() as u64),
            Plan::Read { blocks, .. } => (true, false, blocks * size),
            Plan::Write { blocks, .. } => (false, true, blocks * size),
        };
        // 6.7: cases 1, 4, 9 (the device intends nothing), 2-3 (the host
        // expects no data), 8 and 10 (opposite directions).
        if host == 0 || intended == 0 {
            self.pending.status = if intended == 0 {
                self.pending.status
            } else {
                PHASE_ERROR
            };
            if host == 0 {
                self.phase = Phase::Status;
            } else if host_in {
                // Case 4: nothing to send; the bulk-in STALL ends the data.
                self.halted_in = true;
                self.phase = Phase::Status;
            } else {
                // Case 9: take and discard the host's data.
                self.phase = Phase::DataOut {
                    host,
                    device: 0,
                    lba: 0,
                    buffer: Vec::new(),
                    failed: false,
                };
            }
            return true;
        }
        if host_in != intends_in || (!host_in && !intends_out) {
            self.pending.status = PHASE_ERROR;
            if host_in {
                self.halted_in = true;
            } else {
                self.halted_out = true;
            }
            self.phase = Phase::Status;
            return true;
        }
        // Cases 7 and 13: the device intends more than the host allows.
        let excess = intended > u64::from(host);
        if excess {
            self.pending.status = PHASE_ERROR;
        }
        let device = intended.min(u64::from(host));
        self.phase = match plan {
            Plan::In(data) => Phase::DataIn {
                host,
                device,
                lba: 0,
                buffer: data,
                failed: false,
            },
            Plan::Read { lba, .. } => Phase::DataIn {
                host,
                device,
                lba,
                buffer: Vec::new(),
                failed: false,
            },
            Plan::Write { lba, .. } => Phase::DataOut {
                host,
                device: if excess { 0 } else { device },
                lba,
                buffer: Vec::new(),
                failed: false,
            },
            Plan::None => unreachable!("handled above"),
        };
        true
    }

    fn csw(&mut self) -> [u8; 13] {
        let mut bytes = [0u8; 13];
        bytes[..4].copy_from_slice(&CSW_SIGNATURE.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.pending.tag.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.pending.residue.to_le_bytes());
        bytes[12] = self.pending.status;
        self.phase = Phase::Command;
        bytes
    }

    fn bulk_in(&mut self, packet: &mut [u8]) -> Reply {
        if self.reset_required || self.halted_in {
            return Reply::Stall;
        }
        let size = self.block_size() as usize;
        let max = packet.len();
        match &mut self.phase {
            Phase::Status => {
                let csw = self.csw();
                let n = csw.len().min(max);
                packet[..n].copy_from_slice(&csw[..n]);
                Reply::Ack(n)
            }
            Phase::DataIn {
                host,
                device,
                lba,
                buffer,
                failed,
            } => {
                if buffer.is_empty() && *device > 0 && !*failed {
                    // Reads stream from the backing device a chunk at a time.
                    let bytes = (*device as usize).min(CHUNK) / size * size;
                    let bytes = bytes.max(size);
                    let mut chunk = vec![0u8; bytes];
                    match self.device.read(*lba, &mut chunk) {
                        Ok(()) => {
                            *lba += (bytes / size) as u64;
                            *buffer = chunk;
                        }
                        Err(_) => *failed = true,
                    }
                }
                if *failed {
                    self.sense = READ_ERROR;
                    self.pending.status = FAILED;
                    self.halted_in = true;
                    self.phase = Phase::Status;
                    return Reply::Stall;
                }
                let n = buffer.len().min(*device as usize).min(max);
                packet[..n].copy_from_slice(&buffer[..n]);
                buffer.drain(..n);
                *device -= n as u64;
                *host -= n as u32;
                self.pending.residue = *host;
                if *device == 0 {
                    // Fewer bytes than the host asked for end with a short
                    // packet, or else a bulk-in STALL (6.7.2).
                    if *host != 0 && n == max {
                        self.halted_in = true;
                    }
                    self.phase = Phase::Status;
                }
                Reply::Ack(n)
            }
            Phase::Command | Phase::DataOut { .. } => Reply::Nak,
        }
    }

    fn bulk_out(&mut self, packet: &[u8]) -> Reply {
        if self.reset_required || self.halted_out {
            return Reply::Stall;
        }
        let size = self.block_size() as usize;
        match &mut self.phase {
            Phase::Command => {
                if !self.command(packet) {
                    self.reset_required = true;
                    self.halted_in = true;
                    self.halted_out = true;
                    return Reply::Stall;
                }
                Reply::Ack(packet.len())
            }
            Phase::DataOut {
                host,
                device,
                lba,
                buffer,
                failed,
            } => {
                let n = packet.len().min(*host as usize);
                let taken = n.min(*device as usize);
                if !*failed {
                    buffer.extend_from_slice(&packet[..taken]);
                }
                *device -= taken as u64;
                *host -= n as u32;
                // Bytes the device takes count as processed (6.7.3).
                self.pending.residue -= taken as u32;
                if !buffer.is_empty() && (buffer.len() >= CHUNK || *device == 0) && !*failed {
                    let whole = buffer.len() / size * size;
                    match self.device.write(*lba, &buffer[..whole]) {
                        Ok(()) => {
                            *lba += (whole / size) as u64;
                            buffer.drain(..whole);
                        }
                        Err(_) => {
                            *failed = true;
                            buffer.clear();
                            self.sense = WRITE_ERROR;
                            self.pending.status = FAILED;
                        }
                    }
                }
                if *host == 0 || n < packet.len() {
                    self.phase = Phase::Status;
                }
                Reply::Ack(n)
            }
            Phase::DataIn { .. } | Phase::Status => Reply::Nak,
        }
    }
}

impl Requests for State {
    fn configure(&mut self, _value: u8) -> Result<(), ()> {
        self.phase = Phase::Command;
        self.halted_in = false;
        self.halted_out = false;
        self.reset_required = false;
        Ok(())
    }

    fn request(&mut self, setup: Setup, _data: &[u8]) -> Result<Outcome, ()> {
        let read = setup.device_to_host();
        match (setup.kind(), setup.recipient(), setup.request, read) {
            (CLASS, RECIPIENT_INTERFACE, RESET, false)
                if setup.index == 0 && setup.value == 0 && setup.length == 0 =>
            {
                // Ready for a CBW; halts stay until the host clears them.
                self.phase = Phase::Command;
                self.reset_required = false;
                Ok(Outcome::Done)
            }
            (CLASS, RECIPIENT_INTERFACE, GET_MAX_LUN, true)
                if setup.index == 0 && setup.value == 0 && setup.length == 1 =>
            {
                Ok(Outcome::Data(vec![0]))
            }
            (STANDARD, RECIPIENT_INTERFACE, GET_STATUS, true) if setup.index == 0 => {
                Ok(Outcome::Data(vec![0, 0]))
            }
            (STANDARD, RECIPIENT_INTERFACE, GET_INTERFACE, true) if setup.index == 0 => {
                Ok(Outcome::Data(vec![0]))
            }
            (STANDARD, RECIPIENT_INTERFACE, SET_INTERFACE, false)
                if setup.index == 0 && setup.value == 0 =>
            {
                Ok(Outcome::Done)
            }
            (STANDARD, RECIPIENT_ENDPOINT, GET_STATUS, true) => match setup.index as u8 {
                BULK_IN => Ok(Outcome::Data(vec![u8::from(self.halted_in), 0])),
                BULK_OUT => Ok(Outcome::Data(vec![u8::from(self.halted_out), 0])),
                _ => Err(()),
            },
            (STANDARD, RECIPIENT_ENDPOINT, CLEAR_FEATURE | SET_FEATURE, false)
                if setup.value == ENDPOINT_HALT =>
            {
                let halt = setup.request == SET_FEATURE;
                match setup.index as u8 {
                    BULK_IN => self.halted_in = halt,
                    BULK_OUT => self.halted_out = halt,
                    _ => return Err(()),
                }
                Ok(Outcome::Done)
            }
            _ => Err(()),
        }
    }
}

impl BusPeer for MassStorage {
    fn reset(&mut self) -> Result<(), &'static str> {
        self.control.reset(&mut self.state)?;
        self.state.configure(0).map_err(|()| "mass storage reset")
    }

    fn packet(
        &mut self,
        endpoint: u8,
        token: Token,
        data: &mut [u8],
    ) -> Result<Reply, &'static str> {
        let configured = self.control.configuration() != 0;
        Ok(match (endpoint, token) {
            (0, _) => return self.control.packet(token, data, &mut self.state),
            (_, Token::Setup) => return Err("SETUP to a non-control endpoint"),
            (BULK_IN, Token::In) if configured => self.state.bulk_in(data),
            (BULK_OUT, Token::Out) if configured => self.state.bulk_out(data),
            _ => Reply::Stall,
        })
    }
}

impl Function for MassStorage {
    fn set_time(&mut self, _now: u64) {}

    fn ready_at(&self, endpoint: u8) -> Option<u64> {
        let ready = match self.state.phase {
            Phase::DataIn { .. } | Phase::Status => endpoint == BULK_IN,
            Phase::Command | Phase::DataOut { .. } => endpoint == BULK_OUT,
        };
        ready.then_some(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::{
        pc::block::tests::RamDisk,
        usb::control::{
            SET_ADDRESS, SET_CONFIGURATION,
            tests::{setup, transfer},
        },
    };

    const SERIAL: &str = "0123456789ABCDEF";

    fn device(blocks: u64, block_size: u32, read_only: bool) -> MassStorage {
        let mut disk = RamDisk::new("host", blocks, block_size);
        disk.identity.read_only = read_only;
        for (n, byte) in disk.bytes.iter_mut().enumerate() {
            *byte = (n / block_size as usize) as u8;
        }
        let mut d = MassStorage::new(Box::new(disk), SERIAL, "Host Disk").unwrap();
        transfer(&mut d, setup(0, SET_ADDRESS, 2, 0, 0), &[]).unwrap();
        transfer(&mut d, setup(0, SET_CONFIGURATION, 1, 0, 0), &[]).unwrap();
        d
    }

    fn cbw(tag: u32, length: u32, input: bool, cdb: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0u8; CBW_BYTES];
        bytes[..4].copy_from_slice(&CBW_SIGNATURE.to_le_bytes());
        bytes[4..8].copy_from_slice(&tag.to_le_bytes());
        bytes[8..12].copy_from_slice(&length.to_le_bytes());
        bytes[12] = if input { 0x80 } else { 0 };
        bytes[14] = cdb.len() as u8;
        bytes[15..15 + cdb.len()].copy_from_slice(cdb);
        bytes
    }

    /// One command: its IN data (read until a short packet or STALL), and
    /// its CSW's residue and status.
    fn run(
        d: &mut MassStorage,
        tag: u32,
        length: u32,
        input: bool,
        cdb: &[u8],
        out: &[u8],
    ) -> (Vec<u8>, u32, u8) {
        let mut wrapper = cbw(tag, length, input, cdb);
        assert_eq!(
            d.packet(BULK_OUT, Token::Out, &mut wrapper),
            Ok(Reply::Ack(CBW_BYTES))
        );
        let mut data = Vec::new();
        if input {
            loop {
                if data.len() == length as usize {
                    break;
                }
                let mut packet = [0u8; 512];
                match d.packet(BULK_IN, Token::In, &mut packet).unwrap() {
                    Reply::Ack(n) => {
                        data.extend_from_slice(&packet[..n]);
                        if n < 512 {
                            break;
                        }
                    }
                    Reply::Stall => {
                        transfer(d, setup(0x02, CLEAR_FEATURE, 0, u16::from(BULK_IN), 0), &[])
                            .unwrap();
                        break;
                    }
                    Reply::Nak => panic!("data NAK"),
                }
            }
        } else {
            for chunk in out.chunks(512) {
                match d.packet(BULK_OUT, Token::Out, &mut chunk.to_vec()).unwrap() {
                    Reply::Ack(_) => {}
                    Reply::Stall => {
                        transfer(
                            d,
                            setup(0x02, CLEAR_FEATURE, 0, u16::from(BULK_OUT), 0),
                            &[],
                        )
                        .unwrap();
                        break;
                    }
                    Reply::Nak => panic!("data NAK"),
                }
            }
        }
        let mut csw = [0u8; 512];
        let reply = d.packet(BULK_IN, Token::In, &mut csw).unwrap();
        if reply == Reply::Stall {
            transfer(d, setup(0x02, CLEAR_FEATURE, 0, u16::from(BULK_IN), 0), &[]).unwrap();
            assert_eq!(d.packet(BULK_IN, Token::In, &mut csw), Ok(Reply::Ack(13)));
        } else {
            assert_eq!(reply, Reply::Ack(13));
        }
        assert_eq!(
            u32::from_le_bytes(csw[..4].try_into().unwrap()),
            CSW_SIGNATURE
        );
        assert_eq!(u32::from_le_bytes(csw[4..8].try_into().unwrap()), tag);
        (
            data,
            u32::from_le_bytes(csw[8..12].try_into().unwrap()),
            csw[12],
        )
    }

    fn sense(d: &mut MassStorage) -> (u8, u8) {
        let (data, _, status) = run(d, 99, 18, true, &[REQUEST_SENSE, 0, 0, 0, 18, 0], &[]);
        assert_eq!(status, PASSED);
        (data[2], data[12])
    }

    #[test]
    fn descriptors_and_class_requests_describe_a_bulk_only_scsi_disk() {
        let mut d = device(64, 512, false);
        let config = transfer(&mut d, setup(0x80, 6, 0x200, 0, 255), &[]).unwrap();
        assert_eq!(&config[9..18], &[9, INTERFACE, 0, 0, 2, 8, 6, 0x50, 0]);
        assert_eq!(&config[18..25], &[7, ENDPOINT, BULK_IN, 2, 0, 2, 0]);
        let other = transfer(&mut d, setup(0x80, 6, 0x700, 0, 255), &[]).unwrap();
        assert_eq!(
            u16::from_le_bytes([other[22], other[23]]),
            FULL_SPEED_PACKET
        );
        assert_eq!(
            transfer(&mut d, setup(0xa1, GET_MAX_LUN, 0, 0, 1), &[]).unwrap(),
            [0]
        );
        transfer(&mut d, setup(0x21, RESET, 0, 0, 0), &[]).unwrap();
        assert!(MassStorage::new(Box::new(RamDisk::new("", 8, 512)), "short", "x").is_err());
    }

    #[test]
    fn inquiry_capacity_and_mode_pages_report_the_backing_disk() {
        let mut d = device(64, 4096, false);
        let (data, residue, status) = run(&mut d, 1, 36, true, &[INQUIRY, 0, 0, 0, 36, 0], &[]);
        assert_eq!((residue, status), (0, PASSED));
        assert_eq!(data[0], 0);
        assert_eq!(&data[8..16], b"STELA   ");
        assert_eq!(&data[16..32], b"Host Disk       ");
        let (serial, _, _) = run(&mut d, 2, 255, true, &[INQUIRY, 1, 0x80, 0, 255, 0], &[]);
        assert_eq!(&serial[4..], SERIAL.as_bytes());
        let (capacity, _, _) = run(
            &mut d,
            3,
            8,
            true,
            &[READ_CAPACITY_10, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            &[],
        );
        assert_eq!(capacity, [0, 0, 0, 63, 0, 0, 0x10, 0]);
        let mut cdb16 = [0u8; 16];
        cdb16[0] = SERVICE_ACTION_IN_16;
        cdb16[1] = READ_CAPACITY_16;
        cdb16[13] = 32;
        let (long, _, _) = run(&mut d, 4, 32, true, &cdb16, &[]);
        assert_eq!(&long[..12], &[0, 0, 0, 0, 0, 0, 0, 63, 0, 0, 0x10, 0]);
        let (mode, _, _) = run(
            &mut d,
            5,
            192,
            true,
            &[MODE_SENSE_6, 0, ALL_PAGES, 0, 192, 0],
            &[],
        );
        assert_eq!(&mode[..4], &[23, 0, 0, 0]);
        assert_eq!((mode[4], mode[6]), (CACHING_PAGE, 0x04));
        // Asking for fewer bytes than the reply has trims it: residue 0.
        let (short, residue, _) = run(&mut d, 6, 4, true, &[INQUIRY, 0, 0, 0, 4, 0], &[]);
        assert_eq!((short.len(), residue), (4, 0));
    }

    #[test]
    fn reads_and_writes_move_whole_blocks_through_chunks() {
        let mut d = device(64, 512, false);
        // 150 blocks cross a 128-block chunk.
        let mut d2 = device(160, 512, false);
        let (data, residue, status) = run(
            &mut d2,
            1,
            150 * 512,
            true,
            &[READ_10, 0, 0, 0, 0, 5, 0, 0, 150, 0],
            &[],
        );
        assert_eq!((data.len(), residue, status), (150 * 512, 0, PASSED));
        assert_eq!((data[0], data[512 * 149]), (5, 154));
        let payload: Vec<u8> = (0..3 * 512).map(|n| (n % 251) as u8).collect();
        let (_, residue, status) = run(
            &mut d,
            2,
            3 * 512,
            false,
            &[WRITE_10, 0, 0, 0, 0, 7, 0, 0, 3, 0],
            &payload,
        );
        assert_eq!((residue, status), (0, PASSED));
        let (back, _, _) = run(
            &mut d,
            3,
            3 * 512,
            true,
            &[READ_10, 0, 0, 0, 0, 7, 0, 0, 3, 0],
            &[],
        );
        assert_eq!(back, payload);
        let (_, _, status) = run(
            &mut d,
            4,
            0,
            false,
            &[SYNCHRONIZE_CACHE_10, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            &[],
        );
        assert_eq!(status, PASSED);
    }

    #[test]
    fn errors_report_sense_and_mismatched_lengths_follow_the_thirteen_cases() {
        let mut d = device(64, 512, false);
        let (_, _, status) = run(&mut d, 1, 0, false, &[0x04, 0, 0, 0, 0, 0], &[]);
        assert_eq!(status, FAILED);
        assert_eq!(sense(&mut d), (5, 0x20));
        let (_, _, status) = run(
            &mut d,
            2,
            512,
            true,
            &[READ_10, 0, 0, 0, 0, 64, 0, 0, 1, 0],
            &[],
        );
        assert_eq!(status, FAILED);
        assert_eq!(sense(&mut d), (5, 0x21));
        // Case 5: the host asks for more than the device sends; the full
        // last packet is followed by a STALL and the residue.
        let (data, residue, status) = run(
            &mut d,
            3,
            1024,
            true,
            &[READ_10, 0, 0, 0, 0, 1, 0, 0, 1, 0],
            &[],
        );
        assert_eq!((data.len(), residue, status), (512, 512, PASSED));
        // Case 7: the device intends more than the host takes.
        let (data, _, status) = run(
            &mut d,
            4,
            512,
            true,
            &[READ_10, 0, 0, 0, 0, 1, 0, 0, 2, 0],
            &[],
        );
        assert_eq!((data.len(), status), (512, PHASE_ERROR));
        // Case 2: the host expects no data but the device intends some.
        let (_, _, status) = run(
            &mut d,
            5,
            0,
            false,
            &[READ_10, 0, 0, 0, 0, 1, 0, 0, 1, 0],
            &[],
        );
        assert_eq!(status, PHASE_ERROR);
        // Case 10: the host sends data to a command that reads.
        let (_, _, status) = run(
            &mut d,
            6,
            512,
            false,
            &[READ_10, 0, 0, 0, 0, 1, 0, 0, 1, 0],
            &[0; 512],
        );
        assert_eq!(status, PHASE_ERROR);
        // Case 11: the host sends more than the write takes; the device
        // absorbs the rest and reports it as residue.
        let (_, residue, status) = run(
            &mut d,
            8,
            1024,
            false,
            &[WRITE_10, 0, 0, 0, 0, 1, 0, 0, 1, 0],
            &[7; 1024],
        );
        assert_eq!((residue, status), (512, PASSED));
        let mut ro = device(64, 512, true);
        let (_, _, status) = run(
            &mut ro,
            7,
            512,
            false,
            &[WRITE_10, 0, 0, 0, 0, 1, 0, 0, 1, 0],
            &[0; 512],
        );
        assert_eq!(status, FAILED);
        assert_eq!(sense(&mut ro), (7, 0x27));
    }

    #[test]
    fn an_invalid_cbw_stalls_both_pipes_until_reset_recovery() {
        let mut d = device(64, 512, false);
        let mut bad = cbw(1, 0, false, &[TEST_UNIT_READY]);
        bad[0] = 0;
        assert_eq!(d.packet(BULK_OUT, Token::Out, &mut bad), Ok(Reply::Stall));
        transfer(
            &mut d,
            setup(0x02, CLEAR_FEATURE, 0, u16::from(BULK_OUT), 0),
            &[],
        )
        .unwrap();
        let mut good = cbw(2, 0, false, &[TEST_UNIT_READY]);
        assert_eq!(d.packet(BULK_OUT, Token::Out, &mut good), Ok(Reply::Stall));
        transfer(&mut d, setup(0x21, RESET, 0, 0, 0), &[]).unwrap();
        for endpoint in [BULK_IN, BULK_OUT] {
            transfer(
                &mut d,
                setup(0x02, CLEAR_FEATURE, 0, u16::from(endpoint), 0),
                &[],
            )
            .unwrap();
        }
        let (_, _, status) = run(&mut d, 3, 0, false, &[TEST_UNIT_READY, 0, 0, 0, 0, 0], &[]);
        assert_eq!(status, PASSED);
    }
}
