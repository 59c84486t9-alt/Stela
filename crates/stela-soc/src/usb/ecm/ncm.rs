//! The adapter's Network Control Model framing (USB CDC NCM 1.0): the data
//! interface moves NCM Transfer Blocks in the 16-bit format (NTB16, 3.2.1),
//! each an NTH16 header, its datagrams and one NDP16 table naming them.
//!
//! Evidence: NCM 1.0 (the NCM functional descriptor, 5.2.1; the data
//! interface protocol 01h, 4.3; GetNtbParameters and the NTB parameter
//! structure, 6.2.1 table 6-3; Get/SetNtbFormat, 6.2.4-6.2.5;
//! Get/SetNtbInputSize, 6.2.6-6.2.7; Get/SetMaxDatagramSize, 6.2.8-6.2.9;
//! Get/SetCrcMode, 6.2.10-6.2.11; NTB delimiting by short packets, 3.2.2;
//! payload alignment, 3.3.4). J473 macOS binds `AppleUSBNCM` to interface
//! class 2 subclass 0Dh; the data interface's protocol 01h keeps the ECM
//! data driver (class 10 subclass 0) off it.
//!
//! bmNetworkCapabilities offers only SetEthernetPacketFilter (D0), which
//! the adapter answers as ECM does, as it does the multicast filters and
//! statistics its Ethernet Networking descriptor names. The maximum
//! datagram size and CRC mode requests are answered anyway, at their
//! defaults; NTB32 is not offered.
//!
//! IN: whenever the guest reads the bulk IN endpoint and frames wait, the
//! adapter packs every queued frame that fits into one block of at most
//! the negotiated input size, never waiting for more. Each datagram starts
//! where its Ethernet payload meets the advertised divisor and remainder
//! (3.3.4, as Linux `cdc_ncm` reads it); the NDP16 follows the last
//! datagram. A short packet ends the block, or a zero-length packet when it
//! fills its last packet below the input size (3.2.2).
//!
//! OUT: packets gather until a short packet or [`BLOCK_BYTES`]; the block
//! then decodes into its datagrams, each sent on as an ECM frame would be.
//! A block that does not decode is counted (`malformed`) and discarded;
//! datagrams outside the Ethernet frame sizes are counted as ECM counts
//! them.
use super::{
    CONTROL_INTERFACE, Counters, HEADER_BYTES, MAX_SEGMENT, NCM_QUEUE_FRAMES, State, Statistics,
};
use crate::usb::{
    Reply,
    control::{CLASS, Outcome, RECIPIENT_INTERFACE, Setup, Stall},
};
use alloc::{collections::VecDeque, vec::Vec};
use stela_drivers::usb::cdc::ntb;

/// The communications interface subclass (NCM 1.0, 4.2).
pub(super) const SUBCLASS: u8 = 0x0d;
/// The data interface protocol: NCM Data Class (4.3).
pub(super) const DATA_PROTOCOL: u8 = 0x01;
/// bmNetworkCapabilities: D0, SetEthernetPacketFilter.
const CAPABILITIES: u8 = 0x01;
/// The NCM functional descriptor (5.2.1): bcdNcmVersion 1.00.
pub(super) const FUNCTIONAL: [u8; 6] = [6, 0x24, 0x1a, 0x00, 0x01, CAPABILITIES];

/// dwNtbInMaxSize and dwNtbOutMaxSize: room for forty full frames, under
/// NTB16's 64 KiB.
pub const BLOCK_BYTES: usize = 60 * 1024;
/// The smallest input size a host may set for NTB16 (6.2.7).
const MIN_BLOCK: usize = 2048;
/// wNdp*Divisor, wNdp*PayloadRemainder, wNdp*Alignment.
const DIVISOR: usize = 4;
const REMAINDER: usize = 0;
const ALIGNMENT: usize = 4;
pub(super) const PARAMETER_BYTES: usize = 28;

const NTH16: &[u8; 4] = b"NCMH";
const NTH16_BYTES: usize = 12;
const NDP16: &[u8; 4] = b"NCM0";
/// An NDP16's header: signature, wLength, wNextNdpIndex.
const NDP16_HEADER: usize = 8;
/// One datagram pointer: wDatagramIndex, wDatagramLength.
const POINTER: usize = 4;

const GET_NTB_PARAMETERS: u8 = 0x80;
const GET_NTB_FORMAT: u8 = 0x83;
const SET_NTB_FORMAT: u8 = 0x84;
const GET_NTB_INPUT_SIZE: u8 = 0x85;
const SET_NTB_INPUT_SIZE: u8 = 0x86;
const GET_MAX_DATAGRAM_SIZE: u8 = 0x87;
const SET_MAX_DATAGRAM_SIZE: u8 = 0x88;
const GET_CRC_MODE: u8 = 0x89;
const SET_CRC_MODE: u8 = 0x8a;
/// GetNtbFormat's NTB16, the only format.
const NTB16_FORMAT: u16 = 0;
const CRC_NOT_APPENDED: u16 = 0;
/// Returned frame storage kept for the next OUT datagrams.
const SPARE_FRAMES: usize = 64;
/// Frames one OUT transfer queues for the host at most. The queue takes a
/// transfer only below [`NCM_QUEUE_FRAMES`], so it holds at most twice that.
/// A transfer naming more, as one naming a datagram over and over can, has
/// the rest dropped and counted, as Linux drops past its receive backlog.
const TRANSFER_FRAMES: usize = NCM_QUEUE_FRAMES;

/// The GetNtbParameters structure (6.2.1, table 6-3).
pub(super) fn parameters() -> [u8; PARAMETER_BYTES] {
    let mut b = [0u8; PARAMETER_BYTES];
    let put32 = |b: &mut [u8], at: usize, v: usize| {
        b[at..at + 4].copy_from_slice(&(v as u32).to_le_bytes());
    };
    put16(&mut b, 0, PARAMETER_BYTES);
    // bmNtbFormatsSupported: NTB16 only.
    put16(&mut b, 2, 1);
    put32(&mut b, 4, BLOCK_BYTES);
    put16(&mut b, 8, DIVISOR);
    put16(&mut b, 10, REMAINDER);
    put16(&mut b, 12, ALIGNMENT);
    put32(&mut b, 16, BLOCK_BYTES);
    put16(&mut b, 20, DIVISOR);
    put16(&mut b, 22, REMAINDER);
    put16(&mut b, 24, ALIGNMENT);
    // wNtbOutMaxDatagrams 0: no limit.
    b
}

fn put16(b: &mut [u8], at: usize, v: usize) {
    b[at..at + 2].copy_from_slice(&(v as u16).to_le_bytes());
}

/// The first offset at or after `offset` whose Ethernet payload, after the
/// 14-byte header, lands on the payload remainder modulo the divisor.
fn payload_aligned(offset: usize) -> usize {
    let payload = (offset + HEADER_BYTES) % DIVISOR;
    offset + (REMAINDER + DIVISOR - payload) % DIVISOR
}

/// The NCM state beside the adapter's ECM state.
pub(super) struct Ncm {
    /// dwNtbInMaxSize as the host set it, at most [`BLOCK_BYTES`].
    input: usize,
    /// wNtbInMaxDatagrams as the host set it; 0 is no limit.
    in_datagrams: usize,
    /// The largest datagram for the guest.
    max_datagram: usize,
    /// The next IN block's wSequence.
    sequence: u16,
    /// The IN block being sent; empty between blocks.
    block: Vec<u8>,
    /// The packed datagrams' (index, length), reused per block.
    pointers: Vec<(usize, usize)>,
    /// Frame storage the host link returned.
    spare: Vec<Vec<u8>>,
}

impl Ncm {
    pub(super) fn new() -> Self {
        Self {
            input: BLOCK_BYTES,
            in_datagrams: 0,
            max_datagram: MAX_SEGMENT,
            sequence: 0,
            block: Vec::new(),
            pointers: Vec::new(),
            spare: Vec::new(),
        }
    }

    /// The data interface's alternate setting changed: the block in flight
    /// is dropped. The negotiated parameters stay until the configuration
    /// changes: a host sets them at setting 0 before it selects setting 1,
    /// and a block larger than the size it set would overrun its transfer.
    pub(super) fn select(&mut self) {
        self.block.clear();
        self.sequence = 0;
    }

    /// A configuration change or bus reset: the reset parameters.
    pub(super) fn reset(&mut self) {
        self.select();
        self.input = BLOCK_BYTES;
        self.in_datagrams = 0;
        self.max_datagram = MAX_SEGMENT;
    }

    /// Whether an IN block is part sent.
    pub(super) fn sending(&self) -> bool {
        !self.block.is_empty()
    }

    pub(super) fn recycle(&mut self, mut frame: Vec<u8>) {
        if self.spare.len() < SPARE_FRAMES
            && frame.capacity() >= MAX_SEGMENT
            && frame.capacity() <= MAX_SEGMENT.next_power_of_two()
        {
            frame.clear();
            self.spare.push(frame);
        }
    }

    /// An NCM class request, or `None` for the requests ECM answers.
    pub(super) fn request(&mut self, setup: Setup, data: &[u8]) -> Option<Result<Outcome, Stall>> {
        if setup.kind() != CLASS
            || setup.recipient() != RECIPIENT_INTERFACE
            || setup.index != CONTROL_INTERFACE
        {
            return None;
        }
        let length = usize::from(setup.length);
        let read = setup.device_to_host();
        let word = |v: usize| -> Result<Outcome, Stall> {
            Ok(Outcome::Data((v as u16).to_le_bytes().to_vec()))
        };
        Some(match (setup.request, read) {
            (GET_NTB_PARAMETERS, true) => Ok(Outcome::Data(parameters().to_vec())),
            (GET_NTB_FORMAT, true) if length >= 2 => word(usize::from(NTB16_FORMAT)),
            (SET_NTB_FORMAT, false) if length == 0 && setup.value == NTB16_FORMAT => {
                Ok(Outcome::Done)
            }
            (GET_NTB_INPUT_SIZE, true) if length >= 4 => {
                let mut bytes = (self.input as u32).to_le_bytes().to_vec();
                if length >= 8 {
                    bytes.extend_from_slice(&(self.in_datagrams as u16).to_le_bytes());
                    bytes.extend_from_slice(&[0, 0]);
                }
                Ok(Outcome::Data(bytes))
            }
            (SET_NTB_INPUT_SIZE, false) if (length == 4 || length == 8) && data.len() == length => {
                let size = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
                if size < MIN_BLOCK {
                    return Some(Err(Stall));
                }
                // The host's size, never above the one advertised.
                self.input = size.min(BLOCK_BYTES);
                self.in_datagrams = if length == 8 {
                    usize::from(u16::from_le_bytes([data[4], data[5]]))
                } else {
                    0
                };
                Ok(Outcome::Done)
            }
            (GET_MAX_DATAGRAM_SIZE, true) if length >= 2 => word(self.max_datagram),
            (SET_MAX_DATAGRAM_SIZE, false) if length == 2 && data.len() == 2 => {
                let size = usize::from(u16::from_le_bytes([data[0], data[1]]));
                if size < HEADER_BYTES {
                    return Some(Err(Stall));
                }
                self.max_datagram = size.min(MAX_SEGMENT);
                Ok(Outcome::Done)
            }
            (GET_CRC_MODE, true) if length >= 2 => word(usize::from(CRC_NOT_APPENDED)),
            (SET_CRC_MODE, false) if length == 0 && setup.value == CRC_NOT_APPENDED => {
                Ok(Outcome::Done)
            }
            (
                GET_NTB_PARAMETERS
                | GET_NTB_FORMAT
                | SET_NTB_FORMAT
                | GET_NTB_INPUT_SIZE
                | SET_NTB_INPUT_SIZE
                | GET_MAX_DATAGRAM_SIZE
                | SET_MAX_DATAGRAM_SIZE
                | GET_CRC_MODE
                | SET_CRC_MODE,
                _,
            ) => Err(Stall),
            _ => return None,
        })
    }

    /// Packs the front of `frames` into [`Self::block`]: every frame that
    /// fits the input size and datagram limit, in order. Frames above the
    /// host's maximum datagram size are dropped and counted. Leaves the
    /// block empty when no frame remains.
    fn pack(
        &mut self,
        frames: &mut VecDeque<Vec<u8>>,
        statistics: &mut Statistics,
        counters: &mut Counters,
    ) {
        let most = match self.in_datagrams {
            0 => usize::MAX,
            n => n,
        };
        let block = &mut self.block;
        let pointers = &mut self.pointers;
        block.clear();
        block.resize(NTH16_BYTES, 0);
        pointers.clear();
        while pointers.len() < most {
            let Some(frame) = frames.front() else {
                break;
            };
            if frame.len() > self.max_datagram {
                frames.pop_front();
                counters.oversized += 1;
                statistics.receive_errors += 1;
                continue;
            }
            let start = payload_aligned(block.len());
            let table = (start + frame.len()).next_multiple_of(ALIGNMENT);
            // The table: its header, this and the earlier pointers, and
            // the zero terminator.
            let total = table + NDP16_HEADER + POINTER * (pointers.len() + 2);
            if total > self.input {
                break;
            }
            block.resize(start, 0);
            block.extend_from_slice(frame);
            statistics.received.count(frame);
            counters.to_guest += 1;
            pointers.push((start, frame.len()));
            frames.pop_front();
        }
        if pointers.is_empty() {
            block.clear();
            return;
        }
        let table = block.len().next_multiple_of(ALIGNMENT);
        let table_bytes = NDP16_HEADER + POINTER * (pointers.len() + 1);
        let total = table + table_bytes;
        block.resize(total, 0);
        block[..4].copy_from_slice(NTH16);
        put16(block, 4, NTH16_BYTES);
        put16(block, 6, usize::from(self.sequence));
        put16(block, 8, total);
        put16(block, 10, table);
        block[table..table + 4].copy_from_slice(NDP16);
        put16(block, table + 4, table_bytes);
        // wNextNdpIndex 0; the terminating pointer is already zero.
        for (n, &(index, length)) in pointers.iter().enumerate() {
            let at = table + NDP16_HEADER + POINTER * n;
            put16(block, at, index);
            put16(block, at + 2, length);
        }
        self.sequence = self.sequence.wrapping_add(1);
    }

    /// The datagrams of the OUT block `received`, queued for the host.
    /// Blocks that ran together without the zero-length packet between them
    /// decode one after another.
    fn unpack(
        &mut self,
        received: &[u8],
        outbound: &mut VecDeque<Vec<u8>>,
        statistics: &mut Statistics,
        counters: &mut Counters,
    ) {
        let mut rest = received;
        let mut queued = 0;
        loop {
            let Ok(datagrams) = ntb::decode(rest) else {
                counters.malformed += 1;
                statistics.transmit_errors += 1;
                return;
            };
            for datagram in datagrams {
                if !(HEADER_BYTES..=MAX_SEGMENT).contains(&datagram.len()) {
                    counters.oversized += 1;
                    statistics.transmit_errors += 1;
                    continue;
                }
                if queued == TRANSFER_FRAMES {
                    counters.overflowed += 1;
                    statistics.transmit_errors += 1;
                    continue;
                }
                queued += 1;
                let mut frame = self
                    .spare
                    .pop()
                    .unwrap_or_else(|| Vec::with_capacity(MAX_SEGMENT));
                frame.extend_from_slice(datagram);
                statistics.transmitted.count(&frame);
                outbound.push_back(frame);
                counters.to_host += 1;
            }
            // decode accepted the NTH16, so wBlockLength is present.
            let length = usize::from(u16::from_le_bytes([rest[8], rest[9]]));
            if length == 0 || length >= rest.len() || !rest[length..].starts_with(NTH16) {
                return;
            }
            rest = &rest[length..];
        }
    }
}

impl State {
    /// One bulk IN packet of the current block, packing a new block from
    /// the queued frames when none is in flight.
    pub(super) fn bulk_in_ncm(&mut self, packet: &mut [u8]) -> Reply {
        let State {
            ncm,
            inbound,
            sent,
            zero_length_due,
            statistics,
            counters,
            ..
        } = self;
        let Some(ncm) = ncm else {
            return Reply::Stall;
        };
        if ncm.block.is_empty() {
            ncm.pack(inbound, statistics, counters);
            *sent = 0;
            *zero_length_due = false;
            if ncm.block.is_empty() {
                return Reply::Nak;
            }
        }
        if *zero_length_due {
            *zero_length_due = false;
            ncm.block.clear();
            *sent = 0;
            return Reply::Ack(0);
        }
        let n = (ncm.block.len() - *sent).min(packet.len());
        packet[..n].copy_from_slice(&ncm.block[*sent..*sent + n]);
        *sent += n;
        if *sent == ncm.block.len() {
            // A block ending on a full packet below the input size needs a
            // ZLP to end it; one of exactly the input size ends itself.
            if n == packet.len() && ncm.block.len() < ncm.input {
                *zero_length_due = true;
            } else {
                ncm.block.clear();
                *sent = 0;
            }
        }
        Reply::Ack(n)
    }

    /// One bulk OUT packet: a short packet, a ZLP, or reaching the largest
    /// OUT block ends the block.
    pub(super) fn bulk_out_ncm(&mut self, packet: &[u8], max: usize) -> Reply {
        let State {
            ncm,
            assembling,
            discarding,
            outbound,
            statistics,
            counters,
            ..
        } = self;
        let Some(ncm) = ncm else {
            return Reply::Stall;
        };
        if !*discarding {
            if assembling.len() + packet.len() > BLOCK_BYTES {
                *discarding = true;
                assembling.clear();
            } else {
                assembling.extend_from_slice(packet);
            }
        }
        if packet.len() < max || assembling.len() == BLOCK_BYTES {
            if *discarding {
                counters.malformed += 1;
                statistics.transmit_errors += 1;
            } else if !assembling.is_empty() {
                ncm.unpack(assembling, outbound, statistics, counters);
            }
            *discarding = false;
            assembling.clear();
        }
        Reply::Ack(packet.len())
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        BULK_IN, BULK_OUT, CONNECTION_SPEED_CHANGE, Ecm, Model, NCM_QUEUE_FRAMES,
        NETWORK_CONNECTION, NOTIFY,
    };
    use super::*;
    use crate::{
        dwc3::xhci::tests::host,
        usb::{
            BusPeer, Function, Speed, Token,
            control::{
                self, DEVICE, GET_DESCRIPTOR, INTERFACE, SET_ADDRESS, SET_CONFIGURATION,
                SET_INTERFACE,
                tests::{setup, transfer},
            },
            hub::{Hub, Ports},
        },
    };
    use alloc::vec;
    use stela_drivers::net::{Link, Mac};

    const MAC: Mac = Mac([0x02, 0x53, 0x54, 0x00, 0x00, 0x01]);

    fn adapter(up: bool) -> Ecm {
        let mut e = Ecm::with_model(MAC, Model::Ncm).unwrap();
        transfer(&mut e, setup(0, SET_ADDRESS, 3, 0, 0), &[]).unwrap();
        transfer(&mut e, setup(0, SET_CONFIGURATION, 1, 0, 0), &[]).unwrap();
        if up {
            transfer(&mut e, setup(0x01, SET_INTERFACE, 1, 1, 0), &[]).unwrap();
        }
        e
    }

    fn read(e: &mut Ecm, endpoint: u8) -> Option<Vec<u8>> {
        let mut packet = [0u8; 512];
        match e.packet(endpoint, Token::In, &mut packet).unwrap() {
            Reply::Ack(n) => Some(packet[..n].to_vec()),
            Reply::Nak => None,
            Reply::Stall => panic!("STALL on {endpoint:#x}"),
        }
    }

    /// One IN transfer: packets until a short one (or a ZLP), as an xHCI
    /// TD of the input size gathers them; the packet count beside it.
    fn transfer_in(e: &mut Ecm, size: usize) -> (Vec<u8>, usize) {
        let mut bytes = Vec::new();
        let mut packets = 0;
        while let Some(packet) = read(e, BULK_IN) {
            packets += 1;
            bytes.extend_from_slice(&packet);
            if packet.len() < 512 || bytes.len() == size {
                break;
            }
        }
        (bytes, packets)
    }

    fn write(e: &mut Ecm, block: &[u8]) {
        for chunk in block.chunks(512) {
            assert_eq!(
                e.packet(BULK_OUT, Token::Out, &mut chunk.to_vec()),
                Ok(Reply::Ack(chunk.len()))
            );
        }
        if block.len().is_multiple_of(512) && block.len() < BLOCK_BYTES {
            e.packet(BULK_OUT, Token::Out, &mut []).unwrap();
        }
    }

    fn frame(destination: Mac, length: usize, fill: u8) -> Vec<u8> {
        let mut bytes = vec![fill; length];
        bytes[..6].copy_from_slice(&destination.0);
        bytes[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 9]);
        bytes
    }

    fn le16(b: &[u8], at: usize) -> usize {
        usize::from(u16::from_le_bytes([b[at], b[at + 1]]))
    }

    /// The descriptors of `config` (a configuration descriptor set).
    fn split(config: &[u8]) -> Vec<&[u8]> {
        let mut parts = Vec::new();
        let mut at = 0;
        while at < config.len() {
            let n = usize::from(config[at]);
            parts.push(&config[at..at + n]);
            at += n;
        }
        parts
    }

    #[test]
    fn descriptors_present_an_ncm_function_under_an_interface_association() {
        let mut e = adapter(false);
        let device = transfer(&mut e, setup(0x80, GET_DESCRIPTOR, 0x100, 0, 18), &[]).unwrap();
        assert_eq!(
            (device[1], device[4], device[5], device[6]),
            (DEVICE, 0xef, 2, 1)
        );
        let config = transfer(&mut e, setup(0x80, GET_DESCRIPTOR, 0x200, 0, 255), &[]).unwrap();
        assert_eq!(config[4], 2, "two interfaces");
        assert_eq!(le16(&config, 2), config.len());
        let parts = split(&config);
        assert_eq!(parts[1], &[8, 0x0b, 0, 2, 2, 0x0d, 0, 0], "IAD");
        assert_eq!(parts[2], &[9, INTERFACE, 0, 0, 1, 2, 0x0d, 0, 0]);
        assert_eq!(parts[3], &[5, 0x24, 0x00, 0x10, 0x01], "header");
        assert_eq!(parts[4], &[5, 0x24, 0x06, 0, 1], "union");
        // Ethernet Networking, as ECM: MAC string 4, 1514-byte segments.
        assert_eq!(&parts[5][..4], &[13, 0x24, 0x0f, 4]);
        assert_eq!(le16(parts[5], 8), MAX_SEGMENT);
        assert_eq!(parts[6], &[6, 0x24, 0x1a, 0x00, 0x01, CAPABILITIES], "NCM");
        assert_eq!(parts[7][..3], [7, 5, NOTIFY]);
        // Alternate 0 without endpoints, 1 with both bulk, protocol 01h.
        assert_eq!(parts[8], &[9, INTERFACE, 1, 0, 0, 10, 0, 1, 0]);
        assert_eq!(parts[9], &[9, INTERFACE, 1, 1, 2, 10, 0, 1, 0]);
        assert_eq!(parts[10], &[7, 5, BULK_IN, 2, 0, 2, 0]);
        assert_eq!(parts[11], &[7, 5, BULK_OUT, 2, 0, 2, 0]);
        assert_eq!(parts.len(), 12);
        let mac = transfer(&mut e, setup(0x80, GET_DESCRIPTOR, 0x304, 0x409, 255), &[]).unwrap();
        assert_eq!(mac, control::string("025354000001"));
        // The ECM model keeps its own descriptors.
        let mut ecm = Ecm::new(MAC).unwrap();
        let config = transfer(&mut ecm, setup(0x80, GET_DESCRIPTOR, 0x200, 0, 255), &[]).unwrap();
        assert_eq!(&config[9..18], &[9, INTERFACE, 0, 0, 1, 2, 6, 0, 0]);
        assert_eq!(ecm.model(), Model::Ecm);
        assert_eq!(e.model(), Model::Ncm);
    }

    #[test]
    fn ntb_parameters_offer_ntb16_blocks_of_sixteen_kilobytes() {
        let mut e = adapter(false);
        let bytes = transfer(&mut e, setup(0xa1, 0x80, 0, 0, 28), &[]).unwrap();
        let mut expected = [0u8; 28];
        expected[0] = 0x1c;
        expected[2] = 1;
        expected[4..8].copy_from_slice(&61440u32.to_le_bytes());
        expected[8] = 4;
        expected[12] = 4;
        expected[16..20].copy_from_slice(&61440u32.to_le_bytes());
        expected[20] = 4;
        expected[24] = 4;
        assert_eq!(bytes, expected);
        // The host driver's parser accepts them.
        let p = ntb::Parameters::parse(&bytes).unwrap();
        assert_eq!(
            (p.in_max, p.out_max, p.supports_ntb32),
            (61440, 61440, false)
        );
        // NTB16 is the format; NTB32 is refused.
        assert_eq!(
            transfer(&mut e, setup(0xa1, 0x83, 0, 0, 2), &[]).unwrap(),
            [0, 0]
        );
        transfer(&mut e, setup(0x21, 0x84, 0, 0, 0), &[]).unwrap();
        assert!(transfer(&mut e, setup(0x21, 0x84, 1, 0, 0), &[]).is_err());
        // The input size: honoured, clamped to ours, refused below 2048.
        let size = |e: &mut Ecm| transfer(e, setup(0xa1, 0x85, 0, 0, 4), &[]).unwrap();
        assert_eq!(size(&mut e), 61440u32.to_le_bytes());
        transfer(&mut e, setup(0x21, 0x86, 0, 0, 4), &4096u32.to_le_bytes()).unwrap();
        assert_eq!(size(&mut e), 4096u32.to_le_bytes());
        transfer(&mut e, setup(0x21, 0x86, 0, 0, 4), &65536u32.to_le_bytes()).unwrap();
        assert_eq!(size(&mut e), 61440u32.to_le_bytes());
        assert!(transfer(&mut e, setup(0x21, 0x86, 0, 0, 4), &1024u32.to_le_bytes()).is_err());
        let eight = [0x00, 0x20, 0, 0, 3, 0, 0, 0];
        transfer(&mut e, setup(0x21, 0x86, 0, 0, 8), &eight).unwrap();
        let long = transfer(&mut e, setup(0xa1, 0x85, 0, 0, 8), &[]).unwrap();
        assert_eq!(long, eight);
        // The size outlasts alternate settings; a new configuration
        // restores the reset size.
        transfer(&mut e, setup(0x01, SET_INTERFACE, 1, 1, 0), &[]).unwrap();
        transfer(&mut e, setup(0x01, SET_INTERFACE, 0, 1, 0), &[]).unwrap();
        assert_eq!(size(&mut e), 0x2000u32.to_le_bytes());
        transfer(&mut e, setup(0, SET_CONFIGURATION, 1, 0, 0), &[]).unwrap();
        assert_eq!(size(&mut e), 61440u32.to_le_bytes());
        // ECM's requests still answer.
        transfer(&mut e, setup(0x21, 0x43, 0x0e, 0, 0), &[]).unwrap();
        assert_eq!(
            transfer(&mut e, setup(0xa1, 0x89, 0, 0, 2), &[]).unwrap(),
            [0, 0]
        );
        assert!(transfer(&mut e, setup(0x21, 0x8a, 1, 0, 0), &[]).is_err());
        // The ECM model refuses NCM's requests.
        let mut ecm = Ecm::new(MAC).unwrap();
        transfer(&mut ecm, setup(0, SET_ADDRESS, 3, 0, 0), &[]).unwrap();
        transfer(&mut ecm, setup(0, SET_CONFIGURATION, 1, 0, 0), &[]).unwrap();
        assert!(transfer(&mut ecm, setup(0xa1, 0x80, 0, 0, 28), &[]).is_err());
    }

    #[test]
    fn selecting_the_data_setting_raises_the_link_and_notifies_it() {
        let mut e = adapter(false);
        assert!(!e.up());
        transfer(&mut e, setup(0x01, SET_INTERFACE, 1, 1, 0), &[]).unwrap();
        assert!(e.up());
        let speed = read(&mut e, NOTIFY).unwrap();
        assert_eq!(&speed[..2], &[0xa1, CONNECTION_SPEED_CHANGE]);
        let link = read(&mut e, NOTIFY).unwrap();
        assert_eq!(link, [0xa1, NETWORK_CONNECTION, 1, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn queued_frames_travel_in_one_block_that_decodes_back() {
        let mut e = adapter(true);
        assert_eq!(e.ready_at(BULK_IN), None);
        let frames = [
            frame(MAC, 60, 1),
            frame(Mac::BROADCAST, 1514, 2),
            frame(Mac([0x01, 0, 0x5e, 0, 0, 1]), 333, 3),
        ];
        for f in &frames {
            e.deliver(f);
        }
        assert_eq!(e.ready_at(BULK_IN), Some(0));
        let (block, packets) = transfer_in(&mut e, BLOCK_BYTES);
        assert_eq!(packets, block.len().div_ceil(512));
        assert_eq!(&block[..4], b"NCMH");
        assert_eq!(le16(&block, 4), 12);
        assert_eq!(le16(&block, 6), 0, "first wSequence");
        assert_eq!(le16(&block, 8), block.len());
        let table = le16(&block, 10);
        assert_eq!(table % 4, 0);
        assert_eq!(&block[table..table + 4], b"NCM0");
        assert_eq!(le16(&block, table + 4), 8 + 4 * 4);
        assert_eq!(le16(&block, table + 6), 0);
        for (n, frame) in frames.iter().enumerate() {
            let index = le16(&block, table + 8 + 4 * n);
            // Each Ethernet payload is four-byte aligned.
            assert_eq!((index + 14) % 4, 0);
            assert_eq!(le16(&block, table + 10 + 4 * n), frame.len());
            assert!(index + frame.len() <= table);
        }
        assert_eq!(&block[table + 20..table + 24], &[0; 4], "terminator");
        let decoded = ntb::decode(&block).unwrap();
        assert_eq!(
            decoded,
            frames.iter().map(Vec::as_slice).collect::<Vec<_>>()
        );
        assert_eq!(e.counters().to_guest, 3);
        assert_eq!(e.ready_at(BULK_IN), None);
        assert_eq!(read(&mut e, BULK_IN), None);
        // The next block counts on.
        e.deliver(&frames[0]);
        let (next, _) = transfer_in(&mut e, BLOCK_BYTES);
        assert_eq!(le16(&next, 6), 1);
        assert_eq!(ntb::decode(&next).unwrap(), [&frames[0][..]]);
    }

    #[test]
    fn a_block_stays_within_the_input_size_and_sends_the_rest_next() {
        let mut e = adapter(true);
        for n in 0..NCM_QUEUE_FRAMES {
            assert!(e.has_room());
            e.deliver(&frame(MAC, 1514, n as u8));
        }
        assert!(!e.has_room());
        let mut received = 0;
        let mut blocks = 0;
        while e.ready_at(BULK_IN).is_some() {
            let (block, _) = transfer_in(&mut e, BLOCK_BYTES);
            assert!(block.len() <= BLOCK_BYTES);
            let decoded = ntb::decode(&block).unwrap();
            for datagram in decoded {
                assert_eq!(datagram, frame(MAC, 1514, received as u8));
                received += 1;
            }
            blocks += 1;
        }
        assert_eq!(received, NCM_QUEUE_FRAMES);
        // Forty full frames fit in 60 KiB.
        assert_eq!(blocks, NCM_QUEUE_FRAMES.div_ceil(40));
        // A smaller input size bounds the block.
        transfer(&mut e, setup(0x01, SET_INTERFACE, 0, 1, 0), &[]).unwrap();
        transfer(&mut e, setup(0x21, 0x86, 0, 0, 4), &2048u32.to_le_bytes()).unwrap();
        transfer(&mut e, setup(0x01, SET_INTERFACE, 1, 1, 0), &[]).unwrap();
        e.deliver(&frame(MAC, 1200, 1));
        e.deliver(&frame(MAC, 1200, 2));
        let (block, _) = transfer_in(&mut e, 2048);
        assert!(block.len() <= 2048);
        assert_eq!(ntb::decode(&block).unwrap(), [&frame(MAC, 1200, 1)[..]]);
        let (block, _) = transfer_in(&mut e, 2048);
        assert_eq!(ntb::decode(&block).unwrap(), [&frame(MAC, 1200, 2)[..]]);
    }

    #[test]
    fn a_block_filling_its_last_packet_ends_with_a_zlp_below_the_input_size() {
        // The first datagram starts at 14 (its payload at 28), and the
        // table of one datagram (16 bytes) follows it: 14 + 482 + 16 = 512.
        let mut e = adapter(true);
        e.deliver(&frame(MAC, 482, 7));
        let first = read(&mut e, BULK_IN).unwrap();
        assert_eq!(first.len(), 512);
        assert_eq!(le16(&first, 8), 512);
        assert_eq!(read(&mut e, BULK_IN), Some(Vec::new()), "ZLP");
        assert_eq!(read(&mut e, BULK_IN), None);
        assert_eq!(ntb::decode(&first).unwrap(), [&frame(MAC, 482, 7)[..]]);
        // A short block needs none.
        e.deliver(&frame(MAC, 100, 7));
        assert!(read(&mut e, BULK_IN).unwrap().len() < 512);
        assert_eq!(read(&mut e, BULK_IN), None);
        // A block of exactly the input size ends itself: no ZLP.
        transfer(&mut e, setup(0x01, SET_INTERFACE, 0, 1, 0), &[]).unwrap();
        transfer(&mut e, setup(0x21, 0x86, 0, 0, 4), &2048u32.to_le_bytes()).unwrap();
        transfer(&mut e, setup(0x01, SET_INTERFACE, 1, 1, 0), &[]).unwrap();
        // Datagrams at 14 and 1014 (its payload at 1028), the second
        // ending at 2028, then a 20-byte table: 2048.
        e.deliver(&frame(MAC, 1000, 1));
        e.deliver(&frame(MAC, 1014, 2));
        let (block, packets) = transfer_in(&mut e, 2048);
        assert_eq!(block.len(), 2048);
        assert_eq!(packets, 4);
        assert_eq!(read(&mut e, BULK_IN), None, "no ZLP at the input size");
        assert_eq!(ntb::decode(&block).unwrap().len(), 2);
    }

    #[test]
    fn an_out_block_of_two_datagrams_reaches_the_host_as_two_frames() {
        let mut e = adapter(true);
        let first = frame(Mac::BROADCAST, 600, 1);
        let second = frame(MAC, 1514, 2);
        // An NTB16 as a host builds it: NDP16 right after the header.
        let mut block = vec![0u8; 12 + 16 + 4];
        let one = 32 + 2;
        block.resize(one, 0);
        block.extend_from_slice(&first);
        let two = payload_aligned(block.len());
        block.resize(two, 0);
        block.extend_from_slice(&second);
        let total = block.len();
        block[..4].copy_from_slice(b"NCMH");
        put16(&mut block, 4, 12);
        put16(&mut block, 8, total);
        put16(&mut block, 10, 12);
        block[12..16].copy_from_slice(b"NCM0");
        put16(&mut block, 16, 20);
        put16(&mut block, 20, one);
        put16(&mut block, 22, first.len());
        put16(&mut block, 24, two);
        put16(&mut block, 26, second.len());
        write(&mut e, &block);
        assert_eq!(e.take(), Some(first.clone()));
        assert_eq!(e.take(), Some(second));
        assert_eq!(e.take(), None);
        assert_eq!(e.counters().to_host, 2);
        // Garbage is counted and dropped, not sent on.
        write(&mut e, &[0x55; 700]);
        assert_eq!((e.take(), e.counters().malformed), (None, 1));
        // A pointer past the block's end refuses the block whole.
        let mut bad = block.clone();
        put16(&mut bad, 26, 4000);
        write(&mut e, &bad);
        assert_eq!((e.take(), e.counters().malformed), (None, 2));
        // A runt datagram is counted as ECM counts it; the rest go on.
        let mut runt = block.clone();
        put16(&mut runt, 22, 10);
        write(&mut e, &runt);
        assert_eq!(e.take().map(|f| f.len()), Some(1514));
        assert_eq!(e.counters().oversized, 1);
        // Returned storage carries the next datagram.
        write(&mut e, &block);
        let sent = e.take().unwrap();
        assert_eq!(e.take().map(|f| f.len()), Some(1514));
        let address = sent.as_ptr();
        e.recycle_outbound(sent);
        write(&mut e, &block);
        let reused = e.take().unwrap();
        assert_eq!(reused.as_ptr(), address);
        assert_eq!(reused, first);
    }

    #[test]
    fn out_blocks_end_at_the_largest_size_without_a_zlp_and_survive_run_together_blocks() {
        let mut e = adapter(true);
        let p = ntb::Parameters::parse(&parameters()).unwrap();
        // A block padded to exactly 16 KiB: no ZLP follows.
        let one = p.encode(0, &frame(MAC, 1514, 1)).unwrap();
        let mut padded = one.clone();
        padded.resize(BLOCK_BYTES, 0);
        put16(&mut padded, 8, BLOCK_BYTES);
        for chunk in padded.chunks(512) {
            e.packet(BULK_OUT, Token::Out, &mut chunk.to_vec()).unwrap();
        }
        assert_eq!(e.take(), Some(frame(MAC, 1514, 1)));
        // Two 512-byte blocks sent without the ZLP between them.
        let small = p.encode(1, &frame(MAC, 512 - 30, 3)).unwrap();
        assert_eq!(small.len(), 512);
        let mut joined = small.clone();
        joined.extend_from_slice(&p.encode(2, &frame(MAC, 100, 4)).unwrap());
        write(&mut e, &joined);
        assert_eq!(e.take(), Some(frame(MAC, 512 - 30, 3)));
        assert_eq!(e.take(), Some(frame(MAC, 100, 4)));
        assert_eq!(e.counters().malformed, 0);
    }

    /// One block naming a datagram a thousand times queues no more than a
    /// transfer may; the rest are counted, and the queue stays bounded.
    #[test]
    fn an_out_block_repeating_one_datagram_queues_a_bounded_number_of_frames() {
        let mut e = adapter(true);
        let datagram = frame(MAC, 60, 5);
        let pointers = 1000;
        let table = NTH16_BYTES;
        let start = payload_aligned(table + NDP16_HEADER + POINTER * (pointers + 1));
        let mut block = vec![0u8; start];
        block.extend_from_slice(&datagram);
        let total = block.len();
        block[..4].copy_from_slice(NTH16);
        put16(&mut block, 4, NTH16_BYTES);
        put16(&mut block, 8, total);
        put16(&mut block, 10, table);
        block[table..table + 4].copy_from_slice(NDP16);
        put16(
            &mut block,
            table + 4,
            NDP16_HEADER + POINTER * (pointers + 1),
        );
        for n in 0..pointers {
            let at = table + NDP16_HEADER + POINTER * n;
            put16(&mut block, at, start);
            put16(&mut block, at + 2, datagram.len());
        }
        write(&mut e, &block);
        let mut taken = 0;
        while let Some(frame) = e.take() {
            assert_eq!(frame, datagram);
            taken += 1;
        }
        assert_eq!(taken, TRANSFER_FRAMES);
        assert_eq!(e.counters().to_host, TRANSFER_FRAMES as u64);
        assert_eq!(e.counters().overflowed, (pointers - TRANSFER_FRAMES) as u64);
    }

    struct One(Ecm);
    impl Ports for One {
        fn count(&self) -> usize {
            1
        }
        fn speed(&self, _: usize) -> Speed {
            Speed::High
        }
        fn function(&mut self, _: usize) -> &mut dyn Function {
            &mut self.0
        }
        fn function_ref(&self, _: usize) -> &dyn Function {
            &self.0
        }
    }

    #[test]
    fn the_native_ncm_adapter_moves_frames_for_the_host_driver() {
        let mac = Mac([0x02, 0x53, 0x54, 0, 0, 7]);
        let hub = Hub::new(One(Ecm::with_model(mac, Model::Ncm).unwrap()), "HUB").unwrap();
        let mut bench = host::bench(hub);
        let mut found = host::run(&mut bench);
        assert!(found.failures.is_empty(), "{:?}", found.failures);
        assert_eq!(found.links.len(), 1);
        let mut link = found.links.remove(0);
        assert_eq!(link.mac(), mac);
        assert!(bench.model.borrow().function.ports.0.up());
        let mut outbound = vec![0u8; 1024];
        outbound[..6].copy_from_slice(&Mac::BROADCAST.0);
        outbound[6..12].copy_from_slice(&mac.0);
        link.transmit(&outbound).unwrap();
        assert_eq!(
            bench.model.borrow_mut().function.ports.0.take(),
            Some(outbound)
        );
        // Three frames for the host arrive in one block.
        let inbound: Vec<Vec<u8>> = (0..3u8)
            .map(|n| {
                let mut f = vec![n; 600 + usize::from(n)];
                f[..6].copy_from_slice(&mac.0);
                f
            })
            .collect();
        for f in &inbound {
            bench.model.borrow_mut().function.ports.0.deliver(f);
        }
        let mut received = Vec::new();
        for _ in 0..50 {
            if let Some(frame) = link.receive().unwrap() {
                received.push(frame);
                if received.len() == 3 {
                    break;
                }
            }
        }
        assert_eq!(received, inbound);
        assert_eq!(bench.model.borrow().function.ports.0.counters().to_guest, 3);
    }
}
