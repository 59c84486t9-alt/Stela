//! The peer's frames, parsed and built with smoltcp's wire module: Ethernet
//! II, ARP, IPv4 (whole datagrams in, fragmented out when larger than the
//! link MTU), UDP, ICMP echo and TCP with the MSS and window scale
//! options. Checksums are verified on parse and filled on build.
use smoltcp::{
    phy::ChecksumCapabilities,
    wire::{
        ArpOperation, ArpPacket, ArpRepr, EthernetAddress, EthernetFrame, EthernetProtocol,
        Icmpv4Message, Icmpv4Packet, IpAddress, IpProtocol, Ipv4Packet as RawIpv4, Ipv4Repr,
        TcpControl, TcpPacket, TcpRepr, TcpSeqNumber, UdpPacket, UdpRepr,
    },
};
use std::net::Ipv4Addr as Ipv4;
use stela_drivers::net::Mac;

pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const PSH: u8 = 0x08;
pub const ACK: u8 = 0x10;
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const PROTOCOL_ICMP: u8 = 1;
pub const PROTOCOL_TCP: u8 = 6;
pub const PROTOCOL_UDP: u8 = 17;
const ETHERNET_HEADER: usize = 14;
const IPV4_HEADER: usize = 20;

pub struct Frame<'a> {
    pub source: Mac,
    pub ethertype: u16,
    pub payload: &'a [u8],
}

impl<'a> Frame<'a> {
    pub fn parse(bytes: &'a [u8]) -> Option<Self> {
        let frame = EthernetFrame::new_checked(bytes).ok()?;
        Some(Self {
            source: Mac(frame.src_addr().0),
            ethertype: frame.ethertype().into(),
            payload: &bytes[ETHERNET_HEADER..],
        })
    }
}

pub fn frame(destination: Mac, source: Mac, ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; ETHERNET_HEADER + payload.len()];
    let mut frame = EthernetFrame::new_unchecked(&mut bytes);
    frame.set_dst_addr(EthernetAddress(destination.0));
    frame.set_src_addr(EthernetAddress(source.0));
    frame.set_ethertype(EthernetProtocol::from(ethertype));
    frame.payload_mut().copy_from_slice(payload);
    bytes
}

pub struct Arp {
    pub reply: bool,
    pub sender_mac: Mac,
    pub sender_ip: Ipv4,
    pub target_mac: Mac,
    pub target_ip: Ipv4,
}

impl Arp {
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let ArpRepr::EthernetIpv4 {
            operation,
            source_hardware_addr,
            source_protocol_addr,
            target_hardware_addr,
            target_protocol_addr,
        } = ArpRepr::parse(&ArpPacket::new_checked(bytes).ok()?).ok()?
        else {
            return None;
        };
        Some(Self {
            reply: operation == ArpOperation::Reply,
            sender_mac: Mac(source_hardware_addr.0),
            sender_ip: source_protocol_addr,
            target_mac: Mac(target_hardware_addr.0),
            target_ip: target_protocol_addr,
        })
    }

    pub fn emit(&self) -> Vec<u8> {
        let repr = ArpRepr::EthernetIpv4 {
            operation: match self.reply {
                true => ArpOperation::Reply,
                false => ArpOperation::Request,
            },
            source_hardware_addr: EthernetAddress(self.sender_mac.0),
            source_protocol_addr: self.sender_ip,
            target_hardware_addr: EthernetAddress(self.target_mac.0),
            target_protocol_addr: self.target_ip,
        };
        let mut bytes = vec![0; repr.buffer_len()];
        repr.emit(&mut ArpPacket::new_unchecked(&mut bytes));
        bytes
    }
}

pub struct Ipv4Packet<'a> {
    pub source: Ipv4,
    pub destination: Ipv4,
    pub protocol: u8,
    pub payload: &'a [u8],
}

impl<'a> Ipv4Packet<'a> {
    /// A whole, checksummed datagram; fragments are refused.
    pub fn parse(bytes: &'a [u8]) -> Option<Self> {
        let packet = RawIpv4::new_checked(bytes).ok()?;
        if !packet.verify_checksum() || packet.more_frags() || packet.frag_offset() != 0 {
            return None;
        }
        Some(Self {
            source: packet.src_addr(),
            destination: packet.dst_addr(),
            protocol: packet.next_header().into(),
            payload: &bytes[usize::from(packet.header_len())..usize::from(packet.total_len())],
        })
    }
}

/// Whether `bytes` is a well-formed fragment of a larger IPv4 datagram,
/// which [`Ipv4Packet::parse`] refuses.
pub fn is_fragment(bytes: &[u8]) -> bool {
    RawIpv4::new_checked(bytes).is_ok_and(|packet| packet.more_frags() || packet.frag_offset() != 0)
}

/// One datagram as the IPv4 packets a link of `mtu` bytes carries (RFC 791
/// 3.2): whole when it fits, otherwise fragments that share `ident`, each
/// payload but the last a multiple of 8 bytes, with Don't Fragment clear.
pub fn ipv4_fragments(
    source: Ipv4,
    destination: Ipv4,
    protocol: u8,
    ident: u16,
    payload: &[u8],
    mtu: usize,
) -> Vec<Vec<u8>> {
    if IPV4_HEADER + payload.len() <= mtu {
        return vec![ipv4(source, destination, protocol, payload)];
    }
    let step = (mtu - IPV4_HEADER) & !7;
    let count = payload.len().div_ceil(step);
    payload
        .chunks(step)
        .enumerate()
        .map(|(index, chunk)| {
            let mut bytes = ipv4(source, destination, protocol, chunk);
            let mut packet = RawIpv4::new_unchecked(&mut bytes);
            packet.set_ident(ident);
            packet.set_dont_frag(false);
            packet.set_more_frags(index + 1 < count);
            packet.set_frag_offset((index * step) as u16);
            packet.fill_checksum();
            bytes
        })
        .collect()
}

pub fn ipv4(source: Ipv4, destination: Ipv4, protocol: u8, payload: &[u8]) -> Vec<u8> {
    let repr = Ipv4Repr {
        src_addr: source,
        dst_addr: destination,
        next_header: IpProtocol::from(protocol),
        payload_len: payload.len(),
        hop_limit: 64,
    };
    let mut bytes = vec![0; repr.buffer_len() + payload.len()];
    let mut packet = RawIpv4::new_unchecked(&mut bytes);
    repr.emit(&mut packet, &ChecksumCapabilities::default());
    packet.payload_mut().copy_from_slice(payload);
    bytes
}

pub struct Udp<'a> {
    pub source_port: u16,
    pub destination_port: u16,
    pub payload: &'a [u8],
}

impl<'a> Udp<'a> {
    pub fn parse(source: Ipv4, destination: Ipv4, bytes: &'a [u8]) -> Option<Self> {
        let packet = UdpPacket::new_checked(bytes).ok()?;
        if !packet.verify_checksum(&IpAddress::Ipv4(source), &IpAddress::Ipv4(destination)) {
            return None;
        }
        Some(Self {
            source_port: packet.src_port(),
            destination_port: packet.dst_port(),
            payload: &bytes[8..usize::from(packet.len())],
        })
    }
}

pub fn udp(source: Ipv4, destination: Ipv4, from: u16, to: u16, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 8 + payload.len()];
    UdpRepr {
        src_port: from,
        dst_port: to,
    }
    .emit(
        &mut UdpPacket::new_unchecked(&mut bytes),
        &IpAddress::Ipv4(source),
        &IpAddress::Ipv4(destination),
        payload.len(),
        |body| body.copy_from_slice(payload),
        &ChecksumCapabilities::default(),
    );
    bytes
}

/// The identifier of a checksummed ICMP echo request (RFC 792).
pub fn echo_request(bytes: &[u8]) -> Option<u16> {
    let packet = Icmpv4Packet::new_checked(bytes).ok()?;
    (packet.verify_checksum()
        && packet.msg_type() == Icmpv4Message::EchoRequest
        && packet.msg_code() == 0)
        .then(|| packet.echo_ident())
}

/// The ICMP type and code of `bytes`, for logging what is not forwarded.
pub fn icmp_kind(bytes: &[u8]) -> Option<(u8, u8)> {
    Some((*bytes.first()?, *bytes.get(1)?))
}

/// Turns `bytes`, an echo reply from a host ping socket (whose kernel has
/// checked its checksum), into one for `ident` with its checksum refilled;
/// `false` leaves anything else untouched.
pub fn echo_reply_for(bytes: &mut [u8], ident: u16) -> bool {
    let Ok(mut packet) = Icmpv4Packet::new_checked(&mut *bytes) else {
        return false;
    };
    if packet.msg_type() != Icmpv4Message::EchoReply || packet.msg_code() != 0 {
        return false;
    }
    packet.set_echo_ident(ident);
    packet.fill_checksum();
    true
}

/// The reply to `request`, an echo request [`echo_request`] accepted: the
/// same identifier, sequence number and data.
pub fn echo_answer(request: &[u8]) -> Vec<u8> {
    let mut bytes = request.to_vec();
    let mut packet = Icmpv4Packet::new_unchecked(&mut bytes);
    packet.set_msg_type(Icmpv4Message::EchoReply);
    packet.fill_checksum();
    bytes
}

/// A received TCP segment, its flags as the header's bits.
pub struct Segment<'a> {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence: u32,
    pub acknowledgment: u32,
    pub flags: u8,
    pub window: u16,
    /// The MSS and window scale options, on a SYN.
    pub mss: Option<u16>,
    pub scale: Option<u8>,
    pub payload: &'a [u8],
}

impl<'a> Segment<'a> {
    pub fn parse(source: Ipv4, destination: Ipv4, bytes: &'a [u8]) -> Option<Self> {
        let (source, destination) = (IpAddress::Ipv4(source), IpAddress::Ipv4(destination));
        let packet = TcpPacket::new_checked(bytes).ok()?;
        if !packet.verify_checksum(&source, &destination) {
            return None;
        }
        let repr = TcpRepr::parse(
            &packet,
            &source,
            &destination,
            &ChecksumCapabilities::default(),
        )
        .ok()?;
        let flags = [
            (packet.fin(), FIN),
            (packet.syn(), SYN),
            (packet.rst(), RST),
            (packet.psh(), PSH),
            (packet.ack(), ACK),
        ]
        .iter()
        .filter(|(set, _)| *set)
        .fold(0, |flags, (_, bit)| flags | bit);
        Some(Self {
            source_port: packet.src_port(),
            destination_port: packet.dst_port(),
            sequence: packet.seq_number().0 as u32,
            acknowledgment: packet.ack_number().0 as u32,
            flags,
            window: packet.window_len(),
            mss: repr.max_seg_size,
            scale: repr.window_scale,
            payload: &bytes[usize::from(packet.header_len())..],
        })
    }
}

/// The fields of one outgoing TCP segment. One of SYN, FIN, RST and PSH
/// at most, with or without ACK.
pub struct Outgoing<'a> {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence: u32,
    pub acknowledgment: u32,
    pub flags: u8,
    pub window: u16,
    pub mss: Option<u16>,
    pub scale: Option<u8>,
    pub payload: &'a [u8],
}

pub fn tcp(source: Ipv4, destination: Ipv4, segment: &Outgoing<'_>) -> Vec<u8> {
    let control = match segment.flags & !ACK {
        SYN => TcpControl::Syn,
        FIN => TcpControl::Fin,
        RST => TcpControl::Rst,
        PSH => TcpControl::Psh,
        _ => TcpControl::None,
    };
    let repr = TcpRepr {
        src_port: segment.source_port,
        dst_port: segment.destination_port,
        control,
        seq_number: TcpSeqNumber(segment.sequence as i32),
        ack_number: (segment.flags & ACK != 0)
            .then_some(TcpSeqNumber(segment.acknowledgment as i32)),
        window_len: segment.window,
        window_scale: segment.scale,
        max_seg_size: segment.mss,
        sack_permitted: false,
        sack_ranges: [None; 3],
        timestamp: None,
        payload: segment.payload,
    };
    let mut bytes = vec![0; repr.buffer_len()];
    repr.emit(
        &mut TcpPacket::new_unchecked(&mut bytes),
        &IpAddress::Ipv4(source),
        &IpAddress::Ipv4(destination),
        &ChecksumCapabilities::default(),
    );
    bytes
}
