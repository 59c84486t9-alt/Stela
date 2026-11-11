use super::*;
use crate::boot::lan::{GATEWAY_MAC, flows::Flows, host_resolver, wire::Frame};
use smoltcp::wire::{Icmpv4Packet, Ipv4Packet as RawIpv4};
use std::{
    io::Write,
    sync::{
        Mutex,
        mpsc::{Receiver, channel},
    },
};
use stela_drivers::net::Mac;

const GUEST_MAC: Mac = Mac([0x52, 0x54, 0, 0x12, 0x34, 0x56]);
const WAIT: Duration = Duration::from_secs(5);
const LOOPBACK: Ipv4 = Ipv4::LOCALHOST;

#[derive(Clone, Default)]
struct Log(Arc<Mutex<Vec<u8>>>);
impl Write for Log {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Log {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

fn lan() -> (Lan, Receiver<Event>, Log) {
    let (events, inbox) = channel();
    let log = Log::default();
    let lan = Lan::new(events, Box::new(log.clone()), host_resolver);
    (lan, inbox, log)
}

fn guest_ip(destination: Ipv4, protocol: u8, payload: &[u8]) -> Vec<u8> {
    let packet = wire::ipv4(GUEST, destination, protocol, payload);
    wire::frame(GATEWAY_MAC, GUEST_MAC, wire::ETHERTYPE_IPV4, &packet)
}

fn guest_udp(port: u16, destination: SocketAddrV4, payload: &[u8]) -> Event {
    let datagram = wire::udp(GUEST, *destination.ip(), port, destination.port(), payload);
    Event::Frame(guest_ip(*destination.ip(), wire::PROTOCOL_UDP, &datagram))
}

fn echo_request(ident: u16, sequence: u16, data: &[u8]) -> Vec<u8> {
    let mut bytes = vec![8, 0, 0, 0];
    bytes.extend_from_slice(&ident.to_be_bytes());
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.extend_from_slice(data);
    Icmpv4Packet::new_unchecked(&mut bytes).fill_checksum();
    bytes
}

fn server() -> (UdpSocket, SocketAddrV4) {
    let socket = UdpSocket::bind((LOOPBACK, 0)).unwrap();
    socket.set_read_timeout(Some(WAIT)).unwrap();
    let SocketAddr::V4(address) = socket.local_addr().unwrap() else {
        unreachable!()
    };
    (socket, address)
}

/// Feeds the next host event to the peer and returns the frames it sends.
fn pump(lan: &mut Lan, inbox: &Receiver<Event>) -> Vec<Vec<u8>> {
    let event = inbox.recv_timeout(WAIT).expect("a host datagram");
    lan.handle(event);
    lan.take_frames()
}

/// The IPv4 packet in a frame for the guest, its header checksum verified.
fn to_guest(frame: &[u8]) -> &[u8] {
    assert_eq!(frame[..6], GUEST_MAC.0, "addressed to the guest");
    let frame = Frame::parse(frame).unwrap();
    assert_eq!(frame.ethertype, wire::ETHERTYPE_IPV4);
    frame.payload
}

#[test]
fn udp_reaches_the_host_and_replies_map_back_to_the_guest_port() {
    let (mut lan, inbox, log) = lan();
    let (first, first_address) = server();
    let (second, second_address) = server();
    lan.handle(guest_udp(40000, first_address, b"ping"));
    let mut buffer = [0u8; 64];
    let (n, host) = first.recv_from(&mut buffer).unwrap();
    assert_eq!(&buffer[..n], b"ping");
    first.send_to(b"pong", host).unwrap();
    let frames = pump(&mut lan, &inbox);
    assert_eq!(frames.len(), 1);
    let packet = wire::Ipv4Packet::parse(to_guest(&frames[0])).expect("header checksum");
    assert_eq!(
        (packet.source, packet.destination, packet.protocol),
        (LOOPBACK, GUEST, wire::PROTOCOL_UDP)
    );
    // The UDP checksum is present and right for the translated addresses.
    assert_ne!(packet.payload[6..8], [0, 0]);
    let udp = wire::Udp::parse(packet.source, packet.destination, packet.payload).unwrap();
    assert_eq!(
        (udp.source_port, udp.destination_port, udp.payload),
        (first_address.port(), 40000, &b"pong"[..])
    );

    // The same guest port reaches a second remote from the same host port,
    // and that remote's reply comes back with its own source.
    lan.handle(guest_udp(40000, second_address, b"again"));
    let (n, same_host) = second.recv_from(&mut buffer).unwrap();
    assert_eq!((&buffer[..n], same_host), (&b"again"[..], host));
    second.send_to(b"back", same_host).unwrap();
    let frames = pump(&mut lan, &inbox);
    let packet = wire::Ipv4Packet::parse(to_guest(&frames[0])).unwrap();
    let udp = wire::Udp::parse(packet.source, packet.destination, packet.payload).unwrap();
    assert_eq!(
        (udp.source_port, udp.destination_port, udp.payload),
        (second_address.port(), 40000, &b"back"[..])
    );

    // Another guest port has its own host port.
    lan.handle(guest_udp(40001, first_address, b"other"));
    let (_, other_host) = first.recv_from(&mut buffer).unwrap();
    assert_ne!(other_host.port(), host.port());
    assert_eq!(lan.flows.len(), 2);
    assert_eq!(
        (
            lan.totals.opened,
            lan.totals.udp_to_host,
            lan.totals.udp_to_guest
        ),
        (2, 3, 2)
    );
    lan.finish();
    let text = log.text();
    assert!(
        text.contains(&format!(
            "UDP 10.0.2.15:40000 -> {first_address} open via host port {}",
            host.port()
        )),
        "{text}"
    );
    assert!(
        text.contains("UDP 10.0.2.15:40000 closed: host port")
            && text.contains("to_host=2 to_guest=2"),
        "{text}"
    );
    assert!(
        text.contains("UDP totals: flows opened=2 evicted=0 expired=0 udp to_host=3 to_guest=2"),
        "{text}"
    );
}

#[test]
fn replies_larger_than_the_link_reach_the_guest_as_fragments() {
    let (mut lan, inbox, _log) = lan();
    let (remote, address) = server();
    lan.handle(guest_udp(5000, address, b"get"));
    let mut buffer = [0u8; 16];
    let (_, host) = remote.recv_from(&mut buffer).unwrap();
    let body: Vec<u8> = (0..4000u32).map(|i| (i * 7) as u8).collect();
    remote.send_to(&body, host).unwrap();
    let frames = pump(&mut lan, &inbox);
    // 8 UDP header bytes and 4000 of data in 1480-byte pieces.
    assert_eq!(frames.len(), 3);
    let mut whole = Vec::new();
    let mut ident = None;
    for (index, frame) in frames.iter().enumerate() {
        let bytes = to_guest(frame);
        let packet = RawIpv4::new_checked(bytes).unwrap();
        assert!(packet.verify_checksum());
        assert!(!packet.dont_frag());
        assert_eq!(packet.more_frags(), index < 2);
        assert_eq!(usize::from(packet.frag_offset()), index * 1480);
        assert!(usize::from(packet.total_len()) <= 1500);
        assert_eq!(*ident.get_or_insert(packet.ident()), packet.ident());
        assert!(wire::is_fragment(bytes));
        whole.extend_from_slice(packet.payload());
    }
    let udp = wire::Udp::parse(LOOPBACK, GUEST, &whole).expect("reassembled checksum");
    assert_eq!(
        (udp.source_port, udp.destination_port),
        (address.port(), 5000)
    );
    assert_eq!(udp.payload, &body[..]);
    assert_eq!(lan.totals.fragmented, 1);
}

#[test]
fn link_local_gateway_and_fragmented_datagrams_are_counted_not_forwarded() {
    let (mut lan, _inbox, log) = lan();
    let mdns = SocketAddrV4::new(Ipv4::new(224, 0, 0, 251), 5353);
    lan.handle(guest_udp(5353, mdns, b"query"));
    lan.handle(guest_udp(5353, mdns, b"query"));
    lan.handle(guest_udp(
        138,
        SocketAddrV4::new(Ipv4::new(10, 0, 2, 255), 138),
        b"x",
    ));
    lan.handle(guest_udp(123, SocketAddrV4::new(GATEWAY, 123), &[0x23; 48]));
    let datagram = wire::udp(GUEST, LOOPBACK, 7000, 7000, &[1; 64]);
    let mut packet = wire::ipv4(GUEST, LOOPBACK, wire::PROTOCOL_UDP, &datagram);
    let mut raw = RawIpv4::new_unchecked(&mut packet);
    raw.set_dont_frag(false);
    raw.set_more_frags(true);
    raw.fill_checksum();
    lan.handle(Event::Frame(wire::frame(
        GATEWAY_MAC,
        GUEST_MAC,
        wire::ETHERTYPE_IPV4,
        &packet,
    )));
    assert!(lan.take_frames().is_empty());
    assert_eq!(lan.flows.len(), 0);
    assert_eq!(
        (lan.totals.local, lan.totals.gateway, lan.totals.fragments),
        (3, 1, 1)
    );
    let text = log.text();
    assert_eq!(
        text.matches("224.0.0.251:5353 stays on the link").count(),
        1,
        "{text}"
    );
    assert!(text.contains("10.0.2.255:138 stays on the link"), "{text}");
    assert!(
        text.contains("10.0.2.2:123 dropped: the gateway serves only"),
        "{text}"
    );
    assert!(
        text.contains("IPv4 fragment to 127.0.0.1 dropped"),
        "{text}"
    );
}

#[test]
fn idle_mappings_close_and_a_full_table_evicts_the_one_idle_longest() {
    let (mut lan, inbox, log) = lan();
    lan.flows = Flows::new(2);
    let (remote, address) = server();
    let mut buffer = [0u8; 16];
    lan.handle(guest_udp(1, address, b"1"));
    lan.handle(guest_udp(2, address, b"2"));
    let (_, first_host) = remote.recv_from(&mut buffer).unwrap();
    remote.recv_from(&mut buffer).unwrap();
    // Port 1 carried traffic most recently, so port 2 gives way.
    lan.flows
        .touch(&Flow::Udp(1), Instant::now() + Duration::from_secs(1));
    lan.handle(guest_udp(3, address, b"3"));
    remote.recv_from(&mut buffer).unwrap();
    assert!(lan.flows.contains(&Flow::Udp(1)) && lan.flows.contains(&Flow::Udp(3)));
    assert!(!lan.flows.contains(&Flow::Udp(2)));
    assert_eq!(lan.totals.evicted, 1);
    assert!(
        log.text().contains("UDP 10.0.2.15:2 evicted"),
        "{}",
        log.text()
    );

    // A reply for an ended mapping is not delivered.
    lan.handle(Event::Datagram {
        flow: Flow::Udp(2),
        from: address,
        payload: b"late".to_vec(),
    });
    assert!(lan.take_frames().is_empty());

    // Port 1's mapping still maps replies back before its timeout...
    remote.send_to(b"r", first_host).unwrap();
    assert_eq!(pump(&mut lan, &inbox).len(), 1);
    let now = Instant::now();
    lan.tick(now + UDP_IDLE - Duration::from_secs(10));
    assert_eq!(lan.flows.len(), 2);
    // ...and both end once idle that long.
    lan.tick(now + UDP_IDLE + Duration::from_secs(10));
    assert_eq!(lan.flows.len(), 0);
    assert_eq!(lan.totals.expired, 2);
    let text = log.text();
    assert!(text.contains("UDP 10.0.2.15:1 idle: host port"), "{text}");
    assert!(text.contains("UDP 10.0.2.15:3 idle: host port"), "{text}");
    // The first tick a minute after the start wrote the totals; the next
    // line waits a minute more, or for the end.
    assert!(
        text.contains("UDP totals: flows opened=3 evicted=1 expired=0"),
        "{text}"
    );
    assert!(!text.contains("expired=2"), "{text}");
    lan.finish();
    assert!(
        log.text()
            .contains("UDP totals: flows opened=3 evicted=1 expired=2"),
        "{}",
        log.text()
    );
}

#[test]
fn echo_requests_are_answered_by_the_gateway_and_relayed_beyond_it() {
    let (mut lan, inbox, log) = lan();
    let request = echo_request(0x4242, 7, b"stela");
    lan.handle(Event::Frame(guest_ip(
        GATEWAY,
        wire::PROTOCOL_ICMP,
        &request,
    )));
    let frames = lan.take_frames();
    let packet = wire::Ipv4Packet::parse(to_guest(&frames[0])).unwrap();
    assert_eq!(
        (packet.source, packet.protocol),
        (GATEWAY, wire::PROTOCOL_ICMP)
    );
    let reply = Icmpv4Packet::new_checked(packet.payload).unwrap();
    assert!(reply.verify_checksum());
    assert_eq!(
        (
            reply.msg_type().into(),
            reply.echo_ident(),
            reply.echo_seq_no()
        ),
        (0u8, 0x4242, 7)
    );

    lan.handle(Event::Frame(guest_ip(
        LOOPBACK,
        wire::PROTOCOL_ICMP,
        &request,
    )));
    if ping_socket().is_err() {
        // The documented degraded response, reported once.
        lan.handle(Event::Frame(guest_ip(
            LOOPBACK,
            wire::PROTOCOL_ICMP,
            &request,
        )));
        assert_eq!(lan.totals.unsupported, 2);
        assert_eq!(log.text().matches("ICMP echo unsupported").count(), 1);
        return;
    }
    let frames = pump(&mut lan, &inbox);
    let packet = wire::Ipv4Packet::parse(to_guest(&frames[0])).unwrap();
    assert_eq!(
        (packet.source, packet.destination, packet.protocol),
        (LOOPBACK, GUEST, wire::PROTOCOL_ICMP)
    );
    let reply = Icmpv4Packet::new_checked(packet.payload).unwrap();
    assert!(reply.verify_checksum());
    assert_eq!(
        (
            reply.msg_type().into(),
            reply.echo_ident(),
            reply.echo_seq_no()
        ),
        (0u8, 0x4242, 7)
    );
    assert_eq!(reply.data(), b"stela");
    assert_eq!(
        (
            lan.totals.echo_to_host,
            lan.totals.echo_to_guest,
            lan.totals.echo_answered
        ),
        (1, 1, 1)
    );
    assert!(
        log.text()
            .contains("ICMP echo 10.0.2.15 id 16962 -> 127.0.0.1 open via host id")
    );
}
