//! Source refusal aborts transport state; no timestamp fallback or retry.
use super::*;
#[derive(Clone, Default)]
struct FaultClock {
    inner: TestClock,
    next: Rc<Cell<Option<Result<u64, ClockError>>>>,
    sleep_error: Rc<Cell<Option<ClockError>>>,
    sleeps: Rc<Cell<usize>>,
}
impl Clock for FaultClock {
    fn now_us(&self) -> Result<u64, ClockError> {
        self.next.get().unwrap_or_else(|| self.inner.now_us())
    }
    fn sleep(&self, _: u64) -> Result<(), ClockError> {
        self.sleeps.set(self.sleeps.get() + 1);
        match self.sleep_error.get() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}
fn config() -> Config {
    Config {
        address: Ipv4Cidr::new(CLIENT_IP, 24),
        router: None,
        dns: Vec::new(),
    }
}
#[test]
fn refused_initial_clock_publishes_no_network_frame() {
    let clock = FaultClock::default();
    clock.next.set(Some(Err(ClockError::Native(
        stela_drivers::platform::work::WorkError::Closed,
    ))));
    let out = Rc::new(RefCell::new(Queue::default()));
    let link = End {
        mac: CLIENT,
        out: out.clone(),
        into: Rc::default(),
    };
    assert_eq!(
        Stack::new(link, clock, 7).err(),
        Some(NetError::Clock(ClockError::Native(
            stela_drivers::platform::work::WorkError::Closed
        )))
    );
    assert!(out.borrow().0.is_empty());
}
#[test]
fn lost_clock_aborts_partial_output_and_never_reuses_the_stack() {
    let clock = FaultClock::default();
    let link = Lan::new(100, clock.inner.clone());
    let mut stack = Stack::new(link, clock.clone(), 7).unwrap();
    stack.set_config(config()).unwrap();
    let mut transfer = stack.open_raw("10.0.2.2", 80, 1024).unwrap();
    let body = vec![0x5a; SEND_BUFFER * 2];
    let mut accepted = 0;
    for _ in 0..1000 {
        accepted = stack.write(&mut transfer, &body).unwrap();
        if accepted != 0 {
            break;
        }
    }
    assert!(accepted > 0 && accepted < body.len());
    stack.poll().unwrap();
    let frames = stack.phy.link.frames;
    assert!(frames > 0);
    let reason = ClockError::Native(stela_drivers::platform::work::WorkError::Closed);
    clock.next.set(Some(Err(reason)));
    assert_eq!(
        stack.write(&mut transfer, &body[accepted..]),
        Err(NetError::Clock(reason))
    );
    assert_eq!(
        stack.sockets.get::<tcp::Socket>(transfer.socket()).state(),
        tcp::State::Closed
    );
    let mut called = false;
    assert_eq!(
        stack.read(&mut transfer, |_, _| {
            called = true;
            Ok(true)
        }),
        Err(NetError::Clock(reason))
    );
    assert!(!called);
    clock.next.set(None);
    assert_eq!(stack.poll(), Err(NetError::Clock(reason)));
    assert_eq!(stack.wait(1000), Err(NetError::Clock(reason)));
    assert!(!NetError::Clock(reason).retryable());
    stack.close(transfer);
    assert_eq!(stack.phy.link.frames, frames);
    assert!(
        !stack
            .sockets
            .iter()
            .any(|(_, socket)| matches!(socket, smoltcp::socket::Socket::Tcp(_)))
    );
}
#[test]
fn regressed_or_out_of_range_time_is_permanently_refused() {
    for value in [0, u64::MAX] {
        let clock = FaultClock::default();
        let link = Lan::new(100, clock.inner.clone());
        let mut stack = Stack::new(link, clock.clone(), 7).unwrap();
        clock.next.set(Some(Ok(value)));
        let error = stack.poll().unwrap_err();
        assert!(matches!(
            error,
            NetError::Clock(ClockError::Regressed { .. } | ClockError::OutOfRange(_))
        ));
        clock.next.set(None);
        assert_eq!(stack.poll(), Err(error));
        assert_eq!(stack.phy.link.frames, 0);
    }
}
struct Signalling<L>(L);
impl<L: Link> Link for Signalling<L> {
    fn mac(&self) -> stela_drivers::net::Mac {
        self.0.mac()
    }
    fn transmit(&mut self, frame: &[u8]) -> Result<(), LinkError> {
        self.0.transmit(frame)
    }
    fn receive(&mut self) -> Result<Option<Vec<u8>>, LinkError> {
        self.0.receive()
    }
    fn signals(&self) -> bool {
        true
    }
}
#[test]
fn failed_sleep_preserves_the_source_cause_and_poisons_the_stack() {
    let clock = FaultClock::default();
    let link = Signalling(Lan::new(100, clock.inner.clone()));
    let mut stack = Stack::new(link, clock.clone(), 7).unwrap();
    stack.set_config(config()).unwrap();
    stack.poll().unwrap();
    let reason = ClockError::Native(stela_drivers::platform::work::WorkError::CorruptContext);
    clock.sleep_error.set(Some(reason));
    assert_eq!(stack.wait(1000), Err(NetError::Clock(reason)));
    assert_eq!(clock.sleeps.get(), 1);
    clock.sleep_error.set(None);
    assert_eq!(stack.poll(), Err(NetError::Clock(reason)));
}

struct FailDns {
    link: Lan,
    clock: FaultClock,
    queries: usize,
}
impl Link for FailDns {
    fn mac(&self) -> stela_drivers::net::Mac {
        self.link.mac()
    }
    fn transmit(&mut self, frame: &[u8]) -> Result<(), LinkError> {
        use smoltcp::wire::{EthernetFrame, Ipv4Packet, UdpPacket};
        let query = EthernetFrame::new_checked(frame)
            .ok()
            .filter(|frame| frame.ethertype() == smoltcp::wire::EthernetProtocol::Ipv4)
            .and_then(|frame| Ipv4Packet::new_checked(frame.payload()).ok())
            .filter(|ip| ip.next_header() == smoltcp::wire::IpProtocol::Udp)
            .and_then(|ip| UdpPacket::new_checked(ip.payload()).ok())
            .is_some_and(|udp| udp.dst_port() == 53);
        self.link.transmit(frame)?;
        if query {
            self.queries += 1;
            self.clock.next.set(Some(Err(ClockError::Native(
                stela_drivers::platform::work::WorkError::Closed,
            ))));
        }
        Ok(())
    }
    fn receive(&mut self) -> Result<Option<Vec<u8>>, LinkError> {
        self.link.receive()
    }
}
#[test]
fn clock_loss_during_dns_never_selects_a_stale_cached_address() {
    let clock = FaultClock::default();
    let link = FailDns {
        link: Lan::new(100, clock.inner.clone()),
        clock: clock.clone(),
        queries: 0,
    };
    let mut stack = Stack::new(link, clock.clone(), 7).unwrap();
    stack
        .set_config(Config {
            dns: vec![SERVER_IP],
            ..config()
        })
        .unwrap();
    stack
        .resolved
        .push((String::from("cdn.example"), SERVER_IP.into(), 0));
    clock.inner.0.set(RESOLVED_US + 1);
    assert_eq!(
        stack.resolve_now("cdn.example"),
        Err(NetError::Clock(ClockError::Native(
            stela_drivers::platform::work::WorkError::Closed
        )))
    );
    assert_eq!(stack.phy.link.queries, 1);
    assert_eq!(stack.resolved[0].1, SERVER_IP.into());
}

#[test]
fn uncalibrated_compatibility_clock_returns_its_cause_without_panicking() {
    let clock = stela_drivers::Clock {
        ticks_per_microsecond: 0,
    };
    let link = End {
        mac: CLIENT,
        out: Rc::default(),
        into: Rc::default(),
    };
    assert_eq!(
        Stack::new(link, clock, 7).err(),
        Some(NetError::Clock(ClockError::Calibration(
            stela_drivers::ClockError::Uncalibrated
        )))
    );
}
