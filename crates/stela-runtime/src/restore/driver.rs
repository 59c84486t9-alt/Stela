//! Nonblocking owner of one restored session. Borrow a port provider only for
//! a poll; the engine can run the guest between polls without a device borrow
//! or a host pointer in guest RAM. Protocol evidence is in `session`/`stream`.
use super::{
    Error, Result,
    answers::Answers,
    plist::Limits,
    route::Route,
    session::{Action, Job, PORT, Phase, Session},
    stream::{ByteStream, Endian, Framed},
};
use crate::payload::ReadAt;
use alloc::{boxed::Box, vec::Vec};
use core::task::Poll;

/// Handles identify owned streams, including ones still connecting. A Pending
/// open must not allocate a stream. A successful close releases the handle.
/// Zero-byte reads mean EOF, not an empty receive window.
pub trait Ports {
    type Handle: Copy + Eq;
    fn open(&mut self, port: u16) -> Poll<Result<Self::Handle>>;
    fn read(&mut self, handle: Self::Handle, bytes: &mut [u8]) -> Poll<Result<usize>>;
    fn write(&mut self, handle: Self::Handle, bytes: &[u8]) -> Poll<Result<usize>>;
    fn close(&mut self, handle: Self::Handle) -> Poll<Result<()>>;
}
struct Stream<'a, P: Ports> {
    ports: &'a mut P,
    handle: P::Handle,
}
impl<P: Ports> ByteStream for Stream<'_, P> {
    fn read(&mut self, b: &mut [u8]) -> Poll<Result<usize>> {
        self.ports.read(self.handle, b)
    }
    fn write(&mut self, b: &[u8]) -> Poll<Result<usize>> {
        self.ports.write(self.handle, b)
    }
}
struct Transfer<H> {
    job: Box<Job>,
    handle: Option<H>,
    closing: bool,
}
/// Leave capacity for the control stream and an independently owned proxy.
const DATA_STREAMS: usize = 6;
#[derive(Clone, Copy)]
enum Handshake {
    Type,
    Hardware,
    Started,
}
pub struct Driver<R, H> {
    pub answers: Answers<R>,
    pub session: Session,
    route: Route,
    control: Option<H>,
    frame: Framed,
    handshake: Handshake,
    jobs: Vec<Transfer<H>>,
    failure: Option<Error>,
    complete: bool,
}
impl<R: ReadAt, H: Copy + Eq> Driver<R, H> {
    /// The complete inventory is verified (`Store::prepare`) just before
    /// StartRestore is sent, so a session that stops earlier never pays for
    /// it. A caller that runs a guest meanwhile excludes the poll's host
    /// time from the guest's clock.
    pub fn new(answers: Answers<R>, route: Route) -> Result<Self> {
        Ok(Self {
            answers,
            session: Session::new(),
            route,
            control: None,
            frame: Framed::new(Endian::Big, Limits::default()),
            handshake: Handshake::Type,
            jobs: Vec::new(),
            failure: None,
            complete: false,
        })
    }
    /// One bounded framing operation and at most one operation per scheduled
    /// job. There is no polling loop waiting for guest execution or mux I/O.
    /// Failures are terminal and preserve the session ledger and full request.
    pub fn poll(&mut self, ports: &mut impl Ports<Handle = H>) -> Poll<Result<()>> {
        if let Some(error) = &self.failure {
            return Poll::Ready(Err(error.clone()));
        }
        if self.complete {
            return Poll::Ready(Ok(()));
        }
        let result = self.step(ports);
        if let Poll::Ready(Err(error)) = &result {
            self.failure = Some(error.clone());
        }
        result
    }
    fn step(&mut self, ports: &mut impl Ports<Handle = H>) -> Poll<Result<()>> {
        if self.control.is_none() {
            self.control = Some(match ports.open(PORT) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(v) => v?,
            });
            self.frame.queue(&self.session.query_type()?, false)?;
            return Poll::Pending;
        }
        let control = self.control.unwrap();
        if self.session.phase() == Phase::Complete {
            match ports.close(control) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(v) => v?,
            };
            self.control = None;
            self.complete = true;
            return Poll::Ready(Ok(()));
        }
        if self.frame.sending() {
            match self.frame.poll_send(&mut Stream {
                ports,
                handle: control,
            }) {
                Poll::Ready(Ok(())) => match self.session.phase() {
                    Phase::Starting => self.session.started()?,
                    Phase::FinalAck => self.session.final_ack_sent()?,
                    _ => {}
                },
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {}
            }
        }
        // Read control even while an ASR/DataPort write is backpressured.
        if !self.frame.sending()
            && self.session.phase() != Phase::Complete
            && let Poll::Ready(message) = self.frame.poll_receive(&mut Stream {
                ports,
                handle: control,
            })
        {
            match self.session.receive(message?, &mut self.answers)? {
                Action::None | Action::Event(_) => {}
                Action::Transfer(job) => self.jobs.push(Transfer {
                    job,
                    handle: None,
                    closing: false,
                }),
                Action::FinalAck(value) => self.frame.queue(&value, false)?,
            }
            if self.session.phase() == Phase::Ready {
                let message = match self.handshake {
                    Handshake::Type => {
                        self.handshake = Handshake::Hardware;
                        self.session.query_value("HardwareInfo")?
                    }
                    Handshake::Hardware => {
                        self.handshake = Handshake::Started;
                        self.answers.store.prepare()?;
                        self.session.start_for(&self.answers, self.route)?
                    }
                    Handshake::Started => {
                        return Poll::Ready(Err(Error::Invalid("unexpected ready session")));
                    }
                };
                self.frame.queue(&message, false)?;
            }
        }
        let mut active = self.jobs.iter().filter(|j| j.handle.is_some()).count();
        let mut control_used = self.frame.sending();
        let mut at = 0;
        while at < self.jobs.len() {
            let t = &mut self.jobs[at];
            let handle = if let Some(port) = t.job.port {
                if t.handle.is_none() {
                    if active == DATA_STREAMS {
                        at += 1;
                        continue;
                    }
                    match ports.open(port) {
                        Poll::Pending => {
                            at += 1;
                            continue;
                        }
                        Poll::Ready(Ok(h)) => {
                            t.handle = Some(h);
                            active += 1;
                        }
                        Poll::Ready(Err(e)) => {
                            self.session.finish_job(t.job.id, Err(e))?;
                            unreachable!()
                        }
                    }
                }
                t.handle.unwrap()
            } else {
                // Keep frames of concurrent control jobs from interleaving.
                if control_used {
                    at += 1;
                    continue;
                }
                control_used = true;
                control
            };
            if !t.closing {
                match t
                    .job
                    .poll(&mut Stream { ports, handle }, &mut self.answers.store)
                {
                    Poll::Pending => {
                        at += 1;
                        continue;
                    }
                    Poll::Ready(Err(e)) => {
                        self.session.finish_job(t.job.id, Err(e))?;
                        unreachable!()
                    }
                    Poll::Ready(Ok(())) => t.closing = true,
                }
            }
            if t.handle.is_some() {
                match ports.close(handle) {
                    Poll::Pending => {
                        at += 1;
                        continue;
                    }
                    Poll::Ready(Err(e)) => {
                        self.session.finish_job(t.job.id, Err(e))?;
                        unreachable!()
                    }
                    Poll::Ready(Ok(())) => {
                        active -= 1;
                    }
                }
            }
            self.session.finish_job(t.job.id, Ok(()))?;
            self.jobs.remove(at);
        }
        Poll::Pending
    }
    /// Close all owned streams after a terminal refusal, without emitting any
    /// further protocol bytes. Caller keeps polling while the guest advances.
    pub fn cancel(&mut self, ports: &mut impl Ports<Handle = H>) -> Poll<Result<()>> {
        // Cancellation is terminal, even while close is backpressured.
        self.failure
            .get_or_insert(Error::Invalid("restore session cancelled"));
        for t in &mut self.jobs {
            if let Some(h) = t.handle {
                match ports.close(h) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(v) => v?,
                };
                t.handle = None;
            }
        }
        if let Some(h) = self.control {
            match ports.close(h) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(v) => v?,
            };
            self.control = None;
        }
        Poll::Ready(Ok(()))
    }
    pub fn failed(&self) -> Option<&Error> {
        self.failure.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        plist,
        store::tests::fixture,
        stream::tests::{Memory, receive},
    };
    use super::*;
    use crate::restore::plist::Value;
    use alloc::{collections::BTreeMap, vec};
    struct Harness {
        streams: BTreeMap<u16, Memory>,
        opens: Vec<u16>,
        closed: Vec<u16>,
        ready: bool,
        failed_write: bool,
    }
    impl Ports for Harness {
        type Handle = u16;
        fn open(&mut self, p: u16) -> Poll<Result<u16>> {
            if !self.ready {
                return Poll::Pending;
            }
            if self.opens.contains(&p) {
                return Poll::Ready(Err(Error::Invalid("duplicate open")));
            }
            self.opens.push(p);
            Poll::Ready(Ok(p))
        }
        fn read(&mut self, h: u16, b: &mut [u8]) -> Poll<Result<usize>> {
            let s = self.streams.get_mut(&h).unwrap();
            // An open mux receive window with no data is Pending, not EOF.
            if s.at == s.input.len() {
                Poll::Pending
            } else {
                s.read(b)
            }
        }
        fn write(&mut self, h: u16, b: &[u8]) -> Poll<Result<usize>> {
            if self.failed_write {
                return Poll::Ready(Err(Error::Transport("injected write failure".into())));
            }
            self.streams.get_mut(&h).unwrap().write(b)
        }
        fn close(&mut self, h: u16) -> Poll<Result<()>> {
            assert!(!self.closed.contains(&h));
            self.closed.push(h);
            Poll::Ready(Ok(()))
        }
    }
    fn append(h: &mut Harness, v: Value) {
        let body = plist::encode_binary(&v, Limits::default()).unwrap();
        let s = h.streams.get_mut(&PORT).unwrap();
        s.input.extend((body.len() as u32).to_be_bytes());
        s.input.extend(body);
    }
    fn setup() -> (Driver<crate::payload::tests::Memory, u16>, Harness) {
        let d = Driver::new(
            Answers::new(fixture(b"payload", false)),
            Route::StelaFirmwareStudy,
        )
        .unwrap();
        let mut h = Harness {
            streams: BTreeMap::from([
                (PORT, Memory::new(vec![], 3)),
                (2345, Memory::new(vec![], 1)),
            ]),
            opens: vec![],
            closed: vec![],
            ready: false,
            failed_write: false,
        };
        append(
            &mut h,
            Value::dict([
                ("Type", Value::from("com.apple.mobile.restored")),
                ("Result", Value::from("Success")),
                ("RestoreProtocolVersion", Value::Integer(15)),
            ]),
        );
        append(
            &mut h,
            Value::dict([(
                "HardwareInfo",
                Value::dict([
                    ("ChipID", Value::Integer(0x8112)),
                    ("BoardID", Value::Integer(0x24)),
                    ("UniqueChipID", Value::Integer(1234)),
                ]),
            )]),
        );
        (d, h)
    }
    fn restoring(d: &mut Driver<crate::payload::tests::Memory, u16>, h: &mut Harness) {
        for _ in 0..100 {
            assert!(d.poll(h).is_pending());
        }
        assert!(h.opens.is_empty());
        h.ready = true;
        for _ in 0..100_000 {
            assert!(d.poll(h).is_pending());
            if d.session.phase() == Phase::Restoring {
                return;
            }
        }
        panic!("handshake did not complete");
    }
    fn request(kind: &str, port: bool) -> Value {
        let mut v = Value::dict([
            ("MsgType", Value::from("AsyncDataRequestMsg")),
            ("DataType", Value::from(kind)),
            ("Arguments", Value::dict([("ImageName", Value::from("OS"))])),
        ]);
        if let Value::Dict(m) = &mut v
            && port
        {
            m.insert("DataPort".into(), Value::Integer(2345));
        }
        v
    }
    #[test]
    fn transcript_short_io_concurrent_control_jobs_and_final_ack_write() {
        let (mut d, mut h) = setup();
        restoring(&mut d, &mut h);
        append(&mut h, request("SourceBootObjectV5", true));
        append(&mut h, request("ReceiptManifest", false));
        append(&mut h, request("FDRTrustData", false));
        append(
            &mut h,
            Value::dict([
                ("MsgType", Value::from("ProgressMsg")),
                ("Operation", Value::Integer(13)),
                ("Progress", Value::Integer(50)),
            ]),
        );
        for _ in 0..100_000 {
            assert!(d.poll(&mut h).is_pending());
            if d.session.ledger().len() == 6 && d.session.outstanding() == 0 {
                break;
            }
        }
        assert_eq!(d.session.ledger().len(), 6);
        assert_eq!(d.session.outstanding(), 0);
        assert_eq!(h.opens, vec![PORT, 2345]);
        assert_eq!(h.closed, vec![2345]);
        let s = h.streams.get_mut(&2345).unwrap();
        s.input = core::mem::take(&mut s.output);
        s.at = 0;
        let mut f = Framed::new(Endian::Big, Limits::default());
        assert_eq!(
            receive(&mut f, s)
                .unwrap()
                .required("FileData")
                .unwrap()
                .data()
                .unwrap(),
            b"payload"
        );
        assert!(
            receive(&mut f, s)
                .unwrap()
                .required("FileDataDone")
                .unwrap()
                .boolean()
                .unwrap()
        );
        append(
            &mut h,
            Value::dict([
                ("MsgType", Value::from("StatusMsg")),
                ("Status", Value::Integer(0)),
            ]),
        );
        let mut final_seen = false;
        let mut complete = false;
        for _ in 0..100_000 {
            match d.poll(&mut h) {
                Poll::Ready(v) => {
                    v.unwrap();
                    complete = true;
                    break;
                }
                Poll::Pending => {}
            }
            final_seen |= d.session.phase() == Phase::FinalAck;
        }
        assert!(final_seen && complete);
        assert_eq!(h.closed, vec![2345, PORT]);
        // Decode every control response to catch interleaved frames.
        let s = h.streams.get_mut(&PORT).unwrap();
        s.input = core::mem::take(&mut s.output);
        s.at = 0;
        let mut responses = Vec::new();
        while s.at < s.input.len() {
            responses.push(receive(&mut f, s).unwrap());
        }
        assert_eq!(responses.len(), 6);
        let opts = responses[2].required("RestoreOptions").unwrap();
        assert!(!opts.required("FlashNOR").unwrap().boolean().unwrap());
        assert!(
            opts.required("SupportedDataTypes")
                .unwrap()
                .get("NORData")
                .is_none()
        );
        assert_eq!(
            responses[5].required("MsgType").unwrap().string().unwrap(),
            "ReceivedFinalStatusMsg"
        );
    }
    #[test]
    fn blocked_data_keeps_control_live_and_limits_open_handles() {
        let (_, mut h) = setup();
        let payload = vec![42; 8192];
        let mut d = Driver::new(
            Answers::new(fixture(&payload, false)),
            Route::StelaFirmwareStudy,
        )
        .unwrap();
        restoring(&mut d, &mut h);
        for port in 2345..2352 {
            h.streams.insert(port, Memory::new(vec![], 1));
            let mut r = request("SourceBootObjectV5", false);
            if let Value::Dict(m) = &mut r {
                m.insert("DataPort".into(), Value::Integer(port as u64));
            }
            append(&mut h, r);
        }
        append(
            &mut h,
            Value::dict([
                ("MsgType", Value::from("ProgressMsg")),
                ("Operation", Value::Integer(13)),
                ("Progress", Value::Integer(50)),
            ]),
        );
        for _ in 0..100_000 {
            assert!(d.poll(&mut h).is_pending());
            if d.session.ledger().len() == 10 {
                break;
            }
        }
        assert_eq!(d.session.ledger().len(), 10);
        assert_eq!(d.session.outstanding(), 7);
        assert_eq!(h.opens.len(), DATA_STREAMS + 1);
        assert!(h.closed.is_empty());
        assert_eq!(d.cancel(&mut h), Poll::Ready(Ok(())));
        assert_eq!(h.closed.len(), DATA_STREAMS + 1);
        assert!(matches!(d.poll(&mut h), Poll::Ready(Err(_))));
    }
    #[test]
    fn refusal_retains_request_never_completes_and_cancels_once() {
        let (mut d, mut h) = setup();
        restoring(&mut d, &mut h);
        let r = request("NORData", false);
        append(&mut h, r.clone());
        let error = (0..100_000)
            .find_map(|_| match d.poll(&mut h) {
                Poll::Ready(Err(e)) => Some(e),
                _ => None,
            })
            .expect("refusal did not terminate");
        assert!(matches!(error,Error::Refused{ref request,..} if **request==r));
        let bytes = h.streams[&PORT].output.len();
        assert_eq!(d.poll(&mut h), Poll::Ready(Err(error)));
        assert_eq!(h.streams[&PORT].output.len(), bytes);
        assert_eq!(d.cancel(&mut h), Poll::Ready(Ok(())));
        assert_eq!(d.cancel(&mut h), Poll::Ready(Ok(())));
        assert_eq!(h.closed, vec![PORT]);
    }
    #[test]
    fn write_failure_is_sticky_and_no_final_ack_can_follow() {
        let (mut d, mut h) = setup();
        h.ready = true;
        assert!(d.poll(&mut h).is_pending());
        h.failed_write = true;
        assert!(matches!(
            d.poll(&mut h),
            Poll::Ready(Err(Error::Transport(_)))
        ));
        h.failed_write = false;
        assert!(matches!(d.poll(&mut h), Poll::Ready(Err(_))));
        assert!(h.streams[&PORT].output.is_empty());
        assert_ne!(d.session.phase(), Phase::Complete);
    }
}
