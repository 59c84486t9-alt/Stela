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
fn setup() -> (
    Driver<stela_formats::payload::test_support::Memory, u16>,
    Harness,
) {
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
fn restoring(d: &mut Driver<stela_formats::payload::test_support::Memory, u16>, h: &mut Harness) {
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
    let data = opts.required("SupportedDataTypes").unwrap();
    // The whole vocabulary is advertised; the study route refuses a
    // NORData request when it arrives.
    assert!(!data.required("NORData").unwrap().boolean().unwrap());
    assert!(!data.required("FileDataDone").unwrap().boolean().unwrap());
    let messages = opts.required("SupportedMessageTypes").unwrap();
    for name in [
        "ProvisioningInfo",
        "BBUpdateStatusMsg",
        "ReceivedFinalStatusMsg",
    ] {
        assert!(!messages.required(name).unwrap().boolean().unwrap());
    }
    // An AEA image's content key comes through an asynchronous URLAsset.
    let asynchronous = opts.required("SupportedAsyncDataTypes").unwrap();
    for name in ["RecoveryOSASRImage", "SystemImageData", "URLAsset"] {
        assert!(asynchronous.required(name).unwrap().boolean().unwrap());
    }
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
fn refusal_keeps_request_never_completes_and_cancels_once() {
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
