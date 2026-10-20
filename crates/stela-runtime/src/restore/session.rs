//! Restored protocol 15 session and independently scheduled transfer jobs.
//! No fixed request ordering is assumed. A final status is successful only
//! after all jobs have completed and ReceivedFinalStatusMsg has been written.
use super::{
    Error, Result,
    answers::{Answers, Plan, Segment},
    asr,
    plist::{Limits, Value},
    route::Route,
    store::{MAX_READ_BYTES, Store},
    stream::{ByteStream, Endian, Framed, Output},
};
use crate::payload::ReadAt;
use alloc::{boxed::Box, collections::BTreeMap, format, string::String, vec::Vec};
use core::task::Poll;
pub const PORT: u16 = 62078;
pub const PROTOCOL: u64 = 15;
const MAX_JOBS: usize = 16;
const MAX_LEDGER_BYTES: usize = 16 * 1024 * 1024;
const FILE_CHUNK: usize = 8192;
/// Every message type the host understands, with the value the public host
/// sends for it (idevicerestore 4b3e847e `restore_supported_message_types`,
/// "extracted from ac2"). Restored's `is_host_compatible` compares this
/// dictionary with the messages it can send and fails the restore with
/// AMRError 10 when one it marks required is missing.
const MESSAGE_TYPES: [(&str, bool); 18] = [
    ("AsyncDataRequestMsg", true),
    ("AsyncWait", true),
    ("BBUpdateStatusMsg", false),
    ("CheckpointMsg", true),
    ("CrashLog", true),
    ("DataRequestMsg", false),
    ("FDRSubmit", true),
    ("MsgType", false),
    ("PreviousRestoreLogMsg", false),
    ("ProgressMsg", false),
    ("ProvisioningAck", false),
    ("ProvisioningInfo", false),
    ("ProvisioningStatusMsg", false),
    ("ReceivedFinalStatusMsg", false),
    ("RestoreAttestation", true),
    ("RestoreProtocol", true),
    ("RestoredCrash", true),
    ("StatusMsg", false),
];
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    New,
    QueryType,
    Ready,
    QueryValue,
    Starting,
    Restoring,
    FinalAck,
    Complete,
    Failed,
}
pub enum Action {
    None,
    Event(Value),
    Transfer(Box<Job>),
    FinalAck(Value),
}
/// A fresh per-session ledger. The owner may persist it with its input build
/// ID and source hashes; no previous session's nonces/checkpoints are reused.
pub struct Session {
    phase: Phase,
    route: Route,
    query: Option<String>,
    hardware: Option<Value>,
    ledger: Vec<Value>,
    ledger_bytes: usize,
    next_job: u64,
    outstanding: BTreeMap<u64, Value>,
}
impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}
impl Session {
    pub fn new() -> Self {
        Self {
            phase: Phase::New,
            route: Route::Stock,
            query: None,
            hardware: None,
            ledger: Vec::new(),
            ledger_bytes: 0,
            next_job: 1,
            outstanding: BTreeMap::new(),
        }
    }
    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub fn ledger(&self) -> &[Value] {
        &self.ledger
    }
    pub fn outstanding(&self) -> usize {
        self.outstanding.len()
    }
    pub fn query_type(&mut self) -> Result<Value> {
        if self.phase != Phase::New {
            return Err(Error::Invalid("QueryType phase"));
        }
        self.phase = Phase::QueryType;
        Ok(Value::dict([("Request", Value::from("QueryType"))]))
    }
    pub fn query_value(&mut self, key: &str) -> Result<Value> {
        if self.phase != Phase::Ready || key.is_empty() || key.len() > 256 {
            return Err(Error::Invalid("QueryValue phase/key"));
        }
        self.query = Some(key.into());
        self.phase = Phase::QueryValue;
        Ok(Value::dict([
            ("Request", Value::from("QueryValue")),
            ("QueryKey", Value::from(key)),
        ]))
    }
    pub fn start<R: ReadAt>(&mut self, answers: &Answers<R>) -> Result<Value> {
        self.start_for(answers, Route::Stock)
    }
    pub fn start_for<R: ReadAt>(&mut self, answers: &Answers<R>, route: Route) -> Result<Value> {
        if self.phase != Phase::Ready {
            return Err(Error::Invalid("StartRestore phase"));
        }
        if !answers.store.prepared() {
            return Err(Error::Invalid(
                "payload must be prepared before StartRestore",
            ));
        }
        let hw = self
            .hardware
            .as_ref()
            .ok_or(Error::Invalid("HardwareInfo not queried"))?;
        let identity = answers.store.identity();
        for (field, key) in [("ChipID", "ApChipID"), ("BoardID", "ApBoardID")] {
            if hw.required(field)?.uint()? != identity.number(key)? {
                return Err(super::refuse("hardware/BuildManifest mismatch", hw));
            }
        }
        hw.required("UniqueChipID")?.uint()?;
        let info = identity.info()?;
        let mut opts = BTreeMap::new();
        for key in [
            "AutoBootDelay",
            "CreateFilesystemPartitions",
            "FlashNOR",
            "FormatForAPFS",
            "InstallRecoveryOS",
            "RecoveryOSUnpack",
            "ShouldRestoreSystemImage",
        ] {
            opts.insert(
                key.into(),
                if key == "AutoBootDelay" {
                    Value::Integer(0)
                } else {
                    Value::Boolean(true)
                },
            );
        }
        opts.insert("AllowUntetheredRestore".into(), Value::Boolean(false));
        opts.insert(
            "AuthInstallRestoreBehavior".into(),
            info.required("RestoreBehavior")?.clone(),
        );
        opts.insert(
            "AuthInstallRestoreVariant".into(),
            info.required("Variant")?.clone(),
        );
        if let Some(v) = info.get("MacOSVariant") {
            opts.insert("MacOSVariant".into(), v.clone());
        }
        if let Some(v) = info.get("MinimumSystemPartition") {
            opts.insert("SystemPartitionSize".into(), v.clone());
        }
        opts.insert("SupportedDataTypes".into(), answers.supported());
        opts.insert(
            "SupportedMessageTypes".into(),
            Value::Dict(
                MESSAGE_TYPES
                    .into_iter()
                    .map(|(name, value)| (name.into(), Value::Boolean(value)))
                    .collect(),
            ),
        );
        let mut options = Value::Dict(opts);
        route.options(&mut options)?;
        self.route = route;
        self.phase = Phase::Starting;
        Ok(Value::dict([
            ("Request", Value::from("StartRestore")),
            ("RestoreProtocolVersion", Value::Integer(PROTOCOL)),
            ("RestoreOptions", options),
        ]))
    }
    /// Call only after the entire StartRestore frame has been sent.
    pub fn started(&mut self) -> Result<()> {
        if self.phase != Phase::Starting {
            return Err(Error::Invalid("StartRestore write completion phase"));
        }
        self.phase = Phase::Restoring;
        Ok(())
    }
    pub fn receive<R: ReadAt>(
        &mut self,
        message: Value,
        answers: &mut Answers<R>,
    ) -> Result<Action> {
        let result = self.receive_inner(&message, answers);
        if result.is_err() {
            self.phase = Phase::Failed;
        }
        result.map_err(|e| match e {
            Error::Refused { .. } => e,
            _ => super::refuse(format!("{e}"), &message),
        })
    }
    fn receive_inner<R: ReadAt>(&mut self, m: &Value, answers: &mut Answers<R>) -> Result<Action> {
        if matches!(
            self.phase,
            Phase::Failed | Phase::Complete | Phase::FinalAck | Phase::New | Phase::Starting
        ) {
            return Err(Error::Invalid("message out of session phase"));
        }
        let size = super::plist::encode_binary(m, Limits::default())?.len();
        if size > MAX_LEDGER_BYTES - self.ledger_bytes {
            return Err(Error::Limit("session ledger; persist before exhaustion"));
        }
        self.ledger.push(m.clone());
        self.ledger_bytes += size;
        if self.phase == Phase::QueryType {
            if m.required("Type")?.string()? != "com.apple.mobile.restored"
                || m.required("RestoreProtocolVersion")?.uint()? != PROTOCOL
                || m.required("Result")?.string()? != "Success"
            {
                return Err(Error::Invalid("unsupported restore service/protocol"));
            }
            self.phase = Phase::Ready;
            return Ok(Action::None);
        }
        if self.phase == Phase::QueryValue {
            let key = self
                .query
                .as_ref()
                .ok_or(Error::Invalid("QueryValue key absent"))?;
            let value = m.required(key)?.clone();
            if key == "HardwareInfo" {
                self.hardware = Some(value.clone());
            }
            self.query = None;
            self.phase = Phase::Ready;
            return Ok(Action::Event(value));
        }
        if self.phase != Phase::Restoring {
            return Err(Error::Invalid("unsolicited message before StartRestore"));
        }
        match m.required("MsgType")?.string()? {
            "DataRequestMsg" | "AsyncDataRequestMsg" => {
                if self.outstanding.len() == MAX_JOBS {
                    return Err(Error::Limit("outstanding restore jobs"));
                }
                let kind = m.required("DataType")?.string()?;
                if !self.route.allows(kind) {
                    return Err(super::refuse(
                        "Stela firmware option study: required request remains outside qualified global coverage",
                        m,
                    ));
                }
                let plan = if kind == "NORData" && !self.route.flashes_nor() {
                    answers.sep_firmware(m)?
                } else {
                    answers.plan(m)?
                };
                let port = m
                    .get("DataPort")
                    .map(Value::uint)
                    .transpose()?
                    .map(|n| {
                        u16::try_from(n)
                            .ok()
                            .filter(|p| *p != 0)
                            .ok_or(Error::Invalid("DataPort outside 1..=65535"))
                    })
                    .transpose()?;
                let port = if matches!(plan, Plan::Asr(_)) {
                    Some(port.unwrap_or(asr::PORT))
                } else {
                    port
                };
                if matches!(plan, Plan::Raw(_)) && port.is_none() {
                    return Err(Error::Invalid("raw Bootability transfer requires DataPort"));
                }
                let id = self.next_job;
                self.next_job = self
                    .next_job
                    .checked_add(1)
                    .ok_or(Error::Limit("job identifier"))?;
                self.outstanding.insert(id, m.clone());
                Ok(Action::Transfer(Box::new(Job::new(
                    id,
                    port,
                    m.clone(),
                    plan,
                ))))
            }
            "RestoreAttestation" => {
                if self.outstanding.len() == MAX_JOBS {
                    return Err(Error::Limit("outstanding restore jobs"));
                }
                let id = self.next_job;
                self.next_job += 1;
                self.outstanding.insert(id, m.clone());
                Ok(Action::Transfer(Box::new(Job::new(
                    id,
                    None,
                    m.clone(),
                    Plan::Reply(Value::dict([(
                        "RestoreShouldAttest",
                        Value::Boolean(false),
                    )])),
                ))))
            }
            // `Progress` is a percentage, or -1 for an operation without one,
            // such as the `OperationWeights` announcement of the progress
            // bar's weights (idevicerestore logs the operation alone).
            "ProgressMsg" => {
                m.required("Operation")?.uint()?;
                match m.required("Progress")? {
                    Value::Signed(-1) => {}
                    progress if progress.uint()? <= 100 => {}
                    _ => return Err(Error::Invalid("restore progress outside 0..=100 or -1")),
                }
                if let Some(weights) = m.get("OperationWeights") {
                    weights.required("weight_count")?.uint()?;
                    for table in ["operation_ids", "operation_weights", "operation_progresses"] {
                        let Value::Dict(entries) = weights.required(table)? else {
                            return Err(Error::Invalid(
                                "operation weight table is not a dictionary",
                            ));
                        };
                        for value in entries.values() {
                            value.uint()?;
                        }
                    }
                }
                Ok(Action::Event(m.clone()))
            }
            "CheckpointMsg" => {
                m.required("CHECKPOINT_ID")?.uint()?;
                m.required("CHECKPOINT_NAME")?.string()?;
                let result = m.required("CHECKPOINT_RESULT")?;
                if !matches!(result, Value::Integer(_) | Value::Signed(_)) {
                    return Err(Error::Invalid("checkpoint result integer"));
                }
                m.required("CHECKPOINT_COMPLETE")?.boolean()?;
                Ok(Action::Event(m.clone()))
            }
            // Reports the public host logs and the device continues past.
            "PreviousRestoreLogMsg"
            | "RestoredCrash"
            | "CrashLog"
            | "AsyncWait"
            | "FDRSubmit"
            | "RestoreProtocol" => Ok(Action::Event(m.clone())),
            // J473 has no baseband, and Stela does no factory provisioning:
            // the host understands these messages but cannot act on them.
            "BBUpdateStatusMsg" => Err(super::refuse(
                "baseband update status on a board without a baseband",
                m,
            )),
            "ProvisioningInfo" | "ProvisioningAck" | "ProvisioningStatusMsg" => Err(super::refuse(
                "factory provisioning is not provided by this host",
                m,
            )),
            "StatusMsg" => {
                // A failure may come as a negative status.
                let status = match m.required("Status")? {
                    Value::Signed(status) => *status,
                    status => i64::try_from(status.uint()?).unwrap_or(i64::MAX),
                };
                // Restored reports unconverted ramrod errors as AMRError -1.
                let failed = match m.get("AMRError") {
                    None | Some(Value::Integer(0)) => false,
                    Some(Value::Integer(_) | Value::Signed(_)) => true,
                    Some(_) => return Err(Error::Invalid("AMRError is not an integer")),
                };
                if status != 0 || failed {
                    return Err(super::refuse("device final status is failure", m));
                }
                if !self.outstanding.is_empty() {
                    return Err(Error::Invalid("final status with unfinished data jobs"));
                }
                self.phase = Phase::FinalAck;
                Ok(Action::FinalAck(Value::dict([(
                    "MsgType",
                    Value::from("ReceivedFinalStatusMsg"),
                )])))
            }
            _ => Err(super::refuse("unknown required restore message", m)),
        }
    }
    /// Transfer failures are terminal even if a later StatusMsg says zero.
    pub fn finish_job(&mut self, id: u64, result: Result<()>) -> Result<()> {
        if self.phase != Phase::Restoring {
            return Err(Error::Invalid("job completion outside restoring phase"));
        }
        let request = self
            .outstanding
            .remove(&id)
            .ok_or(Error::Invalid("unknown/already completed restore job"))?;
        if let Err(e) = result {
            self.phase = Phase::Failed;
            return Err(super::refuse(format!("job failed: {e}"), &request));
        }
        Ok(())
    }
    /// Host write completion, not a guest message. Reboot/disconnect is allowed
    /// only after the final acknowledgement has actually left the stream.
    pub fn final_ack_sent(&mut self) -> Result<()> {
        if self.phase != Phase::FinalAck {
            return Err(Error::Invalid("final acknowledgement phase"));
        }
        self.phase = Phase::Complete;
        Ok(())
    }
}
/// The scheduler owns the stream and close/reconnect policy. `port=None` uses
/// the control stream; serialize its outbound frames with all other writers.
/// DataPort jobs can run concurrently with progress/control reads.
pub struct Job {
    pub id: u64,
    pub port: Option<u16>,
    pub request: Value,
    plan: Plan,
    frame: Framed,
    raw: Output,
    index: usize,
    offset: u64,
    /// Verified member bytes read ahead for segment `window_segment`, from
    /// member offset `window_at`.
    window: Vec<u8>,
    window_at: u64,
    window_segment: Option<usize>,
    done: bool,
    failed: bool,
    reply_queued: bool,
}
impl Job {
    fn new(id: u64, port: Option<u16>, request: Value, plan: Plan) -> Self {
        Self {
            id,
            port,
            request,
            plan,
            frame: Framed::new(Endian::Big, Limits::default()),
            raw: Output::default(),
            index: 0,
            offset: 0,
            window: Vec::new(),
            window_at: 0,
            window_segment: None,
            done: false,
            failed: false,
            reply_queued: false,
        }
    }
    pub fn poll<R: ReadAt>(
        &mut self,
        s: &mut impl ByteStream,
        store: &mut Store<R>,
    ) -> Poll<Result<()>> {
        let r = self.step(s, store);
        if matches!(r, Poll::Ready(Err(_))) {
            self.failed = true;
        }
        r.map(|r| r.map_err(|e| super::refuse(format!("transfer failed: {e}"), &self.request)))
    }
    fn step<R: ReadAt>(
        &mut self,
        s: &mut impl ByteStream,
        store: &mut Store<R>,
    ) -> Poll<Result<()>> {
        if self.failed {
            return Poll::Ready(Err(Error::Invalid("restore job already failed")));
        }
        if self.done {
            return Poll::Ready(Ok(()));
        }
        if self.frame.sending() {
            return match self.frame.poll_send(s) {
                Poll::Ready(Ok(())) => Poll::Pending,
                r => r,
            };
        }
        if self.raw.is_pending() {
            return match self.raw.poll(s) {
                Poll::Ready(Ok(())) => Poll::Pending,
                r => r,
            };
        }
        match &mut self.plan {
            Plan::Reply(v) => {
                if self.reply_queued {
                    self.done = true;
                    return Poll::Ready(Ok(()));
                }
                self.frame.queue(v, true)?;
                self.reply_queued = true;
            }
            Plan::Asr(sender) => {
                let r = sender.poll(s, store);
                if matches!(r, Poll::Ready(Ok(()))) {
                    self.done = true;
                }
                return r;
            }
            Plan::File(_) | Plan::Raw(_) => {
                let raw = matches!(&self.plan, Plan::Raw(_));
                let segments = match &self.plan {
                    Plan::File(s) | Plan::Raw(s) => s,
                    _ => unreachable!(),
                };
                while self.index < segments.len() && self.offset == segments[self.index].len() {
                    self.index += 1;
                    self.offset = 0;
                }
                if self.index == segments.len() {
                    if !raw && !self.reply_queued {
                        self.frame
                            .queue(&Value::dict([("FileDataDone", Value::Boolean(true))]), true)?;
                        self.reply_queued = true;
                    } else {
                        self.done = true;
                        return Poll::Ready(Ok(()));
                    }
                } else {
                    let segment = &segments[self.index];
                    let n = (segment.len() - self.offset).min(FILE_CHUNK as u64) as usize;
                    let bytes = match segment {
                        Segment::Bytes(bytes) => {
                            bytes[self.offset as usize..self.offset as usize + n].to_vec()
                        }
                        Segment::Member {
                            path,
                            offset,
                            bytes,
                        } => {
                            // Read the member in large verified runs and frame
                            // them in FILE_CHUNK pieces: a deflated member's
                            // random read replays its inflater from the start.
                            let at = offset + self.offset;
                            let start = self.window_at;
                            if self.window_segment != Some(self.index)
                                || at < start
                                || at + n as u64 > start + self.window.len() as u64
                            {
                                let run = (bytes - self.offset).min(MAX_READ_BYTES as u64);
                                self.window = store.read_at(path, at, run as usize)?;
                                self.window_at = at;
                                self.window_segment = Some(self.index);
                            }
                            let skip = (at - self.window_at) as usize;
                            self.window[skip..skip + n].to_vec()
                        }
                    };
                    self.offset += n as u64;
                    if raw {
                        self.raw.queue(bytes, FILE_CHUNK)?;
                    } else {
                        self.frame
                            .queue(&Value::dict([("FileData", Value::Data(bytes))]), true)?;
                    }
                }
            }
        }
        Poll::Pending
    }
}
#[cfg(test)]
mod tests {
    use super::super::{
        store::tests::fixture,
        stream::tests::{Memory, receive},
    };
    use super::*;
    fn ready() -> (Session, Answers<crate::payload::tests::Memory>) {
        let mut s = Session::new();
        let mut a = Answers::new(fixture(b"payload", false));
        a.store.prepare().unwrap();
        assert_eq!(
            s.query_type()
                .unwrap()
                .required("Request")
                .unwrap()
                .string()
                .unwrap(),
            "QueryType"
        );
        s.receive(
            Value::dict([
                ("Type", Value::from("com.apple.mobile.restored")),
                ("Result", Value::from("Success")),
                ("RestoreProtocolVersion", Value::Integer(15)),
            ]),
            &mut a,
        )
        .unwrap();
        s.query_value("HardwareInfo").unwrap();
        s.receive(
            Value::dict([(
                "HardwareInfo",
                Value::dict([
                    ("ChipID", Value::Integer(0x8112)),
                    ("BoardID", Value::Integer(0x24)),
                    ("UniqueChipID", Value::Integer(1234)),
                    ("ApNonce", Value::Data(vec![1, 2, 3])),
                ]),
            )]),
            &mut a,
        )
        .unwrap();
        let start = s.start(&a).unwrap();
        assert_eq!(
            start
                .required("RestoreProtocolVersion")
                .unwrap()
                .uint()
                .unwrap(),
            15
        );
        assert!(
            start
                .required("RestoreOptions")
                .unwrap()
                .get("recoveryOSPartitionSize")
                .is_none()
        );
        s.started().unwrap();
        (s, a)
    }
    fn request(kind: &str) -> Value {
        Value::dict([
            ("MsgType", Value::from("AsyncDataRequestMsg")),
            ("DataType", Value::from(kind)),
            ("DataPort", Value::Integer(2345)),
            ("Arguments", Value::dict([])),
        ])
    }
    #[test]
    fn a_signed_amr_error_is_a_reported_failure() {
        let (mut session, mut answers) = ready();
        let status = Value::dict([
            ("MsgType", Value::from("StatusMsg")),
            ("Status", Value::Integer(0)),
            ("AMRError", Value::Signed(-1)),
        ]);
        let Err(Error::Refused { reason, .. }) = session.receive(status, &mut answers) else {
            panic!("a failed status must refuse")
        };
        assert_eq!(reason, "device final status is failure");
        let (mut session, mut answers) = ready();
        let status = Value::dict([
            ("MsgType", Value::from("StatusMsg")),
            ("Status", Value::Signed(-1)),
        ]);
        let Err(Error::Refused { reason, .. }) = session.receive(status, &mut answers) else {
            panic!("a negative status must refuse as a failure")
        };
        assert_eq!(reason, "device final status is failure");
    }
    #[test]
    fn progress_is_a_percentage_or_minus_one_with_the_operation_weights() {
        let progress = |value: Value, weights: Option<Value>| {
            let (mut session, mut answers) = ready();
            let mut message = Value::dict([
                ("MsgType", Value::from("ProgressMsg")),
                ("Operation", Value::Integer(30)),
                ("Progress", value),
            ]);
            if let (Value::Dict(fields), Some(weights)) = (&mut message, weights) {
                fields.insert("OperationWeights".into(), weights);
            }
            session.receive(message, &mut answers).is_ok()
        };
        // 26A434 restored's announcement of the progress bar's weights.
        let weights = Value::dict([
            (
                "operation_ids",
                Value::dict([("id_18", Value::Integer(18))]),
            ),
            ("operation_progresses", Value::dict([])),
            (
                "operation_weights",
                Value::dict([("id_18", Value::Integer(200))]),
            ),
            ("weight_count", Value::Integer(98)),
        ]);
        assert!(progress(Value::Signed(-1), Some(weights)));
        assert!(progress(Value::Integer(100), None));
        assert!(!progress(Value::Integer(101), None));
        assert!(!progress(Value::Signed(-2), None));
        let malformed = Value::dict([("weight_count", Value::Integer(1))]);
        assert!(!progress(Value::Signed(-1), Some(malformed)));
    }
    #[test]
    fn device_reports_continue_and_baseband_or_provisioning_messages_refuse() {
        for kind in [
            "RestoredCrash",
            "CrashLog",
            "AsyncWait",
            "FDRSubmit",
            "RestoreProtocol",
        ] {
            let (mut session, mut answers) = ready();
            let message = Value::dict([("MsgType", Value::from(kind))]);
            assert!(matches!(
                session.receive(message, &mut answers),
                Ok(Action::Event(_))
            ));
            assert_eq!(session.phase(), Phase::Restoring);
        }
        for kind in ["BBUpdateStatusMsg", "ProvisioningInfo", "ProvisioningAck"] {
            let (mut session, mut answers) = ready();
            let message = Value::dict([("MsgType", Value::from(kind))]);
            assert!(session.receive(message, &mut answers).is_err());
            assert_eq!(session.phase(), Phase::Failed);
        }
    }
    #[test]
    fn synthetic_public_protocol_transcript_keeps_control_live_and_requires_ack_write() {
        let (mut session, mut answers) = ready();
        let mut r = request("SourceBootObjectV5");
        let Value::Dict(d) = &mut r else {
            unreachable!()
        };
        d.insert(
            "Arguments".into(),
            Value::dict([("ImageName", Value::from("OS"))]),
        );
        let Action::Transfer(mut job) = session.receive(r, &mut answers).unwrap() else {
            panic!("missing job")
        };
        assert_eq!(job.port, Some(2345));
        session
            .receive(
                Value::dict([
                    ("MsgType", Value::from("ProgressMsg")),
                    ("Operation", Value::Integer(13)),
                    ("Progress", Value::Integer(50)),
                ]),
                &mut answers,
            )
            .unwrap();
        let mut stream = Memory::new(Vec::new(), 1);
        let mut complete = false;
        for _ in 0..5000 {
            if let Poll::Ready(v) = job.poll(&mut stream, &mut answers.store) {
                v.unwrap();
                complete = true;
                break;
            }
        }
        assert!(complete);
        session.finish_job(job.id, Ok(())).unwrap();
        stream.input = stream.output;
        stream.output = Vec::new();
        let mut frame = Framed::new(Endian::Big, Limits::default());
        assert_eq!(
            receive(&mut frame, &mut stream)
                .unwrap()
                .required("FileData")
                .unwrap()
                .data()
                .unwrap(),
            b"payload"
        );
        assert!(
            receive(&mut frame, &mut stream)
                .unwrap()
                .required("FileDataDone")
                .unwrap()
                .boolean()
                .unwrap()
        );
        session
            .receive(
                Value::dict([
                    ("MsgType", Value::from("CheckpointMsg")),
                    ("CHECKPOINT_ID", Value::Integer(7)),
                    ("CHECKPOINT_NAME", Value::from("test")),
                    ("CHECKPOINT_RESULT", Value::Signed(-1)),
                    ("CHECKPOINT_COMPLETE", Value::Boolean(true)),
                ]),
                &mut answers,
            )
            .unwrap();
        let Action::FinalAck(ack) = session
            .receive(
                Value::dict([
                    ("MsgType", Value::from("StatusMsg")),
                    ("Status", Value::Integer(0)),
                ]),
                &mut answers,
            )
            .unwrap()
        else {
            panic!("no final ack")
        };
        assert_eq!(
            ack.required("MsgType").unwrap().string().unwrap(),
            "ReceivedFinalStatusMsg"
        );
        assert_eq!(session.phase(), Phase::FinalAck);
        session.final_ack_sent().unwrap();
        assert_eq!(session.phase(), Phase::Complete);
        assert!(session.ledger().len() >= 6);
    }
    /// FileData frames stay FILE_CHUNK bytes while the member is read in
    /// MAX_READ_BYTES runs, across a run boundary, from a deflated member.
    #[test]
    fn a_deflated_member_streams_whole_in_file_chunks_across_read_runs() {
        let data: Vec<u8> = (0..MAX_READ_BYTES + 3 * FILE_CHUNK + 5)
            .map(|i| (i * 7 / 3) as u8)
            .collect();
        let mut answers = Answers::new(fixture(&data, true));
        answers.store.prepare().unwrap();
        let request = Value::dict([
            ("DataType", Value::from("SourceBootObjectV4")),
            ("Arguments", Value::dict([("ImageName", Value::from("OS"))])),
        ]);
        let mut job = Job::new(
            1,
            Some(2345),
            request.clone(),
            answers.plan(&request).unwrap(),
        );
        let mut stream = Memory::new(Vec::new(), 1 << 20);
        while job.poll(&mut stream, &mut answers.store).is_pending() {}
        stream.input = core::mem::take(&mut stream.output);
        let mut frame = Framed::new(Endian::Big, Limits::default());
        let mut got = Vec::new();
        loop {
            let v = receive(&mut frame, &mut stream).unwrap();
            if let Some(done) = v.get("FileDataDone") {
                assert!(done.boolean().unwrap());
                break;
            }
            let chunk = v.required("FileData").unwrap().data().unwrap();
            assert!(chunk.len() <= FILE_CHUNK);
            got.extend_from_slice(chunk);
        }
        assert_eq!(got, data);
    }
    #[test]
    fn unknown_updater_recovery_policy_and_failure_status_retain_full_context() {
        for kind in [
            "RecoveryOSLocalPolicy",
            "FirmwareUpdaterData",
            "UnknownRequiredType",
        ] {
            let (mut s, mut a) = ready();
            let mut r = request(kind);
            let Value::Dict(d) = &mut r else {
                unreachable!()
            };
            d.insert(
                "Arguments".into(),
                Value::dict([
                    ("MessageArgUpdaterName", Value::from("UnqualifiedUpdater")),
                    ("Nonce", Value::Data(vec![9])),
                ]),
            );
            let Err(Error::Refused { request, .. }) = s.receive(r.clone(), &mut a) else {
                panic!("missing refusal")
            };
            assert_eq!(*request, r);
            assert_eq!(s.phase(), Phase::Failed);
        }
        let (mut s, mut a) = ready();
        assert!(
            s.receive(
                Value::dict([
                    ("MsgType", Value::from("StatusMsg")),
                    ("Status", Value::Integer(0)),
                    ("AMRError", Value::Integer(5))
                ]),
                &mut a
            )
            .is_err()
        );
        assert!(s.final_ack_sent().is_err());
    }
    #[test]
    fn no_final_success_with_outstanding_or_failed_jobs() {
        let (mut s, mut a) = ready();
        let Action::Transfer(job) = s.receive(request("FDRTrustData"), &mut a).unwrap() else {
            panic!()
        };
        assert_eq!(s.outstanding(), 1);
        assert!(
            s.finish_job(job.id, Err(Error::Transport("lost stream".into())))
                .is_err()
        );
        assert_eq!(s.phase(), Phase::Failed);
        assert!(
            s.receive(
                Value::dict([
                    ("MsgType", Value::from("StatusMsg")),
                    ("Status", Value::Integer(0))
                ]),
                &mut a
            )
            .is_err()
        );
        let (mut s, mut a) = ready();
        s.receive(request("ReceiptManifest"), &mut a).unwrap();
        assert!(
            s.receive(
                Value::dict([
                    ("MsgType", Value::from("StatusMsg")),
                    ("Status", Value::Integer(0))
                ]),
                &mut a
            )
            .is_err()
        );
    }
}
