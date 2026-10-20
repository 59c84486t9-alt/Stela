//! `cargo xtask restore-dry-run`: the whole restore host against the real
//! IPSW, natively and without QEMU. It opens the IPSW through the same
//! `Extent`/`Store`/`Answers`/`Driver` path `stela.efi` uses, plays
//! restored's side of the mux (`wire`), and sends every request of the
//! matrix (`requests`) in protocol order. Each answer is checked against
//! the input as Image4 and restored read it, decoded independently of the
//! host (`context`, `image4`): whole-IM4P SHA-384 against the BuildManifest
//! digest, the type the digest covers, and the global ticket's binding. A
//! refusal passes only when no valid answer exists in the IPSW. A request
//! that refuses ends its session, as in `stela.efi`; the next one opens a
//! fresh session over the same verified store. The install mode runs
//! Apple's stock options, as `stela.efi --install`; the study the firmware
//! option study's. Signing-service requests get a synthetic, unsigned
//! ticket; nothing touches the network.
//!
//! The matrix and its evidence are in `docs/research/restore-dry-run.md`.
use anyhow::{Context, Result, anyhow, bail, ensure};
use plist::{Dictionary, Value};
use std::{
    collections::BTreeSet,
    fs::File,
    io::Cursor,
    os::unix::fs::FileExt,
    path::PathBuf,
    process::ExitCode,
    task::Poll,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use stela_runtime::{
    payload::{PayloadManifest, ReadAt},
    restore::{
        Error,
        answers::Answers,
        driver::Driver,
        route::Route,
        source::Extent,
        store::{Store, Verify},
        tss::Signer,
    },
};

mod context;
mod cpio;
mod image4;
mod requests;
mod tss;
mod wire;

use context::Ctx;
use requests::{Outcome, Step, Transfer, Verdict};
use wire::{CONTROL, Wire};

/// The device the dry run plays; no real machine's identifier.
const ECID: u64 = 0x0001_2345_6789_abcd;
/// ASR payload read without `--full`.
const ASR_PREFIX: u64 = 16 << 20;
/// A request slower than this natively stalls the guest for far longer under
/// QEMU; it is reported, though it does not fail the run.
const SLOW_SECS: f64 = 20.0;
/// Polls without a byte moving before the host counts as stalled.
const STALL_POLLS: u32 = 400_000;

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum Mode {
    /// `stela.efi --install`: Apple's stock options and the signing
    /// service, here a synthetic one.
    Install,
    /// `stela.efi --restore-study`: the firmware option study's route.
    Study,
}

#[derive(clap::Args)]
pub struct RestoreDryRun {
    /// The restore IPSW.
    #[arg(
        long,
        default_value = ".stela/images/UniversalMac_27.0.1_26A434_Restore.ipsw"
    )]
    ipsw: PathBuf,
    /// The payload inventory (`stela image-manifest --payload-manifest`);
    /// the block hashes it names are read from beside it.
    #[arg(long, default_value = ".stela/restore-study/payload.json")]
    payload: PathBuf,
    /// BuildManifest index of the erase identity; default: the inventory's
    /// only erase identity.
    #[arg(long)]
    identity: Option<usize>,
    #[arg(long, value_enum, default_value = "install")]
    mode: Mode,
    /// In the study, also answer signing-service requests from the
    /// synthetic ticket, as `--tss` does (the install always does).
    #[arg(long)]
    tss: bool,
    /// Check recorded hashes only on the blocks each request reads, as
    /// `--verify-on-read` does, instead of every member before StartRestore.
    #[arg(long)]
    verify_on_read: bool,
    /// Stream whole ASR images and large boot objects.
    #[arg(long)]
    full: bool,
    /// Run only steps whose label contains one of these comma-separated
    /// texts (the handshake always runs).
    #[arg(long)]
    only: Option<String>,
    /// Seed of the fragmentation and backpressure generator.
    #[arg(long, default_value_t = 0x5eed)]
    seed: u64,
}

struct ArchiveFile(File, u64);
impl ReadAt for ArchiveFile {
    type Error = std::io::Error;
    fn len(&self) -> u64 {
        self.1
    }
    fn read_at(&mut self, offset: u64, b: &mut [u8]) -> std::io::Result<()> {
        self.0.read_exact_at(b, offset)
    }
}
type Reader = Extent<ArchiveFile>;

fn reason(e: &Error) -> String {
    match e {
        Error::Refused { reason, .. } => reason.clone(),
        e => format!("{e}"),
    }
}

fn s(v: &str) -> Value {
    Value::String(v.into())
}

struct Runner {
    route: Route,
    seed: u64,
    answers: Option<Answers<Reader>>,
    driver: Option<Driver<Reader, u32>>,
    wire: Wire,
    complete: bool,
    sessions: usize,
    next_port: u16,
    hardware: Dictionary,
    model: String,
}

impl Runner {
    fn end_session(&mut self) {
        if let Some(d) = self.driver.take() {
            self.answers = Some(d.answers);
        }
    }
    /// Poll the host and the guest until `until` yields, the host refuses,
    /// or nothing moves.
    fn pump<T>(
        &mut self,
        mut until: impl FnMut(&mut Wire, bool) -> Result<Option<T>>,
    ) -> Result<std::result::Result<T, String>> {
        let driver = self.driver.as_mut().context("no session")?;
        let mut idle = 0;
        let mut last = self.wire.moved;
        loop {
            match driver.poll(&mut self.wire) {
                Poll::Ready(Err(e)) => return Ok(Err(reason(&e))),
                Poll::Ready(Ok(())) => self.complete = true,
                Poll::Pending => {}
            }
            if let Some(t) = until(&mut self.wire, self.complete)? {
                return Ok(Ok(t));
            }
            if self.wire.moved == last {
                idle += 1;
                ensure!(
                    idle < STALL_POLLS,
                    "the host stalled: no bytes moved in {STALL_POLLS} polls"
                );
            } else {
                idle = 0;
                last = self.wire.moved;
            }
        }
    }
    fn control(&mut self) -> Result<std::result::Result<Value, String>> {
        self.pump(|w, _| w.frame(CONTROL))
    }
    /// QueryType, HardwareInfo and StartRestore; returns StartRestore.
    fn open(&mut self) -> Result<Value> {
        let answers = self.answers.take().context("answers lost")?;
        self.driver = Some(Driver::new(answers, self.route).map_err(|e| anyhow!("{e}"))?);
        self.wire = Wire::new(self.seed.wrapping_add(self.sessions as u64 * 0x9e37));
        self.complete = false;
        self.sessions += 1;
        let q = self
            .control()?
            .map_err(|r| anyhow!("refused before QueryType: {r}"))?;
        ensure!(
            q.as_dictionary().and_then(|d| d.get("Request")) == Some(&s("QueryType")),
            "first host frame is not QueryType: {q:?}"
        );
        let reply = requests::dict([
            ("Type", s("com.apple.mobile.restored")),
            ("RestoreProtocolVersion", Value::Integer(15.into())),
            ("Result", s("Success")),
            ("HardwareModel", s(&self.model)),
            ("SerialNumber", s("")),
            ("SupportsBootedOSUSB", Value::Boolean(true)),
        ]);
        self.wire.send_frame(CONTROL, &reply.into())?;
        let q = self
            .control()?
            .map_err(|r| anyhow!("QueryType reply refused: {r}"))?;
        let d = q.as_dictionary().context("QueryValue")?;
        ensure!(
            d.get("Request") == Some(&s("QueryValue"))
                && d.get("QueryKey") == Some(&s("HardwareInfo")),
            "second host frame is not QueryValue HardwareInfo: {q:?}"
        );
        let reply = requests::dict([("HardwareInfo", Value::Dictionary(self.hardware.clone()))]);
        self.wire.send_frame(CONTROL, &reply.into())?;
        let start = self
            .control()?
            .map_err(|r| anyhow!("HardwareInfo refused: {r}"))?;
        ensure!(
            start.as_dictionary().and_then(|d| d.get("Request")) == Some(&s("StartRestore")),
            "third host frame is not StartRestore"
        );
        Ok(start)
    }
    fn port(&mut self) -> u16 {
        self.next_port = if self.next_port >= 60000 {
            20000
        } else {
            self.next_port + 1
        };
        self.next_port
    }
    fn run(&mut self, ctx: &mut Ctx, step: &Step) -> Result<Outcome> {
        if step.message.is_empty() {
            return Ok(Outcome::Event);
        }
        if self.driver.is_none() {
            self.open()?;
        }
        let mut message = step.message.clone();
        let port = match step.transfer {
            Transfer::File | Transfer::Raw | Transfer::Asr => {
                let p = self.port();
                self.wire.listen(p);
                message.insert("DataPort".into(), Value::Integer(p.into()));
                Some(p)
            }
            _ => None,
        };
        self.wire.send_frame(CONTROL, &message.into())?;
        let outcome = match step.transfer {
            Transfer::Control => match self.control()? {
                Ok(v) => Outcome::Reply(v),
                Err(r) => Outcome::Refused(r),
            },
            Transfer::Event => {
                let mut polls = 0;
                match self.pump(|w, _| {
                    polls += 1;
                    if let Some(f) = w.frame(CONTROL)? {
                        bail!("the host replied to an event: {f:?}");
                    }
                    Ok((polls > 2000).then_some(()))
                })? {
                    Ok(()) => Outcome::Event,
                    Err(r) => Outcome::Refused(r),
                }
            }
            Transfer::Final => {
                let mut ack = None;
                match self.pump(|w, complete| {
                    if ack.is_none() {
                        ack = w.frame(CONTROL)?;
                    }
                    Ok(if complete { ack.take() } else { None })
                })? {
                    Ok(v) => {
                        self.end_session();
                        Outcome::Reply(v)
                    }
                    Err(r) => Outcome::Refused(r),
                }
            }
            Transfer::File => {
                let p = port.unwrap();
                let mut bytes = Vec::new();
                match self.pump(|w, _| {
                    while let Some(f) = w.frame(p)? {
                        let d = f.as_dictionary().context("FileData frame")?;
                        if let Some(b) = d.get("FileData") {
                            bytes.extend_from_slice(b.as_data().context("FileData is not data")?);
                        } else if d.get("FileDataDone") == Some(&Value::Boolean(true)) {
                            return Ok(Some(std::mem::take(&mut bytes)));
                        } else {
                            bail!("unexpected DataPort frame {f:?}");
                        }
                    }
                    Ok(None)
                })? {
                    Ok(b) => {
                        // The job ends when the host closes the DataPort.
                        self.pump(|w, _| Ok(w.socket(p).filter(|s| s.host_closed).map(|_| ())))?
                            .map_err(|r| anyhow!("refused after FileDataDone: {r}"))?;
                        Outcome::Bytes(b)
                    }
                    Err(r) => Outcome::Refused(r),
                }
            }
            Transfer::Raw => {
                let p = port.unwrap();
                let mut bytes = Vec::new();
                match self.pump(|w, _| {
                    let chunk = w.take(p, usize::MAX);
                    bytes.extend(chunk);
                    Ok(w.socket(p)
                        .filter(|s| s.host_closed && s.read == s.from_host.len())
                        .map(|_| ()))
                })? {
                    Ok(()) => Outcome::Bytes(bytes),
                    Err(r) => Outcome::Refused(r),
                }
            }
            Transfer::Asr => self.asr(ctx, port.unwrap())?,
        };
        if matches!(outcome, Outcome::Refused(_)) {
            self.end_session();
        }
        Ok(outcome)
    }
    /// restored's ASR client: Initiate, two OOB reads, then the payload.
    fn asr(&mut self, ctx: &mut Ctx, p: u16) -> Result<Outcome> {
        match self.pump(|w, _| Ok(w.socket(p).map(|_| ())))? {
            Ok(()) => {}
            Err(r) => return Ok(Outcome::Refused(r)),
        }
        let xml = |v: Dictionary| -> Result<Vec<u8>> {
            let mut b = Vec::new();
            Value::Dictionary(v).to_writer_xml(&mut b)?;
            Ok(b)
        };
        let initiate = requests::dict([
            ("Command", s("Initiate")),
            ("Checksum Chunks", Value::Boolean(true)),
        ]);
        self.wire.send(p, &xml(initiate)?);
        let mut text = Vec::new();
        let header = match self.pump(|w, _| {
            // The document ends with its line break, before any OOB bytes.
            text.extend(w.take(p, 1));
            Ok(text.ends_with(b"</plist>\n").then(|| text.clone()))
        })? {
            Ok(b) => Value::from_reader(Cursor::new(b)).context("ASR Initiate response")?,
            Err(r) => return Ok(Outcome::Refused(r)),
        };
        let h = header.as_dictionary().context("ASR response")?;
        let uint = |d: &Dictionary, k: &str| d.get(k).and_then(Value::as_unsigned_integer);
        let size = h
            .get("Payload")
            .and_then(Value::as_dictionary)
            .and_then(|d| uint(d, "Size"))
            .context("ASR Payload Size")?;
        for (k, v) in [
            ("Version", 1),
            ("Stream ID", 1),
            ("Packet Payload Size", 1450),
            ("FEC Slice Stride", 40),
            ("Packets Per FEC", 25),
            ("Checksum Chunk Size", 128 * 1024),
        ] {
            ensure!(
                uint(h, k) == Some(v),
                "ASR {k} is {:?}, expected {v}",
                uint(h, k)
            );
        }
        let image = ["OS", "BaseSystem"]
            .into_iter()
            .filter_map(|c| ctx.path(c, false).map(|p| (c, p)))
            .find(|(_, path)| ctx.member_size(path) == Some(size))
            .ok_or_else(|| anyhow!("ASR size {size} matches no OS or BaseSystem member"))?;
        let path = image.1.clone();
        let mut checked = 0;
        for (offset, len) in [(0u64, 4096u64), (size - 8192, 8192)] {
            let oob = requests::dict([
                ("Command", s("OOBData")),
                ("OOB Offset", Value::Integer(offset.into())),
                ("OOB Length", Value::Integer(len.into())),
            ]);
            self.wire.send(p, &xml(oob)?);
            let mut got = Vec::new();
            match self.pump(|w, _| {
                got.extend(w.take(p, len as usize - got.len()));
                Ok((got.len() == len as usize).then(|| std::mem::take(&mut got)))
            })? {
                Ok(b) => ensure!(
                    b == ctx.stored_range(&path, offset, len as usize)?,
                    "ASR OOB {offset}+{len} differs from {path}"
                ),
                Err(r) => return Ok(Outcome::Refused(r)),
            }
            checked += 1;
        }
        self.wire
            .send(p, &xml(requests::dict([("Command", s("Payload"))]))?);
        let limit = if ctx.full { size } else { size.min(ASR_PREFIX) };
        let mut at = 0u64;
        while at < limit {
            let n = (size - at).min(128 * 1024) as usize;
            let mut got = Vec::new();
            match self.pump(|w, _| {
                got.extend(w.take(p, n + 20 - got.len()));
                Ok((got.len() == n + 20).then(|| std::mem::take(&mut got)))
            })? {
                Ok(b) => {
                    use sha1::Digest;
                    let (data, sum) = b.split_at(n);
                    ensure!(
                        sha1::Sha1::digest(data).as_slice() == sum,
                        "ASR chunk at {at}: SHA-1 trailer"
                    );
                    ensure!(
                        data == ctx.stored_range(&path, at, n)?,
                        "ASR payload at {at} differs from {path}"
                    );
                }
                Err(r) => return Ok(Outcome::Refused(r)),
            }
            at += n as u64;
        }
        if at == size {
            self.pump(|w, _| Ok(w.socket(p).filter(|s| s.host_closed).map(|_| ())))?
                .map_err(|r| anyhow!("refused after the whole ASR payload: {r}"))?;
            return Ok(Outcome::Asr(format!(
                "Initiate, {checked} OOB ranges and all {size} bytes of {} ({path}) match; SHA-1 chunk trailers verified",
                image.0
            )));
        }
        // Stop early, as a cancelled restore does; the host's job fails.
        self.wire.close(p);
        let r = self.pump(|_, _| Ok(None::<()>))?;
        let Err(r) = r else { unreachable!() };
        ensure!(
            r.contains("restored closed"),
            "ASR ended with an unexpected refusal: {r}"
        );
        self.end_session();
        Ok(Outcome::Asr(format!(
            "Initiate, {checked} OOB ranges and the first {at} of {size} bytes of {} ({path}) match; SHA-1 chunk trailers verified (--full streams the rest)",
            image.0
        )))
    }
}

/// Check StartRestore's options against restored's compatibility table and
/// the route; returns the advertised data types.
fn check_start(start: &Value, ctx: &Ctx, route: Route) -> (Verdict, BTreeSet<String>) {
    let mut problems = vec![];
    let d = start.as_dictionary().cloned().unwrap_or_default();
    if d.get("RestoreProtocolVersion")
        .and_then(Value::as_unsigned_integer)
        != Some(15)
    {
        problems.push("RestoreProtocolVersion is not 15".to_string());
    }
    let options = d
        .get("RestoreOptions")
        .and_then(Value::as_dictionary)
        .cloned()
        .unwrap_or_default();
    let keys = |k: &str| -> BTreeSet<String> {
        options
            .get(k)
            .and_then(Value::as_dictionary)
            .map(|d| d.keys().cloned().collect())
            .unwrap_or_default()
    };
    let data = keys("SupportedDataTypes");
    let messages = keys("SupportedMessageTypes");
    let missing: Vec<_> = requests::RESTORED_DATA_TYPES
        .iter()
        .filter(|t| !data.contains(**t))
        .collect();
    if !missing.is_empty() {
        problems.push(format!("SupportedDataTypes lacks restored's {missing:?}"));
    }
    let missing: Vec<_> = requests::RESTORED_MESSAGE_TYPES
        .iter()
        .filter(|t| !messages.contains(**t))
        .collect();
    if !missing.is_empty() {
        problems.push(format!(
            "SupportedMessageTypes lacks restored's {missing:?}"
        ));
    }
    let info = |k: &str| context::info(&ctx.identity, k).map(Value::String);
    for (option, want) in [
        ("AuthInstallRestoreBehavior", info("RestoreBehavior")),
        ("AuthInstallRestoreVariant", info("Variant")),
        ("MacOSVariant", info("MacOSVariant")),
        (
            "SystemPartitionSize",
            ctx.identity
                .get("Info")
                .and_then(Value::as_dictionary)
                .and_then(|i| i.get("MinimumSystemPartition"))
                .cloned(),
        ),
    ] {
        if options.get(option) != want.as_ref() {
            problems.push(format!(
                "{option} is {:?}, identity says {want:?}",
                options.get(option)
            ));
        }
    }
    if !route.flashes_nor() {
        for k in ["FlashNOR", "InstallRecoveryOS", "RecoveryOSUnpack"] {
            if options.get(k) != Some(&Value::Boolean(false)) {
                problems.push(format!("the study route leaves {k} on"));
            }
        }
    }
    let extra = data
        .iter()
        .filter(|t| !requests::RESTORED_DATA_TYPES.contains(&t.as_str()))
        .count();
    let v = if problems.is_empty() {
        Verdict::Ok(format!(
            "protocol 15; {} data types ({extra} beyond restored's table) and {} message types cover restored's compatibility table",
            data.len(),
            messages.len()
        ))
    } else {
        Verdict::Failed(problems.join("; "))
    };
    (v, data)
}

impl RestoreDryRun {
    pub fn run(self) -> Result<ExitCode> {
        let root = crate::tools::root();
        let ipsw = root.join(&self.ipsw);
        let inventory = PayloadManifest::parse(
            &std::fs::read(root.join(&self.payload))
                .with_context(|| format!("{}", self.payload.display()))?,
        )
        .map_err(|e| anyhow!("{e}"))?;
        let index = match self.identity {
            Some(i) => i,
            None => inventory.erase_identity().map_err(|e| anyhow!("{e}"))? as usize,
        };
        let route = match self.mode {
            Mode::Install => Route::Stock,
            Mode::Study => Route::StelaFirmwareStudy,
        };
        let tss = self.tss || self.mode == Mode::Install;
        let recorded = inventory.block_hashes.clone();
        ensure!(
            !self.verify_on_read || recorded.is_some(),
            "--verify-on-read needs an inventory that records its block hashes"
        );
        println!(
            "restore dry run: {} {} identity {index}, {} options{}; hashes {}, verify {}",
            inventory.product_build,
            inventory.device_class,
            match self.mode {
                Mode::Install => "install (stock)",
                Mode::Study => "study",
            },
            if tss { ", synthetic TSS" } else { "" },
            if recorded.is_some() {
                "recorded"
            } else {
                "scanned"
            },
            if self.verify_on_read {
                "on read"
            } else {
                "full"
            },
        );
        let t = Instant::now();
        let mut ctx = Ctx::open(ipsw.clone(), inventory.clone(), index, ECID, self.full)?;
        let file = File::open(&ipsw)?;
        let size = file.metadata()?.len();
        let reader = Extent::new(ArchiveFile(file, size), inventory.source.bytes)
            .map_err(|e| anyhow!("{e}"))?;
        let mut store =
            Store::open(reader, inventory.clone(), index).map_err(|e| anyhow!("{e}"))?;
        store.set_verify(if self.verify_on_read {
            Verify::OnRead
        } else {
            Verify::Full
        });
        if let Some(blocks) = &recorded {
            // As the engine does: the hashes the manifest names, beside it.
            let path = root.join(&self.payload).with_file_name(&blocks.file);
            let bytes = std::fs::read(&path).with_context(|| format!("{}", path.display()))?;
            store
                .adopt_block_hashes(&bytes)
                .map_err(|e| anyhow!("{e}"))?;
        }
        let mut answers = Answers::new(store);
        answers.clock = Some(Box::new(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
        }));
        if tss {
            let ticket = tss::ticket(
                ctx.number("ApChipID").context("ApChipID")?,
                ctx.number("ApBoardID").context("ApBoardID")?,
                ctx.number("ApSecurityDomain").context("ApSecurityDomain")?,
                ECID,
            );
            answers.signer = Some(Signer {
                ecid: ECID,
                transport: Box::new(tss::Synthetic {
                    ticket,
                    requests: tss::REQUESTS.with(|r| r.clone()),
                }),
            });
        }
        println!("opened in {:.1}s", t.elapsed().as_secs_f64());
        let hardware = requests::dict([
            (
                "BoardID",
                Value::Integer(ctx.number("ApBoardID").unwrap_or(0).into()),
            ),
            (
                "ChipID",
                Value::Integer(ctx.number("ApChipID").unwrap_or(0).into()),
            ),
            ("EffectiveProductionMode", Value::Boolean(true)),
            ("EffectiveSecurityMode", Value::Boolean(true)),
            ("ProductionMode", Value::Boolean(true)),
            (
                "SecurityDomain",
                Value::Integer(ctx.number("ApSecurityDomain").unwrap_or(0).into()),
            ),
            ("SecurityMode", Value::Boolean(true)),
            ("SupportsImage4", Value::Boolean(true)),
            ("UniqueChipID", Value::Integer(ECID.into())),
        ]);
        let mut runner = Runner {
            route,
            seed: self.seed,
            answers: Some(answers),
            driver: None,
            wire: Wire::new(self.seed),
            complete: false,
            sessions: 0,
            next_port: 20000,
            hardware,
            model: inventory.device_class.to_uppercase(),
        };
        let t = Instant::now();
        let start = runner.open()?;
        println!(
            "handshake and payload verification (Store::prepare) in {:.1}s",
            t.elapsed().as_secs_f64()
        );
        let (verdict, advertised) = check_start(&start, &ctx, route);
        let mut tally = [0usize; 5];
        let mut print = |label: &str, v: &Verdict, secs: f64| {
            let (tag, text, slot) = match v {
                Verdict::Ok(t) => ("ok", t, 0),
                Verdict::Refused(t) => ("refused", t, 1),
                Verdict::Failed(t) => ("FAILED", t, 2),
                Verdict::Skipped(t) => ("skipped", t, 3),
            };
            tally[slot] += 1;
            let time = if secs >= SLOW_SECS {
                tally[4] += 1;
                format!(" [SLOW {secs:.1}s]")
            } else if secs >= 1.0 {
                format!(" [{secs:.1}s]")
            } else {
                String::new()
            };
            println!("{tag:<8} {label}: {text}{time}");
        };
        print("QueryType, HardwareInfo, StartRestore", &verdict, 0.0);
        let mut steps = requests::events();
        steps.push(requests::attestation());
        steps.extend(requests::answers(route, &ctx));
        steps.extend(requests::boot_objects(route, &ctx));
        steps.extend(requests::images(route, &ctx));
        steps.extend(requests::others(route, tss));
        let covered: BTreeSet<String> = steps
            .iter()
            .filter_map(|s| s.message.get("DataType").and_then(Value::as_string))
            .map(str::to_string)
            .collect();
        steps.extend(requests::refusals(&advertised, &covered));
        steps.push(requests::final_status());
        for step in &steps {
            if self
                .only
                .as_ref()
                .is_some_and(|o| !o.split(',').any(|o| step.label.contains(o)))
            {
                continue;
            }
            let t = Instant::now();
            let verdict = match runner.run(&mut ctx, step) {
                Ok(outcome) => (step.check)(&mut ctx, &outcome),
                Err(e) => {
                    runner.end_session();
                    Verdict::Failed(format!("{e:#}"))
                }
            };
            print(&step.label, &verdict, t.elapsed().as_secs_f64());
        }
        println!(
            "{} ok, {} refused as expected, {} FAILED, {} skipped, {} SLOW (over {SLOW_SECS}s natively); {} sessions",
            tally[0], tally[1], tally[2], tally[3], tally[4], runner.sessions
        );
        Ok(if tally[2] == 0 {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        })
    }
}
