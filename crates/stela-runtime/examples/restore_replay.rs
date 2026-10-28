//! Hosted harness for the native restore client. No sockets or Apple servers.
//! See docs/research/restore-client.md for transcript layout and provenance.
use anyhow::{Context, Result, bail, ensure};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::Path,
    task::Poll,
};
use {
    stela_formats::payload::PayloadManifest, stela_formats::payload::ReadAt,
    stela_runtime::restore::Error, stela_runtime::restore::answers::Answers,
    stela_runtime::restore::plist, stela_runtime::restore::plist::Limits,
    stela_runtime::restore::plist::Value, stela_runtime::restore::session::Action,
    stela_runtime::restore::session::Session, stela_runtime::restore::store::Store,
    stela_runtime::restore::stream::ByteStream, stela_runtime::restore::stream::Endian,
    stela_runtime::restore::stream::Framed,
};
struct ArchiveFile(File, u64);
impl ReadAt for ArchiveFile {
    type Error = std::io::Error;
    fn len(&self) -> u64 {
        self.1
    }
    fn read_at(&mut self, offset: u64, b: &mut [u8]) -> std::io::Result<()> {
        use std::io::{Seek, SeekFrom};
        self.0.seek(SeekFrom::Start(offset))?;
        self.0.read_exact(b)
    }
}
struct Transcript {
    input: File,
    output: File,
    pending: bool,
}
impl Transcript {
    fn open(input: &Path, output: &Path) -> Result<Self> {
        Ok(Self {
            input: File::open(input)?,
            output: File::create(output)?,
            pending: false,
        })
    }
}
impl ByteStream for Transcript {
    fn read(&mut self, b: &mut [u8]) -> Poll<stela_runtime::restore::Result<usize>> {
        self.pending = !self.pending;
        if self.pending {
            return Poll::Pending;
        }
        let n = b.len().min(7);
        Poll::Ready(
            self.input
                .read(&mut b[..n])
                .map_err(|e| Error::Transport(e.to_string())),
        )
    }
    fn write(&mut self, b: &[u8]) -> Poll<stela_runtime::restore::Result<usize>> {
        self.pending = !self.pending;
        if self.pending {
            return Poll::Pending;
        }
        Poll::Ready(
            self.output
                .write(&b[..b.len().min(11)])
                .map_err(|e| Error::Transport(e.to_string())),
        )
    }
}
fn send(f: &mut Framed, s: &mut Transcript, v: &Value) -> Result<()> {
    f.queue(v, true).map_err(|e| anyhow::anyhow!("{e}"))?;
    loop {
        if let Poll::Ready(v) = f.poll_send(s) {
            return v.map_err(|e| anyhow::anyhow!("{e}"));
        }
    }
}
fn receive(f: &mut Framed, s: &mut Transcript) -> Result<Value> {
    loop {
        if let Poll::Ready(v) = f.poll_receive(s) {
            return v.map_err(|e| anyhow::anyhow!("{e}"));
        }
    }
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--inspect") {
        ensure!(args.len() == 2, "--inspect PLIST");
        let b = fs::read(&args[1])?;
        let limits = Limits {
            bytes: 64 * 1024 * 1024,
            nodes: 2_000_000,
            depth: 64,
        };
        let v = plist::decode(&b, limits).map_err(|e| anyhow::anyhow!("{e}"))?;
        let binary = plist::encode_binary(&v, limits).map_err(|e| anyhow::anyhow!("{e}"))?;
        ensure!(
            plist::decode(&binary, limits).map_err(|e| anyhow::anyhow!("{e}"))? == v,
            "round trip differs"
        );
        println!(
            "plist input bytes={} binary bytes={} identities={}",
            b.len(),
            binary.len(),
            v.get("BuildIdentities")
                .and_then(|v| v.array().ok())
                .map_or(0, |a| a.len())
        );
        return Ok(());
    }
    if args.first().map(String::as_str) == Some("--coverage") {
        ensure!(args.len() == 4, "--coverage BUILD_MANIFEST IM4M IDENTITY");
        let limits = Limits {
            bytes: 64 * 1024 * 1024,
            nodes: 2_000_000,
            depth: 64,
        };
        let build =
            plist::decode(&fs::read(&args[1])?, limits).map_err(|e| anyhow::anyhow!("{e}"))?;
        let index: usize = args[3].parse()?;
        let value = build
            .required("BuildIdentities")
            .and_then(Value::array)
            .map_err(|e| anyhow::anyhow!("{e}"))?
            .get(index)
            .context("identity index")?
            .clone();
        let identity = stela_runtime::restore::store::Identity { index, value };
        let global = stela_runtime::restore::ticket::Ticket::global(fs::read(&args[2])?, &identity)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        println!(
            "global manifest parsed for identity {index}: {} bytes; signature not evaluated",
            global.bytes().len()
        );
        return Ok(());
    }
    if args.len() != 5 {
        bail!(
            "usage: restore_replay PAYLOAD_JSON IPSW IDENTITY TRANSCRIPT_DIR OUTPUT_DIR | --inspect PLIST"
        );
    }
    let payload =
        PayloadManifest::parse(&fs::read(&args[0])?).map_err(|e| anyhow::anyhow!("{e}"))?;
    let archive = File::open(&args[1])?;
    let size = archive.metadata()?.len();
    let mut answers = Answers::new(
        Store::open(ArchiveFile(archive, size), payload, args[2].parse()?)
            .map_err(|e| anyhow::anyhow!("{e}"))?,
    );
    answers
        .store
        .prepare()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let input = Path::new(&args[3]);
    let output = Path::new(&args[4]);
    fs::create_dir(output).context("output directory must be fresh")?;
    let mut control = Transcript::open(
        &input.join("control.plists"),
        &output.join("control.plists"),
    )?;
    let mut framing = Framed::new(Endian::Big, Limits::default());
    let mut session = Session::new();
    let result = (|| -> Result<()> {
        send(
            &mut framing,
            &mut control,
            &session.query_type().map_err(|e| anyhow::anyhow!("{e}"))?,
        )?;
        session
            .receive(receive(&mut framing, &mut control)?, &mut answers)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        send(
            &mut framing,
            &mut control,
            &session
                .query_value("HardwareInfo")
                .map_err(|e| anyhow::anyhow!("{e}"))?,
        )?;
        session
            .receive(receive(&mut framing, &mut control)?, &mut answers)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        send(
            &mut framing,
            &mut control,
            &session
                .start(&answers)
                .map_err(|e| anyhow::anyhow!("{e}"))?,
        )?;
        session.started().map_err(|e| anyhow::anyhow!("{e}"))?;
        loop {
            match session
                .receive(receive(&mut framing, &mut control)?, &mut answers)
                .map_err(|e| anyhow::anyhow!("{e}"))?
            {
                Action::None | Action::Event(_) => {}
                Action::FinalAck(v) => {
                    send(&mut framing, &mut control, &v)?;
                    session
                        .final_ack_sent()
                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                    break;
                }
                Action::Transfer(mut job) => {
                    let mut data = job
                        .port
                        .map(|port| {
                            Transcript::open(
                                &input.join(format!("job-{}-port-{port}.input", job.id)),
                                &output.join(format!("job-{}-port-{port}.output", job.id)),
                            )
                        })
                        .transpose()?;
                    let stream = data.as_mut().unwrap_or(&mut control);
                    let result = loop {
                        if let Poll::Ready(v) = job.poll(stream, &mut answers.store) {
                            break v;
                        }
                    };
                    session
                        .finish_job(job.id, result)
                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                }
            }
        }
        Ok(())
    })();
    // Persist the fresh bounded ledger even when the replay refuses a request.
    for (i, v) in session.ledger().iter().enumerate() {
        fs::write(
            output.join(format!("ledger-{i:05}.bplist")),
            plist::encode_binary(v, Limits::default()).map_err(|e| anyhow::anyhow!("{e}"))?,
        )?;
    }
    result?;
    println!("synthetic/recorded replay complete; this does not prove a live install");
    Ok(())
}
