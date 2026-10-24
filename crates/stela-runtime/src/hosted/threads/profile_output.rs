//! One cumulative, atomically replaced file per owned engine epoch.
//! Files are the sole FP profile dataset; completed-thread reports overlap them.
use super::{Kernel, Member, Pe};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const INTERVAL: Duration = Duration::from_secs(2);
const RETURN_INTERVAL: u32 = 64;
const MAX_SNAPSHOT_BYTES: usize = 2 * 1024 * 1024;

fn diagnostic(message: std::fmt::Arguments<'_>) {
    // Diagnostic output failure must not panic or alter the guest outcome.
    let _ = writeln!(std::io::stderr(), "stela: {message}");
}

pub(super) struct ThreadOutput {
    parent: PathBuf,
    directory: PathBuf,
    pid: u32,
    thread: u64,
    sequence: u64,
    started: Instant,
    next_publish: Instant,
    next_block: u64,
    initial_blocks: u64,
    initial_retired: u64,
    returns: u32,
    failed_publications: u64,
    reported_failure: bool,
    active: bool,
}

#[derive(Serialize)]
struct Envelope {
    schema: u32,
    identity: String,
    pid: u32,
    registry_thread_id: u64,
    snapshot_sequence: u64,
    final_snapshot: bool,
    elapsed_monotonic_ns: u128,
    blocks: u64,
    retired: u64,
    initial_blocks: u64,
    initial_retired: u64,
    retired_scope: &'static str,
    compiler_source_sha256: &'static str,
    engine_source_sha256: &'static str,
    failed_publications: u64,
    population_scope: &'static str,
    profile: crate::machine::engine::floating_profile::Snapshot,
}

fn write_atomic(directory: &Path, sequence: u64, bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() <= MAX_SNAPSHOT_BYTES,
        "FP snapshot exceeds its byte bound"
    );
    let temporary = directory.join(format!("snapshot-{sequence}.partial"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(bytes)?;
    drop(file);
    fs::rename(temporary, directory.join("snapshot.json"))?;
    Ok(())
}

impl ThreadOutput {
    fn new(parent: &Path, thread: u64, pe: &mut Pe) -> Result<Self> {
        fs::create_dir_all(parent).context("create the explicit FP profile container")?;
        let directory = tempfile::Builder::new()
            .prefix("engine-")
            .tempdir_in(parent)
            .context("own a fresh FP profile engine directory")?
            .keep();
        // Dedicated diagnostic entropy; never PAC, guest guards or other secrets.
        let [seed] = crate::hosted::random_words::<1>()?;
        pe.enable_floating_profile(seed);
        let now = Instant::now();
        let mut output = Self {
            parent: parent.to_owned(),
            directory,
            pid: std::process::id(),
            thread,
            sequence: 0,
            started: now,
            next_publish: now + INTERVAL,
            next_block: pe.statistics.blocks.saturating_add(super::SLICE_BLOCKS),
            initial_blocks: pe.statistics.blocks,
            initial_retired: pe.cpu.retired,
            returns: 0,
            failed_publications: 0,
            reported_failure: false,
            active: true,
        };
        output.publish(pe, false)?;
        diagnostic(format_args!(
            "FP service profile {}",
            output.directory.display()
        ));
        Ok(output)
    }

    /// A host fork inherits both the live PE and writer. Reset before any child
    /// guest instruction or publication. New child threads independently own
    /// fresh directories too: immutable Engine config retains only the parent
    /// container, never a parent-owned writer/session or a diagnostic mutex.
    pub(super) fn resume(&mut self, pe: &mut Pe) {
        if !self.active || self.pid == std::process::id() {
            return;
        }
        self.active = false;
        pe.disable_floating_profile();
        match Self::new(&self.parent, self.thread, pe) {
            Ok(fresh) => *self = fresh,
            Err(error) => {
                pe.disable_floating_profile();
                diagnostic(format_args!("child FP profiling disabled: {error:#}"));
            }
        }
    }

    fn publish(&mut self, pe: &Pe, final_snapshot: bool) -> Result<()> {
        ensure!(
            self.pid == std::process::id(),
            "inherited FP writer cannot publish"
        );
        self.sequence = self
            .sequence
            .checked_add(1)
            .context("FP snapshot sequence exhausted")?;
        let profile = pe
            .floating_profile_snapshot()
            .context("FP sampler is absent")?;
        let envelope = Envelope {
            schema: 1,
            identity: self
                .directory
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            pid: self.pid,
            registry_thread_id: self.thread,
            snapshot_sequence: self.sequence,
            final_snapshot,
            elapsed_monotonic_ns: self.started.elapsed().as_nanos(),
            blocks: pe.statistics.blocks,
            retired: pe.cpu.retired,
            initial_blocks: self.initial_blocks,
            initial_retired: self.initial_retired,
            retired_scope: "current engine cumulative cpu.retired; subtract initial_retired for this epoch; inherited fork counts remain only in baseline",
            compiler_source_sha256: stela_compiler::SOURCE_SHA256,
            engine_source_sha256: crate::translations::ENGINE_SOURCE_SHA256,
            failed_publications: self.failed_publications,
            population_scope: "serviced scalar/AdvSIMD FP exits; native-success, scalable and AMX excluded; cumulative replace, never sum sequences; live/abruptly ended engines can be stale/partial; FPSR differences are newly observable sticky transitions only",
            profile,
        };
        write_atomic(
            &self.directory,
            self.sequence,
            &serde_json::to_vec(&envelope)?,
        )
    }

    pub(super) fn checkpoint(&mut self, pe: &mut Pe, final_snapshot: bool) {
        // This also covers an early child error/termination before resume.
        self.resume(pe);
        if !self.active {
            return;
        }
        if !final_snapshot {
            self.returns += 1;
            if pe.statistics.blocks < self.next_block && self.returns < RETURN_INTERVAL {
                return;
            }
            self.returns = 0;
            self.next_block = pe.statistics.blocks.saturating_add(super::SLICE_BLOCKS);
            let now = Instant::now();
            if now < self.next_publish {
                return;
            }
            self.next_publish = now + INTERVAL;
        }
        if let Err(error) = self.publish(pe, final_snapshot) {
            self.failed_publications = self.failed_publications.saturating_add(1);
            if !self.reported_failure {
                diagnostic(format_args!(
                    "FP profile publication failed (last complete snapshot retained): {error:#}"
                ));
                self.reported_failure = true;
            }
        }
    }
}

pub(super) fn execute(
    kernel: &mut Kernel,
    pe: &mut Box<Pe>,
    member: &Member,
) -> Result<Option<super::Termination>> {
    let output = kernel
        .process
        .engine
        .fp_profile_output
        .as_deref()
        .map(|parent| ThreadOutput::new(parent, kernel.thread, pe))
        .transpose();
    let mut output = match output {
        Ok(output) => output,
        Err(error) => {
            pe.disable_floating_profile();
            diagnostic(format_args!("engine FP profiling disabled: {error:#}"));
            None
        }
    };
    let outcome = super::run(kernel, pe, member, &mut output);
    if let Some(output) = &mut output {
        output.checkpoint(pe, true);
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_cumulative_replacement_preserves_last_good_after_interrupted_write() -> Result<()> {
        let directory = tempfile::tempdir()?;
        write_atomic(
            directory.path(),
            1,
            br#"{"sequence":1,"population":10,"final":false}"#,
        )?;
        let temporary = directory.path().join("snapshot-2.partial");
        fs::write(&temporary, br#"{"sequence":2,"population":"#)?;
        assert!(write_atomic(directory.path(), 2, b"{}").is_err());
        let read = || -> Result<serde_json::Value> {
            Ok(serde_json::from_slice(&fs::read(
                directory.path().join("snapshot.json"),
            )?)?)
        };
        assert_eq!(read()?["population"], 10);
        write_atomic(
            directory.path(),
            3,
            br#"{"sequence":3,"population":25,"final":true}"#,
        )?;
        assert_eq!(read()?["population"], 25);
        assert_eq!(read()?["final"], true);
        assert!(
            temporary.exists(),
            "incomplete files remain explicitly incomplete evidence"
        );
        assert!(write_atomic(directory.path(), 4, &vec![0; MAX_SNAPSHOT_BYTES + 1]).is_err());
        assert_eq!(read()?["population"], 25);
        Ok(())
    }
}
