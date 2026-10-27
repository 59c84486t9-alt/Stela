//! Terminal-only progress; redirected commands keep their ordinary output.
use indicatif::{HumanBytes, ProgressBar, ProgressStyle};
use std::{
    io::{self, IsTerminal, Read, Write},
    path::Path,
    time::Duration,
};

pub(crate) struct Phase {
    bar: Option<ProgressBar>,
    label: String,
    finished: bool,
}

impl Phase {
    pub(crate) fn bytes(label: impl Into<String>, bytes: u64) -> Self {
        let label = label.into();
        let bar = io::stderr().is_terminal().then(|| {
            let bar = ProgressBar::new(bytes).with_style(
                ProgressStyle::with_template("{msg}\n{wide_bar:.173/239} {percent:>3}%  {bytes}/{total_bytes}  {bytes_per_sec}  ETA {eta_precise}")
                    .expect("a fixed progress template")
                    .progress_chars("█▌░"),
            );
            bar.set_message(label.clone());
            bar.enable_steady_tick(Duration::from_millis(200));
            bar
        });
        Self {
            bar,
            label,
            finished: false,
        }
    }

    pub(crate) fn spinner(label: impl Into<String>) -> Self {
        let label = label.into();
        let bar = io::stderr().is_terminal().then(|| {
            let bar = ProgressBar::new_spinner().with_style(summary());
            bar.set_message(label.clone());
            bar.tick();
            bar
        });
        Self {
            bar,
            label,
            finished: false,
        }
    }

    pub(crate) fn advance(&self, bytes: u64) {
        if let Some(bar) = &self.bar {
            bar.inc(bytes);
        }
    }

    pub(crate) fn position(&self, bytes: u64) {
        if let Some(bar) = &self.bar {
            bar.set_position(bytes);
            bar.reset_eta();
        }
    }

    pub(crate) fn add_work(&self, bytes: u64) {
        if let Some(bar) = &self.bar {
            bar.set_length(bar.length().unwrap_or(0).saturating_add(bytes));
        }
    }

    pub(crate) fn finish(mut self) {
        if let Some(bar) = &self.bar {
            match bar.length() {
                None => bar.finish_and_clear(),
                Some(total) => {
                    // A one-line summary replaces the finished timers.
                    bar.set_style(summary());
                    bar.finish_with_message(format!("{} · {}", self.label, HumanBytes(total)));
                }
            }
        }
        self.finished = true;
    }
}

fn summary() -> ProgressStyle {
    ProgressStyle::with_template("{msg}").expect("a fixed progress template")
}

impl Drop for Phase {
    fn drop(&mut self) {
        if !self.finished
            && let Some(bar) = &self.bar
        {
            bar.set_style(summary());
            bar.abandon_with_message(format!("{} stopped", self.label));
        }
    }
}

pub(crate) fn copy(from: &Path, to: &Path, progress: &Phase) -> io::Result<()> {
    let mut input = std::fs::File::open(from)?;
    let mut output = std::fs::File::create(to)?;
    let mut buffer = vec![0; 1024 * 1024];
    loop {
        let count = match input.read(&mut buffer) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if count == 0 {
            break;
        }
        output.write_all(&buffer[..count])?;
        progress.advance(count as u64);
    }
    output.sync_all()
}
