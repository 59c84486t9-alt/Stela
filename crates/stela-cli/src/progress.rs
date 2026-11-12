//! Terminal-only progress; redirected commands keep their ordinary output.
//! Once the setup wizard has drawn its timeline, each phase continues it: a
//! running step on the rail, then the finished step it leaves behind.
use indicatif::{HumanBytes, ProgressBar, ProgressStyle};
use std::{
    io::{self, IsTerminal, Read, Write},
    path::Path,
    sync::OnceLock,
    time::Duration,
};

/// The wizard timeline's styled glyphs: a running, finished and stopped
/// step, and the rail between steps.
pub(crate) struct Rail {
    pub(crate) active: String,
    pub(crate) done: String,
    pub(crate) stopped: String,
    pub(crate) bar: String,
}

static RAIL: OnceLock<Rail> = OnceLock::new();

/// Draw every later phase on `rail`.
pub(crate) fn follow(rail: Rail) {
    let _ = RAIL.set(rail);
}

/// The start of a step's first line: its glyph on the rail, if any.
fn step(glyph: fn(&Rail) -> &str) -> String {
    RAIL.get()
        .map(|rail| format!("{}  ", glyph(rail)))
        .unwrap_or_default()
}

/// The start of a step's later lines: the rail, if any.
fn detail() -> String {
    RAIL.get()
        .map(|rail| format!("{}  ", rail.bar))
        .unwrap_or_default()
}

/// The columns left free at the right edge.
const MARGIN: &str = "  ";

pub(crate) struct Phase {
    bar: Option<ProgressBar>,
    label: String,
    finished: bool,
}

impl Phase {
    pub(crate) fn bytes(label: impl Into<String>, bytes: u64) -> Self {
        let label = label.into();
        let bar = io::stderr().is_terminal().then(|| {
            let template = format!(
                "{}{{msg}}\n{}{{wide_bar:.173/239}} {{percent:>3}}%  {{bytes}}/{{total_bytes}}  \
                 {{bytes_per_sec}}  ETA {{eta_precise}}{MARGIN}",
                step(|rail| &rail.active),
                detail(),
            );
            let bar = ProgressBar::new(bytes).with_style(
                ProgressStyle::with_template(&template)
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
            let template = format!("{}{{msg}}  {{elapsed:.dim}}", step(|rail| &rail.active));
            let bar = ProgressBar::new_spinner().with_style(
                ProgressStyle::with_template(&template).expect("a fixed progress template"),
            );
            bar.set_message(label.clone());
            bar.enable_steady_tick(Duration::from_secs(1));
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
            // A one-line summary replaces the finished timers. Off the
            // timeline, a step without a size leaves nothing behind.
            match (bar.length(), RAIL.get()) {
                (None, None) => bar.finish_and_clear(),
                (None, Some(_)) => {
                    bar.set_style(summary(|rail| &rail.done));
                    bar.finish_with_message(self.label.clone());
                }
                (Some(total), _) => {
                    bar.set_style(summary(|rail| &rail.done));
                    bar.finish_with_message(format!("{} · {}", self.label, HumanBytes(total)));
                }
            }
        }
        self.finished = true;
    }
}

/// A finished or stopped step: its glyph and message, then the rail.
fn summary(glyph: fn(&Rail) -> &str) -> ProgressStyle {
    let rail = RAIL
        .get()
        .map(|rail| format!("\n{}", rail.bar))
        .unwrap_or_default();
    ProgressStyle::with_template(&format!("{}{{msg}}{rail}", step(glyph)))
        .expect("a fixed progress template")
}

impl Drop for Phase {
    fn drop(&mut self) {
        if !self.finished
            && let Some(bar) = &self.bar
        {
            bar.set_style(summary(|rail| &rail.stopped));
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
    output.sync_all()?;
    drop_cached(&output)
}

/// Drop `file`'s written pages from the cache after `sync_all`, so a check
/// that reads the file back reads what the disk holds rather than what was
/// written.
pub(crate) fn drop_cached(file: &std::fs::File) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        // SAFETY: an advice call on a descriptor `file` keeps open.
        let error =
            unsafe { libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED) };
        match error {
            0 => Ok(()),
            error => Err(io::Error::from_raw_os_error(error)),
        }
    }
    #[cfg(target_os = "macos")]
    {
        invalidate_mapped(file)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = file;
        Ok(())
    }
}

/// macOS keeps a synced file's written pages cached and has no advice that
/// drops them; `msync` with `MS_INVALIDATE` on a shared mapping of the file
/// does. The writer's descriptor is write-only, so the file is mapped
/// through its path, opened again for reading.
#[cfg(target_os = "macos")]
fn invalidate_mapped(file: &std::fs::File) -> io::Result<()> {
    use std::os::unix::{ffi::OsStrExt, io::AsRawFd};
    let length = usize::try_from(file.metadata()?.len())
        .map_err(|_| io::Error::from(io::ErrorKind::FileTooLarge))?;
    if length == 0 {
        return Ok(());
    }
    let mut path = [0 as libc::c_char; libc::PATH_MAX as usize];
    // SAFETY: F_GETPATH writes at most PATH_MAX bytes, NUL-terminated, into
    // `path`, through a descriptor `file` keeps open.
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETPATH, path.as_mut_ptr()) } == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the successful F_GETPATH NUL-terminated `path`.
    let path = unsafe { std::ffi::CStr::from_ptr(path.as_ptr()) };
    let reader = std::fs::File::open(std::ffi::OsStr::from_bytes(path.to_bytes()))?;
    // SAFETY: a new read-only shared mapping of `length` bytes of a file
    // `reader` keeps open; nothing else refers to the mapping.
    let map = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            length,
            libc::PROT_READ,
            libc::MAP_SHARED,
            reader.as_raw_fd(),
            0,
        )
    };
    if map == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `map` is the mapping of `length` bytes made above, unmapped
    // only after the call.
    let invalidated = unsafe { libc::msync(map, length, libc::MS_INVALIDATE) };
    let error = io::Error::last_os_error();
    // SAFETY: unmaps the mapping made above, which nothing uses after this.
    unsafe { libc::munmap(map, length) };
    match invalidated {
        0 => Ok(()),
        _ => Err(error),
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use std::{io::Write, os::unix::io::AsRawFd};

    /// The share of `path`'s pages the cache holds, in percent.
    fn resident(path: &std::path::Path) -> usize {
        let file = std::fs::File::open(path).unwrap();
        let length = file.metadata().unwrap().len() as usize;
        // SAFETY: sysconf takes no pointers.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let mut pages = vec![0 as libc::c_char; length.div_ceil(page)];
        // SAFETY: a read-only mapping of the open file, unmapped below;
        // mincore writes one byte for each of its `pages.len()` pages.
        unsafe {
            let map = libc::mmap(
                std::ptr::null_mut(),
                length,
                libc::PROT_READ,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                0,
            );
            assert_ne!(map, libc::MAP_FAILED);
            assert_eq!(libc::mincore(map, length, pages.as_mut_ptr()), 0);
            libc::munmap(map, length);
        }
        let held = pages
            .iter()
            .filter(|&&state| i32::from(state) & libc::MINCORE_INCORE != 0)
            .count();
        held * 100 / pages.len()
    }

    /// A written, synced file is left cached by macOS; dropping it leaves
    /// none of it cached, on whatever file system holds `TMPDIR`.
    #[test]
    fn a_synced_file_s_pages_leave_the_cache() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("piece");
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(&vec![0x5a; 8 << 20]).unwrap();
        file.sync_all().unwrap();
        assert!(resident(&path) > 50, "{}", resident(&path));
        super::drop_cached(&file).unwrap();
        assert_eq!(resident(&path), 0);
        // An empty file has nothing to drop.
        let empty = std::fs::File::create(temp.path().join("empty")).unwrap();
        super::drop_cached(&empty).unwrap();
    }
}
