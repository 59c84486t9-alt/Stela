//! What the screen says while Stela starts: one line per step, in the style
//! of a Linux boot, while every detail goes to the UART and the boot log
//! ([`output`]). A running step's line shows a moving marker, its progress
//! and its time so far, and its result replaces it when it ends:
//!
//! ```text
//! [  OK  ] Read Install macOS (Stela) (484 MB, 12 s)
//! [ ***  ] Getting a network address on Intel I226-V (3 s)
//! ```
//!
//! [`tick`] moves the marker; anything that waits calls it, at most a few
//! frames a second are drawn. Finished lines are kept as [`history`], which
//! the loader hands to the system engine so its screen carries on from them
//! ([`replay`]).
use crate::{
    console::{self, Color},
    output,
};
use alloc::{format, string::String};
use core::{arch::x86_64::_rdtsc, cell::RefCell};

/// Frames of the running marker: three cells moving across six and back.
const FRAMES: usize = 14;
const MARKER: usize = 6;
/// The finished lines kept for the system engine's screen.
pub const HISTORY_BYTES: usize = 4096;

struct Running {
    title: String,
    detail: String,
    started: u64,
    frame: usize,
    drawn: u64,
}

struct State {
    tsc_hz: u64,
    running: Option<Running>,
    /// Finished lines, each its mark's letter then its text.
    history: String,
}

/// One processor runs the mount; every access is a `try_borrow`, so a line
/// drawn while the state is in use is skipped rather than re-entered.
struct Global(RefCell<State>);
// SAFETY: see `Global`.
unsafe impl Sync for Global {}

static STATE: Global = Global(RefCell::new(State {
    tsc_hz: 0,
    running: None,
    history: String::new(),
}));

fn now() -> u64 {
    // SAFETY: RDTSC has no memory effects.
    unsafe { _rdtsc() }
}

#[derive(Clone, Copy)]
enum Mark {
    Ok,
    Warn,
    Failed,
    Info,
}

impl Mark {
    fn letter(self) -> char {
        match self {
            Mark::Ok => 'o',
            Mark::Warn => 'w',
            Mark::Failed => 'f',
            Mark::Info => 'i',
        }
    }

    fn from_letter(letter: char) -> Option<Self> {
        Some(match letter {
            'o' => Mark::Ok,
            'w' => Mark::Warn,
            'f' => Mark::Failed,
            'i' => Mark::Info,
            _ => return None,
        })
    }

    fn draw(self, text: &str) {
        let (label, color) = match self {
            Mark::Ok => ("  OK  ", Color::Good),
            Mark::Warn => (" WARN ", Color::Warn),
            Mark::Failed => ("FAILED", Color::Fatal),
            Mark::Info => {
                console::rewrite(&[("         ", Color::Text), (text, Color::Text)]);
                console::write(&[("\n", Color::Text)]);
                return;
            }
        };
        console::rewrite(&[
            ("[", Color::Text),
            (label, color),
            ("] ", Color::Text),
            (text, Color::Text),
        ]);
        console::write(&[("\n", Color::Text)]);
    }
}

impl State {
    fn seconds(&self, since: u64) -> u64 {
        (now() - since) / self.tsc_hz.max(1)
    }

    fn draw_running(&mut self) {
        let Some(running) = self.running.as_ref() else {
            return;
        };
        let step = running.frame % FRAMES;
        let head = if step < FRAMES / 2 {
            step
        } else {
            FRAMES - step
        };
        let mut marker = [b' '; MARKER];
        for (cell, byte) in marker.iter_mut().enumerate() {
            if cell <= head && head < cell + 3 {
                *byte = b'*';
            }
        }
        let marker = core::str::from_utf8(&marker).unwrap_or("      ");
        let seconds = self.seconds(running.started);
        let elapsed = match seconds {
            0 => String::new(),
            seconds => format!(" ({seconds} s)"),
        };
        let gap = if running.detail.is_empty() { "" } else { "  " };
        console::rewrite(&[
            ("[", Color::Text),
            (marker, Color::Busy),
            ("] ", Color::Text),
            (&running.title, Color::Text),
            (gap, Color::Text),
            (&running.detail, Color::Text),
            (&elapsed, Color::Dim),
        ]);
    }

    fn finish(&mut self, mark: Mark, result: &str) {
        let Some(running) = self.running.take() else {
            return self.line(mark, result);
        };
        let seconds = self.seconds(running.started);
        let mut text = running.title;
        match (result.is_empty(), seconds) {
            (true, 0) => {}
            (true, seconds) => text.push_str(&format!(" ({seconds} s)")),
            (false, 0) => text.push_str(&format!(" ({result})")),
            (false, seconds) => text.push_str(&format!(" ({result}, {seconds} s)")),
        }
        output::arguments(format_args!("STEP {} {text}\n", mark.letter()));
        self.line(mark, &text);
    }

    fn line(&mut self, mark: Mark, text: &str) {
        mark.draw(text);
        let line = format!("{}{text}\n", mark.letter());
        while self.history.len() + line.len() > HISTORY_BYTES {
            let Some(end) = self.history.find('\n') else {
                self.history.clear();
                break;
            };
            self.history.drain(..=end);
        }
        if line.len() <= HISTORY_BYTES {
            self.history.push_str(&line);
        }
        // The running step's line, which the finished one took, follows it.
        self.draw_running();
    }
}

fn with(f: impl FnOnce(&mut State)) {
    if let Ok(mut state) = STATE.0.try_borrow_mut() {
        f(&mut state);
    }
}

/// The time-stamp counter's rate, for the times steps show.
pub fn set_clock(tsc_hz: u64) {
    with(|state| state.tsc_hz = tsc_hz);
}

/// Start a step; one still running ends first, as done.
pub fn begin(title: &str) {
    with(|state| {
        if state.running.is_some() {
            state.finish(Mark::Ok, "");
        }
        output::arguments(format_args!("STEP {title}\n"));
        state.running = Some(Running {
            title: String::from(title),
            detail: String::new(),
            started: now(),
            frame: 0,
            drawn: now(),
        });
        state.draw_running();
    });
}

/// Show how far the running step has come, such as `182 of 484 MB`.
pub fn progress(detail: &str) {
    with(|state| {
        if let Some(running) = state.running.as_mut() {
            running.detail.clear();
            running.detail.push_str(detail);
            state.draw_running();
        }
    });
}

/// Move the running step's marker, at most eight frames a second.
pub fn tick() {
    with(|state| {
        let frame = state.tsc_hz / 8;
        let Some(running) = state.running.as_mut().filter(|_| frame > 0) else {
            return;
        };
        if now() - running.drawn < frame {
            return;
        }
        running.drawn = now();
        running.frame += 1;
        state.draw_running();
    });
}

/// End the running step with `result`, which may be empty.
pub fn done(result: &str) {
    with(|state| state.finish(Mark::Ok, result));
}

/// End the running step as having gone wrong in a way that lets the boot
/// go on.
pub fn warn(result: &str) {
    with(|state| state.finish(Mark::Warn, result));
}

/// End the running step as failed, or show `result` as a failure.
pub fn fail(result: &str) {
    with(|state| state.finish(Mark::Failed, result));
}

/// A line of its own, under the step lines.
pub fn info(text: &str) {
    with(|state| state.line(Mark::Info, text));
}

/// Draw with Stela's console on `screen` from now on, starting with the
/// finished lines so far and the running step.
pub fn take_screen(screen: Option<console::Framebuffer>) {
    let Some(screen) = screen else {
        return;
    };
    console::install(screen);
    with(|state| {
        for line in state.history.lines() {
            let mut characters = line.chars();
            if let Some(mark) = characters.next().and_then(Mark::from_letter) {
                mark.draw(characters.as_str());
            }
        }
        state.draw_running();
    });
}

/// The finished lines so far.
pub fn history(into: &mut [u8; HISTORY_BYTES]) -> usize {
    let mut bytes = 0;
    if let Ok(state) = STATE.0.try_borrow() {
        bytes = state.history.len();
        into[..bytes].copy_from_slice(state.history.as_bytes());
    }
    bytes
}

/// Draw the loader's finished lines again, as the system engine's screen
/// starts.
pub fn replay(history: &[u8]) {
    let text = core::str::from_utf8(history).unwrap_or_default();
    for line in text.lines() {
        let mut characters = line.chars();
        if let Some(mark) = characters.next().and_then(Mark::from_letter) {
            with(|state| state.line(mark, characters.as_str()));
        }
    }
}
