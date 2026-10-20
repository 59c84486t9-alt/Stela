//! The startup menu (`stela_loader::mount_interface`): when the boot volume
//! has `choices.cfg`, `stela.efi` lists its entries on the firmware console
//! with one highlighted. Up and Down move the highlight, Enter starts the
//! highlighted entry, and an entry's key (`1`-`9`, then `a`-`z`) starts it
//! at once. A countdown from the file's timeout starts the first entry, the
//! one `stela.cfg` holds; any key stops it. A timeout of 0 opens the menu
//! only when a key is already pressed, as a Mac shows its startup options
//! only when asked. A file that cannot be read or parsed is reported and
//! `stela.cfg` boots, so a damaged file never stops the default boot. A
//! machine that can only be restored waits at the menu with no countdown and
//! its install entry highlighted ([`hold`]).
use crate::{engine, output};
use alloc::{format, string::String, vec::Vec};
use core::{fmt::Write, time::Duration};
use stela_loader::mount_interface::{CHOICES_FILE, Choices};
use uefi::{
    CString16,
    boot::{self, EventType, TimerTrigger, Tpl},
    fs::{FileSystem, PathBuf},
    proto::console::text::{Color, Key, Output, ScanCode},
};

/// Columns assumed when the console reports no mode.
const COLUMNS: usize = 80;
const TICK: Duration = Duration::from_secs(1);

enum Press {
    Up,
    Down,
    Enter,
    Character(char),
    Other,
}

/// What a wait for a key ended with.
enum Wait {
    Key(Press),
    /// The key event fired without a key.
    Nothing,
    Timeout,
    /// The console cannot be waited on.
    NoInput,
}

/// The next key, waiting up to `timeout` (forever with `None`).
fn key(timeout: Option<Duration>) -> Wait {
    let Ok(keys) = uefi::system::with_stdin(|input| input.wait_for_key_event()) else {
        return Wait::NoInput;
    };
    let timer = match timeout {
        Some(duration) => {
            // SAFETY: a plain timer event without a notification function.
            let Ok(timer) =
                (unsafe { boot::create_event(EventType::TIMER, Tpl::APPLICATION, None, None) })
            else {
                return Wait::NoInput;
            };
            if boot::set_timer(&timer, TimerTrigger::Relative(duration)).is_err() {
                let _ = boot::close_event(timer);
                return Wait::NoInput;
            }
            Some(timer)
        }
        None => None,
    };
    let mut events = Vec::from([keys]);
    // SAFETY: the copy is only waited on and closed once, below.
    events.extend(timer.as_ref().map(|t| unsafe { t.unsafe_clone() }));
    let signaled = boot::wait_for_event(&events).ok();
    if let Some(timer) = timer {
        let _ = boot::close_event(timer);
    }
    match signaled {
        Some(0) => pressed().map_or(Wait::Nothing, Wait::Key),
        Some(_) => Wait::Timeout,
        None => Wait::NoInput,
    }
}

/// A key already waiting, without waiting.
fn pressed() -> Option<Press> {
    Some(
        match uefi::system::with_stdin(|input| input.read_key()).ok()?? {
            Key::Printable(character) => match char::from(character) {
                '\r' | '\n' => Press::Enter,
                character => Press::Character(character),
            },
            Key::Special(ScanCode::UP) => Press::Up,
            Key::Special(ScanCode::DOWN) => Press::Down,
            Key::Special(_) => Press::Other,
        },
    )
}

/// The volume's startup choices; `None` when it has none or they cannot be
/// read, which is reported.
fn read(volume: &mut FileSystem) -> Option<Choices> {
    let path = CString16::try_from(CHOICES_FILE).map(PathBuf::from).ok()?;
    if !matches!(volume.try_exists(&path), Ok(true)) {
        return None;
    }
    let choices = volume
        .read(&path)
        .map_err(|_| "cannot read choices.cfg")
        .and_then(|bytes| String::from_utf8(bytes).map_err(|_| "choices.cfg is not UTF-8"))
        .and_then(|text| Choices::parse(&text));
    match choices {
        Ok(choices) => Some(choices),
        Err(error) => {
            output::arguments(format_args!("CHOICES refused: {error}\n"));
            None
        }
    }
}

/// The menu on the firmware console.
struct Menu<'a> {
    choices: &'a Choices,
    /// Lines above the entries.
    heading: &'a str,
    selected: usize,
    /// Seconds before the first entry starts, while the countdown runs.
    countdown: Option<u32>,
}

impl Menu<'_> {
    /// Clear the screen and write the heading; the row the entries start on.
    fn open(&self, out: &mut Output) -> usize {
        let _ = out.set_color(Color::LightGray, Color::Black);
        let _ = out.clear();
        let _ = out.enable_cursor(false);
        let _ = out.write_str(self.heading);
        out.cursor_position().1
    }

    /// Draw the entries from row `top`, then the line under them, each over
    /// what was there.
    fn draw(&self, out: &mut Output, top: usize) {
        // Lines stop short of the last column, which would scroll the screen.
        let width = out
            .current_mode()
            .ok()
            .flatten()
            .map_or(COLUMNS, |mode| mode.columns())
            .saturating_sub(1);
        for (n, entry) in self.choices.entries.iter().enumerate() {
            let key = Choices::key(n).unwrap_or(' ');
            let (foreground, background) = match n == self.selected {
                true => (Color::Black, Color::LightGray),
                false => (Color::LightGray, Color::Black),
            };
            let _ = out.set_cursor_position(0, top + n);
            let _ = out.set_color(foreground, background);
            let _ = write!(out, "{:<width$}", format!("  {key}  {}", entry.name));
        }
        let status = match self.countdown {
            Some(seconds) => format!(
                "{} starts in {seconds}. Press any key to stop.",
                self.choices.entries[0].name
            ),
            None => String::from("Up/Down to select, Enter to start."),
        };
        let _ = out.set_cursor_position(0, top + self.choices.entries.len() + 1);
        let _ = out.set_color(Color::LightGray, Color::Black);
        let _ = write!(out, "{status:<width$}");
    }

    /// The chosen entry; `None` without console input.
    fn run(mut self) -> Option<usize> {
        let top = uefi::system::with_stdout(|out| self.open(out));
        loop {
            uefi::system::with_stdout(|out| self.draw(out, top));
            let wait = key(self.countdown.map(|_| TICK));
            if let Wait::Key(_) = wait {
                self.countdown = None;
            }
            let entries = self.choices.entries.len();
            match wait {
                Wait::Key(Press::Up) => self.selected = (self.selected + entries - 1) % entries,
                Wait::Key(Press::Down) => self.selected = (self.selected + 1) % entries,
                Wait::Key(Press::Enter) => return Some(self.selected),
                Wait::Key(Press::Character(key)) => {
                    if let Some(index) = self.choices.chosen(key) {
                        return Some(index);
                    }
                }
                Wait::Key(Press::Other) | Wait::Nothing => {}
                Wait::Timeout => match self.countdown {
                    Some(1) => return Some(0),
                    Some(seconds) => self.countdown = Some(seconds - 1),
                    None => {}
                },
                Wait::NoInput => return None,
            }
        }
    }
}

/// Clear the menu away and log the chosen entry; its options.
fn chosen(choices: &Choices, index: usize) -> Vec<u8> {
    uefi::system::with_stdout(|out| {
        let _ = out.set_color(Color::LightGray, Color::Black);
        let _ = out.clear();
        let _ = out.enable_cursor(true);
    });
    let entry = &choices.entries[index];
    output::arguments(format_args!("CHOICE {} ({})\n", index + 1, entry.name));
    entry.options.clone().into_bytes()
}

/// The options to boot: the chosen entry's, or `options` (`stela.cfg`).
/// `held` is why the default boot can only wait for a restore, when it can.
pub fn choose(volume: &mut FileSystem, options: Vec<u8>, held: Option<&str>) -> Vec<u8> {
    if let Some(reason) = held {
        return hold(volume, reason).unwrap_or(options);
    }
    let Some(choices) = read(volume) else {
        return options;
    };
    // Only a key pressed before the menu opens asks for it.
    if choices.timeout_seconds == 0 && pressed().is_none() {
        return chosen(&choices, 0);
    }
    let menu = Menu {
        choices: &choices,
        heading: "Stela\n\n",
        selected: 0,
        countdown: (choices.timeout_seconds > 0).then_some(choices.timeout_seconds),
    };
    let index = menu.run().unwrap_or(0);
    chosen(&choices, index)
}

/// Wait at the menu after `reason`, with no countdown, as LLB waits in
/// recovery mode for a restore host: the machine can only be restored. The
/// first install entry starts highlighted; any entry may be chosen, and one
/// that cannot boot either returns here. Returns the chosen entry's options;
/// `None` when the volume has no choices or no console input to choose with.
pub fn hold(volume: &mut FileSystem, reason: &str) -> Option<Vec<u8>> {
    let choices = read(volume)?;
    output::arguments(format_args!("HOLD {reason}\n"));
    let install = |options: &str| {
        let mut words = options.split_ascii_whitespace();
        words.clone().any(|word| word == engine::INSTALL_OPTION)
            && !words.any(|word| word == engine::UPDATE_RESTORE_OPTION)
    };
    let menu = Menu {
        choices: &choices,
        heading: &format!("Stela\n\n{reason}\n\n"),
        selected: choices
            .entries
            .iter()
            .position(|entry| install(&entry.options))
            .unwrap_or(0),
        countdown: None,
    };
    let index = menu.run()?;
    Some(chosen(&choices, index))
}
