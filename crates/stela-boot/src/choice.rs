//! The startup menu (`stela_loader::mount_interface`): when the boot volume
//! has `choices.cfg`, `stela.efi` lists on the firmware console the entries
//! that can start now, under the Mac's heading, then the PC firmware's own
//! boot entries (`firmware::entries`), with one highlighted and a line on
//! what it does. A Mac or recoveryOS entry whose SSD the setup restore has
//! not prepared yet is left out (`selection::ready`). Up and Down move the
//! highlight, Enter starts the highlighted entry, and an entry's key (`1`-`9`,
//! then `a`-`z`) starts it at once; a firmware entry restarts the PC into it.
//! A countdown from the file's timeout starts the first entry, the one
//! `stela.cfg` holds; any key stops it. A timeout of 0 opens the menu only
//! when a key is already pressed, as a Mac shows its startup options only
//! when asked. A file that cannot be read or parsed is reported and
//! `stela.cfg` boots, so a damaged file never stops the default boot. A
//! machine that can only be set up waits at the menu with no countdown and
//! its setup entry highlighted ([`hold`]).
use crate::{
    console,
    firmware::entries::{self, Entry},
    output,
    selection::{self, Refusal},
    status,
};
use alloc::{format, string::String, vec::Vec};
use core::{fmt::Write, time::Duration};
use stela_loader::mount_interface::{CHOICES_FILE, ChoiceKind, Choices};
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

/// The heading over Stela's choices.
const MAC: &str = "Stela";
/// The heading over the firmware's entries.
const PC: &str = "This PC";

/// One entry of the menu.
enum Item {
    /// Entry `n` of the startup choices.
    Choice(usize, ChoiceKind),
    /// One of the PC firmware's own boot entries.
    Firmware(Entry),
}

/// One line of the menu.
enum Line<'a> {
    Text(&'a str),
    Item(usize),
}

/// The menu on the firmware console.
struct Menu<'a> {
    choices: &'a Choices,
    items: Vec<Item>,
    /// Why the machine can only be set up, when it can.
    held: Option<&'a str>,
    /// Whether the Mac's SSD is not prepared yet, so setting it up is its
    /// first start rather than a fresh start.
    blank: bool,
    selected: usize,
    /// Seconds before the first entry starts, while the countdown runs.
    countdown: Option<u32>,
    /// Why the last firmware entry chosen did not start.
    notice: Option<&'static str>,
}

impl<'a> Menu<'a> {
    /// The menu of `choices`: those that can start now, then the firmware's
    /// entries. `held` is why the machine can only be set up.
    fn new(choices: &'a Choices, held: Option<&'a str>) -> Self {
        let mut blank = held.is_some();
        let mut items = Vec::new();
        for (n, entry) in choices.entries.iter().enumerate() {
            let kind = entry.kind();
            match selection::ready(&entry.options, kind) {
                Err(refusal @ (Refusal::BlankDisk | Refusal::RecoveryMode)) => {
                    blank |= matches!(refusal, Refusal::BlankDisk);
                    output::arguments(format_args!(
                        "CHOICE {} ({}) left out: its SSD is not set up\n",
                        n + 1,
                        entry.name
                    ));
                }
                _ => items.push(Item::Choice(n, kind)),
            }
        }
        // A setup without its restore choice still lists its own.
        if items.is_empty() {
            items.extend(
                choices
                    .entries
                    .iter()
                    .enumerate()
                    .map(|(n, entry)| Item::Choice(n, entry.kind())),
            );
        }
        items.extend(entries::list().into_iter().map(Item::Firmware));
        let selected = match held {
            Some(_) => items
                .iter()
                .position(|item| matches!(item, Item::Choice(_, ChoiceKind::Setup)))
                .unwrap_or(0),
            None => 0,
        };
        let first_is_default = matches!(items.first(), Some(Item::Choice(0, _)));
        Self {
            choices,
            countdown: (held.is_none() && first_is_default && choices.timeout_seconds > 0)
                .then_some(choices.timeout_seconds),
            items,
            held,
            blank,
            selected,
            notice: None,
        }
    }

    fn name(&self, item: &'a Item) -> &'a str {
        match item {
            Item::Choice(n, _) => &self.choices.entries[*n].name,
            Item::Firmware(entry) => &entry.name,
        }
    }

    /// What `item` does, in a line.
    fn about(&self, item: &Item) -> &'static str {
        match item {
            Item::Firmware(_) => "Restarts the PC into this entry of its firmware's boot menu.",
            Item::Choice(_, kind) => match kind {
                ChoiceKind::Mac => "Starts the Mac from its startup disk, as a Mac starts up.",
                ChoiceKind::Recovery => {
                    "macOS Recovery: Disk Utility, and Reinstall macOS onto a disk of this PC."
                }
                ChoiceKind::Setup if self.blank => {
                    "Run this first: Apple's restore prepares the Mac's SSD. Needs the network."
                }
                ChoiceKind::Setup => {
                    "Erases the Mac's SSD and prepares it again; the PC's disks are kept."
                }
                ChoiceKind::Update => "Updates the Mac's macOS in place, keeping its data.",
                ChoiceKind::Other => "",
            },
        }
    }

    /// The lines from the first heading down: the Mac's entries, then the
    /// firmware's.
    fn lines(&self) -> Vec<Line<'a>> {
        let mut lines = Vec::new();
        let mut section = None;
        for (index, item) in self.items.iter().enumerate() {
            let heading = match item {
                Item::Choice(..) => MAC,
                Item::Firmware(_) => PC,
            };
            if section != Some(heading) {
                if section.is_some() {
                    lines.push(Line::Text(""));
                }
                lines.push(Line::Text(heading));
                section = Some(heading);
            }
            lines.push(Line::Item(index));
        }
        lines
    }

    /// Clear the screen and write why the machine is held; the row the
    /// lines start on.
    fn open(&self, out: &mut Output) -> usize {
        let _ = out.set_color(Color::LightGray, Color::Black);
        let _ = out.clear();
        let _ = out.enable_cursor(false);
        if let Some(reason) = self.held {
            let _ = write!(out, "{reason}\n\n");
        }
        out.cursor_position().1
    }

    /// Draw the lines from row `top`, then what the highlighted entry does
    /// and the line under it, each over what was there.
    fn draw(&self, out: &mut Output, top: usize) {
        // Lines stop short of the last column, which would scroll the screen.
        let width = out
            .current_mode()
            .ok()
            .flatten()
            .map_or(COLUMNS, |mode| mode.columns())
            .saturating_sub(1);
        let mut row = top;
        let mut put = |out: &mut Output, text: &str, highlighted: bool| {
            let (foreground, background) = match highlighted {
                true => (Color::Black, Color::LightGray),
                false => (Color::LightGray, Color::Black),
            };
            let _ = out.set_cursor_position(0, row);
            let _ = out.set_color(foreground, background);
            let text: String = text.chars().take(width).collect();
            let _ = write!(out, "{text:<width$}");
            row += 1;
        };
        for line in self.lines() {
            match line {
                Line::Text(text) => put(out, text, false),
                Line::Item(n) => {
                    let key = Choices::key(n).unwrap_or(' ');
                    let name = self.name(&self.items[n]);
                    put(out, &format!("  {key}  {name}"), n == self.selected);
                }
            }
        }
        put(out, "", false);
        put(out, self.about(&self.items[self.selected]), false);
        let status = match (self.notice, self.countdown) {
            (Some(notice), _) => String::from(notice),
            (None, Some(seconds)) => format!(
                "{} starts in {seconds}. Press any key to stop.",
                self.name(&self.items[0])
            ),
            (None, None) => String::from("Up/Down to select, Enter to start."),
        };
        put(out, &status, false);
    }

    /// The chosen item; `None` without console input.
    fn run(&mut self) -> Option<usize> {
        console::to_firmware();
        let top = uefi::system::with_stdout(|out| self.open(out));
        loop {
            uefi::system::with_stdout(|out| self.draw(out, top));
            let wait = key(self.countdown.map(|_| TICK));
            if let Wait::Key(_) = wait {
                self.countdown = None;
                self.notice = None;
            }
            let items = self.items.len();
            match wait {
                Wait::Key(Press::Up) => self.selected = (self.selected + items - 1) % items,
                Wait::Key(Press::Down) => self.selected = (self.selected + 1) % items,
                Wait::Key(Press::Enter) => return Some(self.selected),
                Wait::Key(Press::Character(key)) => {
                    let chosen = (0..items).find(|&n| Choices::key(n) == Some(key));
                    if chosen.is_some() {
                        return chosen;
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
    });
    let entry = &choices.entries[index];
    output::arguments(format_args!("CHOICE {} ({})\n", index + 1, entry.name));
    status::info(&format!("Starting {}", entry.name));
    entry.options.clone().into_bytes()
}

/// The menu of `choices` until one of them is chosen; its options. A
/// firmware entry chosen restarts the PC into it. `None` without console
/// input to choose with.
fn menu(choices: &Choices, held: Option<&str>) -> Option<Vec<u8>> {
    let mut menu = Menu::new(choices, held);
    loop {
        let index = menu.run()?;
        match &menu.items[index] {
            Item::Choice(n, _) => return Some(chosen(choices, *n)),
            Item::Firmware(entry) => {
                output::arguments(format_args!("CHOICE firmware entry ({})\n", entry.name));
                menu.notice = Some(entries::start(entry.number));
            }
        }
    }
}

/// The options to boot: the chosen entry's, or `options` (`stela.cfg`).
/// `held` is why the default boot can only wait for the setup restore, when
/// it can.
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
    menu(&choices, None).unwrap_or_else(|| chosen(&choices, 0))
}

/// Wait at the menu after `reason`, with no countdown, as LLB waits in
/// recovery mode for a restore host: the machine can only be set up. The
/// setup entry starts highlighted; any entry may be chosen, and one that
/// cannot boot either returns here. Returns the chosen entry's options;
/// `None` when the volume has no choices or no console input to choose with.
pub fn hold(volume: &mut FileSystem, reason: &str) -> Option<Vec<u8>> {
    let choices = read(volume)?;
    output::arguments(format_args!("HOLD {reason}\n"));
    menu(&choices, Some(reason))
}
