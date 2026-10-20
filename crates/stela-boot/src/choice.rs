//! The startup choices (`stela_loader::mount_interface`): when the boot
//! volume has `choices.cfg`, `stela.efi` lists its entries on the firmware
//! console and the UART, waits up to its timeout for an entry's key (Enter, or the
//! timeout, boots the first), and boots the chosen option line in place of
//! `stela.cfg`. A timeout of 0 opens the list only when a key is already
//! pressed, as a Mac shows its startup options only when asked. A file that
//! cannot be read or parsed is reported and `stela.cfg` boots, so a damaged
//! file never stops the default boot. A machine NVRAM holds in recovery
//! mode waits at the list with no timeout ([`hold`]).
use crate::output;
use alloc::{string::String, vec::Vec};
use core::{fmt::Write, time::Duration};
use stela_loader::mount_interface::{CHOICES_FILE, Choices};
use uefi::{
    CString16,
    boot::{self, EventType, TimerTrigger, Tpl},
    fs::{FileSystem, PathBuf},
    proto::console::text::Key,
};

/// Print to the UART and the firmware console, which is the screen until
/// boot services end.
fn show(text: &str) {
    output::arguments(format_args!("{text}"));
    uefi::system::with_stdout(|out| {
        let _ = out.write_str(text);
    });
}

/// What a wait for a key ended with.
enum Wait {
    Key(char),
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
fn pressed() -> Option<char> {
    match uefi::system::with_stdin(|input| input.read_key()).ok()? {
        Some(Key::Printable(character)) => Some(char::from(character)),
        Some(Key::Special(_)) => Some('\0'),
        None => None,
    }
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

/// `heading`, then every entry, numbered from 1.
fn list(choices: &Choices, heading: &str) -> String {
    let mut text = String::from(heading);
    for (n, entry) in choices.entries.iter().enumerate() {
        let key = Choices::key(n).unwrap_or('?');
        let _ = write!(text, "  {key}  {}\r\n", entry.name);
    }
    text
}

fn chosen(choices: &Choices, index: usize) -> Vec<u8> {
    let entry = &choices.entries[index];
    output::arguments(format_args!("CHOICE {} ({})\n", index + 1, entry.name));
    entry.options.clone().into_bytes()
}

/// The options to boot: the chosen entry's, or `options` (`stela.cfg`).
pub fn choose(volume: &mut FileSystem, options: Vec<u8>) -> Vec<u8> {
    let Some(choices) = read(volume) else {
        return options;
    };
    let index = match choices.timeout_seconds {
        // Only a key pressed before the list opens asks for it.
        0 if pressed().is_none() => 0,
        seconds => {
            let mut text = list(&choices, "\r\nStela startup options:\r\n");
            if seconds == 0 {
                text.push_str("Press an entry's key to choose, or Enter for 1.\r\n");
            } else {
                let _ = write!(
                    text,
                    "Press an entry's key to choose, or Enter for 1; 1 starts in {seconds} s.\r\n"
                );
            }
            show(&text);
            let mut timeout = (seconds > 0).then(|| Duration::from_secs(seconds.into()));
            loop {
                match key(timeout) {
                    Wait::Key(key) => match choices.chosen(key) {
                        Some(index) => break index,
                        // Any other key stops the countdown.
                        None => timeout = None,
                    },
                    Wait::Nothing => {}
                    Wait::Timeout | Wait::NoInput => break 0,
                }
            }
        }
    };
    chosen(&choices, index)
}

/// Wait at the startup choices, with no timeout and no default, as LLB
/// waits in recovery mode for a restore host: NVRAM holds the machine there
/// (`auto-boot=false`), as an interrupted restore leaves it. Returns the
/// chosen entry's options; `None` when the volume has no choices or no
/// console input to choose with.
pub fn hold(volume: &mut FileSystem) -> Option<Vec<u8>> {
    let choices = read(volume)?;
    let mut text = list(
        &choices,
        "\r\nThis Mac is in recovery mode: its last restore did not finish. Choose Install \
         macOS (Stela) to restore it again.\r\nStela startup options:\r\n",
    );
    text.push_str("Press an entry's key to choose.\r\n");
    show(&text);
    loop {
        match key(None) {
            Wait::Key(key) => {
                // An entry's key only: Enter would choose the default boot again.
                if let Some(index) = choices.chosen(key).filter(|_| key.is_ascii_alphanumeric()) {
                    return Some(chosen(&choices, index));
                }
            }
            Wait::Nothing | Wait::Timeout => {}
            Wait::NoInput => return None,
        }
    }
}
