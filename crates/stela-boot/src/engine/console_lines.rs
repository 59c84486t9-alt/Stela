//! Bounded guest UART text for the serial log and status display.
//!
//! LF ends a line and CR is normalized away, as on the mount's text console.
//! Every other byte is represented: valid UTF-8 stays readable; controls,
//! invalid UTF-8 and literal backslashes use unambiguous escapes. A full
//! fragment is emitted before accepting the next byte, never instead of it.
use alloc::{string::String, vec::Vec};
use core::fmt::Write;

/// Large enough for ordinary kernel panic and driver diagnostics. This is
/// a logging bound, not an architectural UART or guest line-length limit.
const FRAGMENT_BYTES: usize = 1024;

pub struct Line {
    pub text: String,
    pub bytes: usize,
    pub complete: bool,
    pub beginning: bool,
}

#[derive(Default)]
pub struct Lines {
    bytes: Vec<u8>,
    continuing: bool,
}

impl Lines {
    /// Accept one byte, returning an ended line or a full fragment. Source
    /// bytes past the fragment boundary remain in the next fragment.
    pub fn push(&mut self, byte: u8) -> Option<Line> {
        if byte == b'\r' {
            return None;
        }
        if byte == b'\n' {
            return Some(self.take(self.bytes.len(), true));
        }
        let full = (self.bytes.len() == FRAGMENT_BYTES).then(|| {
            // Keep an incomplete UTF-8 suffix with the next byte, so a
            // valid character is not turned into escaped fragments.
            let end = (self.bytes.len().saturating_sub(3)..self.bytes.len())
                .find(|&start| {
                    core::str::from_utf8(&self.bytes[start..])
                        .is_err_and(|error| error.valid_up_to() == 0 && error.error_len().is_none())
                })
                .unwrap_or(self.bytes.len());
            self.take(end, false)
        });
        self.bytes.push(byte);
        full
    }

    fn take(&mut self, end: usize, complete: bool) -> Line {
        let line = Line {
            text: escaped(&self.bytes[..end]),
            bytes: end,
            complete,
            beginning: !self.continuing,
        };
        self.bytes.drain(..end);
        self.continuing = !complete;
        line
    }
}

/// The earliest panic message observed on the UART. Nested-panic metadata
/// supplies a fallback only when no earlier panic header was received.
#[derive(Default)]
pub struct Panic {
    first: Option<String>,
    nested: bool,
}

impl Panic {
    pub const fn new() -> Self {
        Self {
            first: None,
            nested: false,
        }
    }

    pub fn observe(&mut self, line: &Line) {
        if self.first.is_some() || !line.beginning {
            return;
        }
        let nested = core::mem::take(&mut self.nested);
        let header = line
            .text
            .strip_prefix("panic(")
            .and_then(|rest| rest.split_once("): "))
            .map(|(_, message)| message);
        let message = header.or_else(|| {
            (nested
                && !line.text.trim().is_empty()
                && line.text.trim() != "<end nested panic string>")
                .then(|| {
                    line.text
                        .split_once(" (saved state")
                        .map_or(line.text.as_str(), |(message, _)| message)
                })
        });
        if let Some(message) = message {
            let mut message: String = message.replace("\" \"", "").replace('"', "").trim().into();
            if !line.complete {
                message += " [continued in guest log]";
            }
            self.first = Some(message);
        } else {
            self.nested = line.text.trim() == "Nested panic string:";
        }
    }

    pub fn message(&self) -> Option<&str> {
        self.first.as_deref()
    }
}

fn escaped(mut bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len());
    while !bytes.is_empty() {
        let (valid, invalid) = match core::str::from_utf8(bytes) {
            Ok(valid) => (valid, 0),
            Err(error) => {
                let valid = core::str::from_utf8(&bytes[..error.valid_up_to()])
                    .expect("UTF-8 error identifies a valid prefix");
                (
                    valid,
                    error.error_len().unwrap_or(bytes.len() - valid.len()),
                )
            }
        };
        for character in valid.chars() {
            match character {
                '\\' => text.push_str("\\\\"),
                character if character.is_ascii_control() => {
                    let _ = write!(text, "\\x{:02x}", character as u8);
                }
                character if character.is_control() => {
                    let _ = write!(text, "\\u{{{:x}}}", u32::from(character));
                }
                character => text.push(character),
            }
        }
        bytes = &bytes[valid.len()..];
        for byte in &bytes[..invalid] {
            let _ = write!(text, "\\x{byte:02x}");
        }
        bytes = &bytes[invalid..];
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};

    fn lines(bytes: &[u8]) -> Vec<String> {
        let mut console = Lines::default();
        bytes
            .iter()
            .filter_map(|&byte| console.push(byte).map(|line| line.text))
            .collect()
    }

    #[test]
    fn ordinary_text_and_crlf_keep_their_console_meaning() {
        assert_eq!(lines(b"first\r\n\nsecond\n"), ["first", "", "second"]);
        assert_eq!(
            lines("UTF-8: café 日本語\n".as_bytes()),
            ["UTF-8: café 日本語"]
        );
    }

    #[test]
    fn fragment_boundaries_keep_every_incoming_byte() {
        for length in [
            FRAGMENT_BYTES - 1,
            FRAGMENT_BYTES,
            FRAGMENT_BYTES + 1,
            3 * FRAGMENT_BYTES + 1,
        ] {
            let mut source = vec![b'x'; length];
            source.push(b'\n');
            let parts = lines(&source);
            assert!(parts.iter().all(|part| part.len() <= FRAGMENT_BYTES));
            assert_eq!(parts.concat().as_bytes(), &source[..length]);
        }
        let mut source = vec![b'x'; FRAGMENT_BYTES];
        source.extend_from_slice(b"!\nnext\n");
        let parts = lines(&source);
        assert_eq!(&parts[1..], ["!", "next"]);
    }

    #[test]
    fn fragments_disclose_their_boundary_without_inventing_a_source_newline() {
        let mut console = Lines::default();
        for _ in 0..FRAGMENT_BYTES {
            assert!(console.push(b'x').is_none());
        }
        let fragment = console.push(b'!').unwrap();
        assert_eq!(fragment.bytes, FRAGMENT_BYTES);
        assert!(!fragment.complete);
        assert!(fragment.beginning);
        let line = console.push(b'\n').unwrap();
        assert_eq!(line.text, "!");
        assert_eq!(line.bytes, 1);
        assert!(line.complete);
        assert!(!line.beginning);
        let next = console.push(b'\n').unwrap();
        assert!(next.beginning && next.complete);
    }

    #[test]
    fn binary_and_invalid_utf8_remain_visible_without_lossy_replacement() {
        assert_eq!(
            lines(b"zero=\0 esc=\x1b tab=\t del=\x7f bad=\xff\xc3 end\n"),
            ["zero=\\x00 esc=\\x1b tab=\\x09 del=\\x7f bad=\\xff\\xc3 end"]
        );
        assert_eq!(lines(b"literal=\\x00\n"), ["literal=\\\\x00"]);
        assert_eq!(lines("control=\u{85}\n".as_bytes()), ["control=\\u{85}"]);
    }

    #[test]
    fn a_multibyte_character_crossing_a_fragment_is_not_replaced_or_dropped() {
        let mut source = vec![b'x'; FRAGMENT_BYTES - 1];
        source.extend_from_slice("é\n".as_bytes());
        let parts = lines(&source);
        assert_eq!(parts[0].len(), FRAGMENT_BYTES - 1);
        assert_eq!(parts[1], "é");
    }

    fn panics(bytes: &[u8]) -> Panic {
        let mut lines = Lines::default();
        let mut panic = Panic::new();
        for &byte in bytes {
            if let Some(line) = lines.push(byte) {
                panic.observe(&line);
            }
        }
        panic
    }

    #[test]
    fn the_first_header_survives_nested_panic_text_and_repeated_headers() {
        let source = b"panic(cpu 0 caller 0x1000): primary write far=0x8020\n\
            Nested panic detected - entry count: 2\n\
            Nested panic string:\n\
            secondary sample far=0x90\n\
            <end nested panic string>\n\
            panic(cpu 0 caller 0x2000): secondary sample far=0x90\n";
        assert_eq!(panics(source).message(), Some("primary write far=0x8020"));
    }

    #[test]
    fn a_nested_message_is_a_fallback_when_no_prior_header_was_received() {
        assert_eq!(
            panics(
                b"Nested panic string:\nKernel data abort. at pc 0x1234 (saved state: 0x8000)\n\
                panic(cpu 0 caller 0x2000): later panic\n"
            )
            .message(),
            Some("Kernel data abort. at pc 0x1234")
        );
        assert_eq!(
            panics(
                b"Nested panic string:\n<end nested panic string>\n\
                panic(cpu 0 caller 0x1000): first actual message\n"
            )
            .message(),
            Some("first actual message")
        );
    }

    #[test]
    fn quote_normalization_preserves_the_first_panic_text() {
        assert_eq!(
            panics(b"panic(cpu 1 caller 0x1000): \"Unhandled error: \" \"STS=0\"\r\n").message(),
            Some("Unhandled error: STS=0")
        );
        assert!(
            panics(b"driver: panic(cpu 1 caller 0x1000): ordinary data\n")
                .message()
                .is_none()
        );
    }

    #[test]
    fn continuation_fragments_cannot_invent_a_new_panic_header_or_marker() {
        let mut source = vec![b'x'; FRAGMENT_BYTES];
        source.extend_from_slice(b"panic(cpu 0 caller 0x1000): not a separate line\n");
        assert!(panics(&source).message().is_none());
        source.truncate(FRAGMENT_BYTES);
        source.extend_from_slice(b"Nested panic string:\nordinary following line\n");
        assert!(panics(&source).message().is_none());
    }

    #[test]
    fn a_long_first_panic_has_an_explicit_excerpt_and_keeps_its_identity() {
        let mut source = b"panic(cpu 0 caller 0x1000): ".to_vec();
        source.extend(vec![b'x'; 2 * FRAGMENT_BYTES]);
        source.extend_from_slice(b"\npanic(cpu 0 caller 0x2000): later panic\n");
        let panic = panics(&source);
        let message = panic.message().unwrap();
        assert!(message.starts_with('x') && message.ends_with(" [continued in guest log]"));
        assert!(!message.contains("later panic"));
    }
}
