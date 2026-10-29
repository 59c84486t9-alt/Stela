//! Why a model refused a request: what it refused and the values that
//! decided it.
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

/// A refused request: a static description and the named values that
/// decided it.
///
/// The description is a template. `{name}` shows a value as `format!` would
/// (`{name:#x}`, `{name:08x}` and the other integer radix forms included);
/// values the description does not name follow it as
/// `(name=value, name=value)`. Build one with [`refuse!`](crate::refuse),
/// which names each value after the expression that supplies it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    what: &'static str,
    fields: Vec<(&'static str, Value)>,
}

/// A value a refusal reports. Appended after the description, registers,
/// addresses and raw values show in hex, indices and counts (`usize`) in
/// decimal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Hex(u64),
    Count(u64),
    Signed(i64),
    Flag(bool),
    Text(String),
}

impl Refusal {
    pub const fn new(what: &'static str) -> Self {
        Self {
            what,
            fields: Vec::new(),
        }
    }

    /// Add a named value.
    pub fn with(mut self, name: &'static str, value: &(impl ToValue + ?Sized)) -> Self {
        self.fields.push((name, value.to_value()));
        self
    }

    /// The description template, without its values.
    pub const fn what(&self) -> &'static str {
        self.what
    }

    /// The value reported under `name`.
    pub fn value(&self, name: &str) -> Option<&Value> {
        self.fields
            .iter()
            .find(|(field, _)| *field == name)
            .map(|(_, value)| value)
    }
}

/// A piece of a description template.
enum Piece<'a> {
    Text(&'a str),
    Field { name: &'a str, spec: &'a str },
}

/// Split a template into text and `{name:spec}` fields; `{{` and `}}` are
/// literal braces.
fn pieces(template: &str) -> impl Iterator<Item = Piece<'_>> {
    let mut rest = template;
    core::iter::from_fn(move || {
        if rest.is_empty() {
            return None;
        }
        if let Some(tail) = rest.strip_prefix("{{") {
            rest = tail;
            return Some(Piece::Text("{"));
        }
        if let Some(tail) = rest.strip_prefix("}}") {
            rest = tail;
            return Some(Piece::Text("}"));
        }
        if rest.starts_with('{')
            && let Some(end) = rest.find('}')
        {
            let field = &rest[1..end];
            rest = &rest[end + 1..];
            let (name, spec) = field.split_once(':').unwrap_or((field, ""));
            return Some(Piece::Field { name, spec });
        }
        let end = rest[1..].find(['{', '}']).map_or(rest.len(), |at| at + 1);
        let (text, tail) = rest.split_at(end);
        rest = tail;
        Some(Piece::Text(text))
    })
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for piece in pieces(self.what) {
            match piece {
                Piece::Text(text) => f.write_str(text)?,
                Piece::Field { name, spec } => match self.value(name) {
                    Some(value) => value.write(f, Some(spec))?,
                    None => write!(f, "{{{name}}}")?,
                },
            }
        }
        let named = |name: &str| {
            pieces(self.what)
                .any(|piece| matches!(piece, Piece::Field { name: field, .. } if field == name))
        };
        let mut appended = self
            .fields
            .iter()
            .filter(|(name, _)| !named(name))
            .peekable();
        if appended.peek().is_none() {
            return Ok(());
        }
        for (index, (name, value)) in appended.enumerate() {
            f.write_str(if index == 0 { " (" } else { ", " })?;
            write!(f, "{name}=")?;
            value.write(f, None)?;
        }
        f.write_str(")")
    }
}

impl core::error::Error for Refusal {}

impl From<&'static str> for Refusal {
    fn from(what: &'static str) -> Self {
        Self::new(what)
    }
}

impl Value {
    /// Show the value under a template's format spec, or in its natural
    /// form when it follows the description.
    fn write(&self, f: &mut fmt::Formatter<'_>, spec: Option<&str>) -> fmt::Result {
        let integer = match *self {
            Self::Hex(value) | Self::Count(value) => value,
            Self::Signed(value) => return write!(f, "{value}"),
            Self::Flag(value) => return write!(f, "{value}"),
            Self::Text(ref value) => return f.write_str(value),
        };
        let spec = match spec {
            Some(spec) => spec,
            None if matches!(self, Self::Hex(_)) => "#x",
            None => "",
        };
        let (alternate, rest) = match spec.strip_prefix('#') {
            Some(rest) => (true, rest),
            None => (false, spec),
        };
        let (width, radix) = rest.split_at(rest.len().saturating_sub(1));
        let width = width.trim_start_matches('0').parse().unwrap_or(0);
        match (alternate, radix) {
            (true, "x") => write!(f, "{integer:#0width$x}"),
            (false, "x") => write!(f, "{integer:0width$x}"),
            (true, "X") => write!(f, "{integer:#0width$X}"),
            (false, "X") => write!(f, "{integer:0width$X}"),
            _ => write!(f, "{integer}"),
        }
    }
}

/// A value a refusal can report, read by reference so that reporting it
/// never moves it out of the caller.
pub trait ToValue {
    fn to_value(&self) -> Value;
}

macro_rules! to_value {
    ($variant:ident: $($ty:ty),+) => {$(
        impl ToValue for $ty {
            fn to_value(&self) -> Value {
                Value::$variant((*self).into())
            }
        }
    )+};
}
to_value!(Hex: u8, u16, u32, u64);
to_value!(Signed: i8, i16, i32, i64);

impl ToValue for bool {
    fn to_value(&self) -> Value {
        Value::Flag(*self)
    }
}

impl ToValue for usize {
    fn to_value(&self) -> Value {
        Value::Count(*self as u64)
    }
}

impl ToValue for isize {
    fn to_value(&self) -> Value {
        Value::Signed(*self as i64)
    }
}

impl ToValue for str {
    fn to_value(&self) -> Value {
        Value::Text(self.into())
    }
}

impl ToValue for String {
    fn to_value(&self) -> Value {
        Value::Text(self.clone())
    }
}

impl ToValue for alloc::borrow::Cow<'_, str> {
    fn to_value(&self) -> Value {
        Value::Text(self.as_ref().into())
    }
}

impl<T: ToValue + ?Sized> ToValue for &T {
    fn to_value(&self) -> Value {
        (**self).to_value()
    }
}

/// Build a [`Refusal`]: `refuse!("what")`, `refuse!("what {offset:#x}", /// offset)` or `refuse!("what", kind = message.kind, offset)`. A value is
/// named after its variable, or after the name given before `=`, and read
/// by reference.
#[macro_export]
macro_rules! refuse {
    (@ $name:ident) => {
        $name
    };
    (@ $name:ident $value:expr) => {
        $value
    };
    ($what:expr $(, $name:ident $(= $value:expr)?)* $(,)?) => {
        $crate::refusal::Refusal::new($what)
            $(.with(stringify!($name), &$crate::refuse!(@ $name $($value)?)))*
    };
}

/// Return the [`refuse!`](crate::refuse) refusal of the remaining arguments,
/// converted into the function's error, unless `condition` holds.
#[macro_export]
macro_rules! require {
    ($condition:expr, $($refusal:tt)+) => {
        if !$condition {
            return Err($crate::refuse!($($refusal)+).into());
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn shows_the_description_alone_without_values() {
        assert_eq!(
            refuse!("AFK unknown message type").to_string(),
            "AFK unknown message type"
        );
    }

    #[test]
    fn appends_unnamed_values_in_hex_or_decimal() {
        let offset = 0x40_u64;
        let refusal = refuse!("register outside the window", offset, pe = 3_usize);
        assert_eq!(
            refusal.to_string(),
            "register outside the window (offset=0x40, pe=3)"
        );
        assert_eq!(refusal.what(), "register outside the window");
        assert_eq!(refusal.value("pe"), Some(&Value::Count(3)));
        assert_eq!(refusal.value("width"), None);
    }

    #[test]
    fn fills_named_values_with_their_format_spec() {
        let start = 0x1000_u64;
        let refusal = refuse!(
            "region {start:#x}..{end:010x} has {pages} pages ({{whole}})",
            start,
            end = 0x2000_u64,
            pages = 1_u32,
            owner = "SPTM"
        );
        assert_eq!(
            refusal.to_string(),
            "region 0x1000..0000002000 has 1 pages ({whole}) (owner=SPTM)"
        );
    }

    #[test]
    fn keeps_a_placeholder_without_a_value() {
        assert_eq!(refuse!("missing {name}").to_string(), "missing {name}");
    }

    #[test]
    fn stays_within_the_large_error_limit() {
        assert!(core::mem::size_of::<Refusal>() <= 128);
    }
}
