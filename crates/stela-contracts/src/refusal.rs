//! Why a model refused a request: what it refused and the values that
//! decided it.
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

/// A refused request: a static description, the named values that decided
/// it and, when it explains a nested refusal, that cause.
///
/// The description is a template. `{name}` shows a value as `format!` would
/// (`{name:#x}`, `{name:08x}` and the other integer radix forms included);
/// values the description does not name follow it as
/// `(name=value, name=value)`, and a cause follows as `: cause`. Build one
/// with [`refuse!`](crate::refuse), which names each value after the
/// expression that supplies it.
#[derive(Clone)]
pub struct Refusal {
    what: &'static str,
    fields: Vec<(&'static str, Value)>,
    cause: Option<Box<Refusal>>,
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
            cause: None,
        }
    }

    /// This refusal as what was being done when `cause` was refused.
    pub fn because(mut self, cause: Refusal) -> Self {
        self.cause = Some(Box::new(cause));
        self
    }

    /// The nested refusal this one explains.
    pub fn cause(&self) -> Option<&Refusal> {
        self.cause.as_deref()
    }

    /// Add a named value.
    pub fn with(mut self, name: &'static str, value: &(impl ToValue + ?Sized)) -> Self {
        self.fields.push((name, value.to_value()));
        self
    }

    /// Add a named value in its `Display` form.
    pub fn display(mut self, name: &'static str, value: &(impl fmt::Display + ?Sized)) -> Self {
        self.fields
            .push((name, Value::Text(alloc::format!("{value}"))));
        self
    }

    /// Add a named value in its `Debug` form.
    pub fn debug(mut self, name: &'static str, value: &(impl fmt::Debug + ?Sized)) -> Self {
        self.fields
            .push((name, Value::Text(alloc::format!("{value:?}"))));
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
        if appended.peek().is_some() {
            for (index, (name, value)) in appended.enumerate() {
                f.write_str(if index == 0 { " (" } else { ", " })?;
                write!(f, "{name}=")?;
                value.write(f, None)?;
            }
            f.write_str(")")?;
        }
        match &self.cause {
            Some(cause) => write!(f, ": {cause}"),
            None => Ok(()),
        }
    }
}

/// Refusals are equal when they say the same thing, whether a value was
/// written into the template or reported beside it.
impl PartialEq for Refusal {
    fn eq(&self, other: &Self) -> bool {
        let same =
            self.what == other.what && self.fields == other.fields && self.cause == other.cause;
        same || self.to_string() == other.to_string()
    }
}

impl Eq for Refusal {}

/// The rendered description, so a refusal inside another value's `Debug`
/// reads as the message it reports.
impl fmt::Debug for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Refusal")
            .field(&format_args!("{self}"))
            .finish()
    }
}

impl core::error::Error for Refusal {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        self.cause.as_deref().map(|cause| cause as _)
    }
}

/// Say what was being done when a nested request was refused; `context`
/// runs only on failure.
pub trait Within<T> {
    fn within(self, context: impl FnOnce() -> Refusal) -> Result<T, Refusal>;
}

impl<T> Within<T> for Result<T, Refusal> {
    fn within(self, context: impl FnOnce() -> Refusal) -> Result<T, Refusal> {
        self.map_err(|cause| context().because(cause))
    }
}

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

impl ToValue for char {
    fn to_value(&self) -> Value {
        Value::Text((*self).into())
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

/// Build a [`Refusal`]: `refuse!("what")`, `refuse!("what {offset:#x}",
/// offset)` or `refuse!("what", kind = message.kind, offset)`. A value is
/// named after its variable, or after the name given before `=`, and read
/// by reference; `%name` and `name = %value` report its `Display` form,
/// `?name` and `name = ?value` its `Debug` form.
#[macro_export]
macro_rules! refuse {
    (@ $refusal:expr; $(,)?) => {
        $refusal
    };
    (@ $refusal:expr; %$name:ident $(, $($rest:tt)*)?) => {
        $crate::refuse!(@ $refusal.display(stringify!($name), &$name); $($($rest)*)?)
    };
    (@ $refusal:expr; $name:ident = %$value:expr $(, $($rest:tt)*)?) => {
        $crate::refuse!(@ $refusal.display(stringify!($name), &$value); $($($rest)*)?)
    };
    (@ $refusal:expr; ?$name:ident $(, $($rest:tt)*)?) => {
        $crate::refuse!(@ $refusal.debug(stringify!($name), &$name); $($($rest)*)?)
    };
    (@ $refusal:expr; $name:ident = ?$value:expr $(, $($rest:tt)*)?) => {
        $crate::refuse!(@ $refusal.debug(stringify!($name), &$value); $($($rest)*)?)
    };
    (@ $refusal:expr; $name:ident = $value:expr $(, $($rest:tt)*)?) => {
        $crate::refuse!(@ $refusal.with(stringify!($name), &$value); $($($rest)*)?)
    };
    (@ $refusal:expr; $name:ident $(, $($rest:tt)*)?) => {
        $crate::refuse!(@ $refusal.with(stringify!($name), &$name); $($($rest)*)?)
    };
    ($what:expr $(, $($values:tt)*)?) => {
        $crate::refuse!(@ $crate::refusal::Refusal::new($what); $($($values)*)?)
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

    #[test]
    fn refusals_that_say_the_same_thing_are_equal() {
        let die = 8u32;
        assert_eq!(refuse!("names die {die}", die), refuse!("names die 8"));
        assert_ne!(refuse!("names die {die}", die), refuse!("names die 0x8"));
    }

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
        let state = Some(3_u8);
        assert_eq!(
            refuse!("bad state {state}", ?state, kind = ?Some("hpm")).to_string(),
            "bad state Some(3) (kind=Some(\"hpm\"))"
        );
        let cause = refuse!("inner");
        assert_eq!(
            refuse!("outer: {cause}", %cause, at = %0x10_u8).to_string(),
            "outer: inner (at=16)"
        );
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
    fn follows_with_the_refusal_it_explains() {
        let path = "/arm-io/dart-disp0";
        let refusal = Err::<(), _>(refuse!("vm-base is not one 64-bit address"))
            .within(|| refuse!("{path}", path))
            .unwrap_err();
        assert_eq!(
            refusal.to_string(),
            "/arm-io/dart-disp0: vm-base is not one 64-bit address"
        );
        assert_eq!(
            refusal.cause().map(Refusal::what),
            Some("vm-base is not one 64-bit address")
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
