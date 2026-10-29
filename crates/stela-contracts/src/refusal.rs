//! Why a model refused a request: what it refused and the values that
//! decided it.
use core::fmt;

/// A refused request: a static description and up to two named values,
/// shown as `description (name=value, name=value)`.
///
/// Build one with [`refuse!`](crate::refuse), which names each value after
/// the expression that supplies it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    what: &'static str,
    fields: [Option<(&'static str, Value)>; 2],
}

/// A value a refusal reports. Registers, addresses and raw values show in
/// hex; indices and counts (`usize`) in decimal; names and paths as text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Hex(u64),
    Count(u64),
    Flag(bool),
    Name(&'static str),
    /// A name read from data, such as a path or a node name.
    Text(alloc::string::String),
}

impl Refusal {
    pub const fn new(what: &'static str) -> Self {
        Self {
            what,
            fields: [None, None],
        }
    }

    /// Add a named value; [`refuse!`](crate::refuse) admits two at most.
    pub fn with(mut self, name: &'static str, value: impl Into<Value>) -> Self {
        let slot = self.fields.iter_mut().find(|slot| slot.is_none());
        *slot.expect("a refusal reports two values at most") = Some((name, value.into()));
        self
    }

    /// The description, without its values.
    pub const fn what(&self) -> &'static str {
        self.what
    }

    /// The value reported under `name`.
    pub fn value(&self, name: &str) -> Option<Value> {
        self.fields
            .iter()
            .flatten()
            .find(|(field, _)| *field == name)
            .map(|(_, value)| value.clone())
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.what)?;
        for (index, (name, value)) in self.fields.iter().flatten().enumerate() {
            f.write_str(if index == 0 { " (" } else { ", " })?;
            write!(f, "{name}={value}")?;
        }
        if self.fields[0].is_some() {
            f.write_str(")")?;
        }
        Ok(())
    }
}

impl core::error::Error for Refusal {}

impl From<&'static str> for Refusal {
    fn from(what: &'static str) -> Self {
        Self::new(what)
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hex(value) => write!(f, "{value:#x}"),
            Self::Count(value) => write!(f, "{value}"),
            Self::Flag(value) => write!(f, "{value}"),
            Self::Name(value) => f.write_str(value),
            Self::Text(value) => f.write_str(value),
        }
    }
}

macro_rules! hex {
    ($($ty:ty),+) => {$(
        impl From<$ty> for Value {
            fn from(value: $ty) -> Self {
                Self::Hex(value.into())
            }
        }
    )+};
}
hex!(u8, u16, u32, u64);

impl From<usize> for Value {
    fn from(value: usize) -> Self {
        Self::Count(value as u64)
    }
}

impl From<alloc::string::String> for Value {
    fn from(value: alloc::string::String) -> Self {
        Self::Text(value)
    }
}

impl From<bool> for Value {
    fn from(value: bool) -> Self {
        Self::Flag(value)
    }
}

impl From<&'static str> for Value {
    fn from(value: &'static str) -> Self {
        Self::Name(value)
    }
}

/// Build a [`Refusal`]: `refuse!("what")`, `refuse!("what", offset)` or
/// `refuse!("what", kind = message.kind, offset)`. A value is named after
/// its variable, or after the name given before `=`.
#[macro_export]
macro_rules! refuse {
    ($what:expr $(,)?) => {
        $crate::refusal::Refusal::new($what)
    };
    ($what:expr, $a:ident $(= $av:expr)? $(,)?) => {
        $crate::refusal::Refusal::new($what).with(stringify!($a), $crate::refuse!(@ $a $($av)?))
    };
    ($what:expr, $a:ident $(= $av:expr)?, $b:ident $(= $bv:expr)? $(,)?) => {
        $crate::refusal::Refusal::new($what)
            .with(stringify!($a), $crate::refuse!(@ $a $($av)?))
            .with(stringify!($b), $crate::refuse!(@ $b $($bv)?))
    };
    (@ $name:ident) => {
        $name
    };
    (@ $name:ident $value:expr) => {
        $value
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
    fn shows_values_by_name_in_hex_or_decimal() {
        let offset = 0x40_u64;
        let refusal = refuse!("register outside the window", offset, pe = 3_usize);
        assert_eq!(
            refusal.to_string(),
            "register outside the window (offset=0x40, pe=3)"
        );
        assert_eq!(refusal.what(), "register outside the window");
        assert_eq!(refusal.value("pe"), Some(Value::Count(3)));
        assert_eq!(refusal.value("width"), None);
    }

    #[test]
    fn stays_within_the_large_error_limit() {
        assert!(core::mem::size_of::<Refusal>() <= 128);
    }
}
