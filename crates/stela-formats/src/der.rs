//! Bounded DER cursor for firmware, certificates, and signed containers.
//! X.690 definite, minimal lengths/tags; no BER normalization before hashing.

/// A structural DER failure, including the offending field when available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Truncated {
        offset: usize,
    },
    NonMinimalTag,
    TagOverflow,
    LengthWidth {
        bytes: usize,
    },
    NonMinimalLength,
    LengthOverflow,
    ExtentOverflow,
    ValueTruncated {
        header: usize,
        bytes: usize,
        available: usize,
    },
    UnexpectedTag {
        expected: u32,
        found: u32,
        class: u8,
        constructed: bool,
    },
    TrailingFields {
        bytes: usize,
    },
    EmptyInteger,
    NegativeInteger,
    NonMinimalInteger,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated { offset } => write!(f, "DER is truncated at {offset:#x}"),
            Self::NonMinimalTag => f.write_str("DER tag is not minimal"),
            Self::TagOverflow => f.write_str("DER tag overflows"),
            Self::LengthWidth { bytes } => {
                write!(f, "DER length width {bytes} is indefinite or oversized")
            }
            Self::NonMinimalLength => f.write_str("DER length is not minimal"),
            Self::LengthOverflow => f.write_str("DER length overflows"),
            Self::ExtentOverflow => f.write_str("DER extent overflows"),
            Self::ValueTruncated {
                header,
                bytes,
                available,
            } => write!(
                f,
                "DER value needs {bytes} bytes after header {header}, container has {available}"
            ),
            Self::UnexpectedTag {
                expected,
                found,
                class,
                constructed,
            } => write!(
                f,
                "DER expected tag {expected}, found class {class} tag {found} constructed={constructed}"
            ),
            Self::TrailingFields { bytes } => write!(f, "DER has {bytes} trailing bytes"),
            Self::EmptyInteger => f.write_str("DER integer is empty"),
            Self::NegativeInteger => f.write_str("DER integer is negative"),
            Self::NonMinimalInteger => f.write_str("DER integer is not minimal"),
        }
    }
}

impl core::error::Error for Error {}

#[derive(Clone, Copy, Debug)]
pub struct Element<'a> {
    pub tag: u32,
    pub class: u8,
    pub constructed: bool,
    pub value: &'a [u8],
    pub encoded: &'a [u8],
}

pub struct Cursor<'a>(pub &'a [u8]);

impl<'a> Cursor<'a> {
    pub fn next_element(&mut self) -> Result<Element<'a>, Error> {
        let original = self.0;
        let mut at = 0;
        let mut byte = || {
            let b = *original.get(at).ok_or(Error::Truncated { offset: at })?;
            at += 1;
            Ok::<_, Error>(b)
        };
        let first = byte()?;
        let mut tag = u32::from(first & 31);
        if tag == 31 {
            tag = 0;
            let mut b = byte()?;
            if b & 127 == 0 {
                return Err(Error::NonMinimalTag);
            }
            loop {
                tag = tag
                    .checked_mul(128)
                    .and_then(|n| n.checked_add(u32::from(b & 127)))
                    .ok_or(Error::TagOverflow)?;
                if b & 128 == 0 {
                    break;
                }
                b = byte()?;
            }
            if tag < 31 {
                return Err(Error::NonMinimalTag);
            }
        }
        let first_length = byte()?;
        let length = if first_length < 128 {
            usize::from(first_length)
        } else {
            let width = usize::from(first_length & 127);
            if !(1..=4).contains(&width) {
                return Err(Error::LengthWidth { bytes: width });
            }
            let mut length = 0usize;
            for index in 0..width {
                let b = byte()?;
                if index == 0 && b == 0 {
                    return Err(Error::NonMinimalLength);
                }
                length = length
                    .checked_mul(256)
                    .and_then(|n| n.checked_add(usize::from(b)))
                    .ok_or(Error::LengthOverflow)?;
            }
            if length < 128 {
                return Err(Error::NonMinimalLength);
            }
            length
        };
        let end = at.checked_add(length).ok_or(Error::ExtentOverflow)?;
        let encoded = original.get(..end).ok_or(Error::ValueTruncated {
            header: at,
            bytes: length,
            available: original.len(),
        })?;
        self.0 = &original[end..];
        Ok(Element {
            tag,
            class: first >> 6,
            constructed: first & 32 != 0,
            value: &encoded[at..],
            encoded,
        })
    }

    pub fn take(&mut self, tag: u32) -> Result<Element<'a>, Error> {
        let element = self.next_element()?;
        let constructed = matches!(tag, 16 | 17);
        if element.class != 0 || element.tag != tag || element.constructed != constructed {
            return Err(Error::UnexpectedTag {
                expected: tag,
                found: element.tag,
                class: element.class,
                constructed: element.constructed,
            });
        }
        Ok(element)
    }

    pub fn end(self) -> Result<(), Error> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(Error::TrailingFields {
                bytes: self.0.len(),
            })
        }
    }
}

pub fn sequence(bytes: &[u8]) -> Result<Cursor<'_>, Error> {
    let mut cursor = Cursor(bytes);
    let element = cursor.take(16)?;
    cursor.end()?;
    Ok(Cursor(element.value))
}

pub fn unsigned(bytes: &[u8]) -> Result<&[u8], Error> {
    let first = *bytes.first().ok_or(Error::EmptyInteger)?;
    if first & 128 != 0 {
        return Err(Error::NegativeInteger);
    }
    if bytes.len() > 1 && first == 0 {
        if bytes[1] & 128 == 0 {
            return Err(Error::NonMinimalInteger);
        }
        Ok(&bytes[1..])
    } else {
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_preserves_signed_encoding_and_rejects_noncanonical_inputs() {
        let bytes = b"\x30\x03\x02\x01\x7f";
        let mut cursor = sequence(bytes).unwrap();
        let field = cursor.take(2).unwrap();
        assert_eq!(field.encoded, &bytes[2..]);
        assert_eq!(unsigned(field.value), Ok(b"\x7f".as_slice()));
        cursor.end().unwrap();
        for bad in [
            b"\x30\x80\0\0".as_slice(),
            b"\x30\x81\x03\x02\x01\0",
            b"\x30\x82\0\x80",
            b"\x30\x02\0",
            b"\xff\x80\x1f\0",
            b"\x1f\x01\0",
            b"\x30\0\0",
        ] {
            assert!(sequence(bad).is_err());
        }
        for bad in [b"".as_slice(), b"\x80", b"\0\x7f"] {
            assert!(unsigned(bad).is_err());
        }
        assert_eq!(unsigned(b"\0\x80"), Ok(b"\x80".as_slice()));
        assert!(Cursor(b"\x10\0").take(16).is_err());
        assert!(Cursor(b"\x22\0").take(2).is_err());
    }
}
