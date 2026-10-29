//! Strict, bounded DER cursor for SEP firmware and keystore protocols.
//! X.690 definite, minimal lengths/tags; no BER normalization before hashing.
use crate::Result;
use stela_contracts::refuse;

#[derive(Clone, Copy, Debug)]
pub(super) struct Element<'a> {
    pub tag: u32,
    pub class: u8,
    pub constructed: bool,
    pub value: &'a [u8],
    pub encoded: &'a [u8],
}

pub(super) struct Cursor<'a>(pub &'a [u8]);

impl<'a> Cursor<'a> {
    pub fn next(&mut self) -> Result<Element<'a>> {
        let original = self.0;
        let mut at = 0;
        let mut byte = || {
            let b = *original.get(at).ok_or(refuse!("SEP DER is truncated"))?;
            at += 1;
            Ok::<_, stela_contracts::Refusal>(b)
        };
        let first = byte()?;
        let mut tag = u32::from(first & 31);
        if tag == 31 {
            tag = 0;
            let mut b = byte()?;
            if b & 127 == 0 {
                return Err(refuse!("SEP DER tag is not minimal"));
            }
            loop {
                tag = tag
                    .checked_mul(128)
                    .and_then(|n| n.checked_add(u32::from(b & 127)))
                    .ok_or(refuse!("SEP DER tag overflows"))?;
                if b & 128 == 0 {
                    break;
                }
                b = byte()?;
            }
            if tag < 31 {
                return Err(refuse!("SEP DER tag is not minimal"));
            }
        }
        let first_length = byte()?;
        let length = if first_length < 128 {
            usize::from(first_length)
        } else {
            let width = usize::from(first_length & 127);
            if !(1..=4).contains(&width) {
                return Err(refuse!("SEP DER length is indefinite or oversized"));
            }
            let mut length = 0usize;
            for index in 0..width {
                let b = byte()?;
                if index == 0 && b == 0 {
                    return Err(refuse!("SEP DER length is not minimal"));
                }
                length = length
                    .checked_mul(256)
                    .and_then(|n| n.checked_add(usize::from(b)))
                    .ok_or(refuse!("SEP DER length overflows"))?;
            }
            if length < 128 {
                return Err(refuse!("SEP DER length is not minimal"));
            }
            length
        };
        let end = at
            .checked_add(length)
            .ok_or(refuse!("SEP DER extent overflows"))?;
        let encoded = original
            .get(..end)
            .ok_or(refuse!("SEP DER value is truncated"))?;
        self.0 = &original[end..];
        Ok(Element {
            tag,
            class: first >> 6,
            constructed: first & 32 != 0,
            value: &encoded[at..],
            encoded,
        })
    }

    pub fn take(&mut self, tag: u32) -> Result<Element<'a>> {
        let element = self.next()?;
        let constructed = matches!(tag, 16 | 17);
        if element.class != 0 || element.tag != tag || element.constructed != constructed {
            return Err(refuse!("SEP DER field has an unexpected tag"));
        }
        Ok(element)
    }

    pub fn end(self) -> Result<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(refuse!("SEP DER has trailing fields"))
        }
    }
}

#[cfg(test)]
pub(super) fn sequence(bytes: &[u8]) -> Result<Cursor<'_>> {
    let mut cursor = Cursor(bytes);
    let element = cursor.take(16)?;
    cursor.end()?;
    Ok(Cursor(element.value))
}

pub(super) fn unsigned(bytes: &[u8]) -> Result<&[u8]> {
    let first = *bytes.first().ok_or(refuse!("SEP DER integer is empty"))?;
    if first & 128 != 0 {
        return Err(refuse!("SEP DER integer is negative"));
    }
    if bytes.len() > 1 && first == 0 {
        if bytes[1] & 128 == 0 {
            return Err(refuse!("SEP DER integer is not minimal"));
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
