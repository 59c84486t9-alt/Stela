//! A 16-byte identity in the canonical 8-4-4-4-12 text form, as boot options
//! and Thunderbolt routers name devices.
use core::fmt;

/// The identity's bytes in text order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Uuid(pub [u8; 16]);

impl Uuid {
    /// The bytes of four words, each stored little-endian, as a router's
    /// configuration space holds its UUID.
    pub fn from_le_words(words: [u32; 4]) -> Self {
        let mut bytes = [0; 16];
        for (chunk, word) in bytes.as_chunks_mut::<4>().0.iter_mut().zip(words) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        Self(bytes)
    }

    /// Parse the canonical 8-4-4-4-12 form.
    pub fn parse(text: &str) -> Option<Self> {
        let mut digits = text.bytes().filter(|byte| *byte != b'-');
        let dashes = text.bytes().enumerate().filter(|(_, byte)| *byte == b'-');
        if !dashes.map(|(index, _)| index).eq([8, 13, 18, 23]) {
            return None;
        }
        let mut bytes = [0; 16];
        for byte in &mut bytes {
            let high = char::from(digits.next()?).to_digit(16)?;
            let low = char::from(digits.next()?).to_digit(16)?;
            *byte = (high << 4 | low) as u8;
        }
        digits.next().is_none().then_some(Self(bytes))
    }
}

impl fmt::Display for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, byte) in self.0.iter().enumerate() {
            if matches!(index, 4 | 6 | 8 | 10) {
                f.write_str("-")?;
            }
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}
