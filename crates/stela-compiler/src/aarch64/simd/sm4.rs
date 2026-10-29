//! Fixed-width SM4E and SM4EKEY (Arm FEAT_SM4).
use crate::aarch64::Unsupported;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Encrypt,
    ExpandKey,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub kind: Kind,
    pub destination: u8,
    pub input: u8,
    pub keys: u8,
}
pub fn decode(word: u32) -> Option<Result<Operand, Unsupported>> {
    let destination = (word & 31) as u8;
    let left = ((word >> 5) & 31) as u8;
    let (kind, input, keys) = if word & 0xfffffc00 == 0xcec08400 {
        (Kind::Encrypt, destination, left)
    } else if word & 0xffe0fc00 == 0xce60c800 {
        (Kind::ExpandKey, left, ((word >> 16) & 31) as u8)
    } else {
        return None;
    };
    Some(Ok(Operand {
        kind,
        destination,
        input,
        keys,
    }))
}
#[cfg(test)]
mod tests;
