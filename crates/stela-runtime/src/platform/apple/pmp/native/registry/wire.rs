//! Wire encodings of the PMP registry protocol: class 3 request and reply
//! words by `Kind` (init, add, remove, set), the class 4 incoming request and
//! the 88-byte entry descriptor.
use super::Configuration;
use crate::Result;
use stela_contracts::refuse;
#[derive(Clone, Copy)]
pub(super) enum Kind {
    Init,
    Add,
    Remove,
    Set,
}
impl Kind {
    fn kind(self) -> u64 {
        match self {
            Self::Init => 0,
            Self::Add => 2,
            Self::Remove => 4,
            Self::Set => 6,
        }
    }
    pub(super) fn request(self, body: u64) -> u64 {
        3 << 52 | self.kind() << 48 | body
    }
    pub(super) fn reply_word(self, body: u32) -> u64 {
        3 << 52 | (self.kind() + 1) << 48 | u64::from(body)
    }
    pub(super) fn reply(self, payload: u64) -> Result<u32> {
        if payload & !0xffff_ffff != self.reply_word(0) {
            return Err(refuse!(
                "PMP registry reply does not match its actual class3 waiter"
            ));
        }
        let body = payload as u32;
        if matches!(self, Self::Init) && body != 0 {
            return Err(refuse!("PMP registry init reply has unqualified body bits"));
        }
        Ok(body)
    }
}
pub(super) fn incoming(payload: u64) -> Result<usize> {
    if payload & !0xffff != 0x0046_0000_0000_0000 {
        return Err(refuse!(
            "PMP class4 request has unqualified kind or body bits"
        ));
    }
    Ok((payload & 0xffff) as usize)
}
pub(super) fn descriptor(configuration: &Configuration, bytes: usize, index: usize) -> [u8; 88] {
    let mut result = [0; 88];
    result[..48].copy_from_slice(&configuration.name);
    result[48..56].copy_from_slice(&configuration.unit);
    result[56..64].copy_from_slice(&configuration.value_type);
    result[64..72].copy_from_slice(&(bytes as u64).to_le_bytes());
    result[72..80].copy_from_slice(&(index as u64).to_le_bytes());
    result[80..88].copy_from_slice(&u64::from(configuration.flags >> 1 & 3).to_le_bytes());
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_class3_waiters_and_class4_callback_have_distinct_exact_fields() {
        assert_eq!(Kind::Init.request(0x1234_0000), 0x0030_0000_1234_0000);
        assert_eq!(Kind::Add.request(0x5678_0000), 0x0032_0000_5678_0000);
        assert_eq!(Kind::Remove.request(1023), 0x0034_0000_0000_03ff);
        assert_eq!(Kind::Set.reply_word(16384), 0x0037_0000_0000_4000);
        assert_eq!(incoming(0x0046_0000_0000_03ff), Ok(1023));
        for word in [
            0x0036_0000_0000_0000,
            0x0146_0000_0000_0000,
            0x0046_0000_0001_0000,
            0x0047_0000_0000_0000,
        ] {
            assert!(incoming(word).is_err());
        }
        for word in [
            0x0031_0000_0000_0000,
            0x0043_0000_0000_0000,
            0x0033_0001_0000_0000,
            0x0133_0000_0000_0000,
        ] {
            assert!(Kind::Add.reply(word).is_err());
        }
        assert!(Kind::Init.reply(0x0031_0000_0000_0001).is_err());
        assert_eq!(Kind::Add.reply(0x0033_0000_0000_4000), Ok(16384));
    }
}
