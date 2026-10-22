//! Original PMPEndpoint1 class1, mac13j ApplePMPv2 memory handlers.
pub(super) const BODY: u64 = (1 << 48) - 1;
pub(super) const PAGE: u64 = 4096;
pub(super) const TABLE_BYTES: usize = 0x300;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    Init,
    Allocate,
    Free,
}
impl Kind {
    pub(super) fn request(self, body: u64) -> u64 {
        let kind = match self {
            Self::Init => 0,
            Self::Allocate => 2,
            Self::Free => 4,
        };
        1 << 52 | kind << 48 | body
    }
    pub(super) fn reply(self, payload: u64) -> Result<u64, &'static str> {
        let kind = match self {
            Self::Init => 1,
            Self::Allocate => 3,
            Self::Free => 5,
        };
        if payload >> 56 != 0 || payload >> 52 & 15 != 1 || payload >> 48 & 15 != kind {
            return Err("PMP memory reply does not match its actual class transaction");
        }
        let body = payload & BODY;
        if self == Self::Free && body != 0 {
            return Err("PMP memory free reply has unqualified body bits");
        }
        if self != Self::Free && !body.is_multiple_of(PAGE) {
            return Err("PMP memory reply is not aligned for its native mapping");
        }
        Ok(body)
    }
}

pub(super) fn allocation_bytes(bytes: u32) -> Result<u64, &'static str> {
    let rounded = (u64::from(bytes) + PAGE - 1) & !(PAGE - 1);
    if rounded > 0xff_ffff {
        return Err("PMP allocation exceeds the source request's 24-bit size field");
    }
    Ok(rounded)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_source_fields_never_truncate_sizes_or_credit_other_replies() {
        assert_eq!(Kind::Init.request(0), 0x0010_0000_0000_0000);
        assert_eq!(
            Kind::Allocate.request(allocation_bytes(4097).unwrap()),
            0x0012_0000_0000_2000
        );
        assert_eq!(Kind::Free.request(0x1234_5678_9000), 0x0014_1234_5678_9000);
        assert_eq!(allocation_bytes(0), Ok(0));
        assert_eq!(allocation_bytes(0xff_f000), Ok(0xff_f000));
        assert!(allocation_bytes(0xff_f001).is_err());
        assert!(allocation_bytes(u32::MAX).is_err());
        for payload in [
            0x0011_0000_0000_1000,
            0x0012_0000_0000_1000,
            0x0023_0000_0000_1000,
            0x0113_0000_0000_1000,
            0x0013_0000_0000_1001,
        ] {
            assert!(Kind::Allocate.reply(payload).is_err());
        }
        assert_eq!(Kind::Allocate.reply(0x0013_0000_0000_0000), Ok(0));
        assert_eq!(
            Kind::Allocate.reply(0x0013_1234_5678_9000),
            Ok(0x1234_5678_9000)
        );
        assert!(Kind::Free.reply(0x0015_0000_0000_0001).is_err());
    }
}
