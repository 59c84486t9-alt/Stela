//! Endpoint3 uses bits55:48; reporting endpoint4 uses a different class codec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Command {
    Primary(u64), Filter(u64), Consumed(u32), Reset, Disable, Enable,
    RequestFlush, HostReady, FilterChanged, Unknown,
}
impl Command {
    pub(super) fn decode(raw: u64) -> Self {
        match ((raw>>48)&0xff) as u8 {
            1=>Self::Primary(raw&0x0000_ffff_ffff_ffff),
            2=>Self::Filter(raw&0x0000_ffff_ffff_ffff),
            3=>Self::Consumed(raw as u32),4=>Self::Reset,5=>Self::Disable,
            6=>Self::Enable,7=>Self::RequestFlush,8=>Self::HostReady,
            9=>Self::FilterChanged,_=>Self::Unknown,
        }
    }
}
/// Source101f534 writes bytes8..31 first, narrowing each retained u64 arg to
/// low32. Timestamp is a separate final actual write after DMB ISH.
pub(super) fn encode_body(event:u32,thread:u32,args:[u64;4])->[u8;24] {
    let mut body=[0;24];
    body[..4].copy_from_slice(&event.to_le_bytes());
    body[4..8].copy_from_slice(&thread.to_le_bytes());
    for (out,arg) in body[8..].chunks_exact_mut(4).zip(args) {
        out.copy_from_slice(&(arg as u32).to_le_bytes());
    }
    body
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn endpoint3_classes_are_independent_and_arguments_narrow_to_low32() {
        assert_eq!(Command::decode(0x0001_abcd_1234_5000),Command::Primary(0xabcd_1234_5000));
        assert_eq!(Command::decode(0x0003_ffff_0000_0007),Command::Consumed(7));
        assert_eq!(Command::decode(0x0040_0000_0000_0000),Command::Unknown);
        let body=encode_body(0x1234,0xdead,[0x1234_5678_abcd_ef01,2,u64::MAX,4]);
        assert_eq!(&body[..8],&[0x34,0x12,0,0,0xad,0xde,0,0]);
        assert_eq!(&body[8..12],&0xabcd_ef01u32.to_le_bytes());
        assert_eq!(&body[16..20],&u32::MAX.to_le_bytes());
    }
}
