//! CDC NCM 1.0 transfer blocks in the 16-bit format (NTB16), the format a
//! function uses after reset: an NTH16 header, then NDP16 datagram pointer
//! tables, each naming its datagrams by offset and length.
//!
//! An IN block may hold several datagrams and several chained tables; an
//! OUT block here holds one datagram, placed as the function's NTB
//! parameters (GetNtbParameters) require.
use alloc::vec::Vec;

/// `GET_NTB_PARAMETERS` returns these 28 bytes.
pub const PARAMETER_BYTES: usize = 28;
/// The smallest `dwNtbInMaxSize` and `dwNtbOutMaxSize` a function may
/// report.
pub const MIN_BLOCK: usize = 2048;
/// `bmNtbFormatsSupported` bit 0: NTB16.
const NTB16: u16 = 1;
/// `"NCMH"`, the NTH16 signature.
const NTH16: u32 = u32::from_le_bytes(*b"NCMH");
const NTH16_BYTES: usize = 12;
/// `"NCM0"`, an NDP16 without CRCs; `"NCM1"` has them.
const NDP16: u32 = u32::from_le_bytes(*b"NCM0");
const NDP16_CRC: u32 = u32::from_le_bytes(*b"NCM1");
/// An NDP16's header: signature, wLength, wNextNdpIndex.
const NDP16_HEADER: usize = 8;
/// One datagram pointer: wDatagramIndex, wDatagramLength.
const POINTER: usize = 4;
/// The CRC-32 an `NCM1` datagram carries after its frame.
const CRC_BYTES: usize = 4;
/// NDPs and a block's chain are bounded so a malformed block cannot loop.
const MAX_TABLES: usize = 32;

/// The function's NTB parameters for the OUT direction, and its largest IN
/// block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Parameters {
    pub in_max: usize,
    pub out_max: usize,
    out_divisor: usize,
    out_remainder: usize,
    out_alignment: usize,
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

impl Parameters {
    /// The `GET_NTB_PARAMETERS` structure, refused when it
    /// names no NTB16 support, a block below the 2048-byte minimum, or a
    /// divisor or alignment that is not a power of two.
    pub fn parse(b: &[u8]) -> Result<Self, &'static str> {
        let field = |at| u16_at(b, at).map(usize::from);
        let (Some(formats), Some(in_max), Some(out_max)) =
            (u16_at(b, 2), u32_at(b, 4), u32_at(b, 16))
        else {
            return Err("short NTB parameters");
        };
        let (Some(out_divisor), Some(out_remainder), Some(out_alignment)) =
            (field(20), field(22), field(24))
        else {
            return Err("short NTB parameters");
        };
        if formats & NTB16 == 0 {
            return Err("NCM function without NTB16");
        }
        let (in_max, out_max) = (in_max as usize, out_max as usize);
        if in_max < MIN_BLOCK || out_max < MIN_BLOCK {
            return Err("NTB size below the 2048-byte minimum");
        }
        // A zero divisor or alignment imposes none.
        let out_divisor = out_divisor.max(1);
        let out_alignment = out_alignment.max(4);
        if !out_divisor.is_power_of_two() || !out_alignment.is_power_of_two() {
            return Err("NTB divisor or alignment not a power of two");
        }
        Ok(Self {
            in_max,
            out_max,
            out_divisor,
            out_remainder: out_remainder % out_divisor,
            out_alignment,
        })
    }

    /// One OUT block carrying `frame`: the NTH16, one NDP16 right after it
    /// at the required alignment, then the datagram at the first offset
    /// with the required remainder. `None` when it would exceed `out_max`.
    pub fn encode(&self, sequence: u16, frame: &[u8]) -> Option<Vec<u8>> {
        let table = NTH16_BYTES.next_multiple_of(self.out_alignment);
        let table_bytes = NDP16_HEADER + 2 * POINTER;
        let mut datagram = table + table_bytes;
        datagram += (self.out_remainder + self.out_divisor - datagram % self.out_divisor)
            % self.out_divisor;
        let total = datagram + frame.len();
        if total > self.out_max || total > usize::from(u16::MAX) {
            return None;
        }
        let mut block = alloc::vec![0u8; total];
        let put16 = |b: &mut [u8], at: usize, v: usize| {
            b[at..at + 2].copy_from_slice(&(v as u16).to_le_bytes())
        };
        block[..4].copy_from_slice(&NTH16.to_le_bytes());
        put16(&mut block, 4, NTH16_BYTES);
        put16(&mut block, 6, usize::from(sequence));
        put16(&mut block, 8, total);
        put16(&mut block, 10, table);
        block[table..table + 4].copy_from_slice(&NDP16.to_le_bytes());
        put16(&mut block, table + 4, table_bytes);
        // wNextNdpIndex 0, then this datagram and the zero terminator.
        put16(&mut block, table + NDP16_HEADER, datagram);
        put16(&mut block, table + NDP16_HEADER + 2, frame.len());
        block[datagram..].copy_from_slice(frame);
        Some(block)
    }
}

/// The datagrams of one IN block of `received` bytes, in order. A block
/// that is not a well-formed NTB16 refuses whole; a datagram past the
/// block's end refuses with it.
pub fn decode(received: &[u8]) -> Result<Vec<&[u8]>, &'static str> {
    if u32_at(received, 0) != Some(NTH16) || u16_at(received, 4) != Some(NTH16_BYTES as u16) {
        return Err("not an NTH16");
    }
    let (Some(length), Some(mut table)) = (u16_at(received, 8), u16_at(received, 10)) else {
        return Err("short NTH16");
    };
    // A block shorter than the transfer is its own length; zero means the
    // transfer's.
    let block = match usize::from(length) {
        0 => received,
        n => received.get(..n).ok_or("NTB longer than the transfer")?,
    };
    let mut datagrams = Vec::new();
    for _ in 0..MAX_TABLES {
        if table == 0 {
            return Ok(datagrams);
        }
        let at = usize::from(table);
        if at % 4 != 0 {
            return Err("misaligned NDP16");
        }
        let crc = match u32_at(block, at) {
            Some(NDP16) => 0,
            Some(NDP16_CRC) => CRC_BYTES,
            _ => return Err("not an NDP16"),
        };
        let (Some(bytes), Some(next)) = (u16_at(block, at + 4), u16_at(block, at + 6)) else {
            return Err("short NDP16");
        };
        let end = at + usize::from(bytes);
        if usize::from(bytes) < NDP16_HEADER + 2 * POINTER || end > block.len() {
            return Err("NDP16 length");
        }
        for pointer in (at + NDP16_HEADER..end).step_by(POINTER) {
            let (Some(index), Some(size)) = (u16_at(block, pointer), u16_at(block, pointer + 2))
            else {
                return Err("short datagram pointer");
            };
            if index == 0 || size == 0 {
                break;
            }
            let start = usize::from(index);
            // The advertised length includes the CRC. Validate that complete
            // datagram before stripping it; a present payload does not make a
            // truncated CRC a well-formed transfer block.
            let datagram = block
                .get(start..start + usize::from(size))
                .ok_or("datagram past the NTB's end")?;
            let frame = datagram
                .len()
                .checked_sub(crc)
                .ok_or("datagram shorter than its CRC")?;
            datagrams.push(&datagram[..frame]);
        }
        table = next;
    }
    Err("NDP16 chain too long")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parameters(divisor: u16, remainder: u16, alignment: u16) -> [u8; PARAMETER_BYTES] {
        let mut b = [0u8; PARAMETER_BYTES];
        b[..2].copy_from_slice(&(PARAMETER_BYTES as u16).to_le_bytes());
        b[2..4].copy_from_slice(&NTB16.to_le_bytes());
        b[4..8].copy_from_slice(&16384u32.to_le_bytes());
        b[16..20].copy_from_slice(&8192u32.to_le_bytes());
        b[20..22].copy_from_slice(&divisor.to_le_bytes());
        b[22..24].copy_from_slice(&remainder.to_le_bytes());
        b[24..26].copy_from_slice(&alignment.to_le_bytes());
        b
    }

    #[test]
    fn parameters_need_ntb16_and_the_minimum_sizes() {
        let p = Parameters::parse(&parameters(4, 2, 4)).unwrap();
        assert_eq!((p.in_max, p.out_max), (16384, 8192));
        let mut no16 = parameters(4, 2, 4);
        no16[2] = 2;
        assert!(Parameters::parse(&no16).is_err());
        let mut small = parameters(4, 2, 4);
        small[16..20].copy_from_slice(&1024u32.to_le_bytes());
        assert!(Parameters::parse(&small).is_err());
        assert!(Parameters::parse(&parameters(3, 0, 4)).is_err());
        assert!(Parameters::parse(&parameters(4, 0, 4)[..20]).is_err());
    }

    #[test]
    fn an_out_block_places_its_datagram_by_divisor_and_remainder() {
        let p = Parameters::parse(&parameters(4, 2, 8)).unwrap();
        let frame = [0xab; 60];
        let block = p.encode(7, &frame).unwrap();
        // NTH16 at 0, NDP16 aligned to 8 at 16, its 16 bytes, then the
        // datagram at the first offset that is 2 modulo 4: 34.
        assert_eq!(&block[..4], b"NCMH");
        assert_eq!(u16_at(&block, 6), Some(7));
        assert_eq!(u16_at(&block, 8), Some(block.len() as u16));
        assert_eq!(u16_at(&block, 10), Some(16));
        assert_eq!(&block[16..20], b"NCM0");
        assert_eq!(u16_at(&block, 24), Some(34));
        assert_eq!(&block[34..], frame);
        assert_eq!(decode(&block).unwrap(), [&frame[..]]);
        assert!(p.encode(0, &[0; 8192]).is_none());
    }

    #[test]
    fn an_in_block_yields_every_datagram_of_its_chained_tables() {
        let p = Parameters::parse(&parameters(1, 0, 4)).unwrap();
        let mut block = p.encode(1, &[1; 20]).unwrap();
        // Chain a second NDP16 (with CRCs) naming one more datagram.
        let second = block.len().next_multiple_of(4);
        block.resize(second + 16, 0);
        block[12 + 6..12 + 8].copy_from_slice(&(second as u16).to_le_bytes());
        let datagram = block.len();
        block.extend_from_slice(&[2; 30]);
        block.extend_from_slice(&[0xcc; CRC_BYTES]);
        block[second..second + 4].copy_from_slice(b"NCM1");
        block[second + 4..second + 6].copy_from_slice(&16u16.to_le_bytes());
        block[second + 8..second + 10].copy_from_slice(&(datagram as u16).to_le_bytes());
        block[second + 10..second + 12].copy_from_slice(&34u16.to_le_bytes());
        let total = block.len() as u16;
        block[8..10].copy_from_slice(&total.to_le_bytes());
        assert_eq!(decode(&block).unwrap(), [&[1u8; 20][..], &[2u8; 30][..]]);
        // A datagram past the block's end refuses the block.
        block[second + 10..second + 12].copy_from_slice(&200u16.to_le_bytes());
        assert!(decode(&block).is_err());
        // A table chained to itself ends at the bound.
        let mut looped = p.encode(1, &[1; 20]).unwrap();
        looped[18..20].copy_from_slice(&12u16.to_le_bytes());
        assert!(decode(&looped).is_err());
        assert!(decode(b"NCMX").is_err());
    }

    #[test]
    fn crc_bytes_must_fit_inside_the_declared_block_and_transfer() {
        let p = Parameters::parse(&parameters(1, 0, 4)).unwrap();
        let mut block = p.encode(1, &[0xab; 16]).unwrap();
        assert_eq!(block.len(), 44);
        block[12..16].copy_from_slice(b"NCM1");
        // All 16 payload bytes fit, but none of the advertised CRC does.
        block[22..24].copy_from_slice(&20u16.to_le_bytes());
        for trailing in 0..=CRC_BYTES {
            let mut transfer = block.clone();
            transfer.extend_from_slice(&[0xcc; CRC_BYTES][..trailing]);
            // Extra transfer padding is outside wBlockLength.
            assert!(decode(&transfer).is_err());
            let length = transfer.len() as u16;
            transfer[8..10].copy_from_slice(&length.to_le_bytes());
            if trailing == CRC_BYTES {
                assert_eq!(decode(&transfer).unwrap(), [&[0xab; 16][..]]);
            } else {
                assert!(decode(&transfer).is_err());
            }
        }
    }
}
