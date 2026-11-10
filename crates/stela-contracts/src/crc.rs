//! The two reflected CRC-32s Stela's formats and devices check: IEEE 802.3
//! (GPT, ZIP, WEP, Ethernet) and Castagnoli, CRC-32C (Thunderbolt, ANS).
//! Both are table driven, with all-ones initial state and final XOR.

const IEEE: u32 = 0xedb8_8320;
const CASTAGNOLI: u32 = 0x82f6_3b78;
const IEEE_TABLE: [u32; 256] = table(IEEE);
const CASTAGNOLI_TABLE: [u32; 256] = table(CASTAGNOLI);

const fn table(polynomial: u32) -> [u32; 256] {
    let mut table = [0; 256];
    let mut index = 0;
    while index < 256 {
        let mut crc = index as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ polynomial
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[index] = crc;
        index += 1;
    }
    table
}

fn update(table: &[u32; 256], mut state: u32, bytes: &[u8]) -> u32 {
    for &byte in bytes {
        state = table[((state ^ u32::from(byte)) & 0xff) as usize] ^ (state >> 8);
    }
    state
}

/// The IEEE CRC-32 of `bytes`.
pub fn crc32_ieee(bytes: &[u8]) -> u32 {
    !update(&IEEE_TABLE, !0, bytes)
}

/// The CRC-32C of `bytes`. The integer is independent of a protocol's wire
/// byte order.
pub fn crc32c(bytes: &[u8]) -> u32 {
    !crc32c_update(!0, bytes)
}

/// The CRC-32C register after `bytes`, from `state`: start at `!0` and
/// invert the last state, for a checksum taken over several pieces.
pub fn crc32c_update(state: u32, bytes: &[u8]) -> u32 {
    update(&CASTAGNOLI_TABLE, state, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_polynomials_match_their_check_values() {
        assert_eq!(crc32_ieee(b"123456789"), 0xcbf4_3926);
        assert_eq!(crc32_ieee(b""), 0);
        assert_eq!(crc32c(b"123456789"), 0xe306_9283);
        assert_eq!(crc32c(&[]), 0);
        // The Linux kernel's CRC-32C table starts 0, f26b8303, e13b70f7.
        assert_eq!(CASTAGNOLI_TABLE[..3], [0, 0xf26b_8303, 0xe13b_70f7]);
        assert_eq!(IEEE_TABLE[1], 0x7707_3096);
    }

    #[test]
    fn crc32c_continues_across_pieces() {
        assert_eq!(crc32c(&[0; 32]), 0x8a91_36aa);
        assert_eq!(crc32c(&[0xff; 32]), 0x62a8_ab43);
        let first = crc32c_update(!0, b"1234");
        assert_eq!(!crc32c_update(first, b"56789"), 0xe306_9283);
        assert_eq!(crc32c_update(first, &[]), first);
    }
}
