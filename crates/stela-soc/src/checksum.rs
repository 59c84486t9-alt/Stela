//! Shared CRC32C/Castagnoli for protocols using the same checksum polynomial.
//! ANS BFH and Thunderbolt control traffic independently use this form.
const CASTAGNOLI: u32 = 0x82f6_3b78;
const CRC_TABLE: [u32; 256] = crc_table();

const fn crc_table() -> [u32; 256] {
    let mut table = [0; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ CASTAGNOLI
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

pub(crate) fn crc32c_update(mut state: u32, data: &[u8]) -> u32 {
    for &byte in data {
        state = CRC_TABLE[((state ^ u32::from(byte)) & 0xff) as usize] ^ (state >> 8);
    }
    state
}

/// Reflected CRC32C/Castagnoli, with all-ones initial state and final XOR.
/// The returned integer is independent of a protocol's wire byte order.
pub(crate) fn crc32c(data: &[u8]) -> u32 {
    !crc32c_update(!0, data)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn crc32c_matches_the_castagnoli_check_value_and_kernel_table() {
        assert_eq!(crc32c(b"123456789"), 0xe306_9283);
        // The kernel's table at file 0xb09000 starts 0, f26b8303, e13b70f7.
        assert_eq!(CRC_TABLE[..3], [0, 0xf26b_8303, 0xe13b_70f7]);
        assert_eq!(crc32c(&[]), 0);
    }

    #[test]
    fn incremental_state_matches_independent_castagnoli_vectors() {
        assert_eq!(crc32c(&[0; 32]), 0x8a91_36aa);
        assert_eq!(crc32c(&[0xff; 32]), 0x62a8_ab43);
        let first = crc32c_update(!0, b"1234");
        assert_eq!(!crc32c_update(first, b"56789"), 0xe306_9283);
        assert_eq!(crc32c_update(first, &[]), first);
    }
}
