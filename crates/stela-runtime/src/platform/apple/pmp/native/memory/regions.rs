//! Source-native copy of the AP table, not permission to map its rows.
use super::wire::TABLE_BYTES;
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Region {
    pub physical: u64,
    pub bus: u64,
    pub bytes: u64,
}

pub(super) fn parse(table: &[u8; TABLE_BYTES]) -> Vec<Region> {
    let mut result = Vec::new();
    for words in table.as_chunks::<24>().0 {
        let bytes = u64::from_le_bytes(words[16..24].try_into().unwrap());
        if bytes == 0 {
            break;
        }
        result.push(Region {
            physical: u64::from_le_bytes(words[..8].try_into().unwrap()),
            bus: u64::from_le_bytes(words[8..16].try_into().unwrap()),
            bytes,
        });
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_prefix_copy_keeps_order_and_stops_only_at_actual_zero_size() {
        let mut table = [0u8; TABLE_BYTES];
        for index in 0..32 {
            let at = index * 24;
            let physical = 0x8000_0000u64 + index as u64 * 0x1000;
            table[at..at + 8].copy_from_slice(&physical.to_le_bytes());
            table[at + 8..at + 16].copy_from_slice(&(physical + 0x1_0000_0000).to_le_bytes());
            table[at + 16..at + 24].copy_from_slice(&0x1000u64.to_le_bytes());
        }
        let full = parse(&table);
        assert_eq!(full.len(), 32);
        assert_eq!(
            full[31],
            Region {
                physical: 0x8001_f000,
                bus: 0x1_8001_f000,
                bytes: 0x1000
            }
        );
        table[2 * 24 + 16..3 * 24].fill(0);
        assert_eq!(parse(&table), full[..2]);
        table[16..24].fill(0);
        assert!(parse(&table).is_empty());
    }
}
