//! Only an admission check for the separately source-bound QEMU -smp 1 fixture.
//! This inventory is not a general processor election or SMP quiescence proof.
use crate::Result;
use stela_contracts::refuse;
pub fn one_processor(table: &[u8], executing: u32) -> Result<()> {
    if table.len() < 44 || &table[..4] != b"APIC" {
        return Err(refuse!("work fixture has no valid MADT"));
    }
    let length = u32::from_le_bytes(table[4..8].try_into().unwrap()) as usize;
    if length != table.len() || table.iter().fold(0u8, |a, b| a.wrapping_add(*b)) != 0 {
        return Err(refuse!("work fixture MADT length/checksum invalid"));
    }
    let mut offset = 44;
    let mut processor = None;
    while offset < length {
        let remaining = &table[offset..];
        if remaining.len() < 2 || remaining[1] < 2 || usize::from(remaining[1]) > remaining.len() {
            return Err(refuse!("work fixture MADT entry malformed"));
        }
        let entry = &remaining[..usize::from(remaining[1])];
        let (id, flags) = match entry[0] {
            0 if entry.len() == 8 => (
                u32::from(entry[3]),
                u32::from_le_bytes(entry[4..8].try_into().unwrap()),
            ),
            9 if entry.len() == 16 && entry[2..4] == [0, 0] => (
                u32::from_le_bytes(entry[4..8].try_into().unwrap()),
                u32::from_le_bytes(entry[8..12].try_into().unwrap()),
            ),
            0 | 9 => return Err(refuse!("work fixture MADT processor malformed")),
            _ => {
                offset += entry.len();
                continue;
            }
        };
        // Enabled bit 0 is required. Online-capable bit 1 alone is not enabled;
        // this narrow fixture refuses even additional disabled representations.
        // Neither an alias nor type0+type9 can count as another safe BSP.
        if flags & !3 != 0 || flags & 1 == 0 || processor.replace(id).is_some() {
            return Err(refuse!(
                "work fixture requires exactly one enabled MADT processor"
            ));
        }
        offset += entry.len();
    }
    if processor != Some(executing) {
        return Err(refuse!(
            "work fixture MADT does not match executing APIC ID"
        ));
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};
    fn table(entries: &[u8]) -> Vec<u8> {
        let mut t = vec![0; 44];
        t[..4].copy_from_slice(b"APIC");
        t.extend_from_slice(entries);
        let length = t.len() as u32;
        t[4..8].copy_from_slice(&length.to_le_bytes());
        checksum(&mut t);
        t
    }
    fn checksum(t: &mut [u8]) {
        t[9] = 0;
        t[9] = 0u8.wrapping_sub(t.iter().fold(0u8, |a, b| a.wrapping_add(*b)));
    }
    #[test]
    fn enabled_identity_and_checksum_are_required() {
        let mut t = table(&[0, 8, 0, 7, 1, 0, 0, 0]);
        assert_eq!(one_processor(&t, 7), Ok(()));
        assert!(one_processor(&t, 8).is_err());
        t[48] = 2;
        checksum(&mut t); // Online-capable is not enabled.
        assert!(one_processor(&t, 7).is_err());
        t[48] = 1;
        checksum(&mut t);
        t[9] ^= 1;
        assert!(one_processor(&t, 7).is_err());
        t.pop();
        assert!(one_processor(&t, 7).is_err());
    }
    #[test]
    fn duplicate_disabled_alias_and_malformed_processor_entries_refuse() {
        let cpu = [0, 8, 0, 7, 1, 0, 0, 0];
        for second in [
            vec![0, 8, 1, 8, 1, 0, 0, 0],
            vec![0, 8, 0, 7, 0, 0, 0, 0],
            vec![9, 16, 0, 0, 7, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0],
            vec![0, 7, 0, 7, 1, 0, 0],
        ] {
            let mut entries = cpu.to_vec();
            entries.extend(second);
            assert!(one_processor(&table(&entries), 7).is_err());
        }
        let x2 = table(&[9, 16, 0, 0, 7, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(one_processor(&x2, 7), Ok(()));
        assert!(one_processor(&table(&[]), 7).is_err());
    }
}
