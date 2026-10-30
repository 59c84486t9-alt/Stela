//! The variables of an Apple CHRP bank, read and rewritten as XNU
//! `IONVRAMCHRPHandler.cpp` does (`unserializeVariables`,
//! `serializeVariables`, `escapeDataToData`, `unescapeBytesToData`).
//!
//! Each `common` or `system` partition holds `name=value` entries after its
//! 16-byte CHRP header, each ended by a NUL; an empty name ends the list. A
//! value is escaped so it holds no NUL: a run of up to 127 `0x00` or `0xff`
//! bytes is `0xff` followed by the run length, with bit 7 set for `0xff`.
//! `common` holds Apple's common variables (GUID
//! `7C436110-AB2A-4BBB-A880-FE41995C9F82`), `system` the system ones
//! (`40A0DDD2-77F8-4392-B4A3-1E7304206516`). Saving increments the bank
//! generation and writes the next bank, round robin.
use super::{
    APPLE_HEADER_SIZE, BANK_SIZE, HEADER_SIZE, adler, checksum, generation, partition_name,
    validate,
};
use crate::Result;
use alloc::vec::Vec;
use stela_contracts::refuse;

/// The escape byte that starts a run of `0x00` or `0xff`.
const ESCAPE: u8 = 0xff;
/// The run-length bits of the byte after [`ESCAPE`].
const RUN_LENGTH: u8 = 0x7f;
/// Set in the run byte when the run repeats `0xff`.
const RUN_OF_ONES: u8 = 0x80;
const SEPARATOR: u8 = b'=';
/// Offsets of the bank's Apple-header Adler-32 and generation.
const ADLER_AT: usize = 16;
const GENERATION_AT: usize = 20;

/// Which CHRP partition a variable lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Partition {
    /// `system` / `2system`: Apple's system GUID.
    System,
    /// `common` / `2common`: Apple's common GUID.
    Common,
}

impl Partition {
    fn of(name: &[u8]) -> Option<Self> {
        match name {
            b"system" | b"2system" => Some(Self::System),
            b"common" | b"2common" => Some(Self::Common),
            _ => None,
        }
    }
}

/// A variable's name and its unescaped value.
type Entry = (Vec<u8>, Vec<u8>);

/// One partition's place in the bank and its variables in bank order.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Region {
    partition: Partition,
    /// The payload after the CHRP header.
    start: usize,
    end: usize,
    entries: Vec<Entry>,
}

/// A bank's variables, editable and re-encodable into the next bank.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Variables {
    bank: Vec<u8>,
    regions: Vec<Region>,
}

fn unescape(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut value = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        let byte = bytes[at];
        at += 1;
        if byte != ESCAPE {
            value.push(byte);
            continue;
        }
        let run = *bytes
            .get(at)
            .ok_or(refuse!("NVRAM value ends inside an escape"))?;
        at += 1;
        let count = usize::from(run & RUN_LENGTH);
        if count == 0 {
            return Err(refuse!("NVRAM value has an empty escaped run"));
        }
        let fill = if run & RUN_OF_ONES != 0 { ESCAPE } else { 0 };
        value.extend(core::iter::repeat_n(fill, count));
    }
    Ok(value)
}

fn escape(value: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(value.len());
    let mut at = 0;
    while at < value.len() {
        let byte = value[at];
        if byte != 0 && byte != ESCAPE {
            bytes.push(byte);
            at += 1;
            continue;
        }
        let run = value[at..]
            .iter()
            .take(usize::from(RUN_LENGTH))
            .take_while(|&&b| b == byte)
            .count();
        bytes.push(ESCAPE);
        bytes.push((byte & RUN_OF_ONES) | run as u8);
        at += run;
    }
    bytes
}

fn entries(payload: &[u8]) -> Result<Vec<Entry>> {
    let mut entries = Vec::new();
    let mut at = 0;
    while at < payload.len() && payload[at] != 0 {
        let rest = &payload[at..];
        let end = rest
            .iter()
            .position(|&b| b == 0)
            .ok_or(refuse!("NVRAM entry runs past its partition"))?;
        let entry = &rest[..end];
        let split = entry
            .iter()
            .position(|&b| b == SEPARATOR)
            .ok_or(refuse!("NVRAM entry has no '='"))?;
        entries.push((entry[..split].to_vec(), unescape(&entry[split + 1..])?));
        at += end + 1;
    }
    Ok(entries)
}

impl Variables {
    /// The variables of a valid bank.
    pub fn parse(bank: &[u8]) -> Result<Self> {
        validate(bank)?;
        let mut regions = Vec::new();
        let mut offset = 0;
        while offset < BANK_SIZE {
            let header = &bank[offset..offset + HEADER_SIZE];
            let length = usize::from(u16::from_le_bytes([header[2], header[3]])) * HEADER_SIZE;
            // The bank's own Apple header is a partition named nvram.
            if offset >= APPLE_HEADER_SIZE
                && let Some(partition) = Partition::of(partition_name(header))
            {
                let (start, end) = (offset + HEADER_SIZE, offset + length);
                regions.push(Region {
                    partition,
                    start,
                    end,
                    entries: entries(&bank[start..end])?,
                });
            }
            offset += length;
        }
        Ok(Self {
            bank: bank.to_vec(),
            regions,
        })
    }

    pub fn generation(&self) -> u32 {
        generation(&self.bank)
    }

    fn region(&self, partition: Partition) -> Option<&Region> {
        self.regions.iter().find(|r| r.partition == partition)
    }

    /// The value of `name` in `partition`.
    pub fn get(&self, partition: Partition, name: &[u8]) -> Option<&[u8]> {
        self.region(partition)?
            .entries
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_slice())
    }

    /// Every variable of `partition`, in bank order.
    pub fn list(&self, partition: Partition) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.region(partition)
            .into_iter()
            .flat_map(|r| r.entries.iter().map(|(n, v)| (n.as_slice(), v.as_slice())))
    }

    /// Remove `name` from `partition`; its old value, if it had one.
    pub fn remove(&mut self, partition: Partition, name: &[u8]) -> Option<Vec<u8>> {
        let region = self.regions.iter_mut().find(|r| r.partition == partition)?;
        let index = region.entries.iter().position(|(n, _)| n == name)?;
        Some(region.entries.remove(index).1)
    }

    /// Set `name` in `partition`; refused when the bank has no such
    /// partition or the name cannot be stored.
    pub fn set(&mut self, partition: Partition, name: &[u8], value: &[u8]) -> Result<()> {
        if name.is_empty() || name.iter().any(|&b| b == 0 || b == SEPARATOR) {
            return Err(refuse!(
                "an NVRAM name is non-empty and holds no NUL or '='"
            ));
        }
        let region = self
            .regions
            .iter_mut()
            .find(|r| r.partition == partition)
            .ok_or(refuse!("the NVRAM bank has no such partition"))?;
        match region.entries.iter_mut().find(|(n, _)| n == name) {
            Some(entry) => entry.1 = value.to_vec(),
            None => region.entries.push((name.to_vec(), value.to_vec())),
        }
        Ok(())
    }

    /// The bank these variables save as: the same partitions, the entries
    /// re-serialized, generation `old + 1`, checksums renewed. Refused when
    /// a partition overflows.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut bank = self.bank.clone();
        for region in &self.regions {
            let mut payload = Vec::new();
            for (name, value) in &region.entries {
                payload.extend_from_slice(name);
                payload.push(SEPARATOR);
                payload.extend(escape(value));
                payload.push(0);
            }
            if payload.len() >= region.end - region.start {
                return Err(refuse!("NVRAM variables overflow their partition"));
            }
            let slot = &mut bank[region.start..region.end];
            slot.fill(0);
            slot[..payload.len()].copy_from_slice(&payload);
        }
        let next = self
            .generation()
            .checked_add(1)
            .ok_or(refuse!("NVRAM generation overflow"))?;
        bank[GENERATION_AT..GENERATION_AT + 4].copy_from_slice(&next.to_le_bytes());
        let sum = adler(&bank[GENERATION_AT..]);
        bank[ADLER_AT..ADLER_AT + 4].copy_from_slice(&sum.to_le_bytes());
        debug_assert_eq!(bank[1], checksum(&bank));
        validate(&bank)?;
        Ok(bank)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn escaping_round_trips_runs_of_zeros_and_ones() {
        let value: Vec<u8> = [&[1u8, 0, 0, 0, 2][..], &[0xff; 200], &[0; 130], b"x"].concat();
        let escaped = escape(&value);
        assert!(!escaped.contains(&0));
        assert_eq!(&escaped[..5], &[1, 0xff, 3, 2, 0xff]);
        assert_eq!(escaped[5], 0x80 | 0x7f);
        assert_eq!(unescape(&escaped).unwrap(), value);
        assert!(unescape(&[0xff, 0x00]).is_err());
        assert!(unescape(&[0xff]).is_err());
    }

    #[test]
    fn variables_are_read_set_removed_and_saved_as_the_next_generation() {
        let bank = super::super::empty_bank();
        let mut variables = Variables::parse(&bank).unwrap();
        assert_eq!(variables.get(Partition::System, b"boot-volume"), None);
        variables
            .set(Partition::System, b"boot-volume", b"A:B:C")
            .unwrap();
        variables
            .set(Partition::Common, b"auto-boot", b"true")
            .unwrap();
        variables
            .set(Partition::Common, b"bin", &[0, 0, 0xff, 7])
            .unwrap();
        assert!(variables.set(Partition::Common, b"a=b", b"x").is_err());
        let saved = variables.encode().unwrap();
        assert_eq!(validate(&saved), Ok(()));
        assert_eq!(generation(&saved), 2);
        let again = Variables::parse(&saved).unwrap();
        assert_eq!(
            again.get(Partition::System, b"boot-volume"),
            Some(&b"A:B:C"[..])
        );
        assert_eq!(again.get(Partition::Common, b"boot-volume"), None);
        assert_eq!(
            again.get(Partition::Common, b"bin"),
            Some(&[0, 0, 0xff, 7][..])
        );
        // Entries are `name=value` then NUL, in the common payload.
        let common = again.region(Partition::Common).unwrap().start;
        assert_eq!(&saved[common..common + 15], b"auto-boot=true\0");
        let mut edited = again.clone();
        assert_eq!(
            edited.remove(Partition::System, b"boot-volume"),
            Some(b"A:B:C".to_vec())
        );
        let saved = edited.encode().unwrap();
        assert_eq!(generation(&saved), 3);
        assert_eq!(
            Variables::parse(&saved)
                .unwrap()
                .list(Partition::System)
                .count(),
            0
        );
    }

    #[test]
    fn overflowing_and_corrupt_banks_are_refused() {
        let mut variables = Variables::parse(&super::super::empty_bank()).unwrap();
        variables
            .set(Partition::System, b"big", &vec![b'x'; 0x4000])
            .unwrap();
        assert!(variables.encode().is_err());
        let mut bank = super::super::empty_bank();
        bank[APPLE_HEADER_SIZE + HEADER_SIZE] = b'x';
        assert!(Variables::parse(&bank).is_err());
    }
}
