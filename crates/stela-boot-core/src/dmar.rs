//! Bounded DMAR ownership input for one live, known flat segment. A single
//! include-all unit or a completely matched set of direct endpoint scopes can
//! identify its remapper; neither proves device quiescence. Bridges, aliases,
//! multi-hop scopes, reserved regions, ATS and unknown structures are refused.
use crate::remapping::Scope;
use alloc::vec::Vec;

const HEADER: usize = 48;
const DRHD: u16 = 0;
const RMRR: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DmarError {
    InvalidTable,
    InvalidStructure,
    UnsupportedStructure(u16),
    UnsupportedScope(u8),
    UnsupportedWidth,
    UnsupportedRouting,
    MissingUnit,
    MultipleUnits,
    DuplicateRequester(u16),
    MissingRequester(u16),
    UnlistedRequester(u16),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HardwareUnit {
    pub base: u64,
    pub bytes: usize,
    pub segment: u16,
    pub physical_bits: u8,
}

fn word(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn quad(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

/// A remapping hardware unit (DRHD): its registers, segment and the PCI
/// requesters it translates, or every requester on the segment no other
/// unit lists when `include_all`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Drhd {
    pub base: u64,
    pub bytes: usize,
    pub segment: u16,
    pub include_all: bool,
    pub scopes: Vec<Scope>,
}

/// A reserved memory region (RMRR): memory the firmware keeps DMA-ing to
/// for the requesters in its scopes, which a translating unit must map one
/// to one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Rmrr {
    pub segment: u16,
    pub base: u64,
    pub limit: u64,
    pub scopes: Vec<Scope>,
}

/// A parsed DMAR table: the host address width and the units and reserved
/// regions. ATSR, RHSA, ANDD, SATC and later structures describe ATS,
/// proximity and namespace devices, none of which the mount enables, and
/// are skipped.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Remapping {
    pub physical_bits: u8,
    pub units: Vec<Drhd>,
    pub reserved: Vec<Rmrr>,
}

/// The PCI scopes of a structure starting at `from`. IOAPIC, HPET and ACPI
/// namespace scopes name interrupt sources, which matter only to interrupt
/// remapping.
fn scopes(entry: &[u8], from: usize) -> Result<Vec<Scope>, DmarError> {
    let mut found = Vec::new();
    let mut scope = from;
    while scope < entry.len() {
        let header = entry
            .get(scope..scope + 6)
            .ok_or(DmarError::InvalidStructure)?;
        let bytes = usize::from(header[1]);
        if bytes < 6 || !bytes.is_multiple_of(2) {
            return Err(DmarError::InvalidStructure);
        }
        let end = scope
            .checked_add(bytes)
            .ok_or(DmarError::InvalidStructure)?;
        let path = entry
            .get(scope + 6..end)
            .ok_or(DmarError::InvalidStructure)?
            .as_chunks::<2>()
            .0;
        if path.iter().any(|hop| hop[0] > 31 || hop[1] > 7) {
            return Err(DmarError::InvalidStructure);
        }
        if matches!(header[0], 1 | 2) {
            if path.is_empty() {
                return Err(DmarError::InvalidStructure);
            }
            found.push(Scope {
                bridge: header[0] == 2,
                bus: header[5],
                path: path.iter().map(|hop| (hop[0], hop[1])).collect(),
            });
        }
        scope = end;
    }
    Ok(found)
}

/// Parse a DMAR table, validating its checksum, width and every DRHD and
/// RMRR it holds.
pub fn parse(table: &[u8]) -> Result<Remapping, DmarError> {
    if table.len() < HEADER
        || &table[..4] != b"DMAR"
        || u32::from_le_bytes(table[4..8].try_into().unwrap()) as usize != table.len()
        || table.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)) != 0
    {
        return Err(DmarError::InvalidTable);
    }
    let physical_bits = table[36]
        .checked_add(1)
        .filter(|bits| (32..=64).contains(bits))
        .ok_or(DmarError::UnsupportedWidth)?;
    let mut remapping = Remapping {
        physical_bits,
        units: Vec::new(),
        reserved: Vec::new(),
    };
    let mut offset = HEADER;
    while offset < table.len() {
        let header = table
            .get(offset..offset + 4)
            .ok_or(DmarError::InvalidStructure)?;
        let kind = word(header, 0);
        let length = usize::from(word(header, 2));
        let end = offset
            .checked_add(length)
            .filter(|_| length >= 4)
            .ok_or(DmarError::InvalidStructure)?;
        let entry = table.get(offset..end).ok_or(DmarError::InvalidStructure)?;
        match kind {
            DRHD => {
                if length < 16 {
                    return Err(DmarError::InvalidStructure);
                }
                let base = quad(entry, 8);
                let bytes = 1usize
                    .checked_shl(12 + u32::from(entry[5] & 0xf))
                    .ok_or(DmarError::InvalidStructure)?;
                if base == 0
                    || !base.is_multiple_of(4096)
                    || base.checked_add(bytes as u64).is_none()
                {
                    return Err(DmarError::InvalidStructure);
                }
                remapping.units.push(Drhd {
                    base,
                    bytes,
                    segment: word(entry, 6),
                    include_all: entry[4] & 1 != 0,
                    scopes: scopes(entry, 16)?,
                });
            }
            RMRR => {
                if length < 24 {
                    return Err(DmarError::InvalidStructure);
                }
                let (base, limit) = (quad(entry, 8), quad(entry, 16));
                if !base.is_multiple_of(4096) || limit < base || limit & 0xfff != 0xfff {
                    return Err(DmarError::InvalidStructure);
                }
                remapping.reserved.push(Rmrr {
                    segment: word(entry, 6),
                    base,
                    limit,
                    scopes: scopes(entry, 24)?,
                });
            }
            _ => {}
        }
        offset = end;
    }
    if remapping.units.is_empty() {
        return Err(DmarError::MissingUnit);
    }
    Ok(remapping)
}

/// Validate the complete table before returning one owner of the live flat bus. No
/// unknown/RMRR structure is skipped in order to manufacture a usable domain.
pub fn single_flat_owner(
    table: &[u8],
    segment: u16,
    live_requesters: &[u16],
) -> Result<HardwareUnit, DmarError> {
    if live_requesters.is_empty() || live_requesters.iter().any(|requester| requester >> 8 != 0) {
        return Err(DmarError::UnsupportedRouting);
    }
    let mut expected = live_requesters.to_vec();
    expected.sort_unstable();
    if let Some(pair) = expected.windows(2).find(|pair| pair[0] == pair[1]) {
        return Err(DmarError::DuplicateRequester(pair[0]));
    }
    if table.len() < HEADER
        || &table[..4] != b"DMAR"
        || u32::from_le_bytes(table[4..8].try_into().unwrap()) as usize != table.len()
        || table.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)) != 0
        || table[37] & !7 != 0
        || table[38..HEADER].iter().any(|byte| *byte != 0)
    {
        return Err(DmarError::InvalidTable);
    }
    let physical_bits = table[36]
        .checked_add(1)
        .filter(|bits| (32..=52).contains(bits))
        .ok_or(DmarError::UnsupportedWidth)?;
    let mut unit = None;
    let mut offset = HEADER;
    while offset < table.len() {
        let header = table
            .get(offset..offset + 4)
            .ok_or(DmarError::InvalidStructure)?;
        let kind = word(header, 0);
        let length = usize::from(word(header, 2));
        if length < 4 {
            return Err(DmarError::InvalidStructure);
        }
        let end = offset
            .checked_add(length)
            .ok_or(DmarError::InvalidStructure)?;
        let entry = table.get(offset..end).ok_or(DmarError::InvalidStructure)?;
        if kind != DRHD {
            return Err(DmarError::UnsupportedStructure(kind));
        }
        if length < 16 {
            return Err(DmarError::InvalidStructure);
        }
        if unit.is_some() {
            return Err(DmarError::MultipleUnits);
        }
        if entry[4] & !1 != 0 || word(entry, 6) != segment {
            return Err(DmarError::UnsupportedRouting);
        }
        let base = u64::from_le_bytes(entry[8..16].try_into().unwrap());
        let bytes = 1usize
            .checked_shl(12 + u32::from(entry[5]))
            .ok_or(DmarError::InvalidStructure)?;
        if base == 0
            || !base.is_multiple_of(4096)
            || base
                .checked_add(bytes as u64)
                .is_none_or(|end| end > 1u64 << physical_bits)
        {
            return Err(DmarError::InvalidStructure);
        }
        let mut scope = 16;
        let mut endpoints = Vec::new();
        while scope < length {
            let scope_header = entry
                .get(scope..scope + 6)
                .ok_or(DmarError::InvalidStructure)?;
            let scope_kind = scope_header[0];
            let scope_bytes = usize::from(scope_header[1]);
            if scope_bytes < 8 || !scope_bytes.is_multiple_of(2) || scope_header[2..4] != [0, 0] {
                return Err(DmarError::InvalidStructure);
            }
            let end = scope
                .checked_add(scope_bytes)
                .ok_or(DmarError::InvalidStructure)?;
            let contents = entry
                .get(scope + 6..end)
                .ok_or(DmarError::InvalidStructure)?;
            if !matches!(scope_kind, 1 | 3 | 4) {
                return Err(DmarError::UnsupportedScope(scope_kind));
            }
            if contents
                .as_chunks::<2>()
                .0
                .iter()
                .any(|path| path[0] > 31 || path[1] > 7)
            {
                return Err(DmarError::InvalidStructure);
            }
            if scope_bytes != 8 {
                return Err(DmarError::UnsupportedRouting);
            }
            if scope_kind == 1 {
                if scope_header[4] != 0 {
                    return Err(DmarError::InvalidStructure);
                }
                let requester = u16::from(scope_header[5]) << 8
                    | u16::from(contents[0]) << 3
                    | u16::from(contents[1]);
                if !expected.contains(&requester) {
                    return Err(DmarError::UnlistedRequester(requester));
                }
                if endpoints.contains(&requester) {
                    return Err(DmarError::DuplicateRequester(requester));
                }
                endpoints.push(requester);
            }
            // IOAPIC/HPET interrupt scopes do not change the flat DMA route;
            // this backend does not enable interrupt remapping.
            scope = end;
        }
        if entry[4] & 1 == 0 {
            for requester in &expected {
                if !endpoints.contains(requester) {
                    return Err(DmarError::MissingRequester(*requester));
                }
            }
        }
        unit = Some(HardwareUnit {
            base,
            bytes,
            segment,
            physical_bits,
        });
        offset = end;
    }
    unit.ok_or(DmarError::MissingUnit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};
    fn seal(mut table: Vec<u8>) -> Vec<u8> {
        let bytes = table.len() as u32;
        table[4..8].copy_from_slice(&bytes.to_le_bytes());
        table[9] = 0;
        table[9] = 0u8.wrapping_sub(table.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)));
        table
    }
    fn fixture() -> Vec<u8> {
        let mut table = vec![0; 64];
        table[..4].copy_from_slice(b"DMAR");
        table[36] = 47;
        table[50..52].copy_from_slice(&16u16.to_le_bytes());
        table[52] = 1;
        table[56..64].copy_from_slice(&0xfed90000u64.to_le_bytes());
        seal(table)
    }
    fn scoped(paths: &[[u8; 8]]) -> Vec<u8> {
        let mut table = fixture();
        table[52] = 0;
        for scope in paths {
            table.extend(scope);
        }
        let length = (table.len() - HEADER) as u16;
        table[50..52].copy_from_slice(&length.to_le_bytes());
        seal(table)
    }
    #[test]
    fn parses_units_reserved_regions_and_bridge_paths() {
        let mut table = fixture();
        // A second unit with an endpoint behind a bridge and a bridge scope.
        let mut unit = vec![0, 0, 0, 0, 0, 0, 0, 0];
        unit.extend(0xfed91000u64.to_le_bytes());
        unit.extend([1, 10, 0, 0, 0, 0, 0x1c, 0, 0, 0]);
        unit.extend([2, 8, 0, 0, 0, 0, 0x1d, 0]);
        unit.extend([3, 8, 0, 0, 2, 0xf0, 0x1f, 0]);
        let length = unit.len() as u16;
        unit[2..4].copy_from_slice(&length.to_le_bytes());
        table.extend(unit);
        let mut rmrr = vec![1, 0, 32, 0, 0, 0, 0, 0];
        rmrr.extend(0x7d000000u64.to_le_bytes());
        rmrr.extend(0x7d01ffffu64.to_le_bytes());
        rmrr.extend([1, 8, 0, 0, 0, 0, 0x14, 0]);
        table.extend(rmrr);
        table.extend([3, 0, 4, 0]);
        let parsed = parse(&seal(table)).unwrap();
        assert_eq!(parsed.physical_bits, 48);
        assert_eq!(parsed.units.len(), 2);
        assert!(parsed.units[0].include_all);
        assert_eq!(
            parsed.units[1].scopes,
            [
                Scope {
                    bridge: false,
                    bus: 0,
                    path: vec![(0x1c, 0), (0, 0)]
                },
                Scope {
                    bridge: true,
                    bus: 0,
                    path: vec![(0x1d, 0)]
                }
            ]
        );
        assert_eq!(parsed.reserved[0].limit, 0x7d01ffff);
        assert_eq!(parsed.reserved[0].scopes[0].path, [(0x14, 0)]);
        let mut broken = fixture();
        broken.extend([1, 0, 24, 0, 0, 0, 0, 0]);
        broken.extend(0x1000u64.to_le_bytes());
        broken.extend(0x1000u64.to_le_bytes());
        assert_eq!(parse(&seal(broken)), Err(DmarError::InvalidStructure));
    }

    #[test]
    fn requires_live_endpoint_coverage_and_valid_direct_paths() {
        let one = [1, 8, 0, 0, 0, 0, 1, 0];
        let two = [1, 8, 0, 0, 0, 0, 2, 0];
        let ioapic = [3, 8, 0, 0, 0, 255, 31, 0];
        let complete = scoped(&[two, one, ioapic]);
        assert!(single_flat_owner(&complete, 0, &[8, 16]).is_ok());
        assert_eq!(
            single_flat_owner(&scoped(&[one]), 0, &[8, 16]),
            Err(DmarError::MissingRequester(16))
        );
        assert_eq!(
            single_flat_owner(&scoped(&[one, one]), 0, &[8]),
            Err(DmarError::DuplicateRequester(8))
        );
        assert_eq!(
            single_flat_owner(&scoped(&[one, two]), 0, &[8]),
            Err(DmarError::UnlistedRequester(16))
        );
        assert_eq!(
            single_flat_owner(&complete, 0, &[8, 8]),
            Err(DmarError::DuplicateRequester(8))
        );
        assert_eq!(
            single_flat_owner(&complete, 0, &[0x108]),
            Err(DmarError::UnsupportedRouting)
        );
        let mut bridge = one;
        bridge[0] = 2;
        assert_eq!(
            single_flat_owner(&scoped(&[bridge]), 0, &[8]),
            Err(DmarError::UnsupportedScope(2))
        );
        for (index, value) in [(1, 7), (2, 1), (4, 1), (6, 32), (7, 8)] {
            let mut malformed = one;
            malformed[index] = value;
            assert_eq!(
                single_flat_owner(&scoped(&[malformed]), 0, &[8]),
                Err(DmarError::InvalidStructure)
            );
        }
        let mut multihop = scoped(&[one]);
        multihop[65] = 10;
        multihop.extend([2, 0]);
        multihop[50..52].copy_from_slice(&26u16.to_le_bytes());
        assert_eq!(
            single_flat_owner(&seal(multihop), 0, &[8]),
            Err(DmarError::UnsupportedRouting)
        );
    }
    #[test]
    fn validates_complete_owner_and_refuses_reservations_unknowns_and_other_routes() {
        let table = fixture();
        assert_eq!(
            single_flat_owner(&table, 0, &[8, 16]),
            Ok(HardwareUnit {
                base: 0xfed90000,
                bytes: 4096,
                segment: 0,
                physical_bits: 48
            })
        );
        assert_eq!(
            single_flat_owner(&table, 1, &[8, 16]),
            Err(DmarError::UnsupportedRouting)
        );
        let mut rmrr = table.clone();
        rmrr.extend([1, 0, 4, 0]);
        assert_eq!(
            single_flat_owner(&seal(rmrr), 0, &[8, 16]),
            Err(DmarError::UnsupportedStructure(1))
        );
        let mut multiple = table.clone();
        multiple.extend_from_slice(&table[48..]);
        assert_eq!(
            single_flat_owner(&seal(multiple), 0, &[8, 16]),
            Err(DmarError::MultipleUnits)
        );
        let mut partial = table.clone();
        partial[52] = 0;
        assert_eq!(
            single_flat_owner(&seal(partial), 0, &[8, 16]),
            Err(DmarError::MissingRequester(8))
        );
        for length in [0u16, 3, 15, 17, u16::MAX] {
            let mut broken = table.clone();
            broken[50..52].copy_from_slice(&length.to_le_bytes());
            assert!(single_flat_owner(&seal(broken), 0, &[8, 16]).is_err());
        }
        let mut bad_width = table.clone();
        bad_width[36] = 255;
        assert_eq!(
            single_flat_owner(&seal(bad_width), 0, &[8, 16]),
            Err(DmarError::UnsupportedWidth)
        );
        let mut unaligned = table;
        unaligned[56] = 1;
        assert_eq!(
            single_flat_owner(&seal(unaligned), 0, &[8, 16]),
            Err(DmarError::InvalidStructure)
        );
    }
}
