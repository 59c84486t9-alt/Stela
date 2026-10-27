//! Original 48-byte PMGR records, independent of native-device admission.
//!
//! 26A434 ApplePMGR::_getDeviceID (KC file 0x2b7bc74),
//! _getDeviceParentsID (0x2b7cca0), _getDevicePsRegGroup (0x2b7bd4c)
//! and _getDevicePsRegIndex (0x2b7bda4) define these separate layouts.
//! The low flag byte is distinct from the adjacent cluster/legacy-ID fields.

pub(super) const BYTES: usize = 48;
pub(super) const VIRTUAL: u8 = 1 << 4;
const ID16: usize = 26;
const ID8: usize = 3;
const NAME: usize = 32;
const PARENTS: usize = 4;
const V1_GROUP: usize = 11;
const V1_INDEX: usize = 10;
const V2_LOCATION: usize = 16;
const V2_GROUP: usize = 19;
const V2_INDEX_MASK: u32 = (1 << 21) - 1;
const INDEX_SHIFT: u32 = 3;
const NO_GROUP: u8 = 32;
const NO_V2_INDEX: u32 = 0xffff;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Layout {
    V1,
    V2,
}

impl Layout {
    pub(super) fn select<'a>(
        registers: Option<&'a [u8]>,
        groups: Option<&'a [u8]>,
    ) -> Result<(Self, &'a [u8]), &'static str> {
        let registers = registers.filter(|bytes| !bytes.is_empty());
        let groups = groups.filter(|bytes| !bytes.is_empty());
        match (registers, groups) {
            (Some(bytes), None) => Ok((Self::V1, bytes)),
            (None, Some(bytes)) => Ok((Self::V2, bytes)),
            (None, None) => Err("PMGR has neither ps-regs nor ps-groups"),
            (Some(_), Some(_)) => Err("PMGR has ambiguous ps-regs and ps-groups layouts"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Location {
    pub group: usize,
    pub index: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Record<'a> {
    pub id: u16,
    /// Raw PMP source identity; distinct from the canonical 16-bit device ID.
    pub pmp_source: u8,
    pub parents: [u16; 4],
    pub name: &'a str,
    pub location: Option<Location>,
}

impl<'a> Record<'a> {
    pub(super) fn parse(layout: Layout, bytes: &'a [u8; BYTES]) -> Result<Self, &'static str> {
        let id16 = u16::from_le_bytes([bytes[ID16], bytes[ID16 + 1]]);
        let id = if id16 != 0 {
            id16
        } else {
            u16::from(bytes[ID8])
        };
        let mut parents = [0; 4];
        if layout == Layout::V1 && id16 == 0 {
            for (parent, byte) in parents.iter_mut().zip(&bytes[PARENTS..PARENTS + 4]) {
                *parent = u16::from(*byte);
            }
        } else {
            let count = if layout == Layout::V1 { 2 } else { 4 };
            for (parent, pair) in parents[..count]
                .iter_mut()
                .zip(bytes[PARENTS..PARENTS + 2 * count].as_chunks::<2>().0)
            {
                *parent = u16::from_le_bytes(*pair);
                if *parent == u16::MAX {
                    return Err("PMGR record contains the invalid 16-bit parent sentinel");
                }
            }
        }
        let raw_name = &bytes[NAME..];
        let end = raw_name
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(raw_name.len());
        let name = core::str::from_utf8(&raw_name[..end])
            .map_err(|_| "PMGR record has a non-UTF-8 name")?;
        let location = if bytes[0] & VIRTUAL != 0 {
            None
        } else {
            let (group, index) = match layout {
                Layout::V1 => {
                    let index = u32::from(bytes[V1_INDEX]);
                    if index >= 32 {
                        return Err("PMGR v1 power-state index exceeds its native 32-slot bank");
                    }
                    (bytes[V1_GROUP], index)
                }
                Layout::V2 => {
                    let packed =
                        u32::from_le_bytes(bytes[V2_LOCATION..V2_LOCATION + 4].try_into().unwrap());
                    // The original index helper extracts [23:3]. The low
                    // three bits have no qualified placement meaning here.
                    if packed & ((1 << INDEX_SHIFT) - 1) != 0 {
                        return Err("PMGR v2 power-state location has unqualified low bits");
                    }
                    let index = (packed >> INDEX_SHIFT) & V2_INDEX_MASK;
                    if index == NO_V2_INDEX {
                        return Err("PMGR v2 record contains the invalid power-state index");
                    }
                    (bytes[V2_GROUP], index)
                }
            };
            if group == NO_GROUP {
                return Err("PMGR physical record contains the no-power-state group");
            }
            Some(Location {
                group: usize::from(group),
                index,
            })
        };
        Ok(Self {
            id,
            pmp_source: bytes[3],
            parents,
            name,
            location,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires pinned original 26A434 kernelcache; no Apple image is committed"]
    fn original_kernel_proves_id_parent_group_and_index_selection() {
        use sha2::{Digest, Sha256};
        let path = std::env::var("STELA_TEST_PMGR_KERNEL").expect("original kernelcache path");
        let bytes = std::fs::read(path).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            "06846c718a67715f540c7f5a5d5a183da6185d94b6fc01f1ce57a30b601be44d"
        );
        // Bounded source-integrity fixtures, never production dispatch keys.
        for (offset, opcode) in [
            (0x2b7bc78, 0x79403420),
            (0x2b7bc7c, 0x34000040),
            (0x2b7bc84, 0x39400c20),
            (0x2b7bd7c, 0x39402c00),
            (0x2b7bd84, 0x39404c00),
            (0x2b7bd88, 0x7100801f),
            (0x2b7bdd4, 0x39402800),
            (0x2b7bddc, 0xb9401008),
            (0x2b7bde0, 0x53035d00),
            (0x2b7bde4, 0x529fffe8),
            (0x2b7bde8, 0x6b08001f),
            (0x2b7be24, 0x52800400),
            (0x2b7ccc4, 0x79403428),
            (0x2b7ccc8, 0x34000368),
            (0x2b7cccc, 0x7100045f),
            (0x2b7ccd4, 0x91001029),
            (0x2b7ccdc, 0x8b0a0528),
            (0x2b7cd20, 0x79400100),
            (0x2b7cd24, 0x529fffe8),
            (0x2b7cd28, 0x6b08001f),
            (0x2b7cd34, 0x71000c5f),
            (0x2b7cd48, 0x8b224028),
            (0x2b7cd4c, 0x39401100),
            (0x2b85ad0, 0xb9400548),
            (0x2b85ad4, 0x0b150d00),
            (0x2b85b9c, 0x52800188),
            (0x2b85ba8, 0xb8686920),
        ] {
            assert_eq!(
                u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()),
                opcode,
                "original PMGR at file {offset:#x}"
            );
        }
    }

    #[test]
    #[ignore = "requires pinned original 26A434 mac18g kernel through STELA_TEST_PMGR_M6_KERNELCACHE"]
    fn original_m6_device_configs_keep_the_shared_record_envelope() {
        let bytes =
            std::fs::read(std::env::var("STELA_TEST_PMGR_M6_KERNELCACHE").unwrap()).unwrap();
        assert_eq!(
            crate::sha256(&bytes),
            "09746d1f442153956ba00b385f49bc245460c1ebea92cae7e9e0e4f240745b85"
        );
        // SystemProp::_getDTDeviceList divides the devices property's byte
        // length by48, then allocates/copies48*count. PlatformFactory indexes
        // those configs; Device's constructor reads ID+0x1a, name+0x20 and
        // all four parent halfwords. This establishes structure, not PSD ABI.
        for (offset, length, expected) in [
            (
                0x3047ac0,
                0x140,
                "f42060d83fe8096e0897a3cbca59b4f3c01c792835fdb53c40256207496dff26",
            ),
            (
                0x304c428,
                0x108,
                "133e3cc33141f0225592326dc7537d20669780c6e63ce836f16ef9c6a7c61b68",
            ),
            (
                0x304a288,
                0x94,
                "7984c104d25466e4633e24a2eda944cbdb0675eb8f7dd30e3fb4e867314afe7a",
            ),
        ] {
            assert_eq!(crate::sha256(&bytes[offset..offset + length]), expected);
        }
        assert_eq!(&bytes[0x775c08..0x775c10], b"devices\0");
        for (offset, expected) in [
            (0x3047b48, 0x52955568u32),
            (0x3047b4c, 0x72b55548u32),
            (0x3047b50, 0x9ba87c08u32),
            (0x3047b54, 0xd365fd09u32),
            (0x304a2c4, 0x79403428u32),
            (0x304a2cc, 0x3dc00820u32),
            (0x304a2f8, 0x79400828u32),
            (0x304a300, 0x79400c28u32),
            (0x304a308, 0x79401028u32),
            (0x304a310, 0x79401428u32),
        ] {
            assert_eq!(
                u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()),
                expected
            );
        }
    }

    #[test]
    fn layouts_preserve_every_parent_and_do_not_treat_cluster_bytes_as_flags() {
        let mut raw = [0; BYTES];
        raw[..4].copy_from_slice(&0x0700_0002u32.to_le_bytes());
        raw[ID16..ID16 + 2].copy_from_slice(&0x1234u16.to_le_bytes());
        for (pair, parent) in raw[4..12]
            .as_chunks_mut::<2>()
            .0
            .iter_mut()
            .zip([1u16, 0x234, 7, 9])
        {
            *pair = parent.to_le_bytes();
        }
        raw[16..20].copy_from_slice(&(2u32 << 24 | 0x12340).to_le_bytes());
        raw[32..].copy_from_slice(b"0123456789abcdef");
        let v2 = Record::parse(Layout::V2, &raw).unwrap();
        assert_eq!(
            (v2.id, v2.parents, v2.name),
            (0x1234, [1, 0x234, 7, 9], "0123456789abcdef")
        );
        assert_eq!(
            v2.location,
            Some(Location {
                group: 2,
                index: 0x2468
            })
        );
        raw[10] = 5;
        raw[11] = 3;
        let v1 = Record::parse(Layout::V1, &raw).unwrap();
        assert_eq!(v1.parents, [1, 0x234, 0, 0]);
        assert_eq!(v1.location, Some(Location { group: 3, index: 5 }));
        raw[ID16..ID16 + 2].fill(0);
        raw[3] = 0x7a;
        raw[4..8].copy_from_slice(&[1, 2, 3, 4]);
        let legacy = Record::parse(Layout::V1, &raw).unwrap();
        assert_eq!((legacy.id, legacy.parents), (0x7a, [1, 2, 3, 4]));
        // A v2 record still has four 16-bit parents when its ID falls back.
        raw[16..20].fill(0);
        assert_eq!(
            Record::parse(Layout::V2, &raw).unwrap().parents,
            [0x201, 0x403, 7, 0x305]
        );
    }

    #[test]
    fn invalid_native_sentinels_and_unknown_location_bits_refuse_but_virtual_records_have_no_bank()
    {
        let mut raw = [0; BYTES];
        raw[26] = 1;
        raw[4..6].copy_from_slice(&u16::MAX.to_le_bytes());
        assert!(Record::parse(Layout::V1, &raw).is_err());
        assert!(Record::parse(Layout::V2, &raw).is_err());
        raw[4..6].fill(0);
        raw[10] = 32;
        assert!(Record::parse(Layout::V1, &raw).is_err());
        raw[10] = 0;
        raw[11] = NO_GROUP;
        assert!(Record::parse(Layout::V1, &raw).is_err());
        raw[11] = 0;
        raw[16..20].copy_from_slice(&(NO_V2_INDEX << 3).to_le_bytes());
        assert!(Record::parse(Layout::V2, &raw).is_err());
        for low in 1..8u32 {
            raw[16..20].copy_from_slice(&low.to_le_bytes());
            assert!(Record::parse(Layout::V2, &raw).is_err());
        }
        raw[16..20].copy_from_slice(&(u32::from(NO_GROUP) << 24).to_le_bytes());
        assert!(Record::parse(Layout::V2, &raw).is_err());
        raw[0] = VIRTUAL;
        assert_eq!(Record::parse(Layout::V2, &raw).unwrap().location, None);
        raw[32] = 0xff;
        assert!(Record::parse(Layout::V2, &raw).is_err());
        assert!(Layout::select(None, None).is_err());
        assert!(Layout::select(Some(&[0; 12]), Some(&[0; 12])).is_err());
        assert_eq!(
            Layout::select(Some(&[]), Some(&[0; 12])).unwrap().0,
            Layout::V2
        );
        assert_eq!(Layout::select(Some(&[0; 12]), None).unwrap().0, Layout::V1);
    }
}
