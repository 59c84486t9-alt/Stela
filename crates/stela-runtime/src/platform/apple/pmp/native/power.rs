//! AP-visible PMP power group identities, independent of PMGR domain IDs.
//!
//! Original 26A434 ApplePMGR::_initPMPv2 uses 124-byte soc-device records;
//! _getPMPDeviceIndex reads raw PMGR descriptor byte 3, adds die times the
//! nub's soc-device-die-offset, then looks up the record ordinal. The
//! dashboard request/ACK bit is that ordinal, not either source/domain ID.
//! See docs/research/apple-mcc.md and the pinned original-source tests below.
use alloc::vec::Vec;

pub const RECORD_BYTES: usize = 124;
const SOURCE_IDS: u32 = 256;

/// The source record's distinct identities. Labels/FourCCs are not dispatch
/// keys. Flags retain their original bits without claiming a power effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Device {
    pub ordinal: u32,
    pub source_id: u32,
    pub flags: u32,
}
impl Device {
    pub fn request_bit(self) -> Result<u64, &'static str> {
        1u64.checked_shl(self.ordinal)
            .ok_or("PMP source ordinal exceeds one dashboard power vector")
    }
    /// AP flags+8 bit1 gates waiting for the separately published ACK. A
    /// source device without this flag still has no implied applied state.
    pub fn waits_for_ack(self) -> bool {
        self.flags & 2 != 0
    }
}

/// Owned original properties. This table supplies identities only: creating
/// it, resolving a group or receiving a request never publishes an ACK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceTable {
    records: Vec<[u32; RECORD_BYTES / 4]>,
    power_groups: u64,
    die_offset: Option<u32>,
}
impl DeviceTable {
    pub fn from_properties(
        records: &[u8],
        power_groups: &[u8],
        die_offset: Option<&[u8]>,
    ) -> Result<Self, &'static str> {
        if records.is_empty()
            || !records.len().is_multiple_of(RECORD_BYTES)
            || records.len() / RECORD_BYTES > SOURCE_IDS as usize
        {
            return Err("PMP soc-device is not a bounded whole 124-byte source table");
        }
        let power_groups = u64::from_le_bytes(
            power_groups
                .try_into()
                .map_err(|_| "PMP soc-device-ps-group must retain one complete 64-bit bitmap")?,
        );
        let die_offset = die_offset
            .map(|bytes| {
                bytes.try_into().map(u32::from_le_bytes).map_err(
                    |_| "PMP soc-device-die-offset must be one complete 32-bit source word",
                )
            })
            .transpose()?;
        let mut owned: Vec<[u32; RECORD_BYTES / 4]> = Vec::new();
        for bytes in records.as_chunks::<RECORD_BYTES>().0 {
            let record = core::array::from_fn(|i| {
                u32::from_le_bytes(bytes[i * 4..i * 4 + 4].try_into().unwrap())
            });
            if record[0] >= SOURCE_IDS || owned.iter().any(|previous| previous[0] == record[0]) {
                return Err("PMP soc-device source IDs are out of range or ambiguous");
            }
            owned.push(record);
        }
        if owned.len() < 64 && power_groups >> owned.len() != 0 {
            return Err("PMP power-state group bitmap names an absent source ordinal");
        }
        Ok(Self {
            records: owned,
            power_groups,
            die_offset,
        })
    }
    pub fn len(&self) -> usize {
        self.records.len()
    }
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
    pub fn power_group_mask(&self) -> u64 {
        self.power_groups
    }
    pub fn die_offset(&self) -> Option<u32> {
        self.die_offset
    }
    pub fn records(&self) -> &[[u32; RECORD_BYTES / 4]] {
        &self.records
    }
    pub fn device(&self, ordinal: u32) -> Option<Device> {
        self.records.get(ordinal as usize).map(|row| Device {
            ordinal,
            source_id: row[0],
            flags: row[2],
        })
    }
    /// A multi-die source without an offset selects separate PMP instances in
    /// the original AP driver. That placement needs its own instance owner;
    /// it cannot be flattened into one global source table with an invented
    /// stride. A single-die absent property is the original zero default.
    pub fn resolve(&self, source: u8, die: u32, die_count: u32) -> Result<Device, &'static str> {
        if die_count == 0 || die >= die_count {
            return Err("PMP domain die is outside the actual source topology");
        }
        if die_count > 1 && self.die_offset.is_none() {
            return Err("PMP multi-die source needs its distinct per-instance owner");
        }
        let source_id = die
            .checked_mul(self.die_offset.unwrap_or(0))
            .and_then(|offset| offset.checked_add(u32::from(source)))
            .filter(|id| *id < SOURCE_IDS)
            .ok_or("PMP die-qualified source ID exceeds the original 256-entry lookup")?;
        let ordinal = self
            .records
            .iter()
            .position(|row| row[0] == source_id)
            .ok_or("PMGR source has no matching PMP soc-device record")?;
        Ok(self.device(ordinal as u32).unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    fn records(ids: &[u32]) -> Vec<u8> {
        ids.iter()
            .enumerate()
            .flat_map(|(ordinal, id)| {
                let mut words = [0u32; RECORD_BYTES / 4];
                words[0] = *id;
                words[2] = ordinal as u32;
                words[3] = 14;
                words.into_iter().flat_map(u32::to_le_bytes)
            })
            .collect()
    }
    #[test]
    fn ordinal_source_and_domain_id_are_distinct_and_opaque_words_survive() {
        let table = DeviceTable::from_properties(
            &records(&[1, 2, 16, 17, 3, 4, 5]),
            &0x70u64.to_le_bytes(),
            None,
        )
        .unwrap();
        let dcs = table.resolve(1, 0, 1).unwrap();
        assert_eq!(
            dcs,
            Device {
                ordinal: 0,
                source_id: 1,
                flags: 0
            }
        );
        assert_eq!(dcs.request_bit(), Ok(1));
        let gfx = table.resolve(5, 0, 1).unwrap();
        assert_eq!(gfx.ordinal, 6);
        assert_eq!(gfx.request_bit(), Ok(1 << 6));
        assert!(gfx.waits_for_ack());
        assert_eq!(table.records()[1][3], 14);
        assert_eq!(table.power_group_mask(), 0x70);
        assert_eq!(table.len(), 7);
        assert!(!table.is_empty());
        assert!(table.resolve(14, 0, 1).is_err());
        assert!(table.resolve(1, 1, 1).is_err());
        assert!(table.resolve(1, 0, 0).is_err());
    }
    #[test]
    fn source_stride_is_explicit_and_missing_multi_instance_mapping_refuses() {
        let data = records(&[1, 65, 129]);
        let bitmap = 0u64.to_le_bytes();
        let table =
            DeviceTable::from_properties(&data, &bitmap, Some(&64u32.to_le_bytes())).unwrap();
        assert_eq!(table.die_offset(), Some(64));
        assert_eq!(table.resolve(1, 2, 3).unwrap().ordinal, 2);
        assert!(table.resolve(200, 1, 3).is_err());
        assert!(table.resolve(1, u32::MAX - 1, u32::MAX).is_err());
        let local = DeviceTable::from_properties(&data, &bitmap, None).unwrap();
        assert_eq!(local.die_offset(), None);
        assert!(local.resolve(1, 0, 2).is_err());
        assert_eq!(local.resolve(1, 0, 1).unwrap().ordinal, 0);
    }
    #[test]
    fn malformed_tables_and_ambiguous_source_records_cannot_create_groups() {
        for data in [
            vec![],
            vec![0; RECORD_BYTES - 1],
            records(&[1, 1]),
            records(&[256]),
            records(&(0..257).collect::<Vec<_>>()),
        ] {
            assert!(DeviceTable::from_properties(&data, &0u64.to_le_bytes(), None).is_err());
        }
        let data = records(&[1]);
        assert!(DeviceTable::from_properties(&data, &2u64.to_le_bytes(), None).is_err());
        assert!(DeviceTable::from_properties(&data, &[0; 7], None).is_err());
        assert!(DeviceTable::from_properties(&data, &[0; 8], Some(&[0; 3])).is_err());
        let table =
            DeviceTable::from_properties(&records(&(0..65).collect::<Vec<_>>()), &[0; 8], None)
                .unwrap();
        assert!(table.device(64).unwrap().request_bit().is_err());
        assert!(table.device(65).is_none());
    }

    #[test]
    #[cfg(feature = "std")]
    #[ignore = "requires original J473 DT and KC via STELA_TEST_MCC_J473_DT and STELA_TEST_MCC_J473_KERNELCACHE"]
    fn original_j473_power_vector_uses_source_ordinals_and_distinct_domain_ids() {
        use crate::machine::adt::Node;
        use sha2::{Digest, Sha256};
        let data = std::fs::read(std::env::var("STELA_TEST_MCC_J473_DT").unwrap()).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&data)),
            "a99fa2260f292236fbad210fcee380fc69f101e591125bce347819e84e68034c"
        );
        let root = Node::root(&data).unwrap();
        let io = root.child("arm-io").unwrap();
        let nub = io.child("pmp").unwrap().child("iop-pmp-nub").unwrap();
        let table = DeviceTable::from_properties(
            nub.property("soc-device").unwrap(),
            nub.property("soc-device-ps-group").unwrap(),
            nub.property("soc-device-die-offset"),
        )
        .unwrap();
        assert_eq!(table.len(), 18);
        assert_eq!(table.power_group_mask(), 0x3fff0);
        assert_eq!(table.die_offset(), None);
        for (source, ordinal) in [
            (1, 0),
            (2, 1),
            (16, 2),
            (17, 3),
            (3, 4),
            (4, 5),
            (5, 6),
            (18, 17),
        ] {
            let device = table.resolve(source, 0, 1).unwrap();
            assert_eq!(device.ordinal, ordinal);
            assert_eq!(device.request_bit(), Ok(1 << ordinal));
        }
        assert_eq!(table.records()[1][3], 14); // not PMGR's MCC domain 78
        let pmgr = io.child("pmgr").unwrap();
        let raw = pmgr.property("devices").unwrap();
        for (id, source) in [
            (78, 2),
            (79, 1),
            (86, 1),
            (121, 5),
            (123, 10),
            (368, 10),
            (370, 10),
        ] {
            let row = raw
                .as_chunks::<48>()
                .0
                .iter()
                .find(|row| u16::from_le_bytes(row[26..28].try_into().unwrap()) == id)
                .unwrap();
            assert_eq!(row[3], source);
        }
        let data =
            std::fs::read(std::env::var("STELA_TEST_MCC_J473_KERNELCACHE").unwrap()).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&data)),
            "06846c718a67715f540c7f5a5d5a183da6185d94b6fc01f1ce57a30b601be44d"
        );
        for (start, end, expected) in [
            (
                0x2b69e60,
                0x2b6a95c,
                "a7847c48e2670613253a622e3b5792c8aaf609152f2fc81a2fc202520dc106dd",
            ),
            (
                0x2ba1c84,
                0x2ba1d20,
                "1f5ea4dd72c5c5c06b4bd4e6af338a6bd5201fb5276227fac1021a4a5cf1f724",
            ),
            (
                0x2b98c6c,
                0x2b991b8,
                "4c0b27061c876d7ed15fb7d96a6aa130cd4804a01b0ed49ee5d5f7cabebf5597",
            ),
            (
                0x2b73d98,
                0x2b73e38,
                "4e154886e5a3fb83eb955682b2873bfbce0f118418c485c37fce67b40a88e52c",
            ),
        ] {
            assert_eq!(hex::encode(Sha256::digest(&data[start..end])), expected);
        }
    }
}
