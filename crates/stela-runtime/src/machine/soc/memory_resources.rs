//! Direct T6000 MCC placement, qualified independently of T8112's PMP service.
//! Descriptor parsing does not admit a native-memory completion capability.
use super::{MemoryController, PTD_RANGE, PtdBank};
use crate::{
    machine::adt::Node,
    platform::apple::{mcc, ptd},
};
use alloc::{collections::BTreeSet, format, string::String, vec::Vec};

const COMPATIBLE: &str = "mcc,t6000";
// Original AppleT6000PMGR::initRegMaps, KC 26A434 mac13j 0x2ef5300:
// selector8 is DT reg41. PMP's update alias independently cross-checks it.
const PTD_PMGR_REG: usize = 41;
const ENTRY_BYTES: u64 = 16;
const UPDATE_BYTES: u64 = 8;

/// Original descriptor inputs, not reset measurements or fabricated DRAM/cache
/// configuration. One owner must join these overlapping MCC/AMCC apertures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectMemoryCache {
    pub apertures: Vec<u64>,
    pub config_data: Vec<u32>,
    pub alternate_dram_configuration: u32,
    pub ptd: PtdBank,
    pub ptd_updates: (u64, u64),
    pub ptd_entries: usize,
}

impl DirectMemoryCache {
    /// Recheck public descriptor values before allocating actual owners. This
    /// also protects callers constructing a descriptor without the ADT parser.
    pub fn validate(&self, locks: &MemoryController) -> Result<(), &'static str> {
        if self.apertures.is_empty()
            || self.apertures.len() > 16
            || self.apertures != locks.apertures
            || locks.layout.planes != u32::from(mcc::PLANES)
            || locks.layout.stride != mcc::PLANE_STRIDE
            || locks.layout.aperture_bytes > mcc::APERTURE_BYTES
            || self.config_data.is_empty()
            || self.ptd.ranges.len() != self.ptd.interrupts.len()
        {
            return Err("direct MCC descriptor does not match actual memory resources");
        }
        let ptd_end = self
            .ptd
            .physical
            .checked_add(ptd::PTD_BYTES)
            .ok_or("PTD bank end overflows")?;
        let update_start = self
            .ptd
            .physical
            .checked_add(ptd::UPDATE_OFFSET)
            .ok_or("PTD update start overflows")?;
        let update_end = self
            .ptd_updates
            .0
            .checked_add(self.ptd_updates.1)
            .ok_or("PTD update end overflows")?;
        if self.ptd_entries == 0
            || self.ptd_updates.0 != update_start
            || update_end > ptd_end
            || u64::try_from(self.ptd_entries)
                .ok()
                .and_then(|n| n.checked_mul(UPDATE_BYTES))
                != Some(self.ptd_updates.1)
            || u64::try_from(self.ptd_entries)
                .ok()
                .and_then(|n| n.checked_mul(ENTRY_BYTES))
                .is_none_or(|bytes| bytes > ptd::UPDATE_OFFSET)
        {
            return Err("PTD publication/update capacity is inconsistent");
        }
        let mut mapped = Vec::new();
        for &pa in &self.apertures {
            let end = pa
                .checked_add(mcc::APERTURE_BYTES)
                .ok_or("MCC aperture end overflows")?;
            if mapped.iter().any(|&(other, last)| pa < last && other < end)
                || (pa < ptd_end && self.ptd.physical < end)
            {
                return Err("direct memory resource apertures overlap");
            }
            mapped.push((pa, end));
        }
        let mut ids = BTreeSet::new();
        let mut entries = BTreeSet::new();
        for range in &self.ptd.ranges {
            let end = range
                .start
                .checked_add(range.count)
                .ok_or("PTD range end overflows")?;
            if range.count == 0
                || usize::try_from(end).map_or(true, |end| end > self.ptd_entries)
                || !ids.insert(range.id)
                || range.name.len() > 16
                || range.name.as_bytes().contains(&0)
            {
                return Err("PTD range identity/capacity is invalid");
            }
            for entry in range.start..end {
                if !entries.insert(entry) {
                    return Err("PTD ranges overlap");
                }
            }
        }
        if ids.is_empty() {
            return Err("PTD ranges are absent");
        }
        Ok(())
    }
}

fn scalar(node: &Node<'_>, name: &str) -> Result<u32, String> {
    let bytes = node
        .property(name)
        .filter(|bytes| bytes.len() == 4)
        .ok_or_else(|| format!("memory resource {name} is not one u32"))?;
    Ok(u32::from_le_bytes(bytes.try_into().expect("checked u32")))
}
fn reg_pairs<'a>(node: &Node<'a>) -> Result<&'a [u8], String> {
    node.property("reg")
        .filter(|raw| !raw.is_empty() && raw.len().is_multiple_of(16))
        .ok_or_else(|| "memory resource reg is not whole address/size pairs".into())
}
fn range_at(
    node: &Node<'_>,
    translate: &dyn Fn(u64, u64) -> Option<u64>,
    index: usize,
) -> Result<(u64, u64), String> {
    let pair = reg_pairs(node)?
        .as_chunks::<16>()
        .0
        .get(index)
        .ok_or("selected memory resource reg is absent")?;
    let address = u64::from_le_bytes(pair[..8].try_into().expect("u64"));
    let bytes = u64::from_le_bytes(pair[8..].try_into().expect("u64"));
    let physical =
        translate(address, bytes).ok_or("selected memory resource outside arm-io ranges")?;
    if bytes == 0 || address.checked_add(bytes).is_none() || physical.checked_add(bytes).is_none() {
        return Err(
            "selected memory resource range is empty, overflowing or has inconsistent translation"
                .into(),
        );
    }
    Ok((physical, bytes))
}
fn ranges(
    node: &Node<'_>,
    translate: &dyn Fn(u64, u64) -> Option<u64>,
) -> Result<Vec<(u64, u64)>, String> {
    (0..reg_pairs(node)?.len() / 16)
        .map(|index| range_at(node, translate, index))
        .collect()
}

/// Retain all four header words; the interrupt resource is not an AIC number.
/// Reject overlaps and malformed strings instead of silently truncating records.
pub(super) fn publication_ranges(
    records: &[u8],
    entries: usize,
) -> Result<(Vec<ptd::Range>, Vec<u32>), String> {
    if records.is_empty() || !records.len().is_multiple_of(PTD_RANGE) {
        return Err("PMP PTD descriptors are not whole nonempty records".into());
    }
    let mut ids = BTreeSet::new();
    let mut used = BTreeSet::new();
    let mut ranges = Vec::new();
    let mut interrupts = Vec::new();
    for record in records.as_chunks::<PTD_RANGE>().0 {
        let word = |at| u32::from_le_bytes(record[at..at + 4].try_into().expect("u32"));
        let (id, start, count, interrupt) = (word(0), word(4), word(8), word(12));
        let end = start.checked_add(count).ok_or("PTD range end overflows")?;
        if count == 0 || usize::try_from(end).map_or(true, |end| end > entries) || !ids.insert(id) {
            return Err("PTD range is empty, duplicate or outside its real bank".into());
        }
        for entry in start..end {
            if !used.insert(entry) {
                return Err("PTD ranges overlap".into());
            }
        }
        let name = &record[16..];
        let end = name
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(name.len());
        let name = core::str::from_utf8(&name[..end]).map_err(|_| "PTD range name is not UTF-8")?;
        ranges.push(ptd::Range {
            id,
            start,
            count,
            name: name.into(),
        });
        interrupts.push(interrupt);
    }
    Ok((ranges, interrupts))
}

pub(super) fn direct_memory_cache(
    io: &Node<'_>,
    translate: &dyn Fn(u64, u64) -> Option<u64>,
    controller: Option<&MemoryController>,
) -> Result<Option<DirectMemoryCache>, String> {
    let Some(node) = io.child("mcc").filter(|node| node.compatible(COMPATIBLE)) else {
        return Ok(None);
    };
    let controller = controller.ok_or("T6000 MCC has no actual AMCC descriptor")?;
    let apertures = ranges(&node, translate)?;
    if apertures.is_empty()
        || apertures.len() > 16
        || apertures.len() != controller.apertures.len()
        || apertures
            .iter()
            .zip(&controller.apertures)
            .any(|(&(pa, bytes), &lock_pa)| pa != lock_pa || bytes != mcc::APERTURE_BYTES)
        || controller.layout.planes != u32::from(mcc::PLANES)
        || controller.layout.stride != mcc::PLANE_STRIDE
        || controller.layout.aperture_bytes > mcc::APERTURE_BYTES
    {
        return Err("T6000 MCC and AMCC do not describe the same actual apertures/planes".into());
    }
    for (index, &(start, bytes)) in apertures.iter().enumerate() {
        if apertures[..index]
            .iter()
            .any(|&(other, len)| start < other + len && other < start + bytes)
        {
            return Err("T6000 MCC apertures overlap".into());
        }
    }
    let config = node
        .property("config-data")
        .filter(|data| !data.is_empty() && data.len().is_multiple_of(4))
        .ok_or("T6000 MCC config-data has a partial or missing source word")?;
    let config_data = config
        .as_chunks::<4>()
        .0
        .iter()
        .map(|word| u32::from_le_bytes(*word))
        .collect();
    let pmp = io
        .child("pmp")
        .ok_or("T6000 MCC has no PMP transport descriptor")?;
    if pmp.property("ptd-driver-version").is_some() {
        return Err("PMP versioned PTD routing requires a separately qualified layout".into());
    }
    let pmgr = io
        .child("pmgr")
        .ok_or("T6000 PMP PTD has no PMGR selector8 owner")?;
    // PMGR reg3/reg6 are original zero-length sentinels. Validate the
    // selected actual owner, not unrelated slots that are never mounted here.
    let bank = range_at(&pmgr, translate, PTD_PMGR_REG)?;
    if bank.1 != ptd::PTD_BYTES {
        return Err("T6000 PTD selector8 is not one complete bank".into());
    }
    let index = usize::try_from(scalar(&pmp, "ptd-update-reg-index")?)
        .map_err(|_| "PMP update reg index overflows")?;
    let updates = range_at(&pmp, translate, index)?;
    if updates.0 != bank.0 + ptd::UPDATE_OFFSET
        || updates.1 == 0
        || !updates.1.is_multiple_of(UPDATE_BYTES)
        || updates.0 + updates.1 > bank.0 + ptd::PTD_BYTES
    {
        return Err("PMP update alias does not fit the actual selector8 bank".into());
    }
    let entries =
        usize::try_from(updates.1 / UPDATE_BYTES).map_err(|_| "PTD entry count overflows")?;
    if u64::try_from(entries)
        .ok()
        .and_then(|entries| entries.checked_mul(ENTRY_BYTES))
        .is_none_or(|bytes| bytes > ptd::UPDATE_OFFSET)
    {
        return Err("PMP publication entries overlap the update alias".into());
    }
    let records = pmp
        .child("iop-pmp-nub")
        .and_then(|nub| nub.property("ptd-range"))
        .ok_or("PMP nub has no PTD range records")?;
    let (ranges, interrupts) = publication_ranges(records, entries)?;
    let resource = DirectMemoryCache {
        apertures: apertures.into_iter().map(|(pa, _)| pa).collect(),
        config_data,
        alternate_dram_configuration: scalar(&node, "dramcfg-data")?,
        ptd: PtdBank {
            physical: bank.0,
            ranges,
            interrupts,
        },
        ptd_updates: updates,
        ptd_entries: entries,
    };
    resource.validate(controller).map_err(String::from)?;
    Ok(Some(resource))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::adt::encode;
    use crate::machine::soc::tests::flat_fixture_extent;
    use alloc::vec;

    fn tree(reg_suffix: &[u8], update_bytes: u64, interrupt: u32) -> Vec<u8> {
        let mut regs = Vec::new();
        for aperture in 0..4u64 {
            regs.extend((aperture * mcc::APERTURE_BYTES).to_le_bytes());
            regs.extend(mcc::APERTURE_BYTES.to_le_bytes());
        }
        regs.extend(reg_suffix);
        let mcc = encode(
            &[
                ("name", b"mcc\0"),
                ("compatible", b"mcc,t6000\0"),
                ("reg", &regs),
                ("config-data", &1u32.to_le_bytes()),
                ("dramcfg-data", &u32::MAX.to_le_bytes()),
            ],
            &[],
        );
        let mut pmgr_regs = Vec::new();
        for index in 0..42 {
            pmgr_regs.extend(
                (if [3, 6].contains(&index) {
                    0xffffffffu64
                } else if index == 41 {
                    0x8e3c0000u64
                } else {
                    0x90000000 + index * 0x1000
                })
                .to_le_bytes(),
            );
            pmgr_regs.extend(
                (if [3, 6].contains(&index) {
                    0u64
                } else if index == 41 {
                    ptd::PTD_BYTES
                } else {
                    0x1000u64
                })
                .to_le_bytes(),
            );
        }
        let pmgr = encode(&[("name", b"pmgr\0"), ("reg", &pmgr_regs)], &[]);
        let mut records = [0; PTD_RANGE];
        for (index, word) in [1u32, 376, 1, interrupt].into_iter().enumerate() {
            records[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        records[16..20].copy_from_slice(b"TEST");
        let nub = encode(&[("name", b"iop-pmp-nub\0"), ("ptd-range", &records)], &[]);
        let mut reg = 0x8e3d0000u64.to_le_bytes().to_vec();
        reg.extend(update_bytes.to_le_bytes());
        let pmp = encode(
            &[
                ("name", b"pmp\0"),
                ("reg", &reg),
                ("ptd-update-reg-index", &0u32.to_le_bytes()),
            ],
            &[nub],
        );
        encode(
            &[("name", b"root\0")],
            &[encode(&[("name", b"arm-io\0")], &[mcc, pmgr, pmp])],
        )
    }
    fn locks() -> MemoryController {
        use crate::platform::apple::amcc::{Layout, LockGroup, Register};
        let reg = |offset, mask, value| Register {
            offset,
            mask,
            value,
        };
        MemoryController {
            apertures: (0..4)
                .map(|n| 0x200000000 + n * mcc::APERTURE_BYTES)
                .collect(),
            layout: Layout {
                aperture_bytes: 0x200000,
                planes: 4,
                stride: mcc::PLANE_STRIDE,
                cache_status: Some(reg(0x10000c, 1, 1)),
                dram_base: 0x800000000,
                groups: [
                    Some(LockGroup {
                        page_size_shift: 14,
                        lower_limit: reg(0x680, u32::MAX, 0),
                        upper_limit: reg(0x684, u32::MAX, 0),
                        enable: Some(reg(0x688, 1, 1)),
                        write_disable: None,
                        lock: Some(reg(0x68c, 1, 1)),
                    }),
                    None,
                    None,
                    None,
                ],
            },
        }
    }
    #[test]
    fn direct_descriptor_preserves_real_bank_capacity_and_interrupt_identity() {
        let bytes = tree(&[], 0xc00, 14);
        let io = Node::root(&bytes).unwrap().child("arm-io").unwrap();
        let owner = direct_memory_cache(
            &io,
            &flat_fixture_extent(&|pa| pa.checked_add(0x200000000)),
            Some(&locks()),
        )
        .unwrap()
        .unwrap();
        assert_eq!(owner.ptd_entries, 384);
        assert_eq!(owner.ptd.ranges[0].start, 376);
        assert_eq!(owner.ptd.interrupts, vec![14]);
        assert_eq!(owner.ptd.physical, 0x28e3c0000);
        assert_eq!(owner.ptd_updates, (0x28e3d0000, 0xc00));
        assert_eq!(owner.alternate_dram_configuration, u32::MAX);
        assert_eq!(owner.config_data, vec![1]);
        assert_eq!(owner.apertures.len(), 4);
        for (suffix, size) in [
            (&[0][..], 0xc00),
            (&[][..], 0xc01),
            (&[][..], 0x100000),
            (&[][..], 0x800),
        ] {
            let bytes = tree(suffix, size, 14);
            let io = Node::root(&bytes).unwrap().child("arm-io").unwrap();
            assert!(
                direct_memory_cache(
                    &io,
                    &flat_fixture_extent(&|pa| pa.checked_add(0x200000000)),
                    Some(&locks())
                )
                .is_err()
            );
        }
        assert!(
            direct_memory_cache(
                &io,
                &flat_fixture_extent(&|pa| pa.checked_add(0x200000000)),
                None
            )
            .is_err()
        );
    }
    #[test]
    fn public_descriptor_revalidation_rejects_forged_capacity_and_ownership() {
        let bytes = tree(&[], 0xc00, 14);
        let io = Node::root(&bytes).unwrap().child("arm-io").unwrap();
        let locks = locks();
        let descriptor = direct_memory_cache(
            &io,
            &flat_fixture_extent(&|pa| pa.checked_add(0x200000000)),
            Some(&locks),
        )
        .unwrap()
        .unwrap();
        let mut invalid = descriptor.clone();
        invalid.ptd_entries = 377;
        assert!(invalid.validate(&locks).is_err());
        let mut invalid = descriptor.clone();
        invalid.ptd.interrupts.clear();
        assert!(invalid.validate(&locks).is_err());
        let mut invalid = descriptor.clone();
        invalid.ptd.physical = u64::MAX - 4;
        assert!(invalid.validate(&locks).is_err());
        let mut invalid = descriptor.clone();
        invalid.ptd.physical = locks.apertures[0];
        invalid.ptd_updates.0 = invalid.ptd.physical + ptd::UPDATE_OFFSET;
        assert!(invalid.validate(&locks).is_err());
        let mut invalid = descriptor;
        invalid.ptd.ranges.push(invalid.ptd.ranges[0].clone());
        invalid.ptd.interrupts.push(0);
        assert!(invalid.validate(&locks).is_err());
    }

    #[test]
    #[cfg(feature = "std")]
    #[ignore = "requires the pinned original J314s ADT via STELA_T6000_MCC_DEVICE_TREE"]
    fn original_j314s_descriptor_preserves_all_physical_slots_and_irq_words() {
        let input =
            std::env::var("STELA_T6000_MCC_DEVICE_TREE").expect("explicit original ADT input");
        let bytes = std::fs::read(&input).unwrap();
        let hash = crate::sha256(&bytes);
        assert_eq!(
            hash,
            "44fa41bfd0fe0027fd862b8615ae956885614636625d44a59cab226d682558ad"
        );
        let io = Node::root(&bytes).unwrap().child("arm-io").unwrap();
        let descriptor = direct_memory_cache(
            &io,
            &|address, bytes| io.translate_range(address, bytes),
            Some(&locks()),
        )
        .unwrap()
        .unwrap();
        assert_eq!(descriptor.ptd_entries, 384);
        assert_eq!(descriptor.ptd.ranges.len(), 19);
        assert_eq!(descriptor.ptd.interrupts.len(), 19);
        assert_eq!(
            descriptor
                .ptd
                .ranges
                .iter()
                .map(|range| range.start + range.count)
                .max(),
            Some(377)
        );
        assert_eq!(descriptor.config_data.len(), 50);
        std::println!("original_input={input} sha256={hash}\n{descriptor:#?}");
    }

    #[test]
    fn publication_descriptors_reject_overlap_duplicate_ids_partial_words_and_bad_names() {
        let mut raw = [0u8; PTD_RANGE];
        raw[..4].copy_from_slice(&1u32.to_le_bytes());
        raw[8..12].copy_from_slice(&1u32.to_le_bytes());
        assert!(publication_ranges(&raw, 1).is_ok());
        assert!(publication_ranges(&[raw, raw].concat(), 2).is_err());
        assert!(publication_ranges(&raw[..31], 1).is_err());
        raw[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(publication_ranges(&raw, 2).is_err());
        raw[4..8].fill(0);
        raw[16] = 0xff;
        assert!(publication_ranges(&raw, 1).is_err());
    }
}
