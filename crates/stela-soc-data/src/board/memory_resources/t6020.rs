//! T602x original AP memory layout; parsing grants no native device admission.
//!
//! 26A434 mac14j AppleT6020MemCacheController::start file2ecb65c..2ecb6f0
//! subtracts two entries from the complete 16-byte reg count and passes the
//! sixteen-element array to _mapApertures (2ecbff0), whose source indices begin
//! at two. MCC reg0 is the PTD bank, reg1 a separate auxiliary bank. These
//! are not T6000 direct-aperture ordinals or its PMGR selector8 placement.
use super::{MemoryController, PtdBank, publication_ranges, range_at, reg_pairs, scalar};
use crate::Result;
use crate::mcc::t6020;
use alloc::{collections::BTreeSet, vec::Vec};
use stela_contracts::adt::Node;
use stela_contracts::refuse;

pub const COMPATIBLE: &str = "mcc,t6020";
const PREFIX_REGISTERS: usize = 2;
const AUXILIARY_BYTES: u64 = 0x149c;
const UPDATE_BYTES: u64 = 0x2000;

/// Every source requirement remains visible even when its service is refused.
/// In particular, mcache-pmp and the IRQ-resource words never become ACKs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct T6020Memory {
    pub apertures: Vec<u64>,
    pub auxiliary: (u64, u64),
    pub ptd: PtdBank,
    pub updates: (u64, u64),
    pub entries: usize,
    pub alternate_dram: Vec<u32>,
    pub mcache_pmp: Option<u32>,
    pub dsid_management: Option<u32>,
    pub thermal_loop: Option<u32>,
    pub memory_ranges: Vec<u32>,
    pub smc_ranges: Vec<u32>,
    pub command_entries: u32,
    pub command_ack_entries: u32,
    pub quota_request_entries: u32,
    pub quota_response_entries: u32,
}
impl T6020Memory {
    pub fn layout(&self) -> Result<t6020::Layout> {
        t6020::Layout::new(self.apertures.len())
    }
    pub fn validate(&self, locks: &MemoryController) -> Result<()> {
        self.validate_source()?;
        if self.apertures != locks.apertures
            || locks.layout.planes != u32::from(t6020::PLANES)
            || locks.layout.stride != t6020::PLANE_STRIDE
            || locks.layout.aperture_bytes > t6020::APERTURE_BYTES
        {
            return Err(refuse!(
                "T602x MCC and AMCC do not describe the same actual apertures/planes"
            ));
        }
        Ok(())
    }
    fn validate_source(&self) -> Result<()> {
        self.layout()?;
        let geometry =
            crate::ptd::Geometry::new((self.ptd.physical, crate::ptd::PTD_BYTES), self.updates)?;
        if geometry.entries() != self.entries
            || self.updates.1 != UPDATE_BYTES
            || self.auxiliary.1 != AUXILIARY_BYTES
            || self.alternate_dram.is_empty()
        {
            return Err(refuse!(
                "T602x memory descriptor differs from its source bank/update geometry"
            ));
        }
        if self.ptd.ranges.len() != self.ptd.interrupts.len() || self.ptd.ranges.is_empty() {
            return Err(refuse!(
                "T602x PTD must retain every original range and IRQ-resource word"
            ));
        }
        let mut physical = alloc::vec![(self.ptd.physical, crate::ptd::PTD_BYTES), self.auxiliary];
        physical.extend(self.apertures.iter().map(|&pa| (pa, t6020::APERTURE_BYTES)));
        for (index, &(start, bytes)) in physical.iter().enumerate() {
            let end = start
                .checked_add(bytes)
                .ok_or(refuse!("T602x memory aperture wraps"))?;
            if !start.is_multiple_of(4)
                || physical[..index].iter().any(|&(other, length)| {
                    other
                        .checked_add(length)
                        .is_none_or(|top| start < top && other < end)
                })
            {
                return Err(refuse!(
                    "T602x memory owners overlap or have invalid alignment"
                ));
            }
        }
        let mut ids = BTreeSet::new();
        let mut entries = BTreeSet::new();
        for range in &self.ptd.ranges {
            let end = range
                .start
                .checked_add(range.count)
                .ok_or(refuse!("T602x PTD range wraps"))?;
            if range.count == 0
                || end as usize > self.entries
                || !ids.insert(range.id)
                || range.name.len() > 16
                || range.name.as_bytes().contains(&0)
            {
                return Err(refuse!("T602x PTD range identity or capacity is invalid"));
            }
            for entry in range.start..end {
                if !entries.insert(entry) {
                    return Err(refuse!("T602x PTD ranges overlap"));
                }
            }
        }
        if self
            .memory_ranges
            .iter()
            .chain(&self.smc_ranges)
            .any(|id| !ids.contains(id))
        {
            return Err(refuse!(
                "T602x memory or SMC range names an absent PTD identity"
            ));
        }
        Ok(())
    }
}

fn words(node: &Node<'_>, name: &str) -> Result<Vec<u32>> {
    let raw = node
        .property(name)
        .ok_or_else(|| refuse!("T602x has no source {name}", name))?;
    if raw.is_empty() || !raw.len().is_multiple_of(4) {
        return Err(refuse!("T602x {name} is not complete source words", name));
    }
    Ok(raw
        .as_chunks::<4>()
        .0
        .iter()
        .map(|word| u32::from_le_bytes(*word))
        .collect())
}
fn optional_scalar(node: &Node<'_>, name: &str) -> Result<Option<u32>> {
    node.property(name).map(|_| scalar(node, name)).transpose()
}
fn unique_properties(node: &Node<'_>) -> Result<()> {
    let mut seen = BTreeSet::new();
    for (name, _) in node
        .properties()
        .ok_or(refuse!("T602x source properties are malformed"))?
    {
        if !seen.insert(name) {
            return Err(refuse!("T602x source owner has duplicate properties"));
        }
    }
    Ok(())
}
fn unique_child<'a>(parent: &Node<'a>, name: &str) -> Result<Option<Node<'a>>> {
    let mut children = parent
        .children()
        .ok_or(refuse!("T602x source children are malformed"))?
        .into_iter()
        .filter(|node| {
            node.property("name")
                .and_then(|raw| raw.split(|&byte| byte == 0).next())
                == Some(name.as_bytes())
        });
    let child = children.next();
    if children.next().is_some() {
        return Err(refuse!("T602x source has duplicate {name} owners", name));
    }
    Ok(child)
}

/// Decode physical views through the caller's complete parent-bus extent
/// witness. Numeric coincidence, a chip name or a missing parent is no witness.
pub fn from_io(
    io: &Node<'_>,
    translate: &dyn Fn(u64, u64) -> Option<u64>,
) -> Result<Option<T6020Memory>> {
    let Some(node) = unique_child(io, "mcc")?.filter(|node| node.compatible(COMPATIBLE)) else {
        return Ok(None);
    };
    unique_properties(&node)?;
    let count = reg_pairs(&node)?.len() / 16;
    let apertures = count.checked_sub(PREFIX_REGISTERS).ok_or(refuse!(
        "T602x MCC has no controller apertures after its two prefix banks"
    ))?;
    t6020::Layout::new(apertures)?;
    if scalar(&node, "pmp_ptd_reg_idx")? != 0
        || scalar(&node, "pmp_ptd_update_space_offset")? != crate::ptd::UPDATE_OFFSET as u32
    {
        return Err(refuse!(
            "T602x MCC PTD index/update alias is not its source profile"
        ));
    }
    let bank = range_at(&node, translate, 0)?;
    let auxiliary = range_at(&node, translate, 1)?;
    if bank.1 != crate::ptd::PTD_BYTES || auxiliary.1 != AUXILIARY_BYTES {
        return Err(refuse!(
            "T602x MCC prefix banks have unqualified source extents"
        ));
    }
    let apertures = (PREFIX_REGISTERS..count)
        .map(|index| {
            let (pa, bytes) = range_at(&node, translate, index)?;
            if bytes != t6020::APERTURE_BYTES {
                return Err(refuse!(
                    "T602x direct controller is not a complete source aperture"
                ));
            }
            Ok(pa)
        })
        .collect::<Result<Vec<_>>>()?;
    let pmp = unique_child(io, "pmp")?.ok_or(refuse!("T602x MCC has no source PMP owner"))?;
    unique_properties(&pmp)?;
    if pmp.property("ptd-driver-version").is_some() {
        return Err(refuse!(
            "T602x versioned PTD driver needs its separately qualified protocol"
        ));
    }
    let update_index = usize::try_from(scalar(&pmp, "ptd-update-reg-index")?)
        .map_err(|_| refuse!("T602x update register index overflows"))?;
    let updates = range_at(&pmp, translate, update_index)?;
    let geometry = crate::ptd::Geometry::new(bank, updates)?;
    if updates.1 != UPDATE_BYTES {
        return Err(refuse!(
            "T602x update alias has an unqualified physical capacity"
        ));
    }
    let nub = unique_child(&pmp, "iop-pmp-nub")?.ok_or(refuse!("T602x PMP has no source nub"))?;
    unique_properties(&nub)?;
    let (ranges, interrupts) = publication_ranges(
        nub.property("ptd-range")
            .ok_or(refuse!("T602x PMP has no PTD range records"))?,
        geometry.entries(),
    )?;
    let descriptor = T6020Memory {
        apertures,
        auxiliary,
        ptd: PtdBank {
            physical: bank.0,
            ranges,
            interrupts,
        },
        updates,
        entries: geometry.entries(),
        alternate_dram: words(&node, "dramcfg-data")?,
        mcache_pmp: optional_scalar(&node, "mcache-pmp")?,
        dsid_management: optional_scalar(&node, "dsid_mgmt")?,
        thermal_loop: optional_scalar(&node, "dcs-enable-thermal-loop")?,
        memory_ranges: words(&node, "ptd-ranges")?,
        smc_ranges: words(&node, "ptd-ranges-smc")?,
        command_entries: scalar(&nub, "mc_cmd_ptd_count")?,
        command_ack_entries: scalar(&nub, "mc_cmd_ack_ptd_count")?,
        quota_request_entries: scalar(&nub, "mc_quota_req_ptd_count")?,
        quota_response_entries: scalar(&nub, "mc_quota_rsp_ptd_count")?,
    };
    descriptor.validate_source()?;
    // Every field/physical extent is held above. Full AMCC and canonical
    // resource validation belongs to prepare; this returns source facts only.
    Ok(Some(descriptor))
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_contracts::adt::encode;
    fn z(s: &str) -> Vec<u8> {
        s.as_bytes().iter().copied().chain([0]).collect()
    }
    fn pairs(values: &[(u64, u64)]) -> Vec<u8> {
        values
            .iter()
            .flat_map(|&(a, b)| [a, b])
            .flat_map(u64::to_le_bytes)
            .collect()
    }
    fn fixture(apertures: usize, update_bytes: u64) -> Vec<u8> {
        let mut registers = alloc::vec![
            (0x8e3c0000, crate::ptd::PTD_BYTES),
            (0x8e4d0000, AUXILIARY_BYTES)
        ];
        registers.extend(
            (0..apertures).map(|i| (i as u64 * t6020::APERTURE_BYTES, t6020::APERTURE_BYTES)),
        );
        let mcc = encode(
            &[
                ("name", &z("mcc")),
                ("compatible", &z(COMPATIBLE)),
                ("reg", &pairs(&registers)),
                ("pmp_ptd_reg_idx", &0u32.to_le_bytes()),
                ("pmp_ptd_update_space_offset", &0x10000u32.to_le_bytes()),
                ("dramcfg-data", &0x133u32.to_le_bytes()),
                ("mcache-pmp", &1u32.to_le_bytes()),
                ("dsid_mgmt", &1u32.to_le_bytes()),
                ("dcs-enable-thermal-loop", &1u32.to_le_bytes()),
                ("ptd-ranges", &14u32.to_le_bytes()),
                ("ptd-ranges-smc", &14u32.to_le_bytes()),
            ],
            &[],
        );
        let mut record = Vec::new();
        for word in [14u32, 0, 1, 12] {
            record.extend(word.to_le_bytes());
        }
        record.extend(b"MC-DRV-TO-CTRL");
        record.resize(32, 0);
        let nub = encode(
            &[
                ("name", &z("iop-pmp-nub")),
                ("ptd-range", &record),
                ("mc_cmd_ptd_count", &2u32.to_le_bytes()),
                ("mc_cmd_ack_ptd_count", &1u32.to_le_bytes()),
                ("mc_quota_req_ptd_count", &8u32.to_le_bytes()),
                ("mc_quota_rsp_ptd_count", &8u32.to_le_bytes()),
            ],
            &[],
        );
        let pmp = encode(
            &[
                ("name", &z("pmp")),
                ("ptd-update-reg-index", &1u32.to_le_bytes()),
                (
                    "reg",
                    &pairs(&[(0x10000000, 0x10000), (0x8e3d0000, update_bytes)]),
                ),
            ],
            &[nub],
        );
        encode(&[("name", &z("arm-io"))], &[mcc, pmp])
    }
    #[test]
    fn prefix_banks_never_become_direct_apertures_or_pmgr_selector_eight() {
        for count in [4, 8, 16] {
            let bytes = fixture(count, UPDATE_BYTES);
            let io = Node::root(&bytes).unwrap();
            let descriptor = from_io(&io, &|pa, bytes| {
                pa.checked_add(bytes).map(|_| pa + 0x200000000)
            })
            .unwrap()
            .unwrap();
            assert_eq!(descriptor.apertures.len(), count);
            assert_eq!(descriptor.apertures[0], 0x200000000);
            assert_eq!(descriptor.ptd.physical, 0x28e3c0000);
            assert_eq!(descriptor.auxiliary, (0x28e4d0000, AUXILIARY_BYTES));
            assert_eq!(descriptor.entries, 1024);
            assert_eq!(descriptor.ptd.interrupts, [12]);
            assert_eq!(descriptor.mcache_pmp, Some(1));
            assert_eq!(descriptor.alternate_dram, [0x133]);
        }
    }
    #[test]
    fn missing_extent_and_other_profile_update_capacity_refuse() {
        let bytes = fixture(4, UPDATE_BYTES);
        let io = Node::root(&bytes).unwrap();
        assert!(from_io(&io, &|_, _| None).is_err());
        for size in [0xc00, 0x4000, 0x1fff] {
            let bytes = fixture(4, size);
            assert!(from_io(&Node::root(&bytes).unwrap(), &|pa, _| Some(pa)).is_err());
        }
    }
}
