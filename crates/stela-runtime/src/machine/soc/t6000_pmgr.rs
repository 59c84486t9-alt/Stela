//! Explicit T6000 source descriptors, independent of public PMGR admission.
use super::{Node, PowerStates, power_resources};
use crate::platform::apple::{
    bridge::Bridge,
    pmgr::t6000::{self, tunables},
};
use alloc::{format, string::String, vec::Vec};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeDescriptor {
    pub id: usize,
    pub view: t6000::View,
    pub header: [u8; 4],
    pub configs: Vec<[u8; 36]>,
    pub axi: Option<[u8; 4]>,
    pub devices: Vec<u8>,
}

/// Every original view and ownership requirement; this supplies no live value,
/// lifecycle credit, hardware trigger or permission to publish ApplePMGR.
pub struct Descriptor {
    pub registers: Vec<Option<(u64, u64)>>,
    pub bridges: Vec<BridgeDescriptor>,
    pub optional_bridges: Vec<u8>,
    pub tuning: tunables::Profile,
    pub power: PowerStates,
    /// Original graph qualification, independent of resource word ownership.
    pub coverage_requirement: Option<String>,
    pub source_sha256: String,
}
impl Descriptor {
    /// Guard facts are independently supplied. In particular platform_revision
    /// is not converted into the native raw revision used to select iBootData.
    pub fn parse(
        tree: &[u8],
        chip: u16,
        board: u32,
        platform_revision: u32,
    ) -> Result<Self, String> {
        let tuning = tunables::Profile::new(u32::from(chip), board, platform_revision)
            .map_err(String::from)?;
        let root = Node::root(tree).ok_or("T6000 requires the complete source ADT")?;
        let io = root
            .child("arm-io")
            .ok_or("T6000 source ADT has no arm-io")?;
        let node = io
            .child("pmgr")
            .filter(|n| n.compatible("pmgr1,t6000"))
            .ok_or("T6000 requires its retained original PMGR descriptor")?;
        let translate = |offset, bytes| io.translate_range(offset, bytes);
        let word = |key| -> Result<u32, String> {
            let value: [u8; 4] = node
                .property(key)
                .ok_or_else(|| format!("T6000 PMGR has no {key}"))?
                .try_into()
                .map_err(|_| format!("T6000 PMGR {key} is not a full word"))?;
            Ok(u32::from_le_bytes(value))
        };
        let raw = node
            .property("reg")
            .ok_or("T6000 PMGR has no original register list")?;
        if !raw.len().is_multiple_of(16) {
            return Err("T6000 PMGR reg has partial pairs".into());
        }
        let mut registers = Vec::new();
        for pair in raw.as_chunks::<16>().0 {
            let offset = u64::from_le_bytes(pair[..8].try_into().unwrap());
            let bytes = u64::from_le_bytes(pair[8..].try_into().unwrap());
            // Empty original ordinal slots carry no physical view. Layout
            // still rejects one if any bound selector or bridge needs it.
            if bytes == 0 {
                registers.push(None);
                continue;
            }
            let physical = translate(offset, bytes)
                .ok_or("T6000 PMGR register extent crosses its actual bus domain")?;
            registers.push(Some((physical, bytes)));
        }
        let layout = t6000::Layout::new(
            &registers,
            word("bridge-reg-index")? as usize,
            word("#bridges")? as usize,
        )
        .map_err(String::from)?;
        if word("bridge-settings-version")? != 1 || word("bridge-counter-version")? != 3 {
            return Err("T6000 bridge descriptor versions are unqualified".into());
        }
        let optional = node
            .property("optional-bridge-mask")
            .ok_or("T6000 source optional bridge bitmap is missing")?
            .to_vec();
        tunables::Selection::new(tuning, &optional).map_err(String::from)?;
        let headers = node
            .property("bridge-counters")
            .ok_or("T6000 bridge headers are missing")?;
        let configs = node
            .property("bridge-counter-configs")
            .ok_or("T6000 bridge configs are missing")?;
        let dependencies = node
            .property("device-bridges")
            .ok_or("T6000 bridge dependencies are missing")?;
        let axi = node.property("axi2af-axi-config");
        if headers.len() != t6000::BRIDGE_COUNT * 4
            || !configs.len().is_multiple_of(36)
            || !dependencies.len().is_multiple_of(76)
            || axi.is_some_and(|v| v.len() != t6000::BRIDGE_COUNT * 4)
        {
            return Err("T6000 bridge descriptors have partial rows or wrong counts".into());
        }
        let mut bridges = Vec::new();
        for id in 0..t6000::BRIDGE_COUNT {
            let view = layout.bridge(id).map_err(String::from)?;
            let header: [u8; 4] = headers[id * 4..id * 4 + 4].try_into().unwrap();
            let first = usize::from(header[2]);
            let end = first + usize::from(header[3]);
            let selected = configs
                .as_chunks::<36>()
                .0
                .get(first..end)
                .ok_or("T6000 bridge header exceeds actual configurations")?
                .to_vec();
            let axi = axi.map(|bytes| bytes[id * 4..id * 4 + 4].try_into().unwrap());
            let model =
                Bridge::t6000(tuning, id, header, &selected, axi, &[]).map_err(String::from)?;
            for (offset, bytes) in model.spans() {
                if offset.checked_add(bytes).is_none_or(|end| end > view.bytes)
                    || view.physical.checked_add(offset + bytes).is_none()
                {
                    return Err("T6000 bridge word exceeds its actual source aperture".into());
                }
            }
            let mut devices = Vec::new();
            for row in dependencies.as_chunks::<76>().0 {
                for (slot, &parent) in row[4..].iter().enumerate() {
                    if slot != 0 && parent == 0 {
                        break;
                    }
                    if usize::from(parent) >= t6000::BRIDGE_COUNT {
                        return Err("T6000 dependency names an absent bridge".into());
                    }
                    if usize::from(parent) == id && !devices.contains(&row[3]) {
                        devices.push(row[3]);
                    }
                }
            }
            bridges.push(BridgeDescriptor {
                id,
                view,
                header,
                configs: selected,
                axi,
                devices,
            });
        }
        let power = power_resources::source_power_states(&root, &node, &translate)?;
        let coverage_requirement = power_resources::validate_power_graph(&power).err();
        Ok(Self {
            registers,
            bridges,
            optional_bridges: optional,
            tuning,
            power,
            coverage_requirement,
            source_sha256: crate::sha256(tree),
        })
    }
    pub fn layout(&self) -> Result<t6000::Layout<'_>, &'static str> {
        t6000::Layout::new(
            &self.registers,
            t6000::BRIDGE_REG_INDEX,
            t6000::BRIDGE_COUNT,
        )
    }
}

#[cfg(all(test, feature = "std"))]
mod original {
    use super::*;
    use crate::platform::apple::{
        cluster::t6000::{Complex, T6000},
        power::t6000::native,
    };
    #[test]
    #[ignore = "requires pinned original J314s ADT through STELA_TEST_PMGR_M1_ADT"]
    fn original_complete_descriptor_and_sparse_ownership_have_no_fabricated_state() {
        let data = std::fs::read(std::env::var("STELA_TEST_PMGR_M1_ADT").unwrap()).unwrap();
        assert_eq!(
            crate::sha256(&data),
            "44fa41bfd0fe0027fd862b8615ae956885614636625d44a59cab226d682558ad"
        );
        let d = Descriptor::parse(&data, 0x6000, 8, 0).unwrap();
        assert_eq!(d.registers.len(), 241);
        assert_eq!(d.bridges.len(), 193);
        assert_eq!(d.power.registers.len(), 196);
        assert!(
            d.coverage_requirement
                .as_ref()
                .unwrap()
                .contains("device: 197")
        );
        let layout = d.layout().unwrap();
        let mut spans = Vec::new();
        for complex in [
            Complex::Efficiency,
            Complex::Performance0,
            Complex::Performance1,
        ] {
            let model = T6000::new(complex, 16, &[]).unwrap();
            for offset in model.offsets() {
                let pa = layout.acc(complex.index(), offset as u32, 8).unwrap();
                spans.push((pa, pa + 8, format!("cluster {:?} {offset:x}", complex)));
            }
        }
        for bank in &d.bridges {
            let model = Bridge::t6000(d.tuning, bank.id, bank.header, &bank.configs, bank.axi, &[])
                .unwrap();
            for (offset, bytes) in model.spans() {
                spans.push((
                    bank.view.physical + offset,
                    bank.view.physical + offset + bytes,
                    format!("bridge {} {offset:x}", bank.id),
                ));
            }
        }
        for word in native::controls() {
            spans.push((
                word.address,
                word.address + 4,
                format!("native {:x}", word.address),
            ));
        }
        spans.push((0x292f00000, 0x292f70000, String::from("native SRAM")));
        spans.sort_by_key(|s| s.0);
        let collisions = spans
            .windows(2)
            .filter(|s| s[0].1 > s[1].0)
            .collect::<Vec<_>>();
        println!(
            "descriptor: views={} bridges={} power={} sparse={} collisions={collisions:?}",
            d.registers.len(),
            d.bridges.len(),
            d.power.registers.len(),
            spans.len()
        );
        assert!(
            collisions.is_empty(),
            "source-qualified sparse owners overlap"
        );
    }
    #[test]
    #[ignore = "requires pinned original J314s ADT through STELA_TEST_PMGR_M1_ADT"]
    fn original_descriptor_rejects_incomplete_or_crossed_resource_owners() {
        let original = std::fs::read(std::env::var("STELA_TEST_PMGR_M1_ADT").unwrap()).unwrap();
        assert_eq!(
            crate::sha256(&original),
            "44fa41bfd0fe0027fd862b8615ae956885614636625d44a59cab226d682558ad"
        );
        fn offset(bytes: &[u8], property: &str) -> usize {
            let root = Node::root(bytes).unwrap();
            let io = root.child("arm-io").unwrap();
            let node = io.child("pmgr").unwrap();
            node.property(property).unwrap().as_ptr() as usize - bytes.as_ptr() as usize
        }
        let mut bytes = original.clone();
        let reg = offset(&bytes, "reg");
        // A required actual RegMap ordinal cannot become an empty slot.
        bytes[reg + 8..reg + 16].copy_from_slice(&0u64.to_le_bytes());
        assert!(Descriptor::parse(&bytes, 0x6000, 8, 0).is_err());
        let mut bytes = original.clone();
        // A view whose start is valid must still fit the same translated bus range.
        bytes[reg + 8..reg + 16].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(Descriptor::parse(&bytes, 0x6000, 8, 0).is_err());
        let mut bytes = original.clone();
        let counter = offset(&bytes, "bridge-counters");
        bytes[counter + 2..counter + 4].copy_from_slice(&[255, 255]);
        assert!(Descriptor::parse(&bytes, 0x6000, 8, 0).is_err());
        assert!(Descriptor::parse(&original, 0x6001, 8, 0).is_err());
        assert!(Descriptor::parse(&original, 0x6000, 8, 0x20).is_err());
    }
}
