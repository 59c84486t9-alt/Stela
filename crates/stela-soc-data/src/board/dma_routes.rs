//! DeviceTree placement and validation for dma routes.
use super::{Iommu, Node, String, Vec, format};

/// Declared mapper context and its assigned incoming native DMA stream.
/// This does not resolve a buffer address, strip a relocation tag, or grant
/// access without the placed DART and its live translation tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeDmaRoute {
    pub mapper: u32,
    pub iommu: usize,
    pub instance: usize,
    pub context: u32,
    pub stream: u32,
}

pub(super) fn native_dma_route(darts: &[Iommu], mapper: u32) -> Result<NativeDmaRoute, String> {
    let mut found = darts.iter().enumerate().flat_map(|(index, dart)| {
        dart.mappers
            .iter()
            .filter(move |(phandle, _)| *phandle == mapper)
            .map(move |&(_, context)| (index, dart, context))
    });
    let (iommu, dart, context) = found.next().ok_or("mapper is not mounted")?;
    if mapper == 0 || found.next().is_some() {
        return Err("mapper ownership is zero or ambiguous".into());
    }
    if dart.instances.len() != 1 {
        return Err("DMA owner requires explicit multiple-TRAD selection".into());
    }
    Ok(NativeDmaRoute {
        mapper,
        iommu,
        instance: 0,
        context,
        stream: native_mapper_input(dart, context)?,
    })
}

/// Owner properties are one nonzero phandle, never a truncated first word.
pub(super) fn native_dma_phandle(node: &Node<'_>, key: &str) -> Result<Option<u32>, String> {
    node.property(key)
        .map(|bytes| {
            let value: [u8; 4] = bytes
                .try_into()
                .map_err(|_| format!("{key} is not one native DMA owner phandle"))?;
            let value = u32::from_le_bytes(value);
            if value == 0 {
                return Err(format!("{key} native DMA owner phandle is zero"));
            }
            Ok(value)
        })
        .transpose()
}

/// Display pipes declare primary and PIODMA mapper parents in order.
pub(super) fn native_dma_mapper_list(node: &Node<'_>, key: &str) -> Result<Vec<u32>, String> {
    let Some(bytes) = node.property(key) else {
        return Ok(Vec::new());
    };
    if bytes.is_empty() || !bytes.len().is_multiple_of(4) {
        return Err(format!("{key} is not a complete native DMA mapper list"));
    }
    let mut parents = Vec::new();
    for word in bytes.as_chunks::<4>().0 {
        let parent = u32::from_le_bytes(*word);
        if parent == 0 || parents.contains(&parent) {
            return Err(format!("{key} has a zero or duplicate native DMA mapper"));
        }
        parents.push(parent);
    }
    Ok(parents)
}

/// Assign a modeled native endpoint its declared incoming route while
/// keeping its OS mapper context. This is a Stela endpoint assignment,
/// not an observation of an Apple bus transaction.
pub(super) fn native_mapper_input(dart: &Iommu, context: u32) -> Result<u32, String> {
    if !dart.sids.is_empty() && !dart.sids.contains(&context) {
        return Err("mapper context is absent from the original SID set".into());
    }
    let input = dart
        .profile
        .mapper_input_stream(usize::from(dart.streams), context as usize, &dart.remap)
        .map_err(String::from)?;
    u32::try_from(input).map_err(|_| "native DMA input exceeds u32".into())
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use super::*;

    fn dart(mapper: u32) -> Iommu {
        Iommu {
            profile: crate::dart::Profile::T8110,
            instances: alloc::vec![DartInstance {
                physical: 0x20000,
                bytes: 0x4000,
                number: 0,
                reg_index: 0,
                owner: *b"DART\0\0\0\0",
            }],
            streams: 16,
            irq: 1,
            mappers: alloc::vec![(mapper, 0)],
            apf: None,
            clock_gates: Vec::new(),
            power_gates: Vec::new(),
            retention: false,
            sids: alloc::vec![0],
            remap: alloc::vec![(5, 0)],
            vm_base: 0x4000,
            smmu: None,
        }
    }

    #[test]
    fn native_route_preserves_context_and_requires_one_declared_owner() {
        let actual = dart(0x7d);
        assert_eq!(
            native_dma_route(&[dart(1), actual.clone()], 0x7d).unwrap(),
            NativeDmaRoute {
                mapper: 0x7d,
                iommu: 1,
                instance: 0,
                context: 0,
                stream: 5,
            }
        );
        assert!(native_dma_route(&[actual.clone(), actual.clone()], 0x7d).is_err());
        assert!(native_dma_route(&[], 0x7d).is_err());
        let mut multiple = actual.clone();
        multiple.instances.push(multiple.instances[0].clone());
        assert!(native_dma_route(&[multiple], 0x7d).is_err());
        let mut foreign = actual;
        foreign.sids = alloc::vec![1];
        assert!(native_dma_route(&[foreign], 0x7d).is_err());
    }

    #[test]
    fn native_dma_owner_properties_keep_complete_lists_and_refuse_truncation() {
        use stela_contracts::adt::encode;
        for bytes in [&[][..], &[1, 0, 0][..], &[0, 0, 0, 0][..], &[1; 8][..]] {
            let tree = encode(&[("AAPL,phandle", bytes)], &[]);
            assert!(native_dma_phandle(&Node::root(&tree).unwrap(), "AAPL,phandle").is_err());
        }
        let tree = encode(&[("iommu-parent", &[3, 0, 0, 0, 4, 0, 0, 0])], &[]);
        let node = Node::root(&tree).unwrap();
        assert_eq!(
            native_dma_mapper_list(&node, "iommu-parent").unwrap(),
            [3, 4]
        );
        assert!(native_dma_phandle(&node, "iommu-parent").is_err());
        for bytes in [
            &[][..],
            &[1, 0, 0][..],
            &[1, 0, 0, 0, 0, 0, 0, 0][..],
            &[1, 0, 0, 0, 1, 0, 0, 0][..],
        ] {
            let tree = encode(&[("iommu-parent", bytes)], &[]);
            assert!(native_dma_mapper_list(&Node::root(&tree).unwrap(), "iommu-parent").is_err());
        }
    }
}
