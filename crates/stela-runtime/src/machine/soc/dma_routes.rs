//! DeviceTree placement and validation for dma routes.
use super::{Iommu, Node, String, Vec, format};

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
/// retaining its OS mapper context. This is a Stela endpoint assignment,
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

    #[test]
    fn native_dma_owner_properties_keep_complete_lists_and_refuse_truncation() {
        use crate::machine::adt::encode;
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
