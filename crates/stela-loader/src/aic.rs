//! The AIC property iBoot adds to the DeviceTree it hands the kernel.
//!
//! 26A434 XNU's AppleInterruptControllerV2 panics without `/arm-io/aic`
//! `aic-iack-offset` ("Couldnt find aic-iack-offset device tree property"),
//! reads it as the 64-bit offset of the event register from the node's `reg`
//! and refuses one beyond the mapped registers; `aic-version` and
//! `aic-ext-intr-cfg` are optional. m1n1 `aic.c` reads the same property from
//! the ADT iBoot leaves for an `aic,2` or `aic,3`. The IPSW template has none,
//! so Stela publishes the event offset of the SoC's row in `machine::soc`,
//! the value each board's iBoot writes there (and Linux's DeviceTrees place
//! as the AIC's second `reg`).
use crate::Result;
use crate::apple_device_tree::DeviceTree;
use stela_contracts::require;
use stela_soc_data::board;

const AIC: &str = "/arm-io/aic";
const COMPATIBLE: &str = "compatible";
const IACK_OFFSET: &str = "aic-iack-offset";
/// The AICv1 keeps its event register in the core block.
const AIC1: &str = "aic,1";

/// Publishes `aic-iack-offset` for the SoC with `chip_id`, whose AIC has a
/// separate event block, when the tree's `aic` lacks it; returns whether it
/// did.
pub fn publish(tree: &mut DeviceTree, chip_id: u32) -> Result<bool> {
    let Some((compatible, event)) = board::aic(chip_id) else {
        return Ok(false);
    };
    if compatible == AIC1 || tree.property(AIC, IACK_OFFSET).is_some() {
        return Ok(false);
    }
    let Some(node) = tree.property(AIC, COMPATIBLE) else {
        return Ok(false);
    };
    require!(
        node.value.split(|&byte| byte == 0).next() == Some(compatible.as_bytes()),
        "{AIC} is not the {compatible} of SoC {chip_id:#x}",
        AIC,
        compatible,
        chip_id
    );
    tree.set_property(AIC, IACK_OFFSET, event.to_le_bytes().to_vec())?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apple_device_tree::Node;
    use alloc::vec;

    fn tree(compatible: &[u8]) -> DeviceTree {
        let mut aic = Node::named("aic").unwrap();
        aic.set_property(COMPATIBLE, compatible.to_vec()).unwrap();
        let mut arm_io = Node::named("arm-io").unwrap();
        arm_io.children.push(aic);
        let mut root = Node::named("device-tree").unwrap();
        root.children.push(arm_io);
        DeviceTree { root }
    }

    #[test]
    fn an_m2s_aic2_gets_its_event_offset_as_64_bits() {
        let mut tree = tree(b"aic,2\0");
        assert!(publish(&mut tree, 0x8112).unwrap());
        assert_eq!(
            tree.property(AIC, IACK_OFFSET).unwrap().value,
            vec![0x00, 0x80, 0, 0, 0, 0, 0, 0]
        );
        // Present already: left alone.
        assert!(!publish(&mut tree, 0x8112).unwrap());
    }

    #[test]
    fn an_aic1_or_a_mismatched_aic_gets_none() {
        let mut m1 = tree(b"aic,1\0");
        assert!(!publish(&mut m1, 0x8103).unwrap());
        assert!(m1.property(AIC, IACK_OFFSET).is_none());
        assert!(publish(&mut tree(b"aic,3\0"), 0x8112).is_err());
    }
}
