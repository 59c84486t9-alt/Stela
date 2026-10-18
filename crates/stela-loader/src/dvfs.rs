//! The CPU clusters' `voltage-states` tables, hand-off properties iBoot adds
//! to `/arm-io/pmgr`.
//!
//! The shipped DeviceTree leaves them out; 26A434 J473AP `ApplePMGR::
//! initDriver` panics without them ("voltage-states1 not found"). It looks
//! up a table per performance domain, `voltage-states1` for the E cluster
//! and `voltage-states5` for the P cluster (`ECPU` and `PCPU` in its domain
//! table), each a run of `(period, voltage)` pairs that ends at the first
//! zero period. iBoot (26A434 `iBoot.j473.RELEASE`, the routine that writes
//! `voltage-states1`, `-sram` and `-extra`) stores each state's period as
//! 65,536 × 10⁹ / its clock in Hz, and the driver reads the clock back as
//! 65,536,000 / period MHz.
//!
//! The states are the SoC's operating points (`machine::soc::
//! operating_points`), lowest first. iBoot takes each state's voltage from
//! the chip's own calibration, which an emulated chip does not have; the
//! driver uses it only for its dynamic energy estimate (V² × f). The tables
//! leave it 0, as the templates the IPSW DeviceTree ships for the other
//! domains do, so the estimate states no energy rather than an invented one.
//! The optional `-sram` and `-extra` tables are not published.
use crate::apple_device_tree::DeviceTree;
use alloc::vec::Vec;
use anyhow::{Result, ensure};
use stela_runtime::machine::soc;

const PMGR: &str = "/arm-io/pmgr";
/// The period unit: a state's period is this over its clock in Hz.
const PERIOD_SCALE: u64 = 65_536 * 1_000_000_000;

/// The table name of a cluster type.
fn table(cluster_type: u8) -> Option<&'static str> {
    match cluster_type {
        b'E' => Some("voltage-states1"),
        b'P' => Some("voltage-states5"),
        _ => None,
    }
}

/// Add each cluster's table to `/arm-io/pmgr` on a SoC with known operating
/// points, unless the tree already has it. Returns the tables written.
pub fn publish(tree: &mut DeviceTree, chip_id: u32) -> Result<Vec<&'static str>> {
    let mut written = Vec::new();
    let Some(clusters) = soc::operating_points(chip_id) else {
        return Ok(written);
    };
    if tree.node_mut(PMGR).is_none() {
        return Ok(written);
    }
    for (cluster_type, points) in clusters {
        let Some(name) = table(cluster_type) else {
            continue;
        };
        if tree.property(PMGR, name).is_some() {
            continue;
        }
        ensure!(
            !points.is_empty(),
            "cluster {} has no operating points",
            char::from(cluster_type)
        );
        let mut value = Vec::with_capacity(points.len() * 8);
        for &mhz in points {
            let period = u32::try_from(PERIOD_SCALE / (u64::from(mhz) * 1_000_000))?;
            value.extend_from_slice(&period.to_le_bytes());
            value.extend_from_slice(&0u32.to_le_bytes());
        }
        tree.set_property(PMGR, name, value)?;
        written.push(name);
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apple_device_tree::Node;
    use alloc::vec;

    fn tree() -> DeviceTree {
        let mut io = Node::named("arm-io").unwrap();
        io.children.push(Node::named("pmgr").unwrap());
        let mut root = Node::named("device-tree").unwrap();
        root.children.push(io);
        DeviceTree { root }
    }

    #[test]
    fn the_m2_clusters_get_their_operating_points_as_periods() {
        let mut tree = tree();
        assert_eq!(
            publish(&mut tree, 0x8112).unwrap(),
            vec!["voltage-states1", "voltage-states5"]
        );
        let e = &tree.property(PMGR, "voltage-states1").unwrap().value;
        assert_eq!(e.len(), 7 * 8);
        // 600 MHz is period 109,226, which the driver reads back as 600 MHz.
        assert_eq!(u32::from_le_bytes(e[..4].try_into().unwrap()), 109_226);
        assert_eq!(65_536_000 / 109_226, 600);
        assert_eq!(u32::from_le_bytes(e[4..8].try_into().unwrap()), 0);
        let p = &tree.property(PMGR, "voltage-states5").unwrap().value;
        assert_eq!(p.len(), 17 * 8);
        assert_eq!(
            u32::from_le_bytes(p[16 * 8..16 * 8 + 4].try_into().unwrap()),
            18_703
        );
        // A table the tree has stays, and an unknown SoC gets none.
        assert!(publish(&mut tree, 0x8112).unwrap().is_empty());
        assert!(publish(&mut self::tree(), 0x8122).unwrap().is_empty());
    }
}
