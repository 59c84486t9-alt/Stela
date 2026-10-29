//! The GPU's performance-state tables, hand-off properties iBoot adds to
//! `/arm-io/sgx`.
//!
//! The shipped J473AP DeviceTree carries placeholders: `perf-states` is 16
//! zero states, `perf-state-count` is 0 and `gpu-num-perf-states` 2; it has
//! no `perf-state-table-count` and no `perf-states-sram`. 26A434
//! `iBoot.j473.RELEASE` (the routine at file offset 0x12980..0x12c78) writes
//! `perf-states-sram`, `perf-states` (and their `1`..`7` per-table siblings),
//! `perf-state-count`, then `gpu-num-perf-states` as that count less one and
//! `perf-state-table-count`.
//!
//! 26A434 `AGXG14G` `AGXAccelerator::start` (kernel file offsets
//! 0x1afc0b8..0x1afce30) reads them from the provider:
//!
//! - `gpu-num-perf-states` + 1 is the number of states `n` (1 when the
//!   property is absent); it must lie in 2..=16;
//! - `perf-state-table-count` is the number of tables `t` (1 when absent),
//!   at most 16;
//! - `perf-states` and `perf-states-sram` are `t` tables of `n` `(u32, u32)`
//!   states, table-major; each must hold at least `n × t` states. The first
//!   word is the state's clock, the second its voltage in mV (m1n1
//!   `kboot_gpu.c` `struct perf_state`, which takes the same tables to an OPP
//!   table in Hz and µV);
//! - without `perf-states-sram` the start panics "No set value for
//!   `perf-states-sram`" (0x1b00710) when the accelerator requires SRAM
//!   voltages, as the G14G does.
//!
//! The states are the SoC's operating points: T8112 has one GPU cluster and
//! nine states, off and 444 to 1398 MHz (Asahi Linux
//! `arch/arm64/boot/dts/apple/t8112.dtsi` `gpu_opp`, pinned
//! `94fb23346d522edf53722357c426a3e58030beea`). iBoot takes each state's
//! voltages from the chip's calibration fuses, which an emulated chip lacks
//! (the same DeviceTree notes they "must be filled in by the bootloader"), so
//! both tables state voltage 0, as `dvfs` does for the CPU clusters, rather
//! than an invented one. A SoC without public operating points refuses.
//!
//! T8103 and T600x take the same tables: the 26A434 `AGXG13X`
//! `AGXAccelerator::start` aligns instruction for instruction with G14G's
//! over the property reads above (only object offsets and string addresses
//! differ). One table serves every cluster: Inferred, as the Asahi tables
//! repeat each state's voltage per cluster, and the kext accepts 1..=16
//! tables; iBoot for a multi-cluster board (j314/j316) would confirm the
//! count it writes. T602x likewise: the 26A434 `AGXG14X` `AGXAccelerator::
//! start` aligns with G14G's over the same reads (object offsets, string
//! addresses and register allocation differ).
use crate::Result;
use crate::apple_device_tree::DeviceTree;
use alloc::vec::Vec;
use stela_contracts::refuse;

const SGX: &str = "/arm-io/sgx";

/// T8112's GPU operating points in Hz, lowest (off) first.
const T8112_HZ: [u32; 9] = [
    0,
    444_000_000,
    612_000_000,
    808_000_000,
    968_000_000,
    1_110_000_000,
    1_236_000_000,
    1_338_000_000,
    1_398_000_000,
];

/// T8103's GPU operating points in Hz (Asahi `t8103.dtsi` `gpu_opp`, the
/// same pinned commit).
const T8103_HZ: [u32; 7] = [
    0,
    396_000_000,
    528_000_000,
    720_000_000,
    924_000_000,
    1_128_000_000,
    1_278_000_000,
];

/// The M1 Pro, Max and Ultra GPU operating points in Hz (Asahi
/// `t600x-common.dtsi` `gpu_opp`, the same pinned commit), shared by every
/// cluster.
const T600X_HZ: [u32; 7] = [
    0,
    388_800_000,
    486_000_000,
    648_000_000,
    777_600_000,
    972_000_000,
    1_296_000_000,
];

/// The M2 Pro, Max and Ultra GPU operating points in Hz (Asahi
/// `t602x-common.dtsi` `gpu_opp`, the same pinned commit), T8112's nine.
const T602X_HZ: [u32; 9] = T8112_HZ;

/// The GPU's operating points, lowest first, on the SoC with `chip_id`.
fn operating_points(chip_id: u32) -> Option<&'static [u32]> {
    match chip_id {
        0x8103 => Some(&T8103_HZ),
        0x6000..=0x6002 => Some(&T600X_HZ),
        0x8112 => Some(&T8112_HZ),
        0x6020..=0x6022 => Some(&T602X_HZ),
        _ => None,
    }
}

/// What [`publish`] wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tables {
    /// States per table, the off state included.
    pub states: u32,
    /// Tables (GPU clusters).
    pub tables: u32,
}

fn word(value: u32) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

/// Publish the GPU tables on a tree whose visible `/arm-io/sgx` still
/// carries the shipped placeholders. Run it after `devices::hide_unmodeled`:
/// a tree without the node, one whose node is hidden (no `compatible`), or
/// one that already has `perf-states-sram` and a state count is left alone.
pub fn publish(tree: &mut DeviceTree, chip_id: u32) -> Result<Option<Tables>> {
    let Some(sgx) = tree
        .node(SGX)
        .filter(|sgx| sgx.property("compatible").is_some())
    else {
        return Ok(None);
    };
    let count = sgx
        .property("perf-state-count")
        .map(|p| p.value.as_slice())
        .and_then(|v| <[u8; 4]>::try_from(v).ok())
        .map(u32::from_le_bytes);
    if sgx.property("perf-states-sram").is_some() && count.is_some_and(|n| n != 0) {
        return Ok(None);
    }
    let Some(points) = operating_points(chip_id) else {
        return Err(refuse!(
            "ApChipID {chip_id:#x} has no public GPU operating points for {SGX} perf-states",
            chip_id,
            SGX
        )
        .into());
    };
    let states = points.len();
    if !(2..=16).contains(&states) {
        return Err(refuse!(
            "{states} GPU operating points are outside AGXAccelerator's 2..=16",
            states
        )
        .into());
    }
    let states = states as u32;
    let mut table = Vec::with_capacity(points.len() * 8);
    for &hz in points {
        table.extend_from_slice(&hz.to_le_bytes());
        table.extend_from_slice(&0u32.to_le_bytes());
    }
    tree.set_property(SGX, "perf-states", table.clone())?;
    tree.set_property(SGX, "perf-states-sram", table)?;
    tree.set_property(SGX, "perf-state-count", word(states))?;
    tree.set_property(SGX, "gpu-num-perf-states", word(states - 1))?;
    tree.set_property(SGX, "perf-state-table-count", word(1))?;
    Ok(Some(Tables { states, tables: 1 }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apple_device_tree::Node;
    use alloc::vec;

    /// A tree whose `sgx` has the shipped J473AP placeholders.
    fn shipped() -> DeviceTree {
        let mut sgx = Node::named("sgx").unwrap();
        sgx.set_property("compatible", b"gpu,t8112\0".to_vec())
            .unwrap();
        sgx.set_property("perf-states", vec![0; 128]).unwrap();
        sgx.set_property("perf-state-count", word(0)).unwrap();
        sgx.set_property("gpu-num-perf-states", word(2)).unwrap();
        let mut io = Node::named("arm-io").unwrap();
        io.children.push(sgx);
        let mut root = Node::named("device-tree").unwrap();
        root.children.push(io);
        DeviceTree { root }
    }

    fn u32_at(value: &[u8], index: usize) -> u32 {
        u32::from_le_bytes(value[index * 4..index * 4 + 4].try_into().unwrap())
    }

    #[test]
    fn the_shipped_placeholders_become_the_t8112_operating_points() {
        let mut tree = shipped();
        let tables = publish(&mut tree, 0x8112).unwrap().unwrap();
        assert_eq!(
            tables,
            Tables {
                states: 9,
                tables: 1
            }
        );
        let value = |name| tree.property(SGX, name).unwrap().value.clone();
        // AGXAccelerator::start: gpu-num-perf-states + 1 states, each table
        // at least states × tables × 8 bytes.
        assert_eq!(u32_at(&value("gpu-num-perf-states"), 0) + 1, 9);
        assert_eq!(u32_at(&value("perf-state-count"), 0), 9);
        assert_eq!(u32_at(&value("perf-state-table-count"), 0), 1);
        for name in ["perf-states", "perf-states-sram"] {
            let table = value(name);
            assert_eq!(table.len(), 9 * 8);
            assert_eq!((u32_at(&table, 0), u32_at(&table, 1)), (0, 0));
            assert_eq!((u32_at(&table, 16), u32_at(&table, 17)), (1_398_000_000, 0));
        }
        // A tree that already has the hand-off is left alone.
        assert_eq!(publish(&mut tree, 0x8112).unwrap(), None);
    }

    #[test]
    fn the_m1_gpus_take_their_seven_operating_points() {
        for (chip_id, top) in [
            (0x8103, 1_278_000_000),
            (0x6000, 1_296_000_000),
            (0x6001, 1_296_000_000),
            (0x6002, 1_296_000_000),
        ] {
            let mut tree = shipped();
            let tables = publish(&mut tree, chip_id).unwrap().unwrap();
            assert_eq!(
                tables,
                Tables {
                    states: 7,
                    tables: 1
                }
            );
            let table = tree.property(SGX, "perf-states").unwrap().value.clone();
            assert_eq!((u32_at(&table, 12), u32_at(&table, 13)), (top, 0));
        }
    }

    #[test]
    fn the_m2_pro_max_and_ultra_gpus_take_nine_operating_points() {
        for chip_id in 0x6020..=0x6022 {
            let mut tree = shipped();
            let tables = publish(&mut tree, chip_id).unwrap().unwrap();
            assert_eq!(tables.states, 9);
            let table = tree.property(SGX, "perf-states").unwrap().value.clone();
            assert_eq!(u32_at(&table, 16), 1_398_000_000);
        }
    }

    #[test]
    fn without_operating_points_or_a_visible_sgx_node() {
        assert!(publish(&mut shipped(), 0x8122).is_err());
        let mut hidden = shipped();
        hidden.node_mut(SGX).unwrap().remove_property("compatible");
        assert_eq!(publish(&mut hidden, 0x8122).unwrap(), None);
        let mut bare = DeviceTree {
            root: Node::named("device-tree").unwrap(),
        };
        assert_eq!(publish(&mut bare, 0x8122).unwrap(), None);
    }
}
