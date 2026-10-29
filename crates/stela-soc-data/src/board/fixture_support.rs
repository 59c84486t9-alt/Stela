//! Shared pure ADT fixtures for Data parsing and Runtime model integration.
//! These builders grant no mapping, executor or native effect authority.
use super::*;
pub const PMGR: &str = "pmgr1,t8112";
/// Existing unit fixtures explicitly declare an affine synthetic map.
/// Production callers supply Node::translate_range, never this adapter.
pub fn flat_fixture_extent(
    point: &dyn Fn(u64) -> Option<u64>,
) -> impl Fn(u64, u64) -> Option<u64> + '_ {
    move |address, bytes| {
        if bytes == 0 {
            return None;
        }
        address.checked_add(bytes)?;
        let physical = point(address)?;
        physical.checked_add(bytes)?;
        Some(physical)
    }
}

pub fn layout_of(layout: &[(u8, u32)]) -> Vec<Processor> {
    layout
        .iter()
        .map(|&(cluster_type, reg)| Processor {
            cluster_type,
            reg,
            l2_bytes: Some(if cluster_type == b'P' {
                16 << 20
            } else {
                4 << 20
            }),
        })
        .collect()
}

/// A J473AP-shaped DeviceTree: two PEs, `/arm-io` child 0 at PA
/// 0x2_0000_0000, and the UART, watchdog and AIC as `compatibles` names.
pub fn tree(chip_id: u32, soc: &str, compatibles: [&str; 3]) -> Vec<u8> {
    tree_with(chip_id, soc, compatibles, &[])
}

/// [`tree`] with more `/arm-io/aic` properties.
pub fn tree_with(
    chip_id: u32,
    soc: &str,
    compatibles: [&str; 3],
    aic_properties: &[(&str, u32)],
) -> Vec<u8> {
    tree_with_io(chip_id, soc, compatibles, aic_properties, &[])
}

/// [`tree_with`] with more `/arm-io` children.
pub fn tree_with_io(
    chip_id: u32,
    soc: &str,
    compatibles: [&str; 3],
    aic_properties: &[(&str, u32)],
    io_children: &[Vec<u8>],
) -> Vec<u8> {
    use stela_contracts::adt::encode;
    let z = |text: &str| [text.as_bytes(), &[0]].concat();
    let u32s = |cells: &[u32]| {
        cells
            .iter()
            .flat_map(|c| c.to_le_bytes())
            .collect::<Vec<_>>()
    };
    let u64s = |cells: &[u64]| {
        cells
            .iter()
            .flat_map(|c| c.to_le_bytes())
            .collect::<Vec<_>>()
    };
    // The J473AP's blocks: cpu0's and cpu4's `cpu-impl-reg`, and their
    // clusters' `cpm-impl-reg`.
    let cpu = |name: &str, kind: &[u8], reg: u32| {
        let cluster = 0x100_0000 * u64::from(reg >> 8);
        encode(
            &[
                ("name", &z(name)),
                ("cluster-type", kind),
                ("reg", &u32s(&[reg])),
                ("l2-cache-size", &u32s(&[4 << 20 << (2 * (reg >> 8))])),
                ("cpu-impl-reg", &u64s(&[0x2_1005_0000 + cluster, 0x9010])),
                ("coresight-reg", &u64s(&[0x2_1001_0000 + cluster, 0x300c8])),
                ("cpm-impl-reg", &u64s(&[0x2_10e4_0000 + cluster, 0x9010])),
            ],
            &[],
        )
    };
    let device = |name: &str, compatible: &str, reg: u64, irq: u32| {
        encode(
            &[
                ("name", &z(name)),
                ("compatible", &z(compatible)),
                ("reg", &u64s(&[reg, 0x4000])),
                ("interrupt-parent", &u32s(&[0x63])),
                ("interrupts", &u32s(&[irq])),
            ],
            &[],
        )
    };
    let (name, compatible) = (z("aic"), z(compatibles[2]));
    let (reg, phandle) = (u64s(&[0x3b0c_0000, 0x2_0000]), u32s(&[0x63]));
    // An AICv1 states its 740 inputs (the UART's 739 is the highest) to
    // the word.
    let ipid_mask = vec![0xff; 24 * 4];
    let values: Vec<_> = aic_properties
        .iter()
        .map(|(_, value)| u32s(&[*value]))
        .collect();
    let properties: Vec<(&str, &[u8])> = [
        ("name", name.as_slice()),
        ("compatible", &compatible),
        ("reg", &reg),
        ("AAPL,phandle", &phandle),
    ]
    .into_iter()
    .chain((compatibles[2] == "aic,1").then_some(("ipid-mask", ipid_mask.as_slice())))
    .chain(
        aic_properties
            .iter()
            .zip(&values)
            .map(|((name, _), value)| (*name, value.as_slice())),
    )
    .collect();
    let aic = encode(&properties, &[]);
    let io = encode(
        &[
            ("name", &z("arm-io")),
            (
                "ranges",
                &u64s(&[
                    0,
                    0x2_0000_0000,
                    0x1_0000_0000,
                    0x3_8000_0000,
                    0x3_8000_0000,
                    0x1_0000_0000,
                ]),
            ),
        ],
        &[
            vec![
                device("uart0", compatibles[0], 0x3520_0000, 739),
                device("wdt", compatibles[1], 0x3d2b_0000, 379),
                aic,
            ],
            io_children.to_vec(),
        ]
        .concat(),
    );
    encode(
        &[("name", &z("device-tree"))],
        &[
            encode(
                &[("name", &z("chosen")), ("chip-id", &u32s(&[chip_id]))],
                &[],
            ),
            encode(
                &[("name", &z("product")), ("product-soc-name", &z(soc))],
                &[],
            ),
            encode(
                &[("name", &z("cpus"))],
                &[cpu("cpu0", b"E", 0), cpu("cpu1", b"P", 0x100)],
            ),
            io,
        ],
    )
}

/// `/arm-io` children shaped like J514cAP's: the always-on PTD
/// (phandle 0x127, one cell per notification) and a CLPC (its
/// `/arm-io/pmgr/clpc`) that names the AIC (0x63) for its first three
/// specifiers and the PTD for the four FourCCs after them.
pub fn clpc_with_ptd() -> Vec<Vec<u8>> {
    use stela_contracts::adt::encode;
    let z = |text: &str| [text.as_bytes(), &[0]].concat();
    let words = |cells: &[u32]| {
        cells
            .iter()
            .flat_map(|c| c.to_le_bytes())
            .collect::<Vec<_>>()
    };
    let ptd = encode(
        &[
            ("name", &z("aon-ptd")),
            ("AAPL,phandle", &words(&[0x127])),
            ("#interrupt-cells", &words(&[1])),
            ("interrupt-controller", &z("master")),
        ],
        &[],
    );
    let clpc = encode(
        &[
            ("name", &z("clpc")),
            (
                "interrupt-parent",
                &words(&[0x63, 0x63, 0x63, 0x127, 0x127, 0x127, 0x127]),
            ),
            (
                "interrupts",
                &words(&[
                    0x5bf,
                    0,
                    0x5bd,
                    0x7030_5452,
                    0x7031_5452,
                    0x6130_5452,
                    0x6630_5452,
                ]),
            ),
        ],
        &[],
    );
    vec![ptd, clpc]
}
pub fn cache_fixture(bytes: u32, ways: u32) -> Cache {
    super::cache(bytes, ways)
}
pub fn spmi_controllers(
    io: &Node<'_>,
    translate: &dyn Fn(u64, u64) -> Option<u64>,
    aic: u32,
) -> Result<Vec<SpmiController>, String> {
    super::spmi_topology::spmi_controllers(io, translate, aic)
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImplicitSupplyFixture {
    pub physical: u64,
    pub bytes: u64,
    pub register: u64,
}
pub fn implicit_state_fixture() -> (PowerStates, [ImplicitSupplyFixture; 3]) {
    super::power_resources::implicit::fixture_support::complete_fixture()
}

pub fn parse_watchdog_fixture(
    node: &Node<'_>,
    translate: &dyn Fn(u64, u64) -> Option<u64>,
) -> Result<Option<WatchdogSide>, String> {
    super::watchdog_side(node, translate)
}
pub fn parse_iommu_fixture(
    node: &Node<'_>,
    translate: &dyn Fn(u64, u64) -> Option<u64>,
) -> Result<Iommu, String> {
    super::dart_topology::iommu(node, translate)
}
pub fn parse_dcp_fixture(
    io: &Node<'_>,
    translate: &dyn Fn(u64) -> Option<u64>,
    darts: &[Iommu],
) -> Result<Option<DcpController>, String> {
    super::display_topology::dcp_device(io, translate, darts)
}

pub const T6050_FIXTURE_LIMITS: KernelLimits = super::T6050_LIMITS;
pub fn parse_smc_fixture(
    root: &Node<'_>,
    io: &Node<'_>,
    translate: &dyn Fn(u64, u64) -> Option<u64>,
) -> Result<Option<SmcController>, String> {
    super::smc_topology::smc_controller(root, io, translate)
}

/// Explicit synthetic gate/resource metadata for Runtime model fixtures.
/// The actual Runtime owner still validates every lifecycle/supply binding.
pub fn power_states_fixture(
    blocks: Vec<(u64, u64)>,
    registers: Vec<u64>,
    domains: Vec<crate::pmgr::coverage::Domain>,
    resources: Vec<PowerResource>,
) -> PowerStates {
    PowerStates {
        blocks,
        registers,
        domains,
        resources,
        implicit: Vec::new(),
    }
}
