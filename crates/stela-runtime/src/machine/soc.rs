//! Apple SoCs: a board's chip and PEs from its DeviceTree.
//!
//! The board's DeviceTree gives the SoC: `/chosen` `chip-id` (the identity's
//! ApChipID, which the boot bundle writes there as iBoot does), `/product`
//! `product-soc-name`, and one `/cpus` node per PE with `reg` and
//! `cluster-type`. Each SoC row pairs an ApChipID with the
//! `product-soc-name` its boards' DeviceTrees give in UniversalMac 26A434 and
//! the MIDR_EL1 part number of each cluster type (m1n1 `src/midr.h`
//! `MIDR_PART_<soc>_<core>`). A SoC, cluster type or affinity without that
//! evidence refuses: the M1, M2 and M3 Ultra, the second M3 Max (ApChipID
//! 0x6034), the A18 Pro and the M5 Pro and Max (no `product-soc-name`), and
//! the M6's M cores.
use super::{Chip, adt::Node, registers::Identity};
use crate::platform::apple::{
    aic::{AIC2_IRQ_CFG, AIC3_IRQ_CFG, AicLayout},
    aic1::AIC1_EVENT,
    amcc,
};
use alloc::{format, string::String, vec::Vec};

/// One SoC row: ApChipID, `product-soc-name`, chip, the MIDR_EL1 part
/// number of each `cluster-type`, and the `aic` node's `compatible` with the
/// offset of its event register from its `reg`: for the M1's `aic,1` the
/// event register in its core block (Linux `AIC_EVENT`, 0x2004), and for an
/// `aic,2` or `aic,3` the separate block Linux `arch/arm64/boot/dts/apple`
/// places (0x8000 in `t8112.dtsi`, 0xc000 in `t600x-die0.dtsi` and
/// `t602x-die0.dtsi`, 0x40000 in `t8122.dtsi`). The SoCs whose AIC no public
/// DeviceTree places have none. `dram_base` is where the
/// SoC places DRAM (the `memory@` node of Linux `t8103-jxxx.dtsi`,
/// `t8112-jxxx.dtsi`, `t600x-j314-j316.dtsi` and `t600x-j375.dtsi`, which the
/// t602x boards include); the SoCs without a public memory node have none,
/// and their boards state it in their DeviceTree ([`board_dram_base`]).
/// `lockdown` is the CONTROL offset of the lockdown registers in each PE's
/// `cpu-impl-reg` and each cluster's `cpm-impl-reg` (`platform::apple::
/// lockdown`), on the SoCs whose SPTM shows them: the T8112's 26A434 SPTM.
/// `clocks` is each cluster type's core clock in Hz, in `parts` order, which
/// paces the cycle counter of Apple's performance monitor (`machine::pmu`):
/// the highest operating point of each cluster in Linux
/// `arch/arm64/boot/dts/apple/t8112.dtsi` (`blizzard_opp`, `avalanche_opp`).
/// The IPSW DeviceTree leaves its `voltage-states` tables to iBoot, so the
/// SoCs without that evidence have none.
struct Soc {
    chip_id: u32,
    name: &'static str,
    chip: Chip,
    parts: [(u8, u16); 2],
    aic: Option<(&'static str, u64)>,
    dram_base: Option<u64>,
    lockdown: Option<[u64; 2]>,
    clocks: Option<[u64; 2]>,
}

const SOCS: [Soc; 14] = [
    Soc {
        chip_id: 0x8103,
        name: "Apple M1",
        chip: Chip::AppleM1,
        parts: [(b'E', 0x022), (b'P', 0x023)],
        aic: Some(("aic,1", AIC1_EVENT)),
        dram_base: Some(0x8_0000_0000),
        lockdown: None,
        clocks: None,
    },
    Soc {
        chip_id: 0x6000,
        name: "Apple M1 Pro",
        chip: Chip::AppleM1,
        parts: [(b'E', 0x024), (b'P', 0x025)],
        aic: Some(("aic,2", 0xc000)),
        dram_base: Some(0x100_0000_0000),
        lockdown: None,
        clocks: None,
    },
    Soc {
        chip_id: 0x6001,
        name: "Apple M1 Max",
        chip: Chip::AppleM1,
        parts: [(b'E', 0x028), (b'P', 0x029)],
        aic: Some(("aic,2", 0xc000)),
        dram_base: Some(0x100_0000_0000),
        lockdown: None,
        clocks: None,
    },
    Soc {
        chip_id: 0x8112,
        name: "Apple M2",
        chip: Chip::AppleM2,
        parts: [(b'E', 0x032), (b'P', 0x033)],
        aic: Some(("aic,2", 0x8000)),
        dram_base: Some(0x8_0000_0000),
        lockdown: Some([0x5000, 0x9000]),
        clocks: Some([2_424_000_000, 3_504_000_000]),
    },
    Soc {
        chip_id: 0x6020,
        name: "Apple M2 Pro",
        chip: Chip::AppleM2,
        parts: [(b'E', 0x034), (b'P', 0x035)],
        aic: Some(("aic,2", 0xc000)),
        dram_base: Some(0x100_0000_0000),
        lockdown: None,
        clocks: None,
    },
    Soc {
        chip_id: 0x6021,
        name: "Apple M2 Max",
        chip: Chip::AppleM2,
        parts: [(b'E', 0x038), (b'P', 0x039)],
        aic: Some(("aic,2", 0xc000)),
        dram_base: Some(0x100_0000_0000),
        lockdown: None,
        clocks: None,
    },
    Soc {
        chip_id: 0x8122,
        name: "Apple M3",
        chip: Chip::AppleM3,
        parts: [(b'E', 0x042), (b'P', 0x043)],
        aic: Some(("aic,3", 0x40000)),
        dram_base: None,
        lockdown: None,
        clocks: None,
    },
    Soc {
        chip_id: 0x6030,
        name: "Apple M3 Pro",
        chip: Chip::AppleM3,
        parts: [(b'E', 0x044), (b'P', 0x045)],
        aic: None,
        dram_base: None,
        lockdown: None,
        clocks: None,
    },
    Soc {
        chip_id: 0x6031,
        name: "Apple M3 Max",
        chip: Chip::AppleM3,
        parts: [(b'E', 0x048), (b'P', 0x049)],
        aic: None,
        dram_base: None,
        lockdown: None,
        clocks: None,
    },
    Soc {
        chip_id: 0x8132,
        name: "Apple M4",
        chip: Chip::AppleM4,
        parts: [(b'E', 0x052), (b'P', 0x053)],
        aic: None,
        dram_base: None,
        lockdown: None,
        clocks: None,
    },
    Soc {
        chip_id: 0x6040,
        name: "Apple M4 Pro",
        chip: Chip::AppleM4,
        parts: [(b'E', 0x054), (b'P', 0x055)],
        aic: None,
        dram_base: None,
        lockdown: None,
        clocks: None,
    },
    Soc {
        chip_id: 0x6041,
        name: "Apple M4 Max",
        chip: Chip::AppleM4,
        parts: [(b'E', 0x058), (b'P', 0x059)],
        aic: None,
        dram_base: None,
        lockdown: None,
        clocks: None,
    },
    Soc {
        chip_id: 0x8142,
        name: "Apple M5",
        chip: Chip::AppleM5,
        parts: [(b'E', 0x062), (b'P', 0x063)],
        aic: None,
        dram_base: None,
        lockdown: None,
        clocks: None,
    },
    Soc {
        chip_id: 0x8152,
        name: "Apple M6",
        chip: Chip::AppleM6,
        parts: [(b'E', 0x072), (b'P', 0x073)],
        aic: None,
        dram_base: None,
        lockdown: None,
        clocks: None,
    },
];

/// The chip and PEs a board's SoC row and `/cpus` select.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cpus {
    pub chip: Chip,
    /// The PEs in `/cpus` order.
    pub processors: Vec<Identity>,
    /// The `aic` node's `compatible` and its event register's offset from its
    /// `reg`, on a SoC whose AIC a public DeviceTree places.
    pub aic: Option<(&'static str, u64)>,
    /// The SoC's lockdown CONTROL offsets in `cpu-impl-reg` and
    /// `cpm-impl-reg`, where known.
    pub lockdown: Option<[u64; 2]>,
}

/// The `aic` node's `compatible` and its event register's offset from its
/// `reg` on the SoC with `chip_id`, when a public DeviceTree places it.
pub fn aic(chip_id: u32) -> Option<(&'static str, u64)> {
    SOCS.iter().find(|soc| soc.chip_id == chip_id)?.aic
}

/// The guest DRAM base of the SoC with `chip_id`.
pub fn dram_base(chip_id: u32) -> Result<u64, String> {
    SOCS.iter()
        .find(|soc| soc.chip_id == chip_id)
        .and_then(|soc| soc.dram_base)
        .ok_or_else(|| format!("ApChipID {chip_id:#x} has no public DRAM base"))
}

/// The guest DRAM base of a board whose SoC is `chip_id`: its DeviceTree's
/// `/arm-io/mcc` `dram-base`, which the M3 and later boards state, or else
/// the SoC's public base ([`dram_base`]). Where both exist they must agree.
pub fn board_dram_base(tree: &[u8], chip_id: u32) -> Result<u64, String> {
    let root = Node::root(tree).ok_or("DeviceTree has no root")?;
    let stated = root
        .child("arm-io")
        .and_then(|io| io.child("mcc"))
        .and_then(|mcc| mcc.property("dram-base"))
        .map(|bytes| {
            <[u8; 8]>::try_from(bytes)
                .map(u64::from_le_bytes)
                .map_err(|_| "/arm-io/mcc dram-base is not 8 bytes")
        })
        .transpose()?;
    match (stated, dram_base(chip_id)) {
        (Some(stated), Ok(public)) if stated != public => Err(format!(
            "/arm-io/mcc dram-base {stated:#x} is not ApChipID {chip_id:#x}'s {public:#x}"
        )),
        (Some(stated), _) => Ok(stated),
        (None, public) => public,
    }
}

/// One `/cpus` node: its `cluster-type` letter and `reg`.
#[derive(Debug, Clone, Copy)]
pub struct Processor {
    pub cluster_type: u8,
    pub reg: u32,
}

/// The chip and PEs, in `/cpus` order, of a board whose DeviceTree names
/// `chip_id` and `soc_name`.
///
/// MIDR_EL1 is implementer 0x61 (Apple), variant 1, architecture 0xF, the
/// cluster type's part and revision 0, the values the J473AP profile has
/// always used; variant and revision are inferred until a reference capture
/// supplies them. MPIDR_EL1 is `reg` with bit 31 RES1 and Aff2 1 on a P core:
/// `reg` is Aff1 (cluster) and Aff0 (core) on every single-die board (the
/// J473AP's cpu0-3 are 0-3 and cpu4-7 0x100-0x103), the cores of P clusters
/// have Aff2 1 (the `cpu@` `reg` of Linux `t8103.dtsi`, `t8112.dtsi`,
/// `t600x-common.dtsi` and `t602x-common.dtsi` and `t8122.dtsi`, which XNU
/// masks off in `ml_get_cpu_number`; inferred for the later SoCs), and U and
/// MT are 0 for a multiprocessor without multithreading (inferred). A `reg`
/// beyond Aff1's first eight clusters, as the multi-die boards use, has no
/// public MPIDR mapping and refuses.
pub fn cpus(chip_id: u32, soc_name: &str, processors: &[Processor]) -> Result<Cpus, String> {
    let soc = SOCS
        .iter()
        .find(|soc| soc.chip_id == chip_id)
        .ok_or_else(|| format!("ApChipID {chip_id:#x} ({soc_name}) has no public MIDR part"))?;
    if soc.name != soc_name {
        return Err(format!(
            "ApChipID {chip_id:#x} is {}, but the DeviceTree names {soc_name}",
            soc.name
        ));
    }
    if processors.is_empty() {
        return Err("the DeviceTree has no /cpus nodes".into());
    }
    let processors = processors
        .iter()
        .map(|processor| {
            let index = soc
                .parts
                .iter()
                .position(|(cluster_type, _)| *cluster_type == processor.cluster_type);
            let part = index
                .map(|index| u64::from(soc.parts[index].1))
                .ok_or_else(|| {
                    format!(
                        "{} cluster type {} has no public MIDR part",
                        soc.name,
                        char::from(processor.cluster_type)
                    )
                })?;
            if processor.reg & !0x7ff != 0 {
                return Err(format!(
                    "{} cpu reg {:#x} has no public MPIDR mapping",
                    soc.name, processor.reg
                ));
            }
            Ok(Identity {
                midr: 0x61 << 24 | 1 << 20 | 0xf << 16 | part << 4,
                mpidr: 0x8000_0000
                    | u64::from(processor.cluster_type == b'P') << 16
                    | u64::from(processor.reg),
                clock: soc.clocks.zip(index).map(|(clocks, index)| clocks[index]),
            })
        })
        .collect::<Result<_, String>>()?;
    Ok(Cpus {
        lockdown: soc.lockdown,
        chip: soc.chip,
        processors,
        aic: soc.aic,
    })
}

/// A device's first `reg` range in guest PA and its AIC input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Device {
    pub physical: u64,
    pub bytes: u64,
    pub irq: u32,
}

/// The lockdown registers of one CPU implementation block: the ADT `/cpus`
/// property naming the block, its guest PA and size, and the offset of its
/// lockdown CONTROL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockdownBlock {
    pub name: &'static str,
    pub physical: u64,
    pub bytes: u64,
    pub control: u64,
}

/// The AIC: its core block's guest PA, its input count and its layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterruptController {
    pub physical: u64,
    pub inputs: u16,
    pub layout: AicLayout,
}

/// The register offsets an `aic,3` node states, as m1n1 `aic.c` reads them,
/// and the AICv2 layout they must match (Linux `aic3_info` hard-codes them
/// for the M3 through the M5).
const AIC3_OFFSETS: [(&str, u32); 5] = [
    ("rev-offset", 0),
    ("cap0-offset", 0x4),
    ("maxnumirq-offset", 0xc),
    ("aicglbcfg-offset", 0x14),
    ("extint-baseaddress", AIC3_IRQ_CFG as u32),
];

/// The layout of an `/arm-io/aic` node compatible with `version` whose event
/// register is `event` bytes from its `reg`: the AICv1's, the AICv2's, or the
/// AICv3's once its stated offsets match the modeled layout.
fn aic_layout(aic: &Node<'_>, version: &str, event: u64) -> Result<AicLayout, String> {
    match version {
        "aic,1" => return Ok(AicLayout::V1),
        "aic,2" => {
            return Ok(AicLayout::V2 {
                irq_config: AIC2_IRQ_CFG,
                event,
            });
        }
        _ => {}
    }
    for (name, expected) in AIC3_OFFSETS {
        let found = aic
            .first_u32(name)
            .ok_or_else(|| format!("/arm-io/aic has no {name}"))?;
        if found != expected {
            return Err(format!(
                "/arm-io/aic {name} is {found:#x}, not the modeled {expected:#x}"
            ));
        }
    }
    Ok(AicLayout::V2 {
        irq_config: AIC3_IRQ_CFG,
        event,
    })
}

/// The `compatible` of the S5L UART the engine models (`platform::apple::uart`).
pub const UART: &str = "uart-1,samsung";
/// The `compatible` of the watchdog the engine models (`platform::apple::wdt`).
pub const WATCHDOG: &str = "wdt,s5l8960x";
/// The AIC versions the engine models (`platform::apple::aic1` and `aic`).
const AICS: [&str; 3] = ["aic,1", "aic,2", "aic,3"];

/// Whether the engine models a device `compatible` with `name`: the devices a
/// [`Board`] places. A boot bundle presents no other device to the guest.
pub fn models(name: &str) -> bool {
    name == UART || name == WATCHDOG || AICS.contains(&name)
}

/// Everything the engine models of a board, from its DeviceTree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Board {
    pub cpus: Cpus,
    /// `/arm-io/uart0`, a `uart-1,samsung`.
    pub uart: Device,
    /// `/arm-io/wdt`, a `wdt,s5l8960x`.
    pub watchdog: Device,
    /// `/arm-io/aic`, an `aic,1`, `aic,2` or `aic,3`.
    pub aic: InterruptController,
    /// Every PE's `cpu-impl-reg` and every cluster's `cpm-impl-reg`, once
    /// each, on a SoC whose lockdown offsets are known; none otherwise.
    pub lockdown: Vec<LockdownBlock>,
    /// The AMCC lock registers of `/chosen/lock-regs/amcc`, when iBoot
    /// described them.
    pub memory_controller: Option<MemoryController>,
}

/// The AMCC as `/chosen/lock-regs/amcc` describes it: its apertures and
/// each aperture's planes and lock registers (`platform::apple::amcc`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryController {
    pub apertures: Vec<u64>,
    pub layout: amcc::Layout,
}

const LOCK_GROUP: &str = "amcc-ctrr-a";
/// Lock groups iBoot's map names but leaves empty; one with registers is
/// refused, as the model implements CTRR-A alone.
const EMPTY_GROUPS: [&str; 3] = ["amcc-ctrr-b", "amcc-ctrr-c", "amcc-ctrr-d"];

/// A `<name>-reg-offset`, `-reg-mask` and, for a bit register,
/// `-reg-value` triple.
fn lock_register(
    node: &Node<'_>,
    path: &str,
    name: &str,
    bit: bool,
) -> Result<amcc::Register, String> {
    let field = |suffix: &str| {
        node.first_u32(&format!("{name}-reg-{suffix}"))
            .ok_or_else(|| format!("{path} has no {name}-reg-{suffix}"))
    };
    let mask = field("mask")?;
    let value = if bit { field("value")? } else { 0 };
    if value & !mask != 0 {
        return Err(format!("{path} {name}-reg-value has bits outside its mask"));
    }
    Ok(amcc::Register {
        offset: u64::from(field("offset")?),
        mask,
        value,
    })
}

/// The AMCC map of `/chosen/lock-regs/amcc`, or `None` without one.
fn memory_controller(chosen: &Node<'_>) -> Result<Option<MemoryController>, String> {
    let Some(node) = chosen
        .child("lock-regs")
        .and_then(|regs| regs.child("amcc"))
    else {
        return Ok(None);
    };
    const PATH: &str = "/chosen/lock-regs/amcc";
    let number = |name: &str| {
        node.first_u32(name)
            .ok_or_else(|| format!("{PATH} has no {name}"))
    };
    let count = number("aperture-count")? as usize;
    let apertures: Vec<u64> = node
        .property("aperture-phys-addr")
        .map(|value| {
            value
                .as_chunks::<8>()
                .0
                .iter()
                .map(|cell| u64::from_le_bytes(*cell))
                .collect()
        })
        .unwrap_or_default();
    if count == 0 || apertures.len() != count {
        return Err(format!(
            "{PATH} aperture-phys-addr does not list aperture-count apertures"
        ));
    }
    let group_path = format!("{PATH}/{LOCK_GROUP}");
    let group = node
        .child(LOCK_GROUP)
        .ok_or_else(|| format!("{PATH} has no {LOCK_GROUP}"))?;
    for name in EMPTY_GROUPS {
        if node
            .child(name)
            .is_some_and(|empty| empty.property("page-size-shift").is_some())
        {
            return Err(format!(
                "{PATH}/{name} is a lock group the AMCC model does not implement"
            ));
        }
    }
    let register = |name: &str, bit: bool| lock_register(&group, &group_path, name, bit);
    let dram_base = chosen
        .property("dram-base")
        .and_then(|value| {
            value
                .first_chunk::<8>()
                .map(|cell| u64::from_le_bytes(*cell))
        })
        .ok_or("/chosen has no dram-base")?;
    let layout = amcc::Layout {
        aperture_bytes: u64::from(number("aperture-size")?),
        planes: number("plane-count")?,
        stride: u64::from(number("plane-stride")?),
        cache_status: lock_register(&node, PATH, "cache-status", true)?,
        group: amcc::LockGroup {
            page_size_shift: group
                .first_u32("page-size-shift")
                .ok_or_else(|| format!("{group_path} has no page-size-shift"))?,
            lower_limit: register("lower-limit", false)?,
            upper_limit: register("upper-limit", false)?,
            enable: register("enable", true)?,
            write_disable: register("write-disable", true)?,
            lock: register("lock", true)?,
        },
        dram_base,
    };
    if layout.aperture_bytes == 0 || layout.stride == 0 {
        return Err(format!("{PATH} has an empty aperture or plane stride"));
    }
    Ok(Some(MemoryController { apertures, layout }))
}

/// The board a DeviceTree describes, or why the engine cannot model it: its
/// chip and PEs ([`cpus`], from `/chosen` `chip-id`, `/product`
/// `product-soc-name` and each `/cpus` node with a `cluster-type`) and the
/// devices the engine models, each of which must be `compatible` with its
/// model. An `/arm-io` child's `reg` is translated through `/arm-io`
/// `ranges`; the AIC's input count is one more than the highest
/// `interrupts` value of any node whose `interrupt-parent` is its phandle.
pub fn board(tree: &[u8]) -> Result<Board, String> {
    let root = Node::root(tree).ok_or("DeviceTree has no root")?;
    let chip_id = root
        .child("chosen")
        .and_then(|chosen| chosen.first_u32("chip-id"))
        .ok_or("DeviceTree has no /chosen chip-id")?;
    let soc_name = root
        .child("product")
        .and_then(|product| product.property("product-soc-name"))
        .and_then(|name| core::str::from_utf8(name).ok())
        .map(|name| name.trim_end_matches('\0'))
        .ok_or("DeviceTree has no /product product-soc-name")?;
    let mut found = Vec::new();
    let mut blocks = Vec::new();
    root.child("cpus")
        .ok_or("DeviceTree has no /cpus")?
        .visit(&mut |node| {
            if let Some(cluster_type) = node.property("cluster-type") {
                found.push((cluster_type.first().copied(), node.first_u32("reg")));
                for (index, name) in ["cpu-impl-reg", "cpm-impl-reg"].into_iter().enumerate() {
                    blocks.push((index, name, node.pairs(name)));
                }
            }
        })
        .ok_or("DeviceTree walk failed")?;
    let processors = found
        .into_iter()
        .map(|found| match found {
            (Some(cluster_type), Some(reg)) => Ok(Processor { cluster_type, reg }),
            _ => Err("a /cpus node has no reg or an empty cluster-type"),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let cpus = cpus(chip_id, soc_name, &processors)?;
    let mut lockdown: Vec<LockdownBlock> = Vec::new();
    for (index, name, pairs) in blocks.into_iter().filter(|_| cpus.lockdown.is_some()) {
        let (physical, bytes) = pairs
            .and_then(|pairs| pairs.first().copied())
            .ok_or_else(|| format!("a /cpus node has no {name}"))?;
        let control = cpus.lockdown.expect("filtered")[index];
        if control + 16 > bytes {
            return Err(format!("{name} at {physical:#x} has no lockdown registers"));
        }
        if !lockdown.iter().any(|block| block.physical == physical) {
            lockdown.push(LockdownBlock {
                name,
                physical,
                bytes,
                control,
            });
        }
    }
    let io = root.child("arm-io").ok_or("DeviceTree has no /arm-io")?;
    let ranges = io.ranges().ok_or("/arm-io has no ranges")?;
    let place = |name: &str, model: Option<&str>| -> Result<(Node<'_>, u64, u64), String> {
        let node = io
            .child(name)
            .ok_or_else(|| format!("DeviceTree has no /arm-io/{name}"))?;
        if let Some(model) = model
            && !node.compatible(model)
        {
            return Err(format!("/arm-io/{name} is not {model}, the modeled device"));
        }
        let (offset, bytes) = node
            .pairs("reg")
            .and_then(|reg| reg.first().copied())
            .ok_or_else(|| format!("/arm-io/{name} has no reg"))?;
        let physical = ranges
            .iter()
            .find(|(child, _, size)| (*child..child + size).contains(&offset))
            .map(|(child, parent, _)| parent + (offset - child))
            .ok_or_else(|| format!("/arm-io/{name} lies outside /arm-io ranges"))?;
        Ok((node, physical, bytes))
    };
    let device = |name: &str, model: &str| -> Result<Device, String> {
        let (node, physical, bytes) = place(name, Some(model))?;
        let irq = node
            .first_u32("interrupts")
            .ok_or_else(|| format!("/arm-io/{name} has no interrupts"))?;
        Ok(Device {
            physical,
            bytes,
            irq,
        })
    };
    let uart = device("uart0", UART)?;
    let watchdog = device("wdt", WATCHDOG)?;
    let (version, event) = cpus
        .aic
        .ok_or("the SoC's AIC event register offset is unknown")?;
    let (aic, physical, _) = place("aic", Some(version))?;
    let layout = aic_layout(&aic, version, event)?;
    let phandle = aic
        .first_u32("AAPL,phandle")
        .ok_or("/arm-io/aic has no phandle")?;
    let mut highest = None;
    root.visit(&mut |node| {
        if node.first_u32("interrupt-parent") == Some(phandle)
            && let Some(cells) = node.cells32("interrupts")
        {
            highest = cells.into_iter().chain(highest).max();
        }
    })
    .ok_or("DeviceTree walk failed")?;
    let highest = highest.ok_or("no node names the AIC as its interrupt parent")?;
    let inputs = u16::try_from(highest + 1).map_err(|_| "AIC interrupt number above 65534")?;
    let memory_controller =
        memory_controller(&root.child("chosen").ok_or("DeviceTree has no /chosen")?)?;
    Ok(Board {
        cpus,
        uart,
        watchdog,
        lockdown,
        memory_controller,
        aic: InterruptController {
            physical,
            inputs,
            layout,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layout_of(layout: &[(u8, u32)]) -> Vec<Processor> {
        layout
            .iter()
            .map(|&(cluster_type, reg)| Processor { cluster_type, reg })
            .collect()
    }

    #[test]
    fn a_board_takes_its_chip_and_pes_from_the_device_tree() {
        // J473AP (Mac14,3): cpu0-3 Blizzard E cores, cpu4-7 Avalanche P cores.
        let layout: Vec<(u8, u32)> = (0..8)
            .map(|cpu| {
                (
                    if cpu < 4 { b'E' } else { b'P' },
                    ((cpu / 4) << 8) | (cpu % 4),
                )
            })
            .collect();
        let found = cpus(0x8112, "Apple M2", &layout_of(&layout)).unwrap();
        assert_eq!(
            (found.chip, found.aic),
            (Chip::AppleM2, Some(("aic,2", 0x8000)))
        );
        let identities = found.processors;
        assert_eq!(
            identities[0],
            Identity {
                midr: 0x611f_0320,
                mpidr: 0x8000_0000,
                clock: Some(2_424_000_000),
            }
        );
        assert_eq!(
            identities[7],
            Identity {
                midr: 0x611f_0330,
                mpidr: 0x8001_0103,
                clock: Some(3_504_000_000),
            }
        );
        // J604AP (Mac16,1): six M4 E cores and four P cores.
        let layout = [(b'E', 0), (b'E', 5), (b'P', 0x100), (b'P', 0x103)];
        let found = cpus(0x8132, "Apple M4", &layout_of(&layout)).unwrap();
        assert_eq!((found.chip, found.aic), (Chip::AppleM4, None));
        let identities = found.processors;
        assert_eq!(identities[1].midr, 0x611f_0520);
        assert_eq!(
            identities[3],
            Identity {
                midr: 0x611f_0530,
                mpidr: 0x8001_0103,
                clock: None,
            }
        );
        // An M2 Pro's AIC2 has its event register at +0xc000.
        assert_eq!(
            cpus(0x6020, "Apple M2 Pro", &layout_of(&layout))
                .unwrap()
                .aic,
            Some(("aic,2", 0xc000))
        );
        // The M3's AICv3 has it at +0x40000.
        assert_eq!(
            cpus(0x8122, "Apple M3", &layout_of(&layout)).unwrap().aic,
            Some(("aic,3", 0x40000))
        );
        assert_eq!(dram_base(0x8112), Ok(0x8_0000_0000));
        assert_eq!(dram_base(0x6021), Ok(0x100_0000_0000));
        assert!(dram_base(0x8132).is_err());
        // Every ApChipID appears once.
        for (index, soc) in SOCS.iter().enumerate() {
            assert!(
                SOCS[index + 1..]
                    .iter()
                    .all(|other| other.chip_id != soc.chip_id)
            );
        }
    }

    #[test]
    fn a_board_without_evidence_refuses() {
        let one = layout_of(&[(b'E', 0)]);
        // M2 Ultra: two dies, no public part numbers.
        assert_eq!(
            cpus(0x6022, "Apple M2 Ultra", &one),
            Err("ApChipID 0x6022 (Apple M2 Ultra) has no public MIDR part".into())
        );
        assert!(cpus(0x8112, "Apple M2 Pro", &one).is_err());
        assert!(cpus(0x8112, "Apple M2", &[]).is_err());
        // The M6's M cores and a second die's affinity.
        assert_eq!(
            cpus(0x8152, "Apple M6", &layout_of(&[(b'M', 0)])),
            Err("Apple M6 cluster type M has no public MIDR part".into())
        );
        assert!(cpus(0x6031, "Apple M3 Max", &layout_of(&[(b'P', 0x800)])).is_err());
    }

    /// A J473AP-shaped DeviceTree: two PEs, `/arm-io` child 0 at PA
    /// 0x2_0000_0000, and the UART, watchdog and AIC as `compatibles` names.
    fn tree(chip_id: u32, soc: &str, compatibles: [&str; 3]) -> Vec<u8> {
        tree_with(chip_id, soc, compatibles, &[])
    }
    /// [`tree`] with more `/arm-io/aic` properties.
    fn tree_with(
        chip_id: u32,
        soc: &str,
        compatibles: [&str; 3],
        aic_properties: &[(&str, u32)],
    ) -> Vec<u8> {
        use crate::machine::adt::encode;
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
                    ("cpu-impl-reg", &u64s(&[0x2_1005_0000 + cluster, 0x9010])),
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
                ("ranges", &u64s(&[0, 0x2_0000_0000, 0x1_0000_0000])),
            ],
            &[
                device("uart0", compatibles[0], 0x3520_0000, 739),
                device("wdt", compatibles[1], 0x3d2b_0000, 379),
                aic,
            ],
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

    #[test]
    fn a_board_states_its_dram_base_or_takes_its_socs() {
        use crate::machine::adt::encode;
        let z = |text: &str| [text.as_bytes(), &[0]].concat();
        let with_base = |base: Option<&[u8]>| {
            let mcc = base.map(|base| encode(&[("name", &z("mcc")), ("dram-base", base)], &[]));
            encode(
                &[("name", &z("device-tree"))],
                &[encode(&[("name", &z("arm-io"))], mcc.as_slice())],
            )
        };
        let m3 = 0x8122;
        let stated = 0x100_0000_0000_u64.to_le_bytes();
        // The M3's base is in its DeviceTree only.
        assert_eq!(
            board_dram_base(&with_base(Some(&stated)), m3),
            Ok(0x100_0000_0000)
        );
        assert!(board_dram_base(&with_base(None), m3).is_err());
        // The M2's board states none and takes the public base; a stated base
        // must agree with it.
        assert_eq!(board_dram_base(&with_base(None), 0x8112), Ok(0x8_0000_0000));
        assert!(board_dram_base(&with_base(Some(&stated)), 0x8112).is_err());
        assert!(board_dram_base(&with_base(Some(&[0; 4])), m3).is_err());
    }

    #[test]
    fn a_device_tree_places_the_board_or_says_why_it_cannot() {
        const MODELED: [&str; 3] = ["uart-1,samsung", "wdt,s5l8960x", "aic,2"];
        let found = board(&tree(0x8112, "Apple M2", MODELED)).unwrap();
        assert_eq!(found.cpus.chip, Chip::AppleM2);
        assert_eq!(found.cpus.processors[1].mpidr, 0x8001_0100);
        assert_eq!(
            found.uart,
            Device {
                physical: 0x2_3520_0000,
                bytes: 0x4000,
                irq: 739
            }
        );
        assert_eq!(found.watchdog.irq, 379);
        // Each PE's cpu-impl-reg and each cluster's cpm-impl-reg, once.
        let block = |name, physical, control| LockdownBlock {
            name,
            physical,
            bytes: 0x9010,
            control,
        };
        assert_eq!(
            found.lockdown,
            [
                block("cpu-impl-reg", 0x2_1005_0000, 0x5000),
                block("cpm-impl-reg", 0x2_10e4_0000, 0x9000),
                block("cpu-impl-reg", 0x2_1105_0000, 0x5000),
                block("cpm-impl-reg", 0x2_11e4_0000, 0x9000),
            ]
        );
        // The UART's input 739 is the highest that names the AIC.
        assert_eq!(
            found.aic,
            InterruptController {
                physical: 0x2_3b0c_0000,
                inputs: 740,
                layout: AicLayout::V2 {
                    irq_config: AIC2_IRQ_CFG,
                    event: 0x8000
                }
            }
        );
        // The M1's AICv1 has its event register in its core block.
        let m1 = board(&tree(
            0x8103,
            "Apple M1",
            ["uart-1,samsung", "wdt,s5l8960x", "aic,1"],
        ))
        .unwrap();
        assert_eq!(
            (m1.cpus.chip, m1.aic.layout),
            (Chip::AppleM1, AicLayout::V1)
        );
        // No SPTM shows the M1's lockdown registers.
        assert!(m1.lockdown.is_empty());
        assert_eq!(
            board(&tree(0x8103, "Apple M1", MODELED)),
            Err("/arm-io/aic is not aic,1, the modeled device".into())
        );
        assert_eq!(
            board(&tree(
                0x8112,
                "Apple M2",
                ["uart-2", "wdt,s5l8960x", "aic,2"]
            )),
            Err("/arm-io/uart0 is not uart-1,samsung, the modeled device".into())
        );
        assert_eq!(
            board(&tree(0x8122, "Apple M3", MODELED)),
            Err("/arm-io/aic is not aic,3, the modeled device".into())
        );
        assert!(board(&[0; 4]).is_err());
    }

    #[test]
    fn an_aic3_board_states_the_modeled_offsets() {
        const M3: [&str; 3] = ["uart-1,samsung", "wdt,s5l8960x", "aic,3"];
        let found = board(&tree_with(0x8122, "Apple M3", M3, &AIC3_OFFSETS)).unwrap();
        assert_eq!(
            (found.cpus.chip, found.aic.layout),
            (
                Chip::AppleM3,
                AicLayout::V2 {
                    irq_config: AIC3_IRQ_CFG,
                    event: 0x40000
                }
            )
        );
        assert_eq!(
            board(&tree_with(0x8122, "Apple M3", M3, &AIC3_OFFSETS[1..])),
            Err("/arm-io/aic has no rev-offset".into())
        );
        let mut moved = AIC3_OFFSETS;
        moved[4].1 = 0x20000;
        assert_eq!(
            board(&tree_with(0x8122, "Apple M3", M3, &moved)),
            Err("/arm-io/aic extint-baseaddress is 0x20000, not the modeled 0x10000".into())
        );
        // The M4's AICv3 event register has no public placement.
        assert_eq!(
            board(&tree_with(0x8132, "Apple M4", M3, &AIC3_OFFSETS)),
            Err("the SoC's AIC event register offset is unknown".into())
        );
    }
}
