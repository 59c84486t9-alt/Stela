//! DeviceTree placement and validation for power registers.
use super::CpuCluster;
use super::Identity;
use super::Node;
use super::PMGR2_ARCH;
use super::SOCS;
use super::String;
use super::Vec;
use super::WakeLayout;
use super::apertures;
use super::cluster;
use super::energy;
use super::format;
use super::fuse;
use super::power_resources::PMGR_DEVICE;
use super::wake;
use crate::platform::apple::pmgr::dvfs;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeBank {
    pub physical: u64,
    pub fields: Vec<(u64, u32)>,
    pub header: [u8; 4],
    pub configs: Vec<[u8; 36]>,
    pub axi: Option<[u8; 4]>,
    /// IDs whose `device-bridges` dependency list names this bridge.
    pub devices: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocDpe {
    pub physical: u64,
    pub samples: Vec<(u64, bool)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PowerBank {
    pub physical: u64,
    pub kind: stela_soc_data::power::Kind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WakeBank {
    pub physical: u64,
    pub valid: [u32; wake::WORDS],
    pub sources: Vec<u8>,
    /// `ap-wake-sources`' `SMC.CPUWakeupAP`: the SMC waking the AP.
    pub smc_wake: Option<u8>,
}

/// A version-1 `perf-regs` group: translated global word and the union of
/// selectors named by the DeviceTree's counter-bearing records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PerfBank {
    pub physical: u64,
    pub selectors: Vec<u16>,
}

/// A direct CPU energy bank, with its optional CPM enable configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnergyBank {
    pub physical: u64,
    pub cpm: bool,
}

/// Independently qualified PMGR register families. A missing optional family
/// does not revoke power-state ownership or another family's register model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PmgrBank {
    CpuClusters,
    Bridges,
    SocPower,
    SocDpe,
    WakeMasks,
    Performance,
    CpuEnergy,
    Services,
    /// Source-qualified protocol, awaiting actual native controller effects.
    Dvfs(dvfs::Controller),
}

/// A visible register family whose semantics have not been established.
/// The mount reports these through its unsupported-operation policy; no register
/// or lifecycle effect is supplied by retaining this descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PmgrBankRefusal {
    pub bank: PmgrBank,
    pub reason: &'static str,
}

impl From<dvfs::UnqualifiedEffects> for PmgrBankRefusal {
    fn from(refusal: dvfs::UnqualifiedEffects) -> Self {
        Self {
            bank: PmgrBank::Dvfs(refusal.controller),
            reason: refusal.reason(),
        }
    }
}

/// Validate advertised legacy record envelopes even when their register model
/// is unavailable. An unsupported family is not permission to discard malformed
/// data. The 26A434 v1 driver records are described by the parser below and
/// `power_resources::records`; v2 performance metadata has a separate envelope.
fn validate_bank_records(node: &Node<'_>) -> Result<(), String> {
    for (name, bytes) in [
        ("devices", PMGR_DEVICE),
        ("clocks", 24),
        ("events", 24),
        ("power-domains", 24),
        ("hw-dpe-reg", 40),
        ("perf-regs", 16),
        ("bridge-counters", 4),
        ("bridge-counter-configs", 36),
        ("device-bridges", 76),
        ("axi2af-axi-config", 4),
        ("optional-bridge-mask", 4),
        ("clusters", 4),
        ("ap-wake-sources", 36),
    ] {
        if node
            .property(name)
            .is_some_and(|raw| !raw.len().is_multiple_of(bytes))
        {
            return Err(format!("/arm-io/pmgr {name} has incomplete records"));
        }
    }
    for name in [
        "bridge-reg-index",
        "#bridges",
        "bridge-settings-version",
        "bridge-counter-version",
    ] {
        if node.property(name).is_some_and(|raw| raw.len() != 4) {
            return Err(format!("/arm-io/pmgr {name} is not one complete word"));
        }
    }
    if let Some(count) = node.first_u32("#bridges") {
        for name in ["bridge-counters", "axi2af-axi-config"] {
            if node
                .property(name)
                .is_some_and(|raw| raw.len() / 4 != count as usize)
            {
                return Err(format!("/arm-io/pmgr {name} disagrees with #bridges"));
            }
        }
    }
    if node.first_u32("bridge-settings-version") == Some(1)
        && node.first_u32("bridge-counter-version") == Some(3)
    {
        let count = node
            .first_u32("#bridges")
            .ok_or("PMGR has no bridge count for its known source table")?;
        super::power_resources::bridges::Records::new(node, count as usize)?;
    }
    Ok(())
}

/// The SoC's optional register families, independently of its common
/// power-state table and CPU-start bank. Driver matching comes from the SoC
/// row; each family's qualified layout remains a separate requirement.
pub(super) fn pmgr_registers(
    io: &Node<'_>,
    translate: &dyn Fn(u64, u64) -> Option<u64>,
    chip_id: u32,
) -> Result<PmgrRegisters, String> {
    let mut result = PmgrRegisters::default();
    let Some(soc) = SOCS.iter().find(|soc| soc.chip_id == chip_id) else {
        return Ok(result);
    };
    let Some(parent) = io.child("pmgr").filter(|node| node.compatible(soc.pmgr)) else {
        return Ok(result);
    };
    let node = super::power_resources::register_node(io, &parent)?;
    validate_bank_records(&node)?;
    // Each source view is checked in full before any optional model is kept.
    let reg: Vec<Option<(u64, u64)>> = apertures::registers(&node)
        .ok_or("PMGR reg has incomplete physical pairs")?
        .into_iter()
        .enumerate()
        .map(|(index, (offset, bytes))| {
            if bytes == 0 {
                Ok(None)
            } else {
                translate(offset, bytes)
                    .map(|physical| Some((physical, bytes)))
                    .ok_or_else(|| format!("PMGR reg[{index}] complete view {offset:#x}/{bytes:#x} is outside or ambiguous in its bus domain"))
            }
        })
        .collect::<Result<_, _>>()?;
    let mut refuse = |bank, reason| result.refusals.push(PmgrBankRefusal { bank, reason });
    let clusters = soc
        .clusters
        .map(|clusters| clusters.to_vec())
        .unwrap_or_default();
    if soc.clusters.is_none() && node.property("clusters").is_some() {
        refuse(
            PmgrBank::CpuClusters,
            "CPU cluster register layout is not qualified for this SoC",
        );
    }
    validate_clusters(&reg, &clusters)?;
    result.clusters = clusters;
    result.aon_fuses = soc
        .aon_fuses
        .map(|index| {
            reg.get(index)
                .copied()
                .flatten()
                .filter(|&(_, bytes)| bytes == fuse::FUSE_BYTES)
                .ok_or_else(|| format!("/arm-io/pmgr reg[{index}] is not the eFuse block"))
        })
        .transpose()?;
    if node.property("bridge-reg-index").is_some() && soc.bridge_fields.is_none() {
        refuse(
            PmgrBank::Bridges,
            "bridge register layout is not qualified for this SoC",
        );
    } else if node
        .first_u32("bridge-settings-version")
        .is_some_and(|v| v != 1)
        || node
            .first_u32("bridge-counter-version")
            .is_some_and(|v| v != 3)
        || node
            .property("optional-bridge-mask")
            .is_some_and(|v| v.iter().any(|&b| b != 0))
    {
        refuse(
            PmgrBank::Bridges,
            "bridge version or optional-bank selection is not qualified",
        );
    } else {
        result.bridges = place_bridges(&node, &reg, soc.bridge_fields)?;
    }
    if result.clusters.is_empty() {
        result.cluster_events = Vec::new();
    } else {
        result.cluster_events = acc_events(&node, result.clusters.len())?;
    }
    result.power_banks = place_power_banks(&reg, soc.power_banks)?;
    if soc.power_banks.is_empty() {
        refuse(
            PmgrBank::SocPower,
            "SoC-specific power register roles are not qualified",
        );
    }
    result.soc_dpe = if let Some(index) = soc.dpe_reg {
        Some(place_soc_dpe(&node, &reg, index)?)
    } else {
        if node.property("soc-dpe").is_some() {
            refuse(PmgrBank::SocDpe, "SoC DPE register layout is not qualified");
        }
        None
    };
    // Without the cluster layout, an absolute DPE address cannot be classified
    // as a CPM accumulator merely because it lies inside a broad reg window.
    if result.clusters.is_empty() && node.property("hw-dpe-reg").is_some() {
        refuse(
            PmgrBank::CpuEnergy,
            "CPU/CPM energy register ownership is not qualified",
        );
    } else {
        result.energy = energy_banks(&node, &reg, &result.clusters)?;
    }
    let unsupported_perf = node.property("perf-groups").is_some()
        || node.property("perf-regs").is_some_and(|raw| {
            raw.as_chunks::<16>()
                .0
                .iter()
                .any(|entry| !matches!(entry[12], 0 | 3) || entry[13] > 1 || entry[15] != 0)
        });
    if unsupported_perf {
        refuse(
            PmgrBank::Performance,
            "performance counter class, layout or flags are not qualified",
        );
    } else {
        result.performance = performance_banks(&node, &reg)?;
    }
    result.wake_masks = if let Some(layout) = soc.wake_masks {
        Some(wake_bank(&node, &reg, layout)?)
    } else {
        if node.property("ap-wake-sources").is_some() {
            refuse(
                PmgrBank::WakeMasks,
                "wake-mask register layout is not qualified",
            );
        }
        None
    };
    if parent.compatible(PMGR2_ARCH) {
        refuse(
            PmgrBank::Services,
            "PMGRv2 PSD service-gate command interface is not qualified",
        );
    }
    Ok(result)
}

fn validate_clusters(reg: &[Option<(u64, u64)>], clusters: &[CpuCluster]) -> Result<(), String> {
    let covered = |start: u64, bytes: u64| {
        reg.iter().flatten().any(|&(base, size)| {
            start
                .checked_sub(base)
                .and_then(|offset| offset.checked_add(bytes))
                .is_some_and(|end| end <= size)
        })
    };
    for cluster in clusters {
        let cpm_base = cluster
            .base
            .checked_add(stela_soc_data::cpm::T8112_OFFSET)
            .ok_or("CPM base overflows")?;
        for offset in stela_soc_data::cpm::offsets(cluster.counter_map) {
            if !covered(cpm_base + offset, 8) {
                return Err("PMGR reg does not cover a CPM power register".into());
            }
        }
        for offset in cluster::SCRATCH {
            if !covered(cluster.base + offset, 8) {
                return Err("PMGR reg does not cover CPU state scratch".into());
            }
        }
        let window = cluster.base + cluster::ACC_OFFSET;
        let table = cluster.pstates as u64 * cluster::PSTATE_BYTES;
        if !reg.contains(&Some((window, cluster::ACC_BYTES)))
            || !covered(cluster.base + cluster::PSTATE_OFFSET, table)
        {
            return Err(format!(
                "/arm-io/pmgr reg does not place the CPU cluster at {:#x}",
                cluster.base
            ));
        }
    }
    Ok(())
}

/// The CPU start registers' guest PA and the clusters they start, where the
/// SoC row gives their offset ([`CPU_START_T8112`] and its siblings) from
/// `reg[0]` of the PMGR node: `/arm-io/pmgr`, or `/arm-io/pmgr-child` where
/// `/arm-io/pmgr` is the generic `pmgr2,arch` (m1n1 `pmgr.c`
/// `pmgr_adt_path_offset_trace`; the 26A434 ApplePMGR "Looked up under
/// 'pmgr' and 'pmgr-child'"), when `/arm-io/pmgr` is the row's `pmgr`. The
/// registers must lie in that `reg[0]` with a start word for each cluster
/// of the board's PEs.
pub(super) fn cpu_start(
    io: &Node<'_>,
    translate: &dyn Fn(u64, u64) -> Option<u64>,
    chip_id: u32,
    processors: &[Identity],
) -> Result<Option<(u64, u8)>, String> {
    let Some(soc) = SOCS.iter().find(|soc| soc.chip_id == chip_id) else {
        return Ok(None);
    };
    let (Some(offset), Some(pmgr)) = (soc.cpu_start, io.child("pmgr")) else {
        return Ok(None);
    };
    if !pmgr.compatible(soc.pmgr) {
        return Ok(None);
    }
    let (name, node) = if pmgr.compatible(PMGR2_ARCH) {
        let child = io
            .child("pmgr-child")
            .ok_or("/arm-io/pmgr is pmgr2,arch without /arm-io/pmgr-child")?;
        ("pmgr-child", child)
    } else {
        ("pmgr", pmgr)
    };
    let (base, bytes) = apertures::registers(&node)
        .and_then(|reg| reg.first().copied())
        .ok_or_else(|| format!("/arm-io/{name} has no reg"))?;
    let clusters = processors
        .iter()
        .map(|pe| ((pe.mpidr >> 8) & 0xff) as u8 + 1)
        .max()
        .unwrap_or(0);
    if offset + stela_soc_data::cpustart::bytes(clusters) > bytes {
        return Err(format!(
            "/arm-io/{name} reg[0] does not hold the CPU start registers"
        ));
    }
    let physical = translate(base + offset, stela_soc_data::cpustart::bytes(clusters))
        .ok_or_else(|| format!("/arm-io/{name} reg[0] is outside /arm-io ranges"))?;
    Ok(Some((physical, clusters)))
}

/// Special CPU event types2/7 select E/P ACC accessors, not the SOC-bank
/// selector formula (kernel 0x2b93ac4..0x2b93cec). Byte6 is the event index.
fn acc_events(node: &Node<'_>, clusters: usize) -> Result<Vec<Vec<u8>>, String> {
    let mut events = alloc::vec![Vec::new();clusters];
    let data = node.property("events").unwrap_or_default();
    if !data.len().is_multiple_of(24) {
        return Err("ACC events property is not whole records".into());
    }
    for entry in data.as_chunks::<24>().0 {
        let cluster = match entry[2] {
            2 => 0,
            7 => 1,
            _ => continue,
        };
        let bank = events
            .get_mut(cluster)
            .ok_or("ACC event names a missing CPU cluster")?;
        if entry[6] >= 27 {
            return Err("ACC event selector exceeds the accessor range".into());
        }
        if !bank.contains(&entry[6]) {
            bank.push(entry[6]);
        }
    }
    Ok(events)
}

/// Bridge map and source decoding: kernel file 0x2b71bd8..0x2b71fd8,
/// device dependencies 0x2b73c80 and version3 counter programmer 0x2b96214.
/// `reg` always passes through arm-io ranges, including high PCIe windows.
fn place_bridges(
    node: &Node<'_>,
    reg: &[Option<(u64, u64)>],
    fields: Option<&[&[(u64, u32)]]>,
) -> Result<Vec<BridgeBank>, String> {
    let Some(first) = node.first_u32("bridge-reg-index") else {
        return Ok(Vec::new());
    };
    let fields = fields.ok_or("this SoC has no documented bridge register layouts")?;
    let count = node
        .first_u32("#bridges")
        .ok_or("PMGR has no bridge count")? as usize;
    if count > fields.len()
        || node.first_u32("bridge-settings-version") != Some(1)
        || node.first_u32("bridge-counter-version") != Some(3)
    {
        return Err("unsupported bridge count or configuration version".into());
    }
    let records = super::power_resources::bridges::Records::new(node, count)?;
    let mut banks = Vec::new();
    let optional = node.first_u32("optional-bridge-mask").unwrap_or(0);
    if optional != 0 {
        return Err("optional bridge suppression requires an established selection policy".into());
    }
    for (id, tunables) in fields.iter().enumerate().take(count) {
        let index = (first as usize)
            .checked_add(id)
            .ok_or("bridge reg index overflows")?;
        let (physical, bytes) = reg
            .get(index)
            .copied()
            .flatten()
            .ok_or("bridge names an unmapped DT reg window")?;
        let record = records.record(id).expect("validated bridge ordinal");
        let model = stela_soc_data::bridge::Layout::new(
            tunables,
            record.header,
            &record.configs,
            record.axi,
        )
        .map_err(String::from)?;
        for (o, n) in model.spans() {
            if o.checked_add(n).is_none_or(|end| end > bytes)
                || physical.checked_add(o + n).is_none()
            {
                return Err("bridge configuration lies outside its DT range".into());
            }
        }
        banks.push(BridgeBank {
            physical,
            fields: tunables.to_vec(),
            header: record.header,
            configs: record.configs,
            axi: record.axi,
            devices: record.devices,
        });
    }
    Ok(banks)
}

/// SOC DPE direct split-word records have group 0x1d, die mask 1,
/// command flag 0, split flag 1 and width 64 (PMGR parser 0x2b7796c).
fn place_soc_dpe(
    node: &Node<'_>,
    reg: &[Option<(u64, u64)>],
    index: usize,
) -> Result<SocDpe, String> {
    let (physical, bytes) = reg
        .get(index)
        .copied()
        .flatten()
        .ok_or("SOC DPE has no mapped DT reg bank")?;
    let data = node.property("hw-dpe-reg").unwrap_or_default();
    if !data.len().is_multiple_of(40) {
        return Err("SOC DPE hw-dpe-reg has partial records".into());
    }
    let mut samples = Vec::new();
    for entry in data.as_chunks::<40>().0 {
        if entry[16..18] != [0x1d, 0] || entry[19] != 0 {
            continue;
        }
        if entry[18] != 1 || entry[20] != 1 || entry[23] != 64 {
            return Err("unsupported SOC DPE sampling flags".into());
        }
        let address = u64::from_le_bytes(entry[..8].try_into().expect("8 bytes"));
        let offset = address
            .checked_sub(physical)
            .ok_or("SOC DPE sample below its reg bank")?;
        samples.push((offset, stela_soc_data::dpe::RESTORE.contains(&offset)));
    }
    let model = stela_soc_data::dpe::Layout::new(&samples).map_err(String::from)?;
    for (o, n) in model.spans() {
        if o.checked_add(n).is_none_or(|end| end > bytes) || physical.checked_add(o + n).is_none() {
            return Err("SOC DPE register outside its DT bank".into());
        }
    }
    Ok(SocDpe { physical, samples })
}

/// Bind documented RegMap roles to DT addresses, validating every modeled
/// word against the selected range rather than claiming a broad PMGR bank.
fn place_power_banks(
    reg: &[Option<(u64, u64)>],
    layouts: &[(usize, stela_soc_data::power::Kind)],
) -> Result<Vec<PowerBank>, String> {
    layouts
        .iter()
        .map(|&(index, kind)| {
            let (physical, bytes) = reg
                .get(index)
                .copied()
                .flatten()
                .ok_or("PMGR power bank names an unmapped reg entry")?;
            for offset in kind.offsets() {
                if offset.checked_add(4).is_none_or(|end| end > bytes)
                    || physical.checked_add(offset + 4).is_none()
                    || !physical.is_multiple_of(4)
                {
                    return Err("PMGR power register lies outside its DT range".into());
                }
            }
            Ok(PowerBank { physical, kind })
        })
        .collect()
}

/// `ap-wake-sources` is (u32 source, 32-byte name), kernel parser
/// `ApplePMGR` and `setAPWakeupSources` 0x2fa3f84. Reported sources are
/// validated against hardware capabilities, not used as a reset mask.
fn wake_bank(
    node: &Node<'_>,
    reg: &[Option<(u64, u64)>],
    layout: WakeLayout,
) -> Result<WakeBank, String> {
    const RECORD: usize = 36;
    let (base, bytes) = reg
        .get(layout.reg)
        .copied()
        .flatten()
        .ok_or("PMGR AOP wake masks have no mapped reg bank")?;
    if bytes < wake::OFFSET + wake::BYTES {
        return Err("PMGR AOP wake masks exceed their reg bank".into());
    }
    base.checked_add(wake::OFFSET + wake::BYTES)
        .ok_or("PMGR AOP wake mask span overflows")?;
    let physical = base + wake::OFFSET;
    let data = node.property("ap-wake-sources").unwrap_or_default();
    if !data.len().is_multiple_of(RECORD) {
        return Err("PMGR ap-wake-sources is not whole records".into());
    }
    let mut sources = Vec::new();
    let mut smc_wake = None;
    for entry in data.as_chunks::<RECORD>().0 {
        let source = u32::from_le_bytes(entry[..4].try_into().expect("4 bytes"));
        if entry[4..].split(|&b| b == 0).next() == Some(SMC_WAKE_SOURCE) {
            smc_wake = u8::try_from(source).ok();
        }
        let id =
            u8::try_from(source).map_err(|_| "PMGR wake source exceeds hardware mask width")?;
        if layout.valid[source as usize / u32::BITS as usize] & (1 << (source % u32::BITS)) == 0
            || sources.contains(&id)
        {
            return Err("PMGR ap-wake-sources contains an unsupported or duplicate source".into());
        }
        sources.push(id);
    }
    Ok(WakeBank {
        physical,
        valid: layout.valid,
        sources,
        smc_wake,
    })
}

/// The `ap-wake-sources` name of the SMC's wake of the AP.
const SMC_WAKE_SOURCE: &[u8] = b"SMC.CPUWakeupAP";

/// Version-1 group layout: `_initPerfCountersV1` (kernel file 0x2b79ec0),
/// `_getPerfCounterOffset` (0x2b8e974) and the selector consumers
/// (0x2b92ddc..0x2b93010, 0x2b95884..0x2b95964). No physical address or
/// counter index is inferred from a reporting name or device ID.
fn performance_banks(node: &Node<'_>, reg: &[Option<(u64, u64)>]) -> Result<Vec<PerfBank>, String> {
    use crate::platform::apple::perf::{COUNTER_BASE, STRIDE};
    const GROUP: usize = 16;
    const SOURCE: usize = 24;
    const DEVICE_COUNTER: u8 = 0x20;
    let data = node.property("perf-regs").unwrap_or_default();
    if !data.len().is_multiple_of(GROUP) {
        return Err("/arm-io/pmgr perf-regs is not whole groups".into());
    }
    let mut banks = Vec::new();
    let mut counts = Vec::new();
    for entry in data.as_chunks::<GROUP>().0 {
        let index = u32::from_le_bytes(entry[..4].try_into().expect("4 bytes")) as usize;
        let offset = u64::from(u32::from_le_bytes(entry[4..8].try_into().expect("4 bytes")));
        let count = u16::from_le_bytes(entry[8..10].try_into().expect("2 bytes"));
        // Version zero defaults to one. Parent/global indirection and the
        // busy protocol of classes 1/2 need separate semantics.
        if !matches!(entry[12], 0 | 3) || entry[13] > 1 || entry[15] != 0 {
            return Err("/arm-io/pmgr perf-regs has an unsupported class, layout or flags".into());
        }
        let (base, bytes) = reg
            .get(index)
            .copied()
            .flatten()
            .ok_or("/arm-io/pmgr perf-regs names an unmapped reg bank")?;
        if count == 0
            || !offset.is_multiple_of(4)
            || offset + COUNTER_BASE + u64::from(count) * STRIDE > bytes
        {
            return Err(
                "/arm-io/pmgr perf-regs counters are empty or exceed their reg bank".into(),
            );
        }
        base.checked_add(offset + COUNTER_BASE + u64::from(count) * STRIDE)
            .ok_or("PMGR performance bank span overflows")?;
        let physical = base + offset;
        banks.push(PerfBank {
            physical,
            selectors: Vec::new(),
        });
        counts.push(count);
    }
    if banks.is_empty() {
        return Ok(banks);
    }
    let mut select = |group: u8, index: u8| -> Result<(), String> {
        let bank = banks
            .get_mut(usize::from(group))
            .ok_or("PMGR counter source names a missing perf-regs group")?;
        let index = u16::from(index);
        if index >= counts[usize::from(group)] {
            return Err("PMGR counter source exceeds its perf-regs count".into());
        }
        if !bank.selectors.contains(&index) {
            bank.selectors.push(index);
        }
        Ok(())
    };
    let devices = node.property("devices").unwrap_or_default();
    if !devices.len().is_multiple_of(PMGR_DEVICE) {
        return Err("/arm-io/pmgr devices is not whole entries".into());
    }
    for entry in devices.as_chunks::<PMGR_DEVICE>().0 {
        if entry[0] & DEVICE_COUNTER != 0 {
            select(entry[9], entry[8])?;
        }
    }
    for property in ["clocks", "power-domains", "events"] {
        let data = node.property(property).unwrap_or_default();
        if !data.len().is_multiple_of(SOURCE) {
            return Err(format!(
                "/arm-io/pmgr {property} is not whole counter records"
            ));
        }
        for entry in data.as_chunks::<SOURCE>().0 {
            match property {
                "clocks" if entry[2] & 1 != 0 => select(entry[1], entry[0])?,
                "power-domains" if (entry[2], entry[1]) != (0, 0) => select(entry[2], entry[1])?,
                // Types 2/7 use the ACC accessor, and flag bit 0 selects
                // another event path; neither authorizes a SOC selector.
                "events" if entry[1] & 1 == 0 => match entry[2] {
                    0 => select(entry[7], entry[6])?,
                    1 | 5 | 6 => {
                        select(entry[7], entry[6])?;
                        select(entry[5], entry[4])?;
                    }
                    2 | 7 => (),
                    _ => return Err("PMGR events has an unsupported counter type".into()),
                },
                _ => (),
            }
        }
    }
    for bank in &mut banks {
        bank.selectors.sort_unstable();
    }
    Ok(banks)
}

/// `hw-dpe-reg` records are 40 bytes (`ApplePMGR` parser, kernel file
/// 0x2b7796c..0x2b77af8). The first u64 is an absolute PA, not an arm-io
/// bus address. Direct, single-load, 64-bit CPU records have group 0,
/// die mask 1, command/split flags 0 and behavior flags 1/0. Other groups
/// (GPU/PMP, ANE, SOC DPE) belong to separate models, not CPU accumulators.
fn energy_banks(
    node: &Node<'_>,
    reg: &[Option<(u64, u64)>],
    clusters: &[CpuCluster],
) -> Result<Vec<EnergyBank>, String> {
    const RECORD: usize = 40;
    let data = node.property("hw-dpe-reg").unwrap_or_default();
    if !data.len().is_multiple_of(RECORD) {
        return Err("/arm-io/pmgr hw-dpe-reg is not whole records".into());
    }
    let mut banks = Vec::new();
    for entry in data.as_chunks::<RECORD>().0 {
        if entry[16..18] != [0, 0] || entry[19] != 0 {
            continue;
        }
        if entry[18..24] != [1, 0, 0, 1, 0, 64] {
            return Err(
                "PMGR CPU hw-dpe-reg has unsupported die, sampling, behavior or width flags".into(),
            );
        }
        let physical = u64::from_le_bytes(entry[..8].try_into().expect("8 bytes"));
        let cpm = clusters
            .iter()
            .any(|c| c.base.checked_add(energy::CPM_OFFSET) == Some(physical));
        let bytes = if cpm {
            energy::CONTROL_OFFSET + 8
        } else {
            energy::COUNTER_BYTES
        };
        let covered = reg.iter().flatten().any(|&(base, size)| {
            base <= physical
                && physical
                    .checked_add(bytes)
                    .zip(base.checked_add(size))
                    .is_some_and(|(end, limit)| end <= limit)
                && (cpm
                    || size == energy::CORE_BYTES
                        && base.checked_add(energy::CORE_OFFSET) == Some(physical))
        });
        if !physical.is_multiple_of(8)
            || !covered
            || banks.iter().any(|b: &EnergyBank| b.physical == physical)
        {
            return Err(format!(
                "/arm-io/pmgr CPU hw-dpe-reg PA {physical:#x} is duplicated or outside its reg bank"
            ));
        }
        banks.push(EnergyBank { physical, cpm });
    }
    Ok(banks)
}

/// The PMGR registers the machine models besides its power states.
#[derive(Default)]
pub(super) struct PmgrRegisters {
    pub(super) refusals: Vec<PmgrBankRefusal>,
    pub(super) cluster_events: Vec<Vec<u8>>,
    pub(super) bridges: Vec<BridgeBank>,
    pub(super) soc_dpe: Option<SocDpe>,
    pub(super) power_banks: Vec<PowerBank>,
    pub(super) wake_masks: Option<WakeBank>,
    pub(super) performance: Vec<PerfBank>,
    pub(super) energy: Vec<EnergyBank>,
    pub(super) clusters: Vec<CpuCluster>,
    pub(super) aon_fuses: Option<(u64, u64)>,
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use super::*;

    fn optional_fixture(performance: &[u8], extra: &[(&str, &[u8])]) -> Vec<u8> {
        use stela_contracts::adt::encode;
        let reg = [0x1000u64, 0x1000]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect::<Vec<_>>();
        let clusters = 0u32.to_le_bytes();
        let mut properties = alloc::vec![
            ("name", b"pmgr".as_slice()),
            ("compatible", b"pmgr1,t8103".as_slice()),
            ("reg", reg.as_slice()),
            ("clusters", clusters.as_slice()),
            ("perf-regs", performance),
        ];
        properties.extend_from_slice(extra);
        encode(&[("name", b"arm-io")], &[encode(&properties, &[])])
    }

    fn direct_performance_group() -> [u8; 16] {
        let mut group = [0; 16];
        group[8..10].copy_from_slice(&4u16.to_le_bytes());
        group[12] = 3;
        group[13] = 1;
        group
    }

    #[test]
    fn an_unqualified_optional_bank_preserves_independent_performance_placement() {
        let group = direct_performance_group();
        let bytes = optional_fixture(&group, &[("bridge-reg-index", &0u32.to_le_bytes())]);
        let io = Node::root(&bytes).unwrap();
        let parsed = pmgr_registers(&io, &|address, _| Some(address), 0x8103).unwrap();
        assert_eq!(parsed.performance.len(), 1);
        assert_eq!(parsed.performance[0].physical, 0x1000);
        assert!(parsed.clusters.is_empty());
        assert!(parsed.bridges.is_empty());
        assert!(
            parsed
                .refusals
                .iter()
                .any(|r| r.bank == PmgrBank::CpuClusters)
        );
        assert!(parsed.refusals.iter().any(|r| r.bank == PmgrBank::Bridges));
        assert!(
            !parsed
                .refusals
                .iter()
                .any(|r| r.bank == PmgrBank::Performance)
        );
    }

    #[test]
    fn known_bridge_references_are_validated_even_when_native_layout_is_unqualified() {
        let one = 1u32.to_le_bytes();
        let three = 3u32.to_le_bytes();
        let index = 0u32.to_le_bytes();
        let group = direct_performance_group();
        let mut dependency = [0; 76];
        dependency[4] = 1; // Outside the one-bank source table.
        for (header, dependencies, valid) in [
            ([0, 0, 0, 0], &[][..], true),
            ([0, 0, 0, 1], &[][..], false),
            ([0, 0, 0, 0], &dependency[..], false),
        ] {
            let bytes = optional_fixture(
                &group,
                &[
                    ("bridge-reg-index", &index),
                    ("#bridges", &one),
                    ("bridge-settings-version", &one),
                    ("bridge-counter-version", &three),
                    ("bridge-counters", &header),
                    ("device-bridges", dependencies),
                ],
            );
            let io = Node::root(&bytes).unwrap();
            let result = pmgr_registers(&io, &|address, _| Some(address), 0x8103);
            if valid {
                let parsed = result.unwrap();
                assert!(parsed.bridges.is_empty());
                assert!(parsed.refusals.iter().any(|r| r.bank == PmgrBank::Bridges));
                assert_eq!(parsed.performance.len(), 1);
            } else {
                assert!(result.is_err());
            }
        }
    }

    #[test]
    fn unsupported_performance_semantics_are_named_without_a_register_model() {
        let mut group = direct_performance_group();
        group[12] = 1;
        let bytes = optional_fixture(&group, &[]);
        let io = Node::root(&bytes).unwrap();
        let parsed = pmgr_registers(&io, &|address, _| Some(address), 0x8103).unwrap();
        assert!(parsed.performance.is_empty());
        assert_eq!(
            parsed
                .refusals
                .iter()
                .filter(|r| r.bank == PmgrBank::Performance)
                .count(),
            1
        );
    }

    #[test]
    fn malformed_advertised_records_are_fatal_even_beside_an_unsupported_bank() {
        for (name, malformed) in [
            ("hw-dpe-reg", alloc::vec![0; 39]),
            ("events", alloc::vec![0; 23]),
            ("bridge-counters", alloc::vec![0; 3]),
            ("device-bridges", alloc::vec![0; 75]),
            ("bridge-reg-index", alloc::vec![0; 3]),
        ] {
            let mut group = direct_performance_group();
            group[12] = 1;
            let bytes = optional_fixture(&group, &[(name, &malformed)]);
            let io = Node::root(&bytes).unwrap();
            assert!(
                pmgr_registers(&io, &|address, _| Some(address), 0x8103).is_err(),
                "{name}"
            );
        }
        let group = direct_performance_group();
        let bytes = optional_fixture(&group[..15], &[]);
        let io = Node::root(&bytes).unwrap();
        assert!(pmgr_registers(&io, &|address, _| Some(address), 0x8103).is_err());
    }

    #[test]
    fn performance_bank_capacity_is_independent_of_byte_sized_source_selectors() {
        use stela_contracts::adt::encode;
        let mut group = direct_performance_group();
        group[8..10].copy_from_slice(&306u16.to_le_bytes());
        let mut source = [0; PMGR_DEVICE];
        source[0] = 0x20;
        source[8] = 255;
        let bytes = encode(
            &[
                ("name", b"pmgr"),
                ("perf-regs", &group),
                ("devices", &source),
            ],
            &[],
        );
        let node = Node::root(&bytes).unwrap();
        let banks = performance_banks(&node, &[Some((0x1000, 0x10000))]).unwrap();
        assert_eq!(banks[0].selectors, [255]);
    }

    #[test]
    fn a_supported_family_with_an_invalid_register_reference_is_not_degraded() {
        let mut group = direct_performance_group();
        group[..4].copy_from_slice(&1u32.to_le_bytes());
        let bytes = optional_fixture(&group, &[]);
        let io = Node::root(&bytes).unwrap();
        assert!(pmgr_registers(&io, &|address, _| Some(address), 0x8103).is_err());
        let bytes = optional_fixture(&direct_performance_group(), &[]);
        let io = Node::root(&bytes).unwrap();
        assert!(pmgr_registers(&io, &|_, _| None, 0x8103).is_err());
    }

    #[test]
    fn special_acc_events_use_the_dt_selector_and_cluster_type() {
        use stela_contracts::adt::encode;
        let mut e = [0u8; 24];
        e[2] = 2;
        e[6] = 12;
        let mut p = [0u8; 24];
        p[2] = 7;
        p[6] = 24;
        let data = [e, p].concat();
        let tree = encode(&[("events", &data)], &[]);
        assert_eq!(
            acc_events(&Node::root(&tree).unwrap(), 2).unwrap(),
            vec![vec![12], vec![24]]
        );
        assert!(acc_events(&Node::root(&tree).unwrap(), 1).is_err());
        p[6] = 27;
        let tree = encode(&[("events", &p)], &[]);
        assert!(acc_events(&Node::root(&tree).unwrap(), 2).is_err());
    }

    #[test]
    fn bridge_headers_configs_axi_and_dependencies_place_the_translated_window() {
        use stela_contracts::adt::encode;
        let cells = |v: &[u32]| v.iter().flat_map(|x| x.to_le_bytes()).collect::<Vec<_>>();
        let mut config = [0u8; 36];
        config[1] = 7;
        let mut dependency = [0u8; 76];
        dependency[3] = 9;
        let tree = encode(
            &[
                ("bridge-reg-index", &cells(&[1])),
                ("#bridges", &cells(&[1])),
                ("bridge-settings-version", &cells(&[1])),
                ("bridge-counter-version", &cells(&[3])),
                ("bridge-counters", &[0, 0x80, 0, 1]),
                ("bridge-counter-configs", &config),
                ("axi2af-axi-config", &[0, 0x20, 0x18, 8]),
                ("device-bridges", &dependency),
            ],
            &[],
        );
        let n = Node::root(&tree).unwrap();
        let fields: &[&[(u64, u32)]] = &[&[(0, 0x103)]];
        let banks =
            place_bridges(&n, &[None, Some((0x6_8c00_0000, 0x1000000))], Some(fields)).unwrap();
        assert_eq!(banks[0].physical, 0x6_8c00_0000);
        assert_eq!(banks[0].devices, vec![9]);
        assert_eq!(banks[0].configs, vec![config]);
        assert_eq!(banks[0].axi, Some([0, 0x20, 0x18, 8]));
        assert!(place_bridges(&n, &[None, Some((0, 0x100))], Some(fields)).is_err());
        assert!(place_bridges(&n, &[None], Some(fields)).is_err());
        assert!(place_bridges(&n, &[], None).is_err());
    }

    #[test]
    fn soc_dpe_samples_are_absolute_and_checked_against_the_selected_dt_bank() {
        use stela_contracts::adt::encode;
        let mut sample = [0u8; 40];
        sample[..8].copy_from_slice(&0x5_0000_2708u64.to_le_bytes());
        sample[16..24].copy_from_slice(&[0x1d, 0, 1, 0, 1, 1, 1, 64]);
        let tree = encode(&[("hw-dpe-reg", &sample)], &[]);
        let node = Node::root(&tree).unwrap();
        let bank = place_soc_dpe(&node, &[Some((0x5_0000_0000, 0x8000))], 0).unwrap();
        assert_eq!(bank.samples, vec![(0x2708, true)]);
        assert_eq!(bank.physical, 0x5_0000_0000);
        assert!(place_soc_dpe(&node, &[Some((0, 0x8000))], 0).is_err());
        assert!(place_soc_dpe(&node, &[Some((0x5_0000_0000, 0x3000))], 0).is_err());
    }

    #[test]
    fn soc_power_roles_use_dt_ranges_and_refuse_short_or_overflowed_ranges() {
        let kinds = [
            stela_soc_data::power::Kind::Volman,
            stela_soc_data::power::Kind::Marker,
            stela_soc_data::power::Kind::Gpce,
            stela_soc_data::power::Kind::Gating,
            stela_soc_data::power::Kind::Tvm,
        ];
        for kind in kinds {
            let reg = [None, Some((0x5_0000_0000, 0x20000))];
            assert_eq!(
                place_power_banks(&reg, &[(1, kind)]).unwrap(),
                vec![PowerBank {
                    physical: 0x5_0000_0000,
                    kind
                }]
            );
            assert!(place_power_banks(&[None], &[(1, kind)]).is_err());
            assert!(place_power_banks(&[Some((0, 0))], &[(0, kind)]).is_err());
            assert!(place_power_banks(&[Some((u64::MAX - 3, 0x20000))], &[(0, kind)]).is_err());
        }
    }

    #[test]
    fn wake_masks_derive_the_bank_and_validate_dt_sources_without_assuming_reset_masks() {
        use stela_contracts::adt::encode;
        let layout = SOCS
            .iter()
            .find(|soc| soc.chip_id == 0x8112)
            .unwrap()
            .wake_masks
            .unwrap();
        let mut reg = [None; 5];
        reg[4] = Some((0x2_3d00_4000, 0x1000));
        let named = |id: u32, name: &[u8]| {
            let mut entry = [0u8; 36];
            entry[..4].copy_from_slice(&id.to_le_bytes());
            entry[4..4 + name.len()].copy_from_slice(name);
            entry
        };
        let source = |id: u32| named(id, b"");
        let records = [source(14), source(157)].concat();
        let tree = encode(&[("ap-wake-sources", &records)], &[]);
        let found = wake_bank(&Node::root(&tree).unwrap(), &reg, layout).unwrap();
        assert_eq!(
            found,
            WakeBank {
                physical: 0x2_3d00_4008,
                valid: layout.valid,
                sources: vec![14, 157],
                smc_wake: None,
            }
        );
        // J473AP names the SMC's wake of the AP source 81.
        let records = [named(14, b"AOP.GPIO.IRQ6"), named(81, b"SMC.CPUWakeupAP")].concat();
        let tree = encode(&[("ap-wake-sources", &records)], &[]);
        let found = wake_bank(&Node::root(&tree).unwrap(), &reg, layout).unwrap();
        assert_eq!(found.smc_wake, Some(81));
        reg[4] = Some((0x5_0000_0000, 0x1000));
        assert_eq!(
            wake_bank(&Node::root(&tree).unwrap(), &reg, layout)
                .unwrap()
                .physical,
            0x5_0000_0008
        );
        for invalid in [
            source(255).to_vec(),
            source(256).to_vec(),
            [source(14), source(14)].concat(),
            records[..35].to_vec(),
        ] {
            let tree = encode(&[("ap-wake-sources", &invalid)], &[]);
            assert!(wake_bank(&Node::root(&tree).unwrap(), &reg, layout).is_err());
        }
        reg[4] = Some((0, wake::OFFSET + wake::BYTES - 1));
        assert!(wake_bank(&Node::root(&tree).unwrap(), &reg, layout).is_err());
        reg[4] = Some((u64::MAX - wake::OFFSET, 0x1000));
        assert!(wake_bank(&Node::root(&tree).unwrap(), &reg, layout).is_err());
        reg[4] = None;
        assert!(wake_bank(&Node::root(&tree).unwrap(), &reg, layout).is_err());
    }

    #[test]
    fn perf_groups_derive_sparse_selectors_from_each_dt_record_kind() {
        use stela_contracts::adt::encode;
        let group = |index: u32, offset: u32, count: u16, class: u8| {
            let mut entry = [0u8; 16];
            entry[..4].copy_from_slice(&index.to_le_bytes());
            entry[4..8].copy_from_slice(&offset.to_le_bytes());
            entry[8..10].copy_from_slice(&count.to_le_bytes());
            entry[12] = class;
            entry
        };
        let mut device = [0u8; PMGR_DEVICE];
        device[0] = 0x20;
        device[8] = 9;
        device[9] = 0;
        let source = |bytes: &[u8]| {
            let mut entry = [0u8; 24];
            entry[..bytes.len()].copy_from_slice(bytes);
            entry
        };
        let groups = [
            group(1, 0x34000, 256, 3),
            group(0, 0x58000, 256, 0),
            group(0, 0x78000, 12, 0),
        ]
        .concat();
        let clocks = [source(&[24, 0, 1]), source(&[25, 0, 0])].concat();
        let domains = [source(&[0, 31, 0]), source(&[0, 0, 0])].concat();
        let events = [
            source(&[0, 0, 1, 80, 41, 0, 40, 0]),
            source(&[15, 0, 5, 52, 1, 2, 0, 2]),
            source(&[0, 0, 0, 1, 0, 0, 120, 1]),
            source(&[0, 0, 2, 96, 0, 0, 0, 0]),
            source(&[0, 0, 7, 101, 0, 0, 12, 0]),
            source(&[0, 1, 0, 128, 0, 0, 50, 1]),
        ]
        .concat();
        let tree = |groups: &[u8], clocks: &[u8]| {
            encode(
                &[
                    ("perf-regs", groups),
                    ("devices", &device),
                    ("clocks", clocks),
                    ("power-domains", &domains),
                    ("events", &events),
                ],
                &[],
            )
        };
        let reg = [
            Some((0x2_3b70_0000, 0xcc000)),
            Some((0x2_3d28_0000, 0x7c000)),
        ];
        let data = tree(&groups, &clocks);
        let node = Node::root(&data).unwrap();
        assert_eq!(
            performance_banks(&node, &reg).unwrap(),
            vec![
                PerfBank {
                    physical: 0x2_3d2b_4000,
                    selectors: vec![9, 24, 31, 40, 41]
                },
                PerfBank {
                    physical: 0x2_3b75_8000,
                    selectors: vec![120]
                },
                PerfBank {
                    physical: 0x2_3b77_8000,
                    selectors: vec![0, 1]
                },
            ]
        );
        for invalid in [
            groups[..47].to_vec(),
            {
                let mut bad = groups.clone();
                bad[13] = 2;
                bad
            },
            {
                let mut bad = groups.clone();
                bad[15] = 2;
                bad
            },
            {
                let mut bad = groups.clone();
                bad[12] = 1;
                bad
            },
            {
                let mut bad = groups.clone();
                bad[..4].copy_from_slice(&3u32.to_le_bytes());
                bad
            },
        ] {
            let data = tree(&invalid, &clocks);
            assert!(performance_banks(&Node::root(&data).unwrap(), &reg).is_err());
        }
        for invalid in [
            clocks[..47].to_vec(),
            source(&[12, 2, 1]).to_vec(),
            source(&[0, 3, 1]).to_vec(),
        ] {
            let data = tree(&groups, &invalid);
            assert!(performance_banks(&Node::root(&data).unwrap(), &reg).is_err());
        }
        assert!(performance_banks(&node, &[Some((0, 0x100)), reg[1]]).is_err());
        assert!(performance_banks(&node, &[Some((u64::MAX - 0x58000, 0xcc000)), reg[1]]).is_err());
        let relocated = [
            Some((0x5_0000_0000, 0xcc000)),
            Some((0x6_0000_0000, 0x7c000)),
        ];
        let placed = performance_banks(&node, &relocated).unwrap();
        assert_eq!(placed[0].physical, 0x6_0003_4000);
        assert_eq!(placed[1].physical, 0x5_0005_8000);
    }

    #[test]
    fn cpu_start_registers_follow_the_pmgr_node_with_registers() {
        use stela_contracts::adt::encode;
        let z = |text: &str| [text.as_bytes(), &[0]].concat();
        let reg = |base: u64, bytes: u64| [base.to_le_bytes(), bytes.to_le_bytes()].concat();
        let io = |pmgr: &str, pmgr_reg: Option<(u64, u64)>, child: Option<(u64, u64)>| {
            let (name, compatible) = (z("pmgr"), z(pmgr));
            let pmgr_reg = pmgr_reg.map(|(base, bytes)| reg(base, bytes));
            let mut properties: Vec<(&str, &[u8])> =
                vec![("name", &name), ("compatible", &compatible)];
            if let Some(pmgr_reg) = &pmgr_reg {
                properties.push(("reg", pmgr_reg));
            }
            let mut children = vec![encode(&properties, &[])];
            if let Some((base, bytes)) = child {
                children.push(encode(
                    &[
                        ("name", &z("pmgr-child")),
                        ("compatible", &z("pmgr2,t8152")),
                        ("reg", &reg(base, bytes)),
                    ],
                    &[],
                ));
            }
            let io = encode(&[("name", &z("arm-io"))], &children);
            encode(&[("name", &z("device-tree"))], &[io])
        };
        let place = |tree: &[u8], chip_id, clusters: &[u64]| {
            let processors: Vec<Identity> = clusters
                .iter()
                .map(|&cluster| Identity {
                    midr: 0,
                    mpidr: 0x8000_0000 | cluster << 8,
                    clock: None,
                    caches: None,
                })
                .collect();
            let root = Node::root(tree).unwrap();
            let io = root.child("arm-io").unwrap();
            let translate = |address: u64, _| Some(address + 0x2_0000_0000);
            cpu_start(&io, &translate, chip_id, &processors)
        };
        let m6 = io("pmgr2,arch", None, Some((0x1_0070_0000, 0xd0000)));
        assert_eq!(place(&m6, 0x8152, &[0, 1]), Ok(Some((0x3_0073_4000, 2))));
        assert_eq!(
            place(&io("pmgr2,arch", None, None), 0x8152, &[0, 1]),
            Err("/arm-io/pmgr is pmgr2,arch without /arm-io/pmgr-child".into())
        );
        let short = io("pmgr2,arch", None, Some((0x1_0070_0000, 0x34008)));
        assert_eq!(
            place(&short, 0x8152, &[0, 1]),
            Err("/arm-io/pmgr-child reg[0] does not hold the CPU start registers".into())
        );
        // An M3 (J613AP `reg[0]` 0xc070_0000 for 0xcc000 bytes) without a
        // modeled PMGR still has its CPU start registers.
        let m3 = io("pmgr1,t8122", Some((0xc070_0000, 0xcc000)), None);
        assert_eq!(place(&m3, 0x8122, &[0, 1]), Ok(Some((0x2_c073_4000, 2))));
        // Another SoC's PMGR is not the row's.
        assert_eq!(place(&m3, 0x8132, &[0, 1]), Ok(None));
    }
}
