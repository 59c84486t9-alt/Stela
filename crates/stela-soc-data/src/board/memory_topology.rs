//! DeviceTree placement and validation for memory topology.
use super::MCC;
use super::Node;
use super::SOCS;
use super::String;
use super::Vec;
use super::apertures;
use super::format;
use super::memory_resources;

/// An `mcc,t8112`: its cache in the AMCC aperture, its DRAM channels and
/// the PMP PTD bank it writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryCache {
    pub cache: crate::amcc::Cache,
    /// The DCS channels (`reg[2]`) in guest PA: base, bytes and the
    /// `dcs_num_channels` that share them evenly.
    pub channels: (u64, u64, usize),
    /// The PMP's PTD bank, `reg[pmp_ptd_reg_idx]`.
    pub ptd: PtdBank,
    /// The PMP's actual 8-byte update alias, not the whole half-bank.
    pub ptd_updates: (u64, u64),
    /// Addressable capacity shared by publication, updates and interrupt routing.
    /// This is not the native firmware's implemented entry count. An actual
    /// native constructor must also validate its source-qualified profile.
    pub ptd_entries: usize,
}

/// The PMP's PTD bank (`platform::apple::ptd`): its guest PA and the
/// `ptd-range` records of `/arm-io/pmp/iop-pmp-nub`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PtdBank {
    pub physical: u64,
    pub ranges: Vec<crate::ptd::Range>,
    /// Original fourth word, in exactly the same order as ranges. Not AIC IDs.
    pub interrupts: Vec<u32>,
}

/// A `ptd-range` record's bytes: id, first entry, entries, interrupt and a
/// 16-byte name.
pub(super) const PTD_RANGE: usize = 32;

/// The AMCC as `/chosen/lock-regs/amcc` describes it: its apertures and
/// each aperture's planes and lock registers (`platform::apple::amcc`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryController {
    pub apertures: Vec<u64>,
    pub layout: crate::amcc::Layout,
}

/// The property iBoot's AMCC map always states.
const APERTURE_COUNT: &str = "aperture-count";

/// A `<name>-reg-offset`, `-reg-mask` and, for a bit register,
/// `-reg-value` triple.
fn lock_register(
    node: &Node<'_>,
    path: &str,
    name: &str,
    bit: bool,
) -> Result<crate::amcc::Register, String> {
    let field = |suffix: &str| {
        node.first_u32(&format!("{name}-reg-{suffix}"))
            .ok_or_else(|| format!("{path} has no {name}-reg-{suffix}"))
    };
    let mask = field("mask")?;
    let value = if bit { field("value")? } else { 0 };
    if value & !mask != 0 {
        return Err(format!("{path} {name}-reg-value has bits outside its mask"));
    }
    Ok(crate::amcc::Register {
        offset: u64::from(field("offset")?),
        mask,
        value,
    })
}

fn lock_register_optional(
    node: &Node<'_>,
    path: &str,
    name: &str,
) -> Result<Option<crate::amcc::Register>, String> {
    let present = ["offset", "mask", "value"]
        .iter()
        .any(|suffix| node.property(&format!("{name}-reg-{suffix}")).is_some());
    present
        .then(|| lock_register(node, path, name, true))
        .transpose()
}

/// The lock group at `path` (a child of `node`), or `None` for a template
/// node iBoot left empty (no `page-size-shift`) or none at all.
fn lock_group(node: &Node<'_>, path: &str) -> Result<Option<crate::amcc::LockGroup>, String> {
    let name = path.rsplit('/').next().unwrap_or(path);
    let Some(group) = node.child(name) else {
        return Ok(None);
    };
    let Some(page_size_shift) = group.first_u32("page-size-shift") else {
        return Ok(None);
    };
    let register = |name: &str, bit: bool| lock_register(&group, path, name, bit);
    let optional_register = |name: &str| lock_register_optional(&group, path, name);
    Ok(Some(crate::amcc::LockGroup {
        page_size_shift,
        lower_limit: register("lower-limit", false)?,
        upper_limit: register("upper-limit", false)?,
        enable: optional_register("enable")?,
        write_disable: optional_register("write-disable")?,
        lock: optional_register("lock")?,
    }))
}

pub(super) fn memory_controller(chosen: &Node<'_>) -> Result<Option<MemoryController>, String> {
    memory_controller_named(chosen, "amcc")
}

/// The AMCC map of `/chosen/lock-regs/amcc`, or `None` without one. The
/// IPSW templates carry the node and its group children empty; a node the
/// boot chain left so (no `aperture-count`, on a SoC whose iBoot map the
/// loader lacks, `stela_loader::lock_regs`) describes no controller, and
/// SPTM's own `ctrr_dt_get_lock_group` stops on it.
pub(super) fn memory_controller_named(
    chosen: &Node<'_>,
    controller: &str,
) -> Result<Option<MemoryController>, String> {
    let Some(node) = chosen
        .child("lock-regs")
        .and_then(|regs| regs.child(controller))
        .filter(|node| node.property(APERTURE_COUNT).is_some())
    else {
        return Ok(None);
    };
    let path = format!("/chosen/lock-regs/{controller}");
    let number = |name: &str| {
        node.first_u32(name)
            .ok_or_else(|| format!("{path} has no {name}"))
    };
    let count = number(APERTURE_COUNT)? as usize;
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
    if count == 0
        || apertures.len() != count
        || node
            .property("aperture-phys-addr")
            .is_none_or(|bytes| bytes.len() != count * 8)
    {
        return Err(format!(
            "{path} aperture-phys-addr does not list aperture-count apertures"
        ));
    }
    if node.child(&format!("{controller}-ctrr-a")).is_none() {
        return Err(format!("missing lock group {path}/{controller}-ctrr-a"));
    }
    let mut groups = [None; crate::amcc::GROUPS];
    for (group, suffix) in groups.iter_mut().zip(["a", "b", "c", "d"]) {
        *group = lock_group(&node, &format!("{path}/{controller}-ctrr-{suffix}"))?;
    }
    if groups[0].is_none() {
        return Err(format!("{path}/{controller}-ctrr-a has no page-size-shift"));
    }
    let dram_base = chosen
        .property("dram-base")
        .and_then(|value| {
            value
                .first_chunk::<8>()
                .map(|cell| u64::from_le_bytes(*cell))
        })
        .ok_or("/chosen has no dram-base")?;
    let layout = crate::amcc::Layout {
        aperture_bytes: u64::from(number("aperture-size")?),
        planes: number("plane-count")?,
        stride: u64::from(number("plane-stride")?),
        cache_status: if controller == "amcc" {
            Some(lock_register(&node, &path, "cache-status", true)?)
        } else {
            lock_register_optional(&node, &path, "cache-status")?
        },
        groups,
        // SPTM normalizes IOA absolute page limits by subtracting the
        // DRAM page base (T6000 26A434 VA 0xfffffff0270d7748..d777c).
        dram_base: if controller == "ioa" { 0 } else { dram_base },
    };
    if layout.aperture_bytes == 0 || (layout.stride == 0 && layout.planes != 1) {
        return Err(format!("{path} has an empty aperture or plane stride"));
    }
    Ok(Some(MemoryController { apertures, layout }))
}

/// `/arm-io/mcc`, if it is a modeled memory cache controller. Its planes
/// (`reg[1]`) are the lock-regs planes of the one AMCC aperture, which also
/// holds its shared registers (`reg[0]`) and broadcast window (`reg[3]`);
/// its PTD slot (`reg[pmp_ptd_reg_idx]` plus `pmp_ptd_update_space_offset`)
/// lies in the PMP's PTD update registers.
pub(super) fn memory_cache(
    io: &Node<'_>,
    translate: &dyn Fn(u64, u64) -> Option<u64>,
    chip_id: u32,
    controller: Option<&MemoryController>,
) -> Result<Option<MemoryCache>, String> {
    let Some(node) = io.child("mcc").filter(|node| node.compatible(MCC)) else {
        return Ok(None);
    };
    const PATH: &str = "/arm-io/mcc";
    let controller =
        controller.ok_or_else(|| format!("{PATH} has no /chosen/lock-regs/amcc aperture"))?;
    let [aperture] = controller.apertures[..] else {
        return Err(format!(
            "{PATH} behind several AMCC apertures is not modeled"
        ));
    };
    let layout = &controller.layout;
    let (bytes, ways) = SOCS
        .iter()
        .find(|soc| soc.chip_id == chip_id)
        .and_then(|soc| soc.memory_cache)
        .ok_or_else(|| format!("ApChipID {chip_id:#x} has no memory cache geometry"))?;
    let range = |owner: &Node<'_>, path: &str, index: usize| -> Result<(u64, u64), String> {
        apertures::registers(owner)
            .unwrap_or_default()
            .get(index)
            .and_then(|&(offset, bytes)| Some((translate(offset, bytes)?, bytes)))
            .ok_or_else(|| format!("{path} reg[{index}] is missing or outside /arm-io ranges"))
    };
    let in_aperture = |index: usize| -> Result<(u64, u64), String> {
        let (physical, bytes) = range(&node, PATH, index)?;
        physical
            .checked_sub(aperture)
            .filter(|&offset| offset < layout.aperture_bytes)
            .map(|offset| (offset, bytes))
            .ok_or_else(|| format!("{PATH} reg[{index}] is outside the AMCC aperture"))
    };
    if in_aperture(1)? != (0, layout.stride * u64::from(layout.planes)) {
        return Err(format!("{PATH} reg[1] is not the lock-regs planes"));
    }
    let channels = range(&node, PATH, 2)?;
    let count = node
        .first_u32("dcs_num_channels")
        .filter(|&count| count != 0 && channels.1 % u64::from(count) == 0)
        .ok_or_else(|| format!("{PATH} dcs_num_channels does not divide reg[2]"))?;
    let number = |name: &str| {
        node.first_u32(name)
            .ok_or_else(|| format!("{PATH} has no {name}"))
    };
    let bank = range(&node, PATH, number("pmp_ptd_reg_idx")? as usize)?;
    if bank.1 != crate::ptd::PTD_BYTES
        || u64::from(number("pmp_ptd_update_space_offset")?) != crate::ptd::UPDATE_OFFSET
    {
        return Err(format!("{PATH} PTD registers are not one PTD bank"));
    }
    let pmp = io
        .child("pmp")
        .ok_or_else(|| format!("{PATH} names PTD registers but there is no /arm-io/pmp"))?;
    let index = pmp
        .first_u32("ptd-update-reg-index")
        .ok_or("/arm-io/pmp has no ptd-update-reg-index")?;
    let updates = range(&pmp, "/arm-io/pmp", index as usize)?;
    let geometry = crate::ptd::Geometry::new(bank, updates).map_err(String::from)?;
    let records = pmp
        .child("iop-pmp-nub")
        .and_then(|nub| nub.property("ptd-range"))
        .filter(|records| !records.is_empty() && records.len() % PTD_RANGE == 0)
        .ok_or("/arm-io/pmp/iop-pmp-nub has no whole ptd-range records")?;
    let (ranges, interrupts) = memory_resources::publication_ranges(records, geometry.entries())?;
    let ptd = PtdBank {
        physical: bank.0,
        ranges,
        interrupts,
    };
    Ok(Some(MemoryCache {
        cache: crate::amcc::Cache {
            shared: in_aperture(0)?,
            broadcast: in_aperture(3)?.0,
            bytes,
            ways,
        },
        channels: (channels.0, channels.1, count as usize),
        ptd,
        ptd_updates: geometry.updates(),
        ptd_entries: geometry.entries(),
    }))
}

#[cfg(test)]
mod tests;
