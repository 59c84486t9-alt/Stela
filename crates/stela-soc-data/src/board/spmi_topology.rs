//! DeviceTree placement and validation for spmi topology.
use super::ASC;
use super::Node;
use super::PMU;
use super::SPMI;
use super::Vec;
use super::apertures;
use super::rtbuddy_nub;
use super::smc;
use crate::Result;
use stela_contracts::refuse;

/// A Dialog PMU's slave ID and the register windows its `info-*`
/// properties name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpmiPmu {
    pub sid: u8,
    /// Original is-primary controls global RTC service ownership, not register presence.
    pub primary: bool,
    /// PMU output's local edge vector, independently of the response vector.
    pub interrupt: Option<u16>,
    pub mailbox: Option<FirmwareMailbox>,
    pub alarm_monitor: u8,
    pub rtc_helper: Option<smc::RtcKeyProfile>,
    pub identity: Option<crate::pmu::Window>,
    /// Outside-scratch log, requiring explicit cold/kept history at placement.
    pub fault_log: Option<crate::pmu::Window>,
    /// Outside-scratch off-to-wake source, likewise.
    pub wake_source: Option<crate::pmu::Window>,
    pub windows: Vec<crate::pmu::Window>,
    pub rtc: Option<crate::pmu::Rtc>,
}

/// A PMIC firmware mailbox (`fw-mcom-address`, `fw-host-irq-address` and, on
/// M4 and later, `fw-mcom-int-index`), served by PMIC firmware that does not
/// execute: its registers are unchecked and its vector is never driven,
/// so it stays unrouted (`crate::pmu::Configuration::with_unqualified_firmware_mailbox`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirmwareMailbox {
    pub registers: u16,
    pub doorbell: u16,
    pub vector: Option<u16>,
}

impl SpmiPmu {
    /// This PMU's register owners, with `history`'s initial bytes for each
    /// kept-history owner.
    pub fn configuration(
        &self,
        mut history: impl FnMut(crate::pmu::Retained, crate::pmu::Window) -> Result<Vec<u8>>,
    ) -> Result<crate::pmu::Configuration> {
        let mut configuration =
            crate::pmu::Configuration::new(self.windows.clone(), self.rtc, self.alarm_monitor)?;
        for (kind, window) in self.retained() {
            configuration = configuration.with_retained(kind, window, history(kind, window)?)?;
        }
        if let Some(identity) = self.identity {
            configuration = configuration.with_unqualified_identity(identity)?;
        }
        if let Some(mailbox) = self.mailbox {
            configuration = configuration
                .with_unqualified_firmware_mailbox(mailbox.registers, mailbox.doorbell)?;
        }
        Ok(configuration)
    }

    /// The kept-history owners whose initial bytes placement supplies.
    pub fn retained(
        &self,
    ) -> impl Iterator<Item = (crate::pmu::Retained, crate::pmu::Window)> + use<> {
        let fault = self
            .fault_log
            .map(|log| (crate::pmu::Retained::FaultLog, log));
        let wake = self
            .wake_source
            .map(|source| (crate::pmu::Retained::WakeSource, source));
        fault.into_iter().chain(wake)
    }
}

use crate::spmi::Configuration;

/// A source-checked SPMI controller with independent FIFO/vector geometry.
/// `bank_c` is `reg[2]`: Gen1's optional fault-counter view or the Gen3 and
/// Gen4 arbiter bank.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpmiController {
    pub configuration: Configuration,
    pub bank_c: Option<(u64, u64)>,
    pub banks: [(u64, u64); 2],
    pub irq: u32,
    pub pmus: Vec<SpmiPmu>,
}

/// Every visible `aapl,spmi` controller under `/arm-io`. The `interrupts`
/// cells pair with `interrupt-parent` entries in order, the last parent
/// covering the remaining cells; the one whose parent is the AIC is the
/// controller's line, the others its own vectors.
pub(super) fn spmi_controllers(
    io: &Node<'_>,
    translate: &dyn Fn(u64, u64) -> Option<u64>,
    aic: u32,
) -> Result<Vec<SpmiController>> {
    let mut controllers = Vec::new();
    for node in io
        .children()
        .ok_or(refuse!("/arm-io children are malformed"))?
    {
        if !node.compatible(SPMI) {
            continue;
        }
        if node.property("gen").is_none_or(|bytes| bytes.len() != 4) {
            return Err(refuse!("SPMI generation is not one full32 word"));
        }
        let profile = match node.first_u32("gen") {
            Some(1) => crate::spmi::Profile::Gen1,
            Some(2) => crate::spmi::Profile::Gen2,
            Some(3) => crate::spmi::Profile::Gen3,
            Some(4) => crate::spmi::Profile::Gen4,
            _ => return Err(refuse!("SPMI controller generation is unqualified")),
        };
        let regs = apertures::registers(&node).ok_or(refuse!("SPMI controller has no reg"))?;
        if node
            .property("reg")
            .is_none_or(|bytes| bytes.len() != regs.len() * 16)
        {
            return Err(refuse!("SPMI controller has partial reg pairs"));
        }
        let bank = |index: usize| -> Result<(u64, u64)> {
            let &(offset, bytes) = regs
                .get(index)
                .filter(|(_, bytes)| *bytes == profile.bank_bytes())
                .ok_or(refuse!(
                    "SPMI controller banks do not match the qualified handler geometry"
                ))?;
            let physical =
                translate(offset, bytes).ok_or(refuse!("SPMI bank outside arm-io ranges"))?;
            if !physical.is_multiple_of(4) {
                return Err(refuse!("SPMI bank is unaligned or crosses arm-io ranges"));
            }
            Ok((physical, bytes))
        };
        let parents = node
            .cells32("interrupt-parent")
            .ok_or(refuse!("SPMI controller has no interrupt-parent"))?;
        let cells = node
            .cells32("interrupts")
            .ok_or(refuse!("SPMI controller has no interrupts"))?;
        let irq = parents
            .iter()
            .position(|&parent| parent == aic)
            .and_then(|index| cells.get(index).copied())
            .ok_or(refuse!("SPMI controller has no AIC line"))?;
        let local = node
            .first_u32("AAPL,phandle")
            .ok_or(refuse!("SPMI has no phandle"))?;
        if node
            .property("AAPL,phandle")
            .is_none_or(|bytes| bytes.len() != 4)
            || node
                .property("interrupt-parent")
                .is_none_or(|bytes| bytes.len() != 12)
            || node
                .property("interrupts")
                .is_none_or(|bytes| !bytes.len().is_multiple_of(4))
            || parents.as_slice() != [local, aic, local]
            || cells.len() < 2
            || cells
                .iter()
                .enumerate()
                .any(|(index, &vector)| index != 1 && vector >= 288)
        {
            return Err(refuse!(
                "SPMI interrupt-parent/vector routing is unqualified"
            ));
        }
        let queue_bytes: [u32; 2] = node
            .cells32("queue-depth")
            .filter(|_| {
                node.property("queue-depth")
                    .is_some_and(|bytes| bytes.len() == 8)
            })
            .and_then(|cells| cells.try_into().ok())
            .ok_or(refuse!("SPMI has no two FIFO byte depths"))?;
        let configuration = crate::spmi::Configuration::new(profile, cells[0], queue_bytes)?;
        let counters = match node.property("fault-counters-enabled") {
            None => false,
            Some(bytes) if bytes.len() == 4 => match node.first_u32("fault-counters-enabled") {
                Some(0) => false,
                Some(1) => true,
                _ => return Err(refuse!("SPMI fault-counter enable encoding is unqualified")),
            },
            _ => return Err(refuse!("SPMI fault-counter enable is not one full32 word")),
        };
        let bank_c = if profile.arbiter_bank() {
            Some(bank(2)?)
        } else if counters && profile == crate::spmi::Profile::Gen1 {
            let &(offset, bytes) = regs
                .get(2)
                .filter(|(_, bytes)| Some(*bytes) == profile.counter_bytes())
                .ok_or(refuse!("SPMI Gen1 needs its separate fault-counter bank"))?;
            let physical = translate(offset, bytes)
                .ok_or(refuse!("SPMI fault counters outside arm-io ranges"))?;
            if !physical.is_multiple_of(4) {
                return Err(refuse!(
                    "SPMI fault counters are unaligned or cross arm-io ranges"
                ));
            }
            Some((physical, bytes))
        } else {
            None
        };
        let expected = if bank_c.is_some() { 3 } else { 2 };
        if regs.len() != expected {
            return Err(refuse!("SPMI has an unqualified extra register view"));
        }
        let mut pmus = Vec::new();
        for child in node
            .children()
            .ok_or(refuse!("SPMI children are malformed"))?
        {
            if child.compatible(PMU) {
                let pmu = spmi_pmu(&child, io)?;
                if (pmu.interrupt.is_some()
                    || pmu.mailbox.is_some_and(|mailbox| mailbox.vector.is_some()))
                    && (child
                        .property("interrupt-parent")
                        .is_none_or(|bytes| bytes.len() != 4)
                        || child.first_u32("interrupt-parent") != Some(local))
                {
                    return Err(refuse!(
                        "PMU output is not parented by its own SPMI controller"
                    ));
                }
                pmus.push(pmu);
            }
        }
        let mut vectors: Vec<u16> = pmus
            .iter()
            .flat_map(|pmu| {
                pmu.interrupt
                    .into_iter()
                    .chain(pmu.mailbox.and_then(|mailbox| mailbox.vector))
            })
            .collect();
        let routed = vectors.len();
        vectors.sort_unstable();
        vectors.dedup();
        if vectors.len() != routed
            || vectors
                .iter()
                .any(|&vector| u32::from(vector) == configuration.response_vector())
        {
            return Err(refuse!(
                "PMU interrupt vectors alias each other or the response"
            ));
        }
        controllers.push(SpmiController {
            configuration,
            bank_c,
            banks: [bank(0)?, bank(1)?],
            irq,
            pmus,
        });
    }
    if controllers
        .iter()
        .flat_map(|controller| &controller.pmus)
        .filter(|pmu| pmu.primary)
        .count()
        > 1
    {
        return Err(refuse!("multiple primary PMU system-service owners"));
    }
    Ok(controllers)
}

/// A PMU's slave ID (`reg` cell 0) and its `info-*` windows: pairs are
/// `<base bytes>`, single cells one byte, except the legacy scratchpad.
fn spmi_pmu(node: &Node<'_>, io: &Node<'_>) -> Result<SpmiPmu> {
    let sid = node
        .first_u32("reg")
        .and_then(|sid| u8::try_from(sid).ok())
        .filter(|&sid| sid <= 0xf)
        .ok_or(refuse!("PMU has no four-bit SPMI slave ID"))?;
    let primary = match node.property("is-primary") {
        None => false,
        Some(bytes) if bytes.len() == 4 => match node.first_u32("is-primary") {
            Some(0) => false,
            Some(1) => true,
            _ => return Err(refuse!("PMU primary-service encoding is unqualified")),
        },
        _ => return Err(refuse!("PMU is-primary is not one full32 word")),
    };
    // `interrupts` lists the PMU output and, at `fw-mcom-int-index` where
    // given, the PMIC firmware mailbox's vector (`pmu::Pmu`).
    let vectors = match node.property("interrupts") {
        None => Vec::new(),
        Some(bytes) if bytes.len() == 4 || bytes.len() == 8 => node
            .cells32("interrupts")
            .unwrap_or_default()
            .into_iter()
            .map(|vector| {
                u16::try_from(vector)
                    .ok()
                    .filter(|&vector| vector < 288)
                    .ok_or(refuse!(
                        "PMU local interrupt vector exceeds the SPMI input bank"
                    ))
            })
            .collect::<Result<Vec<_>, _>>()?,
        _ => return Err(refuse!("PMU interrupts are not one or two full32 vectors")),
    };
    let mailbox_index = match node.property("fw-mcom-int-index") {
        None => None,
        Some(bytes) if bytes.len() == 4 => node
            .first_u32("fw-mcom-int-index")
            .and_then(|index| usize::try_from(index).ok()),
        _ => return Err(refuse!("PMU fw-mcom-int-index is not one full32 word")),
    };
    let mailbox_vector = mailbox_index
        .map(|index| {
            vectors
                .get(index)
                .copied()
                .ok_or(refuse!("PMU firmware mailbox index names no interrupt"))
        })
        .transpose()?;
    let mut outputs = (0..vectors.len())
        .filter(|&index| Some(index) != mailbox_index)
        .map(|index| vectors[index]);
    let interrupt = outputs.next();
    if outputs.next().is_some() || (vectors.len() == 2 && vectors[0] == vectors[1]) {
        return Err(refuse!(
            "PMU interrupts are not one output and one firmware mailbox"
        ));
    }
    let address =
        |value: u32| u16::try_from(value).map_err(|_| refuse!("PMU address above 16 bits"));
    let pair = |name: &str| -> Result<Option<crate::pmu::Window>> {
        match node.cells32(name).as_deref() {
            None => Ok(None),
            Some(&[base, bytes]) if node.property(name).is_some_and(|value| value.len() == 8) => {
                Ok(Some(crate::pmu::Window {
                    base: address(base)?,
                    bytes: address(bytes)?,
                }))
            }
            Some(_) => Err(refuse!("PMU {name} is not <base bytes>", name)),
        }
    };
    let single = |name: &str| -> Result<Option<u16>> {
        if node.property(name).is_some_and(|bytes| bytes.len() != 4) {
            return Err(refuse!("PMU {name} is not one full32 word", name));
        }
        node.first_u32(name).map(address).transpose()
    };
    let scratch = pair("info-scrpad")?;
    let mut windows = Vec::new();
    windows.extend(scratch);
    windows.extend(pair("info-fault_shadow")?);
    // A byte-counted history (`_readFaultLog`, `_readOff2WakeSource`) is its
    // own owner outside scratch, and scratch storage inside it.
    let retained = |name: &str| -> Result<Option<crate::pmu::Window>> {
        let Some(log) = pair(name)? else {
            return Ok(None);
        };
        let end = u32::from(log.base) + u32::from(log.bytes);
        if log.bytes == 0 || log.bytes > u16::from(u8::MAX) || end > 0x10000 {
            return Err(refuse!(
                "PMU {name} count or extent exceeds the qualified byte-count resource",
                name
            ));
        }
        let Some(scratch) = scratch else {
            return Ok(Some(log));
        };
        let scratch_end = u32::from(scratch.base) + u32::from(scratch.bytes);
        if u32::from(log.base) < scratch_end && u32::from(scratch.base) < end {
            if log.base < scratch.base || end > scratch_end {
                return Err(refuse!(
                    "PMU {name} partially aliases scratch storage",
                    name
                ));
            }
            return Ok(None); // Same canonical scratch owner; original zero-clear form.
        }
        Ok(Some(log))
    };
    let fault_log = retained("info-fault_log")?;
    let wake_source = retained("info-off2wake_source")?;
    if let Some(base) = single("info-leg_scrpad")? {
        windows.push(crate::pmu::Window {
            base,
            bytes: crate::pmu::LEGACY_SCRATCH_BYTES,
        });
    }
    if let Some(base) = single("info-pm_setting")? {
        windows.push(crate::pmu::Window { base, bytes: 1 });
    }
    // The SOCD and LPM windows lie inside the scratchpad.
    let inside = |base: u16, bytes: u16| {
        windows.iter().any(|w| {
            base >= w.base
                && u32::from(base) + u32::from(bytes) <= u32::from(w.base) + u32::from(w.bytes)
        })
    };
    if let Some(socd) = pair("info-scrpad_socd")?
        && !inside(socd.base, socd.bytes)
    {
        return Err(refuse!("PMU SOCD scratchpad outside its scratchpad"));
    }
    for name in ["info-scrpad_lpm_log", "info-scrpad_lpm_ctrl"] {
        if let Some(base) = single(name)?
            && !inside(base, 1)
        {
            return Err(refuse!("PMU {name} outside its scratchpad", name));
        }
    }
    let rtc = match single("info-rtc")? {
        None => None,
        Some(upcount) => {
            let need = |name: &str| -> Result<u16> {
                single(name)?.ok_or_else(|| refuse!("PMU RTC has no {name}", name))
            };
            // Without `info-clock_offset` the driver keeps the offset in the
            // legacy scratchpad (`crate::pmu::ClockOffset::LegacyScratch`).
            let clock_offset = match pair("info-clock_offset")? {
                Some(window) if window.bytes == 6 => crate::pmu::ClockOffset::Register(window.base),
                Some(_) => return Err(refuse!("PMU RTC clock offset is not six bytes")),
                None => crate::pmu::ClockOffset::LegacyScratch(single("info-leg_scrpad")?.ok_or(
                    refuse!("PMU RTC has neither a clock offset nor a legacy scratchpad"),
                )?),
            };
            if node
                .property("info-rtc_alarm_ctrl_en_mask")
                .is_none_or(|bytes| bytes.len() != 4)
            {
                return Err(refuse!("PMU alarm enable mask is not one full32 word"));
            }
            let alarm_enable = node
                .first_u32("info-rtc_alarm_ctrl_en_mask")
                .and_then(|mask| u8::try_from(mask).ok())
                .ok_or(refuse!("PMU RTC has no alarm enable mask"))?;
            let bits = |name: &str| -> Result<Option<u8>> {
                if node.property(name).is_some_and(|bytes| bytes.len() != 4) {
                    return Err(refuse!("PMU {name} is not one full32 word", name));
                }
                node.first_u32(name)
                    .map(|mask| {
                        u8::try_from(mask).map_err(|_| refuse!("PMU {name} exceeds a byte", name))
                    })
                    .transpose()
            };
            Some(crate::pmu::Rtc {
                upcount,
                clock_offset,
                alarm_control: need("info-rtc_alarm_ctrl")?,
                alarm_enable,
                alarm_offset: need("info-rtc_alarm_offset")?,
                alarm_event: need("info-rtc_alarm_event")?,
                irq_mask: need("info-rtc_irq_mask_offset")?,
                event_mask: bits("info-rtc_alarm_event_mask")?
                    .unwrap_or(crate::pmu::DEFAULT_EVENT_MASK),
                interrupt_mask: bits("info-rtc_alarm_mask")?
                    .ok_or(refuse!("PMU RTC has no info-rtc_alarm_mask"))?,
            })
        }
    };
    let alarm_monitor = if rtc.is_some() {
        single("info-rtc_alarm_monitor_mask")?
            .and_then(|mask| u8::try_from(mask).ok())
            .ok_or(refuse!("PMU RTC has no byte monitor mask"))?
    } else {
        0
    };
    // The primary's alarm is the board's RTC wake source. An output alone
    // needs no RTC: without one it stays deasserted (`pmu::Pmu`).
    if primary && rtc.is_none() {
        return Err(refuse!(
            "PMU primary system service requires a qualified RTC owner"
        ));
    }
    let rtc_helper = match node.property("function-rtc_read_helper") {
        None => None,
        Some(bytes) => {
            if !primary || rtc.is_none() || bytes.len() != 12 {
                return Err(refuse!(
                    "RTC helper requires a primary RTC and complete three-cell descriptor"
                ));
            }
            let source = io
                .child("smc")
                .filter(|node| {
                    node.compatible(ASC) && node.property("role") == Some(b"SMC\0".as_slice())
                })
                .ok_or(refuse!("RTC helper has no qualified visible SMC provider"))?;
            let nub = rtbuddy_nub(&source, "SMC")?;
            let provider = nub
                .child("smc-pmu")
                .ok_or(refuse!("RTC helper has no SMC PMU provider"))?;
            if provider
                .property("AAPL,phandle")
                .is_none_or(|bytes| bytes.len() != 4)
            {
                return Err(refuse!("SMC PMU provider phandle is not one full32 word"));
            }
            let provider = provider
                .first_u32("AAPL,phandle")
                .ok_or(refuse!("SMC PMU has no phandle"))?;
            let cells = node
                .cells32("function-rtc_read_helper")
                .ok_or(refuse!("RTC helper has no cells"))?;
            Some(smc::RtcKeyProfile::from_function(&cells, provider)?)
        }
    };
    let identity = pair("info-id")?;
    let mailbox = match (single("fw-mcom-address")?, single("fw-host-irq-address")?) {
        (None, None) if mailbox_vector.is_none() => None,
        (Some(registers), Some(doorbell)) => Some(FirmwareMailbox {
            registers,
            doorbell,
            vector: mailbox_vector,
        }),
        _ => return Err(refuse!("PMU firmware mailbox is incomplete")),
    };
    let pmu = SpmiPmu {
        sid,
        primary,
        interrupt,
        mailbox,
        alarm_monitor,
        rtc_helper,
        identity,
        fault_log,
        wake_source,
        windows,
        rtc,
    };
    // Validate geometry only. This temporary value never becomes a PMU;
    // placement separately requires explicit resource history.
    pmu.configuration(|_, window| Ok(alloc::vec![0; usize::from(window.bytes)]))?;
    Ok(pmu)
}

pub(super) fn cells_of(value: &[u8]) -> Option<[u32; 4]> {
    let cells = value.as_chunks::<4>().0;
    let cell = |i: usize| cells.get(i).map(|c| u32::from_le_bytes(*c));
    Some([cell(0)?, cell(1)?, cell(2)?, cell(3)?])
}

#[cfg(test)]
mod tests;
