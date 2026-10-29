//! DeviceTree placement and validation for spmi topology.
use super::ASC;
use super::Node;
use super::PMU;
use super::SPMI;
use super::String;
use super::Vec;
use super::apertures;
use super::format;
use super::rtbuddy_nub;
use super::smc;

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
    pub identity: Option<stela_soc_data::pmu::Window>,
    /// Outside-scratch log, requiring explicit cold/retained history at placement.
    pub fault_log: Option<stela_soc_data::pmu::Window>,
    /// Outside-scratch off-to-wake source, likewise.
    pub wake_source: Option<stela_soc_data::pmu::Window>,
    pub windows: Vec<stela_soc_data::pmu::Window>,
    pub rtc: Option<stela_soc_data::pmu::Rtc>,
}

/// A PMIC firmware mailbox (`fw-mcom-address`, `fw-host-irq-address` and, on
/// M4 and later, `fw-mcom-int-index`), served by PMIC firmware that does not
/// execute: its registers are unqualified and its vector is never driven,
/// so it stays unrouted (`stela_soc_data::pmu::Configuration::with_unqualified_firmware_mailbox`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirmwareMailbox {
    pub registers: u16,
    pub doorbell: u16,
    pub vector: Option<u16>,
}

impl SpmiPmu {
    /// This PMU's register owners, with `history`'s initial bytes for each
    /// retained-history owner.
    pub fn configuration(
        &self,
        mut history: impl FnMut(
            stela_soc_data::pmu::Retained,
            stela_soc_data::pmu::Window,
        ) -> Result<Vec<u8>, String>,
    ) -> Result<stela_soc_data::pmu::Configuration, String> {
        let mut configuration = stela_soc_data::pmu::Configuration::new(
            self.windows.clone(),
            self.rtc,
            self.alarm_monitor,
        )?;
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

    /// The retained-history owners whose initial bytes placement supplies.
    pub fn retained(
        &self,
    ) -> impl Iterator<Item = (stela_soc_data::pmu::Retained, stela_soc_data::pmu::Window)> + use<>
    {
        let fault = self
            .fault_log
            .map(|log| (stela_soc_data::pmu::Retained::FaultLog, log));
        let wake = self
            .wake_source
            .map(|source| (stela_soc_data::pmu::Retained::WakeSource, source));
        fault.into_iter().chain(wake)
    }
}

use stela_soc_data::spmi::Configuration;

/// A source-qualified SPMI controller with independent FIFO/vector geometry.
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
) -> Result<Vec<SpmiController>, String> {
    let mut controllers = Vec::new();
    for node in io.children().ok_or("/arm-io children are malformed")? {
        if !node.compatible(SPMI) {
            continue;
        }
        if node.property("gen").is_none_or(|bytes| bytes.len() != 4) {
            return Err("SPMI generation is not one full32 word".into());
        }
        let profile = match node.first_u32("gen") {
            Some(1) => stela_soc_data::spmi::Profile::Gen1,
            Some(2) => stela_soc_data::spmi::Profile::Gen2,
            Some(3) => stela_soc_data::spmi::Profile::Gen3,
            Some(4) => stela_soc_data::spmi::Profile::Gen4,
            _ => return Err("SPMI controller generation is unqualified".into()),
        };
        let regs = apertures::registers(&node).ok_or("SPMI controller has no reg")?;
        if node
            .property("reg")
            .is_none_or(|bytes| bytes.len() != regs.len() * 16)
        {
            return Err("SPMI controller has partial reg pairs".into());
        }
        let bank = |index: usize| -> Result<(u64, u64), String> {
            let &(offset, bytes) = regs
                .get(index)
                .filter(|(_, bytes)| *bytes == profile.bank_bytes())
                .ok_or("SPMI controller banks do not match the qualified handler geometry")?;
            let physical = translate(offset, bytes).ok_or("SPMI bank outside arm-io ranges")?;
            if !physical.is_multiple_of(4) {
                return Err("SPMI bank is unaligned or crosses arm-io ranges".into());
            }
            Ok((physical, bytes))
        };
        let parents = node
            .cells32("interrupt-parent")
            .ok_or("SPMI controller has no interrupt-parent")?;
        let cells = node
            .cells32("interrupts")
            .ok_or("SPMI controller has no interrupts")?;
        let irq = parents
            .iter()
            .position(|&parent| parent == aic)
            .and_then(|index| cells.get(index).copied())
            .ok_or("SPMI controller has no AIC line")?;
        let local = node
            .first_u32("AAPL,phandle")
            .ok_or("SPMI has no phandle")?;
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
            return Err("SPMI interrupt-parent/vector routing is unqualified".into());
        }
        let queue_bytes: [u32; 2] = node
            .cells32("queue-depth")
            .filter(|_| {
                node.property("queue-depth")
                    .is_some_and(|bytes| bytes.len() == 8)
            })
            .and_then(|cells| cells.try_into().ok())
            .ok_or("SPMI has no two FIFO byte depths")?;
        let configuration =
            stela_soc_data::spmi::Configuration::new(profile, cells[0], queue_bytes)
                .map_err(String::from)?;
        let counters = match node.property("fault-counters-enabled") {
            None => false,
            Some(bytes) if bytes.len() == 4 => match node.first_u32("fault-counters-enabled") {
                Some(0) => false,
                Some(1) => true,
                _ => return Err("SPMI fault-counter enable encoding is unqualified".into()),
            },
            _ => return Err("SPMI fault-counter enable is not one full32 word".into()),
        };
        let bank_c = if profile.arbiter_bank() {
            Some(bank(2)?)
        } else if counters && profile == stela_soc_data::spmi::Profile::Gen1 {
            let &(offset, bytes) = regs
                .get(2)
                .filter(|(_, bytes)| Some(*bytes) == profile.counter_bytes())
                .ok_or("SPMI Gen1 needs its separate fault-counter bank")?;
            let physical =
                translate(offset, bytes).ok_or("SPMI fault counters outside arm-io ranges")?;
            if !physical.is_multiple_of(4) {
                return Err("SPMI fault counters are unaligned or cross arm-io ranges".into());
            }
            Some((physical, bytes))
        } else {
            None
        };
        let expected = if bank_c.is_some() { 3 } else { 2 };
        if regs.len() != expected {
            return Err("SPMI has an unqualified extra register view".into());
        }
        let mut pmus = Vec::new();
        for child in node.children().ok_or("SPMI children are malformed")? {
            if child.compatible(PMU) {
                let pmu = spmi_pmu(&child, io)?;
                if (pmu.interrupt.is_some()
                    || pmu.mailbox.is_some_and(|mailbox| mailbox.vector.is_some()))
                    && (child
                        .property("interrupt-parent")
                        .is_none_or(|bytes| bytes.len() != 4)
                        || child.first_u32("interrupt-parent") != Some(local))
                {
                    return Err("PMU output is not parented by its own SPMI controller".into());
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
            return Err("PMU interrupt vectors alias each other or the response".into());
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
        return Err("multiple primary PMU system-service owners".into());
    }
    Ok(controllers)
}

/// A PMU's slave ID (`reg` cell 0) and its `info-*` windows: pairs are
/// `<base bytes>`, single cells one byte, except the legacy scratchpad.
fn spmi_pmu(node: &Node<'_>, io: &Node<'_>) -> Result<SpmiPmu, String> {
    let sid = node
        .first_u32("reg")
        .and_then(|sid| u8::try_from(sid).ok())
        .filter(|&sid| sid <= 0xf)
        .ok_or("PMU has no four-bit SPMI slave ID")?;
    let primary = match node.property("is-primary") {
        None => false,
        Some(bytes) if bytes.len() == 4 => match node.first_u32("is-primary") {
            Some(0) => false,
            Some(1) => true,
            _ => return Err("PMU primary-service encoding is unqualified".into()),
        },
        _ => return Err("PMU is-primary is not one full32 word".into()),
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
                    .ok_or("PMU local interrupt vector exceeds the SPMI input bank")
            })
            .collect::<Result<Vec<_>, _>>()?,
        _ => return Err("PMU interrupts are not one or two full32 vectors".into()),
    };
    let mailbox_index = match node.property("fw-mcom-int-index") {
        None => None,
        Some(bytes) if bytes.len() == 4 => node
            .first_u32("fw-mcom-int-index")
            .and_then(|index| usize::try_from(index).ok()),
        _ => return Err("PMU fw-mcom-int-index is not one full32 word".into()),
    };
    let mailbox_vector = mailbox_index
        .map(|index| {
            vectors
                .get(index)
                .copied()
                .ok_or("PMU firmware mailbox index names no interrupt")
        })
        .transpose()?;
    let mut outputs = (0..vectors.len())
        .filter(|&index| Some(index) != mailbox_index)
        .map(|index| vectors[index]);
    let interrupt = outputs.next();
    if outputs.next().is_some() || (vectors.len() == 2 && vectors[0] == vectors[1]) {
        return Err("PMU interrupts are not one output and one firmware mailbox".into());
    }
    let address = |value: u32| u16::try_from(value).map_err(|_| "PMU address above 16 bits");
    let pair = |name: &str| -> Result<Option<stela_soc_data::pmu::Window>, String> {
        match node.cells32(name).as_deref() {
            None => Ok(None),
            Some(&[base, bytes]) if node.property(name).is_some_and(|value| value.len() == 8) => {
                Ok(Some(stela_soc_data::pmu::Window {
                    base: address(base)?,
                    bytes: address(bytes)?,
                }))
            }
            Some(_) => Err(format!("PMU {name} is not <base bytes>")),
        }
    };
    let single = |name: &str| -> Result<Option<u16>, String> {
        if node.property(name).is_some_and(|bytes| bytes.len() != 4) {
            return Err(format!("PMU {name} is not one full32 word"));
        }
        node.first_u32(name)
            .map(address)
            .transpose()
            .map_err(String::from)
    };
    let scratch = pair("info-scrpad")?;
    let mut windows = Vec::new();
    windows.extend(scratch);
    windows.extend(pair("info-fault_shadow")?);
    // A byte-counted history (`_readFaultLog`, `_readOff2WakeSource`) is its
    // own retained owner outside scratch, and scratch storage inside it.
    let retained = |name: &str| -> Result<Option<stela_soc_data::pmu::Window>, String> {
        let Some(log) = pair(name)? else {
            return Ok(None);
        };
        let end = u32::from(log.base) + u32::from(log.bytes);
        if log.bytes == 0 || log.bytes > u16::from(u8::MAX) || end > 0x10000 {
            return Err(format!(
                "PMU {name} count or extent exceeds the qualified byte-count resource"
            ));
        }
        let Some(scratch) = scratch else {
            return Ok(Some(log));
        };
        let scratch_end = u32::from(scratch.base) + u32::from(scratch.bytes);
        if u32::from(log.base) < scratch_end && u32::from(scratch.base) < end {
            if log.base < scratch.base || end > scratch_end {
                return Err(format!("PMU {name} partially aliases scratch storage"));
            }
            return Ok(None); // Same canonical scratch owner; original zero-clear form.
        }
        Ok(Some(log))
    };
    let fault_log = retained("info-fault_log")?;
    let wake_source = retained("info-off2wake_source")?;
    if let Some(base) = single("info-leg_scrpad")? {
        windows.push(stela_soc_data::pmu::Window {
            base,
            bytes: stela_soc_data::pmu::LEGACY_SCRATCH_BYTES,
        });
    }
    if let Some(base) = single("info-pm_setting")? {
        windows.push(stela_soc_data::pmu::Window { base, bytes: 1 });
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
        return Err("PMU SOCD scratchpad outside its scratchpad".into());
    }
    for name in ["info-scrpad_lpm_log", "info-scrpad_lpm_ctrl"] {
        if let Some(base) = single(name)?
            && !inside(base, 1)
        {
            return Err(format!("PMU {name} outside its scratchpad"));
        }
    }
    let rtc = match single("info-rtc")? {
        None => None,
        Some(upcount) => {
            let need = |name: &str| -> Result<u16, String> {
                single(name)?.ok_or_else(|| format!("PMU RTC has no {name}"))
            };
            // Without `info-clock_offset` the driver keeps the offset in the
            // legacy scratchpad (`stela_soc_data::pmu::ClockOffset::LegacyScratch`).
            let clock_offset = match pair("info-clock_offset")? {
                Some(window) if window.bytes == 6 => {
                    stela_soc_data::pmu::ClockOffset::Register(window.base)
                }
                Some(_) => return Err("PMU RTC clock offset is not six bytes".into()),
                None => stela_soc_data::pmu::ClockOffset::LegacyScratch(
                    single("info-leg_scrpad")?
                        .ok_or("PMU RTC has neither a clock offset nor a legacy scratchpad")?,
                ),
            };
            if node
                .property("info-rtc_alarm_ctrl_en_mask")
                .is_none_or(|bytes| bytes.len() != 4)
            {
                return Err("PMU alarm enable mask is not one full32 word".into());
            }
            let alarm_enable = node
                .first_u32("info-rtc_alarm_ctrl_en_mask")
                .and_then(|mask| u8::try_from(mask).ok())
                .ok_or("PMU RTC has no alarm enable mask")?;
            let bits = |name: &str| -> Result<Option<u8>, String> {
                if node.property(name).is_some_and(|bytes| bytes.len() != 4) {
                    return Err(format!("PMU {name} is not one full32 word"));
                }
                node.first_u32(name)
                    .map(|mask| {
                        u8::try_from(mask).map_err(|_| format!("PMU {name} exceeds a byte"))
                    })
                    .transpose()
            };
            Some(stela_soc_data::pmu::Rtc {
                upcount,
                clock_offset,
                alarm_control: need("info-rtc_alarm_ctrl")?,
                alarm_enable,
                alarm_offset: need("info-rtc_alarm_offset")?,
                alarm_event: need("info-rtc_alarm_event")?,
                irq_mask: need("info-rtc_irq_mask_offset")?,
                event_mask: bits("info-rtc_alarm_event_mask")?
                    .unwrap_or(stela_soc_data::pmu::DEFAULT_EVENT_MASK),
                interrupt_mask: bits("info-rtc_alarm_mask")?
                    .ok_or("PMU RTC has no info-rtc_alarm_mask")?,
            })
        }
    };
    let alarm_monitor = if rtc.is_some() {
        single("info-rtc_alarm_monitor_mask")?
            .and_then(|mask| u8::try_from(mask).ok())
            .ok_or("PMU RTC has no byte monitor mask")?
    } else {
        0
    };
    // The primary's alarm is the board's RTC wake source. An output alone
    // needs no RTC: without one it stays deasserted (`pmu::Pmu`).
    if primary && rtc.is_none() {
        return Err("PMU primary system service requires a qualified RTC owner".into());
    }
    let rtc_helper = match node.property("function-rtc_read_helper") {
        None => None,
        Some(bytes) => {
            if !primary || rtc.is_none() || bytes.len() != 12 {
                return Err(
                    "RTC helper requires a primary RTC and complete three-cell descriptor".into(),
                );
            }
            let source = io
                .child("smc")
                .filter(|node| {
                    node.compatible(ASC) && node.property("role") == Some(b"SMC\0".as_slice())
                })
                .ok_or("RTC helper has no qualified visible SMC provider")?;
            let nub = rtbuddy_nub(&source, "SMC")?;
            let provider = nub
                .child("smc-pmu")
                .ok_or("RTC helper has no SMC PMU provider")?;
            if provider
                .property("AAPL,phandle")
                .is_none_or(|bytes| bytes.len() != 4)
            {
                return Err("SMC PMU provider phandle is not one full32 word".into());
            }
            let provider = provider
                .first_u32("AAPL,phandle")
                .ok_or("SMC PMU has no phandle")?;
            let cells = node
                .cells32("function-rtc_read_helper")
                .ok_or("RTC helper has no cells")?;
            Some(smc::RtcKeyProfile::from_function(&cells, provider).map_err(String::from)?)
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
        _ => return Err("PMU firmware mailbox is incomplete".into()),
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
    // actual placement separately requires explicit resource history.
    pmu.configuration(|_, window| Ok(alloc::vec![0; usize::from(window.bytes)]))?;
    Ok(pmu)
}

pub(super) fn cells_of(value: &[u8]) -> Option<[u32; 4]> {
    let cells = value.as_chunks::<4>().0;
    let cell = |i: usize| cells.get(i).map(|c| u32::from_le_bytes(*c));
    Some([cell(0)?, cell(1)?, cell(2)?, cell(3)?])
}

#[cfg(test)]
mod tests {
    use super::super::tests::flat_fixture_extent;
    use super::super::*;
    use super::*;

    #[test]
    fn spmi_placement_reads_banks_aic_line_and_pmu_windows() {
        use stela_contracts::adt::encode;
        let z = |text: &str| [text.as_bytes(), &[0]].concat();
        let cells = |values: &[u32]| {
            values
                .iter()
                .flat_map(|n| n.to_le_bytes())
                .collect::<Vec<_>>()
        };
        let pairs = |values: &[(u64, u64)]| {
            values
                .iter()
                .flat_map(|&(a, b)| [a, b])
                .flat_map(u64::to_le_bytes)
                .collect::<Vec<_>>()
        };
        // The J473AP pmu-main and its controller, trimmed.
        let tree = |offset: &[u32]| {
            let pmu = encode(
                &[
                    ("name", &z("pmu-main")),
                    ("compatible", b"pmu,spmi\0pmu,stowe\0"),
                    ("reg", &cells(&[0xe, 3, 0, 4, 0, 0])),
                    ("info-scrpad", &cells(&[0x8000, 0x2800])),
                    ("info-scrpad_socd", &cells(&[0x8b00, 0x1800])),
                    ("info-scrpad_lpm_ctrl", &cells(&[0xa7dc])),
                    ("info-leg_scrpad", &cells(&[0xf700])),
                    ("info-fault_log", &cells(&[0xfa00, 5])),
                    ("info-pm_setting", &cells(&[0xf801])),
                    ("info-rtc", &cells(&[0xf802])),
                    ("info-clock_offset", &cells(offset)),
                    ("info-rtc_alarm_ctrl", &cells(&[0xf800])),
                    ("info-rtc_alarm_ctrl_en_mask", &cells(&[0x40])),
                    ("info-rtc_alarm_monitor_mask", &cells(&[1])),
                    ("is-primary", &cells(&[1])),
                    ("info-rtc_alarm_offset", &cells(&[0xf808])),
                    ("info-rtc_alarm_event", &cells(&[0xf80c])),
                    ("info-rtc_irq_mask_offset", &cells(&[0xf80e])),
                    ("info-rtc_alarm_mask", &cells(&[0x1])),
                ],
                &[],
            );
            // Hidden: the loader removed its compatible.
            let btm = encode(&[("name", &z("btm")), ("reg", &cells(&[0xe]))], &[]);
            let spmi = encode(
                &[
                    ("name", &z("nub-spmi0")),
                    ("compatible", &z(SPMI)),
                    ("gen", &cells(&[2])),
                    ("queue-depth", &cells(&[256, 256])),
                    ("AAPL,phandle", &cells(&[0xae])),
                    (
                        "reg",
                        &pairs(&[(0x3d71_4000, 0x4000), (0x3d70_4000, 0x4000)]),
                    ),
                    ("interrupt-parent", &cells(&[0xae, 0x63, 0xae])),
                    ("interrupts", &cells(&[0x100, 0x180, 0x119, 0x104])),
                ],
                &[pmu, btm],
            );
            encode(&[("name", &z("arm-io"))], &[spmi])
        };
        let translate = |offset| Some(0x2_0000_0000 + offset);
        let bytes = tree(&[0xf900, 6]);
        let io = Node::root(&bytes).unwrap();
        let [controller] =
            &spmi_controllers(&io, &flat_fixture_extent(&translate), 0x63).unwrap()[..]
        else {
            panic!("one controller");
        };
        assert_eq!(
            controller.banks,
            [(0x2_3d71_4000, 0x4000), (0x2_3d70_4000, 0x4000)]
        );
        assert_eq!(controller.irq, 0x180);
        let [pmu] = &controller.pmus[..] else {
            panic!("one visible PMU");
        };
        assert_eq!(pmu.sid, 0xe);
        assert!(pmu.primary);
        assert_eq!(pmu.alarm_monitor, 1);
        assert_eq!(pmu.interrupt, None);
        let window = |base, bytes| stela_soc_data::pmu::Window { base, bytes };
        assert_eq!(
            pmu.windows,
            [
                window(0x8000, 0x2800),
                window(0xf700, stela_soc_data::pmu::LEGACY_SCRATCH_BYTES),
                window(0xf801, 1),
            ]
        );
        assert_eq!(pmu.fault_log, Some(window(0xfa00, 5)));
        assert_eq!(pmu.rtc_helper, None);
        let rtc = pmu.rtc.unwrap();
        assert_eq!(
            (rtc.upcount, rtc.clock_offset, rtc.alarm_enable),
            (
                0xf802,
                stela_soc_data::pmu::ClockOffset::Register(0xf900),
                0x40
            )
        );
        // J473AP gives no event mask: the driver's default holds.
        assert_eq!((rtc.event_mask, rtc.interrupt_mask), (0x1, 0x1));
        // A clock offset that is not six bytes refuses.
        let bytes = tree(&[0xf900, 4]);
        let io = Node::root(&bytes).unwrap();
        assert!(spmi_controllers(&io, &flat_fixture_extent(&translate), 0x63).is_err());
    }

    #[test]
    fn chapel_places_a_shared_alarm_byte_and_explicit_off_to_wake_history() {
        use stela_contracts::adt::encode;
        let z = |text: &str| [text.as_bytes(), &[0]].concat();
        let cells = |values: &[u32]| {
            values
                .iter()
                .flat_map(|n| n.to_le_bytes())
                .collect::<Vec<_>>()
        };
        let pairs = |values: &[(u64, u64)]| {
            values
                .iter()
                .flat_map(|&(a, b)| [a, b])
                .flat_map(u64::to_le_bytes)
                .collect::<Vec<_>>()
        };
        // The J514sAP nub-spmi0 Chapel primary and Spitfire, trimmed.
        let tree = |wake: &[u32]| {
            let chapel = encode(
                &[
                    ("name", &z("spmi-chapelL1")),
                    ("compatible", b"pmu,spmi\0pmu,chapel\0"),
                    ("reg", &cells(&[0xb, 3, 0, 4, 0, 0])),
                    ("info-scrpad", &cells(&[0x8000, 0x2800])),
                    ("info-scrpad_socd", &cells(&[0x8b00, 0x1800])),
                    ("info-fault_shadow", &cells(&[0x867b, 0x10])),
                    ("info-leg_scrpad", &cells(&[0xf800])),
                    ("info-fault_log", &cells(&[0x2200, 7])),
                    ("info-off2wake_source", &cells(wake)),
                    ("info-pm_setting", &cells(&[0x2001])),
                    ("info-rtc", &cells(&[0x2002])),
                    ("info-clock_offset", &cells(&[0x2100, 6])),
                    ("info-rtc_alarm_ctrl", &cells(&[0x2000])),
                    ("info-rtc_alarm_ctrl_en_mask", &cells(&[0x40])),
                    ("info-rtc_alarm_monitor_mask", &cells(&[1])),
                    ("info-rtc_alarm_offset", &cells(&[0x2008])),
                    ("info-rtc_alarm_event", &cells(&[0x2000])),
                    ("info-rtc_alarm_event_mask", &cells(&[2])),
                    ("info-rtc_irq_mask_offset", &cells(&[0x200e])),
                    ("info-rtc_alarm_mask", &cells(&[1])),
                    ("info-id", &cells(&[0, 10])),
                    ("is-primary", &cells(&[1])),
                    ("interrupt-parent", &cells(&[0x141])),
                    ("interrupts", &cells(&[2])),
                ],
                &[],
            );
            let spitfire = encode(
                &[
                    ("name", &z("spmi-spitfireE1")),
                    ("compatible", b"pmu,spmi\0pmu,spitfire\0"),
                    ("reg", &cells(&[0x9, 3, 0, 4, 0, 0])),
                    ("info-fault_log", &cells(&[0x1000, 4])),
                    ("info-id", &cells(&[0, 10])),
                ],
                &[],
            );
            let spmi = encode(
                &[
                    ("name", &z("nub-spmi0")),
                    ("compatible", &z(SPMI)),
                    ("gen", &cells(&[2])),
                    ("queue-depth", &cells(&[256, 256])),
                    ("AAPL,phandle", &cells(&[0x141])),
                    (
                        "reg",
                        &pairs(&[(0x3d71_4000, 0x4000), (0x3d70_4000, 0x4000)]),
                    ),
                    ("interrupt-parent", &cells(&[0x141, 0x63, 0x141])),
                    ("interrupts", &cells(&[0x100, 0x180, 0x119, 0x104])),
                ],
                &[chapel, spitfire],
            );
            encode(&[("name", &z("arm-io"))], &[spmi])
        };
        let translate = |offset| Some(0x2_0000_0000 + offset);
        let bytes = tree(&[0x281c, 2]);
        let io = Node::root(&bytes).unwrap();
        let [controller] =
            &spmi_controllers(&io, &flat_fixture_extent(&translate), 0x63).unwrap()[..]
        else {
            panic!("one controller");
        };
        let [chapel, spitfire] = &controller.pmus[..] else {
            panic!("two PMUs");
        };
        assert!(chapel.rtc.unwrap().shares_event());
        let window = |base, bytes| stela_soc_data::pmu::Window { base, bytes };
        assert_eq!(
            chapel.retained().collect::<Vec<_>>(),
            [
                (stela_soc_data::pmu::Retained::FaultLog, window(0x2200, 7)),
                (stela_soc_data::pmu::Retained::WakeSource, window(0x281c, 2)),
            ]
        );
        assert_eq!(spitfire.retained().count(), 1);
        let cold = |pmus: &[SpmiPmu]| {
            pmus.iter()
                .flat_map(|pmu| {
                    pmu.retained()
                        .map(|(kind, window)| (pmu.sid, kind, vec![0; usize::from(window.bytes)]))
                })
                .collect::<Vec<_>>()
        };
        let epoch = crate::platform::apple::pmu::RtcEpoch {
            counter: 0,
            ticks: 0,
        };
        let mut history = cold(&controller.pmus);
        let mut devices = crate::machine::apple::AppleDevices::new();
        assert!(
            devices
                .add_spmi_with_resources(controller, None, epoch, &history[..2])
                .is_err()
        );
        history[1].2.pop();
        assert!(
            devices
                .add_spmi_with_resources(controller, None, epoch, &history)
                .is_err()
        );
        let history = cold(&controller.pmus);
        devices
            .add_spmi_with_resources(controller, None, epoch, &history)
            .unwrap();
        // Inside scratch it is scratch storage; a partial alias refuses.
        let bytes = tree(&[0x8100, 2]);
        let io = Node::root(&bytes).unwrap();
        let controllers = spmi_controllers(&io, &flat_fixture_extent(&translate), 0x63).unwrap();
        assert_eq!(controllers[0].pmus[0].wake_source, None);
        let bytes = tree(&[0x7fff, 2]);
        let io = Node::root(&bytes).unwrap();
        assert!(spmi_controllers(&io, &flat_fixture_extent(&translate), 0x63).is_err());
    }

    #[test]
    fn an_rtc_without_a_clock_offset_register_keeps_it_in_the_legacy_scratchpad() {
        use stela_contracts::adt::encode;
        let z = |text: &str| [text.as_bytes(), &[0]].concat();
        let cells = |values: &[u32]| {
            values
                .iter()
                .flat_map(|n| n.to_le_bytes())
                .collect::<Vec<_>>()
        };
        // The J700AP Baku pmu-main, trimmed: no `info-clock_offset`.
        let node = |legacy: bool| {
            let mut properties: Vec<(&str, Vec<u8>)> = alloc::vec![
                ("name", z("pmu-main")),
                ("compatible", b"pmu,spmi\0pmu,baku\0".to_vec()),
                ("reg", cells(&[0xe, 3, 0, 4, 0, 0])),
                ("info-scrpad", cells(&[0x8000, 0x1000])),
                ("info-pm_setting", cells(&[0xf801])),
                ("info-rtc", cells(&[0xf802])),
                ("info-rtc_alarm_ctrl", cells(&[0xf800])),
                ("info-rtc_alarm_ctrl_en_mask", cells(&[0x40])),
                ("info-rtc_alarm_monitor_mask", cells(&[1])),
                ("info-rtc_alarm_offset", cells(&[0xf808])),
                ("info-rtc_alarm_event", cells(&[0xf80c])),
                ("info-rtc_irq_mask_offset", cells(&[0xf80e])),
                ("info-rtc_alarm_mask", cells(&[1])),
            ];
            if legacy {
                properties.push(("info-leg_scrpad", cells(&[0xf700])));
            }
            let properties: Vec<(&str, &[u8])> = properties
                .iter()
                .map(|(name, value)| (*name, value.as_slice()))
                .collect();
            let pmu = encode(&properties, &[]);
            encode(&[("name", &z("arm-io"))], &[pmu])
        };
        let bytes = node(true);
        let io = Node::root(&bytes).unwrap();
        let pmu = spmi_pmu(&io.children().unwrap()[0], &io).unwrap();
        assert_eq!(
            pmu.rtc.unwrap().clock_offset,
            stela_soc_data::pmu::ClockOffset::LegacyScratch(0xf700)
        );
        let bytes = node(false);
        let io = Node::root(&bytes).unwrap();
        assert!(spmi_pmu(&io.children().unwrap()[0], &io).is_err());
    }

    #[test]
    fn a_firmware_mailbox_names_its_vector_registers_and_doorbell() {
        use stela_contracts::adt::encode;
        let z = |text: &str| [text.as_bytes(), &[0]].concat();
        let cells = |values: &[u32]| {
            values
                .iter()
                .flat_map(|n| n.to_le_bytes())
                .collect::<Vec<_>>()
        };
        let pairs = |values: &[(u64, u64)]| {
            values
                .iter()
                .flat_map(|&(a, b)| [a, b])
                .flat_map(u64::to_le_bytes)
                .collect::<Vec<_>>()
        };
        // J604AP-shaped Club and Jerez-shaped secondary: `interrupts` holds the
        // output and the mailbox vector `fw-mcom-int-index` selects.
        let tree = |pmus: &[(&[u32], Option<u32>, bool)]| {
            let children: Vec<Vec<u8>> = pmus
                .iter()
                .enumerate()
                .map(|(sid, &(vectors, index, addresses))| {
                    let mut properties: Vec<(&str, Vec<u8>)> = alloc::vec![
                        ("name", z("pmu")),
                        ("compatible", b"pmu,spmi\0pmu,club\0".to_vec()),
                        ("reg", cells(&[sid as u32 + 0xd, 3, 0, 4, 0, 0])),
                        ("info-fault_log", cells(&[0x1000, 5])),
                        ("interrupt-parent", cells(&[0x146])),
                        ("interrupts", cells(vectors)),
                    ];
                    if let Some(index) = index {
                        properties.push(("fw-mcom-int-index", cells(&[index])));
                    }
                    if addresses {
                        properties.push(("fw-mcom-address", cells(&[0x2860])));
                        properties.push(("fw-host-irq-address", cells(&[0x2808])));
                    }
                    let properties: Vec<(&str, &[u8])> = properties
                        .iter()
                        .map(|(name, value)| (*name, value.as_slice()))
                        .collect();
                    encode(&properties, &[])
                })
                .collect();
            let spmi = encode(
                &[
                    ("name", &z("nub-spmi1")),
                    ("compatible", &z(SPMI)),
                    ("gen", &cells(&[3])),
                    ("queue-depth", &cells(&[256, 256])),
                    ("AAPL,phandle", &cells(&[0x146])),
                    (
                        "reg",
                        &pairs(&[
                            (0x8861_4000, 0x4000),
                            (0x8860_4000, 0x4000),
                            (0x8860_0000, 0x4000),
                        ]),
                    ),
                    ("interrupt-parent", &cells(&[0x146, 0x63, 0x146])),
                    ("interrupts", &cells(&[0x100, 0x206, 0x119, 0x104])),
                ],
                &children,
            );
            encode(&[("name", &z("arm-io"))], &[spmi])
        };
        let translate = |offset| Some(0x1_0000_0000 + offset);
        let parse = |pmus: &[(&[u32], Option<u32>, bool)]| {
            let bytes = tree(pmus);
            let io = Node::root(&bytes).unwrap();
            spmi_controllers(&io, &flat_fixture_extent(&translate), 0x63)
                .map(|controllers| controllers[0].pmus.clone())
        };
        let pmus = parse(&[(&[2, 62], Some(1), true), (&[126], Some(0), true)]).unwrap();
        assert_eq!(pmus[0].interrupt, Some(2));
        assert_eq!(
            pmus[0].mailbox,
            Some(FirmwareMailbox {
                registers: 0x2860,
                doorbell: 0x2808,
                vector: Some(62)
            })
        );
        assert_eq!(pmus[1].interrupt, None);
        assert_eq!(pmus[1].mailbox.unwrap().vector, Some(126));
        // T6030 Chapel declares the registers without a vector.
        let pmus = parse(&[(&[2], None, true)]).unwrap();
        assert_eq!(
            (pmus[0].interrupt, pmus[0].mailbox.unwrap().vector),
            (Some(2), None)
        );
        for invalid in [
            &[(&[2, 62][..], None, true)][..],
            &[(&[2, 62], Some(2), true)],
            &[(&[2, 62], Some(1), false)],
            &[(&[2, 2], Some(1), true)],
            &[(&[2, 0x100], Some(1), true)],
            &[(&[2, 62], Some(1), true), (&[62], Some(0), true)],
            &[(&[2, 62, 63], Some(1), true)],
        ] {
            assert!(parse(invalid).is_err());
        }
    }

    #[test]
    fn a_pmu_output_needs_no_rtc_but_the_primary_service_does() {
        use stela_contracts::adt::encode;
        let z = |text: &str| [text.as_bytes(), &[0]].concat();
        let cells = |values: &[u32]| {
            values
                .iter()
                .flat_map(|n| n.to_le_bytes())
                .collect::<Vec<_>>()
        };
        let pairs = |values: &[(u64, u64)]| {
            values
                .iter()
                .flat_map(|&(a, b)| [a, b])
                .flat_map(u64::to_le_bytes)
                .collect::<Vec<_>>()
        };
        // A J504AP-shaped pmu-aux (Vale) on its own controller, trimmed.
        let tree = |primary: u32| {
            let pmu = encode(
                &[
                    ("name", &z("pmu-aux")),
                    ("compatible", b"pmu,spmi\0pmu,vale\0"),
                    ("reg", &cells(&[0xe, 3, 0, 4, 0, 0])),
                    ("info-scrpad", &cells(&[0xa000, 0x800])),
                    ("info-leg_scrpad", &cells(&[0xbb00])),
                    ("info-fault_log", &cells(&[0x1800, 3])),
                    ("info-id", &cells(&[0, 10])),
                    ("is-primary", &cells(&[primary])),
                    ("interrupt-parent", &cells(&[0x110])),
                    ("interrupts", &cells(&[2])),
                ],
                &[],
            );
            let spmi = encode(
                &[
                    ("name", &z("nub-spmi1")),
                    ("compatible", &z(SPMI)),
                    ("gen", &cells(&[2])),
                    ("queue-depth", &cells(&[256, 256])),
                    ("AAPL,phandle", &cells(&[0x110])),
                    (
                        "reg",
                        &pairs(&[(0x3d81_4000, 0x4000), (0x3d80_4000, 0x4000)]),
                    ),
                    ("interrupt-parent", &cells(&[0x110, 0x63, 0x110])),
                    ("interrupts", &cells(&[0x100, 0x184, 0x119, 0x104])),
                ],
                &[pmu],
            );
            encode(&[("name", &z("arm-io"))], &[spmi])
        };
        let translate = |offset| Some(0x2_0000_0000 + offset);
        let bytes = tree(0);
        let io = Node::root(&bytes).unwrap();
        let controllers = spmi_controllers(&io, &flat_fixture_extent(&translate), 0x63).unwrap();
        let pmu = &controllers[0].pmus[0];
        assert_eq!(
            (pmu.primary, pmu.interrupt, pmu.rtc),
            (false, Some(2), None)
        );
        let bytes = tree(1);
        let io = Node::root(&bytes).unwrap();
        assert!(spmi_controllers(&io, &flat_fixture_extent(&translate), 0x63).is_err());
    }

    #[test]
    fn gen3_and_gen4_spmi_controllers_place_their_arbiter_bank() {
        use stela_contracts::adt::encode;
        let z = |text: &str| [text.as_bytes(), &[0]].concat();
        let cells = |values: &[u32]| {
            values
                .iter()
                .flat_map(|n| n.to_le_bytes())
                .collect::<Vec<_>>()
        };
        let pairs = |values: &[(u64, u64)]| {
            values
                .iter()
                .flat_map(|&(a, b)| [a, b])
                .flat_map(u64::to_le_bytes)
                .collect::<Vec<_>>()
        };
        // The J813AP nub-spmi0, trimmed.
        let tree = |generation: u32, reg: &[(u64, u64)]| {
            let spmi = encode(
                &[
                    ("name", &z("nub-spmi0")),
                    ("compatible", &z(SPMI)),
                    ("gen", &cells(&[generation])),
                    ("queue-depth", &cells(&[256, 256])),
                    ("AAPL,phandle", &cells(&[0x106])),
                    ("reg", &pairs(reg)),
                    ("interrupt-parent", &cells(&[0x106, 0x9c, 0x106])),
                    (
                        "interrupts",
                        &cells(&[0x100, 0x248, 0x119, 0x104, 0x110, 0x111]),
                    ),
                ],
                &[],
            );
            encode(&[("name", &z("arm-io"))], &[spmi])
        };
        let translate = |offset| Some(0x1_0000_0000 + offset);
        let banks = [
            (0x7871_4000, 0x4000),
            (0x7870_4000, 0x4000),
            (0x7870_0000, 0x4000),
        ];
        for (generation, profile) in [
            (3, stela_soc_data::spmi::Profile::Gen3),
            (4, stela_soc_data::spmi::Profile::Gen4),
        ] {
            let bytes = tree(generation, &banks);
            let io = Node::root(&bytes).unwrap();
            let [controller] =
                &spmi_controllers(&io, &flat_fixture_extent(&translate), 0x9c).unwrap()[..]
            else {
                panic!("one controller");
            };
            assert_eq!(controller.configuration.profile(), profile);
            assert_eq!(
                controller.banks,
                [(0x1_7871_4000, 0x4000), (0x1_7870_4000, 0x4000)]
            );
            assert_eq!(controller.bank_c, Some((0x1_7870_0000, 0x4000)));
            assert_eq!(controller.irq, 0x248);
            // The handler fails without reg[2].
            let bytes = tree(generation, &banks[..2]);
            let io = Node::root(&bytes).unwrap();
            assert!(spmi_controllers(&io, &flat_fixture_extent(&translate), 0x9c).is_err());
        }
        let bytes = tree(5, &banks);
        let io = Node::root(&bytes).unwrap();
        assert!(spmi_controllers(&io, &flat_fixture_extent(&translate), 0x9c).is_err());
    }
}
