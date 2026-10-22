//! DeviceTree placement and validation for smc topology.
use super::spmi_topology::cells_of;
use super::{ASC, Node, String, Vec, apertures, asc, format, rtbuddy_nub, smc};

/// The SMC's DT placement: `reg[0]` is the ASC wrapper, its four
/// interrupts the mailbox lines, `reg[timers-reg-index]` the hardware
/// watchdog AppleSMC maps, and its RTBuddy nub's `region-base`/`region-size`
/// the window AppleSMCKeysEndpoint accepts the shared page in
/// (`_keyEndpointHandler`, 0xfffffe0009da5a20). `gpio_keys` are the keys
/// the tree's `pKW4` platform functions write through the nub's `smc-pmu`.
/// `quiesced` is the nub's hand-off state (`rtkit::RtKit::quiesced`).
/// `wake_bits` are the `MBSW` bits `smc-pmu`'s `event_name-bitN`
/// properties name for the wake sources the board models.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmcController {
    pub wrapper: (u64, u64),
    pub interrupts: [u16; 4],
    pub watchdog: Option<(u64, u64)>,
    pub region: (u64, u64),
    pub gpio_keys: Vec<u32>,
    pub quiesced: bool,
    pub wake_bits: smc::WakeBits,
}

/// A platform function property is the provider's phandle, the function's
/// four-character code and its arguments, all little-endian u32 cells
/// (`function-reg_on` = smc-pmu, `pKW4`, `gP0d`, 0x8000).
const SMC_GPIO_WRITE: u32 = smc::code(b"pKW4");

pub(super) fn smc_controller(
    root: &Node<'_>,
    io: &Node<'_>,
    translate: &dyn Fn(u64, u64) -> Option<u64>,
) -> Result<Option<SmcController>, String> {
    let Some(node) = io
        .child("smc")
        .filter(|n| n.compatible(ASC) && n.property("role") == Some(b"SMC\0".as_slice()))
    else {
        return Ok(None);
    };
    let nub = rtbuddy_nub(&node, "SMC")?;
    let regs = apertures::registers(&node).ok_or("SMC has no reg pairs")?;
    let place = |index: usize, minimum: u64, what: &str| -> Result<(u64, u64), String> {
        let &(offset, bytes) = regs
            .get(index)
            .filter(|(_, bytes)| *bytes >= minimum)
            .ok_or_else(|| format!("SMC {what} bank is absent or too short"))?;
        let physical =
            translate(offset, bytes).ok_or_else(|| format!("SMC {what} outside arm-io ranges"))?;
        Ok((physical, bytes))
    };
    let wrapper = place(0, asc::WRAPPER_BYTES, "wrapper")?;
    let watchdog = node
        .first_u32("timers-reg-index")
        .map(|index| place(index as usize, smc::WATCHDOG_BYTES, "watchdog"))
        .transpose()?;
    let irqs = node.cells32("interrupts").ok_or("SMC has no interrupts")?;
    let irq = |index: usize| -> Result<u16, String> {
        irqs.get(index)
            .and_then(|&n| u16::try_from(n).ok())
            .ok_or_else(|| "SMC needs four valid mailbox interrupts".into())
    };
    let interrupts = [irq(0)?, irq(1)?, irq(2)?, irq(3)?];
    let read64 = |name: &str| {
        nub.property(name)
            .and_then(|value| value.try_into().ok())
            .map(u64::from_le_bytes)
    };
    let (base, size) = read64("region-base")
        .zip(read64("region-size"))
        .ok_or("SMC nub has no region-base/region-size")?;
    if size < smc::SRAM_BYTES {
        return Err("SMC region is smaller than the shared page".into());
    }
    let mut gpio_keys = Vec::new();
    let mut wake_bits = smc::WakeBits::default();
    // By name: the loader removes a hidden `smc-pmu`'s compatible, but the
    // keys its functions name are the SMC's whatever the AP binds.
    if let Some(pmu) = nub.child("smc-pmu") {
        // AppleSMCPMU names each set MBSW bit by its `event_name-bitN`
        // (`nameWakeReason`, file 0x2da12ec).
        for (name, value) in pmu.properties().unwrap_or_default() {
            let Some(bit) = name
                .strip_prefix(b"event_name-bit")
                .and_then(|digits| core::str::from_utf8(digits).ok())
                .and_then(|digits| digits.parse::<u8>().ok())
                .filter(|&bit| bit < 64)
            else {
                continue;
            };
            match value.split(|&b| b == 0).next() {
                Some(b"pwrbtn") => wake_bits.power_button = Some(bit),
                Some(b"rtc") => wake_bits.rtc = Some(bit),
                _ => {}
            }
        }
        let phandle = pmu
            .first_u32("AAPL,phandle")
            .ok_or("smc-pmu has no phandle")?;
        root.visit(&mut |candidate| {
            for (name, value) in candidate.properties().unwrap_or_default() {
                if name.starts_with(b"function-")
                    && let Some([provider, function, key, _]) = cells_of(value)
                    && provider == phandle
                    && function == SMC_GPIO_WRITE
                {
                    gpio_keys.push(key);
                }
            }
        })
        .ok_or("DeviceTree walk failed")?;
    }
    gpio_keys.sort_unstable();
    gpio_keys.dedup();
    Ok(Some(SmcController {
        wrapper,
        interrupts,
        watchdog,
        region: (base, size),
        gpio_keys,
        quiesced: nub.property("quiesced").is_some(),
        wake_bits,
    }))
}

#[cfg(test)]
mod tests {
    use super::super::tests::flat_fixture_extent;
    use super::super::*;
    use super::*;

    /// The J473AP SMC subtree: its wrapper and watchdog banks, the nub's
    /// shared-page region and the `pKW4` functions other nodes route
    /// through `smc-pmu`.
    #[test]
    fn smc_placement_reads_its_banks_region_and_function_keys() {
        use crate::machine::adt::encode;
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
        let function =
            |key: &[u8; 4], value: u32| cells(&[0x91, smc::code(b"pKW4"), smc::code(key), value]);
        let tree = |region_size: u64| {
            let pmu = encode(
                // Hidden: the loader removed its compatible.
                &[
                    ("name", &z("smc-pmu")),
                    ("AAPL,phandle", &cells(&[0x91])),
                    ("event_name-bit0", &z("pwrbtn")),
                    ("event_name-bit13", &z("wifibt")),
                    ("event_name-bit48", &z("rtc")),
                ],
                &[],
            );
            let nub = encode(
                &[
                    ("name", &z("iop-smc-nub")),
                    ("compatible", &z(RTBUDDY)),
                    ("region-base", &0x2_3fe0_0000u64.to_le_bytes()),
                    ("region-size", &region_size.to_le_bytes()),
                    ("quiesced", &[]),
                ],
                &[pmu],
            );
            let smc = encode(
                &[
                    ("name", &z("smc")),
                    ("compatible", &z(ASC)),
                    ("role", &z("SMC")),
                    (
                        "reg",
                        &pairs(&[
                            (0x3e40_0000, 0x6c000),
                            (0x3e05_0000, 0x4000),
                            (0x3e81_0000, 0x14),
                        ]),
                    ),
                    ("interrupts", &cells(&[0x1f4, 0x1f3, 0x1f6, 0x1f5])),
                    ("timers-reg-index", &cells(&[2])),
                ],
                &[nub],
            );
            let hdmi = encode(
                &[
                    ("name", &z("dp2hdmi-gpio")),
                    ("function-reset", &function(b"gP09", 0x100)),
                    ("function-hdmi_pwr_en", &function(b"gP16", 0x8000)),
                ],
                &[],
            );
            let standby = encode(
                &[
                    ("name", &z("pmu-main")),
                    (
                        "function-external_standby",
                        &cells(&[0x91, smc::code(b"keyW"), smc::code(b"MBSE")]),
                    ),
                ],
                &[],
            );
            let io = encode(&[("name", &z("arm-io"))], &[smc, hdmi, standby]);
            let amfm = encode(
                &[
                    ("name", &z("amfm")),
                    ("function-reg_on", &function(b"gP0d", 0x8000)),
                ],
                &[],
            );
            encode(&[("name", &z("device-tree"))], &[io, amfm])
        };
        let bytes = tree(0x10_0000);
        let root = Node::root(&bytes).unwrap();
        let io = root.child("arm-io").unwrap();
        let translate = |offset| Some(0x2_0000_0000 + offset);
        let placed = smc_controller(&root, &io, &flat_fixture_extent(&translate))
            .unwrap()
            .unwrap();
        assert_eq!(placed.wrapper, (0x2_3e40_0000, 0x6c000));
        assert_eq!(placed.watchdog, Some((0x2_3e81_0000, 0x14)));
        assert_eq!(placed.interrupts, [0x1f4, 0x1f3, 0x1f6, 0x1f5]);
        assert_eq!(placed.region, (0x2_3fe0_0000, 0x10_0000));
        assert!(placed.quiesced);
        assert_eq!(
            placed.wake_bits,
            smc::WakeBits {
                power_button: Some(0),
                rtc: Some(48),
            }
        );
        // Sorted; `keyW` is not a GPIO write.
        assert_eq!(
            placed.gpio_keys,
            [smc::code(b"gP09"), smc::code(b"gP0d"), smc::code(b"gP16")]
        );
        let small = tree(0x1000);
        let root = Node::root(&small).unwrap();
        let io = root.child("arm-io").unwrap();
        assert!(smc_controller(&root, &io, &flat_fixture_extent(&translate)).is_err());
        // The SMC claim owns its nub and the nub's PMU child; the buttons
        // the PMU provides are a modeled compatible.
        let smc_role = |key: &str| (key == "role").then_some(b"SMC\0".as_slice());
        let [nub] = model_children(ASC, smc_role) else {
            panic!("the SMC claim owns one nub");
        };
        assert_eq!(nub.compatible, RTBUDDY);
        assert_eq!(
            nub.children
                .iter()
                .map(|child| child.compatible)
                .collect::<Vec<_>>(),
            [SMC_PMU]
        );
        assert!(models(BUTTONS, |_| None));
        assert!(!models(SMC_PMU, |_| None));
    }
}
