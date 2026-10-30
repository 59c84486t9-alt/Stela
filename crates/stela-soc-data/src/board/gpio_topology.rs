//! DeviceTree placement and validation for gpio topology.
use super::GPIO;
use super::GPIO_FUNCTION;
use super::GPIO_S5L;
use super::GPIO_T6000;
use super::Node;
use super::String;
use super::Vec;
use super::single_range;
use super::spmi_topology::cells_of;
use crate::Result;
use stela_contracts::refusal::Within;
use stela_contracts::refuse;

/// Compatible identifies register semantics, while role bounds the checked
/// board owner. Only the AP S5L bank is admitted: auxiliary restoration,
/// wake groups and nets remain explicit unchecked board dependencies.
pub(super) fn gpio_profile<'a>(
    property: impl Fn(&str) -> Option<&'a [u8]>,
) -> Option<crate::gpio::Profile> {
    let compatibles = property("compatible")?;
    let has = |name: &str| {
        compatibles
            .split(|byte| *byte == 0)
            .any(|c| c == name.as_bytes())
    };
    match (has(GPIO), has(GPIO_T6000), has(GPIO_S5L)) {
        (true, false, false) => Some(crate::gpio::Profile::T8101),
        (false, true, true) if property("role") == Some(b"AP\0".as_slice()) => {
            Some(crate::gpio::Profile::S5l8960x)
        }
        _ => None,
    }
}

/// The visible AP GPIO bank, from `reg`, `#gpio-pins`, its AIC-parented
/// `interrupts` (one per `#gpio-int-groups`) and phandle, with the board's
/// pulled-up I2C lines in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpioBank {
    pub profile: crate::gpio::Profile,
    /// Original software restoration exclusions. The device model does not
    /// restore pads or implement global 0xc48/wake from this metadata.
    pub no_restore_pins: Vec<u32>,
    pub physical: u64,
    pub bytes: u64,
    pub pins: u32,
    /// `#gpio-int-groups`; the first `lines.len()` have an AIC line.
    pub groups: u32,
    pub phandle: u32,
    pub lines: Vec<u16>,
    /// The ADT's `gpio-iic_scl`/`gpio-iic_sda` pins in this bank.
    pub i2c_lines: Vec<u32>,
}

pub(super) fn gpio_bank(
    io: &Node<'_>,
    translate: &dyn Fn(u64, u64) -> Option<u64>,
    aic: u32,
) -> Result<Option<GpioBank>> {
    let Some(node) = AP_GPIO_NAMES
        .iter()
        .find_map(|name| io.child(name))
        .filter(|n| gpio_profile(|key| n.property(key)).is_some())
    else {
        return Ok(None);
    };
    let mut bank = gpio_geometry(&node, translate, aic)?;
    bank.i2c_lines = i2c_lines(io, bank.pins)?;
    Ok(Some(bank))
}

/// Another visible GPIO bank (`gpio,t8101` under `/arm-io` other than the
/// AP's `gpio`: J473AP's `aop-gpio` and `smc-gpio`), and the pins its
/// clients name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuxGpioBank {
    pub name: String,
    pub bank: GpioBank,
    /// Pins the tree's other nodes use: each `interrupts` pin of a node
    /// whose `interrupt-parent` is the bank (`[pin, flags]` pairs) and each
    /// `function-*` GPIO pin on it (`[bank, 'GPIO', pin, flags]`), such as
    /// `dp2hdmi-gpio`'s HDMI hot-plug input, `aop-gpio` pin 0x31.
    pub client_pins: Vec<u32>,
}

pub(super) fn aux_gpio_banks(
    root: &Node<'_>,
    io: &Node<'_>,
    translate: &dyn Fn(u64, u64) -> Option<u64>,
    aic: u32,
) -> Result<Vec<AuxGpioBank>> {
    let mut banks = Vec::new();
    for node in io
        .children()
        .ok_or(refuse!("/arm-io children are malformed"))?
    {
        let name = node
            .property("name")
            .and_then(|name| core::str::from_utf8(name).ok())
            .map(|name| name.trim_end_matches('\0'))
            .unwrap_or_default();
        if AP_GPIO_NAMES.contains(&name) || !node.compatible(GPIO) {
            continue;
        }
        let bank = gpio_geometry(&node, translate, aic).within(|| refuse!("{name}", name))?;
        let mut client_pins = Vec::new();
        root.visit(&mut |client| {
            if client.first_u32("interrupt-parent") == Some(bank.phandle)
                && let Some(cells) = client.cells32("interrupts")
            {
                client_pins.extend(cells.as_chunks::<2>().0.iter().map(|[pin, _]| *pin));
            }
            for (property, value) in client.properties().unwrap_or_default() {
                if property.starts_with(b"function-")
                    && let Some([provider, GPIO_FUNCTION, pin, _]) = cells_of(value)
                    && provider == bank.phandle
                {
                    client_pins.push(pin);
                }
            }
        })
        .ok_or(refuse!("DeviceTree walk failed"))?;
        client_pins.sort_unstable();
        client_pins.dedup();
        if let Some(&pin) = client_pins.iter().find(|&&pin| pin >= bank.pins) {
            return Err(refuse!(
                "{name}: a client names pin {pin} past the bank",
                name,
                pin
            ));
        }
        banks.push(AuxGpioBank {
            name: name.into(),
            bank,
            client_pins,
        });
    }
    Ok(banks)
}

/// The AP GPIO bank's node: `gpio` in the M1 and M2 DeviceTrees, `gpio0`
/// (die 0) in the M2 Pro and Max and every later one (J414sAP, J504AP).
const AP_GPIO_NAMES: [&str; 2] = ["gpio", "gpio0"];

/// The pin words a bank's `#gpio-pins` may name (`platform::apple::gpio`).
const GPIO_PINS: u32 = 512;

/// The first interrupt group's status bank and the stride between groups
/// (`platform::apple::gpio`).
const GPIO_IRQ_BASE: u64 = 0x800;

const GPIO_IRQ_STRIDE: u64 = 0x40;

/// A `gpio,t8101` node's registers, pins, groups and AIC lines: up to
/// [`crate::gpio::GROUPS`] interrupt groups, the first of which have the node's
/// `interrupts` as their lines.
fn gpio_geometry(
    node: &Node<'_>,
    translate: &dyn Fn(u64, u64) -> Option<u64>,
    aic: u32,
) -> Result<GpioBank> {
    let (physical, bytes) = single_range(node, translate)?;
    let pins = node
        .first_u32("#gpio-pins")
        .ok_or(refuse!("GPIO pin count missing"))?;
    let groups = node
        .first_u32("#gpio-int-groups")
        .ok_or(refuse!("GPIO group count missing"))?;
    let lines = node
        .cells32("interrupts")
        .ok_or(refuse!("GPIO interrupts missing"))?
        .into_iter()
        .map(|irq| u16::try_from(irq).map_err(|_| refuse!("GPIO interrupt too large")))
        .collect::<Result<Vec<_>, _>>()?;
    if pins == 0
        || pins > GPIO_PINS
        || !(1..=crate::gpio::GROUPS as u32).contains(&groups)
        || lines.is_empty()
        || lines.len() > groups as usize
        || node.first_u32("interrupt-parent") != Some(aic)
        || bytes < GPIO_IRQ_BASE + u64::from(groups) * GPIO_IRQ_STRIDE
    {
        return Err(refuse!("unsupported GPIO geometry or interrupt parent"));
    }
    let profile = gpio_profile(|key| node.property(key)).ok_or(refuse!(
        "GPIO register profile or board role is unqualified"
    ))?;
    let no_restore_pins = match node.property("no-restore-gpio-pins") {
        None => Vec::new(),
        Some(raw) if raw.len().is_multiple_of(4) => {
            let values = node.cells32("no-restore-gpio-pins").unwrap_or_default();
            if values
                .iter()
                .enumerate()
                .any(|(index, pin)| *pin >= pins || values[..index].contains(pin))
            {
                return Err(refuse!(
                    "GPIO restoration exclusions contain an invalid or duplicate pin"
                ));
            }
            values
        }
        Some(_) => return Err(refuse!("GPIO restoration exclusions have incomplete cells")),
    };
    if profile == crate::gpio::Profile::S5l8960x
        && [
            "no-resume-restore",
            "supported-int-groups",
            "wake-events",
            "wake-no-interrupt-group",
        ]
        .iter()
        .any(|key| node.property(key).is_some())
    {
        return Err(refuse!(
            "S5L AP GPIO restoration/wake overrides are unqualified"
        ));
    }
    Ok(GpioBank {
        profile,
        no_restore_pins,
        physical,
        bytes,
        pins,
        groups,
        phandle: node
            .first_u32("AAPL,phandle")
            .ok_or(refuse!("GPIO phandle missing"))?,
        lines,
        i2c_lines: Vec::new(),
    })
}

/// The ADT cell naming the AP GPIO bank in a `gpio-iic_*` pin property
/// (`[pin, flags, bank]`); the AOP bank's pins (`AOP`) are not in it.
pub(super) const AP_GPIO_BANK: u32 = 0x5041;

/// Every AP-bank pin an `arm-io` I2C node names as its SCL or SDA line.
pub(super) fn i2c_lines(io: &Node<'_>, pins: u32) -> Result<Vec<u32>> {
    let mut lines = Vec::new();
    let mut failure = None;
    io.visit(&mut |node| {
        for name in ["gpio-iic_scl", "gpio-iic_sda"] {
            let Some(cells) = node.cells32(name) else {
                continue;
            };
            match cells[..] {
                [pin, _, AP_GPIO_BANK] if pin < pins => lines.push(pin),
                [_, _, bank] if bank != AP_GPIO_BANK => {}
                _ => failure = Some(refuse!("unsupported {name} pin encoding", name)),
            }
        }
    })
    .ok_or(refuse!("I2C line walk failed"))?;
    match failure {
        Some(error) => Err(error),
        None => Ok(lines),
    }
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use super::*;
    use crate::board::fixture_support::flat_fixture_extent;

    #[test]
    fn s5l_gpio_admission_requires_checked_pair_and_ap_role() {
        let compatible = b"gpio,t6000\0gpio,s5l8960x\0";
        for role in [
            b"AP\0".as_slice(),
            b"AOP\0",
            b"SMC\0",
            b"NUB\0",
            b"unknown\0",
        ] {
            let property = |key: &str| match key {
                "compatible" => Some(compatible.as_slice()),
                "role" => Some(role),
                _ => None,
            };
            for name in [GPIO_T6000, GPIO_S5L] {
                assert_eq!(models(name, property), role == b"AP\0");
            }
        }
        for compatible in [
            b"gpio,s5l8960x\0".as_slice(),
            b"gpio,t9999\0gpio,s5l8960x\0",
            b"gpio,t6000\0gpio,t8101\0gpio,s5l8960x\0",
        ] {
            assert!(!models(GPIO_S5L, |key| match key {
                "compatible" => Some(compatible),
                "role" => Some(b"AP\0"),
                _ => None,
            }));
        }
    }

    #[test]
    fn s5l_ap_geometry_preserves_validated_restoration_exclusions() {
        use stela_contracts::adt::encode;
        let make = |excluded: &[u8], override_key: Option<&str>| {
            let reg = [0x19b028000u64, 0x4000]
                .into_iter()
                .flat_map(u64::to_le_bytes)
                .collect::<Vec<_>>();
            let irqs = (427u32..434).flat_map(u32::to_le_bytes).collect::<Vec<_>>();
            let pins = 255u32.to_le_bytes();
            let groups = 7u32.to_le_bytes();
            let parent = 130u32.to_le_bytes();
            let phandle = 136u32.to_le_bytes();
            let mut properties = vec![
                ("compatible", b"gpio,t6000\0gpio,s5l8960x\0".as_slice()),
                ("role", b"AP\0"),
                ("reg", reg.as_slice()),
                ("#gpio-pins", &pins),
                ("#gpio-int-groups", &groups),
                ("interrupt-parent", &parent),
                ("interrupts", irqs.as_slice()),
                ("AAPL,phandle", &phandle),
                ("no-restore-gpio-pins", excluded),
            ];
            if let Some(key) = override_key {
                properties.push((key, b""));
            }
            encode(&properties, &[])
        };
        let excluded = [114u32, 115, 119]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        let data = make(&excluded, None);
        let bank = gpio_geometry(
            &Node::root(&data).unwrap(),
            &flat_fixture_extent(&|value| value.checked_add(0x200000000)),
            130,
        )
        .unwrap();
        assert_eq!(bank.profile, crate::gpio::Profile::S5l8960x);
        assert_eq!(bank.physical, 0x39b028000);
        assert_eq!(bank.no_restore_pins, [114, 115, 119]);
        for values in [vec![114u32, 114], vec![255], vec![u32::MAX]] {
            let raw = values
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect::<Vec<_>>();
            let data = make(&raw, None);
            assert!(
                gpio_geometry(
                    &Node::root(&data).unwrap(),
                    &flat_fixture_extent(&Some),
                    130
                )
                .is_err()
            );
        }
        let data = make(&excluded[..3], None);
        assert!(
            gpio_geometry(
                &Node::root(&data).unwrap(),
                &flat_fixture_extent(&Some),
                130
            )
            .is_err()
        );
        for key in [
            "no-resume-restore",
            "supported-int-groups",
            "wake-events",
            "wake-no-interrupt-group",
        ] {
            let data = make(&excluded, Some(key));
            assert!(
                gpio_geometry(
                    &Node::root(&data).unwrap(),
                    &flat_fixture_extent(&Some),
                    130
                )
                .is_err()
            );
        }
    }

    #[test]
    fn other_gpio_banks_carry_the_pins_their_clients_name() {
        use stela_contracts::adt::encode;
        let words = |v: &[u32]| v.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<_>>();
        let pairs = |v: &[u64]| v.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<_>>();
        // J473AP's aop-gpio, its dp2hdmi-gpio client and a hidden smc-gpio.
        let aop = encode(
            &[
                ("name", b"aop-gpio\0"),
                ("compatible", b"gpio,t8101\0"),
                ("reg", &pairs(&[0x4a820000, 0x4000])),
                ("#gpio-pins", &words(&[0x36])),
                ("#gpio-int-groups", &words(&[7])),
                ("AAPL,phandle", &words(&[0x6b])),
                ("interrupt-parent", &words(&[99])),
                (
                    "interrupts",
                    &words(&[0x12d, 0x12e, 0x12f, 0x130, 0x131, 0x132, 0x133]),
                ),
            ],
            &[],
        );
        let hidden = encode(
            &[
                ("name", b"smc-gpio\0"),
                ("reg", &pairs(&[0x3e820000, 0x4000])),
                ("AAPL,phandle", &words(&[0x6d])),
            ],
            &[],
        );
        let client = encode(
            &[
                ("name", b"dp2hdmi-gpio\0"),
                ("interrupt-parent", &words(&[0x6b])),
                ("interrupts", &words(&[0x31, 0x500_0004])),
                (
                    "function-hdmi_hpd",
                    &words(&[0x6b, GPIO_FUNCTION, 0x31, 0x100]),
                ),
                (
                    "function-force-dpfu",
                    &words(&[0x6b, GPIO_FUNCTION, 0x28, 0x1]),
                ),
                (
                    "function-hdmi_pwr_en",
                    &words(&[0x91, u32::from_be_bytes(*b"pKW4"), 0x6750_3136, 0x80_0000]),
                ),
            ],
            &[],
        );
        let io = encode(&[("name", b"arm-io\0")], &[aop, hidden, client]);
        let data = encode(&[("name", b"device-tree\0")], &[io]);
        let root = Node::root(&data).unwrap();
        let io = root.child("arm-io").unwrap();
        let translate = |v: u64| v.checked_add(0x2_0000_0000);
        let banks = aux_gpio_banks(&root, &io, &flat_fixture_extent(&translate), 99).unwrap();
        assert_eq!(banks.len(), 1);
        assert_eq!(banks[0].name, "aop-gpio");
        assert_eq!(banks[0].bank.physical, 0x2_4a82_0000);
        assert_eq!(banks[0].bank.pins, 0x36);
        assert_eq!(banks[0].client_pins, [0x28, 0x31]);
        assert!(aux_gpio_banks(&root, &io, &flat_fixture_extent(&translate), 100).is_err());
    }

    #[test]
    fn gpio_aperture_requires_complete_source_ranges_before_any_bank_is_returned() {
        use stela_contracts::adt::encode;
        let raw = [0u64, 0x1000]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect::<Vec<_>>();
        for (rows, expected) in [
            (
                vec![
                    (0u64, 0x200000000u64, 0x800u64),
                    (0x800, 0x200000800, 0x800),
                ],
                true,
            ),
            (
                vec![(0, 0x200000000, 0x800), (0x900, 0x200000900, 0x700)],
                false,
            ),
            (
                vec![(0, 0x200000000, 0x800), (0x800, 0x300000800, 0x800)],
                false,
            ),
        ] {
            let ranges = rows
                .into_iter()
                .flat_map(|(a, b, c)| [a, b, c])
                .flat_map(u64::to_le_bytes)
                .collect::<Vec<_>>();
            for trailing in [false, true] {
                let mut reg = raw.clone();
                if trailing {
                    reg.push(0);
                }
                let gpio = encode(
                    &[
                        ("name", b"gpio"),
                        ("compatible", b"gpio,t8101\0"),
                        ("reg", &reg),
                        ("#gpio-pins", &2u32.to_le_bytes()),
                        ("#gpio-int-groups", &1u32.to_le_bytes()),
                        ("interrupts", &7u32.to_le_bytes()),
                        ("interrupt-parent", &9u32.to_le_bytes()),
                        ("AAPL,phandle", &4u32.to_le_bytes()),
                    ],
                    &[],
                );
                let tree = encode(&[("name", b"arm-io"), ("ranges", &ranges)], &[gpio]);
                let io = Node::root(&tree).unwrap();
                let actual = gpio_bank(&io, &|a, b| io.translate_range(a, b), 9);
                assert_eq!(actual.is_ok(), expected && !trailing);
            }
        }
    }
}
