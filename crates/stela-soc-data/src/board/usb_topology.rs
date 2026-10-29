//! DeviceTree placement and validation for usb topology.
use super::dma_routes::{native_dma_phandle, native_mapper_input};
use super::{
    ATC_PHY, Device, GpioBank, HPM, HPM_MANAGER, Iommu, Node, String, Vec, apertures, atc_phy,
    format, i2c,
};

/// The ATC PHY register layouts, selected by the primary compatible.
/// `AppleT8103TypeCPhy` binds all of them. The T8103 (J274AP) and
/// T6020 (J414sAP, `atc-phy,t6020` then `atc-phy,t8112`) views are the
/// T8112 (J473AP) views without its last, core+0x4c000, which is beyond the
/// canonical core window. The views the model places (USB2, event block,
/// core+0x20000, core) are views 0 to 3 in each.
pub(super) const ATC_PHY_LAYOUTS: [(&str, usize); 4] = [
    (ATC_PHY, ATC_PHY_BASE_VIEWS + 1),
    ("atc-phy,t6020", ATC_PHY_BASE_VIEWS),
    ("atc-phy,t8103", ATC_PHY_BASE_VIEWS),
    ("atc-phy,t6000", ATC_PHY_BASE_VIEWS),
];

/// The ADT views every [`ATC_PHY_LAYOUTS`] layout starts with.
const ATC_PHY_BASE_VIEWS: usize = 28;

/// Qualified Apple I2C register families. The original 26A434 ADTs use
/// these first compatibles ahead of `i2c,s5l8940x` and `iic,soft`; the latter
/// fallback strings alone do not establish a modelled Apple register file.
/// T6000 and T6020 retain the same one-bank byte-FIFO interface (`i2c`).
const I2C_COMPATIBLES: &[&str] = &["i2c,t8101", "i2c,t6000", "i2c,t6020"];

/// USB DRD families whose nine-view layout is qualified. The original
/// 26A434 ADTs give M1/T6000
/// a 0x1800-byte reg[2], versus 0x5800 on M2/T6020 and M3/T8122. In each,
/// reg[2] begins at reg[0]+0xc000 and reg[8] at reg[0]+0xd000.
/// Later families move reg[8] or add a tenth view and are not aliases.
const USB_DRD_LAYOUTS: &[(&str, u64)] = &[
    ("usb-drd,t8103", 0x1800),
    ("usb-drd,t6000", 0x1800),
    ("usb-drd,t8112", 0x5800),
    ("usb-drd,t6020", 0x5800),
    ("usb-drd,t8122", 0x5800),
];

/// Validate the complete property before admitting any of its family names.
/// A missing property supports the loader's pure family-name queries.
pub fn i2c_compatible(name: &str, compatibles: Option<&[u8]>) -> bool {
    I2C_COMPATIBLES.contains(&name)
        && compatibles.is_none_or(|raw| {
            compatible_list(raw).is_some_and(|list| {
                let mut entries = list.split('\0');
                entries
                    .next()
                    .is_some_and(|first| I2C_COMPATIBLES.contains(&first))
                    && entries.all(|entry| {
                        I2C_COMPATIBLES.contains(&entry)
                            || ["i2c,s5l8940x", "iic,soft"].contains(&entry)
                    })
                    && list.split('\0').any(|entry| entry == name)
            })
        })
}

/// Whether the full property selects a qualified nine-view USB DRD family.
pub fn usb_controller_compatible(name: &str, compatibles: Option<&[u8]>) -> bool {
    USB_DRD_LAYOUTS.iter().any(|&(family, _)| family == name)
        && compatibles.is_none_or(|raw| {
            usb_layout(raw).is_some()
                && compatible_list(raw)
                    .is_some_and(|list| list.split('\0').any(|entry| entry == name))
        })
}

/// Whether the full property selects a qualified ATC PHY register layout.
pub fn atc_phy_compatible(name: &str, compatibles: Option<&[u8]>) -> bool {
    ATC_PHY_LAYOUTS.iter().any(|&(family, _)| family == name)
        && compatibles.is_none_or(|raw| {
            atc_layout(raw).is_some()
                && compatible_list(raw)
                    .is_some_and(|list| list.split('\0').any(|entry| entry == name))
        })
}

fn compatible_list(raw: &[u8]) -> Option<&str> {
    let list = core::str::from_utf8(raw).ok()?.trim_end_matches('\0');
    (!list.is_empty() && list.split('\0').all(|entry| !entry.is_empty())).then_some(list)
}

fn usb_layout(raw: &[u8]) -> Option<u64> {
    let mut entries = compatible_list(raw)?.split('\0');
    let first = entries.next()?;
    let (_, bytes) = USB_DRD_LAYOUTS.iter().find(|&&(name, _)| name == first)?;
    entries
        .all(|entry| USB_DRD_LAYOUTS.contains(&(entry, *bytes)))
        .then_some(*bytes)
}

fn atc_layout(raw: &[u8]) -> Option<(&'static str, usize)> {
    let mut entries = compatible_list(raw)?.split('\0');
    let first = entries.next()?;
    let &(primary, count) = ATC_PHY_LAYOUTS.iter().find(|&&(name, _)| name == first)?;
    entries
        .all(|entry| {
            ATC_PHY_LAYOUTS.contains(&(entry, count))
            // Original T6020 lists this 29-view fallback after its 28-view primary.
            || (primary == "atc-phy,t6020" && entry == ATC_PHY)
        })
        .then_some((primary, count))
}

pub(super) fn is_usb_controller(node: &Node<'_>) -> bool {
    node.property("compatible")
        .is_some_and(|raw| usb_layout(raw).is_some())
}

pub(super) fn is_typec_phy(node: &Node<'_>) -> bool {
    node.property("compatible")
        .is_some_and(|raw| atc_layout(raw).is_some())
}

/// Recognize candidates independently of qualification so unsupported families
/// produce a named refusal, including malformed lists with a known fallback.
fn family_candidate(node: &Node<'_>, prefix: &[u8]) -> bool {
    node.property("compatible").is_some_and(|raw| {
        raw.split(|&byte| byte == 0)
            .any(|entry| entry.starts_with(prefix))
    })
}

fn usb_alias_bytes(node: &Node<'_>) -> Option<u64> {
    usb_layout(node.property("compatible")?)
}

/// Nine ADT windows, five interrupt inputs and the mapper-selected DMA
/// stream. Apple reg[2]/reg[8] overlap reg[0]; preserve their physical alias.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsbController {
    pub ranges: [(u64, u64); 9],
    pub irqs: [u32; 5],
    pub iommu: usize,
    /// Actual owner identities; context survives native incoming assignment.
    pub phandle: Option<u32>,
    pub mapper: u32,
    pub mapper_context: u32,
    pub stream: u32,
    /// The Type-C connector's `port-number`, shared with its HPM die.
    pub port: u32,
    /// Ordinary controller state survives supply gating only when declared.
    pub retention: bool,
    /// Actual digital PHY provider (`atc-phy-parent`), never inferred from
    /// the connector's display name or ordinal.
    pub phy: u32,
}

/// An I2C child address is the first 32-bit `reg` cell followed by bus
/// timing, not a 64-bit MMIO address. HPM nubs instead use `hpm-iic-addr`.
/// `interrupt` is the AP GPIO pin of a target's own GPIO-parented
/// `interrupts`; an HPM has none of its own and shares its `iicProvider` bus
/// manager's line, which the dies' open-drain interrupt outputs drive.
/// `firmware` is the `usbc-fw-personality` of an HPM's image. A DT names it
/// only on dies the restore updater flashes (`usbc-flash-update`), and the
/// images name the dies they serve by `rid`: J456AP's hpm0 runs
/// `HPM,30` (configuration board string "J456P01", rids 0 and 1) and hpm2
/// `HPM,30-P23` (rids 2 and 3); J180dAP pairs P01, P23, P45 and P67 the
/// same way. On every registry board an unnamed die has the
/// `transports-supported` of the named die with the greatest lower `rid` on
/// its bus manager, and runs that die's image: J473AP's hpm1 runs hpm0's,
/// and J474sAP's rids 1 to 3 all run rid 0's. `port` is an HPM's connector
/// `port-number`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct I2cAddress {
    pub address: u8,
    pub compatible: String,
    pub interrupt: Option<u32>,
    pub firmware: Option<String>,
    pub port: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct I2cController {
    pub device: Device,
    pub targets: Vec<I2cAddress>,
}

/// The guest file name of the image an HPM die with `personality` runs: the
/// name macOS keeps it under in `/usr/standalone/firmware`.
pub fn hpm_firmware_file(personality: &str) -> String {
    format!("USB-C_{personality}.bin")
}

/// Digital PHY placement preserves all ADT views for evidence, but maps the
/// canonical USB2/core regions once. The pipehandler belongs to the same PHY
/// via `usb-drd*/atc-phy-parent`, whose `reg[3]` supplies its aperture; its
/// `reg[4]` is the PHY's own view 1, the core event block
/// (`AppleT8103TypeCPhy::initRegisterSpaces` keeps view n at +0x158 + 16n).
/// A PHY no `usb-drd` names (J414sAP `atc-phy3`, whose port has no USB
/// controller) has no pipehandler.
/// Unqualified shared fuse, AXI and analog-only views are not claimed here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypecPhy {
    pub phandle: u32,
    pub retention: bool,
    pub views: Vec<(u64, u64)>,
    pub usb2: (u64, u64),
    pub core: (u64, u64),
    pub pipe: Option<(u64, u64)>,
    pub events: (u64, u64),
    pub port: u32,
}

pub(super) fn typec_devices(
    io: &Node<'_>,
    translate: &dyn Fn(u64, u64) -> Option<u64>,
    aic: u32,
    gpio: Option<&GpioBank>,
) -> Result<(Vec<I2cController>, Vec<TypecPhy>), String> {
    let mut i2cs = Vec::new();
    let mut phys = Vec::new();
    let mut failure = None;
    let root_translate = translate;
    apertures::visit(io, root_translate, &mut |node, translate| {
        let place = |(offset, bytes): (u64, u64)| -> Result<_, String> {
            let first =
                translate(offset, bytes).ok_or("Type-C range starts outside arm-io ranges")?;
            Ok((first, bytes))
        };

        if failure.is_some() {
            return;
        }
        let result = (|| -> Result<(), String> {
            if family_candidate(node, b"i2c,") || family_candidate(node, b"iic,") {
                let raw = node.property("compatible").unwrap();
                if !I2C_COMPATIBLES
                    .iter()
                    .any(|name| i2c_compatible(name, Some(raw)))
                {
                    return Err("I2C controller has no qualified compatible list".into());
                }
                let regs = apertures::registers(node).ok_or("I2C controller has no reg pairs")?;
                let &[range] = regs.as_slice() else {
                    return Err("I2C controller requires one reg range".into());
                };
                let (physical, bytes) = place(range)?;
                if bytes != i2c::BYTES
                    || !physical.is_multiple_of(i2c::BYTES)
                    || node.first_u32("interrupt-parent") != Some(aic)
                {
                    return Err("unsupported I2C aperture or interrupt parent".into());
                }
                let irq = node
                    .first_u32("interrupts")
                    .filter(|&i| u16::try_from(i).is_ok())
                    .ok_or("I2C interrupt is absent or too large")?;
                let mut targets = Vec::new();
                // Each target's phandle and, for an HPM, its provider and rid.
                let mut links: Vec<(Option<u32>, Option<u32>, Option<u32>)> = Vec::new();
                let mut bad = None;
                let mut first = true;
                node.visit(&mut |target| {
                    if first {
                        first = false;
                        return;
                    }
                    let Some(compatible) = target
                        .property("compatible")
                        .and_then(|b| b.split(|b| *b == 0).next())
                        .and_then(|b| core::str::from_utf8(b).ok())
                    else {
                        return;
                    };
                    let address = if target.compatible(HPM) {
                        target.first_u32("hpm-iic-addr")
                    } else {
                        target.first_u32("reg")
                    };
                    let interrupt = match target.cells32("interrupts").as_deref() {
                        None => None,
                        Some(&[pin, _]) => match gpio {
                            Some(gpio)
                                if target.first_u32("interrupt-parent") == Some(gpio.phandle)
                                    && pin < gpio.pins =>
                            {
                                Some(pin)
                            }
                            _ => {
                                bad = Some("I2C target interrupt is not a visible AP GPIO pin");
                                return;
                            }
                        },
                        Some(_) => {
                            bad = Some("unsupported I2C target interrupt encoding");
                            return;
                        }
                    };
                    let firmware = target
                        .property("usbc-fw-personality")
                        .and_then(|b| b.split(|b| *b == 0).next())
                        .and_then(|b| core::str::from_utf8(b).ok())
                        .filter(|name| !name.is_empty())
                        .map(String::from);
                    match address
                        .and_then(|v| u8::try_from(v).ok())
                        .filter(|&v| v > 0 && v < 0x78)
                    {
                        Some(address)
                            if !targets.iter().any(|t: &I2cAddress| t.address == address) =>
                        {
                            let hpm = |name| {
                                target
                                    .compatible(HPM)
                                    .then(|| target.first_u32(name))
                                    .flatten()
                            };
                            links.push((
                                target.first_u32("AAPL,phandle"),
                                hpm("iicProvider"),
                                hpm("rid"),
                            ));
                            targets.push(I2cAddress {
                                address,
                                compatible: compatible.into(),
                                interrupt,
                                firmware,
                                port: target
                                    .compatible(HPM)
                                    .then(|| target.first_u32("port-number"))
                                    .flatten(),
                            })
                        }
                        _ => {
                            bad = Some(
                                "I2C target has an invalid, missing or duplicate seven-bit address",
                            )
                        }
                    }
                })
                .ok_or("I2C target walk failed")?;
                if let Some(error) = bad {
                    return Err(error.into());
                }
                // The images the dies name themselves, before partners share.
                let named: Vec<Option<String>> =
                    targets.iter().map(|t| t.firmware.clone()).collect();
                for index in 0..targets.len() {
                    if targets[index].compatible != HPM {
                        continue;
                    }
                    let provider = links[index]
                        .1
                        .and_then(|p| links.iter().position(|&(phandle, ..)| phandle == Some(p)))
                        .filter(|&p| targets[p].compatible == HPM_MANAGER)
                        .ok_or("HPM has no visible usbc,manager iicProvider")?;
                    if targets[index].interrupt.is_some() || targets[index].port.is_none() {
                        return Err("HPM lacks a port number or names its own interrupt".into());
                    }
                    targets[index].interrupt = targets[provider].interrupt;
                    if named[index].is_some() {
                        continue;
                    }
                    let rid = links[index].2.ok_or("HPM has no rid")?;
                    targets[index].firmware = (0..targets.len())
                        .filter(|&t| links[t].1 == links[index].1 && named[t].is_some())
                        .filter_map(|t| Some((links[t].2.filter(|&owner| owner < rid)?, t)))
                        .max()
                        .and_then(|(_, t)| named[t].clone());
                }
                i2cs.push(I2cController {
                    device: Device {
                        physical,
                        bytes,
                        irq,
                    },
                    targets,
                });
            }
            if family_candidate(node, b"atc-phy,") {
                let (layout, count) = node
                    .property("compatible")
                    .and_then(atc_layout)
                    .ok_or("ATC PHY has no qualified compatible list")?;
                let reg = apertures::registers(node).ok_or("ATC PHY has no reg pairs")?;
                if reg.len() != count {
                    return Err(format!(
                        "{layout} ATC PHY requires its {count} register views"
                    ));
                }
                let views = reg.into_iter().map(place).collect::<Result<Vec<_>, _>>()?;
                let usb2 = views[0];
                let core = (views[3].0, atc_phy::CORE_BYTES);
                if usb2.1 != atc_phy::WINDOW_BYTES
                    || views[2].0
                        != core
                            .0
                            .checked_add(0x20000)
                            .ok_or("ATC core address overflows")?
                {
                    return Err(format!(
                        "ATC USB2/core views disagree with the {layout} layout"
                    ));
                }
                let phandle =
                    native_dma_phandle(node, "AAPL,phandle")?.ok_or("ATC PHY has no phandle")?;
                let port = node
                    .first_u32("port-number")
                    .filter(|&p| p != 0)
                    .ok_or("ATC PHY has no port number")?;
                let mut controller_views = None;
                let mut duplicate = false;
                let mut invalid_controller = false;
                apertures::visit(io, root_translate, &mut |controller, controller_path| {
                    if controller.property("device_type") == Some(b"usb-drd\0".as_slice())
                        && controller.first_u32("atc-phy-parent") == Some(phandle)
                    {
                        duplicate |= controller_views.is_some();
                        controller_views = apertures::registers(controller).and_then(|r| {
                            let &(pipe, pipe_bytes) = r.get(3)?;
                            let &(events, event_bytes) = r.get(4)?;
                            Some((
                                (controller_path(pipe, pipe_bytes)?, pipe_bytes),
                                (controller_path(events, event_bytes)?, event_bytes),
                            ))
                        });
                        invalid_controller |= controller_views.is_none();
                    }
                })
                .ok_or("ATC controller walk failed")?;
                let events = views[1];
                let pipe = match controller_views {
                    Some((pipe, controller_events)) => {
                        if pipe.1 != atc_phy::WINDOW_BYTES || controller_events != events {
                            return Err(
                                "ATC controller's pipehandler or event view disagrees".into()
                            );
                        }
                        Some(pipe)
                    }
                    None => None,
                };
                if invalid_controller || duplicate || events.1 != atc_phy::WINDOW_BYTES {
                    return Err("ambiguous ATC controller or incomplete event view".into());
                }
                phys.push(TypecPhy {
                    phandle,
                    retention: node.property("retention").is_some(),
                    views,
                    usb2,
                    core,
                    pipe,
                    events,
                    port,
                });
            }
            Ok(())
        })();
        if let Err(error) = result {
            failure = Some(error);
        }
    })
    .ok_or("Type-C DeviceTree walk failed")?;
    if let Some(error) = failure {
        return Err(error);
    }
    Ok((i2cs, phys))
}

/// Every qualified early-family USB DRD, in DeviceTree order, with its
/// original reg/interrupts/iommu-parent (research transport section 1).
pub(super) fn usb_controllers(
    io: &Node<'_>,
    translate: &dyn Fn(u64, u64) -> Option<u64>,
    darts: &[Iommu],
) -> Result<Vec<UsbController>, String> {
    let mut controllers = Vec::new();
    let mut failure = None;
    apertures::visit(io, translate, &mut |node, translate| {
        if failure.is_none() && family_candidate(node, b"usb-drd,") {
            match usb_controller(node, translate, darts) {
                Ok(controller) => controllers.push(controller),
                Err(error) => failure = Some(error),
            }
        }
    })
    .ok_or("USB controller walk failed")?;
    failure.map_or(Ok(controllers), Err)
}

/// Resolve all arm-io ranges, including the identity USB window; no fixed
/// 8 GiB bias. The separate USB-DART worker owns multi-instance DART
/// parsing; this consumer uses the mapper stream that it publishes.
fn usb_controller(
    node: &Node<'_>,
    translate: &dyn Fn(u64, u64) -> Option<u64>,
    darts: &[Iommu],
) -> Result<UsbController, String> {
    let name = node
        .property("name")
        .and_then(|name| core::str::from_utf8(name.split(|&b| b == 0).next()?).ok())
        .unwrap_or("usb-drd");
    let err = |why: &str| format!("{name} {why}");
    let alias_bytes =
        usb_alias_bytes(node).ok_or_else(|| err("has no consistent qualified USB DRD layout"))?;
    let raw: [(u64, u64); 9] = apertures::registers(node)
        .unwrap_or_default()
        .try_into()
        .map_err(|_| err("requires nine register windows"))?;
    let mut ranges = [(0, 0); 9];
    for (slot, (offset, bytes)) in ranges.iter_mut().zip(raw) {
        if bytes == 0 {
            return Err(err("has an empty register extent"));
        }
        let physical = translate(offset, bytes).ok_or_else(|| err("lies outside arm-io ranges"))?;
        *slot = (physical, bytes);
    }
    if ranges[0].1 < 0x11800
        || ranges[0].0.checked_add(0xc000).map(|at| (at, alias_bytes)) != Some(ranges[2])
        || ranges[0].0.checked_add(0xd000).map(|at| (at, 0x4000)) != Some(ranges[8])
    {
        return Err(err("has an undescribed DWC3 alias layout"));
    }
    if [1, 3, 4, 5, 6, 7].iter().any(|&n| ranges[n].1 != 0x4000) {
        return Err(err("platform window is not 16 KiB"));
    }
    let irqs: [u32; 5] = node
        .cells32("interrupts")
        .unwrap_or_default()
        .try_into()
        .map_err(|_| err("requires five ADT interrupts"))?;
    if irqs.iter().any(|&irq| u16::try_from(irq).is_err()) {
        return Err(err("interrupt exceeds AIC input encoding"));
    }
    let phandle = native_dma_phandle(node, "AAPL,phandle").map_err(|why| err(&why))?;
    let parent = native_dma_phandle(node, "iommu-parent")
        .map_err(|why| err(&why))?
        .ok_or_else(|| err("has no iommu-parent"))?;
    let mut matching = darts.iter().enumerate().flat_map(|(index, dart)| {
        dart.mappers
            .iter()
            .filter(move |(phandle, _)| *phandle == parent)
            .map(move |&(_, stream)| (index, stream))
    });
    let (iommu, mapper_context) = matching
        .next()
        .ok_or_else(|| err("iommu-parent is no modeled DART mapper"))?;
    if matching.next().is_some() {
        return Err(err("iommu-parent is ambiguous"));
    }
    let stream = native_mapper_input(&darts[iommu], mapper_context).map_err(|why| err(&why))?;
    let port = node
        .first_u32("port-number")
        .filter(|&port| port != 0)
        .ok_or_else(|| err("has no Type-C port number"))?;
    Ok(UsbController {
        ranges,
        irqs,
        iommu,
        phandle,
        mapper: parent,
        mapper_context,
        stream,
        port,
        retention: node.property("retention").is_some(),
        phy: native_dma_phandle(node, "atc-phy-parent")
            .map_err(|why| err(&why))?
            .ok_or_else(|| err("has no atc-phy-parent"))?,
    })
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use super::*;
    use crate::board::fixture_support::{flat_fixture_extent, tree, tree_with_io};

    #[test]
    fn compatible_admission_checks_the_full_list() {
        for (name, list) in [
            (
                "i2c,t8101",
                b"i2c,t8101\0i2c,s5l8940x\0iic,soft\0".as_slice(),
            ),
            ("i2c,t6000", b"i2c,t6000\0i2c,s5l8940x\0iic,soft\0"),
            ("i2c,t6020", b"i2c,t6020\0i2c,s5l8940x\0iic,soft\0"),
        ] {
            assert!(i2c_compatible(name, None));
            assert!(i2c_compatible(name, Some(list)));
        }
        for (name, list) in [
            (
                "usb-drd,t8103",
                b"usb-drd,t6000\0usb-drd,t8103\0".as_slice(),
            ),
            ("usb-drd,t8112", b"usb-drd,t6020\0usb-drd,t8112\0"),
            ("usb-drd,t8122", b"usb-drd,t8122"),
        ] {
            assert!(usb_controller_compatible(name, None));
            assert!(usb_controller_compatible(name, Some(list)));
        }
        assert!(atc_phy_compatible(
            ATC_PHY,
            Some(b"atc-phy,t6020\0atc-phy,t8112\0")
        ));
        assert!(atc_phy_compatible(
            "atc-phy,t6000",
            Some(b"atc-phy,t6000\0")
        ));
        for (name, accepts) in [
            (
                "i2c,t8101",
                i2c_compatible as fn(&str, Option<&[u8]>) -> bool,
            ),
            ("usb-drd,t8112", usb_controller_compatible),
            (ATC_PHY, atc_phy_compatible),
        ] {
            for list in [
                format!("unknown\0{name}\0").into_bytes(),
                format!("{name}\0unknown\0").into_bytes(),
                format!("{name}\0\0unknown\0").into_bytes(),
                [b"\xff\0".as_slice(), name.as_bytes()].concat(),
            ] {
                assert!(!accepts(name, Some(&list)), "{name}: {list:?}");
            }
        }
        assert!(!i2c_compatible(
            "i2c,t8101",
            Some(b"i2c,t9999\0i2c,t8101\0")
        ));
        assert!(!i2c_compatible(
            "i2c,t8101",
            Some(b"i2c,s5l8940x\0i2c,t8101\0")
        ));
        assert!(!i2c_compatible("i2c,s5l8940x", None));
        assert!(!i2c_compatible("iic,soft", None));
        assert!(!usb_controller_compatible(
            "usb-drd,t8112",
            Some(b"usb-drd,t9999\0usb-drd,t8112\0")
        ));
        assert!(!usb_controller_compatible(
            "usb-drd,t8112",
            Some(b"usb-drd,t8103\0usb-drd,t8112\0")
        ));
        assert!(!atc_phy_compatible(
            ATC_PHY,
            Some(b"atc-phy,t9999\0atc-phy,t8112\0")
        ));
        assert!(!atc_phy_compatible(
            ATC_PHY,
            Some(b"atc-phy,t8112\0atc-phy,t6020\0")
        ));
        // A supplied property must actually contain the requested model name.
        assert!(!i2c_compatible("i2c,t6000", Some(b"i2c,t8101\0")));
        assert!(!usb_controller_compatible(
            "usb-drd,t6020",
            Some(b"usb-drd,t8112\0")
        ));
        assert!(!atc_phy_compatible(
            "atc-phy,t6000",
            Some(b"atc-phy,t8112\0")
        ));
    }

    #[test]
    fn typec_placement_distinguishes_i2c_addresses_from_mmio_and_preserves_phy_aliases() {
        use stela_contracts::adt::encode;
        let c = |v: &[u32]| v.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<_>>();
        let r = |v: &[u64]| v.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<_>>();
        let hpm = |name: &[u8], address: u32, rid: u32, personality: Option<&[u8]>| {
            let mut properties = vec![("name", name), ("compatible", b"usbc,cd3217\0".as_slice())];
            let address = c(&[address]);
            let (provider, port, rid) = (c(&[0x9b]), c(&[1]), c(&[rid]));
            properties.extend([
                ("hpm-iic-addr", address.as_slice()),
                ("iicProvider", provider.as_slice()),
                ("port-number", port.as_slice()),
                ("rid", rid.as_slice()),
            ]);
            properties.extend(personality.map(|p| ("usbc-fw-personality", p)));
            encode(&properties, &[])
        };
        let manager = encode(
            &[
                ("name", b"hpmBusManager\0"),
                ("compatible", b"usbc,manager\0"),
                ("reg", &c(&[0x6b, 2500, 0, 0])),
                ("AAPL,phandle", &c(&[0x9b])),
                ("interrupt-parent", &c(&[0x6a])),
                ("interrupts", &c(&[8, 1])),
            ],
            &[
                hpm(b"hpm0\0", 0x38, 0, Some(b"HPM,47\0")),
                hpm(b"hpm1\0", 0x3f, 1, None),
                hpm(b"hpm3\0", 0x3c, 3, None),
                hpm(b"hpm2\0", 0x3b, 2, Some(b"HPM,47-P23\0")),
            ],
        );
        let gpio = GpioBank {
            profile: crate::gpio::Profile::T8101,
            no_restore_pins: Vec::new(),
            physical: 0x23c100000,
            bytes: 0x100000,
            pins: 213,
            groups: 7,
            phandle: 0x6a,
            lines: vec![199],
            i2c_lines: vec![],
        };
        let i2c_with = |compatible: &[u8]| {
            encode(
                &[
                    ("name", b"i2c0\0"),
                    ("compatible", compatible),
                    ("reg", &r(&[0x35010000, 0x4000])),
                    ("interrupt-parent", &c(&[0x63])),
                    ("interrupts", &c(&[761])),
                ],
                core::slice::from_ref(&manager),
            )
        };
        let i2c = i2c_with(b"i2c,t8101\0");
        let mut views = vec![(0x383000000, 0x4000); 29];
        views[0] = (0x382a90000, 0x4000);
        views[1] = (0x382800000, 0x4000);
        views[2] = (0x383020000, 0x4000);
        views[4] = (0x383002000, 0x4000);
        let phy_views = |compatible: &[u8], views: &[(u64, u64)]| {
            encode(
                &[
                    ("name", b"atc-phy0\0"),
                    ("compatible", compatible),
                    ("AAPL,phandle", &c(&[0xa2])),
                    ("port-number", &c(&[1])),
                    (
                        "reg",
                        &r(&views.iter().flat_map(|&(a, n)| [a, n]).collect::<Vec<_>>()),
                    ),
                ],
                &[],
            )
        };
        let phy = |compatible: &[u8]| phy_views(compatible, &views);
        let usb = encode(
            &[
                ("name", b"usb-drd0\0"),
                ("device_type", b"usb-drd\0"),
                ("atc-phy-parent", &c(&[0xa2])),
                (
                    "reg",
                    &r(&[
                        0x382280000,
                        0x11800,
                        0x382200000,
                        0x4000,
                        0x38228c000,
                        0x5800,
                        0x382a84000,
                        0x4000,
                        0x382800000,
                        0x4000,
                    ]),
                ),
            ],
            &[],
        );
        // ACIO also references the PHY, but is not its USB pipehandler.
        let acio = encode(
            &[
                ("name", b"acio0\0"),
                ("device_type", b"acio\0"),
                ("atc-phy-parent", &c(&[0xa2])),
                ("reg", &r(&[0x381f00000, 0x100000])),
            ],
            &[],
        );
        let io = encode(
            &[("name", b"arm-io\0")],
            &[i2c.clone(), phy(b"atc-phy,t8112\0"), usb.clone(), acio],
        );
        let translate = |a| Some(if a < 0x100000000 { a + 0x200000000 } else { a });
        let place = |io: &[u8], aic, gpio| {
            typec_devices(
                &Node::root(io).unwrap(),
                &flat_fixture_extent(&translate),
                aic,
                gpio,
            )
        };
        let (buses, phys) = place(&io, 0x63, Some(&gpio)).unwrap();
        assert_eq!(buses[0].device.physical, 0x235010000);
        assert_eq!(buses[0].device.irq, 761);
        // Every die shares the manager's GPIO line; a die that names no
        // image runs the one of the flash-updated die below it in rid order.
        let hpm = |address, port, image: &str| I2cAddress {
            address,
            compatible: HPM.into(),
            interrupt: Some(8),
            firmware: Some(image.into()),
            port,
        };
        assert_eq!(
            buses[0].targets,
            [
                I2cAddress {
                    address: 0x6b,
                    compatible: HPM_MANAGER.into(),
                    interrupt: Some(8),
                    firmware: None,
                    port: None,
                },
                hpm(0x38, Some(1), "HPM,47"),
                hpm(0x3f, Some(1), "HPM,47"),
                hpm(0x3c, Some(1), "HPM,47-P23"),
                hpm(0x3b, Some(1), "HPM,47-P23"),
            ]
        );
        // A board with these buses carries each image its dies run, once.
        let mut with_buses = board(&tree(
            0x8112,
            "Apple M2",
            ["uart-1,samsung", "wdt,s5l8960x", "aic,2"],
        ))
        .unwrap();
        assert!(with_buses.firmware_files().is_empty());
        with_buses.i2cs = buses.clone();
        assert_eq!(
            with_buses.firmware_files(),
            ["USB-C_HPM,47.bin", "USB-C_HPM,47-P23.bin"]
        );
        // The manager's line must be a visible AP GPIO pin.
        assert!(place(&io, 0x63, None).is_err());
        assert_eq!(phys[0].usb2, (0x382a90000, 0x4000));
        assert_eq!(phys[0].core, (0x383000000, atc_phy::CORE_BYTES));
        assert_eq!(phys[0].pipe, Some((0x382a84000, 0x4000)));
        assert_eq!(phys[0].events, (0x382800000, 0x4000));
        assert_eq!(phys[0].views, views);
        assert!(place(&io, 0x99, Some(&gpio)).is_err());
        assert!(
            typec_devices(
                &Node::root(&io).unwrap(),
                &flat_fixture_extent(&|_| None),
                0x63,
                Some(&gpio)
            )
            .is_err()
        );
        for compatible in [
            I2C,
            HPM_MANAGER,
            HPM,
            ATC_PHY,
            "atc-phy,t6020",
            "atc-phy,t8103",
        ] {
            assert!(models(compatible, |_| None));
        }
        // The T6020 layout has the 28 views the T8112's starts with; its
        // first compatible, not the T8112 one it also lists, selects it.
        let t6020 = |views: &[(u64, u64)]| {
            encode(
                &[("name", b"arm-io\0")],
                &[
                    i2c.clone(),
                    phy_views(b"atc-phy,t6020\0atc-phy,t8112\0", views),
                    usb.clone(),
                ],
            )
        };
        let (_, phys) = place(&t6020(&views[..ATC_PHY_BASE_VIEWS]), 0x63, Some(&gpio)).unwrap();
        assert_eq!(phys[0].core, (0x383000000, atc_phy::CORE_BYTES));
        assert_eq!(phys[0].events, (0x382800000, 0x4000));
        assert!(place(&t6020(&views), 0x63, Some(&gpio)).is_err());
        // A PHY no controller names keeps its event block, without a
        // pipehandler.
        let alone = encode(
            &[("name", b"arm-io\0")],
            &[i2c.clone(), phy(b"atc-phy,t8112\0")],
        );
        let (_, phys) = place(&alone, 0x63, Some(&gpio)).unwrap();
        assert_eq!(
            (phys[0].pipe, phys[0].events),
            (None, (0x382800000, 0x4000))
        );
        for compatible in [
            b"i2c,t6000\0i2c,s5l8940x\0iic,soft\0".as_slice(),
            b"i2c,t6020\0i2c,s5l8940x\0iic,soft\0",
        ] {
            let bytes = encode(&[("name", b"arm-io\0")], &[i2c_with(compatible)]);
            let (controllers, _) = place(&bytes, 0x63, Some(&gpio)).unwrap();
            assert_eq!(controllers, buses);
        }
        for compatible in [
            b"i2c,t9999\0i2c,t8101\0".as_slice(),
            b"i2c,t8101\0i2c,t9999\0",
            b"unknown\0i2c,t8101\0",
        ] {
            let bytes = encode(&[("name", b"arm-io\0")], &[i2c_with(compatible)]);
            assert!(
                place(&bytes, 0x63, Some(&gpio))
                    .unwrap_err()
                    .contains("qualified compatible list")
            );
        }
        for compatible in [
            b"atc-phy,t9999\0atc-phy,t8112\0".as_slice(),
            b"atc-phy,t8112\0atc-phy,t9999\0",
            b"unknown\0atc-phy,t8112\0",
        ] {
            let bytes = encode(&[("name", b"arm-io\0")], &[phy(compatible)]);
            assert!(
                place(&bytes, 0x63, Some(&gpio))
                    .unwrap_err()
                    .contains("qualified compatible list")
            );
        }
        let t6000 = encode(
            &[("name", b"arm-io\0")],
            &[phy_views(b"atc-phy,t6000\0", &views[..ATC_PHY_BASE_VIEWS])],
        );
        let (_, phys) = place(&t6000, 0x63, None).unwrap();
        assert_eq!(phys.len(), 1);
        assert_eq!(phys[0].phandle, 0xa2);
        assert_eq!(phys[0].core, (0x383000000, atc_phy::CORE_BYTES));
        // The retimer's register protocol is undetermined: hidden, not refused.
        assert!(!models(RETIMER, |_| None));
        // Hidden PHYs are not parsed or mapped merely because reg survives.
        let io = encode(&[("name", b"arm-io\0")], &[i2c, phy(b"hidden\0"), usb]);
        assert!(place(&io, 0x63, Some(&gpio)).unwrap().1.is_empty());
    }

    #[test]
    fn usb_placement_uses_identity_ranges_mapper_and_all_interrupts() {
        use stela_contracts::adt::encode;
        let words = |cells: &[u32]| {
            cells
                .iter()
                .flat_map(|n| n.to_le_bytes())
                .collect::<Vec<_>>()
        };
        let pairs = |cells: &[(u64, u64)]| {
            cells
                .iter()
                .flat_map(|&(a, b)| [a, b])
                .flat_map(|n| n.to_le_bytes())
                .collect::<Vec<_>>()
        };
        let ranges = [
            (0x382280000, 0x11800),
            (0x382200000, 0x4000),
            (0x38228c000, 0x5800),
            (0x382a84000, 0x4000),
            (0x382800000, 0x4000),
            (0x382a80000, 0x4000),
            (0x382000000, 0x4000),
            (0x382080000, 0x4000),
            (0x38228d000, 0x4000),
        ];
        let mapper = encode(
            &[
                ("name", b"mapper-usb0\0"),
                ("compatible", b"iommu-mapper\0"),
                ("reg", &words(&[1])),
                ("AAPL,phandle", &words(&[0xa4])),
            ],
            &[],
        );
        // One-instance fixture: the independent Type-C worker owns the
        // production two-instance USB DART layout and SID remap.
        let dart = encode(
            &[
                ("name", b"dart-usb0\0"),
                ("compatible", b"dart,t8110\0"),
                ("reg", &pairs(&[(0x382f00000, 0x4000)])),
                ("instance", b"TRAD\0\0\0\0DART\0\0\0\0"),
                ("sid-count", &words(&[16])),
                ("interrupts", &words(&[1035])),
            ],
            &[mapper],
        );
        let usb_with = |compatible: &[u8], ranges: &[(u64, u64)], parent: u32, irqs: &[u32]| {
            encode(
                &[
                    ("name", b"usb-drd0\0"),
                    ("compatible", compatible),
                    ("reg", &pairs(ranges)),
                    ("iommu-parent", &words(&[parent])),
                    ("interrupts", &words(irqs)),
                    ("port-number", &words(&[1])),
                    ("atc-phy-parent", &words(&[0xa2])),
                ],
                &[],
            )
        };
        let usb = |ranges: &[(u64, u64)], parent, irqs: &[u32]| {
            usb_with(b"usb-drd,t8112\0", ranges, parent, irqs)
        };
        let irqs = [1031, 1032, 1033, 1034, 990];
        let tree = |usb| {
            tree_with_io(
                0x8112,
                "Apple M2",
                [UART, WATCHDOG, "aic,2"],
                &[],
                &[dart.clone(), usb],
            )
        };
        let found = board(&tree(usb(&ranges, 0xa4, &irqs))).unwrap();
        assert_eq!(
            found.usbs,
            [UsbController {
                ranges,
                irqs,
                iommu: 0,
                phandle: None,
                mapper: 0xa4,
                mapper_context: 1,
                stream: 1,
                port: 1,
                retention: false,
                phy: 0xa2,
            }]
        );
        for (compatible, bytes) in [
            (b"usb-drd,t8103\0".as_slice(), 0x1800),
            (b"usb-drd,t6000\0usb-drd,t8103\0", 0x1800),
            (b"usb-drd,t6020\0usb-drd,t8112\0", 0x5800),
            (b"usb-drd,t8122\0", 0x5800),
        ] {
            let mut family_ranges = ranges;
            family_ranges[2].1 = bytes;
            let family = board(&tree(usb_with(compatible, &family_ranges, 0xa4, &irqs))).unwrap();
            assert_eq!(family.usbs.len(), 1);
            assert_eq!(family.usbs[0].ranges, family_ranges);
            family_ranges[2].1 = if bytes == 0x1800 { 0x5800 } else { 0x1800 };
            assert!(board(&tree(usb_with(compatible, &family_ranges, 0xa4, &irqs))).is_err());
        }
        assert!(
            board(&tree(usb_with(
                b"usb-drd,t8103\0usb-drd,t8112\0",
                &ranges,
                0xa4,
                &irqs,
            )))
            .is_err()
        );
        assert_eq!(found.darts[0].instances[0].physical, 0x382f00000);
        for compatible in [
            b"usb-drd,t8132\0".as_slice(),
            b"usb-drd,t8142\0",
            b"usb-drd,t8152\0",
            b"usb-drd,t9999\0usb-drd,generic\0",
            b"usb-drd,t9999\0usb-drd,t8112\0",
            b"usb-drd,t8112\0usb-drd,t9999\0",
            b"unknown\0usb-drd,t8112\0",
        ] {
            let bytes = usb_with(compatible, &ranges, 0xa4, &irqs);
            let node = Node::root(&bytes).unwrap();
            assert!(
                usb_controller(&node, &flat_fixture_extent(&Some), &found.darts)
                    .unwrap_err()
                    .contains("qualified USB DRD layout")
            );
        }
        let bytes = usb(&ranges, 0xa4, &irqs);
        let node = Node::root(&bytes).unwrap();
        let mut routes = found.darts.clone();
        routes[0].profile = crate::dart::Profile::T6000;
        routes[0].remap = vec![(0, 1)];
        routes[0].sids = vec![1, 3];
        let routed = usb_controller(&node, &flat_fixture_extent(&Some), &routes).unwrap();
        assert_eq!(
            (routed.mapper, routed.mapper_context, routed.stream),
            (0xa4, 1, 0)
        );
        routes[0].sids = vec![0, 3];
        assert!(
            usb_controller(&node, &flat_fixture_extent(&Some), &routes)
                .unwrap_err()
                .contains("SID set")
        );
        routes[0].sids = vec![1, 3];
        routes[0].mappers.push((0xa4, 3));
        assert!(
            usb_controller(&node, &flat_fixture_extent(&Some), &routes)
                .unwrap_err()
                .contains("ambiguous")
        );
        // Every controller is placed, in DeviceTree order; a malformed
        // second one names itself.
        let second = encode(
            &[
                ("name", b"usb-drd1\0"),
                ("compatible", b"usb-drd,t8112\0"),
                ("reg", &pairs(&ranges)),
                ("iommu-parent", &words(&[0xa4])),
                ("interrupts", &words(&irqs)),
                ("port-number", &words(&[2])),
                ("atc-phy-parent", &words(&[0xa3])),
            ],
            &[],
        );
        let pair = |second| {
            tree_with_io(
                0x8112,
                "Apple M2",
                [UART, WATCHDOG, "aic,2"],
                &[],
                &[dart.clone(), usb(&ranges, 0xa4, &irqs), second],
            )
        };
        let ports: Vec<_> = board(&pair(second))
            .unwrap()
            .usbs
            .iter()
            .map(|u| u.port)
            .collect();
        assert_eq!(ports, [1, 2]);
        let unnumbered = encode(
            &[
                ("name", b"usb-drd1\0"),
                ("compatible", b"usb-drd,t8112\0"),
                ("reg", &pairs(&ranges)),
                ("iommu-parent", &words(&[0xa4])),
                ("interrupts", &words(&irqs)),
            ],
            &[],
        );
        assert_eq!(
            board(&pair(unnumbered)).unwrap_err(),
            "usb-drd1 has no Type-C port number"
        );
        assert!(models(USB_DRD, |_| None));
        assert!(board(&tree(usb(&ranges, 0xff, &irqs))).is_err());
        assert!(board(&tree(usb(&ranges, 0xa4, &irqs[..4]))).is_err());
        let mut bad = ranges;
        bad[2].0 += 4;
        assert!(board(&tree(usb(&bad, 0xa4, &irqs))).is_err());
        let mut bad = ranges;
        bad[0].1 = u64::MAX;
        assert!(board(&tree(usb(&bad, 0xa4, &irqs))).is_err());
    }
}
