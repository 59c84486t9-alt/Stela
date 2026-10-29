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

/// Checked Apple I2C register families. The original 26A434 ADTs use
/// these first compatibles ahead of `i2c,s5l8940x` and `iic,soft`; the latter
/// fallback strings alone do not establish a modelled Apple register file.
/// T6000 and T6020 keep the same one-bank byte-FIFO interface (`i2c`).
const I2C_COMPATIBLES: &[&str] = &["i2c,t8101", "i2c,t6000", "i2c,t6020"];

/// USB DRD families whose nine-view layout is checked. The original
/// 26A434 ADTs give M1/T6000
/// a 0x1800-byte `reg[2]`, versus 0x5800 on M2/T6020 and M3/T8122. In each,
/// `reg[2]` begins at `reg[0]`+0xc000 and `reg[8]` at `reg[0]`+0xd000.
/// Later families move `reg[8]` or add a tenth view and are not aliases.
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

/// Whether the full property selects a checked nine-view USB DRD family.
pub fn usb_controller_compatible(name: &str, compatibles: Option<&[u8]>) -> bool {
    USB_DRD_LAYOUTS.iter().any(|&(family, _)| family == name)
        && compatibles.is_none_or(|raw| {
            usb_layout(raw).is_some()
                && compatible_list(raw)
                    .is_some_and(|list| list.split('\0').any(|entry| entry == name))
        })
}

/// Whether the full property selects a checked ATC PHY register layout.
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

/// Recognize candidates independently of validation so unsupported families
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
/// stream. Apple `reg[2]`/`reg[8]` overlap `reg[0]`; preserve their physical alias.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsbController {
    pub ranges: [(u64, u64); 9],
    pub irqs: [u32; 5],
    pub iommu: usize,
    /// Owner identities; context survives native incoming assignment.
    pub phandle: Option<u32>,
    pub mapper: u32,
    pub mapper_context: u32,
    pub stream: u32,
    /// The Type-C connector's `port-number`, shared with its HPM die.
    pub port: u32,
    /// Ordinary controller state survives supply gating only when declared.
    pub retention: bool,
    /// Digital PHY provider (`atc-phy-parent`), never inferred from
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

/// Every checked early-family USB DRD, in DeviceTree order, with its
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
mod tests;
