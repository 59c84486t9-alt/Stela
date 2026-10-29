//! DeviceTree placement and validation for storage topology.
use super::AES;
use super::ASC;
use super::Device;
use super::DomainId;
use super::GPIO_FUNCTION;
use super::GpioBank;
use super::Iommu;
use super::NOR;
use super::Node;
use super::SART;
use super::SPI;
use super::String;
use super::Vec;
use super::ans;
use super::apertures;
use super::asc;
use super::dma_routes::{native_dma_phandle, native_mapper_input};
use super::format;
use super::name_of;
use super::power_resources;
use super::rtbuddy_nub;
use super::sart;
use super::single_range;
use super::spi;

/// `/arm-io/ans` properties under which SPTM's `nvme_bootstrap`
/// (0x270c8a74..8bc0, 0x270c8dac) drives banks or flows the ANS2 model
/// lacks: the secure BAR and its alternate register layout (SPTM programs
/// the queues at `reg[9]` or +0x4000), the transfer-length workaround
/// (`reg[10..12]` doorbells written on unmap) and the SHA engine
/// (`reg[14]`). docs/research/ans2.md has the matrix.
const UNMODELED_ANS_SPTM: [&str; 4] = [
    "nvme-secure-bar",
    "nvme-secure-reg-layout",
    "nvme-tl-wa",
    "nvme-ans-sha-present",
];

/// Placement from SPI `reg`/`interrupts`, `function-spi_cs0`, the GPIO
/// phandle and GPIO `reg`/`#gpio-pins`/`#gpio-int-groups`. No PA or pin is fixed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpiNor {
    pub device: Device,
    pub image: crate::nor::Image,
    /// The AP GPIO pin of an external chip select.
    pub select: Option<u32>,
}

/// The byte-PIO SPI NOR topology. The 26A434 SPIMC driver accepts
/// `internal-cs`; otherwise `function-spi_cs0` names an Apple GPIO function
/// (four cells: provider phandle, 'GPIO', pin, function flags). J473AP uses
/// pin 49 with flags 0x10001; other function encodings refuse.
pub(super) fn spi_nor(
    root: &Node<'_>,
    io: &Node<'_>,
    translate: &dyn Fn(u64, u64) -> Option<u64>,
    aic: u32,
    gpio: Option<&GpioBank>,
) -> Result<Option<SpiNor>, String> {
    let Some(node) = io.child("spi1").filter(|n| n.compatible(SPI)) else {
        return Ok(None);
    };
    if node.first_u32("spi-version") != Some(1) {
        return Err("unsupported SPI version".into());
    }
    let (physical, bytes) = single_range(&node, translate)?;
    if bytes < spi::BYTES || node.first_u32("interrupt-parent") != Some(aic) {
        return Err("SPI aperture or interrupt parent is unsupported".into());
    }
    let irq = node
        .first_u32("interrupts")
        .filter(|&irq| irq <= u32::from(u16::MAX))
        .ok_or("SPI interrupt missing or too large")?;
    let flash = node
        .child("spinor")
        .filter(|n| n.compatible(NOR))
        .ok_or("SPI1 has no modeled NOR child")?;
    // AppleARMSPIDevice's 32-byte AppleARMSPIConfig: CS index,
    // clock period, CPOL/CPHA/bit order/word size, then delays.
    // The byte PIO model has only one MSB-first NOR slave, at CS0.
    let config = flash
        .property("reg")
        .ok_or("NOR SPI configuration missing")?;
    if config.len() != 32
        || config[..4] != [0; 4]
        || config[8] > 1
        || config[9] > 1
        || config[10..12] != [1, 8]
    {
        return Err("unsupported NOR SPI configuration or chip select".into());
    }
    if flash.cells32("ranges").as_deref() != Some(&[0, 0, crate::nor::CAPACITY as u32]) {
        return Err("unsupported NOR ranges".into());
    }
    for (name, regions) in [
        ("firmware", crate::nor::FIRMWARE.as_slice()),
        ("anvram", core::slice::from_ref(&crate::nor::ANVRAM)),
        ("syscfg", crate::nor::SYSCFG.as_slice()),
    ] {
        let expected = regions
            .iter()
            .flat_map(|&(offset, size)| [offset, size])
            .collect::<Vec<_>>();
        if flash.child(name).and_then(|n| n.cells32("reg")) != Some(expected) {
            return Err(format!(
                "NOR {name} lacks its supported boot-firmware partition"
            ));
        }
    }
    let chosen = root.child("chosen").ok_or("NVRAM chosen missing")?;
    if chosen.first_u32("nvram-bank-size") != Some(crate::nor::nvram::BANK_SIZE as u32)
        || chosen.first_u32("nvram-bank-count") != Some(crate::nor::nvram::BANK_COUNT)
    {
        return Err("unsupported NVRAM bank geometry".into());
    }
    let current = chosen
        .first_u32("nvram-current-bank")
        .ok_or("NVRAM current bank missing")?;
    let proxy = chosen
        .property("nvram-proxy-data")
        .ok_or("NVRAM proxy missing")?;
    let image = crate::nor::Image::fresh()
        .with_proxy(current, proxy)
        .map_err(String::from)?;
    let select = if node.property("internal-cs").is_some() {
        None
    } else {
        let cells = node
            .cells32("function-spi_cs0")
            .ok_or("SPI external chip select missing")?;
        let [phandle, opcode, pin, flags] = cells[..] else {
            return Err("invalid SPI chip-select function".into());
        };
        if opcode != GPIO_FUNCTION || flags != 0x10001 {
            return Err("unsupported SPI chip-select function encoding".into());
        }
        let gpio = gpio
            .filter(|gpio| gpio.phandle == phandle)
            .ok_or("SPI CS GPIO provider is absent or unmodeled")?;
        if pin >= gpio.pins {
            return Err("SPI chip select beyond the GPIO bank".into());
        }
        if gpio.i2c_lines.contains(&pin) {
            return Err("SPI chip select shares an I2C line".into());
        }
        Some(pin)
    };
    Ok(Some(SpiNor {
        device: Device {
            physical,
            bytes,
            irq,
        },
        image,
        select,
    }))
}

/// The AES engine: its block and key-disable register ranges, from
/// version 5 its DKey range, its `aes-version`, `address-width` and
/// key-disable layout, its AIC input, and the [`Board::darts`] index and
/// stream of its `iommu-parent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AesEngine {
    pub phandle: Option<u32>,
    pub mapper: u32,
    pub mapper_context: u32,
    pub instance: usize,
    pub ranges: [(u64, u64); 2],
    pub dkey: Option<(u64, u64)>,
    pub config: crate::aes::Config,
    pub irq: u32,
    pub iommu: usize,
    pub stream: u32,
}

use crate::ans::QueueGeometry;

/// ANS2's DT placement. `reg[0]` is the ASC wrapper; `reg[3]` is the
/// NVMe aperture. `iommu-parent` names SART itself, not a DART stream.
/// J473AP: `IOCoastGuardSARTMapper::start` (kernel file 0x2ccada8),
/// `AppleANS2NVMeController::start` (0x3dbb040); neither map is guessed.
/// `vdma` is `reg[13]`, which SPTM reads only under `nvme-vdma-wa`
/// (`ans::VDMA_CACHE_OFFSET`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnsController {
    pub geometry: QueueGeometry,
    pub wrapper: (u64, u64),
    pub nvme: (u64, u64),
    pub vdma: Option<(u64, u64)>,
    pub sart: (u64, u64),
    /// The SART's entry and throttle registers, from `sart-version`,
    /// `sart-throttle-version` and `sart-throttle-offset`.
    pub sart_layout: sart::Layout,
    pub sart_idle: u64,
    /// The SART's `power-canary-offset` word in its `reg[1]`.
    pub sart_canary: Option<u64>,
    /// The SART node's `exclusive-bounds`: entry SIZEs count pages rather
    /// than naming the last one ([`sart::Bounds`]).
    pub sart_exclusive_bounds: bool,
    pub interrupts: [u16; 4],
    pub completion_irq: u16,
    pub namespaces: Vec<crate::ans::Description>,
    pub clock_gates: Vec<DomainId>,
    pub power_gates: Vec<DomainId>,
}

/// Only explicitly visible ANS2 hardware is placed. Do not preserve all
/// ASC compatibles in the loader: SIO, AOP and others need their own
/// native application protocols before they can be exposed.
/// `iboot_security` is `/defaults nvme-iboot-sptm-security`: the boot
/// stage has configured the controller, linear submission mode included,
/// so the kernel and SPTM leave its linear-SQ, PRP-check and command
/// permission registers alone (`AppleANS3CGv2Controller::EnableLinearSQ`
/// 0x3db9064, `AppleANS2CGv2Controller::DisablePRPNullCheck` 0x3de5b3c,
/// `AppleANS2CGv2Controller::EnableAutoQueueManage` 0x3de5adc, read by
/// `AppleANS2NVMeController::CheckEDTProperties` 0x3dc1740). Without it
/// the kernel read-modify-writes 0x24004 and 0x24008, which have no model.
pub(super) fn ans_controller(
    io: &Node<'_>,
    translate: &dyn Fn(u64, u64) -> Option<u64>,
    iboot_security: bool,
) -> Result<Option<AnsController>, String> {
    let Some(node) = io.child("ans").filter(|n| n.compatible(ASC)) else {
        return Ok(None);
    };
    if node.property("role") != Some(b"ANS2\0".as_slice()) {
        return Err("/arm-io/ans role is not the modeled ANS2".into());
    }
    if !iboot_security {
        return Err(
            "ANS2 without /defaults nvme-iboot-sptm-security selects kernel-programmed ANS2 registers the model does not carry"
                .into(),
        );
    }
    if node.property("nvme-linear-sq").is_none() {
        return Err("ANS2 requires the modeled linear submission contract".into());
    }
    let geometry = QueueGeometry::linear(
        node.first_u32("nvme-queue-entries")
            .ok_or("ANS2 has no nvme-queue-entries handoff")?,
    )
    .map_err(String::from)?;
    if let Some(flag) = UNMODELED_ANS_SPTM
        .into_iter()
        .find(|flag| node.property(flag).is_some())
    {
        return Err(format!(
            "ANS2 {flag} selects an SPTM NVMe contract the model does not carry"
        ));
    }
    rtbuddy_nub(&node, "ANS2")?;
    let regs = apertures::registers(&node).ok_or("ANS2 has no reg pairs")?;
    let parent = node
        .first_u32("iommu-parent")
        .ok_or("ANS2 has no iommu-parent")?;
    let mut found = None;
    let mut duplicate = false;
    io.visit(&mut |candidate| {
        if candidate.first_u32("AAPL,phandle") == Some(parent) {
            duplicate |= found.is_some();
            found = Some(name_of(candidate));
        }
    })
    .ok_or("DeviceTree walk failed")?;
    if duplicate {
        return Err("ANS2 iommu-parent is ambiguous".into());
    }
    let sart_node = found
        .and_then(|name| io.child(&name))
        .filter(|n| n.compatible(SART))
        .ok_or("ANS2 iommu-parent is not a SART")?;
    // SPTM's sart_bootstrap_parse_edt panics on any of these that is not
    // one word.
    let word = |name: &str| -> Result<Option<u32>, String> {
        match sart_node.property(name) {
            None => Ok(None),
            Some(bytes) if bytes.len() == 4 => Ok(sart_node.first_u32(name)),
            Some(_) => Err(format!("SART {name} is not one word")),
        }
    };
    let version = word("sart-version")?.ok_or("SART has no sart-version")?;
    if sart_node.property("sart-throttle-disable").is_some() {
        return Err("SART throttle-disable leaves throttle words the model does not carry".into());
    }
    let sart_layout = sart::Layout::new(
        version,
        word("sart-throttle-version")?.unwrap_or(version),
        word("sart-throttle-offset")?.unwrap_or(0),
    )
    .map_err(String::from)?;
    let sart_regs = apertures::registers(&sart_node).ok_or("SART has no reg pairs")?;
    let place = |pairs: &[(u64, u64)], index: usize, minimum: u64| -> Result<(u64, u64), String> {
        let &(offset, bytes) = pairs
            .get(index)
            .filter(|(_, bytes)| *bytes >= minimum)
            .ok_or("ANS2/SART register bank is absent or too short")?;
        let first = translate(offset, bytes).ok_or("ANS2/SART bank outside arm-io ranges")?;
        Ok((first, bytes))
    };
    let wrapper = place(&regs, 0, asc::WRAPPER_BYTES)?;
    let nvme = place(&regs, 3, ans::REGISTER_BYTES)?;
    let vdma = node
        .property("nvme-vdma-wa")
        .map(|_| place(&regs, 13, ans::VDMA_CACHE_OFFSET + geometry.vdma_bytes()))
        .transpose()?;
    let sart = place(&sart_regs, 0, sart_layout.register_bytes())?;
    let sart_canary = word("power-canary-offset")?
        .map(|offset| {
            let offset = u64::from(offset);
            let bank = place(&sart_regs, 1, offset + 4)?;
            Ok::<_, String>(bank.0 + offset)
        })
        .transpose()?;
    let power = place(&sart_regs, 2, 4)?;
    let offset = u64::from(
        sart_node
            .first_u32("sart-power-reg-offset")
            .ok_or("SART has no idle register offset")?,
    );
    if offset + 4 > power.1 {
        return Err("SART idle word outside reg[2]".into());
    }
    let sart_idle = power
        .0
        .checked_add(offset)
        .ok_or("SART idle address wraps")?;
    if sart_idle < nvme.0 || sart_idle + 4 > nvme.0 + nvme.1 {
        return Err("SART idle word is not inside the shared NVMe bank".into());
    }
    let irqs = node.cells32("interrupts").ok_or("ANS2 has no interrupts")?;
    let index = node
        .first_u32("nvme-interrupt-idx")
        .ok_or("ANS2 has no nvme-interrupt-idx")? as usize;
    if index < 4 {
        return Err("ANS2 completion interrupt overlaps ASC mailbox lines".into());
    }
    let irq = |index: usize| -> Result<u16, String> {
        irqs.get(index)
            .and_then(|&n| u16::try_from(n).ok())
            .ok_or_else(|| "ANS2 interrupt index/number is invalid".into())
    };
    let interrupts = [irq(0)?, irq(1)?, irq(2)?, irq(3)?];
    let completion_irq = irq(index)?;
    let namespaces = crate::ans::Description::decode(
        node.property("namespaces")
            .ok_or("ANS2 has no namespaces")?,
    )
    .map_err(String::from)?;
    Ok(Some(AnsController {
        geometry,
        wrapper,
        nvme,
        vdma,
        sart,
        sart_layout,
        sart_idle,
        sart_canary,
        sart_exclusive_bounds: sart_node.property("exclusive-bounds").is_some(),
        interrupts,
        completion_irq,
        namespaces,
        clock_gates: node
            .property("clock-gates")
            .map(|_| power_resources::gate_ids(&node, "/arm-io/ans", "clock-gates"))
            .ok_or("ANS2 has no clock-gates")??,
        power_gates: node
            .property("power-gates")
            .map(|_| power_resources::gate_ids(&node, "/arm-io/ans", "power-gates"))
            .ok_or("ANS2 has no power-gates")??,
    }))
}

/// The modeled AES engine under `/arm-io`, if the DeviceTree keeps one; its
/// `iommu-parent` must be a mapper of a modeled DART. Its `reg` has the
/// DKey range third from `aes-version` 5, as the 26A434
/// AppleS8000AESAccelerator `start` maps it; `address-width` (default 36)
/// and the `sioaesdisable*-offset` words are the driver's
/// `OverrideRegMap` inputs, 32-bit like its `getDTProperty` requires.
pub(super) fn aes_engine(
    io: &Node<'_>,
    translate: &dyn Fn(u64, u64) -> Option<u64>,
    darts: &[Iommu],
) -> Result<Option<AesEngine>, String> {
    let Some(node) = io.child("aes").filter(|node| node.compatible(AES)) else {
        return Ok(None);
    };
    const PATH: &str = "/arm-io/aes";
    let number = |name: &str| {
        node.first_u32(name)
            .ok_or_else(|| format!("{PATH} has no {name}"))
    };
    let optional = |name: &str| match node.property(name) {
        None => Ok(None),
        Some(&[a, b, c, d]) => Ok(Some(u32::from_le_bytes([a, b, c, d]))),
        Some(_) => Err(format!("{PATH} {name} is not one 32-bit cell")),
    };
    let version = number("aes-version")?;
    let reg = apertures::registers(&node).unwrap_or_default();
    let (block, key_disable, dkey) = match (reg.as_slice(), version >= crate::aes::DKEY_VERSION) {
        (&[block, key_disable], false) => (block, key_disable, None),
        (&[block, key_disable, dkey], true) => (block, key_disable, Some(dkey)),
        _ => {
            return Err(format!(
                "{PATH} aes-version {version} has {} register ranges",
                reg.len()
            ));
        }
    };
    let place = |(offset, bytes): (u64, u64)| {
        translate(offset, bytes)
            .map(|physical| (physical, bytes))
            .ok_or_else(|| format!("{PATH} lies outside /arm-io ranges"))
    };
    let config = crate::aes::Config {
        version,
        address_width: optional("address-width")?.unwrap_or(crate::aes::DEFAULT_ADDRESS_WIDTH),
        key_disable: crate::aes::KeyDisable {
            bytes: key_disable.1,
            word: optional("sioaesdisable-offset")?.unwrap_or(0),
            keys: [
                optional("sioaesdisableuid1-offset")?,
                optional("sioaesdisablegid0-offset")?,
                optional("sioaesdisablegid1-offset")?,
            ],
        },
    };
    config.validate().map_err(|why| format!("{PATH}: {why}"))?;
    let phandle =
        native_dma_phandle(&node, "AAPL,phandle").map_err(|why| format!("{PATH} {why}"))?;
    let parent = native_dma_phandle(&node, "iommu-parent")
        .map_err(|why| format!("{PATH} {why}"))?
        .ok_or_else(|| format!("{PATH} has no iommu-parent"))?;
    let mut matching = darts.iter().enumerate().flat_map(|(index, dart)| {
        dart.mappers
            .iter()
            .filter(move |(phandle, _)| *phandle == parent)
            .map(move |&(_, context)| (index, context))
    });
    let (iommu, mapper_context) = matching
        .next()
        .ok_or_else(|| format!("{PATH} iommu-parent {parent:#x} is no modeled DART's mapper"))?;
    if matching.next().is_some() {
        return Err(format!("{PATH} mapper ownership is ambiguous"));
    }
    if darts[iommu].instances.len() != 1 {
        return Err(format!(
            "{PATH} DMA instance routing is undetermined for a multi-instance DART"
        ));
    }
    let stream = native_mapper_input(&darts[iommu], mapper_context)
        .map_err(|why| format!("{PATH} {why}"))?;
    Ok(Some(AesEngine {
        phandle,
        mapper: parent,
        mapper_context,
        instance: 0,
        ranges: [place(block)?, place(key_disable)?],
        dkey: dkey.map(place).transpose()?,
        config,
        irq: number("interrupts")?,
        iommu,
        stream,
    }))
}

#[cfg(test)]
mod tests {
    use super::super::gpio_topology::AP_GPIO_BANK;
    use super::super::*;
    use super::*;
    use crate::board::fixture_support::flat_fixture_extent;

    #[test]
    fn spi_nor_placement_uses_dt_ranges_bank_proxy_and_gpio_function() {
        use stela_contracts::adt::encode;
        let words = |v: &[u32]| v.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<_>>();
        let pairs = |v: &[u64]| v.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<_>>();
        let partitions: Vec<_> = [
            ("firmware", crate::nor::FIRMWARE.as_slice()),
            ("anvram", core::slice::from_ref(&crate::nor::ANVRAM)),
            ("syscfg", crate::nor::SYSCFG.as_slice()),
        ]
        .into_iter()
        .map(|(name, regions)| {
            let registers = regions
                .iter()
                .flat_map(|&(offset, size)| [offset, size])
                .collect::<Vec<_>>();
            encode(
                &[("name", name.as_bytes()), ("reg", &words(&registers))],
                &[],
            )
        })
        .collect();
        let flash = encode(
            &[
                ("name", b"spinor"),
                ("compatible", NOR.as_bytes()),
                ("reg", &words(&[0, 25, 0x08010000, 0, 20, 0, 0, 0])),
                ("ranges", &words(&[0, 0, crate::nor::CAPACITY as u32])),
            ],
            &partitions,
        );
        let spi = encode(
            &[
                ("name", b"spi1"),
                ("compatible", SPI.as_bytes()),
                ("spi-version", &words(&[1])),
                ("reg", &pairs(&[0x35104000, 0x4000])),
                ("interrupts", &words(&[749])),
                ("interrupt-parent", &words(&[99])),
                (
                    "function-spi_cs0",
                    &words(&[106, GPIO_FUNCTION, 49, 0x10001]),
                ),
            ],
            &[flash],
        );
        let gpio = encode(
            &[
                ("name", b"gpio"),
                ("compatible", GPIO.as_bytes()),
                ("reg", &pairs(&[0x3c100000, 0x100000])),
                ("#gpio-pins", &words(&[213])),
                ("#gpio-int-groups", &words(&[7])),
                ("AAPL,phandle", &words(&[106])),
                ("interrupt-parent", &words(&[99])),
                ("interrupts", &words(&[199, 200, 201, 202, 203, 204, 205])),
            ],
            &[],
        );
        let i2c = encode(
            &[
                ("name", b"i2c2"),
                ("gpio-iic_sda", &words(&[0x56, 0x10102, AP_GPIO_BANK])),
                ("gpio-lstx", &words(&[0x1c, 0x100, 0x504f41])),
                ("gpio-iic_scl", &words(&[0x57, 0x10102, 0x504f41])),
            ],
            &[],
        );
        let io = encode(&[("name", b"arm-io")], &[spi, gpio, i2c]);
        let chosen = encode(
            &[
                ("name", b"chosen"),
                ("nvram-proxy-data", &crate::nor::nvram::empty_bank()),
                ("nvram-bank-size", &words(&[65536])),
                ("nvram-bank-count", &words(&[2])),
                ("nvram-current-bank", &words(&[0])),
            ],
            &[],
        );
        let data = encode(&[("name", b"device-tree")], &[chosen, io]);
        let root = Node::root(&data).unwrap();
        let io = root.child("arm-io").unwrap();
        let translate = |v: u64| v.checked_add(0x2_0000_0000);
        let bank = gpio_bank(&io, &flat_fixture_extent(&translate), 99)
            .unwrap()
            .unwrap();
        assert_eq!(bank.physical, 0x2_3c10_0000);
        assert_eq!(bank.lines, [199, 200, 201, 202, 203, 204, 205]);
        // Only the AP bank's I2C line; the AOP-bank pin belongs elsewhere.
        assert_eq!(bank.i2c_lines, [0x56]);
        assert!(gpio_bank(&io, &flat_fixture_extent(&translate), 100).is_err());
        let placed = spi_nor(
            &root,
            &io,
            &flat_fixture_extent(&translate),
            99,
            Some(&bank),
        )
        .unwrap()
        .unwrap();
        assert_eq!(placed.device.physical, 0x2_3510_4000);
        assert_eq!(placed.device.irq, 749);
        assert_eq!(placed.select, Some(49));
        assert_eq!(
            placed.image.bank(0).unwrap(),
            crate::nor::nvram::empty_bank()
        );
        assert!(spi_nor(&root, &io, &flat_fixture_extent(&|_| None), 99, Some(&bank)).is_err());
        assert!(spi_nor(&root, &io, &flat_fixture_extent(&Some), 100, Some(&bank)).is_err());
        assert!(spi_nor(&root, &io, &flat_fixture_extent(&translate), 99, None).is_err());
    }

    #[test]
    fn ans2_placement_uses_phandles_interrupt_index_and_sparse_register_banks() {
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
        let mut banks = vec![
            (0x7740_0000, 0x6c000),
            (0x7705_0000, 0x4000),
            (0, 0),
            (0x7bcc_0000, 0x60000),
        ];
        banks.resize(13, (0, 0));
        banks.push((0x7b10_0000, 0x44000));
        let banks = pairs(&banks);
        let flagged = |flags: &[&'static str], version: u32, parent: u32, interrupt_index: u32| {
            let nub = encode(
                &[("name", &z("iop-ans-nub")), ("compatible", &z(RTBUDDY))],
                &[],
            );
            let (name, compatible, role) = (z("ans"), z(ASC), z("ANS2"));
            let (entries, index) = (cells(&[64]), cells(&[interrupt_index]));
            let interrupts = cells(&[718, 717, 720, 719, 724]);
            let iommu = cells(&[parent]);
            let namespaces = cells(&[1, 1, 0, 2, 8, 768, 3, 13, 32768]);
            let gates = cells(&[125]);
            let mut properties: Vec<(&str, &[u8])> = vec![
                ("name", &name),
                ("compatible", &compatible),
                ("role", &role),
                ("reg", &banks),
                ("nvme-linear-sq", &[]),
                ("nvme-queue-entries", &entries),
                ("nvme-interrupt-idx", &index),
                ("interrupts", &interrupts),
                ("iommu-parent", &iommu),
                ("namespaces", &namespaces),
                ("clock-gates", &gates),
                ("power-gates", &gates),
            ];
            properties.extend(flags.iter().map(|&flag| (flag, [].as_slice())));
            let ans = encode(&properties, &[nub]);
            let sart = encode(
                &[
                    ("name", &z("sart-ans")),
                    ("compatible", &z(SART)),
                    ("sart-version", &cells(&[version])),
                    ("AAPL,phandle", &cells(&[0x8e])),
                    ("sart-power-reg-offset", &cells(&[0x13e8])),
                    (
                        "reg",
                        &pairs(&[(0x7bc5_0000, 0xc000), (0, 0), (0x7bcc_0000, 0x4000)]),
                    ),
                ],
                &[],
            );
            encode(&[("name", &z("arm-io"))], &[ans, sart])
        };
        let tree =
            |version, parent, interrupt_index| flagged(&[], version, parent, interrupt_index);
        let bytes = tree(3, 0x8e, 4);
        let io = Node::root(&bytes).unwrap();
        let placed = ans_controller(
            &io,
            &flat_fixture_extent(&|offset| Some(0x2_0000_0000 + offset)),
            true,
        )
        .unwrap()
        .unwrap();
        assert_eq!(placed.wrapper, (0x2_7740_0000, 0x6c000));
        assert_eq!(placed.nvme, (0x2_7bcc_0000, 0x60000));
        assert_eq!(placed.sart, (0x2_7bc5_0000, 0xc000));
        assert_eq!(placed.sart_idle, 0x2_7bcc_13e8);
        assert_eq!(placed.sart_layout, sart::Layout::V3);
        assert_eq!(placed.sart_canary, None);
        assert!(!placed.sart_exclusive_bounds);
        // A version 4 SART places with SPTM's version 4 layout.
        let bytes = tree(4, 0x8e, 4);
        let v4 = ans_controller(
            &Node::root(&bytes).unwrap(),
            &flat_fixture_extent(&|a| Some(a)),
            true,
        )
        .unwrap()
        .unwrap();
        assert_eq!(v4.sart_layout, sart::Layout::new(4, 4, 0).unwrap());
        // So does T8103's version 2, whose throttles follow its version.
        let bytes = tree(2, 0x8e, 4);
        let v2 = ans_controller(
            &Node::root(&bytes).unwrap(),
            &flat_fixture_extent(&|a| Some(a)),
            true,
        )
        .unwrap()
        .unwrap();
        assert_eq!(v2.sart_layout, sart::Layout::new(2, 2, 0).unwrap());
        assert_eq!(placed.completion_irq, 724);
        assert_eq!(placed.interrupts, [718, 717, 720, 719]);
        assert_eq!(
            placed.namespaces[2],
            crate::ans::Description {
                id: 3,
                kind: 13,
                blocks: 32768
            }
        );
        assert_eq!(
            placed.clock_gates,
            [DomainId {
                die: 0,
                device: 125
            }]
        );
        // reg[13] is SPTM's VDMA cache only under nvme-vdma-wa.
        assert_eq!(placed.vdma, None);
        let vdma = flagged(&["nvme-vdma-wa"], 3, 0x8e, 4);
        let placed = ans_controller(
            &Node::root(&vdma).unwrap(),
            &flat_fixture_extent(&|a| Some(a)),
            true,
        )
        .unwrap()
        .unwrap();
        assert_eq!(placed.vdma, Some((0x7b10_0000, 0x44000)));
        for flag in UNMODELED_ANS_SPTM {
            let bytes = flagged(&[flag], 3, 0x8e, 4);
            let error = ans_controller(
                &Node::root(&bytes).unwrap(),
                &flat_fixture_extent(&|a| Some(a)),
                true,
            )
            .unwrap_err();
            assert!(error.contains(flag), "{error}");
        }
        for bytes in [
            tree(5, 0x8e, 4),
            tree(3, 0x99, 4),
            tree(3, 0x8e, 3),
            tree(3, 0x8e, 5),
        ] {
            assert!(
                ans_controller(
                    &Node::root(&bytes).unwrap(),
                    &flat_fixture_extent(&|a| Some(a)),
                    true
                )
                .is_err()
            );
        }
        assert!(ans_controller(&io, &flat_fixture_extent(&|_| None), true).is_err());
        // Without the boot stage's security hand-off the kernel programs
        // registers the model does not carry.
        assert!(
            ans_controller(
                &io,
                &flat_fixture_extent(&|offset| Some(0x2_0000_0000 + offset)),
                false
            )
            .is_err()
        );
        // These compatibles are shared by other hardware. The partial ANS
        // controller cannot authorize advertising every ASC/RTBuddy/SART.
        assert!(!models(ASC, |_| None));
        assert!(!models(RTBUDDY, |_| None));
        assert!(!models(SART, |_| None));
    }
}
