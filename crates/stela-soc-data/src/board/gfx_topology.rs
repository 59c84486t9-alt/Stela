//! DeviceTree placement and validation for gfx topology.
use super::{ASC, Node, String, Vec, agx, apertures, asc, format, rtbuddy_nub};
use alloc::vec;

/// Whether `compatible` names an `sgx` GPU whose whole interface is modeled
/// on every SoC that carries it (`agx::generation`, every SoC 26A434
/// supports; only admitted ones stay visible).
pub fn admitted_gpu(compatible: &str) -> bool {
    agx::generation::compatible_admitted(compatible)
}

/// The AGX GPU's DT placement: the `gfx-asc` wrapper (`reg[0]`) and its four
/// mailbox interrupts, and the `sgx` register banks. The firmware reaches
/// memory through the UAT the `sgx` MMU configuration roots, which
/// `gfx-asc`'s `iommu-parent` (`mapper-gfx-asc`, `AGXArmFirmwareMapper`)
/// names; no DART stream is involved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GfxController {
    /// The census entry the `sgx` node's `compatible` names.
    pub gpu: &'static agx::generation::Gpu,
    pub wrapper: (u64, u64),
    pub interrupts: [u16; 4],
    /// The `sgx` banks as `(physical base, bytes, register offset)`. Register
    /// offsets are relative to `reg[0]`'s base, as `readGFXReg32` takes them:
    /// `reg[0]` is the first bank, and `reg[1]` another unless it lies inside
    /// `reg[0]` (T8112). On the Pro/Max SoCs `reg[0]` is 1 MiB and the
    /// registers lie in `reg[1]` (docs/research/agx.md §6).
    pub sgx: Vec<(u64, u64, u64)>,
    /// The GPU's TTBAT as the boot stage publishes it (`gptbat-ready`,
    /// `ttbat-phys-addr-base` in 16 KiB pages; the loader sets it to
    /// `gpu-region-base`): the MMU is handed off rooted there
    /// (stateful `Sgx::handed_off`).
    pub ttbat: u64,
    /// The shared TTBR1 window's page-directory page (`gfx-shared-l2-region`,
    /// one page, as SPTM's `uat_bootstrap_parse_dt` requires).
    pub shared_l2: u64,
}

/// The `sgx` banks of [`GfxController::sgx`] from `reg[0]` and `reg[1]`
/// (physical base, bytes).
fn sgx_banks(block: (u64, u64), info: (u64, u64)) -> Result<Vec<(u64, u64, u64)>, &'static str> {
    if block.1 == 0 || info.1 == 0 {
        return Err("sgx register view is empty");
    }
    let block_end = block.0.checked_add(block.1).ok_or("sgx block overflows")?;
    let info_end = info.0.checked_add(info.1).ok_or("sgx info overflows")?;
    if info.0 < block.0 {
        return Err("sgx reg[1] lies below reg[0]");
    }
    let mut banks = vec![(block.0, block.1, 0)];
    if info_end > block_end {
        if info.0 < block_end {
            return Err("sgx reg[1] straddles the end of reg[0]");
        }
        banks.push((info.0, info.1, info.0 - block.0));
    }
    Ok(banks)
}

pub(super) fn gfx_controller(
    io: &Node<'_>,
    translate: &dyn Fn(u64, u64) -> Option<u64>,
    chip_id: u32,
) -> Result<Option<GfxController>, String> {
    let asc = io
        .child("gfx-asc")
        .filter(|n| n.compatible(ASC) && n.property("role") == Some(b"GFX\0".as_slice()));
    // Several SoCs share one `sgx` compatible; the chip names the GPU.
    let sgx = io.child("sgx").filter(|n| {
        agx::generation::GPUS
            .iter()
            .any(|gpu| n.compatible(gpu.compatible))
    });
    let (asc, sgx) = match (asc, sgx) {
        (None, None) => return Ok(None),
        (Some(asc), Some(sgx)) => (asc, sgx),
        _ => return Err("the GFX coprocessor and the sgx GPU must be visible together".into()),
    };
    let gpu = agx::generation::by_chip(chip_id)
        .filter(|gpu| sgx.compatible(gpu.compatible))
        .ok_or_else(|| format!("sgx is not the GPU of ApChipID {chip_id:#x}"))?;
    gpu.admitted()
        .map_err(|reason| format!("{} is not modeled: {reason}", gpu.compatible))?;
    rtbuddy_nub(&asc, "GFX")?;
    let place = |node: &Node<'_>, index: usize, minimum: u64, what: &str| {
        let (offset, bytes) = apertures::registers(node)
            .and_then(|regs| regs.get(index).copied())
            .filter(|&(_, bytes)| bytes >= minimum)
            .ok_or_else(|| format!("{what} bank is absent or too short"))?;
        let physical =
            translate(offset, bytes).ok_or_else(|| format!("{what} outside arm-io ranges"))?;
        Ok::<_, String>((physical, bytes))
    };
    let wrapper = place(&asc, 0, asc::WRAPPER_BYTES, "gfx-asc wrapper")?;
    let block = place(&sgx, 0, 1, "sgx register")?;
    let info = place(&sgx, 1, 1, "sgx info")?;
    let banks = sgx_banks(block, info)?;
    agx::registers::covers(gpu.family, &banks)?;
    let irqs = asc
        .cells32("interrupts")
        .ok_or("gfx-asc has no interrupts")?;
    let irq = |index: usize| -> Result<u16, String> {
        irqs.get(index)
            .and_then(|&n| u16::try_from(n).ok())
            .ok_or_else(|| "gfx-asc needs four valid mailbox interrupts".into())
    };
    if sgx.property("gptbat-ready").is_none() {
        return Err("sgx has no gptbat-ready: the boot stage published no GPU TTBAT".into());
    }
    let ttbat = sgx
        .property("ttbat-phys-addr-base")
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .map(|page| u64::from(u32::from_le_bytes(page)) << agx::uat::PAGE_SHIFT)
        .filter(|&base| base != 0)
        .ok_or("sgx ttbat-phys-addr-base is not one nonzero 32-bit page number")?;
    let u64_property = |name: &str| {
        sgx.property(name)
            .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
            .map(u64::from_le_bytes)
    };
    let shared_l2 = match (
        u64_property("gfx-shared-l2-region-base"),
        u64_property("gfx-shared-l2-region-size"),
    ) {
        (Some(base), Some(agx::uat::PAGE_BYTES)) if base != 0 => base,
        _ => return Err("sgx gfx-shared-l2-region is not one nonzero 16 KiB page".into()),
    };
    Ok(Some(GfxController {
        gpu,
        wrapper,
        interrupts: [irq(0)?, irq(1)?, irq(2)?, irq(3)?],
        sgx: banks,
        ttbat,
        shared_l2,
    }))
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use super::*;
    use crate::board::fixture_support::flat_fixture_extent;

    #[test]
    fn gfx_placement_needs_the_coprocessor_and_the_gpu_together() {
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
        let tree = |asc_visible: bool, sgx_visible: bool| {
            let nub = encode(
                &[("name", &z("iop-gfx-nub0")), ("compatible", &z(RTBUDDY))],
                &[],
            );
            let (name, role, asc_compatible) = (z("gfx-asc"), z("GFX"), z(ASC));
            let asc_reg = pairs(&[(0x640_0000, 0x6c000), (0x605_0000, 8)]);
            let irqs = cells(&[0x2c6, 0x2c5, 0x2c8, 0x2c7]);
            let mut asc: Vec<(&str, &[u8])> = vec![
                ("name", &name),
                ("role", &role),
                ("reg", &asc_reg),
                ("interrupts", &irqs),
            ];
            if asc_visible {
                asc.push(("compatible", &asc_compatible));
            }
            let (sgx_name, sgx_compatible) = (z("sgx"), z("gpu,t8112"));
            let sgx_reg = pairs(&[(0x400_0000, 0x400_0000), (0x4d0_0000, 0x2_0000)]);
            let ttbat_page = cells(&[0x20_0011]);
            let l2_base = 0x8_0008_8000u64.to_le_bytes();
            let l2_size = 0x4000u64.to_le_bytes();
            let mut sgx: Vec<(&str, &[u8])> = vec![
                ("name", &sgx_name),
                ("reg", &sgx_reg),
                ("gptbat-ready", b""),
                ("ttbat-phys-addr-base", &ttbat_page),
                ("gfx-shared-l2-region-base", &l2_base),
                ("gfx-shared-l2-region-size", &l2_size),
            ];
            if sgx_visible {
                sgx.push(("compatible", &sgx_compatible));
            }
            let io = encode(
                &[("name", &z("arm-io"))],
                &[encode(&asc, &[nub]), encode(&sgx, &[])],
            );
            encode(&[("name", &z("device-tree"))], &[io])
        };
        let translate = |offset| Some(0x2_0000_0000 + offset);
        let placed_on = |asc: bool, sgx: bool, chip_id: u32| {
            let bytes = tree(asc, sgx);
            let root = Node::root(&bytes).unwrap();
            let io = root.child("arm-io").unwrap();
            gfx_controller(&io, &flat_fixture_extent(&translate), chip_id)
        };
        let placed = |asc: bool, sgx: bool| placed_on(asc, sgx, 0x8112);
        assert_eq!(
            placed(true, true).unwrap(),
            Some(GfxController {
                gpu: agx::generation::by_chip(0x8112).unwrap(),
                wrapper: (0x2_0640_0000, 0x6c000),
                interrupts: [0x2c6, 0x2c5, 0x2c8, 0x2c7],
                sgx: vec![(0x2_0400_0000, 0x400_0000, 0)],
                ttbat: 0x8_0004_4000,
                shared_l2: 0x8_0008_8000,
            })
        );
        assert_eq!(placed(false, false).unwrap(), None);
        assert!(placed(true, false).is_err());
        assert!(placed(false, true).is_err());
        // The `sgx` must be the board chip's own GPU.
        assert!(placed_on(true, true, 0x8103).is_err());
    }

    /// The census `sgx` layouts: T8112's `reg[1]` inside `reg[0]`, the
    /// T6000's 1 MiB `reg[0]` with the registers in `reg[1]`, and the
    /// T6020's longer `reg[1]` that holds the G14X core masks.
    #[test]
    fn sgx_banks_place_the_registers_at_their_offsets_from_reg0() {
        use agx::generation::{G13X, G14G, G14X};
        let t8112 = sgx_banks((0x2_0400_0000, 0x400_0000), (0x2_04d0_0000, 0x2_0000)).unwrap();
        assert_eq!(t8112, [(0x2_0400_0000, 0x400_0000, 0)]);
        assert_eq!(agx::registers::covers(&G14G, &t8112), Ok(()));
        let t6000 = sgx_banks((0x2_0400_0000, 0x10_0000), (0x2_04d0_0000, 0x2_0000)).unwrap();
        assert_eq!(
            t6000,
            [
                (0x2_0400_0000, 0x10_0000, 0),
                (0x2_04d0_0000, 0x2_0000, 0xd0_0000)
            ]
        );
        assert_eq!(agx::registers::covers(&G13X, &t6000), Ok(()));
        // The G14X core masks at 0xe01500 need T6020's 0x16c000-byte bank.
        assert!(agx::registers::covers(&G14X, &t6000).is_err());
        let t6020 = sgx_banks((0x2_0400_0000, 0x10_0000), (0x2_04d0_0000, 0x16_c000)).unwrap();
        assert_eq!(agx::registers::covers(&G14X, &t6020), Ok(()));
        assert!(sgx_banks((0x2_0400_0000, 0x10_0000), (0x2_0000_0000, 0x10)).is_err());
        assert!(sgx_banks((0x2_0400_0000, 0x10_0000), (0x2_040f_0000, 0x2_0000)).is_err());
    }
}
