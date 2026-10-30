//! DeviceTree placement and validation for interrupts.
use super::{
    AIC2_DIE_STRIDE, AIC2_MAX_DIES, AIC3_IRQ_CFG, AIC3_TIMESTAMPS, AicLayout, BTreeMap, Node,
    String, Vec,
};
use crate::Result;
use stela_contracts::refuse;

/// The AIC: its core block's guest PA, NR_IRQ (the inputs each die
/// reports) and its layout, which counts its populated dies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterruptController {
    pub physical: u64,
    pub inputs: u16,
    pub layout: AicLayout,
}

/// The register offsets and masks an `aic,3` node states, as m1n1 `aic.c`
/// and the 26A434 `AppleInterruptControllerV3` (`OverrideRegMap`) read them,
/// and the modeled layout they must match: the AICv2's registers with its
/// arrays at 0x10000 (Linux `aic3_info`) and its timestamp slots at 0x1000
/// ([`AIC3_TIMESTAMPS`]).
const AIC3_OFFSETS: [(&str, u32); 10] = [
    ("rev-offset", 0),
    ("cap0-offset", 0x4),
    ("maxnumirq-offset", 0xc),
    ("aicglbcfg-offset", 0x14),
    ("extint-baseaddress", AIC3_IRQ_CFG as u32),
    ("pubstampcfg0-offset", AIC3_TIMESTAMPS as u32),
    ("pubstamplo0-offset", AIC3_TIMESTAMPS as u32 + 8),
    ("pubstampdhi-offset", AIC3_TIMESTAMPS as u32 + 0xc),
    ("pubstampstride-mask", 0x10),
    ("pubstampdcfg0en-mask", 1 << 31),
];

/// The layout of an `/arm-io/aic` node compatible with `version` whose event
/// register is `event` bytes from its `reg`: the AICv1's, the AICv2's, or the
/// AICv3's once its stated offsets match the modeled layout. An `aic,3`
/// with `max-extint-num` selects the driver's doubled array layout
/// (`getAICIntMaskSetOffset`), which is not modeled.
pub(super) fn aic_layout(aic: &Node<'_>, version: &str, event: u64) -> Result<AicLayout> {
    let timestamps = aic.first_u32("#shared-timestamps").unwrap_or(0);
    let timestamps = u8::try_from(timestamps)
        .map_err(|_| refuse!("/arm-io/aic has {timestamps} shared timestamps", timestamps))?;
    match version {
        "aic,1" => return Ok(AicLayout::V1),
        "aic,2" => return Ok(AicLayout::aic2(event, timestamps)),
        _ => {}
    }
    for (name, expected) in AIC3_OFFSETS {
        let found = aic
            .first_u32(name)
            .ok_or_else(|| refuse!("/arm-io/aic has no {name}", name))?;
        if found != expected {
            return Err(refuse!(
                "/arm-io/aic {name} is {found:#x}, not the modeled {expected:#x}",
                name,
                found,
                expected
            ));
        }
    }
    if aic.property("max-extint-num").is_some() {
        return Err(refuse!(
            "/arm-io/aic max-extint-num selects an unmodeled array layout"
        ));
    }
    Ok(AicLayout::aic3(event, timestamps))
}

/// The `aic,3` properties that give each per-die array's die stride, which
/// the 26A434 `AppleInterruptControllerV3` multiplies by the die once
/// `extint-baseaddress` is stated (`getAICExtIntrCfgOffset`,
/// `getAICIntMaskSetOffset`, `getAICIntMaskClrOffset`,
/// `getAICHwIntMonOffset`). Two-die boards state [`AIC2_DIE_STRIDE`];
/// some single-die boards state 0, which die 0 never multiplies.
const AIC3_DIE_STRIDES: [&str; 4] = [
    "extintrcfg-stride",
    "intmaskset-stride",
    "intmaskclear-stride",
    "hwintmon-stride",
];

/// The AIC vectors the tree wires to the controller with phandle `aic`, in
/// tree order, as XNU's `IODTMapInterruptsSharing` maps each node's
/// `interrupts` (`iokit/Kernel/IODeviceTreeSupport.cpp`): a list of
/// specifiers, the i-th for `interrupt-parent` entry i, or entry 0 once the
/// entries run out (`IODTFindInterruptParent`), spanning that parent's
/// `#interrupt-cells` cells, one when unstated (`IODTGetICellCounts`); a
/// parent of zero cells ends the node's mapping (`IODTMapOneInterrupt`
/// returns 0). Specifiers for another parent are not the AIC's: every M3
/// Pro and later CLPC (`/arm-io/pmgr/clpc`) follows its AIC lines with
/// notification FourCCs such as 0x70305452 for `/arm-io/aon-ptd`.
pub(super) fn aic_vectors(root: &Node<'_>, aic: u32) -> Result<Vec<u32>> {
    let mut cells_of = BTreeMap::new();
    root.visit(&mut |node| {
        if let Some(phandle) = node.first_u32("AAPL,phandle") {
            cells_of.insert(phandle, node.first_u32("#interrupt-cells").unwrap_or(1));
        }
    })
    .ok_or(refuse!("DeviceTree walk failed"))?;
    if cells_of.get(&aic) != Some(&1) {
        return Err(refuse!(
            "/arm-io/aic does not number each input in one cell"
        ));
    }
    let mut vectors = Vec::new();
    let mut failure = None;
    root.visit(&mut |node| {
        let (Some(parents), Some(cells)) =
            (node.cells32("interrupt-parent"), node.cells32("interrupts"))
        else {
            return;
        };
        let name = || {
            let name = node.property("name").unwrap_or_default();
            String::from_utf8_lossy(name.strip_suffix(&[0]).unwrap_or(name)).into_owned()
        };
        let mut rest = cells.as_slice();
        for index in 0.. {
            let Some(&parent) = parents.get(index).or(parents.first()) else {
                break;
            };
            if rest.is_empty() {
                break;
            }
            let Some(&count) = cells_of.get(&parent) else {
                failure.get_or_insert_with(|| {
                    refuse!(
                        "{node} names interrupt parent {parent:#x}, which no node is",
                        node = name(),
                        parent
                    )
                });
                return;
            };
            if count == 0 {
                break;
            }
            let Some((specifier, tail)) = rest.split_at_checked(count as usize) else {
                failure.get_or_insert_with(|| {
                    refuse!("{node} ends inside an interrupt specifier", node = name())
                });
                return;
            };
            if parent == aic {
                vectors.push(specifier[0]);
            }
            rest = tail;
        }
    })
    .ok_or(refuse!("DeviceTree walk failed"))?;
    match failure {
        Some(failure) => Err(failure),
        None => Ok(vectors),
    }
}

/// NR_IRQ and the populated dies of an AIC with `layout` whose ADT node is
/// `aic` and whose wired vectors are `vectors` ([`aic_vectors`]), and the
/// layout with those dies. Vector V is die V / MAX_IRQ, IRQ V % MAX_IRQ, as
/// the 26A434 drivers number them (`platform::apple::aic`); the dies are
/// those up to the last one any vector names, at most the drivers'
/// [`AIC2_MAX_DIES`], and an AICv1 has one.
///
/// No 26A434 ADT or firmware states an AICv2's or AICv3's NR_IRQ, the
/// hardware's inputs per die, so the model reports the fewest that cover
/// every wired vector: one more than the highest IRQ on any die. The
/// drivers only use it to bound the mask words they set, so no higher count
/// would change what the guest sees of any wired input. An AICv1's ADT does
/// state it to the word: its `AppleInterruptController::start` panics
/// unless `ipid-mask` holds one bit per input rounded up to 32
/// (`kernelcache.release.mac13g`, "ipid-mask property length is %d but
/// should be %d"), and every M1's wired IRQs end at its 896th.
///
/// Each driver reads NR_IRQ through a field mask, which must hold it:
/// 0x3ff for an AICv1 and 0x7ff for an AICv2, and for an AICv3 the ADT's
/// `cap0_max_interrupt_umask` (0x7ff on J433, J504, J514s and J613, 0xffff
/// on most), with MAX_IRQ under its `max_irq_interrupt_umask`. A
/// multi-die AICv3 must state the modeled die stride for every array
/// ([`AIC3_DIE_STRIDES`]).
pub(super) fn aic_inputs(
    aic: &Node<'_>,
    layout: AicLayout,
    vectors: &[u32],
) -> Result<(u16, AicLayout)> {
    let max_irq = u32::from(layout.max_irq());
    let mut inputs = 0;
    let mut dies = 0;
    for &vector in vectors {
        inputs = inputs.max(vector % max_irq + 1);
        dies = dies.max(vector / max_irq + 1);
    }
    if inputs == 0 {
        return Err(refuse!("no node names the AIC as its interrupt parent"));
    }
    let mask = |name: &str| aic.first_u32(name).unwrap_or(0xffff);
    let (field, max_field) = match layout {
        AicLayout::V1 => (0x3ff, 0xffff),
        AicLayout::V2 { version: 2, .. } => (0x7ff, 0xffff),
        AicLayout::V2 { .. } => (
            mask("cap0_max_interrupt_umask"),
            mask("max_irq_interrupt_umask"),
        ),
    };
    if inputs & !field != 0 || max_irq & !max_field != 0 {
        return Err(refuse!(
            "/arm-io/aic's {inputs} inputs or {max_irq} IRQs per die exceed the fields its driver reads",
            inputs,
            max_irq
        ));
    }
    let inputs = u16::try_from(inputs).expect("below MAX_IRQ");
    if matches!(layout, AicLayout::V2 { version: 3, .. }) && dies > 1 {
        for name in AIC3_DIE_STRIDES {
            if aic.first_u32(name) != Some(AIC2_DIE_STRIDE as u32) {
                return Err(refuse!(
                    "/arm-io/aic {name} is not the modeled die stride {AIC2_DIE_STRIDE:#x}",
                    name,
                    AIC2_DIE_STRIDE
                ));
            }
        }
    }
    match layout {
        AicLayout::V1 => {
            if dies > 1 {
                return Err(refuse!(
                    "an aic,1 input is above its {max_irq:#x} IRQs",
                    max_irq
                ));
            }
            let words = aic
                .property("ipid-mask")
                .map(|mask| mask.len() / 4)
                .ok_or(refuse!("/arm-io/aic has no ipid-mask"))?;
            if words != usize::from(inputs).div_ceil(32) {
                return Err(refuse!(
                    "/arm-io/aic ipid-mask has {words} words for {inputs} inputs",
                    words,
                    inputs
                ));
            }
            Ok((inputs, layout))
        }
        AicLayout::V2 { .. } => {
            let dies = u8::try_from(dies)
                .ok()
                .filter(|&dies| dies <= AIC2_MAX_DIES)
                .ok_or_else(|| refuse!("an AIC vector names die {die}", die = dies - 1))?;
            Ok((inputs, layout.with_dies(dies)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use super::*;
    use crate::board::fixture_support::{clpc_with_ptd, tree_with, tree_with_io};

    #[test]
    fn an_aic3_board_states_the_modeled_offsets() {
        const M3: [&str; 3] = ["uart-1,samsung", "wdt,s5l8960x", "aic,3"];
        let found = board(&tree_with(0x8122, "Apple M3", M3, &AIC3_OFFSETS)).unwrap();
        assert_eq!(
            (found.cpus.chip, found.aic.layout),
            (Chip::AppleM3, AicLayout::aic3(0x40000, 0))
        );
        assert_eq!(
            board(&tree_with(0x8122, "Apple M3", M3, &AIC3_OFFSETS[1..])),
            Err(refuse!("/arm-io/aic has no rev-offset"))
        );
        let mut moved = AIC3_OFFSETS;
        moved[4].1 = 0x20000;
        assert_eq!(
            board(&tree_with(0x8122, "Apple M3", M3, &moved)),
            Err(refuse!(
                "/arm-io/aic extint-baseaddress is 0x20000, not the modeled 0x10000"
            ))
        );
        let mut doubled = AIC3_OFFSETS.to_vec();
        doubled.push(("max-extint-num", 0x2000));
        assert_eq!(
            board(&tree_with(0x8122, "Apple M3", M3, &doubled)),
            Err(refuse!(
                "/arm-io/aic max-extint-num selects an unmodeled array layout"
            ))
        );
        // The M3's driver reads NR_IRQ under an 11-bit mask, which holds
        // the UART's 740 but not a 9-bit one.
        let mut masked = AIC3_OFFSETS.to_vec();
        masked.push(("cap0_max_interrupt_umask", 0x7ff));
        assert!(board(&tree_with(0x8122, "Apple M3", M3, &masked)).is_ok());
        masked.last_mut().unwrap().1 = 0x1ff;
        assert_eq!(
            board(&tree_with(0x8122, "Apple M3", M3, &masked)),
            Err(refuse!(
                "/arm-io/aic's 740 inputs or 4096 IRQs per die exceed the fields its driver reads"
            ))
        );
        // A J514cAP-shaped CLPC: three AIC lines, then notification FourCCs
        // for the always-on PTD, which are not AIC inputs.
        let found = board(&tree_with_io(
            0x8122,
            "Apple M3",
            M3,
            &AIC3_OFFSETS,
            &clpc_with_ptd(),
        ))
        .unwrap();
        assert_eq!(found.aic.inputs, 0x5c0);
        assert_eq!(found.aic.layout.dies(), 1);
        // iBoot places every later AICv3's event register at +0x40000 too.
        for (chip_id, name, chip) in [
            (0x8132, "Apple M4", Chip::AppleM4),
            (0x8142, "Apple M5", Chip::AppleM5),
        ] {
            let found = board(&tree_with(chip_id, name, M3, &AIC3_OFFSETS)).unwrap();
            assert_eq!(
                (found.cpus.chip, found.aic.layout),
                (chip, AicLayout::aic3(AIC3_EVENT, 0))
            );
        }
    }

    #[test]
    fn aic_vectors_follow_each_specifiers_own_parent() {
        use stela_contracts::adt::encode;
        let z = |text: &str| [text.as_bytes(), &[0]].concat();
        let words = |cells: &[u32]| {
            cells
                .iter()
                .flat_map(|c| c.to_le_bytes())
                .collect::<Vec<_>>()
        };
        let node = |name: &str, parents: &[u32], cells: &[u32]| {
            encode(
                &[
                    ("name", &z(name)),
                    ("interrupt-parent", &words(parents)),
                    ("interrupts", &words(cells)),
                ],
                &[],
            )
        };
        let controller = |name: &str, phandle: u32, cells: u32| {
            encode(
                &[
                    ("name", &z(name)),
                    ("AAPL,phandle", &words(&[phandle])),
                    ("#interrupt-cells", &words(&[cells])),
                ],
                &[],
            )
        };
        let tree = |extra: Option<Vec<u8>>| {
            let mut children = clpc_with_ptd();
            children.extend([
                controller("aic", 0x63, 1),
                controller("pair", 0x64, 2),
                controller("none", 0x65, 0),
                // Past the parent list, specifiers take entry 0's parent:
                // two cells for 0x64, one AIC line, two cells for 0x64.
                node("mixed", &[0x64, 0x63], &[1, 2, 7, 3, 4]),
                // The second die's line 0x5bf.
                node("die1", &[0x63], &[0x15bf]),
                // A zero-cell parent ends the node's mapping.
                node("stops", &[0x63, 0x65], &[9, 0x9999]),
            ]);
            children.extend(extra);
            encode(&[("name", &z("device-tree"))], &children)
        };
        let ok = tree(None);
        let root = Node::root(&ok).unwrap();
        let vectors = aic_vectors(&root, 0x63).unwrap();
        assert_eq!(vectors, [0x5bf, 0, 0x5bd, 7, 0x15bf, 9]);
        // A parent no node is, and a specifier the cells end inside.
        for (extra, error) in [
            (
                node("lost", &[0x99], &[1]),
                "lost names interrupt parent 0x99, which no node is",
            ),
            (
                node("short", &[0x63, 0x64], &[1, 2]),
                "short ends inside an interrupt specifier",
            ),
        ] {
            let bad = tree(Some(extra));
            assert_eq!(
                aic_vectors(&Node::root(&bad).unwrap(), 0x63),
                Err(error.into())
            );
        }
        // The AIC numbers each input in one cell.
        assert!(aic_vectors(&root, 0x64).is_err());
    }

    #[test]
    fn aic_inputs_split_vectors_into_dies() {
        use stela_contracts::adt::encode;
        let z = |text: &str| [text.as_bytes(), &[0]].concat();
        let mask = |words: usize| {
            encode(
                &[("name", &z("aic")), ("ipid-mask", &vec![0xff; 4 * words])],
                &[],
            )
        };
        let v2 = AicLayout::aic2(0xc000, 16);
        let plain = encode(&[("name", &z("aic"))], &[]);
        let aic = Node::root(&plain).unwrap();
        // An M1 Ultra's: die 1's highest line 0x62c, die 0's 0x64d.
        assert_eq!(
            aic_inputs(&aic, v2, &[0x64d, 0x162c, 3]),
            Ok((0x64e, v2.with_dies(2)))
        );
        assert_eq!(
            aic_inputs(&aic, v2, &[0x77fe]),
            Ok((0x7ff, v2.with_dies(8)))
        );
        assert_eq!(
            aic_inputs(&aic, v2, &[0x8000]),
            Err(refuse!("an AIC vector names die 8"))
        );
        // The aic,2 driver reads NR_IRQ from INFO1 [10:0].
        assert_eq!(
            aic_inputs(&aic, v2, &[0x7ff]),
            Err(refuse!(
                "/arm-io/aic's 2048 inputs or 4096 IRQs per die exceed the fields its driver reads"
            ))
        );
        // An M3 Ultra's second die (its CLPC's 0x15bf) needs the stated die
        // strides.
        let v3 = AicLayout::aic3(AIC3_EVENT, 16);
        assert_eq!(
            aic_inputs(&aic, v3, &[0x5bf, 0x15bf]),
            Err(refuse!(
                "/arm-io/aic extintrcfg-stride is not the modeled die stride 0x4a00"
            ))
        );
        let stride = (AIC2_DIE_STRIDE as u32).to_le_bytes();
        let strided = encode(&AIC3_DIE_STRIDES.map(|name| (name, stride.as_slice())), &[]);
        assert_eq!(
            aic_inputs(&Node::root(&strided).unwrap(), v3, &[0x5bf, 0x15bf]),
            Ok((0x5c0, v3.with_dies(2)))
        );
        // One die never multiplies the stride, which some boards state as 0.
        assert_eq!(aic_inputs(&aic, v3, &[0x5bf]), Ok((0x5c0, v3)));
        assert_eq!(
            aic_inputs(&aic, v2, &[]),
            Err(refuse!("no node names the AIC as its interrupt parent"))
        );
        // An M1's 896 inputs fill its 28-word ipid-mask; its one die holds
        // 0x400 IRQs.
        let m1 = mask(28);
        let aic = Node::root(&m1).unwrap();
        assert_eq!(
            aic_inputs(&aic, AicLayout::V1, &[0x37f, 5]),
            Ok((0x380, AicLayout::V1))
        );
        assert_eq!(
            aic_inputs(&aic, AicLayout::V1, &[0x35f]),
            Err(refuse!("/arm-io/aic ipid-mask has 28 words for 864 inputs"))
        );
        assert_eq!(
            aic_inputs(&aic, AicLayout::V1, &[0x400]),
            Err(refuse!("an aic,1 input is above its 0x400 IRQs"))
        );
        let aic = Node::root(&plain).unwrap();
        assert_eq!(
            aic_inputs(&aic, AicLayout::V1, &[0x37f]),
            Err(refuse!("/arm-io/aic has no ipid-mask"))
        );
    }
}
