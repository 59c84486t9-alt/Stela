//! Apple SoCs: a board's chip and PEs from its DeviceTree.
//!
//! The board's DeviceTree gives the SoC: `/chosen` `chip-id` (the identity's
//! ApChipID, which the boot bundle writes there as iBoot does), `/product`
//! `product-soc-name`, and one `/cpus` node per PE with `reg` and
//! `cluster-type`. Each SoC row pairs an ApChipID with the
//! `product-soc-name` its boards' DeviceTrees give in UniversalMac 26A434 and
//! the MIDR_EL1 part number of each cluster type (m1n1 `src/midr.h`
//! `MIDR_PART_<soc>_<core>`). A SoC, cluster type or affinity without that
//! evidence refuses: the M1, M2 and M3 Ultra, the second M3 Max (ApChipID
//! 0x6034), the A18 Pro and the M5 Pro and Max (no `product-soc-name`), and
//! the M6's M cores.
use super::{Chip, registers::Identity};
use alloc::{format, string::String, vec::Vec};

/// One SoC row: ApChipID, `product-soc-name`, chip, and the MIDR_EL1 part
/// number of each `cluster-type`.
struct Soc {
    chip_id: u32,
    name: &'static str,
    chip: Chip,
    parts: &'static [(u8, u16)],
}

const fn soc(chip_id: u32, name: &'static str, chip: Chip, parts: &'static [(u8, u16)]) -> Soc {
    Soc {
        chip_id,
        name,
        chip,
        parts,
    }
}

const SOCS: [Soc; 14] = [
    soc(
        0x8103,
        "Apple M1",
        Chip::AppleM1,
        &[(b'E', 0x022), (b'P', 0x023)],
    ),
    soc(
        0x6000,
        "Apple M1 Pro",
        Chip::AppleM1,
        &[(b'E', 0x024), (b'P', 0x025)],
    ),
    soc(
        0x6001,
        "Apple M1 Max",
        Chip::AppleM1,
        &[(b'E', 0x028), (b'P', 0x029)],
    ),
    soc(
        0x8112,
        "Apple M2",
        Chip::AppleM2,
        &[(b'E', 0x032), (b'P', 0x033)],
    ),
    soc(
        0x6020,
        "Apple M2 Pro",
        Chip::AppleM2,
        &[(b'E', 0x034), (b'P', 0x035)],
    ),
    soc(
        0x6021,
        "Apple M2 Max",
        Chip::AppleM2,
        &[(b'E', 0x038), (b'P', 0x039)],
    ),
    soc(
        0x8122,
        "Apple M3",
        Chip::AppleM3,
        &[(b'E', 0x042), (b'P', 0x043)],
    ),
    soc(
        0x6030,
        "Apple M3 Pro",
        Chip::AppleM3,
        &[(b'E', 0x044), (b'P', 0x045)],
    ),
    soc(
        0x6031,
        "Apple M3 Max",
        Chip::AppleM3,
        &[(b'E', 0x048), (b'P', 0x049)],
    ),
    soc(
        0x8132,
        "Apple M4",
        Chip::AppleM4,
        &[(b'E', 0x052), (b'P', 0x053)],
    ),
    soc(
        0x6040,
        "Apple M4 Pro",
        Chip::AppleM4,
        &[(b'E', 0x054), (b'P', 0x055)],
    ),
    soc(
        0x6041,
        "Apple M4 Max",
        Chip::AppleM4,
        &[(b'E', 0x058), (b'P', 0x059)],
    ),
    soc(
        0x8142,
        "Apple M5",
        Chip::AppleM5,
        &[(b'E', 0x062), (b'P', 0x063)],
    ),
    soc(
        0x8152,
        "Apple M6",
        Chip::AppleM6,
        &[(b'E', 0x072), (b'P', 0x073)],
    ),
];

/// One `/cpus` node: its `cluster-type` letter and `reg`.
#[derive(Debug, Clone, Copy)]
pub struct Processor {
    pub cluster_type: u8,
    pub reg: u32,
}

/// The chip and PEs, in `/cpus` order, of a board whose DeviceTree names
/// `chip_id` and `soc_name`.
///
/// MIDR_EL1 is implementer 0x61 (Apple), variant 1, architecture 0xF, the
/// cluster type's part and revision 0, the values the J473AP profile has
/// always used; variant and revision are inferred until a reference capture
/// supplies them. MPIDR_EL1 is `reg` with bit 31 RES1:
/// `reg` is Aff1 (cluster) and Aff0 (core) on every single-die board (the
/// J473AP's cpu0-3 are 0-3 and cpu4-7 0x100-0x103), and U and MT are 0 for a
/// multiprocessor without multithreading (inferred). A `reg` beyond Aff1's
/// first eight clusters, as the multi-die boards use, has no public MPIDR
/// mapping and refuses.
pub fn board(
    chip_id: u32,
    soc_name: &str,
    processors: &[Processor],
) -> Result<(Chip, Vec<Identity>), String> {
    let soc = SOCS
        .iter()
        .find(|soc| soc.chip_id == chip_id)
        .ok_or_else(|| format!("ApChipID {chip_id:#x} ({soc_name}) has no public MIDR part"))?;
    if soc.name != soc_name {
        return Err(format!(
            "ApChipID {chip_id:#x} is {}, but the DeviceTree names {soc_name}",
            soc.name
        ));
    }
    if processors.is_empty() {
        return Err("the DeviceTree has no /cpus nodes".into());
    }
    let identities = processors
        .iter()
        .map(|processor| {
            let part = soc
                .parts
                .iter()
                .find(|(cluster_type, _)| *cluster_type == processor.cluster_type)
                .map(|(_, part)| u64::from(*part))
                .ok_or_else(|| {
                    format!(
                        "{} cluster type {} has no public MIDR part",
                        soc.name,
                        char::from(processor.cluster_type)
                    )
                })?;
            if processor.reg & !0x7ff != 0 {
                return Err(format!(
                    "{} cpu reg {:#x} has no public MPIDR mapping",
                    soc.name, processor.reg
                ));
            }
            Ok(Identity {
                midr: 0x61 << 24 | 1 << 20 | 0xf << 16 | part << 4,
                mpidr: 0x8000_0000 | u64::from(processor.reg),
            })
        })
        .collect::<Result<_, String>>()?;
    Ok((soc.chip, identities))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cpus(layout: &[(u8, u32)]) -> Vec<Processor> {
        layout
            .iter()
            .map(|&(cluster_type, reg)| Processor { cluster_type, reg })
            .collect()
    }

    #[test]
    fn a_board_takes_its_chip_and_pes_from_the_device_tree() {
        // J473AP (Mac14,3): cpu0-3 Blizzard E cores, cpu4-7 Avalanche P cores.
        let layout: Vec<(u8, u32)> = (0..8)
            .map(|cpu| {
                (
                    if cpu < 4 { b'E' } else { b'P' },
                    ((cpu / 4) << 8) | (cpu % 4),
                )
            })
            .collect();
        let (chip, identities) = board(0x8112, "Apple M2", &cpus(&layout)).unwrap();
        assert_eq!(chip, Chip::AppleM2);
        assert_eq!(
            identities[0],
            Identity {
                midr: 0x611f_0320,
                mpidr: 0x8000_0000
            }
        );
        assert_eq!(
            identities[7],
            Identity {
                midr: 0x611f_0330,
                mpidr: 0x8000_0103
            }
        );
        // J604AP (Mac16,1): six M4 E cores and four P cores.
        let layout = [(b'E', 0), (b'E', 5), (b'P', 0x100), (b'P', 0x103)];
        let (chip, identities) = board(0x8132, "Apple M4", &cpus(&layout)).unwrap();
        assert_eq!(chip, Chip::AppleM4);
        assert_eq!(identities[1].midr, 0x611f_0520);
        assert_eq!(
            identities[3],
            Identity {
                midr: 0x611f_0530,
                mpidr: 0x8000_0103
            }
        );
        // Every ApChipID appears once, and each chip has an E and a P part.
        for (index, soc) in SOCS.iter().enumerate() {
            assert!(
                SOCS[index + 1..]
                    .iter()
                    .all(|other| other.chip_id != soc.chip_id)
            );
            assert_eq!(soc.parts.len(), 2, "{}", soc.name);
        }
    }

    #[test]
    fn a_board_without_evidence_refuses() {
        let one = cpus(&[(b'E', 0)]);
        // M2 Ultra: two dies, no public part numbers.
        assert_eq!(
            board(0x6022, "Apple M2 Ultra", &one),
            Err("ApChipID 0x6022 (Apple M2 Ultra) has no public MIDR part".into())
        );
        assert!(board(0x8112, "Apple M2 Pro", &one).is_err());
        assert!(board(0x8112, "Apple M2", &[]).is_err());
        // The M6's M cores and a second die's affinity.
        assert_eq!(
            board(0x8152, "Apple M6", &cpus(&[(b'M', 0)])),
            Err("Apple M6 cluster type M has no public MIDR part".into())
        );
        assert!(board(0x6031, "Apple M3 Max", &cpus(&[(b'P', 0x800)])).is_err());
    }
}
