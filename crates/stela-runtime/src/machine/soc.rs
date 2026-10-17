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

/// One SoC row: ApChipID, `product-soc-name`, chip, the MIDR_EL1 part
/// number of each `cluster-type`, and for an `aic,2` interrupt controller the
/// offset of its event register from the `aic` `reg` (Linux
/// `arch/arm64/boot/dts/apple`: 0x8000 in `t8112.dtsi`, 0xc000 in
/// `t600x-die0.dtsi` and `t602x-die0.dtsi`). The M1's `aic,1` and the `aic,3`
/// of the M3 and later have no event offset here. `dram_base` is where the
/// SoC places DRAM (the `memory@` node of Linux `t8103-jxxx.dtsi`,
/// `t8112-jxxx.dtsi`, `t600x-j314-j316.dtsi` and `t600x-j375.dtsi`, which the
/// t602x boards include); the SoCs without a public memory node have none.
struct Soc {
    chip_id: u32,
    name: &'static str,
    chip: Chip,
    parts: [(u8, u16); 2],
    aic2_event: Option<u64>,
    dram_base: Option<u64>,
}

const SOCS: [Soc; 14] = [
    Soc {
        chip_id: 0x8103,
        name: "Apple M1",
        chip: Chip::AppleM1,
        parts: [(b'E', 0x022), (b'P', 0x023)],
        aic2_event: None,
        dram_base: Some(0x8_0000_0000),
    },
    Soc {
        chip_id: 0x6000,
        name: "Apple M1 Pro",
        chip: Chip::AppleM1,
        parts: [(b'E', 0x024), (b'P', 0x025)],
        aic2_event: Some(0xc000),
        dram_base: Some(0x100_0000_0000),
    },
    Soc {
        chip_id: 0x6001,
        name: "Apple M1 Max",
        chip: Chip::AppleM1,
        parts: [(b'E', 0x028), (b'P', 0x029)],
        aic2_event: Some(0xc000),
        dram_base: Some(0x100_0000_0000),
    },
    Soc {
        chip_id: 0x8112,
        name: "Apple M2",
        chip: Chip::AppleM2,
        parts: [(b'E', 0x032), (b'P', 0x033)],
        aic2_event: Some(0x8000),
        dram_base: Some(0x8_0000_0000),
    },
    Soc {
        chip_id: 0x6020,
        name: "Apple M2 Pro",
        chip: Chip::AppleM2,
        parts: [(b'E', 0x034), (b'P', 0x035)],
        aic2_event: Some(0xc000),
        dram_base: Some(0x100_0000_0000),
    },
    Soc {
        chip_id: 0x6021,
        name: "Apple M2 Max",
        chip: Chip::AppleM2,
        parts: [(b'E', 0x038), (b'P', 0x039)],
        aic2_event: Some(0xc000),
        dram_base: Some(0x100_0000_0000),
    },
    Soc {
        chip_id: 0x8122,
        name: "Apple M3",
        chip: Chip::AppleM3,
        parts: [(b'E', 0x042), (b'P', 0x043)],
        aic2_event: None,
        dram_base: None,
    },
    Soc {
        chip_id: 0x6030,
        name: "Apple M3 Pro",
        chip: Chip::AppleM3,
        parts: [(b'E', 0x044), (b'P', 0x045)],
        aic2_event: None,
        dram_base: None,
    },
    Soc {
        chip_id: 0x6031,
        name: "Apple M3 Max",
        chip: Chip::AppleM3,
        parts: [(b'E', 0x048), (b'P', 0x049)],
        aic2_event: None,
        dram_base: None,
    },
    Soc {
        chip_id: 0x8132,
        name: "Apple M4",
        chip: Chip::AppleM4,
        parts: [(b'E', 0x052), (b'P', 0x053)],
        aic2_event: None,
        dram_base: None,
    },
    Soc {
        chip_id: 0x6040,
        name: "Apple M4 Pro",
        chip: Chip::AppleM4,
        parts: [(b'E', 0x054), (b'P', 0x055)],
        aic2_event: None,
        dram_base: None,
    },
    Soc {
        chip_id: 0x6041,
        name: "Apple M4 Max",
        chip: Chip::AppleM4,
        parts: [(b'E', 0x058), (b'P', 0x059)],
        aic2_event: None,
        dram_base: None,
    },
    Soc {
        chip_id: 0x8142,
        name: "Apple M5",
        chip: Chip::AppleM5,
        parts: [(b'E', 0x062), (b'P', 0x063)],
        aic2_event: None,
        dram_base: None,
    },
    Soc {
        chip_id: 0x8152,
        name: "Apple M6",
        chip: Chip::AppleM6,
        parts: [(b'E', 0x072), (b'P', 0x073)],
        aic2_event: None,
        dram_base: None,
    },
];

/// What a board's DeviceTree selects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Board {
    pub chip: Chip,
    /// The PEs in `/cpus` order.
    pub processors: Vec<Identity>,
    /// The AIC2 event register's offset from the `aic` `reg`, on a SoC whose
    /// interrupt controller is `aic,2`.
    pub aic2_event: Option<u64>,
}

/// The guest DRAM base of the SoC with `chip_id`.
pub fn dram_base(chip_id: u32) -> Result<u64, String> {
    SOCS.iter()
        .find(|soc| soc.chip_id == chip_id)
        .and_then(|soc| soc.dram_base)
        .ok_or_else(|| format!("ApChipID {chip_id:#x} has no public DRAM base"))
}

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
pub fn board(chip_id: u32, soc_name: &str, processors: &[Processor]) -> Result<Board, String> {
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
    let processors = processors
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
    Ok(Board {
        chip: soc.chip,
        processors,
        aic2_event: soc.aic2_event,
    })
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
        let board_ = board(0x8112, "Apple M2", &cpus(&layout)).unwrap();
        assert_eq!(
            (board_.chip, board_.aic2_event),
            (Chip::AppleM2, Some(0x8000))
        );
        let identities = board_.processors;
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
        let board_ = board(0x8132, "Apple M4", &cpus(&layout)).unwrap();
        assert_eq!((board_.chip, board_.aic2_event), (Chip::AppleM4, None));
        let identities = board_.processors;
        assert_eq!(identities[1].midr, 0x611f_0520);
        assert_eq!(
            identities[3],
            Identity {
                midr: 0x611f_0530,
                mpidr: 0x8000_0103
            }
        );
        // An M2 Pro's AIC2 has its event register at +0xc000.
        assert_eq!(
            board(0x6020, "Apple M2 Pro", &cpus(&layout))
                .unwrap()
                .aic2_event,
            Some(0xc000)
        );
        assert_eq!(dram_base(0x8112), Ok(0x8_0000_0000));
        assert_eq!(dram_base(0x6021), Ok(0x100_0000_0000));
        assert!(dram_base(0x8132).is_err());
        // Every ApChipID appears once.
        for (index, soc) in SOCS.iter().enumerate() {
            assert!(
                SOCS[index + 1..]
                    .iter()
                    .all(|other| other.chip_id != soc.chip_id)
            );
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
