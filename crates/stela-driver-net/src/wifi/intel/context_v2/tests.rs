use super::super::{
    identity::Observed,
    platform::{self, CapturedVariable, Observation, Stage, Variable},
};
use super::*;
use crate::firmware::Catalog;
use alloc::{string::String, vec::Vec};
use sha2::{Digest, Sha256};

fn profile() -> Profile {
    Profile::select(Observed {
        vendor: 0x8086,
        device: 0x2725,
        subsystem_vendor: 0x8086,
        subsystem_device: 0x0084,
        pci_revision: 0x1a,
        hardware_revision: 0x420,
        radio_id: 0x10d000,
    })
    .unwrap()
}
fn tlv(bytes: &mut Vec<u8>, kind: u32, data: &[u8]) {
    bytes.extend(kind.to_le_bytes());
    bytes.extend((data.len() as u32).to_le_bytes());
    bytes.extend(data);
    bytes.resize(bytes.len().next_multiple_of(4), 0);
}
fn image() -> Vec<u8> {
    let mut bytes = vec![0; 88];
    bytes[4..8].copy_from_slice(&0x0a4c5749u32.to_le_bytes());
    bytes[72..76].copy_from_slice(&(89u32 << 8).to_le_bytes());
    tlv(&mut bytes, 27, &2u32.to_le_bytes());
    tlv(&mut bytes, 32, &4096u32.to_le_bytes());
    for (offset, len) in [
        (0u32, 16),
        (0xffffcccc, 0),
        (0x1000, 16),
        (0xaaaabbbb, 0),
        (0, 16),
        (0x2000, 4096),
    ] {
        let mut section = offset.to_le_bytes().to_vec();
        section.resize(4 + len, 0x5a);
        tlv(&mut bytes, 19, &section);
    }
    bytes
}
fn step_catalog(present: bool) -> (Observation, Catalog) {
    if present {
        let mut captured = CapturedVariable::from_variable(
            Variable::Step,
            vec![1, 0xab, 0x12, 0x34, 0x56, 0x78],
            7,
            Some(6),
        )
        .unwrap();
        (
            captured.observation(),
            Catalog::from_handoff(vec![captured.take_resource().unwrap()]).unwrap(),
        )
    } else {
        (
            Observation::from_error(Stage::Probe, (1 << 63) | 14, None),
            Catalog::from_handoff(vec![]).unwrap(),
        )
    }
}
fn queues(entries: u16) -> Queues {
    Queues {
        free: Region {
            address: 0x10000,
            bytes: usize::from(entries) * 16,
        },
        used: Region {
            address: 0x20000,
            bytes: usize::from(entries) * 32,
        },
        status: Region {
            address: 0x30000,
            bytes: 2,
        },
        command: Region {
            address: 0x40000,
            bytes: 32768,
        },
        receive_entries: entries,
    }
}
fn memory() -> Memory {
    Memory {
        info: Region {
            address: 0x50000,
            bytes: INFO_BYTES,
        },
        scratch: Region {
            address: 0x60000,
            bytes: SCRATCH_BYTES,
        },
        context: Region {
            address: 0x70000,
            bytes: CONTEXT_BYTES,
        },
        iml: Region {
            address: 0x80000,
            bytes: 64,
        },
    }
}
fn regions(fw: &Firmware<'_>) -> [Vec<Region>; 3] {
    let plan = fw.self_load_plan().unwrap();
    let mut address = 0x100000;
    [plan.lmac(), plan.umac(), plan.paging()].map(|sections| {
        sections
            .iter()
            .map(|s| {
                let region = Region {
                    address,
                    bytes: s.data.len(),
                };
                address += (s.data.len() as u64).next_multiple_of(4096);
                region
            })
            .collect()
    })
}
fn images(regions: &[Vec<Region>; 3]) -> Images<'_> {
    Images {
        lmac: &regions[0],
        umac: &regions[1],
        paging: &regions[2],
    }
}

#[test]
fn exact_full_scratch_size_byte_advertisement_tail_slots_and_step() {
    let mut bytes = image();
    tlv(&mut bytes, 52, &[0x5a; 64]);
    let fw = Firmware::parse(&bytes).unwrap();
    let regions = regions(&fw);
    for present in [false, true] {
        let (observation, catalog) = step_catalog(present);
        let step = platform::load_step(observation, &catalog).unwrap();
        for entries in [16, 32, 64, 128, 256, 512, 1024] {
            let result = Ax210Context::encode(
                &profile(),
                &fw,
                queues(entries),
                images(&regions),
                memory(),
                &step,
            )
            .unwrap();
            let mut expected_context = [0; CONTEXT_BYTES];
            for (at, address) in [
                (8, 0x50000u64),
                (16, 0x30000),
                (24, 0x50800),
                (32, 0x50c00),
                (52, 0x40000),
                (60, 0x20000),
                (88, 0x60000),
            ] {
                expected_context[at..at + 8].copy_from_slice(&address.to_le_bytes());
            }
            expected_context[68..70].copy_from_slice(&4u16.to_le_bytes());
            expected_context[70..72].copy_from_slice(&(entries.ilog2() as u16).to_le_bytes());
            expected_context[96..100].copy_from_slice(&1660u32.to_le_bytes());
            assert_eq!(*result.context(), expected_context);
            let mut expected_scratch = [0; SCRATCH_BYTES];
            expected_scratch[..2].copy_from_slice(&0x420u16.to_le_bytes());
            expected_scratch[4..6].copy_from_slice(&431u16.to_le_bytes());
            expected_scratch[8..12].copy_from_slice(&0xf0000u32.to_le_bytes());
            expected_scratch[48..56].copy_from_slice(&0x10000u64.to_le_bytes());
            for (at, value) in [
                (76, if present { 0x56341201u32 } else { 0 }),
                (80, if present { 0x78 } else { 0 }),
            ] {
                expected_scratch[at..at + 4].copy_from_slice(&value.to_le_bytes());
            }
            for (base, regions) in [(124, &regions[1]), (636, &regions[0]), (1148, &regions[2])] {
                for (i, region) in regions.iter().enumerate() {
                    expected_scratch[base + i * 8..base + i * 8 + 8]
                        .copy_from_slice(&region.address.to_le_bytes());
                }
            }
            assert_eq!(*result.scratch(), expected_scratch);
        }
    }
}
#[test]
fn missing_iml_wrong_family_api_and_all_resource_constraints_refuse() {
    let mut bytes = image();
    let (observation, catalog) = step_catalog(false);
    let step = platform::load_step(observation, &catalog).unwrap();
    let fw = Firmware::parse(&bytes).unwrap();
    let regions = regions(&fw);
    assert_eq!(
        Ax210Context::encode(
            &profile(),
            &fw,
            queues(32),
            images(&regions),
            memory(),
            &step
        )
        .unwrap_err(),
        Error::Firmware(firmware::Error::Missing("IML"))
    );
    tlv(&mut bytes, 52, &[0x55; 64]);
    let fw = Firmware::parse(&bytes).unwrap();
    let mut observed = profile().observed();
    observed.device = 0x2723;
    observed.hardware_revision = 0x340;
    observed.radio_id = 0x10a000;
    assert_eq!(
        Ax210Context::encode(
            &Profile::select(observed).unwrap(),
            &fw,
            queues(32),
            images(&regions),
            memory(),
            &step
        )
        .unwrap_err(),
        Error::WrongFamily
    );
    for entries in [0, 8, 17, 2048] {
        assert_eq!(
            Ax210Context::encode(
                &profile(),
                &fw,
                queues(entries),
                images(&regions),
                memory(),
                &step
            )
            .unwrap_err(),
            Error::Layout(context::Error::QueueSize)
        );
    }
    for field in 0..8 {
        for mode in 0..5 {
            let mut q = queues(32);
            let mut m = memory();
            let selected = match field {
                0 => &mut q.free,
                1 => &mut q.used,
                2 => &mut q.status,
                3 => &mut q.command,
                4 => &mut m.info,
                5 => &mut m.scratch,
                6 => &mut m.context,
                _ => &mut m.iml,
            };
            match mode {
                0 => selected.bytes -= 1,
                1 => selected.address = 0,
                2 => selected.address += 1,
                3 => selected.address = u64::MAX - 3,
                _ => selected.address = 0x10000,
            };
            if mode == 4 && field == 0 {
                continue;
            }
            assert!(
                Ax210Context::encode(&profile(), &fw, q, images(&regions), m, &step).is_err(),
                "{field} {mode}"
            );
        }
    }
    let mut m = memory();
    m.info.address = 0xfffff000;
    assert_eq!(
        Ax210Context::encode(&profile(), &fw, queues(32), images(&regions), m, &step).unwrap_err(),
        Error::Layout(context::Error::FourGiBoundary)
    );
    assert!(
        Ax210Context::encode(
            &profile(),
            &fw,
            queues(32),
            Images {
                lmac: &[],
                ..images(&regions)
            },
            memory(),
            &step
        )
        .is_err()
    );
    bytes[72..76].copy_from_slice(&(77u32 << 8).to_le_bytes());
    assert!(matches!(
        Ax210Context::encode(
            &profile(),
            &Firmware::parse(&bytes).unwrap(),
            queues(32),
            images(&regions),
            memory(),
            &step
        ),
        Err(Error::Firmware(firmware::Error::FirmwareApi { .. }))
    ));
}

fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write;
    let mut text = String::new();
    for byte in bytes {
        write!(&mut text, "{byte:02x}").unwrap();
    }
    text
}
fn fnv(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf29ce484222325u64, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
    })
}
#[test]
#[ignore = "oracle: STELA_IWLWIFI_CONTEXT_V2_ORACLE, STELA_IWLWIFI_IMAGES"]
fn unchanged_linux_ax210_context_scratch_iml_and_payload_copies() {
    extern crate std;
    let trace = std::fs::read(std::env::var("STELA_IWLWIFI_CONTEXT_V2_ORACLE").unwrap()).unwrap();
    assert_eq!(
        hex(&Sha256::digest(&trace)),
        "6258e28c8346ab6f4e40233d4f2c662b75117c9ea8852809fe9fca3190d45874"
    );
    let root = std::env::var("STELA_IWLWIFI_IMAGES").unwrap();
    let bytes =
        std::fs::read(std::path::Path::new(&root).join(Family::Ax210.firmware_name())).unwrap();
    assert_eq!(
        hex(&Sha256::digest(&bytes)),
        "792478ef7752595525379a5068e2d47e310a2c344636b7df866c54746ced1dc0"
    );
    let fw = Firmware::parse(&bytes).unwrap();
    let plan = fw.self_load_plan().unwrap();
    let mut lines = core::str::from_utf8(&trace).unwrap().lines();
    assert_eq!(
        lines.next().unwrap(),
        "layout 104 1724 1660 124 636 1148 16"
    );
    let mut cases = 0;
    while let Some(line) = lines.next() {
        let fields: Vec<_> = line.split_whitespace().collect();
        assert_eq!(fields[0], "case");
        let entries = fields[1].parse().unwrap();
        let (observation, catalog) = step_catalog(fields[2] == "1");
        let step = platform::load_step(observation, &catalog).unwrap();
        let fields: Vec<_> = lines.next().unwrap().split_whitespace().collect();
        assert_eq!(fields[0], "memory");
        let address = |at| u64::from_str_radix(fields[at], 16).unwrap();
        let memory = Memory {
            info: Region {
                address: address(1),
                bytes: INFO_BYTES,
            },
            scratch: Region {
                address: address(2),
                bytes: SCRATCH_BYTES,
            },
            context: Region {
                address: address(3),
                bytes: CONTEXT_BYTES,
            },
            iml: Region {
                address: address(4),
                bytes: fields[5].parse().unwrap(),
            },
        };
        let mut regions = [Vec::new(), Vec::new(), Vec::new()];
        for (bank, sections) in [plan.lmac(), plan.umac(), plan.paging()]
            .into_iter()
            .enumerate()
        {
            for (index, section) in sections.iter().enumerate() {
                let fields: Vec<_> = lines.next().unwrap().split_whitespace().collect();
                assert_eq!(fields[0], "section");
                assert_eq!(fields[1], ["L", "U", "P"][bank]);
                assert_eq!(fields[2].parse::<usize>().unwrap(), index);
                assert_eq!(fields[3].parse::<usize>().unwrap(), section.data.len());
                assert_eq!(
                    u64::from_str_radix(fields[4], 16).unwrap(),
                    fnv(section.data)
                );
                regions[bank].push(Region {
                    address: u64::from_str_radix(fields[5], 16).unwrap(),
                    bytes: section.data.len(),
                });
            }
        }
        let iml = fw.iml().unwrap();
        assert_eq!(iml.len(), 13944);
        assert_eq!(
            hex(&Sha256::digest(iml)),
            "78a40b5d954dcf9d86d64a5b37ffa9ecd826ff58eab5fe5c1b56c630106634d0"
        );
        assert_eq!(
            lines.next().unwrap(),
            alloc::format!("iml {:016x}", fnv(iml))
        );
        let result = Ax210Context::encode(
            &profile(),
            &fw,
            queues(entries),
            images(&regions),
            memory,
            &step,
        )
        .unwrap();
        assert_eq!(
            lines.next().unwrap(),
            alloc::format!("context {}", hex(result.context()))
        );
        assert_eq!(
            lines.next().unwrap(),
            alloc::format!("scratch {}", hex(result.scratch()))
        );
        cases += 1;
    }
    assert_eq!(cases, 14);
}
