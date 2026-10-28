//! PMGR's input to PMP grouping, independent of requested or applied state.
//!
//! 26A434 ApplePMGR::_getPMPDeviceIndex (J473 VA 0xfffffe0009ba5c84)
//! loads the source ID from DeviceData byte 3, adds die times the PMP nub's
//! soc-device-die-offset, and looks up the soc-device ordinal. The common
//! helper uses the same fields in every original mac13g..mac18g kernel.
//! Native PMP owns that table and its die/instance policy. A source byte is
//! neither a canonical PMGR ID nor a completion token.

use super::{Dies, DomainId, Layout, Node, PMGR_DEVICE, PowerStates, Record, SOCS};
use alloc::{format, string::String, vec::Vec};

/// One original PMGR member of a potential PMP power group. Multiple
/// physical domains and virtual aliases can share the same raw source ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PmpDomain {
    pub id: DomainId,
    /// Virtual members have no register and still remain in the inventory.
    pub address: Option<u64>,
    /// Unadjusted DeviceData byte 3, including zero and unmatched sources.
    pub source: u8,
}

impl PowerStates {
    /// Recover source identities against the exact canonical domain table.
    /// This supplies no group membership, initial state or lifecycle credit;
    /// native PMP resolves sources with its own original soc-device table.
    pub fn pmp_domains(&self, root: &Node<'_>) -> Result<Vec<PmpDomain>, String> {
        let io = root.child("arm-io").ok_or("PMP PMGR requires arm-io")?;
        let parent = io.child("pmgr").ok_or("PMP PMGR requires pmgr")?;
        // M6's generic controller has a separate DeviceConfig implementation.
        // The legacy helper's presence in that KC alone does not establish
        // that the new implementation publishes byte 3 with these semantics.
        if parent.compatible(super::PMGR2_ARCH)
            || !SOCS.iter().any(|soc| parent.compatible(soc.pmgr))
        {
            return Err("PMP PMGR source-byte layout is unqualified for this controller".into());
        }
        let dies = Dies::of(root, &parent)?;
        let table = super::decode_domain_table(&parent, dies, &|address, bytes| {
            io.translate_range(address, bytes)
        })?;
        if self.domains != table.domains
            || self.blocks != table.blocks
            || self.registers != table.registers
        {
            return Err("PMP PMGR canonical inventory differs from the source tree".into());
        }
        let (layout, _) = Layout::select(parent.property("ps-regs"), parent.property("ps-groups"))
            .map_err(String::from)?;
        let bytes = parent
            .property("devices")
            .ok_or("PMP PMGR requires devices")?;
        let mut output = Vec::with_capacity(self.domains.len());
        for die in 0..dies.count {
            for raw in bytes.as_chunks::<PMGR_DEVICE>().0 {
                let record = Record::parse(layout, raw).map_err(String::from)?;
                let domain = &self.domains[output.len()];
                if domain.id
                    != (DomainId {
                        die,
                        device: record.id,
                    })
                {
                    return Err(format!("PMP PMGR source identity differs on die {die}"));
                }
                output.push(PmpDomain {
                    id: domain.id,
                    address: domain.address,
                    source: record.pmp_source,
                });
            }
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_contracts::adt::encode;

    fn fixture() -> Vec<u8> {
        let mut records = [[0u8; PMGR_DEVICE]; 4];
        // Two physical domains, a virtual member and a non-PMP source. The
        // canonical IDs deliberately differ from the grouping source byte.
        for (index, (id, source)) in [(78u16, 2), (79, 2), (368, 2), (9, 0)]
            .into_iter()
            .enumerate()
        {
            records[index][3] = source;
            records[index][26..28].copy_from_slice(&id.to_le_bytes());
            records[index][10] = index as u8;
            records[index][32] = b'A' + index as u8;
        }
        records[2][0] = super::super::records::VIRTUAL;
        let devices = records.into_iter().flatten().collect::<Vec<_>>();
        let reg = [0x1000u64, 0x100]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect::<Vec<_>>();
        let groups = [0u32, 0, 0]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        let pmgr = encode(
            &[
                ("name", b"pmgr"),
                ("compatible", b"pmgr1,t6001"),
                ("reg", &reg),
                ("ps-regs", &groups),
                ("devices", &devices),
            ],
            &[],
        );
        let ranges = [0u64, 0, 1 << 40]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect::<Vec<_>>();
        let io = encode(&[("name", b"arm-io"), ("ranges", &ranges)], &[pmgr]);
        let cpu = encode(&[("name", b"cpu"), ("die-id", &1u32.to_le_bytes())], &[]);
        let cpus = encode(&[("name", b"cpus")], &[cpu]);
        encode(&[("name", b"device-tree")], &[io, cpus])
    }

    fn states(root: &Node<'_>) -> PowerStates {
        let io = root.child("arm-io").unwrap();
        let pmgr = io.child("pmgr").unwrap();
        let table = super::super::decode_domain_table(
            &pmgr,
            Dies::of(root, &pmgr).unwrap(),
            &|address, bytes| io.translate_range(address, bytes),
        )
        .unwrap();
        PowerStates {
            blocks: table.blocks,
            registers: table.registers,
            domains: table.domains,
            resources: Vec::new(),
            implicit: Vec::new(),
        }
    }

    #[test]
    fn source_inventory_retains_many_to_one_virtual_unmapped_and_die_members() {
        let bytes = fixture();
        let root = Node::root(&bytes).unwrap();
        let states = states(&root);
        let domains = states.pmp_domains(&root).unwrap();
        assert_eq!(domains.len(), 8);
        for die in 0..2 {
            for (index, (device, source, address)) in [
                (78, 2, Some(0x1000)),
                (79, 2, Some(0x1008)),
                (368, 2, None),
                (9, 0, Some(0x1018)),
            ]
            .into_iter()
            .enumerate()
            {
                assert_eq!(
                    domains[die as usize * 4 + index],
                    PmpDomain {
                        id: DomainId { die, device },
                        source,
                        address: address.map(|address| address + u64::from(die) * (1 << 37)),
                    }
                );
            }
        }
        // Physical aliases and virtual records stay separate. A subsequent
        // PMP resolver must join all these members before reporting a group.
        assert_eq!(
            domains.iter().filter(|domain| domain.source == 2).count(),
            6
        );
    }

    #[test]
    fn mismatched_canonical_inventory_cannot_supply_grouping_metadata() {
        let bytes = fixture();
        let root = Node::root(&bytes).unwrap();
        for mutation in 0..4 {
            let mut states = states(&root);
            match mutation {
                0 => states.domains[0].id.device += 1,
                1 => states.domains[0].address = None,
                2 => states.domains[0].name.push('!'),
                _ => {
                    states.registers.pop().unwrap();
                }
            }
            assert!(
                states
                    .pmp_domains(&root)
                    .unwrap_err()
                    .contains("canonical inventory")
            );
        }
    }

    #[test]
    fn malformed_advertised_records_refuse_before_supplying_metadata() {
        let pmgr = encode(
            &[
                ("name", b"pmgr"),
                ("compatible", b"pmgr1,t8112"),
                ("reg", &[0; 16]),
                ("ps-regs", &[0; 12]),
                ("devices", &[0; 1]),
            ],
            &[],
        );
        let io = encode(&[("name", b"arm-io")], &[pmgr]);
        let bytes = encode(&[("name", b"device-tree")], &[io]);
        let root = Node::root(&bytes).unwrap();
        let empty = PowerStates {
            blocks: Vec::new(),
            registers: Vec::new(),
            domains: Vec::new(),
            resources: Vec::new(),
            implicit: Vec::new(),
        };
        assert!(
            empty
                .pmp_domains(&root)
                .unwrap_err()
                .contains("not whole entries")
        );
        for compatible in [b"pmgr2,arch".as_slice(), b"pmgr1,unknown"] {
            let pmgr = encode(&[("name", b"pmgr"), ("compatible", compatible)], &[]);
            let io = encode(&[("name", b"arm-io")], &[pmgr]);
            let bytes = encode(&[("name", b"device-tree")], &[io]);
            assert!(
                empty
                    .pmp_domains(&Node::root(&bytes).unwrap())
                    .unwrap_err()
                    .contains("source-byte layout is unqualified")
            );
        }
    }

    #[test]
    #[ignore = "oracle: STELA_TEST_PMGR_KERNELCACHES"]
    fn original_family_helpers_use_raw_source_die_offset_and_ordinal() {
        let directory = std::env::var("STELA_TEST_PMGR_KERNELCACHES").unwrap();
        for (family, offset, expected) in [
            (
                "mac13g",
                0x2b145a4,
                "d196456a0809aca37bbf5918eb633cf8ada9000c48f4c0082ca8f61c86b2866b",
            ),
            (
                "mac13j",
                0x2b45d34,
                "5109fca5209bdbb89cec29e3241cc42a90418cb737d65e31962b059b9879af90",
            ),
            (
                "mac14g",
                0x2ba1c84,
                "06846c718a67715f540c7f5a5d5a183da6185d94b6fc01f1ce57a30b601be44d",
            ),
            (
                "mac14j",
                0x2b6acd4,
                "ef4712e54102b35c11665c46fa7543a3fafc0c419723f583cb0ac891016f531a",
            ),
            (
                "mac15g",
                0x2b2e024,
                "8210f3645ea16c2481bcaf285ead56eaf2e591bb0d124fe2c01f596c6361ded3",
            ),
            (
                "mac15j",
                0x2ba9e84,
                "d2c63d611b83f9b12a3b66f0b9e3882260de44f665423d341bf1ea60808ec3e6",
            ),
            (
                "mac15s",
                0x2b22654,
                "1e95b8667e1afb3e52ef45fb7e66e67f89b2da084a65f46c49d3d0eb7db84d11",
            ),
            (
                "mac16g",
                0x2ba9124,
                "196efb3db57543e7c2cc8f12e6468a7a95b6d80a3924117178dfbe3ade52ca0e",
            ),
            (
                "mac16j",
                0x2bb6334,
                "753f8c8cf712ed2250feeb813096a5b8645844c2c5bb0a895d34c84c09d88916",
            ),
            (
                "mac17g",
                0x2bc5334,
                "4c7c9ba936b617c1c0a8cb27381acd6b56d99f1a954216b80ca7ae96439affcf",
            ),
            (
                "mac17j",
                0x286fd04,
                "3132eb048457c1488308166d47c7020b0b1f2858633dfcf6acb745973102366e",
            ),
            (
                "mac17p",
                0x27b4d54,
                "12ee4fc644e44efa5f5137240a92b94c2f2babf80bcc7ba3b89ae11b94f51d45",
            ),
            (
                "mac18g",
                0x28b4e74,
                "09746d1f442153956ba00b385f49bc245460c1ebea92cae7e9e0e4f240745b85",
            ),
        ] {
            let bytes = std::fs::read(
                std::path::Path::new(&directory)
                    .join(alloc::format!("kernelcache.release.{family}")),
            )
            .unwrap();
            assert_eq!(stela_formats::sha256(&bytes), expected);
            let helper = &bytes[offset..offset + 156];
            assert_eq!(
                stela_formats::sha256(helper),
                if family == "mac18g" {
                    "a25fd16e0a9ce011af7761f805a2f7e165dc1090eb2cf81197601749be1ab24b"
                } else {
                    "1f5ea4dd72c5c5c06b4bd4e6af338a6bd5201fb5276227fac1021a4a5cf1f724"
                }
            );
            // ldrb raw+3; ldr stride; madd source+stride*die; cmp source,256.
            for (relative, opcode) in [
                (0x40, 0x39400c08u32),
                (0x44, 0xb94002a9),
                (0x48, 0x1b142128),
                (0x4c, 0x7104011f),
                (0x74, 0xb9400140),
            ] {
                assert_eq!(
                    u32::from_le_bytes(helper[relative..relative + 4].try_into().unwrap()),
                    opcode
                );
            }
        }
    }
}
