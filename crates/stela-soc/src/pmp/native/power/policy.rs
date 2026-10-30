//! Pure native T8112 power policy, distinct from applied controller effects.
//!
//! Original t8112pmp SHA256 b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c:
//! VM100d46c..100d54c derives masks from native descriptors, not PMGR aliases;
//! VM10109d8..1010e8c merges requests, adds forced bits, scans dependencies,
//! selects count-indexed votes and checks both source controller packet pairs.
//! VM1032d88..1032e20 initializes three vote rows. No ACK writer or applied
//! lifecycle setter is supplied by this module.
use super::DeviceTable;
use crate::Result;
use crate::pmp::native::Packets;
use stela_contracts::refuse;

const SOURCE_IDS: [u32; 18] = [
    1, 2, 16, 17, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 18,
];
const INVENTORY_MASK: u64 = (1 << SOURCE_IDS.len()) - 1;
// Descriptor byte +0x25 == 1 at source config objects, in ordinal order;
// dependency masks are descriptor +0x18. See pinned pointer-chain fixture.
const FORCED_ON: u64 = 0x1003e;
const DEPENDENCIES: [(u8, u64); 4] = [(0, 0xfff0), (1, 0xf9f0), (2, 0xfff0), (3, 0xfff0)];
const VOTE_MASKS: [u64; 3] = [0x1f9f3, 0x200, 0x600];

/// Full original 128-bit packet image, with 32 low-to-high state nibbles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControllerStates(pub [u64; 2]);
impl ControllerStates {
    pub fn state(self, controller: u8) -> Option<u8> {
        let index = usize::from(controller);
        (index < 32).then(|| ((self.0[index / 16] >> ((index % 16) * 4)) & 15) as u8)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bounds {
    pub controllers: u32,
    pub lower: Option<ControllerStates>,
    pub upper: Option<ControllerStates>,
}

/// A source count-indexed policy requirement, never a hardware write or receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Vote {
    pub devices: u64,
    pub selected_count: u32,
    pub bounds: Option<Bounds>,
}

/// Source packet pair checked by VM1010c64..1010da0. First is settled
/// logical DVFS state (+0x320/+0x328); Second is issued (+0x330/+0x338).
/// VM1017370 and VM1017a50 own their distinct updates. Equal numbers supplied
/// by a caller do not establish controller completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketPair {
    First,
    Second,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    Lower,
    Upper,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnmetVote {
    pub table: u8,
    pub controller: u8,
    pub packet: PacketPair,
    pub actual: u8,
    pub limit: Limit,
    pub required: u8,
}
/// Diagnostic comparison only. Even WithinConstraints is not an applied
/// receipt and cannot authorize source per-device effects, readiness or ACKs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstraintState {
    WithinConstraints,
    Unmet(UnmetVote),
}

/// Immutable requested/resolved requirements. Applied state is
/// absent: only controller/effect owners can produce that permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resolution {
    requested: u64,
    resolved: u64,
    votes: [Vote; 3],
}
impl Resolution {
    pub fn requested(&self) -> u64 {
        self.requested
    }
    pub fn resolved(&self) -> u64 {
        self.resolved
    }
    pub fn votes(&self) -> &[Vote; 3] {
        &self.votes
    }

    /// Preserve the source six-word packet identity: checks use words 0/1 and
    /// 2/3; words 4/5 are a separate original packet, not a substitute snapshot.
    pub fn check_packets(&self, packets: Packets) -> ConstraintState {
        let pairs = [
            (
                PacketPair::First,
                ControllerStates([packets.0[0], packets.0[1]]),
            ),
            (
                PacketPair::Second,
                ControllerStates([packets.0[2], packets.0[3]]),
            ),
        ];
        for (table, vote) in self.votes.iter().enumerate() {
            let Some(bounds) = vote.bounds else { continue };
            for controller in 0..32 {
                if bounds.controllers & (1 << controller) == 0 {
                    continue;
                }
                for (limit, packed) in [(Limit::Lower, bounds.lower), (Limit::Upper, bounds.upper)]
                {
                    let Some(packed) = packed else { continue };
                    let required = packed.state(controller).unwrap();
                    for (packet, states) in pairs {
                        let actual = states.state(controller).unwrap();
                        if (limit == Limit::Lower && actual < required)
                            || (limit == Limit::Upper && actual > required)
                        {
                            return ConstraintState::Unmet(UnmetVote {
                                table: table as u8,
                                controller,
                                packet,
                                actual,
                                limit,
                                required,
                            });
                        }
                    }
                }
            }
        }
        ConstraintState::WithinConstraints
    }
}

/// One source-checked family policy over the exact owned AP source table.
/// This model computes requirements. It owns no controller, PMGR transition,
/// packet producer, transport publication or successful completion token.
pub struct Policy {
    table: DeviceTable,
    display_min_word: Option<u32>,
}
impl Policy {
    /// Original native T8112 inventory/constructor order. The unmodified
    /// source-ID order must match; labels and firmware hashes are not dispatch
    /// keys. The optional original property is one complete little-endian word.
    pub fn t8112(table: DeviceTable, display_min_state: Option<&[u8]>) -> Result<Self> {
        if table.len() != SOURCE_IDS.len()
            || !table
                .records()
                .iter()
                .zip(SOURCE_IDS)
                .all(|(row, source)| row[0] == source)
        {
            return Err(refuse!(
                "native T8112 power policy has a different source ordinal inventory"
            ));
        }
        let display_min_word = display_min_state
            .map(|bytes| {
                bytes.try_into().map(u32::from_le_bytes).map_err(|_| {
                    refuse!("native display minimum state is not a complete source word")
                })
            })
            .transpose()?;
        Ok(Self {
            table,
            display_min_word,
        })
    }
    pub fn source(&self) -> &DeviceTable {
        &self.table
    }
    pub fn display_min_word(&self) -> Option<u32> {
        self.display_min_word
    }
    pub fn forced_on(&self) -> u64 {
        FORCED_ON
    }

    /// Source VM1010a3c..1010a48 keeps old bits outside the selected mask,
    /// then ORs the full incoming word. It does not mask the incoming request.
    pub fn merge_request(&self, previous: u64, incoming: u64) -> Result<u64> {
        self.validate_bits(previous | incoming)?;
        Ok((previous & !self.table.power_group_mask()) | incoming)
    }
    fn validate_bits(&self, bits: u64) -> Result<()> {
        if bits & !INVENTORY_MASK != 0 {
            return Err(refuse!(
                "native power request names a device outside its actual source inventory"
            ));
        }
        Ok(())
    }
    pub fn resolve(&self, requested: u64) -> Result<Resolution> {
        self.validate_bits(requested)?;
        let mut resolved = requested | FORCED_ON;
        // Original ascending single pass. Repeating to a fixpoint could change
        // another profile's policy; these source descriptors need no inference.
        for (ordinal, dependencies) in DEPENDENCIES {
            if resolved & dependencies != 0 {
                resolved |= 1 << ordinal;
            }
        }
        let votes = core::array::from_fn(|index| {
            let devices = VOTE_MASKS[index];
            let selected_count = (resolved & devices).count_ones();
            let bounds = match index {
                0 => None,
                1 => Some(Bounds {
                    controllers: 4,
                    lower: Some(ControllerStates([
                        if selected_count == 1 {
                            u64::from(self.display_min_word.unwrap_or(0)) << 8
                        } else {
                            0
                        },
                        0,
                    ])),
                    upper: None,
                }),
                2 => Some(Bounds {
                    controllers: 1,
                    lower: Some(ControllerStates([
                        if selected_count == 2 { 3 } else { 0 },
                        0,
                    ])),
                    upper: None,
                }),
                _ => unreachable!(),
            };
            Vote {
                devices,
                selected_count,
                bounds,
            }
        });
        Ok(Resolution {
            requested,
            resolved,
            votes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    fn table() -> DeviceTable {
        let records: Vec<u8> = SOURCE_IDS
            .into_iter()
            .flat_map(|source| {
                let mut words = [0u32; 31];
                words[0] = source;
                words[3] = 0xfedcba98;
                words.into_iter().flat_map(u32::to_le_bytes)
            })
            .collect();
        DeviceTable::from_properties(&records, &0x3fff0u64.to_le_bytes(), None).unwrap()
    }
    fn policy(min: u32) -> Policy {
        Policy::t8112(table(), Some(&min.to_le_bytes())).unwrap()
    }

    #[test]
    fn requests_preserve_opaque_source_rows_and_resolve_separate_forced_dependencies() {
        let policy = policy(0);
        assert_eq!(policy.source().records()[0][3], 0xfedcba98);
        let plan = policy.resolve(0).unwrap();
        assert_eq!(plan.requested(), 0);
        assert_eq!(plan.resolved(), 0x1003f);
        assert_eq!(policy.forced_on(), 0x1003e);
        let incoming = 1 << 9;
        assert_eq!(policy.merge_request(1, incoming), Ok(incoming | 1));
        assert_eq!(policy.merge_request(incoming, 0), Ok(0));
        let plan = policy.resolve(incoming).unwrap();
        assert_eq!(plan.requested(), incoming);
        assert_eq!(plan.resolved(), incoming | 0x1003f);
        assert!(policy.resolve(1 << 18).is_err());
        assert!(policy.merge_request(0, 1 << 63).is_err());
    }
    #[test]
    fn vote_rows_select_by_device_population_and_keep_full_source_minimum_word() {
        let policy = policy(0x12345678);
        assert_eq!(policy.display_min_word(), Some(0x12345678));
        for (request, count, min) in [
            (0, 0, 0),
            (1 << 9, 1, 0),
            (1 << 10, 1, 0),
            ((1 << 9) | (1 << 10), 2, 3),
        ] {
            let plan = policy.resolve(request).unwrap();
            assert_eq!(plan.votes()[2].selected_count, count);
            assert_eq!(
                plan.votes()[2].bounds.unwrap().lower.unwrap().state(0),
                Some(min)
            );
        }
        let plan = policy.resolve(1 << 9).unwrap();
        assert_eq!(
            plan.votes()[1].bounds.unwrap().lower,
            Some(ControllerStates([0x1234567800, 0]))
        );
        assert_eq!(
            plan.votes()[1].bounds.unwrap().lower.unwrap().state(2),
            Some(8)
        );
        assert!(plan.votes()[0].bounds.is_none());
    }
    #[test]
    fn both_source_packet_pairs_must_meet_each_required_nibble() {
        let plan = policy(4).resolve((1 << 9) | (1 << 10)).unwrap();
        assert_eq!(
            plan.check_packets(Packets([0x403, 0, 0x403, 0, 0, 0])),
            ConstraintState::WithinConstraints
        );
        assert_eq!(
            plan.check_packets(Packets([0x403, 0, 0x402, 0, u64::MAX, u64::MAX])),
            ConstraintState::Unmet(UnmetVote {
                table: 2,
                controller: 0,
                packet: PacketPair::Second,
                actual: 2,
                limit: Limit::Lower,
                required: 3
            })
        );
        assert_eq!(
            plan.check_packets(Packets([0x303, 0, 0x403, 0, 0, 0])),
            ConstraintState::Unmet(UnmetVote {
                table: 1,
                controller: 2,
                packet: PacketPair::First,
                actual: 3,
                limit: Limit::Lower,
                required: 4
            })
        );
        assert_eq!(
            ControllerStates([0, 0xf000000000000000]).state(31),
            Some(15)
        );
        assert_eq!(ControllerStates([0, 0]).state(32), None);
    }
    #[test]
    fn numeric_packet_checks_are_not_an_applied_state_or_source_effect() {
        let mut plan = policy(0).resolve(0).unwrap();
        plan.votes[0].bounds = Some(Bounds {
            controllers: 1 << 31,
            lower: None,
            upper: Some(ControllerStates([0, 0x7000000000000000])),
        });
        assert_eq!(
            plan.check_packets(Packets([0, 0x8000000000000000, 0, 0, 0, 0])),
            ConstraintState::Unmet(UnmetVote {
                table: 0,
                controller: 31,
                packet: PacketPair::First,
                actual: 8,
                limit: Limit::Upper,
                required: 7
            })
        );
        assert_eq!(plan.requested(), 0);
        assert_eq!(plan.resolved(), 0x1003f);
        assert_eq!(
            plan.check_packets(Packets([0; 6])),
            ConstraintState::WithinConstraints
        );
        assert_eq!(
            plan.check_packets(Packets([0; 6])),
            ConstraintState::WithinConstraints
        );
    }
    #[test]
    fn native_inventory_and_property_shape_are_checked_before_resolution() {
        assert!(Policy::t8112(table(), Some(&[0; 3])).is_err());
        let mut wrong = table();
        wrong.records.swap(0, 1);
        assert!(Policy::t8112(wrong, None).is_err());
        let absent = Policy::t8112(table(), None).unwrap();
        assert_eq!(absent.display_min_word(), None);
        assert_eq!(
            absent.resolve(1 << 9).unwrap().votes()[1]
                .bounds
                .unwrap()
                .lower,
            Some(ControllerStates([0, 0]))
        );
    }

    #[test]
    #[cfg(feature = "std")]
    #[ignore = "oracle: STELA_TEST_MCC_J473_DT, STELA_TEST_PMP_T8112"]
    fn original_native_constructor_descriptors_and_request_policy_match_the_profile() {
        use sha2::{Digest, Sha256};
        use stela_contracts::adt::Node;
        let data = std::fs::read(std::env::var("STELA_TEST_PMP_T8112").unwrap()).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&data)),
            "b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c"
        );
        for (start, end, expected) in [
            (
                0xe46c,
                0xe54c,
                "7cf4e481cb2ba6988378c8d5103a77722dbbe3aacf68fafccb6fe2f775982ffa",
            ),
            (
                0x74d8,
                0x7574,
                "a13050256f1910ea1643da22053ff234a48de4972699588b994311c9824f61c6",
            ),
            (
                0x33d88,
                0x34a64,
                "8a8f7752a7bd2364e7c663ee0ebb576b2c74e5bde00d9e78b02ae323fb20b8dc",
            ),
            (
                0x119d8,
                0x11e8c,
                "6f0216e4fd57571086951bf8168902d377eee20f3f88b72a901f77e23795c99a",
            ),
            (
                0x43878,
                0x438b8,
                "1cba0abcd450fd38574bcaa13c4fabd65b79d7db36373aa5ebb8d77f0a66fde2",
            ),
            (
                0x471b0,
                0x471e0,
                "825f928101e1d54a45bf262bae771405e99c4d329bc2e607a6dafdc1b2b5a415",
            ),
            (
                0x463e8,
                0x46478,
                "b1a6ac1197790f5fbf1dd8feaea454cd0e32fbbd442f0520fb9de023363577ab",
            ),
        ] {
            assert_eq!(hex::encode(Sha256::digest(&data[start..end])), expected);
        }
        // Constructor x0/x1 pairs, joined in the native ordinal object's order.
        // The full constructor hash above binds these source pointer facts.
        let config_offsets = [
            0x47698, 0x47ab8, 0x4b868, 0x4bbc8, 0x487d0, 0x48b08, 0x48e18, 0x49410, 0x49810,
            0x49c48, 0x4a080, 0x4a4b8, 0x4a728, 0x4aa88, 0x4acf8, 0x4af68, 0x4b5f8, 0x4b2b0,
        ];
        let mut forced = 0;
        let mut dependencies = Vec::new();
        for (ordinal, offset) in config_offsets.into_iter().enumerate() {
            if data[offset + 0x25] == 1 {
                forced |= 1 << ordinal;
            }
            let mask = u64::from_le_bytes(data[offset + 0x18..offset + 0x20].try_into().unwrap());
            if mask != 0 {
                dependencies.push((ordinal as u8, mask));
            }
        }
        assert_eq!(forced, FORCED_ON);
        assert_eq!(dependencies, DEPENDENCIES);
        let data = std::fs::read(std::env::var("STELA_TEST_MCC_J473_DT").unwrap()).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&data)),
            "a99fa2260f292236fbad210fcee380fc69f101e591125bce347819e84e68034c"
        );
        let root = Node::root(&data).unwrap();
        let nub = root
            .child("arm-io")
            .unwrap()
            .child("pmp")
            .unwrap()
            .child("iop-pmp-nub")
            .unwrap();
        let table = DeviceTable::from_properties(
            nub.property("soc-device").unwrap(),
            nub.property("soc-device-ps-group").unwrap(),
            nub.property("soc-device-die-offset"),
        )
        .unwrap();
        let policy = Policy::t8112(table, nub.property("dvfs-disp-min-state")).unwrap();
        assert_eq!(policy.display_min_word(), Some(0));
        assert_eq!(policy.resolve(0).unwrap().resolved(), 0x1003f);
        let (dvfs, tail) = nub.property("dvfs-domain").unwrap().as_chunks::<28>();
        assert!(tail.is_empty());
        assert_eq!(dvfs.len(), 3);
        for (ordinal, row) in dvfs.iter().enumerate() {
            assert_eq!(
                u32::from_le_bytes(row[..4].try_into().unwrap()),
                ordinal as u32 + 1
            );
        }
    }
}
