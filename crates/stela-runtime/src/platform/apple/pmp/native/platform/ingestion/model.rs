//! Semantic projection of original generic descriptor data, not executable code.
use super::{CounterReference, Descriptor, Error, Ordinal};
use alloc::vec::Vec;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frequency {
    pub(super) references: [CounterReference; 2],
    pub coefficient_inputs: [u32; 3],
    pub frequencies: [u32; 16],
    pub(super) invert: bool,
    pub(super) group: u32,
    pub(super) shift: u32,
    pub(super) active: Vec<u32>,
    pub(super) inactive: Vec<u32>,
    pub(super) extra: Vec<u32>,
    pub(super) qualified: bool,
}
/// Actual56-byte control descriptor and its20-byte member rows. Raw pointer
/// cells are provenance only; resource resolution uses typed ordinal/selectors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Auxiliary {
    pub words: [u32; 14],
    pub members: Vec<[u32; 5]>,
}
#[derive(Clone, Debug)]
pub struct Configuration {
    pub(super) ordinal: Ordinal,
    pub(super) references: [CounterReference; 8],
    pub(super) frequencies: Vec<Frequency>,
    pub(super) histogram_shift: u32,
    pub(super) auxiliary: bool,
    pub(super) auxiliaries: Vec<Auxiliary>,
    pub(super) periods: (u32, u64),
    pub(super) has_ratio: bool,
    pub(super) extended_count: u32,
    pub(super) state_trace: u32,
    pub(super) output_source: u32,
    pub(super) output_start: u32,
    pub(super) output_count: u32,
}
impl Auxiliary {
    fn empty() -> Self {
        Self {
            words: [0; 14],
            members: Vec::new(),
        }
    }
}
impl Configuration {
    pub fn periods(&self) -> (u32, u64) {
        self.periods
    }

    pub fn ordinal(&self) -> Ordinal {
        self.ordinal
    }
    pub fn references(&self) -> &[CounterReference; 8] {
        &self.references
    }

    pub fn auxiliary_descriptors(&self) -> &[Auxiliary] {
        &self.auxiliaries
    }

    pub fn t8112(d: &Descriptor) -> Result<Self, Error> {
        let mut references = [r([0; 6]); 8];
        let mut frequencies = Vec::new();
        let mut auxiliary = false;
        let mut state_trace = 0;
        let mut histogram_max = 0;
        let mut auxiliaries = Vec::new();
        match d.ordinal().index() {
            0 => {
                auxiliaries.push(Auxiliary::empty());
                auxiliaries.push(Auxiliary::empty());
                auxiliaries.push(Auxiliary::empty());
                auxiliaries.push(Auxiliary::empty());

                histogram_max = 128;
                references[3] = r([1, 0, 0, 0, 0, 671088641]);
                references[4] = r([1, 0, 1, 0, 0, 671088641]);
                references[6] = r([1, 2, 0, 0, 1, 3959422980]);
                references[7] = r([1, 3, 0, 0, 1, 3959422980]);
                frequencies.push(Frequency {
                    coefficient_inputs: [0, 0, 0],
                    frequencies: [712, 1536, 2133, 2733, 3200, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    references: [r([1, 1, 1, 0, 0, 0]), r([1, 1, 0, 0, 0, 0])],
                    invert: true,
                    group: 0,
                    shift: 0,
                    active: Vec::new(),
                    inactive: Vec::new(),
                    extra: Vec::new(),
                    qualified: false,
                });
            }
            1 => {
                // AMCC100467c..1004690 defaults K25c to128 before the
                // generic initializer, so its generic histograms use shift2.
                histogram_max = 128;
                auxiliaries.push(Auxiliary::empty());
                auxiliaries.push(Auxiliary::empty());
                auxiliaries.push(Auxiliary::empty());
                auxiliaries.push(Auxiliary::empty());

                references[3] = r([2, 0, 0, 32, 1, 402653185]);
                references[4] = r([2, 0, 32, 32, 1, 402653185]);
            }
            2 => {
                auxiliaries.push(Auxiliary::empty());
                auxiliaries.push(Auxiliary::empty());
                auxiliaries.push(Auxiliary::empty());
                auxiliaries.push(Auxiliary::empty());

                references[6] = r([4, 0, 0, 0, 0, 0]);
                frequencies.push(Frequency {
                    coefficient_inputs: [1071896330, 1, 0],
                    frequencies: [300, 400, 450, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    references: [r([0, 0, 0, 0, 0, 0]), r([1, 0, 7, 0, 0, 0])],
                    invert: true,
                    group: 0,
                    shift: 0,
                    active: Vec::new(),
                    inactive: Vec::new(),
                    extra: Vec::new(),
                    qualified: false,
                });
            }
            3 => {
                auxiliaries.push(Auxiliary::empty());
                auxiliaries.push(Auxiliary::empty());
                auxiliaries.push(Auxiliary::empty());
                auxiliaries.push(Auxiliary::empty());

                references[6] = r([4, 0, 0, 0, 0, 0]);
                frequencies.push(Frequency {
                    coefficient_inputs: [1125424824, 52, 1092511334],
                    frequencies: [534, 712, 1068, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    references: [r([1, 0, 9, 0, 0, 0]), r([1, 0, 8, 0, 0, 0])],
                    invert: true,
                    group: 0,
                    shift: 0,
                    active: Vec::new(),
                    inactive: Vec::new(),
                    extra: Vec::new(),
                    qualified: false,
                });
            }
            4 => {
                auxiliaries.push(Auxiliary {
                    words: [0, 64, 2, 0, 192, 16, 0, 9, 17070656, 0, 0, 0, 0, 0],
                    members: alloc::vec![
                        [0, 0, 0, 0, 0],
                        [0, 0, 0, 0, 0],
                        [0, 0, 0, 0, 0],
                        [0, 0, 0, 0, 0],
                        [0, 0, 0, 0, 0],
                        [0, 0, 0, 0, 0],
                        [0, 0, 0, 0, 0],
                        [0, 0, 0, 0, 0],
                        [1, 0, 0, 0, 0]
                    ],
                });
                auxiliaries.push(Auxiliary::empty());
                auxiliaries.push(Auxiliary::empty());
                auxiliaries.push(Auxiliary::empty());

                histogram_max = 64;
                references[0] = r([3, 0, 2, 0, 1, 0]);
                references[1] = r([3, 0, 3, 0, 0, 0]);
                references[3] = r([3, 0, 47, 0, 1, 0]);
                references[4] = r([3, 0, 48, 0, 1, 0]);
                auxiliary = true;
                state_trace = 2248737664;
            }
            5 => {
                auxiliaries.push(Auxiliary {
                    words: [0, 87, 2, 0, 192, 16, 0, 3, 17071480, 0, 0, 0, 0, 0],
                    members: alloc::vec![[1, 0, 0, 0, 0], [0, 0, 0, 0, 0], [1, 0, 0, 0, 0]],
                });
                auxiliaries.push(Auxiliary {
                    words: [1, 90, 2, 0, 208, 16, 0, 1, 17071540, 0, 0, 0, 0, 0],
                    members: alloc::vec![[1, 0, 0, 0, 0]],
                });
                auxiliaries.push(Auxiliary {
                    words: [2, 92, 2, 0, 224, 16, 0, 3, 17071560, 0, 0, 0, 0, 0],
                    members: alloc::vec![[1, 0, 0, 0, 0], [0, 0, 0, 0, 0], [1, 0, 0, 0, 0]],
                });
                auxiliaries.push(Auxiliary::empty());

                histogram_max = 64;
                references[0] = r([3, 0, 0, 0, 0, 0]);
                references[1] = r([3, 0, 1, 0, 0, 0]);
                references[3] = r([3, 0, 45, 0, 0, 0]);
                references[4] = r([3, 0, 46, 0, 0, 0]);
                auxiliary = true;
                state_trace = 2248737792;
            }
            6 => {
                auxiliaries.push(Auxiliary {
                    words: [0, 0, 2, 0, 192, 16, 0, 0, 0, 0, 0, 0, 0, 0],
                    members: alloc::vec![],
                });
                auxiliaries.push(Auxiliary::empty());
                auxiliaries.push(Auxiliary::empty());
                auxiliaries.push(Auxiliary::empty());

                histogram_max = 128;
                references[0] = r([3, 0, 4, 0, 1, 0]);
                references[1] = r([3, 0, 5, 0, 1, 0]);
                references[3] = r([3, 0, 49, 0, 1, 0]);
                references[4] = r([3, 0, 50, 0, 1, 0]);
                auxiliary = true;
                state_trace = 2248737920;
            }
            7 => {
                auxiliaries.push(Auxiliary {
                    words: [0, 509, 2, 0, 192, 16, 0, 10, 17073976, 0, 0, 0, 0, 0],
                    members: alloc::vec![
                        [0, 0, 0, 0, 0],
                        [0, 0, 0, 0, 0],
                        [0, 0, 0, 0, 0],
                        [0, 0, 0, 0, 0],
                        [0, 0, 0, 0, 0],
                        [0, 0, 0, 0, 0],
                        [0, 0, 0, 0, 0],
                        [0, 0, 0, 0, 0],
                        [1, 0, 0, 0, 0],
                        [1, 0, 0, 0, 0]
                    ],
                });
                auxiliaries.push(Auxiliary::empty());
                auxiliaries.push(Auxiliary::empty());
                auxiliaries.push(Auxiliary::empty());

                histogram_max = 64;
                references[0] = r([3, 0, 8, 0, 1, 0]);
                references[1] = r([3, 0, 9, 0, 1, 0]);
                references[3] = r([3, 0, 51, 0, 1, 0]);
                references[4] = r([3, 0, 52, 0, 1, 0]);
                auxiliary = true;
                state_trace = 2248738048;
            }
            8 => {
                auxiliaries.push(Auxiliary::empty());
                auxiliaries.push(Auxiliary::empty());
                auxiliaries.push(Auxiliary::empty());
                auxiliaries.push(Auxiliary::empty());

                references[1] = r([3, 0, 35, 0, 1, 0]);
                references[3] = r([3, 0, 73, 0, 0, 0]);
                references[4] = r([3, 0, 74, 0, 0, 0]);
                references[6] = r([1, 0, 0, 0, 1, 3959422980]);
                references[7] = r([1, 1, 0, 0, 1, 3959422980]);
                frequencies.push(Frequency {
                    coefficient_inputs: [0, 0, 0],
                    frequencies: [300, 427, 533, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    references: [r([0, 0, 0, 0, 0, 0]), r([0, 0, 0, 0, 0, 0])],
                    invert: false,
                    group: 0,
                    shift: 0,
                    active: Vec::new(),
                    inactive: Vec::new(),
                    extra: Vec::new(),
                    qualified: false,
                });
            }
            9 => {
                auxiliaries.push(Auxiliary::empty());
                auxiliaries.push(Auxiliary::empty());
                auxiliaries.push(Auxiliary::empty());
                auxiliaries.push(Auxiliary::empty());

                references[0] = r([3, 0, 32, 0, 0, 0]);
                references[1] = r([3, 0, 33, 0, 0, 0]);
                references[3] = r([3, 0, 71, 0, 0, 0]);
                references[4] = r([3, 0, 72, 0, 0, 0]);
                references[6] = r([4, 0, 0, 0, 0, 0]);
                frequencies.push(Frequency {
                    coefficient_inputs: [1128042986, 485, 0],
                    frequencies: [360, 533, 533, 712, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    references: [r([1, 0, 3, 0, 0, 0]), r([1, 0, 2, 0, 0, 0])],
                    invert: true,
                    group: 0,
                    shift: 0,
                    active: Vec::new(),
                    inactive: Vec::new(),
                    extra: Vec::new(),
                    qualified: false,
                });
            }
            10 => {
                auxiliaries.push(Auxiliary::empty());
                auxiliaries.push(Auxiliary::empty());
                auxiliaries.push(Auxiliary::empty());
                auxiliaries.push(Auxiliary::empty());

                references[0] = r([3, 0, 16, 0, 0, 0]);
                references[1] = r([3, 0, 17, 0, 0, 0]);
                references[3] = r([3, 0, 59, 0, 0, 0]);
                references[4] = r([3, 0, 60, 0, 0, 0]);
                references[6] = r([4, 0, 0, 0, 0, 0]);
                frequencies.push(Frequency {
                    coefficient_inputs: [1126642483, 453, 0],
                    frequencies: [360, 533, 625, 900, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    references: [r([1, 0, 5, 0, 0, 0]), r([1, 0, 4, 0, 0, 0])],
                    invert: true,
                    group: 0,
                    shift: 0,
                    active: Vec::new(),
                    inactive: Vec::new(),
                    extra: Vec::new(),
                    qualified: false,
                });
            }
            11 => {
                auxiliaries.push(Auxiliary::empty());
                auxiliaries.push(Auxiliary::empty());
                auxiliaries.push(Auxiliary::empty());
                auxiliaries.push(Auxiliary::empty());

                references[0] = r([3, 0, 30, 0, 1, 0]);
                references[1] = r([3, 0, 31, 0, 1, 0]);
                references[3] = r([3, 0, 69, 0, 0, 0]);
                references[4] = r([3, 0, 70, 0, 0, 0]);
                references[6] = r([1, 0, 0, 0, 1, 3959422980]);
            }
            12 => {
                auxiliaries.push(Auxiliary::empty());
                auxiliaries.push(Auxiliary::empty());
                auxiliaries.push(Auxiliary::empty());
                auxiliaries.push(Auxiliary::empty());

                references[0] = r([3, 0, 12, 0, 1, 0]);
                references[1] = r([3, 0, 13, 0, 1, 0]);
                references[3] = r([3, 0, 55, 0, 0, 0]);
                references[4] = r([3, 0, 56, 0, 0, 0]);
                references[6] = r([4, 0, 0, 0, 0, 0]);
                frequencies.push(Frequency {
                    coefficient_inputs: [1099793695, 183, 0],
                    frequencies: [257, 400, 600, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    references: [r([1, 0, 6, 0, 0, 0]), r([1, 0, 6, 0, 0, 0])],
                    invert: true,
                    group: 0,
                    shift: 0,
                    active: Vec::new(),
                    inactive: Vec::new(),
                    extra: Vec::new(),
                    qualified: false,
                });
            }
            13 => {
                auxiliaries.push(Auxiliary::empty());
                auxiliaries.push(Auxiliary::empty());
                auxiliaries.push(Auxiliary::empty());
                auxiliaries.push(Auxiliary::empty());

                references[2] = r([3, 0, 37, 0, 0, 0]);
                references[3] = r([3, 0, 77, 0, 0, 0]);
                references[4] = r([3, 0, 78, 0, 0, 0]);
                references[6] = r([1, 0, 0, 0, 1, 3959422980]);
            }
            14 => {
                auxiliaries.push(Auxiliary::empty());
                auxiliaries.push(Auxiliary::empty());
                auxiliaries.push(Auxiliary::empty());
                auxiliaries.push(Auxiliary::empty());

                references[2] = r([3, 0, 36, 0, 0, 0]);
                references[3] = r([3, 0, 75, 0, 0, 0]);
                references[4] = r([3, 0, 76, 0, 0, 0]);
            }
            15 => {
                auxiliaries.push(Auxiliary::empty());
                auxiliaries.push(Auxiliary::empty());
                auxiliaries.push(Auxiliary::empty());
                auxiliaries.push(Auxiliary::empty());

                references[0] = r([3, 0, 20, 0, 0, 0]);
                references[1] = r([3, 0, 21, 0, 0, 0]);
                references[3] = r([3, 0, 63, 0, 0, 0]);
                references[4] = r([3, 0, 64, 0, 0, 0]);
            }
            16 => {
                auxiliaries.push(Auxiliary::empty());
                auxiliaries.push(Auxiliary::empty());
                auxiliaries.push(Auxiliary::empty());
                auxiliaries.push(Auxiliary::empty());
            }
            17 => {
                auxiliaries.push(Auxiliary::empty());
                auxiliaries.push(Auxiliary::empty());
                auxiliaries.push(Auxiliary::empty());
                auxiliaries.push(Auxiliary::empty());
            }
            _ => {
                return Err(Error::Contract(
                    "generic source ordinal outside T8112 registry",
                ));
            }
        }
        // Initializer1019c54..9c90 only enables ratio when each metric group exists.
        let has_ratio = references[..3].iter().any(|r| r.kind != 0)
            && references[3..6].iter().any(|r| r.kind != 0);
        let histogram_shift = if histogram_max == 0 {
            0
        } else {
            (!((histogram_max >> 5) as u32).leading_zeros()) & 31
        };
        Ok(Self {
            auxiliaries,
            histogram_shift,
            ordinal: d.ordinal(),
            references,
            frequencies,
            auxiliary,
            periods: d.times(),
            has_ratio,
            extended_count: 0,
            state_trace,
            output_source: d.raw_soc_device()[4],
            output_start: 0,
            output_count: 0,
        })
    }
}
const fn r(w: [u32; 6]) -> CounterReference {
    CounterReference {
        kind: w[0],
        provider: w[1],
        start: w[2],
        width: w[3],
        flags: w[4],
        scale: w[5],
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    #[test]
    #[ignore = "requires original T8112 PMP and J473 DT via STELA_TEST_PMP_T8112 and STELA_TEST_MCC_J473_DT"]
    fn original_t8112_ingestion_descriptor_facts_match_inputs() {
        use sha2::{Digest, Sha256};
        let bytes = std::fs::read(std::env::var("STELA_TEST_PMP_T8112").unwrap()).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            "b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c"
        );
        let u = |a: usize| {
            u32::from_le_bytes(bytes[a - 0xfff000..a - 0xfff000 + 4].try_into().unwrap())
        };
        let q = |a: usize| {
            u64::from_le_bytes(bytes[a - 0xfff000..a - 0xfff000 + 8].try_into().unwrap()) as usize
        };
        let configs = [
            0x1046698, 0x1046ab8, 0x104a868, 0x104abc8, 0x10477d0, 0x1047b08, 0x1047e18, 0x1048410,
            0x1048810, 0x1048c48, 0x1049080, 0x10494b8, 0x1049728, 0x1049a88, 0x1049cf8, 0x1049f68,
            0x104a5f8, 0x104a2b0,
        ];
        let dt = std::fs::read(std::env::var("STELA_TEST_MCC_J473_DT").unwrap()).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&dt)),
            "a99fa2260f292236fbad210fcee380fc69f101e591125bce347819e84e68034c"
        );
        let root = crate::machine::adt::Node::root(&dt).unwrap();
        let nub = root
            .child("arm-io")
            .unwrap()
            .child("pmp")
            .unwrap()
            .child("iop-pmp-nub")
            .unwrap();
        let table = super::super::super::super::power::DeviceTable::from_properties(
            nub.property("soc-device").unwrap(),
            nub.property("soc-device-ps-group").unwrap(),
            nub.property("soc-device-die-offset"),
        )
        .unwrap();
        let profile = super::super::super::Profile::t8112(
            &table,
            nub.property("dvfs-domain").unwrap(),
            super::super::super::Slice {
                start: 16,
                count: 144,
            },
        )
        .unwrap();
        for (i, c) in configs.into_iter().enumerate() {
            let model = Configuration::t8112(&profile.descriptors[i]).unwrap();
            for k in 0..8 {
                assert_eq!(
                    model.references[k],
                    r(core::array::from_fn(|j| u(c + 0x8c + k * 24 + j * 4)))
                )
            }
            assert_eq!(model.frequencies.len(), u(c + 0x240) as usize);
            for (k, f) in model.frequencies.iter().enumerate() {
                let a = q(c + 0x248) + k * 240;
                for j in 0..2 {
                    assert_eq!(
                        f.references[j],
                        r(core::array::from_fn(|t| u(a + 0xb4 + j * 24 + t * 4)))
                    )
                }
                assert_eq!(f.group, u(a + 0xac));
                assert_eq!(f.shift, u(a + 0xb0));
                assert_eq!(f.invert, u(a + 0xe4) & 255 != 0);
                assert_eq!(f.coefficient_inputs, [u(a), u(a + 0x2c), u(a + 0xa8)]);
                assert_eq!(f.frequencies, core::array::from_fn(|j| u(a + 0x30 + j * 4)));
            }
            for (k, aux) in model.auxiliaries.iter().enumerate() {
                let a = c + 0x160 + k * 56;
                assert_eq!(aux.words, core::array::from_fn(|j| u(a + j * 4)));
                assert_eq!(aux.members.len(), u(a + 0x1c) as usize);
                for (j, m) in aux.members.iter().enumerate() {
                    assert_eq!(
                        *m,
                        core::array::from_fn(|t| u(q(a + 0x20) + j * 20 + t * 4))
                    );
                }
            }
            assert_eq!(model.output_source, table.records()[i][4]);
            assert_eq!(u(c + 0x74), 0); // compiled default only: actual output range still resolves SOC row+10
            let raw_max = u(c + 0x25c);
            let initialized_max = if i == 1 && raw_max == 0 { 128 } else { raw_max };
            let expected_shift = if initialized_max == 0 {
                0
            } else {
                (!(initialized_max >> 5).leading_zeros()) & 31
            };
            assert_eq!(model.histogram_shift, expected_shift, "ordinal{i}");
        }
        for (a, word) in [
            (0x100467c, 0xb9425d09), // load current K25c
            (0x1004680, 0x35000069), // preserve nonzero range
            (0x1004684, 0x52801009), // default128
            (0x1004688, 0xb9025d09), // retain before generic initializer
            (0x1004690, 0x9400540f), // BL10196cc
        ] {
            assert_eq!(u(a), word, "{a:x}");
        }
    }
}
