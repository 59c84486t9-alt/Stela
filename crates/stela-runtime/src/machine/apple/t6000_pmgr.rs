//! Explicit private T6000 native resource assembly; no public PMGR admission.
use super::AppleDevices;
use alloc::{boxed::Box, format, string::String, vec::Vec};
use {
    crate::platform::apple::bridge::Bridge, crate::platform::apple::cluster::t6000::Complex,
    crate::platform::apple::cluster::t6000::Snapshot,
    crate::platform::apple::cluster::t6000::T6000, crate::platform::apple::power::t6000 as power,
    crate::platform::apple::power::t6000::Controller,
    crate::platform::apple::power::t6000::identity, crate::platform::apple::power::t6000::native,
    stela_contracts::bus::DeviceId, stela_contracts::bus::LifecycleState,
    stela_contracts::bus::MmioDevice, stela_soc_data::board::t6000_pmgr::Descriptor,
    stela_soc_data::pmgr::t6000::SRAM_BASE, stela_soc_data::pmgr::t6000::SRAM_LIMIT,
    stela_soc_data::pmgr::t6000::reconfiguration,
};

/// Supplied provenance is not authenticated by naming it. No variant supplies
/// omitted register bytes, PS states, lifecycle observations or completion.
pub enum Authority {
    Captured { source: String },
    DeclaredStela { entry: String },
}
pub enum RevisionAuthority {
    /// Explicit resource construction before the firmware RAM cache exists.
    DeclaredBeforeCache,
    /// The root owns this firmware-RAM observation, independently of
    /// immutable physical inputs. MAX follows the source's uncached branch.
    ObservedCache { value: u32, known: u32 },
}
pub struct IbootData {
    pub source: String,
    pub expected_sha256: String,
    pub bytes: Vec<u8>,
}
pub struct Requests {
    pub geometry: Vec<power::Instance>,
    pub lifecycle: LifecycleState,
    pub observations: Vec<power::Observation>,
}
pub struct Inputs {
    pub authority: Authority,
    pub identity: identity::Image,
    pub revision: RevisionAuthority,
    pub board: u32,
    pub platform_revision: u32,
    pub clusters: [Snapshot; 3],
    /// Every original bridge in ID order; an empty image explicitly keeps
    /// that bank unknown. Missing entries cannot default into zero banks.
    pub bridges: Vec<Vec<(u64, stela_contracts::bus::Width, u64)>>,
    pub requests: Requests,
    pub native: native::Handoff,
    pub ibootdata: IbootData,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramSource {
    pub revision: u32,
    pub offset: usize,
    pub bytes: usize,
    pub rows: usize,
    pub sha256: String,
}
#[derive(Debug, Clone, Copy)]
pub struct Mapping {
    pub model: usize,
    pub physical: u64,
    pub bytes: u64,
    pub offset: u64,
}

pub struct Prepared {
    descriptor: Descriptor,
    models: Vec<Box<dyn MmioDevice>>,
    mappings: Vec<Mapping>,
    identity: usize,
    clusters: [usize; 3],
    bridges: Vec<usize>,
    native_controls: usize,
    native_sram: usize,
    controller: Controller,
    authority: Authority,
    ibootdata: IbootData,
    program: ProgramSource,
}
impl Prepared {
    pub fn new(adt: &[u8], input: Inputs) -> Result<Self, String> {
        let declared = match &input.authority {
            Authority::Captured { source } => {
                if source.is_empty() {
                    return Err("T6000 capture provenance is missing".into());
                }
                if input.identity.authority() == identity::Authority::DeclaredStela
                    || matches!(input.native, native::Handoff::StelaEmpty { .. })
                {
                    return Err("T6000 Stela initialization is not a captured Apple handoff".into());
                }
                false
            }
            Authority::DeclaredStela { entry } => {
                if entry.is_empty() {
                    return Err("T6000 declared entry authority is missing".into());
                }
                true
            }
        };
        let chip = input
            .identity
            .chip()
            .map_err(|e| format!("T6000 identity: {e:?}"))?;
        let raw_revision = input
            .identity
            .revision()
            .map_err(|e| format!("T6000 revision: {e:?}"))?;
        match input.revision {
            RevisionAuthority::DeclaredBeforeCache if declared => {},
            RevisionAuthority::ObservedCache { value, known }
                if known == u32::MAX && (value == u32::MAX || value == u32::from(raw_revision)) => {},
            _ => return Err("T6000 RCfg selection requires pre-cache authority or an actual agreeing firmware cache word".into()),
        }
        let descriptor = Descriptor::parse(adt, chip, input.board, input.platform_revision)?;
        if input.ibootdata.source.is_empty()
            || input.ibootdata.expected_sha256.len() != 64
            || !input
                .ibootdata
                .expected_sha256
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
            || !stela_formats::sha256(&input.ibootdata.bytes)
                .eq_ignore_ascii_case(&input.ibootdata.expected_sha256)
        {
            return Err("T6000 iBootData provenance/digest does not bind the actual input".into());
        }
        let program = {
            let image = reconfiguration::Image::parse(&input.ibootdata.bytes)
                .map_err(|e| format!("T6000 iBootData container: {e:?}"))?;
            let source = image
                .t6000(u32::from(raw_revision))
                .map_err(|e| format!("T6000 original RCfg selection: {e:?}"))?;
            ProgramSource {
                revision: u32::from(raw_revision),
                offset: source.offset(),
                bytes: source.bytes().len(),
                rows: source.rows().len(),
                sha256: stela_formats::sha256(source.bytes()),
            }
        };
        if input.bridges.len() != descriptor.bridges.len() {
            return Err("T6000 handoff must explicitly retain all 193 bridge images".into());
        }
        let layout = descriptor.layout().map_err(String::from)?;
        let mut models: Vec<Box<dyn MmioDevice>> = Vec::new();
        let mut mappings = Vec::new();
        let identity = models.len();
        for address in input.identity.addresses() {
            mappings.push(Mapping {
                model: identity,
                physical: address,
                bytes: 4,
                offset: address,
            });
        }
        models.push(Box::new(input.identity));
        let mut clusters = [0; 3];
        for (index, (complex, image)) in [
            Complex::Efficiency,
            Complex::Performance0,
            Complex::Performance1,
        ]
        .into_iter()
        .zip(input.clusters)
        .enumerate()
        {
            if image.complex != complex {
                return Err("T6000 cluster images do not name E/P0/P1 independently".into());
            }
            let model = T6000::restore(&image).map_err(String::from)?;
            let id = models.len();
            clusters[index] = id;
            for offset in model.offsets() {
                let logical =
                    u32::try_from(offset).map_err(|_| "T6000 ACC logical offset overflows")?;
                let physical = layout.acc(index, logical, 8).map_err(String::from)?;
                mappings.push(Mapping {
                    model: id,
                    physical,
                    bytes: 8,
                    offset,
                });
            }
            models.push(Box::new(model));
        }
        let mut bridges = Vec::new();
        for (bank, image) in descriptor.bridges.iter().zip(input.bridges) {
            let model = Bridge::t6000(
                descriptor.tuning,
                bank.id,
                bank.header,
                &bank.configs,
                bank.axi,
                &image,
            )
            .map_err(String::from)?;
            let id = models.len();
            bridges.push(id);
            for (offset, bytes) in model.spans() {
                if offset
                    .checked_add(bytes)
                    .is_none_or(|end| end > bank.view.bytes)
                {
                    return Err("T6000 bridge handoff exceeds its actual descriptor".into());
                }
                mappings.push(Mapping {
                    model: id,
                    physical: bank
                        .view
                        .physical
                        .checked_add(offset)
                        .ok_or("T6000 bridge physical word overflows")?,
                    bytes,
                    offset,
                });
            }
            models.push(Box::new(model));
        }
        let geometry = input.requests.geometry.clone();
        let controller = Controller::with_native(
            geometry.clone(),
            input.requests.lifecycle,
            input.requests.observations,
            input.native,
        )
        .map_err(|e| format!("T6000 supplied native resource: {e:?}"))?;
        for (instance, geometry) in geometry.into_iter().enumerate() {
            for (bank, selector) in [(power::Bank::Pmgr, 0), (power::Bank::ClkGenSoc, 0x5b)] {
                let offsets = geometry.offsets(bank);
                if offsets.is_empty() {
                    continue;
                }
                let view = layout.register(selector).map_err(String::from)?;
                let model = match bank {
                    power::Bank::Pmgr => controller.view(instance as u8),
                    power::Bank::ClkGenSoc => controller.clock_view(instance as u8),
                }
                .map_err(|e| format!("T6000 request view: {e:?}"))?;
                let id = models.len();
                for offset in offsets {
                    if offset.checked_add(4).is_none_or(|end| end > view.bytes) {
                        return Err("T6000 request exceeds its actual RegMap".into());
                    }
                    mappings.push(Mapping {
                        model: id,
                        physical: view
                            .physical
                            .checked_add(offset)
                            .ok_or("T6000 request physical address overflows")?,
                        bytes: 4,
                        offset,
                    });
                }
                models.push(Box::new(model));
            }
        }
        let native_controls = models.len();
        for word in native::controls() {
            if !descriptor.registers.iter().flatten().any(|&(base, bytes)| {
                word.address
                    .checked_sub(base)
                    .and_then(|offset| offset.checked_add(4))
                    .is_some_and(|end| end <= bytes)
            }) && !matches!(word.address, 0x292000200 | 0x292000204)
            {
                return Err("T6000 native control lacks its source register view".into());
            }
            // LLB4b030 and indirect row3d7d4 separately own the exact two
            // native controller words292000200/+204; neither is in DT reg.
            // No surrounding aperture or MCC ownership is inferred.
            mappings.push(Mapping {
                model: native_controls,
                physical: word.address,
                bytes: 4,
                offset: word.address,
            });
        }
        models.push(Box::new(
            controller
                .native_controls()
                .map_err(|e| format!("T6000 native controls: {e:?}"))?,
        ));
        let native_sram = models.len();
        mappings.push(Mapping {
            model: native_sram,
            physical: SRAM_BASE,
            bytes: SRAM_LIMIT - SRAM_BASE,
            offset: 0,
        });
        models.push(Box::new(
            controller
                .native_sram()
                .map_err(|e| format!("T6000 SRAM owner: {e:?}"))?,
        ));
        mappings.sort_by_key(|map| map.physical);
        for map in &mappings {
            if map.bytes == 0
                || map.physical.checked_add(map.bytes).is_none()
                || map.offset.checked_add(map.bytes).is_none()
            {
                return Err("T6000 actual resource mapping is empty or overflows".into());
            }
        }
        for pair in mappings.windows(2) {
            if pair[0].physical + pair[0].bytes > pair[1].physical {
                return Err(format!(
                    "T6000 actual sparse owners overlap at {:#x}",
                    pair[1].physical
                ));
            }
        }
        Ok(Self {
            descriptor,
            models,
            mappings,
            identity,
            clusters,
            bridges,
            native_controls,
            native_sram,
            controller,
            authority: input.authority,
            ibootdata: input.ibootdata,
            program,
        })
    }
    pub fn mappings(&self) -> &[Mapping] {
        &self.mappings
    }
    pub fn descriptor(&self) -> &Descriptor {
        &self.descriptor
    }
    pub fn program(&self) -> &ProgramSource {
        &self.program
    }

    /// Root must join canonical physical SRAM to the returned native_memory()
    /// before firmware runs. This publishes no PMGR admission/lifecycle credit
    /// for clusters/bridges and creates no separate memory backing plane.
    pub fn publish(self, devices: &mut AppleDevices) -> Result<Mounted, String> {
        for map in &self.mappings {
            devices
                .bus
                .check_free(map.physical, map.bytes)
                .map_err(|e| format!("T6000 full-resource MMIO preflight: {e:?}"))?;
        }
        let memory = self
            .controller
            .native_memory()
            .map_err(|e| format!("T6000 canonical SRAM: {e:?}"))?;
        let ids = self
            .models
            .into_iter()
            .map(|model| devices.bus.add(model))
            .collect::<Vec<_>>();
        for map in self.mappings {
            devices
                .bus
                .map(ids[map.model], map.physical, map.bytes, map.offset)
                .expect("complete exclusive native map preflight remains valid");
        }
        Ok(Mounted {
            identity: ids[self.identity],
            clusters: self.clusters.map(|i| ids[i]),
            bridges: self.bridges.into_iter().map(|i| ids[i]).collect(),
            native_controls: ids[self.native_controls],
            native_sram: ids[self.native_sram],
            controller: self.controller,
            memory,
            descriptor: self.descriptor,
            authority: self.authority,
            ibootdata: self.ibootdata,
            program: self.program,
        })
    }
}
pub struct Mounted {
    pub identity: DeviceId,
    pub clusters: [DeviceId; 3],
    pub bridges: Vec<DeviceId>,
    pub native_controls: DeviceId,
    pub native_sram: DeviceId,
    pub controller: Controller,
    pub memory: native::Sram,
    pub descriptor: Descriptor,
    pub authority: Authority,
    pub ibootdata: IbootData,
    pub program: ProgramSource,
}

#[cfg(all(test, feature = "std"))]
mod original {
    use super::*;
    use alloc::vec;
    use stela_contracts::bus::Access;
    use stela_engine::machine::engine::Devices;
    const ADT_SHA: &str = "44fa41bfd0fe0027fd862b8615ae956885614636625d44a59cab226d682558ad";
    const IBDT_SHA: &str = "6d38d4b30deedb1be526e36179205004957f10e23254392fc3645c63dfd2b095";
    // These values declare a newly owned test resource, never Apple reset.
    fn inputs() -> Inputs {
        let image = identity::Image::new(identity::Input::DeclaredStela(
            identity::Register::ALL
                .into_iter()
                .map(|register| identity::Observation {
                    register,
                    value: if register == identity::Register::Revision {
                        0x20
                    } else {
                        0
                    },
                    known: u32::MAX,
                })
                .collect(),
        ))
        .unwrap();
        let geometry = power::Instance {
            complexes: 7,
            cio_ports: 15,
            cpm_controls: 7,
            isp_clocks: 15,
        };
        let observations = [power::Bank::Pmgr, power::Bank::ClkGenSoc]
            .into_iter()
            .flat_map(|bank| {
                geometry
                    .offsets(bank)
                    .into_iter()
                    .map(move |offset| power::Observation {
                        instance: 0,
                        bank,
                        offset,
                        value: 0,
                        known: u32::MAX,
                    })
            })
            .collect();
        let bytes = std::fs::read(std::env::var("STELA_TEST_PMGR_M1_IBOOTDATA").unwrap()).unwrap();
        assert_eq!(stela_formats::sha256(&bytes), IBDT_SHA);
        Inputs {
            authority: Authority::DeclaredStela {
                entry: "explicit test resource".into(),
            },
            identity: image,
            revision: RevisionAuthority::DeclaredBeforeCache,
            board: 8,
            platform_revision: 0,
            clusters: [
                Complex::Efficiency,
                Complex::Performance0,
                Complex::Performance1,
            ]
            .map(|complex| Snapshot {
                complex,
                states: 16,
                words: Vec::new(),
            }),
            bridges: vec![Vec::new(); 193],
            requests: Requests {
                geometry: vec![geometry],
                lifecycle: LifecycleState {
                    powered: true,
                    clocked: true,
                    quiesced: false,
                    reset: false,
                    retention: true,
                },
                observations,
            },
            native: native::Handoff::StelaEmpty {
                sram: native::SramInitialization::Unknown,
            },
            ibootdata: IbootData {
                source: "pinned original identity5 ibdt member; signature not verified".into(),
                expected_sha256: IBDT_SHA.into(),
                bytes,
            },
        }
    }
    fn adt() -> Vec<u8> {
        let bytes = std::fs::read(std::env::var("STELA_TEST_PMGR_M1_ADT").unwrap()).unwrap();
        assert_eq!(stela_formats::sha256(&bytes), ADT_SHA);
        bytes
    }
    #[test]
    #[ignore = "oracle: STELA_TEST_PMGR_M1_ADT, STELA_TEST_PMGR_M1_IBOOTDATA"]
    fn original_shared_native_bytes_and_sparse_unknown_owners() {
        let prepared = Prepared::new(&adt(), inputs()).unwrap();
        assert_eq!(prepared.program().revision, 0x20);
        assert_eq!(prepared.program().rows, 17739);
        assert_eq!(prepared.program().bytes, 0x67f08);
        assert!(
            prepared
                .mappings()
                .iter()
                .any(|m| m.physical == 0x2922dc21c)
        );
        assert!(!prepared.mappings().iter().any(|m| m.physical == 0x292dc21c));
        let cluster_word = prepared
            .mappings()
            .iter()
            .find(|m| m.model == prepared.clusters[0])
            .unwrap()
            .physical;
        let bridge_word = prepared
            .mappings()
            .iter()
            .find(|m| m.model == prepared.bridges[0])
            .unwrap()
            .physical;
        let mut devices = AppleDevices::new();
        let mut mounted = prepared.publish(&mut devices).unwrap();
        assert_eq!(mounted.descriptor.power.registers.len(), 196);
        assert_eq!(mounted.bridges.len(), 193);
        assert!(
            devices
                .bus
                .device_mut::<T6000>(mounted.clusters[0])
                .unwrap()
                .lifecycle()
                .is_none()
        );
        assert!(
            devices
                .bus
                .device_mut::<Bridge>(mounted.bridges[0])
                .unwrap()
                .lifecycle()
                .is_none()
        );
        for (address, width) in [(cluster_word, 8), (bridge_word, 4)] {
            assert!(
                matches!(devices.read(0, address, width, 0), Err(stela_engine::machine::engine::DeviceError::Refused(reason)) if reason.contains("unknown"))
            );
        }
        assert_eq!(
            devices.read(0, identity::Register::Revision.address(), 4, 0),
            Ok(0x20)
        );
        assert!(
            devices
                .write(0, identity::Register::Feature.address(), 4, 1 << 31, 0)
                .is_err()
        );
        let mut unchanged = [0xa5; 4];
        assert!(
            mounted
                .memory
                .read_checked(SRAM_BASE, &mut unchanged)
                .is_err()
        );
        assert_eq!(unchanged, [0xa5; 4]);
        devices.write(0, SRAM_BASE, 4, 0x12345678, 0).unwrap();
        mounted
            .memory
            .read_checked(SRAM_BASE, &mut unchanged)
            .unwrap();
        assert_eq!(unchanged, 0x12345678u32.to_le_bytes());
        mounted
            .memory
            .write_checked(SRAM_BASE + 4, &[1, 2, 3, 4])
            .unwrap();
        assert_eq!(devices.read(0, SRAM_BASE + 4, 4, 0), Ok(0x04030201));
        let mut access = Access::new(0, 0, &mut devices.latch);
        let view = devices
            .bus
            .device_mut::<native::View>(mounted.native_controls)
            .unwrap();
        let proposed = LifecycleState {
            clocked: false,
            ..mounted.controller.lifecycle()
        };
        let lifecycle = view.lifecycle().unwrap();
        lifecycle.check_lifecycle(proposed).unwrap();
        lifecycle.set_lifecycle(proposed, &mut access);
        assert!(
            mounted
                .memory
                .read_checked(SRAM_BASE, &mut unchanged)
                .is_err()
        );
        assert!(devices.read(0, SRAM_BASE, 4, 0).is_err());
        // Pausing native resources cannot grant lifecycle credit to ACC/bridge.
        assert!(
            devices
                .bus
                .device_mut::<T6000>(mounted.clusters[0])
                .unwrap()
                .lifecycle()
                .is_none()
        );
    }
    #[test]
    #[ignore = "oracle: STELA_TEST_PMGR_M1_ADT, STELA_TEST_PMGR_M1_IBOOTDATA"]
    fn original_complete_preflight_keeps_existing_owner_and_publishes_nothing() {
        let prepared = Prepared::new(&adt(), inputs()).unwrap();
        let mut devices = AppleDevices::new();
        let existing = devices.bus.add(Box::new(inputs().identity));
        // An interior owner of a large proposed SRAM span must be found.
        devices
            .bus
            .map(
                existing,
                SRAM_BASE + 0x1234,
                4,
                identity::Register::Revision.address(),
            )
            .unwrap();
        assert!(prepared.publish(&mut devices).is_err());
        assert_eq!(devices.read(0, SRAM_BASE + 0x1234, 4, 0), Ok(0x20));
        assert!(
            devices
                .read(0, identity::Register::Chip.address(), 4, 0)
                .is_err()
        );
        assert!(devices.read(0, SRAM_BASE, 4, 0).is_err());
    }
    #[test]
    #[ignore = "oracle: STELA_TEST_PMGR_M1_ADT, STELA_TEST_PMGR_M1_IBOOTDATA"]
    fn original_permission_provenance_cache_and_full_family_refusals() {
        let bytes = adt();
        let mut input = inputs();
        input.revision = RevisionAuthority::ObservedCache {
            value: 0x10,
            known: u32::MAX,
        };
        assert!(
            Prepared::new(&bytes, input)
                .err()
                .unwrap()
                .contains("cache word")
        );
        let mut input = inputs();
        input.ibootdata.bytes[0] ^= 1;
        assert!(
            Prepared::new(&bytes, input)
                .err()
                .unwrap()
                .contains("digest")
        );
        let mut input = inputs();
        input.bridges.pop();
        assert!(Prepared::new(&bytes, input).err().unwrap().contains("193"));
        let mut input = inputs();
        input.authority = Authority::Captured {
            source: "not a declared resource".into(),
        };
        assert!(
            Prepared::new(&bytes, input)
                .err()
                .unwrap()
                .contains("captured Apple handoff")
        );
        let mut input = inputs();
        input.requests.observations.pop();
        assert!(
            Prepared::new(&bytes, input)
                .err()
                .unwrap()
                .contains("MissingObservation")
        );
        let mut input = inputs();
        input.revision = RevisionAuthority::ObservedCache {
            value: u32::MAX,
            known: u32::MAX,
        };
        assert!(Prepared::new(&bytes, input).is_ok());
    }
}
