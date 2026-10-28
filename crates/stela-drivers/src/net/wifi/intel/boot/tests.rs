// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2007-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
//! Shared Intel boot fixtures and protocol cases.
extern crate std;
use super::super::{
    dma::tests::{Domain, Records, Source},
    identity::Observed,
    power::ManagementSession,
};
use super::*;
use alloc::collections::BTreeMap;
use core::sync::atomic::AtomicUsize;
use std::sync::Mutex;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    Read(u32),
    Write(u32, u32),
    Write8(u32, u8),
    Delay(u32),
}
struct Owner(Arc<AtomicUsize>);
impl Drop for Owner {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}
struct Model {
    state: Arc<Mutex<ModelState>>,
    _owner: Owner,
}
struct ModelState {
    registers: BTreeMap<u32, u32>,
    ops: Vec<Op>,
    fail: Option<usize>,
    fail_read: Option<u32>,
    all_ff: bool,
    stop_ack: bool,
    sentinel: Option<(usize, u32)>,
}
impl Default for ModelState {
    fn default() -> Self {
        Self {
            registers: BTreeMap::from([(0x28, 0x340), (0x9c, 0x10a000), (0x24, 0x08000001)]),
            ops: Vec::new(),
            fail: None,
            fail_read: None,
            all_ff: false,
            stop_ack: true,
            sentinel: None,
        }
    }
}
impl Model {
    fn operation(
        &mut self,
        op: Op,
    ) -> Result<std::sync::MutexGuard<'_, ModelState>, power::AccessError> {
        let mut state = self.state.lock().unwrap();
        let index = state.ops.len();
        state.ops.push(op);
        if state.fail == Some(index) {
            return Err(power::AccessError::Unavailable);
        }
        Ok(state)
    }
}
impl Csr for Model {
    fn read32(&mut self, register: u32) -> Result<u32, power::AccessError> {
        let state = self.operation(Op::Read(register))?;
        if state.fail_read == Some(register) {
            return Err(power::AccessError::Unavailable);
        }
        if state.all_ff {
            return Ok(u32::MAX);
        }
        let value = if let Some((at, value)) = state.sentinel
            && at == state.ops.len() - 1
        {
            value
        } else {
            state.registers.get(&register).copied().unwrap_or(0)
        };
        Ok(
            if register == 0x20 && value & 0x200 != 0 && state.stop_ack {
                value | 0x100
            } else {
                value
            },
        )
    }
    fn write32(&mut self, register: u32, value: u32) -> Result<(), power::AccessError> {
        let mut state = self.operation(Op::Write(register, value))?;
        if register == 8 || register == 16 {
            let prior = state.registers.entry(register).or_default();
            *prior &= !value;
        } else {
            state.registers.insert(register, value);
        }
        Ok(())
    }
    fn delay_us(&mut self, microseconds: u32) -> Result<(), power::AccessError> {
        drop(self.operation(Op::Delay(microseconds))?);
        Ok(())
    }
}
// SAFETY: real owned synchronous CSR/requester model; no alternate accesses
// occur except explicit serialized device events through its shared state.
unsafe impl BootIo for Model {
    fn write8(&mut self, register: u32, value: u8) -> Result<(), power::AccessError> {
        let mut state = self.operation(Op::Write8(register, value))?;
        let word = state.registers.entry(register & !3).or_default();
        let shift = (register & 3) * 8;
        *word = (*word & !(0xff << shift)) | (u32::from(value) << shift);
        Ok(())
    }
}
fn profile() -> Profile {
    Profile::select(Observed {
        vendor: 0x8086,
        device: 0x2723,
        subsystem_vendor: 0x8086,
        subsystem_device: 0x84,
        pci_revision: 0x1a,
        hardware_revision: 0x340,
        radio_id: 0x10a000,
    })
    .unwrap()
}
fn awake(state: Arc<Mutex<ModelState>>, drops: Arc<AtomicUsize>) -> Power<Model> {
    awake_profile(state, drops, profile())
}
fn awake_profile(
    state: Arc<Mutex<ModelState>>,
    drops: Arc<AtomicUsize>,
    profile: Profile,
) -> Power<Model> {
    let mut power = Power::new(
        Model {
            state: state.clone(),
            _owner: Owner(drops),
        },
        profile,
    );
    power.wake(ManagementSession::NotConnected).unwrap();
    state.lock().unwrap().ops.clear();
    power
}
fn firmware_bytes() -> Vec<u8> {
    let mut bytes = vec![0; 88];
    bytes[4..8].copy_from_slice(&0x0a4c5749u32.to_le_bytes());
    bytes[72..76].copy_from_slice(&(77u32 << 8).to_le_bytes());
    let mut tlv = |kind: u32, data: &[u8]| {
        bytes.extend(kind.to_le_bytes());
        bytes.extend((data.len() as u32).to_le_bytes());
        bytes.extend(data);
        while !bytes.len().is_multiple_of(4) {
            bytes.push(0);
        }
    };
    tlv(27, &2u32.to_le_bytes());
    tlv(32, &4096u32.to_le_bytes());
    tlv(48, &[1, 0, 99, 6, 0xfe, 0xc, 99, 1]);
    tlv(23, &0x2du32.to_le_bytes());
    for (offset, n, seed) in [
        (0u32, 16, 1u8),
        (0xffffcccc, 0, 0),
        (0x1000, 16, 2),
        (0xaaaabbbb, 0, 0),
        (0, 16, 3),
        (0x2000, 4096, 4),
    ] {
        let mut data = offset.to_le_bytes().to_vec();
        data.extend((0..n).map(|n| seed.wrapping_add(n as u8)));
        tlv(19, &data);
    }
    bytes
}
fn catalog_for(profile: &Profile, name: &str, bytes: &[u8]) -> resources::Catalog {
    let request = profile.firmware_request();
    catalog_for_target(request.requirement().target, name, bytes)
}
fn catalog_for_target(
    target: resources::Target<'_>,
    name: &str,
    bytes: &[u8],
) -> resources::Catalog {
    use sha2::{Digest, Sha256};
    resources::Catalog::from_handoff(vec![resources::Resource {
        name,
        target,
        provenance: resources::Provenance {
            source: "test",
            revision: "immutable",
            member: name,
            license: "LicenseRef-Local-Test-Fixture",
        },
        expected_length: bytes.len(),
        expected_sha256: Sha256::digest(bytes).into(),
        bytes: bytes.to_vec(),
    }])
    .unwrap()
}
fn start<'a>(
    catalog: &'a resources::Catalog,
    source: &Source,
    domain: &Arc<Domain>,
    state: &Arc<Mutex<ModelState>>,
    drops: &Arc<AtomicUsize>,
) -> Ax200Boot<'a, Model> {
    // SAFETY: fixture owns fresh actual host RAM and a synchronous isolated
    // coherent domain/device; no IRQ, competing worker or real DMA exists.
    unsafe {
        Ax200Boot::start(
            awake(state.clone(), drops.clone()),
            super::super::identity::stage(&profile(), catalog).unwrap(),
            source,
            Some(domain.clone()),
            32,
        )
        .unwrap()
    }
}
fn id(address: u64) -> u64 {
    (address - 0x100000) / 0x10000
}
fn phase_catalog(
    profile: &Profile,
    sku: [u32; 3],
    bios: bool,
    reduced: bool,
) -> (Observations, resources::Catalog) {
    use super::super::platform::{CapturedVariable, Observation, Stage, Variable};
    use sha2::{Digest, Sha256};
    fn tlv(bytes: &mut Vec<u8>, kind: u32, data: &[u8]) {
        bytes.extend(kind.to_le_bytes());
        bytes.extend((data.len() as u32).to_le_bytes());
        bytes.extend(data);
        bytes.resize(bytes.len().next_multiple_of(4), 0);
    }
    let mut pnvm = Vec::new();
    let sku_bytes: Vec<_> = sku.into_iter().flat_map(u32::to_le_bytes).collect();
    tlv(&mut pnvm, 64, &sku_bytes);
    let observed = profile.observed();
    let mut hw = Vec::new();
    hw.extend((((observed.hardware_revision & 0xfff0) >> 4) as u16).to_le_bytes());
    hw.extend((((observed.radio_id & 0xfff000) >> 12) as u16).to_le_bytes());
    tlv(&mut pnvm, 58, &hw);
    tlv(&mut pnvm, 62, &0x12345678u32.to_le_bytes());
    for n in 0..2 {
        let mut chunk = (0x1234u32 + n).to_le_bytes().to_vec();
        chunk.extend(vec![0x40 + n as u8; 16 + n as usize]);
        tlv(&mut pnvm, 19, &chunk);
    }
    let mut power = Vec::new();
    tlv(&mut power, 64, &sku_bytes);
    for n in 0..2 {
        let mut chunk = (0xf0000000u32 + n).to_le_bytes().to_vec();
        chunk.extend((12u32 + n).to_le_bytes());
        chunk.extend(vec![0x60 + n as u8; 12 + n as usize]);
        tlv(&mut power, 7, &chunk);
    }
    let mut ppackage = vec![0; 14];
    ppackage.extend(&pnvm);
    let mut rpackage = vec![0; 14];
    rpackage.extend(power);
    let mut pc = CapturedVariable::from_variable(Variable::OemPnvm, ppackage, 7, None).unwrap();
    let mut rc =
        CapturedVariable::from_variable(Variable::ReducedPower, rpackage, 7, None).unwrap();
    let absent = Observation::from_error(Stage::Probe, (1 << 63) | 14, None);
    let observations = Observations {
        oem_pnvm: if bios { pc.observation() } else { absent },
        reduced_power: if reduced { rc.observation() } else { absent },
        step: Observation::NotCaptured,
        ..Observations::default()
    };
    let mut resources = Vec::new();
    if bios {
        resources.push(pc.take_resource().unwrap());
    }
    if reduced {
        resources.push(rc.take_resource().unwrap());
    }
    let request = profile.pnvm_request();
    if let Some(ref request) = request {
        resources.push(resources::Resource {
            name: request.name,
            target: request.requirement().target,
            provenance: resources::Provenance {
                source: "test",
                revision: "immutable",
                member: request.name,
                license: "LicenseRef-Local-Test-Fixture",
            },
            expected_length: pnvm.len(),
            expected_sha256: Sha256::digest(&pnvm).into(),
            bytes: pnvm,
        });
    }
    (
        observations,
        resources::Catalog::from_handoff(resources).unwrap(),
    )
}
fn command_ready<'a>(
    mut boot: RomBoot<'a, Model>,
    empty: &'a resources::Catalog,
    source: &Source,
    domain: &Domain,
    state: &Arc<Mutex<ModelState>>,
) -> RomBoot<'a, Model> {
    event(state, 1);
    boot.poll().unwrap();
    let mut packet = rx_packet(1, 0xcafe, 0);
    set_sku(&mut packet, [0; 3]);
    complete(&boot, domain, 0, 1, &packet);
    boot.poll().unwrap().unwrap();
    assert!(matches!(
        unsafe { boot.begin_pnvm(empty, Observations::default(), source) }.unwrap(),
        PnvmProgress::Skipped
    ));
    boot
}
fn command_packet(id: super::super::command::Id, sequence: u16, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 4096];
    bytes[..4].copy_from_slice(&(4u32 + payload.len() as u32).to_le_bytes());
    bytes[4] = id.opcode;
    bytes[5] = id.group;
    bytes[6..8].copy_from_slice(&sequence.to_le_bytes());
    bytes[8..8 + payload.len()].copy_from_slice(payload);
    let next = (8 + payload.len()).next_multiple_of(64);
    bytes[next..next + 4].copy_from_slice(&0x55550000u32.to_le_bytes());
    bytes
}
fn command_id() -> super::super::command::Id {
    super::super::command::Id {
        group: 2,
        opcode: 3,
        version: 1,
    }
}
fn radio_bytes(ax210: bool) -> Vec<u8> {
    let mut bytes = unified_bytes(ax210);
    let mut at = 88;
    while at < bytes.len() {
        let kind = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let len = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as usize;
        if kind == 23 {
            let word = u32::from_le_bytes(bytes[at + 8..at + 12].try_into().unwrap()) | (3 << 16);
            bytes[at + 8..at + 12].copy_from_slice(&word.to_le_bytes());
        }
        at += 8 + len.next_multiple_of(4);
    }
    let versions = [
        0xd1,
        1,
        3,
        0,
        0x98,
        1,
        1,
        0,
        0x9b,
        1,
        6,
        0,
        1,
        2,
        2,
        0,
        0xc1,
        0,
        99,
        if ax210 { 5 } else { 4 },
        0x1c,
        1,
        if ax210 { 10 } else { 9 },
        7,
        0xf7,
        5,
        99,
        3,
    ];
    let mut at = 88;
    while at < bytes.len() {
        let kind = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let len = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as usize;
        if kind == 48 {
            bytes.splice(at + 8 + len..at + 8 + len, versions);
            bytes[at + 4..at + 8].copy_from_slice(&((len + versions.len()) as u32).to_le_bytes());
            break;
        }
        at += 8 + len.next_multiple_of(4);
    }
    bytes.extend(30u32.to_le_bytes());
    bytes.extend(8u32.to_le_bytes());
    bytes.extend(1u32.to_le_bytes());
    bytes.extend((1u32 << 5).to_le_bytes());
    if ax210 {
        bytes.extend(29u32.to_le_bytes());
        bytes.extend(8u32.to_le_bytes());
        bytes.extend(2u32.to_le_bytes());
        bytes.extend((1u32 << 4).to_le_bytes());
    }
    bytes
}
fn drive_nvm<'a>(
    boot: RomBoot<'a, Model>,
    source: &Source,
    domain: &Domain,
    state: &Arc<Mutex<ModelState>>,
) -> UnifiedNvm<'a, Model> {
    use super::super::nvm::Request;
    state
        .lock()
        .unwrap()
        .registers
        .extend([(0x388, 0x02123456), (0x38c, 0x789a)]);
    let init = boot.initialize_on_device_nvm();
    let before = state.lock().unwrap().ops.len();
    let mut init = match init.begin_radio() {
        Err(owner) => *owner,
        Ok(_) => panic!("uninitialized owner admitted"),
    };
    assert_eq!(state.lock().unwrap().ops.len(), before);
    unsafe { init.advance(source) }.unwrap();
    complete(
        &init.boot,
        domain,
        1,
        2,
        &command_packet(Request::ExtendedConfiguration.id(), 0, &[]),
    );
    unsafe { init.advance(source) }.unwrap();
    complete(
        &init.boot,
        domain,
        2,
        3,
        &command_packet(Request::AccessComplete.id(), 1, &[]),
    );
    unsafe { init.advance(source) }.unwrap();
    complete(
        &init.boot,
        domain,
        3,
        4,
        &command_packet(
            super::super::command::Id {
                group: 0,
                opcode: 4,
                version: 0,
            },
            0x8000,
            &[0x76],
        ),
    );
    unsafe { init.advance(source) }.unwrap();
    complete(
        &init.boot,
        domain,
        4,
        5,
        &command_packet(Request::GetInformation.id(), 2, &nvm_response()),
    );
    assert_eq!(
        unsafe { init.advance(source) }.unwrap(),
        InitializationProgress::Observed
    );
    init
}
fn exercise_cold_radio(actual: bool) {
    use super::super::radio::InitialPlan;
    for ax210 in [false, true] {
        let profile = if ax210 { ax210_profile() } else { profile() };
        let bytes = if actual {
            let root = std::env::var("STELA_IWLWIFI_IMAGES").unwrap();
            std::fs::read(std::path::Path::new(&root).join(profile.family().firmware_name()))
                .unwrap()
        } else {
            radio_bytes(ax210)
        };
        let catalog = catalog_for(&profile, profile.family().firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let (observation, step_catalog) = step_fixture();
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let state = if ax210 {
            ax210_state()
        } else {
            Arc::new(Mutex::new(ModelState::default()))
        };
        let drops = Arc::new(AtomicUsize::new(0));
        let boot = if ax210 {
            start_ax210(
                &catalog,
                super::super::platform::load_step(observation, &step_catalog).unwrap(),
                &source,
                &domain,
                &state,
                &drops,
            )
        } else {
            start(&catalog, &source, &domain, &state, &drops)
        };
        let boot = command_ready(boot, &empty, &source, &domain, &state);
        let init = drive_nvm(boot, &source, &domain, &state);
        let expected = InitialPlan::prepare(
            &init.boot.firmware,
            profile.family(),
            &init.receipt().unwrap().information,
        )
        .unwrap();
        let mut copied = init.receipt().unwrap().clone();
        copied.information.tx_chains = 0xff;
        copied.address.bytes = [0; 6];
        let mut radio = init
            .begin_radio()
            .unwrap_or_else(|_| panic!("genuine NVM refused"));
        let before = state.lock().unwrap().ops.len();
        assert!(matches!(radio.poll_mpdu_observation(), Err(Error::State)));
        assert_eq!(state.lock().unwrap().ops.len(), before);
        assert_eq!(radio.initialized_nvm().information.tx_chains, 3);
        assert_ne!(radio.initialized_nvm().address.bytes, copied.address.bytes);
        assert_eq!(
            unsafe { radio.advance(&source) }.unwrap(),
            ColdRadioPhase::Waiting(expected.commands()[0].stage())
        );
        for (i, command) in expected.commands().iter().enumerate() {
            let sequence = 3 + i as u16;
            let boot = &radio.initialized.boot;
            let wire = device_read(
                &domain,
                boot.command.region().address,
                usize::from(sequence) * 256,
                256,
            );
            let first = u64::from_le_bytes(wire[4..12].try_into().unwrap());
            let encoded =
                super::super::command::Command::encode(command.id(), 0, sequence, command.bytes())
                    .unwrap();
            let mut emitted = device_read(&domain, first, 0, encoded.bytes().len().min(20));
            if encoded.bytes().len() > 20 {
                let rest = u64::from_le_bytes(wire[14..22].try_into().unwrap());
                emitted.extend(device_read(&domain, rest, 0, encoded.bytes().len() - 20));
            }
            assert_eq!(emitted, encoded.bytes());
            let doorbell = state.lock().unwrap().registers[&0x460];
            assert_eq!(
                unsafe { radio.advance(&source) }.unwrap(),
                ColdRadioPhase::Waiting(command.stage())
            );
            assert_eq!(state.lock().unwrap().registers[&0x460], doorbell);
            let mut response_id = command.id();
            if response_id.group == 0 {
                response_id.group = 1;
            }
            complete(
                &radio.initialized.boot,
                &domain,
                5 + i as u16,
                6 + i as u16,
                &command_packet(response_id, sequence, &[0xa0 + i as u8]),
            );
            if i == 0 {
                let mut r = domain.records.lock().unwrap();
                r.cpu_sync_fail = Some(r.cpu_syncs + 1);
                drop(r);
                assert!(matches!(
                    unsafe { radio.advance(&source) },
                    Err(Error::CommandReclaim(_))
                ));
                assert_eq!(radio.phase(), ColdRadioPhase::Waiting(command.stage()));
                assert_eq!(state.lock().unwrap().registers[&0x460], doorbell);
                domain.records.lock().unwrap().cpu_sync_fail = None;
            }
            let phase = unsafe { radio.advance(&source) }.unwrap();
            assert_eq!(
                phase,
                expected
                    .commands()
                    .get(i + 1)
                    .map_or(ColdRadioPhase::PlatformConfigurationRequired, |next| {
                        ColdRadioPhase::Waiting(next.stage())
                    })
            );
            assert_eq!(radio.prefix_responses().len(), i + 1);
            assert_eq!(radio.prefix_responses()[i].raw, [0xa0 + i as u8]);
        }
        let ops = state.lock().unwrap().ops.len();
        let allocations = source.calls.load(Ordering::Relaxed);
        assert_eq!(
            unsafe { radio.advance(&source) }.unwrap(),
            ColdRadioPhase::PlatformConfigurationRequired
        );
        assert_eq!(state.lock().unwrap().ops.len(), ops);
        assert_eq!(source.calls.load(Ordering::Relaxed), allocations);
        exercise_mpdu_observations(&mut radio, &source, &domain, &state);
        radio.stop().unwrap();
        drop(radio);
        assert!(domain.records.lock().unwrap().live.is_empty());
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }
}
fn exercise_mpdu_observations(
    radio: &mut ColdRadio<'_, Model>,
    source: &Source,
    domain: &Arc<Domain>,
    state: &Arc<Mutex<ModelState>>,
) {
    use super::super::command::Id;
    let ax210 = radio.initialized.boot.profile.family() == Family::Ax210;
    radio.replenish_completed_receive().unwrap();
    let allocations = source.calls.load(Ordering::Relaxed);
    let maps = domain.records.lock().unwrap().maps;
    let mut preserved = None;
    let mut normalized_preserved = None;
    let wire_frame = |cycle: u8| {
        let mut bytes: Vec<_> = (0..45u8).map(|n| n.wrapping_add(cycle)).collect();
        bytes[..2].copy_from_slice(&0x4208u16.to_le_bytes());
        bytes[22..24].copy_from_slice(&(u16::from(cycle) << 4).to_le_bytes());
        bytes[24..32].copy_from_slice(&[cycle + 1, 0, 0, 0x60, 0, 0, 0, 0]);
        bytes
    };
    let complete_payload = |radio: &ColdRadio<'_, Model>, payload: &[u8]| {
        let boot = &radio.initialized.boot;
        let slot = boot.read;
        let stride = if ax210 { 16 } else { 8 };
        let free = device_read(
            domain,
            boot.free.region().address,
            usize::from(slot) * stride,
            stride,
        );
        let vid = if ax210 {
            u16::from_le_bytes(free[..2].try_into().unwrap())
        } else {
            (u64::from_le_bytes(free.try_into().unwrap()) & 0xfff) as u16
        };
        let mut packet = command_packet(
            Id {
                group: 0,
                opcode: 0xc1,
                version: 0,
            },
            0x8000,
            payload,
        );
        let flags = u32::from_le_bytes(packet[..4].try_into().unwrap()) | (1 << 26);
        packet[..4].copy_from_slice(&flags.to_le_bytes());
        complete_from_free_slot(boot, domain, slot, vid, slot, &packet);
    };
    for cycle in 0..40u8 {
        let size = if ax210 { 64 } else { 48 };
        let mut payload = vec![0; size + 45];
        payload[..2].copy_from_slice(&45u16.to_le_bytes());
        payload[2] = 4 << 4; // 8 source-reported MIC/CRC bytes
        payload[3] = 0x20; // 2-byte pad after MAC + retained IV
        payload[7] = 1 << 6; // actual explicit band code 1 = 2.4 GHz
        payload[12..16].copy_from_slice(&0x0500026fu32.to_le_bytes());
        payload[16..20].copy_from_slice(&(127u32 << 24).to_le_bytes());
        let (rate, energy) = if ax210 { (36, 40) } else { (28, 32) };
        payload[rate..rate + 4].copy_from_slice(&(3u32 << 14).to_le_bytes());
        payload[energy..energy + 3].copy_from_slice(&[44, 56, 6]);
        payload[size..].copy_from_slice(&wire_frame(cycle));
        complete_payload(radio, &payload);
        let received = match radio.poll_mpdu_observation().unwrap() {
            MpduProgress::Observed(received) => received,
            _ => panic!("missing actual completed MPDU"),
        };
        assert_eq!(received.raw_mpdu(), &payload[size..]);
        assert_eq!(received.descriptor(), &payload[..size]);
        assert!(received.trailing().is_empty());
        assert_eq!(received.packet_flags() & (1 << 26), 1 << 26);
        assert_eq!(received.receive_queue(), 0);
        assert_eq!(received.metadata().status.station_id(), Some(5));
        assert_eq!(received.metadata().status.cipher_code(), 2);
        assert!(received.metadata().status.mic_ok_bit());
        assert!(!received.metadata().status.decrypted_bit());
        let normalized = received.normalize().unwrap();
        let mut expected = wire_frame(cycle)[..32].to_vec();
        expected.extend(&wire_frame(cycle)[34..37]);
        assert_eq!(normalized.frame().bytes(), expected);
        assert_eq!(normalized.frame().radio.frequency_mhz, 2437);
        assert_eq!(normalized.frame().security.key, None);
        assert_eq!(
            normalized.frame().security.integrity,
            crate::net::wifi::security::Integrity::Unknown
        );
        assert_eq!(
            normalized.frame().security.pn.unwrap().value(),
            u64::from(cycle) + 1
        );
        assert_eq!(normalized.key_index(), Some(1));
        assert!(normalized.crypto().decrypted);
        if cycle == 0 {
            preserved = Some(received);
            normalized_preserved = Some(normalized);
        }
        assert!(matches!(
            radio.poll_mpdu_observation().unwrap(),
            MpduProgress::Pending
        ));
        assert_eq!(radio.replenish_completed_receive().unwrap().returned, 1);
    }
    assert_eq!(preserved.unwrap().raw_mpdu(), wire_frame(0));
    let normalized = normalized_preserved.unwrap();
    let mut expected = wire_frame(0)[..32].to_vec();
    expected.extend(&wire_frame(0)[34..37]);
    assert_eq!(normalized.frame().bytes(), expected);
    assert_eq!(normalized.frame().security.pn.unwrap().value(), 1);
    // A malformed actual descriptor is retained as a rejection, never
    // retagged as a frame or allowed to poison the control/RX owner.
    let size = if ax210 { 64 } else { 48 };
    let mut bad = vec![0; size];
    bad[..2].copy_from_slice(&1u16.to_le_bytes());
    complete_payload(radio, &bad);
    let rejected = match radio.poll_mpdu_observation().unwrap() {
        MpduProgress::Rejected(r) => r,
        _ => panic!("malformed frame was not rejected"),
    };
    assert_eq!(
        rejected.error(),
        super::super::receive::mpdu::Error::MpduLength {
            declared: 1,
            available: 0
        }
    );
    assert_eq!(&rejected.raw_packet()[8..], bad);
    assert_eq!(radio.initialized.boot.state, State::PnvmObserved);
    radio.replenish_completed_receive().unwrap();
    // Queue-capacity fixture: canonical packet capture, not forged
    // public diagnostic restoration. One-RB reservation is family-specific.
    let count = if ax210 { 128 } else { 65 };
    for n in 0..count {
        let raw = command_packet(
            Id {
                group: 2,
                opcode: 0xe0,
                version: 0,
            },
            0x8000,
            &[n as u8],
        );
        let packet = Packets::new(radio.initialized.boot.profile.family(), 0, &raw)
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        radio
            .initialized
            .boot
            .hcmd
            .retain_notification(&packet)
            .unwrap();
    }
    let before = state.lock().unwrap().ops.len();
    let credits = radio.initialized.boot.credits;
    for _ in 0..3 {
        assert!(
            matches!(radio.poll_mpdu_observation().unwrap(),MpduProgress::Backpressure {notifications} if notifications==count)
        );
    }
    assert_eq!(state.lock().unwrap().ops.len(), before);
    assert_eq!(radio.initialized.boot.credits, credits);
    let mut notice = radio.take_firmware_notification().unwrap();
    assert_eq!(notice.raw, [0]);
    notice.command = 0xc1;
    notice.raw = vec![0; 64];
    assert!(matches!(
        radio.poll_mpdu_observation().unwrap(),
        MpduProgress::Pending
    ));
    for n in 1..count {
        let notification = radio.take_firmware_notification().unwrap();
        assert_eq!(
            (
                notification.command,
                notification.group,
                notification.sequence
            ),
            (0xe0, 2, 0x8000)
        );
        assert_eq!(notification.raw, [n as u8]);
    }
    let foreign = hcmd::CapturedNotification {
        epoch: Arc::new(()),
        bytes: rejected.raw_packet().to_vec(),
    };
    assert!(matches!(
        radio.initialized.boot.decode_captured_mpdu(foreign),
        Err(Error::ReceiveEpoch)
    ));
    assert_eq!(source.calls.load(Ordering::Relaxed), allocations);
    assert_eq!(domain.records.lock().unwrap().maps, maps);
    // Actual failed CPU handoff cannot issue an MPDU receipt or release
    // mappings. Actual bus-master/reset stop below still owns teardown.
    complete_payload(radio, &vec![0; size]);
    let live = domain.records.lock().unwrap().live.len();
    {
        let mut r = domain.records.lock().unwrap();
        r.cpu_sync_fail = Some(r.cpu_syncs);
    }
    assert!(matches!(radio.poll_mpdu_observation(), Err(Error::Dma(_))));
    assert_eq!(radio.initialized.boot.state, State::Poisoned);
    assert_eq!(domain.records.lock().unwrap().live.len(), live);
    domain.records.lock().unwrap().cpu_sync_fail = None;
    let before = state.lock().unwrap().ops.len();
    assert!(matches!(radio.poll_mpdu_observation(), Err(Error::State)));
    assert_eq!(state.lock().unwrap().ops.len(), before);
}
fn unified_bytes(ax210: bool) -> Vec<u8> {
    let mut b = if ax210 {
        ax210_bytes()
    } else {
        firmware_bytes()
    };
    let mut at = 88;
    loop {
        let kind = u32::from_le_bytes(b[at..at + 4].try_into().unwrap());
        let len = u32::from_le_bytes(b[at + 4..at + 8].try_into().unwrap()) as usize;
        if kind == 48 {
            b.splice(at + 8 + len..at + 8 + len, [2, 12, 1, 4]);
            b[at + 4..at + 8].copy_from_slice(&((len + 4) as u32).to_le_bytes());
            break;
        }
        at += 8 + len.next_multiple_of(4);
    }
    b.extend(29u32.to_le_bytes());
    b.extend(8u32.to_le_bytes());
    b.extend(1u32.to_le_bytes());
    b.extend((1u32 << 16).to_le_bytes());
    b
}
fn nvm_response() -> Vec<u8> {
    let mut b = vec![0; 468];
    for (at, word) in [
        (0, 1u32),
        (8, 0x8000001f),
        (12, 3),
        (16, 3),
        (20, 1),
        (24, 2),
        (28, 0x12345678),
        (32, 0xabcdef),
    ] {
        b[at..at + 4].copy_from_slice(&word.to_le_bytes());
    }
    b[4..8].copy_from_slice(&[0x34, 0x12, 0xa5, 4]);
    b
}
fn exercise_unified_nvm(actual_image: bool) {
    use super::super::nvm::{AddressSource, Request};
    for ax210 in [false, true] {
        let p = if ax210 { ax210_profile() } else { profile() };
        let bytes = if actual_image {
            let root = std::env::var("STELA_IWLWIFI_IMAGES").unwrap();
            let b = std::fs::read(std::path::Path::new(&root).join(p.family().firmware_name()))
                .unwrap();
            use sha2::{Digest, Sha256};
            assert_eq!(
                std::format!("{:x}", Sha256::digest(&b)),
                if ax210 {
                    "792478ef7752595525379a5068e2d47e310a2c344636b7df866c54746ced1dc0"
                } else {
                    "1866a58a1daee56b120362122d5f7548b443b53d33f2558a7e4407d58fd27dab"
                }
            );
            b
        } else {
            unified_bytes(ax210)
        };
        let catalog = catalog_for(&p, p.family().firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let (observation, step_catalog) = step_fixture();
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let state = if ax210 {
            ax210_state()
        } else {
            Arc::new(Mutex::new(ModelState::default()))
        };
        let drops = Arc::new(AtomicUsize::new(0));
        let boot = if ax210 {
            start_ax210(
                &catalog,
                super::super::platform::load_step(observation, &step_catalog).unwrap(),
                &source,
                &domain,
                &state,
                &drops,
            )
        } else {
            start(&catalog, &source, &domain, &state, &drops)
        };
        let mut boot = command_ready(boot, &empty, &source, &domain, &state);
        {
            let mut s = state.lock().unwrap();
            *s.registers.get_mut(&0x24).unwrap() &= !0x08000000;
            s.registers.extend(if ax210 {
                [(0x388, 0x02123456), (0x38c, 0x789a)]
            } else {
                [(0x380, 0x02123456), (0x384, 0x789a)]
            });
        }
        assert!(matches!(
            unsafe { boot.submit_command(command_id(), &[], &source) },
            Err(Error::RfKilled)
        ));
        let mut init = boot.initialize_on_device_nvm();
        assert_eq!(
            unsafe { init.advance(&source) }.unwrap(),
            InitializationProgress::Pending(InitializationPhase::ExtendedConfiguration)
        );
        let tfd = device_read(&domain, init.boot.command.region().address, 0, 256);
        let first = u64::from_le_bytes(tfd[4..12].try_into().unwrap());
        assert_eq!(
            device_read(&domain, first, 0, 12),
            [3, 2, 0, 0, 4, 0, 0, 0, 2, 0, 0, 0]
        );
        assert_eq!(
            unsafe { init.advance(&source) }.unwrap(),
            InitializationProgress::Pending(InitializationPhase::ExtendedConfiguration)
        );
        complete(
            &init.boot,
            &domain,
            1,
            2,
            &command_packet(Request::ExtendedConfiguration.id(), 0, &[]),
        );
        // Retry actual completed-range CPU visibility without replaying the
        // command or losing its exact initialization stage.
        {
            let mut r = domain.records.lock().unwrap();
            r.cpu_sync_fail = Some(r.cpu_syncs + 1);
        }
        assert!(matches!(
            unsafe { init.advance(&source) },
            Err(Error::CommandReclaim(_))
        ));
        assert_eq!(init.phase(), InitializationPhase::ExtendedConfiguration);
        domain.records.lock().unwrap().cpu_sync_fail = None;
        assert_eq!(
            unsafe { init.advance(&source) }.unwrap(),
            InitializationProgress::Pending(InitializationPhase::AccessComplete)
        );
        complete(
            &init.boot,
            &domain,
            2,
            3,
            &command_packet(Request::AccessComplete.id(), 1, &[]),
        );
        assert_eq!(
            unsafe { init.advance(&source) }.unwrap(),
            InitializationProgress::Pending(InitializationPhase::InitNotification)
        );
        assert_eq!(
            unsafe { init.advance(&source) }.unwrap(),
            InitializationProgress::Pending(InitializationPhase::InitNotification)
        );
        assert_eq!(state.lock().unwrap().registers.get(&0x460), Some(&2));
        let wrong = super::super::command::Id {
            group: 1,
            opcode: 4,
            version: 0,
        };
        complete(
            &init.boot,
            &domain,
            3,
            4,
            &command_packet(wrong, 0x8000, &[0x55]),
        );
        assert_eq!(
            unsafe { init.advance(&source) }.unwrap(),
            InitializationProgress::Pending(InitializationPhase::InitNotification)
        );
        let actual = super::super::command::Id {
            group: 0,
            opcode: 4,
            version: 0,
        };
        complete(
            &init.boot,
            &domain,
            4,
            5,
            &command_packet(actual, 0x8000, &[0x66]),
        );
        assert_eq!(
            unsafe { init.advance(&source) }.unwrap(),
            InitializationProgress::Pending(InitializationPhase::NvmInformation)
        );
        let raw = nvm_response();
        complete(
            &init.boot,
            &domain,
            5,
            6,
            &command_packet(Request::GetInformation.id(), 2, &raw),
        );
        assert_eq!(
            unsafe { init.advance(&source) }.unwrap(),
            InitializationProgress::Observed
        );
        let r = init.receipt().unwrap();
        assert_eq!(r.information.raw, raw);
        assert_eq!(r.information.channel_count, 2);
        assert_eq!(r.information.channel_profiles[1], 0xabcdef);
        assert_eq!(r.address.bytes, [2, 0x12, 0x34, 0x56, 0x78, 0x9a]);
        assert_eq!(
            r.address.source,
            if ax210 {
                AddressSource::Strap
            } else {
                AddressSource::Otp
            }
        );
        assert_eq!(r.init_complete.raw, [0x66]);
        assert_eq!(
            r.product_reset,
            ax210.then_some(ProductResetObservation {
                sb_configuration: 0,
                coordination: ProductResetCoordination::NotPerformedNoIwlmei
            })
        );
        assert_eq!(
            unsafe { init.advance(&source) }.unwrap(),
            InitializationProgress::Observed
        );
        let (mut boot, _) = match init.into_parts() {
            Ok(parts) => parts,
            Err(_) => panic!("missing observation"),
        };
        assert_eq!(boot.take_firmware_notification().unwrap().raw, [0x55]);
        let ops = state.lock().unwrap().ops.clone();
        if ax210 {
            assert!(!ops.contains(&Op::Read(0x380)));
            assert!(!ops.contains(&Op::Read(0x384)));
        }
        boot.stop().unwrap();
        assert!(domain.records.lock().unwrap().live.is_empty());
    }
}
fn exercise_rx_recycling(oracle: Option<&str>) {
    for ax210 in [false, true] {
        let mut reference = Vec::new();
        if let Some(oracle) = oracle {
            for line in oracle.lines() {
                let fields: Vec<_> = line.split_whitespace().collect();
                if fields[1].parse::<u8>().unwrap() != u8::from(ax210) {
                    continue;
                }
                if fields[0] == "initial" {
                    assert_eq!(&fields[2..], ["31", "24"]);
                } else {
                    assert_eq!(fields[0], "recycle");
                    let row: Vec<u16> = fields[2..].iter().map(|v| v.parse().unwrap()).collect();
                    reference.push(row);
                }
            }
            assert_eq!(reference.len(), 521);
            assert_eq!(reference[0], [0, 0, 1, 0, 0]);
        }
        let p = if ax210 { ax210_profile() } else { profile() };
        let bytes = if ax210 {
            ax210_bytes()
        } else {
            firmware_bytes()
        };
        let catalog = catalog_for(&p, p.family().firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let (observation, step_catalog) = step_fixture();
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let state = if ax210 {
            ax210_state()
        } else {
            Arc::new(Mutex::new(ModelState::default()))
        };
        let drops = Arc::new(AtomicUsize::new(0));
        let boot = if ax210 {
            start_ax210(
                &catalog,
                super::super::platform::load_step(observation, &step_catalog).unwrap(),
                &source,
                &domain,
                &state,
                &drops,
            )
        } else {
            start(&catalog, &source, &domain, &state, &drops)
        };
        let mut boot = command_ready(boot, &empty, &source, &domain, &state);
        let calls = source.calls.load(Ordering::Relaxed);
        let maps = domain.records.lock().unwrap().maps;
        assert_eq!(
            boot.replenish_completed_receive().unwrap(),
            Replenished {
                returned: 1,
                published: 8,
                device_credits: 31,
                waiting_for_completed_slot: false
            }
        );
        assert_eq!(state.lock().unwrap().registers.get(&0x1c80), Some(&0));
        let mut preserved = None;
        for n in 0..520u16 {
            let ticket = unsafe { boot.submit_command(command_id(), &[n as u8], &source) }.unwrap();
            let slot = (n + 1) & 31;
            let stride = if ax210 { 16 } else { 8 };
            let free = device_read(
                &domain,
                boot.free.region().address,
                usize::from(slot) * stride,
                stride,
            );
            let (vid, address) = if ax210 {
                (
                    u16::from_le_bytes(free[..2].try_into().unwrap()),
                    u64::from_le_bytes(free[8..16].try_into().unwrap()),
                )
            } else {
                let word = u64::from_le_bytes(free.try_into().unwrap());
                ((word & 0xfff) as u16, word & !0xfff)
            };
            assert_eq!(
                address,
                boot.buffers[usize::from(vid - 1)]
                    .allocation
                    .region()
                    .address
            );
            if oracle.is_some() {
                assert_eq!(
                    (
                        reference[usize::from(n) + 1][0],
                        reference[usize::from(n) + 1][1],
                        reference[usize::from(n) + 1][2]
                    ),
                    (n + 1, slot, vid)
                );
            }
            complete_from_free_slot(
                &boot,
                &domain,
                slot,
                vid,
                slot,
                &command_packet(command_id(), ticket.sequence(), &[n as u8]),
            );
            let response = match boot.poll_command(&ticket).unwrap() {
                CommandProgress::Completed(r) => r,
                _ => panic!("no completion"),
            };
            assert_eq!(response.raw, [n as u8]);
            if n == 0 {
                preserved = Some(response.raw);
            }
            let replenished = boot.replenish_completed_receive().unwrap();
            assert_eq!(replenished.returned, 1);
            assert!(!replenished.waiting_for_completed_slot);
            assert!(matches!(replenished.published, 0 | 8));
            let expected = ((32 + n + 1) & 31) & !7;
            assert_eq!(
                state.lock().unwrap().registers.get(&0x1c80),
                Some(&u32::from(expected))
            );
            if oracle.is_some() {
                assert_eq!(reference[usize::from(n) + 1][4], expected);
            }
        }
        assert_eq!(preserved.unwrap(), [0]);
        assert_eq!(source.calls.load(Ordering::Relaxed), calls);
        assert_eq!(domain.records.lock().unwrap().maps, maps);
        boot.stop().unwrap();
        assert!(domain.records.lock().unwrap().live.is_empty());
    }
}
fn pnvm_packet(status: u32) -> Vec<u8> {
    let mut bytes = vec![0; 4096];
    bytes[..4].copy_from_slice(&12u32.to_le_bytes());
    bytes[4] = 0xfe;
    bytes[5] = 0xc;
    bytes[7] = 0x80;
    bytes[8..12].copy_from_slice(&status.to_le_bytes());
    bytes[12..16].copy_from_slice(&0x12345678u32.to_le_bytes());
    bytes[64..68].copy_from_slice(&0x55550000u32.to_le_bytes());
    bytes
}
fn set_sku(bytes: &mut [u8], sku: [u32; 3]) {
    for (n, word) in sku.into_iter().enumerate() {
        bytes[124 + n * 4..128 + n * 4].copy_from_slice(&word.to_le_bytes());
    }
}
fn alive_ax210<'a>(
    catalog: &'a resources::Catalog,
    step: StepConfiguration<'a>,
    source: &Source,
    domain: &Arc<Domain>,
    state: &Arc<Mutex<ModelState>>,
    drops: &Arc<AtomicUsize>,
) -> RomBoot<'a, Model> {
    let mut boot = start_ax210(catalog, step, source, domain, state, drops);
    event(state, 1);
    boot.poll().unwrap();
    complete(&boot, domain, 0, 1, &rx_packet(1, 0xcafe, 0));
    boot.poll().unwrap().unwrap();
    boot
}
fn device_write(domain: &Domain, address: u64, offset: usize, bytes: &[u8], complete: bool) {
    let mut r = domain.records.lock().unwrap();
    let id = id(address);
    assert!(matches!(
        r.permissions.get(&id),
        Some(Direction::FromDevice | Direction::Bidirectional)
    ));
    let pointer = r
        .live
        .get(&id)
        .unwrap()
        .address(
            (address - (0x100000 + id * 0x10000)) as usize + offset,
            bytes.len(),
        )
        .unwrap();
    // SAFETY: serialized model requester writes only actual mapped live RAM
    // with device-write permission, before publishing its completion status.
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), pointer.as_ptr(), bytes.len());
    }
    if complete {
        assert!(r.completed.insert(id));
    }
}
fn device_read(domain: &Domain, address: u64, offset: usize, n: usize) -> Vec<u8> {
    let r = domain.records.lock().unwrap();
    let id = id(address);
    assert!(matches!(
        r.permissions.get(&id),
        Some(Direction::ToDevice | Direction::Bidirectional)
    ));
    let pointer = r
        .live
        .get(&id)
        .unwrap()
        .address((address - (0x100000 + id * 0x10000)) as usize + offset, n)
        .unwrap();
    let mut bytes = vec![0; n];
    unsafe {
        core::ptr::copy_nonoverlapping(pointer.as_ptr(), bytes.as_mut_ptr(), n);
    }
    bytes
}
fn rx_packet(command: u8, status: u16, queue: u8) -> Vec<u8> {
    let mut bytes = vec![0; 4096];
    bytes[..4].copy_from_slice(&(148u32 | (u32::from(queue) << 16)).to_le_bytes());
    bytes[4] = command;
    bytes[7] = 0x80;
    bytes[8..10].copy_from_slice(&status.to_le_bytes());
    for (n, word) in [0x610d0u32, 0x1234, 0x55667788].iter().enumerate() {
        bytes[124 + n * 4..128 + n * 4].copy_from_slice(&word.to_le_bytes());
    }
    bytes[192..196].copy_from_slice(&0x55550000u32.to_le_bytes());
    bytes
}
fn event(state: &Arc<Mutex<ModelState>>, cause: u32) {
    let mut s = state.lock().unwrap();
    *s.registers.entry(8).or_default() |= cause;
}
fn complete(boot: &Ax200Boot<'_, Model>, domain: &Domain, index: u16, vid: u16, packet: &[u8]) {
    complete_from_free_slot(boot, domain, index, vid, vid - 1, packet);
}
fn complete_from_free_slot(
    boot: &Ax200Boot<'_, Model>,
    domain: &Domain,
    index: u16,
    vid: u16,
    free_slot: u16,
    packet: &[u8],
) {
    let stride = if boot.profile.family() == Family::Ax210 {
        16
    } else {
        8
    };
    // Actual model requester consumed this emitted free descriptor before
    // completing its receive payload; this grants only that exact range.
    let mut r = domain.records.lock().unwrap();
    r.completed_ranges.insert((
        id(boot.free.region().address),
        usize::from(free_slot) * stride,
        usize::from(free_slot + 1) * stride,
    ));
    drop(r);
    // The device model's real matching HCMD response ends access to the
    // submitted slot/TB0 before publishing the RX completion. Merely
    // receiving an unsolicited/wrong sequence grants no such ownership.
    if let Ok(packets) = Packets::new(boot.profile.family(), 0, packet) {
        for response in packets.flatten() {
            if response.unsolicited() || (response.group == 0 && response.command == 0x1c) {
                continue;
            }
            let slots = if boot.profile.family() == Family::Ax210 {
                128
            } else {
                32
            };
            let slot = response.sequence & (slots - 1);
            let tfd = device_read(
                domain,
                boot.command.region().address,
                usize::from(slot) * 256,
                256,
            );
            let first = u64::from_le_bytes(tfd[4..12].try_into().unwrap());
            let header = device_read(domain, first, 0, 8);
            if response.sequence == u16::from_le_bytes(header[2..4].try_into().unwrap()) {
                let mut r = domain.records.lock().unwrap();
                r.completed.insert(id(boot.command.region().address));
                r.completed.insert(id(first));
            }
        }
    }
    let payload = &boot.buffers[usize::from(vid - 1)].allocation;
    device_write(domain, payload.region().address, 0, packet, true);
    let mut descriptor = [0; 32];
    let stride = if boot.profile.family() == Family::Ax210 {
        descriptor[4..6].copy_from_slice(&vid.to_le_bytes());
        32
    } else {
        descriptor[..4].copy_from_slice(&(0xf0000000 | u32::from(vid)).to_le_bytes());
        4
    };
    device_write(
        domain,
        boot.used.region().address,
        usize::from(index) * stride,
        &descriptor[..stride],
        false,
    );
    device_write(
        domain,
        boot.status.region().address,
        0,
        &(index + 1).to_le_bytes(),
        false,
    );
}

fn ax210_profile() -> Profile {
    let mut observed = profile().observed();
    observed.device = 0x2725;
    observed.hardware_revision = 0x420;
    observed.radio_id = 0x10d000;
    Profile::select(observed).unwrap()
}
fn ax210_state() -> Arc<Mutex<ModelState>> {
    let state = Arc::new(Mutex::new(ModelState::default()));
    state
        .lock()
        .unwrap()
        .registers
        .extend([(0x28, 0x420), (0x9c, 0x10d000), (0, 0x45678900)]);
    state
}
fn ax210_bytes() -> Vec<u8> {
    let mut bytes = firmware_bytes();
    bytes[72..76].copy_from_slice(&(89u32 << 8).to_le_bytes());
    bytes.extend(52u32.to_le_bytes());
    bytes.extend(64u32.to_le_bytes());
    bytes.extend([0xa5; 64]);
    bytes
}
fn step_fixture() -> (super::super::platform::Observation, resources::Catalog) {
    use super::super::platform::{CapturedVariable, Variable};
    let mut captured = CapturedVariable::from_variable(
        Variable::Step,
        vec![1, 0xab, 0x12, 0x34, 0x56, 0x78],
        7,
        Some(6),
    )
    .unwrap();
    (
        captured.observation(),
        resources::Catalog::from_handoff(vec![captured.take_resource().unwrap()]).unwrap(),
    )
}
fn start_ax210<'a>(
    catalog: &'a resources::Catalog,
    step: StepConfiguration<'a>,
    source: &Source,
    domain: &Arc<Domain>,
    state: &Arc<Mutex<ModelState>>,
    drops: &Arc<AtomicUsize>,
) -> RomBoot<'a, Model> {
    unsafe {
        RomBoot::start_ax210(
            awake_profile(state.clone(), drops.clone(), ax210_profile()),
            super::super::identity::stage(&ax210_profile(), catalog).unwrap(),
            step,
            source,
            Some(domain.clone()),
            32,
            ProductResetPolicy::NoIwlmei,
        )
        .unwrap()
    }
}
struct RadioBios {
    drops: Arc<AtomicUsize>,
    unavailable: bool,
    absent: bool,
}
impl Drop for RadioBios {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::Relaxed);
    }
}
// SAFETY: this peripheral model executes exact namespace reads for the
// same modeled function; production service attachment remains external.
unsafe impl super::super::radio::bios::service::BiosIo for RadioBios {
    fn evaluate(
        &mut self,
        request: super::super::radio::bios::service::Request,
    ) -> Result<
        super::super::radio::bios::service::Object,
        super::super::radio::bios::service::IoError,
    > {
        use super::super::radio::bios::service::{IoError, Object, Request};
        if self.unavailable {
            return Err(IoError::Unavailable);
        }
        if self.absent {
            return Err(IoError::NotFound);
        }
        assert_eq!(request, Request::Glai);
        Ok(Object::Package(vec![
            Object::Integer(0),
            Object::Package(vec![Object::Integer(7), Object::Integer(1)]),
        ]))
    }
    fn variable(
        &mut self,
        variable: super::super::platform::Variable,
    ) -> Result<Vec<u8>, super::super::radio::bios::service::IoError> {
        use super::super::platform::Variable;
        if self.absent {
            return Err(super::super::radio::bios::service::IoError::NotFound);
        }
        Ok(match variable {
            Variable::GeneralConfiguration => {
                let mut raw = vec![4];
                for i in 0..32u32 {
                    raw.extend(if i == 0 { u32::MAX } else { i }.to_le_bytes());
                }
                raw
            }
            Variable::Wbem => vec![0, 3, 0, 0, 0],
            _ => panic!("unrequested source"),
        })
    }
}
fn lari_bytes(ax210: bool, schema: u8) -> Vec<u8> {
    let mut bytes = radio_bytes(ax210);
    let mut at = 88;
    while at < bytes.len() {
        let kind = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let len = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as usize;
        if kind == 48 {
            bytes.splice(at + 8 + len..at + 8 + len, [1, 12, schema, 0, 8, 12, 1, 0]);
            bytes[at + 4..at + 8].copy_from_slice(&((len + 8) as u32).to_le_bytes());
            break;
        }
        at += 8 + len.next_multiple_of(4);
    }
    bytes
}
fn drive_cold_prefix<'a>(
    init: UnifiedNvm<'a, Model>,
    source: &Source,
    domain: &Domain,
) -> (ColdRadio<'a, Model>, u16, u16) {
    let expected = super::super::radio::InitialPlan::prepare(
        &init.boot.firmware,
        init.boot.profile.family(),
        &init.receipt().unwrap().information,
    )
    .unwrap();
    let mut radio = init.begin_radio().unwrap_or_else(|_| panic!("actual NVM"));
    unsafe { radio.advance(source) }.unwrap();
    for (i, command) in expected.commands().iter().enumerate() {
        let mut id = command.id();
        if id.group == 0 {
            id.group = 1;
        }
        complete(
            &radio.initialized.boot,
            domain,
            5 + i as u16,
            6 + i as u16,
            &command_packet(id, 3 + i as u16, &[]),
        );
        unsafe { radio.advance(source) }.unwrap();
    }
    assert_eq!(radio.phase(), ColdRadioPhase::PlatformConfigurationRequired);
    let count = expected.commands().len() as u16;
    (radio, 3 + count, 5 + count)
}
fn exercise_lari_bios(actual: bool) {
    for ax210 in [false, true] {
        let profile = if ax210 { ax210_profile() } else { profile() };
        let bytes = if actual {
            use sha2::{Digest, Sha256};
            let root = std::env::var("STELA_IWLWIFI_IMAGES").unwrap();
            let bytes =
                std::fs::read(std::path::Path::new(&root).join(profile.family().firmware_name()))
                    .unwrap();
            assert_eq!(
                std::format!("{:x}", Sha256::digest(&bytes)),
                if ax210 {
                    "792478ef7752595525379a5068e2d47e310a2c344636b7df866c54746ced1dc0"
                } else {
                    "1866a58a1daee56b120362122d5f7548b443b53d33f2558a7e4407d58fd27dab"
                }
            );
            bytes
        } else {
            lari_bytes(ax210, if ax210 { 12 } else { 6 })
        };
        let expected_ids = if actual && !ax210 {
            vec![1]
        } else {
            vec![8, 1]
        };
        let catalog = catalog_for(&profile, profile.family().firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let state = if ax210 {
            ax210_state()
        } else {
            Arc::new(Mutex::new(ModelState::default()))
        };
        let drops = Arc::new(AtomicUsize::new(0));
        let bios_drops = Arc::new(AtomicUsize::new(0));
        let (observation, step_catalog) = step_fixture();
        let boot = if ax210 {
            start_ax210(
                &catalog,
                super::super::platform::load_step(observation, &step_catalog).unwrap(),
                &source,
                &domain,
                &state,
                &drops,
            )
        } else {
            start(&catalog, &source, &domain, &state, &drops)
        };
        let boot = command_ready(boot, &empty, &source, &domain, &state);
        let init = drive_nvm(boot, &source, &domain, &state);
        let cold = init.begin_radio().unwrap_or_else(|_| panic!("actual NVM"));
        let before = state.lock().unwrap().ops.len();
        let rejected = unsafe {
            cold.begin_lari(RadioBios {
                drops: bios_drops.clone(),
                unavailable: false,
                absent: false,
            })
        }
        .err()
        .unwrap();
        assert_eq!(state.lock().unwrap().ops.len(), before);
        assert_eq!(bios_drops.load(Ordering::Relaxed), 0);
        let (mut cold, bios) = *rejected;
        // Resume the original owner, without copying its initialization.
        let expected = super::super::radio::InitialPlan::prepare(
            &cold.initialized.boot.firmware,
            profile.family(),
            &cold.initialized_nvm().information,
        )
        .unwrap();
        unsafe { cold.advance(&source) }.unwrap();
        for (i, command) in expected.commands().iter().enumerate() {
            let mut id = command.id();
            if id.group == 0 {
                id.group = 1;
            }
            complete(
                &cold.initialized.boot,
                &domain,
                5 + i as u16,
                6 + i as u16,
                &command_packet(id, 3 + i as u16, &[]),
            );
            unsafe { cold.advance(&source) }.unwrap();
        }
        let mut lari = unsafe { cold.begin_lari(bios) }.unwrap_or_else(|_| panic!("real prefix"));
        assert_eq!(
            unsafe { lari.advance(&source) }.unwrap(),
            LariPhase::Waiting {
                command: expected_ids[0]
            }
        );
        let commands: Vec<_> = lari
            .plan()
            .unwrap()
            .commands()
            .map(|(id, b)| (id, b.to_vec()))
            .collect();
        assert_eq!(
            commands.iter().map(|(id, _)| id.opcode).collect::<Vec<_>>(),
            expected_ids
        );
        assert_eq!(
            lari.plan().unwrap().schema(),
            if ax210 {
                if actual { 8 } else { 12 }
            } else {
                6
            }
        );
        assert_eq!(lari.platform_reads().len(), 3); // actual GLAI, GeneralCfg, WBEM
        let mut copied = lari.plan().unwrap().clone();
        let copied_inputs = *copied.inputs();
        copied = super::super::radio::lari::Plan::prepare(
            &lari.radio.initialized.boot.firmware,
            0,
            copied_inputs,
        )
        .unwrap();
        assert_eq!(copied.commands().count(), commands.len()); // no owner/advancement authority
        let base = expected.commands().len() as u16;
        for (i, (id, payload)) in commands.iter().enumerate() {
            let sequence = 3 + base + i as u16;
            let boot = &lari.radio.initialized.boot;
            let descriptor = device_read(
                &domain,
                boot.command.region().address,
                usize::from(sequence) * 256,
                256,
            );
            let first = u64::from_le_bytes(descriptor[4..12].try_into().unwrap());
            let encoded =
                super::super::command::Command::encode(*id, 0, sequence, payload).unwrap();
            let mut emitted = device_read(&domain, first, 0, encoded.bytes().len().min(20));
            if encoded.bytes().len() > 20 {
                let rest = u64::from_le_bytes(descriptor[14..22].try_into().unwrap());
                emitted.extend(device_read(&domain, rest, 0, encoded.bytes().len() - 20));
            }
            assert_eq!(emitted, encoded.bytes());
            let bell = state.lock().unwrap().registers[&0x460];
            assert_eq!(
                unsafe { lari.advance(&source) }.unwrap(),
                LariPhase::Waiting { command: id.opcode }
            );
            assert_eq!(state.lock().unwrap().registers[&0x460], bell);
            complete(
                &lari.radio.initialized.boot,
                &domain,
                5 + base + i as u16,
                6 + base + i as u16,
                &command_packet(*id, sequence, &[0xa5 + i as u8]),
            );
            if i == 0 {
                let mut r = domain.records.lock().unwrap();
                r.cpu_sync_fail = Some(r.cpu_syncs + 1);
                drop(r);
                assert!(matches!(
                    unsafe { lari.advance(&source) },
                    Err(LariError::Boot(Error::CommandReclaim(_)))
                ));
                assert_eq!(lari.phase(), LariPhase::Waiting { command: id.opcode });
                assert_eq!(state.lock().unwrap().registers[&0x460], bell);
                domain.records.lock().unwrap().cpu_sync_fail = None;
            }
            assert_eq!(
                unsafe { lari.advance(&source) }.unwrap(),
                commands
                    .get(i + 1)
                    .map_or(LariPhase::RxQueueConfigurationRequired, |(id, _)| {
                        LariPhase::Waiting { command: id.opcode }
                    })
            );
        }
        assert_eq!(lari.responses().len(), commands.len());
        for (i, response) in lari.responses().iter().enumerate() {
            assert_eq!(response.raw, [0xa5 + i as u8]);
        }
        let ops = state.lock().unwrap().ops.len();
        assert_eq!(
            unsafe { lari.advance(&source) }.unwrap(),
            LariPhase::RxQueueConfigurationRequired
        );
        assert_eq!(state.lock().unwrap().ops.len(), ops);
        assert_eq!(bios_drops.load(Ordering::Relaxed), 0);
        lari.stop().unwrap();
        drop(lari);
        assert!(domain.records.lock().unwrap().live.is_empty());
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        assert_eq!(bios_drops.load(Ordering::Relaxed), 1);
    }
}
// Kept with the original boot peripheral model: these cases exercise the
// same physical-owner/DMA epoch through post-LARI command retirement.
mod ax200_board_tests;
mod ax200_country_tests;
mod ax200_mac_tests;
mod ax200_native_scan_tests;
mod ax200_scan_tests;
mod ax200_tests;

mod cold_radio;
mod command_completion;
mod command_publication;
mod firmware_inputs;
mod lari_policy;
mod nvm_admission;
mod nvm_completion;
mod pnvm_lifetimes;
mod pnvm_selection;
mod product_reset;
mod receive_recycling;
mod rom_admission;
mod rom_context;
mod rom_fault_cleanup;
mod rom_publication_faults;
mod rom_retirement;
