//! Native ordinary-memory sequences preserve cached inputs over every split.
#![cfg(all(target_arch = "x86_64", target_os = "macos"))]
use anyhow::Result;
use std::sync::Arc;
use stela_compiler::{GuestState, TargetCpu};
use stela_runtime::{
    hosted::{hardware, host::ProcessHost, memory, pe, tables::Tables},
    machine::{Machine, NoDevices, Stop, system::Register},
};

const HOST_PAGE: u64 = 4096;
const MAPPING_BYTES: u64 = 4 * HOST_PAGE;
const PREFIX: u32 = 0x9100_04a5; // add x5,x5,#1
const SUFFIX: u32 = 0x9100_04c6; // add x6,x6,#1
const VECTOR: [u64; 2] = [0xfedc_ba98_7654_3210, 0x0123_4567_89ab_cdef];

struct Mapping(u64);
impl Mapping {
    fn new() -> Result<Self> {
        Ok(Self(memory::allocate(
            0,
            MAPPING_BYTES,
            true,
            memory::Protection::READ_WRITE,
        )?))
    }
}
impl Drop for Mapping {
    fn drop(&mut self) {
        memory::deallocate(self.0, MAPPING_BYTES).unwrap();
    }
}

fn machine(
    code: &Mapping,
    words: &[u32],
    target: TargetCpu,
) -> Result<Machine<ProcessHost, NoDevices>> {
    assert!(memory::write(
        code.0,
        &words
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>()
    ));
    let tables = Arc::new(Tables::new()?);
    let hardware = hardware::Hardware::of_model(hardware::DEFAULT_MODEL, 8 << 30)?;
    let cpu = pe::user_thread(
        hardware.chip,
        code.0,
        &tables,
        &pe::Keys::random()?,
        pe::UserJop::Disabled,
    );
    let mut machine = Machine::new(
        cpu,
        ProcessHost::new(tables)?,
        NoDevices,
        pe::profile(&hardware, target)?,
        target,
    );
    let mut points = pe::vectors().to_vec();
    points.push(code.0 + words.len() as u64 * 4);
    machine.set_breakpoints(&points);
    Ok(machine)
}

/// First transfer and a later transfer that reuses the same input. Pairs
/// exercise both XMM sources; scalar cases control the byte-prefix path.
fn cases() -> Vec<(&'static str, Vec<u32>, Vec<u8>, u64)> {
    let vector = VECTOR
        .into_iter()
        .flat_map(u64::to_le_bytes)
        .collect::<Vec<_>>();
    let mut cases = vec![];
    for (name, store, bytes) in [
        ("str b", 0x3900_0001, 1),
        ("str h", 0x7900_0001, 2),
        ("str w", 0xb900_0001, 4),
        ("str x", 0xf900_0001, 8),
        ("str s", 0xbd00_0000, 4),
        ("str d", 0xfd00_0000, 8),
        ("str q", 0x3d80_0000, 16),
    ] {
        // The second store uses X2, so both addresses can be independently
        // placed across or away from a boundary in the same native block.
        cases.push((
            name,
            vec![store, store | (2 << 5)],
            vector[..bytes].to_vec(),
            0,
        ));
    }
    for (name, store, bytes, writeback) in [
        ("stp w", 0x2900_0801, 8, 0),           // stp w1,w2,[x0]
        ("stp x", 0xa900_0801, 16, 0),          // stp x1,x2,[x0]
        ("stp s", 0x2d00_0400, 8, 0),           // stp s0,s1,[x0]
        ("stp d", 0x6d00_0400, 16, 0),          // stp d0,d1,[x0]
        ("stp q", 0xad00_0400, 32, 0),          // stp q0,q1,[x0]
        ("stp q repeated", 0xad00_0000, 32, 0), // stp q0,q0,[x0]
        ("stnp q", 0xac00_0400, 32, 0),         // stnp q0,q1,[x0]
        ("stp q post", 0xac81_0400, 32, 32),    // stp q0,q1,[x0],#32
    ] {
        // The later Q0 store must still use the complete architectural V0.
        cases.push((
            name,
            vec![store, 0x3d80_0060],
            match name {
                "stp w" | "stp s" => [VECTOR[0] as u32, VECTOR[1] as u32]
                    .into_iter()
                    .flat_map(u32::to_le_bytes)
                    .collect(),
                "stp q repeated" => vector.iter().copied().cycle().take(bytes).collect(),
                _ => VECTOR
                    .into_iter()
                    .chain(VECTOR.into_iter().rev())
                    .flat_map(u64::to_le_bytes)
                    .take(bytes)
                    .collect(),
            },
            writeback,
        ));
    }
    cases
}

fn initial_state(address: u64, later: u64, name: &str) -> GuestState {
    let mut state = GuestState {
        x: std::array::from_fn(|index| 0x1234_5678_9abc_def0_u64.rotate_left(index as u32)),
        v: std::array::from_fn(|index| [index as u64 ^ VECTOR[0], index as u64 ^ VECTOR[1]]),
        nzcv: 0xa000_0000,
        fpcr: 0x0400_0000,
        fpsr: 0x0800_0000,
        ..GuestState::default()
    };
    state.x[0] = address;
    state.x[1] = VECTOR[0];
    state.x[2] = if matches!(name, "stp w" | "stp x") {
        VECTOR[1]
    } else {
        later
    };
    state.x[3] = later;
    state.v[0] = VECTOR;
    state.v[1] = [VECTOR[1], VECTOR[0]];
    state
}

fn assert_memory(data: &Mapping, writes: &[(u64, &[u8])], context: &str) {
    let mut expected = vec![0xa5; MAPPING_BYTES as usize];
    for &(address, bytes) in writes {
        let start = (address - data.0) as usize;
        expected[start..start + bytes.len()].copy_from_slice(bytes);
    }
    assert_eq!(
        memory::read(data.0, MAPPING_BYTES as usize).unwrap(),
        expected,
        "{context}"
    );
}

#[test]
fn every_store_split_preserves_sources_and_later_in_block_effects() -> Result<()> {
    let data = Mapping::new()?;
    let code = Mapping::new()?;
    for target in [TargetCpu::Baseline, TargetCpu::detect()] {
        for (name, stores, first, writeback) in cases() {
            let words = [vec![PREFIX], stores, vec![SUFFIX]].concat();
            let mut machine = machine(&code, &words, target)?;
            let mut compiled = None;
            for split in 0..first.len() {
                // Split 0 is aligned; every other value is the accessible
                // prefix before a 4 KiB boundary, with both pages writable.
                let address = data.0 + HOST_PAGE - split as u64;
                assert!(memory::write(data.0, &vec![0xa5; MAPPING_BYTES as usize]));
                let initial = initial_state(address, data.0 + 2 * HOST_PAGE + 64, name);
                machine.cpu.state = initial.clone();
                machine.cpu.pc = code.0;
                let retired = machine.cpu.retired;
                assert_eq!(
                    machine.run(machine.statistics.blocks + 64),
                    Stop::Breakpoint(code.0 + words.len() as u64 * 4),
                    "{name} split {split}"
                );
                let mut expected = initial;
                expected.x[0] += writeback;
                expected.x[5] += 1;
                expected.x[6] += 1;
                assert_eq!(machine.cpu.state, expected, "{name} split {split}");
                assert_eq!(
                    machine.cpu.retired - retired,
                    words.len() as u64,
                    "{name} split {split}"
                );
                assert_eq!(
                    memory::read(address, first.len()).unwrap(),
                    first,
                    "first {name} split {split}"
                );
                let later = if name.starts_with("stp") || name.starts_with("stnp") {
                    expected.x[3]
                } else {
                    expected.x[2]
                };
                let output = if name.starts_with("stp") || name.starts_with("stnp") {
                    VECTOR
                        .into_iter()
                        .flat_map(u64::to_le_bytes)
                        .collect::<Vec<_>>()
                } else {
                    first.clone()
                };
                assert_eq!(
                    memory::read(later, output.len()).unwrap(),
                    output,
                    "later {name} split {split}"
                );
                assert_memory(&data, &[(address, &first), (later, &output)], name);
                let first_compiled = *compiled.get_or_insert(machine.statistics.compiled);
                assert_eq!(
                    machine.statistics.compiled, first_compiled,
                    "cached {name} split {split}"
                );
            }
        }
    }
    Ok(())
}

#[test]
fn fault_prefix_and_repaired_continuation_keep_exact_pc_and_writeback() -> Result<()> {
    let data = Mapping::new()?;
    let code = Mapping::new()?;
    for target in [TargetCpu::Baseline, TargetCpu::detect()] {
        for (name, stores, first, writeback) in cases() {
            let words = [vec![PREFIX], stores, vec![SUFFIX]].concat();
            let mut machine = machine(&code, &words, target)?;
            let mut compiled = None;
            for split in 1..first.len() {
                let address = data.0 + HOST_PAGE - split as u64;
                assert!(memory::write(data.0, &vec![0xa5; MAPPING_BYTES as usize]));
                let initial = initial_state(address, data.0 + 2 * HOST_PAGE + 64, name);
                machine.cpu.state = initial.clone();
                machine.cpu.pc = code.0;
                let retired = machine.cpu.retired;
                memory::protect(data.0 + HOST_PAGE, HOST_PAGE, memory::Protection::NONE)?;
                let stopped = machine.run(machine.statistics.blocks + 64);
                // Restore permissions before any assertion can unwind and
                // before observing the page's exact untouched suffix.
                memory::protect(
                    data.0 + HOST_PAGE,
                    HOST_PAGE,
                    memory::Protection::READ_WRITE,
                )?;
                assert_eq!(
                    stopped,
                    Stop::Breakpoint(pe::LOWER_SYNCHRONOUS),
                    "{name} split {split}"
                );
                assert_eq!(
                    machine.cpu.read(Register::ELR_EL1),
                    code.0 + 4,
                    "{name} split {split}"
                );
                assert_eq!(
                    machine.cpu.read(Register::FAR_EL1),
                    data.0 + HOST_PAGE,
                    "{name} split {split}"
                );
                let mut prefix = initial.clone();
                prefix.x[5] += 1;
                assert_eq!(
                    machine.cpu.state, prefix,
                    "fault state {name} split {split}"
                );
                assert_eq!(
                    machine.cpu.retired - retired,
                    1,
                    "fault retirement {name} split {split}"
                );
                let mut partial = vec![0xa5; first.len()];
                partial[..split].copy_from_slice(&first[..split]);
                assert_eq!(
                    memory::read(address, first.len()).unwrap(),
                    partial,
                    "fault prefix {name} split {split}"
                );
                assert_memory(&data, &[(address, &first[..split])], name);
                machine.return_from_exception();
                assert_eq!(machine.cpu.pc, code.0 + 4);
                assert_eq!(
                    machine.run(machine.statistics.blocks + 64),
                    Stop::Breakpoint(code.0 + words.len() as u64 * 4),
                    "resume {name} split {split}"
                );
                let mut expected = initial;
                expected.x[0] += writeback;
                expected.x[5] += 1;
                expected.x[6] += 1;
                assert_eq!(
                    machine.cpu.state, expected,
                    "resumed state {name} split {split}"
                );
                assert_eq!(
                    machine.cpu.retired - retired,
                    words.len() as u64,
                    "resumed retirement {name} split {split}"
                );
                assert_eq!(
                    memory::read(address, first.len()).unwrap(),
                    first,
                    "resumed {name} split {split}"
                );
                let later = if name.starts_with("stp") || name.starts_with("stnp") {
                    expected.x[3]
                } else {
                    expected.x[2]
                };
                let output = if name.starts_with("stp") || name.starts_with("stnp") {
                    VECTOR
                        .into_iter()
                        .flat_map(u64::to_le_bytes)
                        .collect::<Vec<_>>()
                } else {
                    first.clone()
                };
                assert_eq!(
                    memory::read(later, output.len()).unwrap(),
                    output,
                    "resumed later {name} split {split}"
                );
                assert_memory(&data, &[(address, &first), (later, &output)], name);
                let first_compiled = *compiled.get_or_insert(machine.statistics.compiled);
                assert_eq!(
                    machine.statistics.compiled, first_compiled,
                    "cached {name} split {split}"
                );
            }
        }
    }
    Ok(())
}
