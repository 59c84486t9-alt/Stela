//! Bounded execution of the unchanged original Stage1 entry, never a firmware
//! or hardware-state substitute. No unknown memory/system input is answered.
#![cfg(all(feature = "std", target_os = "macos", target_arch = "x86_64"))]

use sha2::{Digest, Sha256};
use std::{cell::RefCell, collections::VecDeque, io::Write as _, rc::Rc};
use stela_compiler::{GuestState, TargetCpu, aarch64::system::registers::Encoding};
use stela_runtime::{
    hosted::host::NativeRunner,
    machine::{
        Chip, Cpu, CpuProfile, DeviceError, Devices, FaultCause, Host, InstallError, Lines,
        Machine, NativeCode, NativeExit, Regime, Stop,
        exception::Pstate,
        identification::{self, Speculation},
        mmu,
        registers::encodings::MPIDR_EL1,
    },
};

const BASE: u64 = 0x1fc050000;
const SOURCE_SHA: &str = "d6c695d26e5d816a2ecd523c0be20a15307af24c404b1603d74a970b53e75e77";
const ARENA: usize = 16 << 20;
// The fixed guest guard and native signal runner belong to one entry probe.
static EXECUTION: std::sync::Mutex<()> = std::sync::Mutex::new(());
const GUARD_BASE: u64 = 0x1fc000000;
// Reserve source SRAM and the T8112/T6000 physical-I/O interval without mapping
// their contents. Every actual access must leave native code for qualification.
const GUARD_BYTES: usize = (0x400000000 - GUARD_BASE) as usize;
struct Original {
    base: u64,
    sha: &'static str,
    chip: Chip,
    chip_id: u32,
    ram_end: u64,
    first_input: usize,
    image_env: &'static str,
    observations_env: &'static str,
    report_env: &'static str,
    name: &'static str,
    windows: &'static [(usize, usize, &'static str)],
}
const M2: Original = Original {
    base: BASE,
    sha: SOURCE_SHA,
    chip: Chip::AppleM2,
    chip_id: 0x8112,
    ram_end: 0x1fc2fadd0,
    first_input: 0x29470,
    image_env: "STELA_TEST_PMGR_LLB",
    observations_env: "STELA_TEST_PMGR_LLB_OBSERVATIONS",
    report_env: "STELA_TEST_PMGR_LLB_REPORT",
    name: "original T8112 LLB bounded cold-entry exploration",
    windows: &[
        (
            0,
            0x1bc,
            "f445367bef64acfe63a7504a87b01304dc3d99fcf20d7265797f57429168e68a",
        ),
        (
            0x380,
            0x420,
            "765e861d2c3b37b54f531a5989e6181eb7401f32790b20a8ae9b9137c376be62",
        ),
        (
            0x29470,
            0x29510,
            "f221891930541fb53913c51685cd7e5762e06b1cf7158132557e138e06dabcac",
        ),
        (
            0x23418,
            0x23520,
            "0bad24bbbeb2ae1f0582046862d4ae674016a3035dc26ff3b4f56901e0c22d85",
        ),
        (
            0x2d860,
            0x2d878,
            "e6e464ca98ae2a783ee7b647f7bc172ea881b458fbb4caf4eb87d69d5753aba1",
        ),
    ],
};
const M1_PRO: Original = Original {
    base: 0x1fc058000,
    sha: "f45549025d8cb4aa5e1cdb6107a25f90999f6b96da0b31a2f3cfb90561653ae1",
    chip: Chip::AppleM1,
    chip_id: 0x6000,
    ram_end: 0x1fc2d1dd0,
    first_input: 0x282c0,
    image_env: "STELA_TEST_PMGR_M1_LLB",
    observations_env: "STELA_TEST_PMGR_M1_LLB_OBSERVATIONS",
    report_env: "STELA_TEST_PMGR_M1_LLB_REPORT",
    name: "original T6000 J314s LLB bounded cold-entry exploration",
    windows: &[
        (
            0,
            0x1bc,
            "84da23dc0681899fc5b564a70c12e1b830ab8580ed309d9546b845efdb6e8d24",
        ),
        (
            0x380,
            0x420,
            "287f2cb6840eaf5b2fcabde3b460472186b872277ec7e8fe592d50b8cbe730e9",
        ),
        (
            0x282c0,
            0x28370,
            "915a5f295a595c78927762170b7c184634a7cfd4cf403f26598873b29fb8b38b",
        ),
    ],
};

#[derive(Debug, serde::Serialize)]
struct Access {
    physical: u64,
    bytes: u8,
    written: Option<u64>,
    observed: Option<u64>,
}

#[derive(Debug, serde::Serialize)]
struct RamWrite {
    physical: u64,
    data: Vec<u8>,
}

/// Optional observations are a bounded original trace, not a register model.
/// A row is consumed once, in order, only at its actual matching read. Writes
/// still need a real modeled owner and never become successful trace entries.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Observations {
    schema: u32,
    image_sha256: String,
    chip_id: u32,
    entry: u64,
    provenance: String,
    rows: VecDeque<Observation>,
}
#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum Observation {
    System { encoding: [u8; 5], value: u64 },
    Physical { address: u64, bytes: u8, value: u64 },
}
impl Observations {
    fn load(original: &Original) -> Option<Self> {
        let path = std::env::var_os(original.observations_env)?;
        let trace: Self = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(trace.schema, 1);
        assert_eq!(trace.image_sha256, original.sha);
        assert_eq!(trace.chip_id, original.chip_id);
        assert_eq!(trace.entry, original.base);
        assert!(!trace.provenance.trim().is_empty());
        for row in &trace.rows {
            match row {
                Observation::System { encoding, .. } => {
                    assert_eq!(encoding[0], 3);
                    assert_eq!(encoding[2], 15);
                    assert!(encoding[1] <= 7 && encoding[3] <= 15 && encoding[4] <= 7);
                }
                Observation::Physical {
                    address,
                    bytes,
                    value,
                } => {
                    assert!(matches!(bytes, 1 | 2 | 4 | 8));
                    assert!(address.is_multiple_of(u64::from(*bytes)));
                    assert!(*bytes == 8 || *value < 1 << (*bytes * 8));
                }
            }
        }
        Some(trace)
    }
    fn system(&mut self, encoding: Encoding) -> Option<u64> {
        let fields = [
            encoding.op0(),
            encoding.op1(),
            encoding.crn(),
            encoding.crm(),
            encoding.op2(),
        ];
        if let Some(Observation::System {
            encoding: expected,
            value,
        }) = self.rows.front()
            && *expected == fields
        {
            let value = *value;
            self.rows.pop_front();
            Some(value)
        } else {
            None
        }
    }
    fn physical(&mut self, address: u64, bytes: u8) -> Option<u64> {
        if let Some(Observation::Physical {
            address: expected,
            bytes: expected_bytes,
            value,
        }) = self.rows.front()
            && address == *expected
            && bytes == *expected_bytes
        {
            let value = *value;
            self.rows.pop_front();
            Some(value)
        } else {
            None
        }
    }
}

struct Ram {
    start: u64,
    bytes: Vec<u8>,
    known: Vec<bool>,
    accesses: Vec<Access>,
    system_inputs: Vec<(Encoding, Option<u64>)>,
    observations: Option<Observations>,
    replayed: Vec<Observation>,
    writes: Vec<RamWrite>,
}
impl Ram {
    fn from_original(bytes: &[u8], original: &Original) -> Self {
        let q = |offset| u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        // These are original literal addresses, not a Mach-O load command.
        // File bytes are known; the source's other RAM extents are UNKNOWN
        // until actual executed stores initialize them.
        assert_eq!(q(0x380), original.base);
        assert_eq!(q(0x3a8), GUARD_BASE);
        assert_eq!(q(0x3c0), original.ram_end);
        assert_eq!(q(0x418), 0); // source relocation context, not a fabricated pointer
        let mut ram = Self {
            start: GUARD_BASE,
            bytes: vec![0; (q(0x3c0) - GUARD_BASE) as usize],
            known: vec![false; (q(0x3c0) - GUARD_BASE) as usize],
            accesses: Vec::new(),
            system_inputs: Vec::new(),
            observations: None,
            replayed: Vec::new(),
            writes: Vec::new(),
        };
        let offset = (original.base - ram.start) as usize;
        ram.bytes[offset..offset + bytes.len()].copy_from_slice(bytes);
        ram.known[offset..offset + bytes.len()].fill(true);
        ram
    }
    fn range(&self, address: u64, len: usize) -> Option<std::ops::Range<usize>> {
        let offset = usize::try_from(address.checked_sub(self.start)?).ok()?;
        let end = offset.checked_add(len)?;
        (end <= self.bytes.len()).then_some(offset..end)
    }
    fn read(&self, address: u64, out: &mut [u8]) -> bool {
        let Some(range) = self.range(address, out.len()) else {
            return false;
        };
        if !self.known[range.clone()].iter().all(|known| *known) {
            return false;
        }
        out.copy_from_slice(&self.bytes[range]);
        true
    }
    fn write(&mut self, address: u64, data: &[u8]) -> bool {
        let Some(range) = self.range(address, data.len()) else {
            return false;
        };
        self.bytes[range.clone()].copy_from_slice(data);
        self.known[range].fill(true);
        self.writes.push(RamWrite {
            physical: address,
            data: data.to_vec(),
        });
        true
    }
}

struct Bus(Rc<RefCell<Ram>>);
impl Devices for Bus {
    fn read(&mut self, _: usize, physical: u64, bytes: u8, _: u64) -> Result<u64, DeviceError> {
        let mut value = [0; 8];
        if bytes > 8 {
            return Err(DeviceError::Refused(
                "LLB probe access wider than native scalar route".into(),
            ));
        }
        let mut ram = self.0.borrow_mut();
        let known = ram.read(physical, &mut value[..usize::from(bytes)]);
        let observed = if known {
            Some(u64::from_le_bytes(value))
        } else {
            ram.observations
                .as_mut()
                .and_then(|trace| trace.physical(physical, bytes))
                .inspect(|value| {
                    ram.replayed.push(Observation::Physical {
                        address: physical,
                        bytes,
                        value: *value,
                    });
                })
        };
        ram.accesses.push(Access {
            physical,
            bytes,
            written: None,
            observed,
        });
        observed.ok_or_else(|| {
            DeviceError::Refused(
                "original LLB physical input is unknown; no zero substitution".into(),
            )
        })
    }
    fn write(
        &mut self,
        _: usize,
        physical: u64,
        bytes: u8,
        value: u64,
        _: u64,
    ) -> Result<(), DeviceError> {
        let mut ram = self.0.borrow_mut();
        if bytes > 8 || !ram.write(physical, &value.to_le_bytes()[..usize::from(bytes)]) {
            ram.accesses.push(Access {
                physical,
                bytes,
                written: Some(value),
                observed: None,
            });
            return Err(DeviceError::Refused(
                "original LLB target has no qualified RAM/MMIO owner".into(),
            ));
        }
        ram.accesses.push(Access {
            physical,
            bytes,
            written: Some(value),
            observed: Some(value),
        });
        Ok(())
    }
    fn lines(&mut self, _: usize, _: u64) -> Lines {
        Lines::default()
    }
    fn system_register(
        &mut self,
        _: usize,
        encoding: Encoding,
        write: Option<u64>,
        _: u64,
    ) -> Option<Result<u64, &'static str>> {
        let mut ram = self.0.borrow_mut();
        ram.system_inputs.push((encoding, write));
        if write.is_none()
            && let Some(value) = ram
                .observations
                .as_mut()
                .and_then(|trace| trace.system(encoding))
        {
            ram.replayed.push(Observation::System {
                encoding: [
                    encoding.op0(),
                    encoding.op1(),
                    encoding.crn(),
                    encoding.crm(),
                    encoding.op2(),
                ],
                value,
            });
            return Some(Ok(value));
        }
        Some(Err(
            "original LLB Apple system-register input/effect is unknown",
        ))
    }
}

/// All guest data accesses fault out of native code and use the actual
/// instrumented RAM/device route. No guest RAM is mapped into the host.
struct ProbeHost {
    ram: Rc<RefCell<Ram>>,
    arena: *mut u8,
    used: usize,
    guard: *mut libc::c_void,
    runner: NativeRunner,
    regime: Option<Regime>,
}
impl ProbeHost {
    fn new(ram: Rc<RefCell<Ram>>) -> Self {
        // SAFETY: reserve without MAP_FIXED; fail if an existing mapping
        // prevents the requested unmapped guest interval. Never replace it.
        let guard = unsafe {
            libc::mmap(
                GUARD_BASE as *mut _,
                GUARD_BYTES,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        assert_ne!(guard, libc::MAP_FAILED);
        if guard as u64 != GUARD_BASE {
            // SAFETY: mmap returned this distinct owned reservation.
            unsafe {
                libc::munmap(guard, GUARD_BYTES);
            }
            panic!("guest guard is already occupied");
        }
        // SAFETY: private executable mapping owns only installed compiler code.
        let arena = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                ARENA,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        assert_ne!(arena, libc::MAP_FAILED);
        Self {
            ram,
            arena: arena.cast(),
            used: 0,
            guard,
            runner: NativeRunner::new(vec![(arena as u64, arena as u64 + ARENA as u64)]),
            regime: None,
        }
    }
}
impl Drop for ProbeHost {
    fn drop(&mut self) {
        // SAFETY: these mappings are owned here, with no native invocation live.
        unsafe {
            libc::munmap(self.arena.cast(), ARENA);
            libc::munmap(self.guard, GUARD_BYTES);
        }
    }
}
impl Host for ProbeHost {
    fn read_ram(&mut self, physical: u64, out: &mut [u8]) -> bool {
        self.ram.borrow().read(physical, out)
    }
    fn write_ram(&mut self, physical: u64, data: &[u8]) -> bool {
        self.ram.borrow_mut().write(physical, data)
    }
    fn install(&mut self, bytes: &[u8]) -> Result<NativeCode, InstallError> {
        let offset = self.used.next_multiple_of(16);
        let end = offset + bytes.len();
        if end > ARENA {
            return Err(InstallError::Full);
        }
        // SAFETY: unused owned arena bytes, outside a native invocation.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), self.arena.add(offset), bytes.len());
        }
        self.used = end;
        Ok(NativeCode(self.arena as usize + offset))
    }
    fn patch(&mut self, code: NativeCode, bytes: &[u8]) {
        let offset = code.0.checked_sub(self.arena as usize).unwrap();
        assert!(offset + bytes.len() <= self.used);
        // SAFETY: checked installed owned code, outside native invocation.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), self.arena.add(offset), bytes.len());
        }
    }
    fn discard_code(&mut self) {
        self.used = 0;
    }
    unsafe fn execute(&mut self, code: NativeCode, state: &mut GuestState) -> NativeExit {
        // SAFETY: the shared Machine installed this code with its block ABI.
        match unsafe { self.runner.run(code.0, state) } {
            Ok(exit) => NativeExit::Exit {
                next_pc: exit.next_pc,
                kind: exit.kind,
            },
            Err(fault) => {
                let cause = if fault.trap == 14 {
                    let regime = self
                        .regime
                        .as_ref()
                        .expect("Machine publishes the current regime");
                    match mmu::translate(
                        &regime.controls,
                        fault.address,
                        if fault.write {
                            mmu::Access::Write
                        } else {
                            mmu::Access::Read
                        },
                        regime.requester,
                        &mut Tables(self.ram.clone()),
                    ) {
                        mmu::Outcome::Mapped(mapped) => FaultCause::Device {
                            physical: mapped.physical,
                        },
                        mmu::Outcome::Fault(fault) => FaultCause::Guest(fault),
                        mmu::Outcome::Unsupported(reason) => FaultCause::Translation(reason),
                    }
                } else {
                    fault.check_cause().unwrap_or(FaultCause::InvalidOpcode)
                };
                NativeExit::Fault(
                    fault.native(fault.rip.wrapping_sub(code.0 as u64) as usize, cause),
                )
            }
        }
    }
    fn set_regime(&mut self, regime: &Regime) {
        self.regime = Some(*regime);
    }
    fn invalidate_translations(&mut self) {}
    fn counter(&mut self) -> u64 {
        0
    }
    fn arm_timer(&mut self, _: Option<u64>) {}
    fn wait_for_interrupt(&mut self) {
        panic!("bounded LLB probe cannot invent an external wake");
    }
}

struct Tables(Rc<RefCell<Ram>>);
impl mmu::TableMemory for Tables {
    fn read_descriptor(&mut self, physical: u64) -> Option<u64> {
        let mut bytes = [0; 8];
        self.0
            .borrow()
            .read(physical, &mut bytes)
            .then(|| u64::from_le_bytes(bytes))
    }
    fn update_descriptor(&mut self, physical: u64, old: u64, new: u64) -> Option<bool> {
        let current = self.read_descriptor(physical)?;
        if current != old {
            return Some(false);
        }
        self.0
            .borrow_mut()
            .write(physical, &new.to_le_bytes())
            .then_some(true)
    }
}

#[test]
#[ignore = "requires original J473 LLB; executes bounded original entry on x86 macOS"]
fn original_llb_entry_executes_with_an_explicit_unknown_input_and_committed_write_ledger() {
    execute_original(&M2);
}

#[test]
#[ignore = "requires original J314s LLB; executes bounded original entry on x86 macOS"]
fn original_m1_pro_llb_entry_retains_its_own_link_profile_and_unknown_input() {
    execute_original(&M1_PRO);
}

fn execute_original(original: &Original) {
    let _execution = EXECUTION.lock().unwrap();
    let bytes =
        std::fs::read(std::env::var(original.image_env).expect("original LLB path")).unwrap();
    assert_eq!(hex::encode(Sha256::digest(&bytes)), original.sha);
    for &(start, end, digest) in original.windows {
        assert_eq!(hex::encode(Sha256::digest(&bytes[start..end])), digest);
    }
    // EL2 is required by the unchanged first instruction, MSR VTTBR_EL2.
    // This is an explicitly cold-reset MODEL scenario, not proof of the
    // BootROM's entry HCR or an actual hardware handoff snapshot.
    let cpu = Cpu::of(original.chip, original.base, Pstate::reset(2));
    let ram = Rc::new(RefCell::new(Ram::from_original(&bytes, original)));
    ram.borrow_mut().observations = Observations::load(original);
    let replay = ram.borrow().observations.is_some();
    let target = TargetCpu::detect();
    let mut fixed = identification::derive(original.chip, target, true, Speculation::NONE);
    fixed.push((MPIDR_EL1, 0x80000000));
    let profile = CpuProfile {
        name: original.name,
        chip: original.chip,
        counter_frequency: 24_000_000,
        fixed,
        processors: Vec::new(),
    };
    let mut machine = Machine::new(
        cpu,
        ProbeHost::new(ram.clone()),
        Bus(ram.clone()),
        profile,
        target,
    );
    machine.set_watches(&[(GUARD_BASE, GUARD_BASE + GUARD_BYTES as u64 - 1)]);
    let mut watch = Vec::new();
    // Drain per-block so the bounded watch buffer cannot erase an earlier
    // committed prefix. There is one PE and no chaining across routed faults.
    let stopped = (1..=256)
        .find_map(|budget| {
            // The probe ends at the first operation answered degraded.
            let mut stopped = machine.run(budget);
            if let Some(first) = machine.take_unmodeled().into_iter().next() {
                stopped = Stop::Unsupported(first);
            }
            for hit in machine.take_watch_hits() {
                assert_eq!(
                    hit.dropped, 0,
                    "source trace may not silently drop accesses"
                );
                watch.push(serde_json::json!({
                    "pc": hit.pc, "physical": hit.physical, "bytes": hit.bytes,
                    "value": hit.value, "write": hit.write, "completed": hit.completed,
                }));
            }
            (stopped != Stop::Budget).then_some(stopped)
        })
        .unwrap_or(Stop::Budget);
    eprintln!("original LLB entry stop: {stopped:?}");
    eprintln!(
        "physical accesses: {}; committed RAM writes: {}",
        ram.borrow().accesses.len(),
        ram.borrow().writes.len()
    );
    eprintln!(
        "unknown Apple system inputs: {:?}",
        ram.borrow().system_inputs
    );
    if let Some(path) = std::env::var_os(original.report_env) {
        let ram = ram.borrow();
        let report = serde_json::json!({
            "schema": 1,
            "image_sha256": original.sha,
            "entry": original.base,
            "chip_id": original.chip_id,
            "initial_core": "Cpu::of cold-reset MODEL scenario; actual BootROM entry state remains unqualified",
            "ram": "Only source image bytes initially known; other source-header RAM unknown until committed stores",
            "stop": format!("{stopped:?}"),
            "pc": machine.cpu.pc,
            "blocks": machine.statistics.blocks,
            "exceptions": machine.statistics.exceptions,
            "physical_accesses": ram.accesses,
            "source_access_trace": watch,
            "committed_ram_writes": ram.writes,
            "system_accesses": ram.system_inputs.iter().map(|(encoding, value)| (format!("{encoding:?}"), value)).collect::<Vec<_>>(),
            "observation_provenance": ram.observations.as_ref().map(|trace| &trace.provenance),
            "replayed_observations": ram.replayed,
            "unconsumed_observations": ram.observations.as_ref().map(|trace| &trace.rows),
            "qualification": "Trace observations and source execution do not qualify native controller effects, retirement, physical initial values or full firmware handoff"
        });
        // Fresh immutable receipts only; do not replace earlier evidence.
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        file.write_all(&serde_json::to_vec_pretty(&report).unwrap())
            .unwrap();
        file.write_all(b"\n").unwrap();
    }
    assert!(
        matches!(stopped, Stop::Unsupported(_) | Stop::Budget),
        "probe must retain an explicit boundary"
    );
    if replay {
        return;
    }
    let Stop::Unsupported(requirement) = stopped else {
        panic!("missing original input must refuse before budget")
    };
    assert_eq!(
        (requirement.pc, requirement.el),
        (original.base + original.first_input as u64, 2)
    );
    let ram = ram.borrow();
    assert_eq!(ram.system_inputs, [(Encoding::new(3, 3, 15, 7, 0), None)]);
    assert_eq!(ram.accesses.len(), 1);
    let access = &ram.accesses[0];
    assert_eq!(
        (
            access.physical,
            access.bytes,
            access.written,
            access.observed
        ),
        (original.base + 0x380, 8, None, Some(original.base))
    );
    assert_eq!(machine.cpu.state.x[30], original.base + 0x2c);
    assert_eq!(machine.statistics.exceptions, 0);
    assert!(ram.writes.is_empty());
    assert_eq!(watch.len(), 1);
    assert_eq!(watch[0]["pc"], original.base + 0x24);
    // No PMGR/GPCE/SRAM store or controller completion occurred. A capture
    // of this cache-controller input and its progress is the next dependency;
    // taking its READY bit from desired firmware polling would fake it.
}

#[test]
fn observations_are_consumed_once_in_order_and_do_not_authorize_effects_or_zero_fill_ram() {
    let encoding = Encoding::new(3, 3, 15, 7, 0);
    let mut trace = Observations {
        schema: 1,
        image_sha256: SOURCE_SHA.into(),
        chip_id: 0x8112,
        entry: BASE,
        provenance: "explicit synthetic parser fixture, no hardware qualification".into(),
        rows: VecDeque::from([
            Observation::System {
                encoding: [3, 3, 15, 7, 0],
                value: 0x123,
            },
            Observation::Physical {
                address: 0x23b700438,
                bytes: 4,
                value: 0x456,
            },
        ]),
    };
    assert_eq!(trace.physical(0x23b700438, 4), None);
    assert_eq!(trace.system(Encoding::new(3, 3, 15, 8, 0)), None);
    assert_eq!(trace.rows.len(), 2);
    assert_eq!(trace.system(encoding), Some(0x123));
    assert_eq!(trace.system(encoding), None);
    assert_eq!(trace.physical(0x23b700438, 8), None);
    assert_eq!(trace.physical(0x23b700438, 4), Some(0x456));
    assert!(trace.rows.is_empty());
    let ram = Rc::new(RefCell::new(Ram {
        start: GUARD_BASE,
        bytes: vec![0; 16],
        known: vec![false; 16],
        accesses: Vec::new(),
        system_inputs: Vec::new(),
        observations: Some(trace),
        replayed: Vec::new(),
        writes: Vec::new(),
    }));
    let mut bus = Bus(ram.clone());
    assert!(bus.read(0, GUARD_BASE, 4, 0).is_err());
    assert!(
        bus.system_register(0, encoding, Some(0), 0)
            .unwrap()
            .is_err()
    );
    assert!(bus.write(0, 0x23b700438, 4, 0, 0).is_err());
    assert!(ram.borrow().writes.is_empty());
    // Partial initialization does not disclose unknown neighboring bytes.
    assert!(bus.write(0, GUARD_BASE, 4, 0x76543210, 0).is_ok());
    assert_eq!(bus.read(0, GUARD_BASE, 4, 0).unwrap(), 0x76543210);
    assert!(bus.read(0, GUARD_BASE, 8, 0).is_err());
    assert_eq!(ram.borrow().writes.len(), 1);
}
