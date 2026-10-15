//! Frozen Store candidate consumer of the shared qualified process fixture.
//! This adds tests to the existing runtime test binary, no raw native entry.
use super::{Fixture, ScalableLeafExit, TargetCpu};
use serde::{Deserialize, Serialize};
use std::{fs::OpenOptions, io::Write, path::Path, time::Instant};

const RAM_BYTES: usize = 8192;
const MAX_ITERATIONS: u64 = 1_000_000;
const MAX_SAMPLE_NS: u128 = 250_000_000;
const DEADLINE_BATCH: u64 = 64;
const MARKER: &str = "STELA_STORE_OBSERVATION=";

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
struct Frame {
    x: Vec<u64>,
    sp: u64,
    nzcv: u32,
    reserved: u32,
    fpcr: u32,
    fpsr: u32,
    z: Vec<Vec<u8>>,
    p: Vec<Vec<u8>>,
    ffr: Vec<u8>,
    za: Vec<u8>,
    zt0: Vec<u8>,
    tpidr2: u64,
    fpmr: u64,
}
#[derive(Deserialize)]
struct Case {
    name: String,
    words: Vec<u32>,
    guest_base: u64,
    svl_bytes: usize,
    initial: Frame,
    expected: Frame,
    ram: Vec<u8>,
    expected_ram: Vec<u8>,
    expected_exit: serde_json::Value,
    compiler_cx16: bool,
    mappings: Vec<serde_json::Value>,
    historical_policy: Option<serde_json::Value>,
    expected_req4: Option<serde_json::Value>,
    #[serde(default)]
    projection: Option<String>,
}
impl Frame {
    fn import(&self, fixture: &mut Fixture) {
        assert_eq!(self.x.len(), fixture.registers.x.len());
        fixture.registers.x.copy_from_slice(&self.x);
        fixture.registers.sp = self.sp;
        fixture.registers.nzcv = self.nzcv;
        fixture.registers.reserved = self.reserved;
        for (index, value) in self.z.iter().enumerate() {
            fixture
                .scalable
                .write_z(&mut fixture.registers, index as u8, value)
                .unwrap();
        }
        for (index, value) in self.p.iter().enumerate() {
            fixture
                .scalable
                .write_predicate(index as u8, value)
                .unwrap();
        }
        fixture.scalable.write_ffr(&self.ffr).unwrap();
        fixture.scalable.write_za(0, &self.za).unwrap();
        fixture.scalable.write_zt0(0, &self.zt0).unwrap();
        fixture.scalable.set_tpidr2_el0(self.tpidr2);
        fixture.scalable.set_fpmr(self.fpmr);
        fixture.registers.fpcr = self.fpcr;
        fixture.registers.fpsr = self.fpsr;
    }
    fn observe(fixture: &Fixture) -> Self {
        let length = fixture.scalable.vector_length().bytes();
        let mut z = vec![vec![0; length]; 32];
        for (index, bytes) in z.iter_mut().enumerate() {
            fixture
                .scalable
                .read_z(&fixture.registers, index as u8, bytes)
                .unwrap();
        }
        let mut p = vec![vec![0; length / 8]; 16];
        for (index, bytes) in p.iter_mut().enumerate() {
            fixture.scalable.read_predicate(index as u8, bytes).unwrap();
        }
        let mut ffr = vec![0; length / 8];
        let mut za = vec![0; length * length];
        let mut zt0 = vec![0; 64];
        fixture.scalable.read_ffr(&mut ffr).unwrap();
        fixture.scalable.read_za(0, &mut za).unwrap();
        fixture.scalable.read_zt0(0, &mut zt0).unwrap();
        Self {
            x: fixture.registers.x.to_vec(),
            sp: fixture.registers.sp,
            nzcv: fixture.registers.nzcv,
            reserved: fixture.registers.reserved,
            fpcr: fixture.registers.fpcr,
            fpsr: fixture.registers.fpsr,
            z,
            p,
            ffr,
            za,
            zt0,
            tpidr2: fixture.scalable.tpidr2_el0(),
            fpmr: fixture.scalable.fpmr(),
        }
    }
}
fn cases() -> Vec<Case> {
    let path = std::env::var("STELA_STORE_FIXTURES").expect("source-bound fixture path required");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}
fn make_fixture(case: &Case) -> Fixture {
    let target = if case.compiler_cx16 {
        TargetCpu::Cx16
    } else {
        TargetCpu::Baseline
    };
    let split = case.mappings.get(1).map(|entry| {
        (
            entry["offset"].as_u64().unwrap() as usize,
            entry["writable"].as_bool().unwrap(),
        )
    });
    let mut fixture = Fixture::new_program(
        &case.words,
        case.guest_base,
        case.svl_bytes,
        TargetCpu::Cx16,
        target,
        split,
    );
    case.initial.import(&mut fixture);
    assert_eq!(case.ram.len(), RAM_BYTES);
    // SAFETY: pinned fixture initialization precedes every synchronous entry.
    unsafe { fixture.storage.write_bytes(&case.ram) };
    fixture
}
fn mxcsr() -> u32 {
    let mut value = 0_u32;
    // SAFETY: valid writable u32; reads only caller floating control state.
    unsafe {
        std::arch::asm!("stmxcsr [{address}]", address = in(reg) &mut value,
                            options(nostack, preserves_flags));
    }
    value
}
fn cpu_ns() -> u64 {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: live writable timespec, read-only process CPU clock.
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut time) },
        0
    );
    u64::try_from(time.tv_sec).unwrap() * 1_000_000_000 + u64::try_from(time.tv_nsec).unwrap()
}
fn durable(value: &serde_json::Value) {
    let path = std::env::var("STELA_STORE_RAW").expect("fresh durable journal path required");
    let mut stream = OpenOptions::new()
        .create(true)
        .append(true)
        .open(Path::new(&path))
        .unwrap();
    serde_json::to_writer(&mut stream, value).unwrap();
    stream.write_all(b"\n").unwrap();
    stream.sync_all().unwrap();
}
fn artifact(fixture: &Fixture) -> serde_json::Value {
    let identity = fixture.prepared.identity();
    serde_json::json!({
        "compiler_source_sha256":identity.compiler_source_sha256,
        "source_sha256":identity.source_sha256,
        "native_sha256":identity.native_sha256,
        "native_bytes":fixture.prepared.native_bytes(),
        "source_map":fixture.prepared.source_map().iter().map(|(pc,offset)|(pc.0,*offset)).collect::<Vec<_>>(),
        "memory_requirements":format!("{:?}",identity.memory_requirements),
        "per_pc_execution_requirements":format!("{:?}",identity.execution_requirements),
        "execution_requirements_version":identity.execution_requirements_version
    })
}
fn typed_exit(exit: &Result<ScalableLeafExit, super::ScalableExecutionError>) -> serde_json::Value {
    match exit {
        Ok(ScalableLeafExit::Returned) => serde_json::json!({"kind":"completed"}),
        Ok(ScalableLeafExit::MemoryFault(fault)) => serde_json::json!({
            "kind":"fault", "status_code":fault.status as u32,
            "address":fault.address.0,"pc":fault.pc.0,"completed_bytes":fault.completed_bytes}),
        Ok(ScalableLeafExit::EntryDeclined(status)) => {
            serde_json::json!({"kind":"declined","status_code":*status as u32})
        }
        other => serde_json::json!({"kind":"error","detail":format!("{other:?}")}),
    }
}
fn validate(
    case: &Case,
    fixture: &Fixture,
    observed: &serde_json::Value,
    before_context: (usize, usize, usize),
    before_mxcsr: u32,
) {
    assert_eq!(
        Frame::observe(fixture),
        case.expected,
        "{} full frame",
        case.name
    );
    assert_eq!(
        fixture.storage.bytes(),
        case.expected_ram,
        "{} complete RAM",
        case.name
    );
    assert_eq!(
        before_context,
        (
            fixture.context.memory as usize,
            fixture.context.scalable as usize,
            fixture.context.system as usize
        )
    );
    assert_eq!(before_mxcsr, mxcsr());
    if let Some(expected) = &case.expected_req4 {
        let actual = fixture.prepared.identity().memory_requirements;
        assert_eq!(
            u64::from(actual.required_flags),
            expected["required_flags"].as_u64().unwrap()
        );
        assert_eq!(
            u64::from(actual.required_host_caps),
            expected["required_host_caps"].as_u64().unwrap()
        );
        assert_eq!(
            u64::from(actual.required_profile),
            expected["required_profile"].as_u64().unwrap()
        );
        assert_eq!(
            format!("{:?}", actual.required_sp_alignment),
            expected["required_sp_alignment"].as_str().unwrap()
        );
    }
    assert_eq!(
        fixture.prepared.identity().execution_requirements_version,
        stela_compiler::aarch64::scalable::execution::SCALABLE_EXECUTION_REQUIREMENTS_VERSION
    );
    assert_ne!(
        observed["kind"], "error",
        "{} unexpected outer/finalization error",
        case.name
    );
    for key in ["kind", "status_code", "address", "pc", "completed_bytes"] {
        if let Some(expected) = case.expected_exit.get(key)
            && !expected.is_null()
        {
            assert_eq!(&observed[key], expected, "{} {key}", case.name);
        }
    }
}
#[test]
#[ignore = "explicit frozen three-compiler Store functional activation only"]
fn qualified_store_current17() {
    let cases = cases();
    assert_eq!(cases.len(), 17);
    for case in &cases {
        let _historical_policy = &case.historical_policy;
        let mut fixture = make_fixture(case);
        let before_mxcsr = mxcsr();
        let before_context = (
            fixture.context.memory as usize,
            fixture.context.scalable as usize,
            fixture.context.system as usize,
        );
        let mut alternate = None;
        let typed;
        let raw_exit;
        match case.projection.as_deref() {
            Some("mte0_tco_constructor") => {
                use crate::system::{
                    pstate::TCO_MASK,
                    state::{El1Registers, PSTATE_EL0T, StateError, SystemState},
                };
                let result =
                    SystemState::new(PSTATE_EL0T | TCO_MASK, 0, El1Registers::new(0, 0, 0, 0, 0));
                assert!(
                    matches!(result, Err(StateError::UnsupportedPstateBits(bits)) if bits == TCO_MASK)
                );
                raw_exit = format!("{result:?}");
                typed = serde_json::json!({"kind":"constructor_refused"});
            }
            Some("suppressed_constructor") => {
                use crate::system::scalable_controls::{Error, Implementation};
                use stela_compiler::{
                    aarch64::scalable::VectorLength, context::memory::MemoryImplementationProfile,
                };
                let result = Implementation::declared_sca16(
                    &[VectorLength::from_bytes(case.svl_bytes).unwrap()],
                    MemoryImplementationProfile::StreamingSveTagSuppression,
                );
                assert!(matches!(
                    result,
                    Err(Error::UnsupportedImplementationProfile)
                ));
                raw_exit = format!("{result:?}");
                typed = serde_json::json!({"kind":"constructor_refused"});
            }
            projection => {
                if projection == Some("unspecified_sca16") {
                    fixture.sca16 = false;
                }
                if matches!(projection, Some("wrong_snapshot" | "wrong_domain")) {
                    alternate = Some(make_fixture(case));
                    let other = alternate.as_mut().unwrap();
                    if projection == Some("wrong_snapshot") {
                        fixture.ids = std::sync::Arc::clone(&other.ids);
                    } else {
                        std::mem::swap(&mut fixture.memory, &mut other.memory);
                    }
                }
                let exit = fixture.execute();
                raw_exit = format!("{exit:?}");
                if let Some(projection) = projection {
                    use super::ScalableExecutionError as Error;
                    match projection {
                        "unspecified_sca16" => assert!(matches!(exit, Err(Error::UnsupportedSourceAtomicity { actual: crate::system::scalable_controls::SourceAtomicity::Unspecified, .. }))),
                        "wrong_snapshot" => assert!(matches!(exit, Err(Error::WrongIdentificationSnapshot { .. }))),
                        "wrong_domain" => assert!(matches!(exit, Err(Error::MemoryAuthority { cause: crate::system::process_memory::ProcessMemoryError::WrongMemoryDomain, .. }))),
                        _ => panic!("unrecognized current projection"),
                    }
                    typed = serde_json::json!({"kind":"outer_refused"});
                } else {
                    typed = typed_exit(&exit);
                }
            }
        }
        let _keep_alternate_domain_live = alternate;
        durable(&serde_json::json!({"name":case.name,"exit":typed,
            "raw_exit":raw_exit,"qualified_call_attempted":!matches!(case.projection.as_deref(),Some("suppressed_constructor"|"mte0_tco_constructor")),
            "native_executed":matches!(typed["kind"].as_str(),Some("completed"|"fault")),
            "frame":Frame::observe(&fixture),
            "ram":fixture.storage.bytes(),"identity":format!("{:?}", fixture.prepared.identity()),
            "expected_req4":case.expected_req4,"artifact":artifact(&fixture),"mxcsr":mxcsr()}));
        validate(case, &fixture, &typed, before_context, before_mxcsr);
    }
}
#[test]
#[ignore = "broker-supervised source-bound qualified Store timing sample only"]
fn qualified_store_timing_sample() {
    let cases = cases();
    assert_eq!(cases.len(), 14);
    let index: usize = std::env::var("STELA_STORE_COHORT")
        .unwrap()
        .parse()
        .unwrap();
    let iterations: u64 = std::env::var("STELA_STORE_ITERATIONS")
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=MAX_ITERATIONS).contains(&iterations));
    let case = &cases[index];
    let mut fixture = make_fixture(case);
    let before_mxcsr = mxcsr();
    let before_context = (
        fixture.context.memory as usize,
        fixture.context.scalable as usize,
        fixture.context.system as usize,
    );
    // One warm correctness entry establishes full repeated-store effects.
    let warm = fixture.execute();
    let typed = typed_exit(&warm);
    durable(
        &serde_json::json!({"phase":"warm","name":case.name,"exit":typed,
        "frame":Frame::observe(&fixture),"ram":fixture.storage.bytes()}),
    );
    validate(case, &fixture, &typed, before_context, before_mxcsr);
    let policy_before = *fixture.memory.policy_mut();
    let system_before = fixture.system.clone();
    let mut completed = 0_u64;
    let mut failure = None;
    // Construction and allocation are outside the sample. The returned owner
    // borrows the actual Snapshot and disjoint fixture fields for this whole
    // scope; each call still performs the actual source/state qualification.
    let (wall_ns, process_cpu_ns) = {
        let mut entry = super::retained::RetainedEntry::new(&mut fixture);
        let cpu_start = cpu_ns();
        let start = Instant::now();
        for _ in 0..iterations {
            let exit = entry.execute();
            if !matches!(exit, Ok(ScalableLeafExit::Returned)) {
                failure = Some(format!("{exit:?}"));
                break;
            }
            completed += 1;
            if completed.is_multiple_of(DEADLINE_BATCH)
                && start.elapsed().as_nanos() > MAX_SAMPLE_NS
            {
                failure = Some("cooperative250ms deadline exceeded".to_owned());
                break;
            }
        }
        (start.elapsed().as_nanos(), cpu_ns() - cpu_start)
    };
    assert_eq!(*fixture.memory.policy_mut(), policy_before);
    assert_eq!(fixture.system, system_before);
    let observation = serde_json::json!({"phase":"sample","name":case.name,"index":index,
        "entry":"retained-owner-per-call-qualification","owner_constructions":1,
        "requested_iterations":iterations,"completed_iterations":completed,
        "wall_ns":wall_ns,"process_cpu_ns":process_cpu_ns,"failure":failure,
        "frame":Frame::observe(&fixture),"ram":fixture.storage.bytes(),
        "identity":format!("{:?}",fixture.prepared.identity()),"mxcsr":mxcsr(),
        "placements":{"registers":(&fixture.registers as *const _) as usize,
            "context":(&fixture.context as *const _) as usize,"scalable":(&fixture.scalable as *const _) as usize}});
    durable(&observation);
    assert!(failure.is_none());
    assert_eq!(completed, iterations);
    assert!(wall_ns <= MAX_SAMPLE_NS);
    validate(
        case,
        &fixture,
        &serde_json::json!({"kind":"completed"}),
        before_context,
        before_mxcsr,
    );
    println!(
        "{MARKER}{}",
        serde_json::json!({"name":case.name,"index":index,
        "entry":"retained-owner-per-call-qualification","owner_constructions":1,
        "requested_iterations":iterations,"completed_iterations":completed,
        "wall_ns":wall_ns,"process_cpu_ns":process_cpu_ns,
        "compiler_source_sha256":fixture.prepared.identity().compiler_source_sha256,
        "source_sha256":fixture.prepared.identity().source_sha256,
        "native_sha256":fixture.prepared.identity().native_sha256,
        "native_bytes":fixture.prepared.native_bytes(),
        "source_map":fixture.prepared.source_map().iter().map(|(pc,offset)|(pc.0,*offset)).collect::<Vec<_>>() })
    );
}

#[test]
#[ignore = "source-bound success cohorts through the same qualified fixture"]
fn qualified_store_success14() {
    let cases = cases();
    assert_eq!(cases.len(), 14);
    for (index, case) in cases.iter().enumerate() {
        let mut fixture = make_fixture(case);
        let before_mxcsr = mxcsr();
        let pointers = (
            fixture.context.memory as usize,
            fixture.context.scalable as usize,
            fixture.context.system as usize,
        );
        let exit = fixture.execute();
        let typed = typed_exit(&exit);
        durable(
            &serde_json::json!({"name":case.name,"index":index,"exit":typed,"artifact":artifact(&fixture),
            "raw_exit":format!("{exit:?}"),"frame":Frame::observe(&fixture),
            "ram":fixture.storage.bytes(),"identity":format!("{:?}",fixture.prepared.identity())}),
        );
        validate(case, &fixture, &typed, pointers, before_mxcsr);
    }
}
