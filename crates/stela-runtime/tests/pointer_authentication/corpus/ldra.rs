//! Original LDRA frames through the actual address-space-owned reader.
use super::*;
use std::{
    alloc::{Layout, alloc_zeroed, dealloc},
    ptr::NonNull,
    sync::Arc,
};
use stela_compiler::context::memory::MemoryStatus;
use stela_runtime::memory::{
    backing::{AccessKind, AccessPermissions, MemoryBacking, MemoryView},
    domain::{MappingAttributes, MemoryDomain, MemorySystem, MemoryThread},
    policy::{LowerAddressProfile, MemoryControls, TagCheckFaultMode},
};

const RAM_ALIGNMENT: usize = 16;
const SCTLR_ALIGNMENT: u64 = 1 << 1;
const SCTLR_SP_ALIGNMENT_EL0: u64 = 1 << 4;
const SCTLR_DATA_AUTHENTICATION: u64 = 1 << 27;
const SCTLR_DATA_AUTHENTICATION_B: u64 = 1 << 13;
const ADDRESS_BITS: u8 = 47;

struct Storage {
    pointer: NonNull<u8>,
    layout: Layout,
}
// SAFETY: only the raw lifetime owner is shared, without byte references.
unsafe impl Send for Storage {}
// SAFETY: all native access/publication uses the same physical owner.
unsafe impl Sync for Storage {}
impl Drop for Storage {
    fn drop(&mut self) {
        // SAFETY: the original raw allocation/layout remain owned until now.
        unsafe { dealloc(self.pointer.as_ptr(), self.layout) };
    }
}

fn memory(base: u64, initial: &[u8]) -> Result<(Arc<MemoryBacking>, MemoryThread<MemoryControls>)> {
    let system = MemorySystem::new(RAM_ALIGNMENT as u64, 4).unwrap();
    let layout = Layout::from_size_align(initial.len(), RAM_ALIGNMENT)?;
    // SAFETY: valid nonempty layout retained by Storage until backing destruction.
    let pointer = NonNull::new(unsafe { alloc_zeroed(layout) }).context("RAM allocation")?;
    let owner = Arc::new(Storage { pointer, layout });
    let rights = AccessPermissions {
        readable: true,
        writable: true,
        executable: false,
    };
    // SAFETY: coherent, stable, raw owned Normal RAM, without Rust byte references.
    let backing = unsafe { MemoryBacking::new(pointer, initial.len(), rights, owner) }.unwrap();
    // SAFETY: private immutable source and distinct live writable RAM, before execution.
    unsafe { system.publish(&backing, 0, initial) }.unwrap();
    let view = MemoryView::new(
        Arc::clone(&backing),
        base,
        0,
        initial.len(),
        AccessPermissions {
            writable: false,
            ..rights
        },
    )
    .unwrap();
    let domain = MemoryDomain::new_for_address_space(
        ADDRESS_SPACE,
        system,
        vec![(
            view,
            MappingAttributes {
                tagged: false,
                shareable: true,
            },
        )],
        TargetCpu::detect(),
    )
    .unwrap();
    // Original fixed profile is EL0, VA47/dataTBI1, MTE allocation checks off.
    let controls = MemoryControls::new(
        LowerAddressProfile::new(ADDRESS_BITS, true).unwrap(),
        false,
        false,
        false,
        TagCheckFaultMode::Ignore,
        false,
    );
    Ok((backing, domain.thread(controls)))
}

fn ram_snapshot(backing: &MemoryBacking) -> Result<Vec<u8>> {
    let pointer = backing
        .host_pointer(0, backing.bytes(), AccessKind::Read)
        .unwrap();
    let mut bytes = vec![0; backing.bytes()];
    // SAFETY: this serialized fixture owns all RAM writers, translated subjects
    // only read, and the observation copies into disjoint private storage.
    unsafe { std::ptr::copy_nonoverlapping(pointer.as_ptr(), bytes.as_mut_ptr(), bytes.len()) };
    Ok(bytes)
}

struct Inputs<'a> {
    context: &'a pauth::Context,
    controls: pauth::memory::Controls,
    cases: &'a [Value],
    validation: &'a [Value],
    inputs: &'a [u8],
    expected: &'a [u8],
    ram: &'a [u8],
}

fn execute_ldra(
    runtime: &mut BlockRuntime,
    reader: &mut MemoryThread<MemoryControls>,
    backing: &MemoryBacking,
    corpus: &Inputs<'_>,
    output: &Path,
    phase: &str,
) -> Result<Value> {
    let stride = INPUT_HEADER_BYTES + size_of::<GuestState>() + INPUT_TRAILER_BYTES;
    ensure!(
        corpus.inputs.len() == corpus.cases.len() * stride,
        "input record count"
    );
    let mut native_states = fs::File::create(output.join(format!("{phase}-states.bin")))?;
    let mut rows = Vec::with_capacity(corpus.cases.len());
    let mut direct = 0;
    let mut policy = 0;
    let mut compiled = 0;
    let mut disk = 0;
    let mut memory_hits = 0;
    for (index, case) in corpus.cases.iter().enumerate() {
        let function = case["function_index"].as_u64().context("case function")? as usize;
        ensure!(
            word(corpus.inputs, index * stride) as usize == function,
            "input function binding"
        );
        let start = index * stride + INPUT_HEADER_BYTES;
        let before = state(&corpus.inputs[start..start + size_of::<GuestState>()]);
        ensure!(
            sha256(state_bytes(&before))
                == case["initial_state_sha256"]
                    .as_str()
                    .context("input hash")?,
            "raw input identity"
        );
        let initial_sp = before.sp;
        let pc = entry(function);
        let mut thread = ThreadState {
            registers: before,
            pc,
        };
        // SAFETY: immutable LDRA-only blocks return at the helper boundary; the
        // actual same-address-space reader owns translation, rights and raw RAM.
        let result = unsafe {
            runtime.run_with_pauth_memory(
                &mut thread,
                Some(GuestAddress(pc.0 + INSTRUCTION_BYTES as u64)),
                BLOCK_BUDGET,
                corpus.context,
                reader,
                corpus.controls,
            )?
        };
        let fault = &case["expected_fault"];
        if fault.is_null() {
            ensure!(
                result.reason == StopReason::StopAddress,
                "expected successful LDRA at {phase}/{index}: {:?}",
                result.reason
            );
            ensure!(
                thread.pc == GuestAddress(pc.0 + INSTRUCTION_BYTES as u64),
                "successful continuation"
            );
        } else {
            ensure!(
                thread.pc == pc && result.pointer_authentication_events.is_empty(),
                "fault committed continuation/event"
            );
            match fault["kind"].as_str().context("fault kind")? {
                "pac_failure" => ensure!(
                    matches!(result.reason, StopReason::PointerAuthenticationFailure { code, .. } if u64::from(code) == fault["iss"].as_u64().unwrap()),
                    "wrong authentication failure {phase}/{index}: {:?}",
                    result.reason
                ),
                "sp_alignment" => ensure!(
                    matches!(result.reason, StopReason::PointerAuthenticationStackAlignment { stack_pointer, .. } if stack_pointer == initial_sp),
                    "wrong SP fault {phase}/{index}: {:?}",
                    result.reason
                ),
                "constrained_unpredictable" => ensure!(
                    matches!(
                        result.reason,
                        StopReason::PointerAuthenticationLoadUndefined { .. }
                    ),
                    "wrong overlap policy"
                ),
                "data_abort" => match &result.reason {
                    StopReason::PointerAuthenticationMemoryFault { fault: actual, .. } => {
                        ensure!(
                            actual.status == MemoryStatus::Translation && actual.pc == pc.0,
                            "wrong memory fault metadata"
                        );
                        let range = fault["far_range"].as_array().context("FAR range")?;
                        ensure!(
                            actual.address >= range[0].as_u64().unwrap()
                                && actual.address <= range[1].as_u64().unwrap(),
                            "wrong detailed raw fault address {phase}/{index}: {:?}",
                            actual
                        );
                    }
                    _ => anyhow::bail!("wrong read fault {phase}/{index}: {:?}", result.reason),
                },
                other => anyhow::bail!("unreviewed source fault: {other}"),
            }
        }
        let expected = &corpus.expected
            [index * size_of::<GuestState>()..(index + 1) * size_of::<GuestState>()];
        ensure!(
            state_bytes(&thread.registers) == expected,
            "full State mismatch {phase}/{index}"
        );
        let actual_ram = ram_snapshot(backing)?;
        ensure!(actual_ram == corpus.ram, "RAM changed {phase}/{index}");
        let classification = corpus.validation[index]["classification"]
            .as_str()
            .context("original classification")?;
        if classification == "direct_original" {
            ensure!(
                sha256(expected) == corpus.validation[index]["state_sha256"].as_str().unwrap(),
                "direct original State binding"
            );
            ensure!(
                sha256(&actual_ram) == corpus.validation[index]["ram_sha256"].as_str().unwrap(),
                "direct original RAM binding"
            );
            direct += 1;
        } else if matches!(
            classification,
            "constrained_unpredictable_original_choice" | "qemu_sp_alignment_check_omission"
        ) {
            policy += 1;
        } else {
            anyhow::bail!("unrecognized original classification: {classification}");
        }
        native_states.write_all(state_bytes(&thread.registers))?;
        compiled += result.compiled_blocks;
        disk += result.disk_cache_hits;
        memory_hits += result.memory_cache_hits;
        rows.push(json!({"case":index,"function":function,"pc":thread.pc,"classification":classification,"state_sha256":sha256(state_bytes(&thread.registers)),"ram_sha256":sha256(&actual_ram),"outcome":result}));
    }
    native_states.flush()?;
    fs::write(
        output.join(format!("{phase}-outcomes.json")),
        serde_json::to_vec_pretty(&rows)?,
    )?;
    let report = json!({"phase":phase,"cases":corpus.cases.len(),"direct_original_full_state_ram":direct,"policy_only_full_state_ram":policy,"compiled_blocks":compiled,"disk_cache_hits":disk,"memory_cache_hits":memory_hits,"native_states_sha256":sha256(&fs::read(output.join(format!("{phase}-states.bin")))?)});
    println!("{}", serde_json::to_string(&report)?);
    Ok(report)
}

fn verify_ldra(corpus: &Path, output: &Path) -> Result<Value> {
    ensure!(size_of::<GuestState>() == ORIGINAL_STATE_BYTES, "guest ABI");
    ensure!(!output.exists(), "fresh output required");
    fs::create_dir_all(output)?;
    let profile: Value = serde_json::from_slice(&fs::read(corpus.join("profile.json"))?)?;
    let sctlr = profile["sctlr"].as_u64().context("SCTLR")?;
    ensure!(
        sctlr & SCTLR_ALIGNMENT == 0
            && sctlr & SCTLR_DATA_AUTHENTICATION != 0
            && sctlr & SCTLR_DATA_AUTHENTICATION_B != 0,
        "this production profile requires alignment enforcement off and data authentication enabled"
    );
    let cases: Vec<Value> = serde_json::from_slice(&fs::read(corpus.join("cases.json"))?)?;
    let functions: Vec<Value> = serde_json::from_slice(&fs::read(corpus.join("functions.json"))?)?;
    let words: Vec<u32> = functions
        .iter()
        .map(|function| function["operations"][0]["word"].as_u64().unwrap() as u32)
        .collect();
    ensure!(
        words.iter().all(|word| matches!(
            stela_compiler::block::pauth_memory::decode(*word),
            Some(stela_compiler::block::pauth_memory::Instruction::Load(_))
        )),
        "LDRA-only corpus"
    );
    let validation: Value =
        serde_json::from_slice(&fs::read(corpus.join("validation-receipt.json"))?)?;
    ensure!(
        validation["passed"] == true,
        "original validation must pass"
    );
    let keys = &profile["keys"];
    let context = pauth::Context::new_with_version(
        ADDRESS_SPACE,
        pauth::Keys::from_words(
            [0, 0],
            [0, 0],
            [
                keys["APDAKeyLo_EL1"].as_u64().unwrap(),
                keys["APDAKeyHi_EL1"].as_u64().unwrap(),
            ],
            [
                keys["APDBKeyLo_EL1"].as_u64().unwrap(),
                keys["APDBKeyHi_EL1"].as_u64().unwrap(),
            ],
        ),
        pauth::Version::FaultingCombined,
    );
    let plan: Value = serde_json::from_slice(&fs::read(corpus.join("memory-plan.json"))?)?;
    let ram = fs::read(corpus.join("memory.bin"))?;
    let (backing, mut reader) = memory(plan["ram_address"].as_u64().unwrap(), &ram)?;
    let inputs = fs::read(corpus.join("inputs.bin"))?;
    let expected = fs::read(corpus.join("expected-states.bin"))?;
    ensure!(
        expected.len() == cases.len() * size_of::<GuestState>(),
        "expected State count"
    );
    ensure!(
        validation["cases"]
            .as_array()
            .context("original cases")?
            .len()
            == cases.len(),
        "original case count"
    );
    ensure!(
        ram.len() as u64 == plan["ram_bytes"].as_u64().unwrap(),
        "RAM extent"
    );
    ensure!(
        sha256(&ram) == plan["initial_ram_sha256"].as_str().unwrap(),
        "RAM input identity"
    );
    let corpus = Inputs {
        context: &context,
        controls: pauth::memory::Controls {
            check_sp_alignment: sctlr & SCTLR_SP_ALIGNMENT_EL0 != 0,
            privileged: false,
        },
        cases: &cases,
        validation: validation["cases"].as_array().context("original cases")?,
        inputs: &inputs,
        expected: &expected,
        ram: &ram,
    };
    let cache = output.join("cache");
    let mut cold = runtime(&cache, &words)?;
    let mut phases = vec![execute_ldra(
        &mut cold,
        &mut reader,
        &backing,
        &corpus,
        output,
        "cold",
    )?];
    phases.push(execute_ldra(
        &mut cold,
        &mut reader,
        &backing,
        &corpus,
        output,
        "hot",
    )?);
    drop(cold);
    let mut disk = runtime(&cache, &words)?;
    phases.push(execute_ldra(
        &mut disk,
        &mut reader,
        &backing,
        &corpus,
        output,
        "disk",
    )?);
    let mut aot = runtime(&output.join("aot-cache"), &words)?;
    for index in 0..words.len() {
        aot.prepare(entry(index))?;
    }
    phases.push(execute_ldra(
        &mut aot,
        &mut reader,
        &backing,
        &corpus,
        output,
        "aot",
    )?);
    let emission = inspect(&cache, &words, output)?;
    let report = json!({"kind":"ldra-integrated-actual-owned-memory-full-state-original","passed":true,"compiler_sha256":sha256(stela_compiler::SOURCE_FINGERPRINT_MATERIAL.as_bytes()),"context_profile":context.profile_id(),"memory_target":TargetCpu::detect().id(),"controls":{"sctlr":sctlr,"privileged":false},"phases":phases,"emission":emission,"limits":["Original SP-check omissions and constrained-overlap choices remain policy-only, excluded from direct equality.","General alignment enforcement enabled and data-authentication disabled remain outside this declared production Context/profile.","Detailed checked data faults are runtime boundaries; architectural ESR/exception delivery remains outside this proof."]});
    fs::write(
        output.join("report.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    Ok(report)
}

#[test]
#[ignore = "requires independently captured LDRA frames and a fresh output directory"]
fn authenticated_load_original_corpus() -> Result<()> {
    let corpus = PathBuf::from(
        std::env::var_os("STELA_PAUTH_ORIGINALS").context("STELA_PAUTH_ORIGINALS required")?,
    );
    let output = PathBuf::from(
        std::env::var_os("STELA_PAUTH_NATIVE_OUTPUT")
            .context("STELA_PAUTH_NATIVE_OUTPUT required")?,
    );
    let report = verify_ldra(&corpus, &output)?;
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}
