//! The actual shared-system compiler ABI inside a fixed EL0 oracle fixture.
//! This deliberately grants no production native-system CPU authority.
use super::*;
use stela_compiler::{
    block::{BlockExit, CheckedMemoryProfile, CompilationPlan},
    context::memory::{FaultAccess, MemoryStatus},
};
use stela_runtime::memory::domain::MemoryFault;

pub struct CheckedSystemRegion {
    compiled: stela_compiler::block::CompiledBlock,
    requirements: MemoryRequirements,
    executable: Executable,
}

impl CheckedSystemRegion {
    pub(super) fn artifact(&self, words: &[u32]) -> Result<serde_json::Value> {
        let source: Vec<_> = words
            .iter()
            .chain(&[RET])
            .flat_map(|w| w.to_le_bytes())
            .collect();
        let baseline = CompilationPlan::new(
            &source,
            GuestAddress(CODE_PAGE),
            BlockProfile::CheckedMemory(CheckedMemoryProfile::SpAlignmentEnabled),
            target(),
        )?
        .compile()?;
        Ok(serde_json::json!({
            "kind": "checked-system-region-artifact",
            "compiler_source_sha256": stela_compiler::SOURCE_SHA256,
            "source_sha256": stela_runtime::sha256(&source), "source": source,
            "target": target().id(), "entry": CODE_PAGE,
            "abi": BlockProfile::SystemModeSharedV1(CheckedMemoryProfile::SpAlignmentEnabled).abi(),
            "requirements": self.requirements,
            "native_sha256": stela_runtime::sha256(&self.compiled.native.x86_64_code),
            "native": self.compiled.native.x86_64_code, "source_map": self.compiled.native.source_map,
            "baseline_native": baseline.native.x86_64_code, "baseline_source_map": baseline.native.source_map,
            "scope": "exact shared-system output and unoptimized checked-body comparison; fixture grants no production CPU authority"
        }))
    }

    pub(super) fn prepare(words: &[u32]) -> Result<Self> {
        Self::prepare_for(
            words,
            BlockProfile::SystemModeSharedV1(CheckedMemoryProfile::SpAlignmentEnabled),
        )
    }

    fn prepare_for(words: &[u32], profile: BlockProfile) -> Result<Self> {
        let source: Vec<_> = words
            .iter()
            .chain(&[RET])
            .flat_map(|w| w.to_le_bytes())
            .collect();
        let plan = CompilationPlan::new(&source, GuestAddress(CODE_PAGE), profile, target())?;
        ensure!(
            plan.source_bytes() == source.len(),
            "shared region ends early"
        );
        let requirements = plan
            .memory_requirements()
            .context("shared region requirements")?;
        let compiled = plan.compile()?;
        ensure!(
            compiled.fault_recovery.is_empty(),
            "shared region has raw fault recovery"
        );
        let executable = Executable::new(&compiled.native.x86_64_code)?;
        Ok(Self {
            compiled,
            requirements,
            executable,
        })
    }

    pub(super) fn run(
        &self,
        windows: &Windows,
        case: &Case,
    ) -> Result<(GuestState, u64, Option<super::super::Exception>)> {
        let mut memory = memory_thread(windows, self.requirements)?;
        let mut state = case.state.clone();
        let entry = memory
            .prepare(self.requirements)
            .map_err(|status| anyhow::anyhow!("shared region entry: {status:?}"))?;
        let mut raw = None;
        // SAFETY: the windows mutex retains all source/data mappings. This
        // exact compiler body and its requirements own the synchronous view;
        // every memory effect is checked, with no unjoined direct writer.
        let observed = unsafe {
            entry.with_checked_view(|view| -> Result<_> {
                let mut context = ExecutionContext {
                    memory: std::ptr::from_mut(view).cast(),
                    ..Default::default()
                };
                let call: unsafe extern "sysv64" fn(
                    *mut GuestState,
                    *mut ExecutionContext,
                ) -> BlockExit = std::mem::transmute(self.executable.pointer.as_ptr());
                let exit = call(&mut state, &mut context);
                raw = Some((
                    view.fault_kind,
                    view.fault_access,
                    view.fault_pc,
                    view.fault_address,
                    view.completed_bytes,
                ));
                ensure!(
                    context.has_supported_header()
                        && context.memory == std::ptr::from_mut(view).cast(),
                    "shared region context changed"
                );
                let status =
                    MemoryStatus::from_code(view.fault_kind).context("shared region status")?;
                let access = FaultAccess::from_code(view.fault_access)
                    .context("shared region fault access")?;
                let fault = (status != MemoryStatus::Success).then_some(MemoryFault {
                    status,
                    access,
                    address: view.fault_address,
                    pc: view.fault_pc,
                    completed_bytes: view.completed_bytes,
                });
                if let Some(fault) = fault {
                    // A failed checked callback returns a status carrier, not
                    // a BlockExit. The retained view owns precise fault state.
                    ensure!(
                        self.compiled
                            .native
                            .source_map
                            .iter()
                            .any(|(pc, _)| pc.0 == fault.pc),
                        "shared region fault outside retained source"
                    );
                } else {
                    let kind = ExitKind::try_from(exit.kind)
                        .map_err(|_| anyhow::anyhow!("shared region exit kind"))?;
                    ensure!(
                        kind == ExitKind::Return && exit.next_pc == state.x[30],
                        "shared region terminal mismatch: {exit:?}"
                    );
                }
                Ok(fault)
            })
        }
        .map_err(|status| {
            anyhow::anyhow!("shared region finalization: {status:?}; raw={raw:?}")
        })??;
        let exception = observed
            .map(|fault| super::shared_memory::translation_fault(fault, case))
            .transpose()?;
        let next = exception.map_or(
            CODE_PAGE + (case.steps * INSTRUCTION_BYTES) as u64,
            |fault| fault.address,
        );
        Ok((state, next, exception))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const ADD_X0: u32 = 0x9100_0400;
    const STORE_X0_BYTE: u32 = 0x3900_0380; // STRB W0,[X28].
    const LOAD_W1_BYTE: u32 = 0x3940_03a1; // LDRB W1,[X29].

    #[test]
    fn shared_regions_match_unoptimized_callbacks_full_state_and_fault_prefix() {
        let words = [
            ADD_X0,
            ADD_X0,
            ADD_X0,
            STORE_X0_BYTE,
            ADD_X0,
            ADD_X0,
            ADD_X0,
            LOAD_W1_BYTE,
            ADD_X0,
        ];
        let body = CheckedSystemRegion::prepare(&words).unwrap();
        let baseline = CheckedSystemRegion::prepare_for(
            &words,
            BlockProfile::CheckedMemory(CheckedMemoryProfile::SpAlignmentEnabled),
        )
        .unwrap();
        assert!(
            body.compiled.native.x86_64_code.len() < baseline.compiled.native.x86_64_code.len()
        );
        let windows = windows().unwrap().lock().unwrap();
        for fault in [false, true] {
            let mut state = GuestState::default();
            for (index, value) in state.x.iter_mut().enumerate() {
                *value = 0x1122_3344_5566_7700 + index as u64;
            }
            state.x[28] = DATA_WINDOW;
            state.x[29] = if fault {
                DATA_WINDOW + 0x10_0000
            } else {
                DATA_WINDOW + 16
            };
            state.sp = DATA_WINDOW + 0x100;
            state.nzcv = 0xa000_0000;
            state.v.fill([0x1234_5678_9abc_def0, 0xfedc_ba98_7654_3210]);
            let case = Case {
                code: words.to_vec(),
                steps: words.len(),
                state,
                data: vec![0x5a; DATA_BYTES].into(),
                scalable: None,
                el: 0,
                hypervisor: None,
                pauth: false,
            };
            let run = |body: &CheckedSystemRegion| {
                // SAFETY: the one windows mutex excludes every other invocation.
                unsafe { install_case(&windows, &case) }.unwrap();
                let result = body.run(&windows, &case).unwrap();
                // SAFETY: the checked entry has finalized; windows remain owned.
                let data = unsafe { std::slice::from_raw_parts(windows.data.as_ptr(), DATA_BYTES) }
                    .to_vec();
                (result, data)
            };
            let actual = run(&body);
            assert_eq!(actual, run(&baseline));
            assert_eq!(actual.0.0.x[0], case.state.x[0] + if fault { 6 } else { 7 });
            assert_eq!(actual.1[0], (case.state.x[0] + 3) as u8);
            assert_eq!(actual.0.0.x[1], if fault { case.state.x[1] } else { 0x5a });
            assert_eq!(actual.0.2.is_some(), fault);
        }
    }

    #[test]
    fn shared_regions_preserve_live_flags_callees_and_failed_store_state() {
        let mut pressure = Vec::new();
        for _ in 0..8 {
            for register in 0..12 {
                pressure.push(0x9100_0400 | register << 5 | register);
            }
        }
        pressure.push(LOAD_W1_BYTE);
        let flags = vec![
            0xb100_0400,
            0x9100_04a5,
            0x9100_04a5,
            0x9100_04a5,
            0x9100_04a5,
            0x9a84_0067,
            0x3940_0381,
            0x9a84_0062,
            ADD_X0,
        ];
        let store_fault = vec![
            ADD_X0,
            ADD_X0,
            ADD_X0,
            STORE_X0_BYTE,
            ADD_X0,
            ADD_X0,
            ADD_X0,
            0x3900_03a0,
            ADD_X0,
        ];
        let windows = windows().unwrap().lock().unwrap();
        for words in [pressure, flags, store_fault] {
            let selected = CheckedSystemRegion::prepare(&words).unwrap();
            let baseline = CheckedSystemRegion::prepare_for(
                &words,
                BlockProfile::CheckedMemory(CheckedMemoryProfile::SpAlignmentEnabled),
            )
            .unwrap();
            assert!(
                selected.compiled.native.x86_64_code.len()
                    < baseline.compiled.native.x86_64_code.len()
            );
            if words.len() > 90 {
                // The wrapper itself also pushes R15; inspect the register
                // span after its exact source-map entry, not the wrapper.
                let begin = selected.compiled.native.source_map[0].1;
                let end = selected.compiled.native.source_map[words.len() - 1].1;
                assert!(
                    selected.compiled.native.x86_64_code[begin..end]
                        .windows(2)
                        .any(|w| w == [0x41, 0x57])
                );
                assert!(
                    selected.compiled.native.x86_64_code[begin..end]
                        .windows(2)
                        .any(|w| w == [0x41, 0x5f])
                );
            }
            for fault in [false, true] {
                let mut state = GuestState::default();
                state.x.fill(0x1122_3344_5566_7788);
                state.x[0] = u64::MAX;
                state.x[3] = 0x1234;
                state.x[4] = 0x5678;
                state.x[28] = DATA_WINDOW;
                state.x[29] = if fault {
                    DATA_WINDOW + 0x10_0000
                } else {
                    DATA_WINDOW + 16
                };
                state.sp = DATA_WINDOW + 0x100;
                state.nzcv = 0xa000_0000;
                state.v.fill([0xaabb_ccdd_eeff_0099, 0x1122_3344_5566_7788]);
                let case = Case {
                    code: words.clone(),
                    steps: words.len(),
                    state,
                    data: vec![0x5a; DATA_BYTES].into(),
                    scalable: None,
                    el: 0,
                    hypervisor: None,
                    pauth: false,
                };
                let run = |body: &CheckedSystemRegion| {
                    // SAFETY: the owned mutex holds the fixed oracle windows.
                    unsafe { install_case(&windows, &case) }.unwrap();
                    let result = body.run(&windows, &case).unwrap();
                    // SAFETY: the checked invocation has finalized its loans.
                    let data =
                        unsafe { std::slice::from_raw_parts(windows.data.as_ptr(), DATA_BYTES) }
                            .to_vec();
                    (result, data)
                };
                let actual = run(&selected);
                assert_eq!(actual, run(&baseline));
                if words[0] == 0xb100_0400 {
                    assert_eq!(actual.0.0.x[2], case.state.x[3]);
                    assert_eq!(actual.0.0.nzcv, 0x6000_0000);
                } else if words.len() == 9 && fault {
                    assert_eq!(actual.0.0.x[0], 5);
                    assert_eq!(actual.1[0], 2);
                    assert_eq!(actual.1[16], 0x5a);
                    assert!(actual.0.2.is_some());
                }
            }
        }
    }
}
