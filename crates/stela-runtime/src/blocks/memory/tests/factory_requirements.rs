//! A deliberately incorrect provider cannot weaken canonical body preflight.
use crate::{
    blocks::{BlockRuntime, StopReason, ThreadState},
    memory::{
        MemoryRegionSpec, OwnedMemory, SharedMemoryConfig,
        domain::{MappingAttributes, MemorySystem, MemoryThread},
        policy::{LowerAddressProfile, MemoryControls, TagCheckFaultMode},
    },
    system::{
        execution::{Boundary, Dispatcher, EntryBoundary, Failure},
        process_memory::{
            FixedProcessMemoryControls, PreparedProcessMemory, ProcessMemoryFeatures,
            SourceNormalWbDomain,
        },
        profile::BaseSpeAbsence,
        state::{El1Registers, PSTATE_EL0T, SystemState},
    },
};
use anyhow::Result;
use stela_compiler::{
    GuestAddress, GuestState,
    block::{BlockProfile, CheckedMemoryProfile},
    context::{
        ExecutionContext,
        memory::{MemoryRequirements, MemoryStatus},
    },
};
const ADDRESS_SPACE: u64 = 193;
const SOURCE_PC: GuestAddress = GuestAddress(0x8000);
const RETURN_PC: GuestAddress = GuestAddress(0x9000);
const RAM_ADDRESS: u64 = 0x1_7000_0000;
const RAM_BYTES: usize = 4096;
const MMFR2_LSE2: u64 = 1 << 32;
const SCTLR_MMU_DATA_CACHE: u64 = (1 << 0) | (1 << 2);
const LOWER_ADDRESS_BITS: u8 = 39;
const TCR_LOWER_SIZE: u64 = 64 - LOWER_ADDRESS_BITS as u64;
const INITIAL_RAM_BYTE: u8 = 0x11;
const INITIAL_PREFIX_REGISTER: u64 = 0x19;
const PREFIX_REGISTER: usize = 3;
const PREFIX_VALUE: u64 = 0x44;
const MOVZ_X3_44: u32 = 0xd280_0883;
const STRB_W3_X0: u32 = 0x3900_0003;
const RET_X30: u32 = 0xd65f_03c0;
struct Factory {
    controls: FixedProcessMemoryControls,
    system: SystemState,
    thread: MemoryThread<MemoryControls>,
    source: Vec<u8>,
    weaken: bool,
    prepares: usize,
}
impl Dispatcher for Factory {
    fn address_space(&self) -> u64 {
        ADDRESS_SPACE
    }
    fn validate_entry(
        &mut self,
        boundary: &EntryBoundary,
        source: &[u8],
        _: &GuestState,
    ) -> std::result::Result<(), Failure> {
        if boundary.entry() != SOURCE_PC
            || boundary.address_space() != ADDRESS_SPACE
            || source != self.source
        {
            return Err(Failure::Unsupported("factory fixture source differs"));
        }
        Ok(())
    }
    fn prepare_memory_entry<'run>(
        &'run mut self,
        boundary: &EntryBoundary,
        _: &[u8],
        requirements: MemoryRequirements,
        registers: &GuestState,
    ) -> std::result::Result<PreparedProcessMemory<'run>, Failure> {
        self.prepares += 1;
        // The negative provider deliberately ignores the fresh derived metadata.
        // The owned entry must reject this opaque token before native execution.
        let selected = if self.weaken {
            MemoryRequirements::default()
        } else {
            requirements
        };
        self.controls
            .prepare(
                boundary,
                selected,
                &self.system,
                registers,
                &mut self.thread,
                None,
            )
            .map_err(|_| Failure::Unsupported("factory fixture controls declined"))
    }
    fn complete(
        &mut self,
        _: Boundary,
        _: &mut GuestState,
    ) -> std::result::Result<GuestAddress, Failure> {
        Err(Failure::Unsupported(
            "no System terminal in factory fixture",
        ))
    }
}
#[test]
fn checked_factory_cannot_downgrade_source_requirements_before_prefix() -> Result<()> {
    for (weaken, late_failure) in [(true, false), (false, false), (false, true)] {
        let cache = tempfile::tempdir()?;
        let source: Vec<_> = [MOVZ_X3_44, STRB_W3_X0, RET_X30]
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect();
        let mut runtime = BlockRuntime::new_with_profile(
            ADDRESS_SPACE,
            cache.path().to_path_buf(),
            BlockProfile::CheckedMemory(CheckedMemoryProfile::SpAlignmentDisabled),
        );
        runtime.register_code(SOURCE_PC, source.clone())?;
        let prepared = runtime.prepare(SOURCE_PC)?;
        let derived = prepared
            .prepared
            .manifest
            .memory_requirements
            .expect("canonical checked metadata");
        assert_ne!(derived, MemoryRequirements::default());
        let initial_ram = vec![INITIAL_RAM_BYTE; RAM_BYTES];
        let mut owned = OwnedMemory::map(vec![MemoryRegionSpec {
            guest_address: RAM_ADDRESS,
            virtual_bytes: RAM_BYTES as u64,
            initial_bytes: initial_ram.clone(),
            readable: true,
            writable: true,
            executable: false,
        }])?;
        // SAFETY: one retained exact-address anonymous owner, no live references,
        // aliases, other executors, protection changes or retirement in this test.
        let domain = unsafe {
            owned.bind_shared_memory(
                SharedMemoryConfig {
                    address_space: ADDRESS_SPACE,
                    system: MemorySystem::new(16, 8).unwrap(),
                    target: runtime.target_cpu(),
                    attributes: MappingAttributes {
                        tagged: false,
                        shareable: true,
                    },
                },
                &mut [],
            )
        }?;
        // SAFETY: this fresh software fixture explicitly declares every retained
        // source mapping NormalWB/RW/untagged/shareable with identity offsets.
        let witness =
            unsafe { SourceNormalWbDomain::from_source_resolved(std::sync::Arc::clone(&domain)) }
                .unwrap();
        let features = ProcessMemoryFeatures::from_id_registers(
            0,
            MMFR2_LSE2,
            0,
            0,
            BaseSpeAbsence::from_id_aa64dfr0_el1(0).unwrap(),
        )
        .unwrap();
        let controls = FixedProcessMemoryControls::new(
            features,
            SCTLR_MMU_DATA_CACHE,
            TCR_LOWER_SIZE,
            LOWER_ADDRESS_BITS,
            witness,
        )
        .unwrap();
        let mut thread = domain.thread(MemoryControls::new(
            LowerAddressProfile::new(LOWER_ADDRESS_BITS, false).unwrap(),
            false,
            false,
            false,
            TagCheckFaultMode::Ignore,
            false,
        ));
        let previous_policy = *thread.policy_mut();
        if late_failure {
            thread.inject_post_body_failure_once_for_test();
        }
        let system = SystemState::new(PSTATE_EL0T, 0, El1Registers::new(0, 0, 0, 0, 0)).unwrap();
        let mut factory = Factory {
            controls,
            system,
            thread,
            source,
            weaken,
            prepares: 0,
        };
        let mut registers = GuestState::default();
        registers.x[0] = RAM_ADDRESS;
        registers.x[PREFIX_REGISTER] = INITIAL_PREFIX_REGISTER;
        registers.x[30] = RETURN_PC.0;
        let before = registers.clone();
        let mut state = ThreadState {
            registers,
            pc: SOURCE_PC,
        };
        let mut context = ExecutionContext::default();
        let old_memory = context.memory;
        let old_scalable = context.scalable;
        // SAFETY: compiler-owned RX, exact source/profile/domain, synchronous
        // retained CPU/thread loans and exclusive test storage ownership.
        let result = unsafe {
            runtime.run_with_memory(&mut state, Some(RETURN_PC), 1, &mut factory, &mut context)
        };
        assert_eq!(factory.prepares, 1);
        assert_eq!(context.memory, old_memory);
        assert_eq!(context.scalable, old_scalable);
        assert_eq!(*factory.thread.policy_mut(), previous_policy);
        let mut observed_ram = vec![0u8; RAM_BYTES];
        // SAFETY: all token/native scopes ended, owner remains pinned/readable,
        // sole quiescent executor, copy raw bytes only into disjoint output.
        unsafe {
            std::ptr::copy_nonoverlapping(
                RAM_ADDRESS as usize as *const u8,
                observed_ram.as_mut_ptr(),
                RAM_BYTES,
            )
        };
        if weaken {
            let error = result.expect_err("weaker token must decline before native prefix");
            assert!(format!("{error:#}").contains("checked body/token requirements mismatch"));
            assert_eq!(state.registers, before);
            assert_eq!(state.pc, SOURCE_PC);
            assert_eq!(observed_ram, initial_ram);
        } else {
            let outcome = result?;
            assert_eq!(state.registers.x[PREFIX_REGISTER], PREFIX_VALUE);
            if late_failure {
                assert!(
                    matches!(outcome.reason, StopReason::MemoryFinalizationFailed {
                    status, native_executed: true, original_fault: None,
                    completed_bytes: 1, observed_exit: Some(_), retry_safe: false, ..
                } if status == MemoryStatus::Domain as u32)
                );
                assert_eq!(state.pc, SOURCE_PC);
                assert_eq!(
                    factory.thread.validate_execution(0),
                    Err(MemoryStatus::Domain)
                );
            } else {
                assert_eq!(outcome.blocks_executed, 1);
                assert_eq!(state.pc, RETURN_PC);
            }
            let mut expected = initial_ram;
            expected[0] = PREFIX_VALUE as u8;
            assert_eq!(observed_ram, expected);
        }
    }
    Ok(())
}
