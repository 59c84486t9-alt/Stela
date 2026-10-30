//! Scalable-code entry with checked memory.
use super::*;
use crate::{
    memory::domain::{MemoryDomain, MemorySystem},
    system::state::{El1Registers, PSTATE_EL0T, PSTATE_IL_MASK},
};
use fixture::*;
use std::sync::Arc;
use stela_compiler::{TargetCpu, aarch64::scalable::ScalableMode, context::memory::MemoryStatus};

mod fixture {
    //! A software CPU and memory domain for scalable entry tests.
    use super::super::super::{
        SCTLR_NATIVE_NORMAL_WB, SCTLR_SP_ALIGNMENT_EL0, SourceNormalWbDomain,
    };
    use super::super::*;
    use crate::{
        memory::{
            backing::{AccessPermissions, MemoryBacking, MemoryView},
            domain::{MappingAttributes, MemoryDomain, MemorySystem},
            policy::{LowerAddressProfile, TagCheckFaultMode},
        },
        system::{
            identification::Register,
            identification_snapshot::Snapshot,
            scalable_controls::{Implementation, Readbacks},
            state::{El1Registers, PSTATE_EL0T},
        },
    };
    use std::{
        alloc::{Layout, alloc_zeroed, dealloc},
        ptr::NonNull,
        sync::Arc,
    };
    use stela_compiler::{
        TargetCpu,
        aarch64::scalable::{
            LOOKUP_TABLE_BYTES, PREDICATE_REGISTER_COUNT, ScalableMode, VECTOR_CHUNK_BYTES,
            VECTOR_REGISTER_COUNT, VectorLength,
            features::{ScalableFeature, ScalableFeatures},
            profile::ScalableControls,
        },
        context::{ScalableStateView, memory::MemoryImplementationProfile},
        scalable_context::ScalableProfile,
    };

    pub(super) const PC: u64 = 0x1000;
    pub(super) const RAM: u64 = 0x1400_74000;
    pub(super) const VL: usize = VECTOR_CHUNK_BYTES;
    pub(super) const DATA_BYTES: usize = 8192;
    pub(super) const CODE_PAGE_BYTES: usize = 4096;
    const OBSERVER_SVC: u32 = 0xd400_2461;
    pub(super) const ST2Q_Z1_P0_X5: u32 = 0xe440_00a1;
    pub(super) const LDR_ZA_W12_X5: u32 = 0xe100_00a0;
    pub(super) const STR_ZA_W12_X5: u32 = 0xe120_00a0;
    pub(super) const LDR_ZT0_X5: u32 = 0xe11f_80a0;
    pub(super) const STR_ZT0_X5: u32 = 0xe13f_80a0;
    pub(super) const STORAGE_BYTES: usize = DATA_BYTES + CODE_PAGE_BYTES;
    pub(super) const LOWER_BITS: u8 = 44;
    pub(super) const RET_X30: u32 = 0xd65f_03c0;
    pub(super) const MOV_X3_SEVEN: u32 = 0xd280_00e3;
    pub(super) const LD1B_Z1_P0_X5: u32 = 0xa400_a0a1;
    pub(super) const LD1B_Z1_P0_SP: u32 = 0xa400_a3e1;
    pub(super) const LD1D_Z1_P0_X5: u32 = 0xa5e0_a0a1;
    pub(super) const LD1Q_ZA_P0_X5: u32 = 0xe1c0_00a0;
    pub(super) const ST1Q_ZA_P0_X5: u32 = 0xe1e0_00a0;
    pub(super) const FPEN_SHIFT: u32 = 20;
    pub(super) const ZEN_SHIFT: u32 = 16;
    pub(super) const SMEN_SHIFT: u32 = 24;
    pub(super) const ALL_ACCESS: u64 = (3 << FPEN_SHIFT) | (3 << ZEN_SHIFT) | (3 << SMEN_SHIFT);
    pub(super) const EZT0: u64 = 1 << 30;
    pub(super) const DATA_RIGHTS: AccessPermissions = AccessPermissions {
        readable: true,
        writable: true,
        executable: false,
    };

    // Same pinned raw-storage ownership as scalable::leaf::tests. Bytes are read
    // only between synchronous entries and every native write uses this one domain.
    pub(super) struct Storage {
        pointer: NonNull<u8>,
        layout: Layout,
    }
    // SAFETY: no byte references escape; Arc keeps the allocation through entry.
    unsafe impl Send for Storage {}
    // SAFETY: tests serialize native entry and all observations of the raw bytes.
    unsafe impl Sync for Storage {}
    impl Storage {
        fn new(source: &[u8], code_offset: usize, original_code_page: Option<&[u8]>) -> Arc<Self> {
            assert!(
                code_offset
                    .checked_add(source.len())
                    .is_some_and(|end| end <= CODE_PAGE_BYTES)
            );
            let layout = Layout::from_size_align(STORAGE_BYTES, VL).unwrap();
            // SAFETY: valid allocation and matching deallocation in Drop.
            let pointer = NonNull::new(unsafe { alloc_zeroed(layout) }).unwrap();
            for offset in 0..DATA_BYTES {
                // SAFETY: exclusive allocation before publication into any domain.
                unsafe { pointer.as_ptr().add(offset).write((offset & 255) as u8) };
            }
            if let Some(page) = original_code_page {
                assert_eq!(page.len(), CODE_PAGE_BYTES);
                assert_eq!(source.len(), 2 * size_of::<u32>());
                assert_eq!(
                    &page[code_offset..code_offset + size_of::<u32>()],
                    &source[..size_of::<u32>()]
                );
                assert_eq!(
                    &page[code_offset + size_of::<u32>()..code_offset + 2 * size_of::<u32>()],
                    OBSERVER_SVC.to_le_bytes()
                );
                assert_eq!(&source[size_of::<u32>()..], RET_X30.to_le_bytes());
                // SAFETY: complete captured code page initializes fresh exclusive
                // storage before backing/domain/source publication. The source copy
                // below preserves the subject and changes only observer SVC to RET.
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        page.as_ptr(),
                        pointer.as_ptr().add(DATA_BYTES),
                        CODE_PAGE_BYTES,
                    )
                };
            }
            // SAFETY: source fits the separate code page, before publication.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    source.as_ptr(),
                    pointer.as_ptr().add(DATA_BYTES + code_offset),
                    source.len(),
                )
            };
            Arc::new(Self { pointer, layout })
        }
        pub(super) fn bytes(&self) -> Vec<u8> {
            // SAFETY: callers observe only between synchronous invocations.
            unsafe { std::slice::from_raw_parts(self.pointer.as_ptr(), DATA_BYTES).to_vec() }
        }
    }
    impl Drop for Storage {
        fn drop(&mut self) {
            // SAFETY: the last Arc frees the allocation with its layout.
            unsafe { dealloc(self.pointer.as_ptr(), self.layout) };
        }
    }

    pub(super) fn snapshot(lse2: bool, sme_version: u64) -> Arc<Snapshot> {
        Arc::new(
            Snapshot::declared(
                "qualified-scalable-native-software-owner",
                &[
                    (Register::IdAa64Pfr0El1, 0x11),
                    (Register::IdAa64Pfr1El1, 2 << 24),
                    (Register::IdAa64Smfr0El1, sme_version << 56),
                    (Register::IdAa64Zfr0El1, 0),
                    (Register::IdAa64Isar1El1, 0),
                    (Register::IdAa64Isar3El1, 0),
                    (Register::IdAa64Dfr0El1, 0),
                    (Register::IdAa64Mmfr0El1, 0),
                    (Register::IdAa64Mmfr2El1, u64::from(lse2) << 32),
                    (Register::IdAa64Mmfr3El1, 0),
                    (Register::IdAa64Mmfr4El1, 0),
                ],
            )
            .unwrap(),
        )
    }

    pub(super) fn fixed(
        ids: Arc<Snapshot>,
        domain: &Arc<MemoryDomain>,
        sa0: bool,
    ) -> Result<FixedProcessMemoryControls, ProcessMemoryError> {
        fixed_with_lower_bits(ids, domain, sa0, LOWER_BITS)
    }

    fn fixed_with_lower_bits(
        ids: Arc<Snapshot>,
        domain: &Arc<MemoryDomain>,
        sa0: bool,
        lower_bits: u8,
    ) -> Result<FixedProcessMemoryControls, ProcessMemoryError> {
        // SAFETY: the fixture declares its data and code views Normal write-back
        // with matching source and native rights; no other domain or raw writer is
        // involved.
        let source = unsafe { SourceNormalWbDomain::from_source_resolved(Arc::clone(domain)) }
            .map_err(ProcessMemoryError::Memory)?;
        FixedProcessMemoryControls::new_with_identification(
            ids,
            SCTLR_NATIVE_NORMAL_WB | if sa0 { SCTLR_SP_ALIGNMENT_EL0 } else { 0 },
            64 - u64::from(lower_bits),
            lower_bits,
            source,
        )
    }

    pub(super) fn access(
        ids: &Snapshot,
        sca16: bool,
        cpacr: u64,
        bytes: usize,
    ) -> ScalableControlOwner<'_> {
        let lengths = [VectorLength::from_bytes(bytes).unwrap()];
        let implementation = if sca16 {
            Implementation::declared_sca16(&lengths, MemoryImplementationProfile::ScalableTagChecks)
        } else {
            Implementation::declared(&lengths, MemoryImplementationProfile::ScalableTagChecks)
        }
        .unwrap();
        ScalableControlOwner::new_declared_el10(
            ids,
            Readbacks {
                cpacr_el1: cpacr,
                smcr_el1: EZT0,
            },
            implementation,
        )
        .unwrap()
    }

    fn profile(bytes: usize, sme_version: u64, mode: ScalableMode) -> ScalableProfile {
        let length = VectorLength::from_bytes(bytes).unwrap();
        let features = ScalableFeatures::of(ScalableFeature::Sme).with(ScalableFeature::Sme2);
        let features = if sme_version >= 2 {
            features.with(ScalableFeature::Sme2p1)
        } else {
            features
        };
        ScalableProfile::new_with_features(
            length,
            mode,
            features,
            ScalableControls::new(length, true),
        )
        .unwrap()
    }

    #[derive(Debug, PartialEq, Eq)]
    pub(super) struct Banks {
        z: Vec<Vec<u8>>,
        p: Vec<Vec<u8>>,
        ffr: Vec<u8>,
        za: Vec<u8>,
        zt0: Vec<u8>,
        tpidr2: u64,
        fpmr: u64,
        mode: ScalableMode,
    }
    pub(super) fn banks(registers: &GuestState, scalable: &ScalableState) -> Banks {
        let bytes = scalable.vector_length().bytes();
        let z = (0..VECTOR_REGISTER_COUNT)
            .map(|i| {
                let mut b = vec![0; bytes];
                scalable.read_z(registers, i, &mut b).unwrap();
                b
            })
            .collect();
        let p = (0..PREDICATE_REGISTER_COUNT)
            .map(|i| {
                let mut b = vec![0; bytes / 8];
                scalable.read_predicate(i, &mut b).unwrap();
                b
            })
            .collect();
        let mut ffr = vec![0; bytes / 8];
        scalable.read_ffr(&mut ffr).unwrap();
        let mut za = vec![0; bytes * bytes];
        scalable.read_za(0, &mut za).unwrap();
        let mut zt0 = vec![0; LOOKUP_TABLE_BYTES];
        scalable.read_zt0(0, &mut zt0).unwrap();
        Banks {
            z,
            p,
            ffr,
            za,
            zt0,
            tpidr2: scalable.tpidr2_el0(),
            fpmr: scalable.fpmr(),
            mode: scalable.mode(),
        }
    }

    /// The source a fixture runs, and the targets and placement it runs with.
    pub(super) struct Program<'a> {
        pub(super) words: &'a [u32],
        pub(super) guest_base: u64,
        pub(super) ram_base: u64,
        pub(super) svl_bytes: usize,
        pub(super) compiler_target: TargetCpu,
        pub(super) domain_target: TargetCpu,
        pub(super) split: Option<(usize, bool)>,
        pub(super) sme_version: u64,
        pub(super) mode: ScalableMode,
    }

    pub(super) struct Fixture {
        pub(super) storage: Arc<Storage>,
        pub(super) domain: Arc<MemoryDomain>,
        pub(super) ids: Arc<Snapshot>,
        pub(super) controls: FixedProcessMemoryControls,
        pub(super) prepared: PreparedScalableLeaf,
        pub(super) memory: MemoryThread<MemoryControls>,
        pub(super) system: SystemState,
        pub(super) registers: GuestState,
        pub(super) scalable: ScalableState,
        pub(super) context: ExecutionContext,
        pub(super) sca16: bool,
        pub(super) cpacr: u64,
        pub(super) svl_bytes: usize,
    }
    impl Fixture {
        pub(super) fn new(
            word: u32,
            compiler_target: TargetCpu,
            domain_target: TargetCpu,
            split: Option<(usize, bool)>,
        ) -> Self {
            Self::build(Program {
                words: &[MOV_X3_SEVEN, word, RET_X30],
                guest_base: PC,
                ram_base: RAM,
                svl_bytes: VL,
                compiler_target,
                domain_target,
                split,
                sme_version: 1,
                mode: ScalableMode::new(true, true),
            })
        }
        pub(super) fn new_program(
            words: &[u32],
            guest_base: u64,
            svl_bytes: usize,
            compiler_target: TargetCpu,
            domain_target: TargetCpu,
            split: Option<(usize, bool)>,
        ) -> Self {
            Self::build(Program {
                words,
                guest_base,
                ram_base: RAM,
                svl_bytes,
                compiler_target,
                domain_target,
                split,
                sme_version: 2,
                mode: ScalableMode::new(true, true),
            })
        }
        pub(super) fn build(program: Program<'_>) -> Self {
            let Program {
                words,
                guest_base,
                ram_base,
                svl_bytes,
                compiler_target,
                domain_target,
                split,
                sme_version,
                mode,
            } = program;
            let (lower_bits, data_rights, original_code_page) = (LOWER_BITS, DATA_RIGHTS, None);
            assert!(
                compiler_target.supported(),
                "host lacks required native test recipe"
            );
            let source: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
            let code_offset = guest_base as usize & (CODE_PAGE_BYTES - 1);
            let code_page = guest_base - code_offset as u64;
            let storage = Storage::new(&source, code_offset, original_code_page);
            // SAFETY: the storage is pinned, owned and disjoint, and never accessed
            // concurrently with the domain's synchronous native call.
            let backing = unsafe {
                MemoryBacking::new(
                    storage.pointer,
                    STORAGE_BYTES,
                    AccessPermissions {
                        executable: true,
                        ..DATA_RIGHTS
                    },
                    Arc::clone(&storage),
                )
            }
            .unwrap();
            let mut views = Vec::new();
            if let Some((boundary, translation)) = split {
                assert!((1..DATA_BYTES).contains(&boundary));
                views.push(
                    MemoryView::new(Arc::clone(&backing), ram_base, 0, boundary, data_rights)
                        .unwrap(),
                );
                if !translation {
                    views.push(
                        MemoryView::new(
                            Arc::clone(&backing),
                            ram_base + boundary as u64,
                            boundary,
                            DATA_BYTES - boundary,
                            AccessPermissions {
                                readable: false,
                                writable: false,
                                executable: false,
                            },
                        )
                        .unwrap(),
                    );
                }
            } else {
                views.push(
                    MemoryView::new(Arc::clone(&backing), ram_base, 0, DATA_BYTES, data_rights)
                        .unwrap(),
                );
            }
            views.push(
                MemoryView::new(
                    backing,
                    code_page,
                    DATA_BYTES,
                    CODE_PAGE_BYTES,
                    AccessPermissions {
                        readable: true,
                        writable: false,
                        executable: true,
                    },
                )
                .unwrap(),
            );
            let domain = MemoryDomain::new_for_address_space(
                7,
                MemorySystem::new(VL as u64, 4).unwrap(),
                views
                    .into_iter()
                    .map(|view| {
                        (
                            view,
                            MappingAttributes {
                                tagged: false,
                                shareable: true,
                            },
                        )
                    })
                    .collect(),
                domain_target,
            )
            .unwrap();
            let ids = snapshot(true, sme_version);
            let controls =
                fixed_with_lower_bits(Arc::clone(&ids), &domain, true, lower_bits).unwrap();
            let memory = domain.thread(MemoryControls::new(
                LowerAddressProfile::new(lower_bits, false).unwrap(),
                false,
                false,
                false,
                TagCheckFaultMode::Ignore,
                false,
            ));
            let prepared = PreparedScalableLeaf::prepare(
                &source,
                GuestAddress(guest_base),
                profile(svl_bytes, sme_version, mode),
                compiler_target,
            )
            .unwrap();
            let mut registers = GuestState::default();
            registers.x[3] = 0x5432;
            registers.x[5] = ram_base;
            registers.sp = ram_base;
            registers.nzcv = 0xa000_0000;
            registers.fpcr = 0x07c0_0000;
            registers.fpsr = 0x8800_009f;
            let mut scalable =
                ScalableState::new(profile(svl_bytes, sme_version, mode).vector_length(), true);
            scalable
                .apply_mode(&mut registers, ScalableMode::new(true, true))
                .unwrap();
            for i in 0..VECTOR_REGISTER_COUNT {
                scalable
                    .write_z(&mut registers, i, &vec![i + 1; svl_bytes])
                    .unwrap();
            }
            for i in 0..PREDICATE_REGISTER_COUNT {
                scalable
                    .write_predicate(i, &vec![i.wrapping_mul(17); svl_bytes / 8])
                    .unwrap();
            }
            let mut predicate = vec![0; svl_bytes / 8];
            predicate[0] = 3;
            scalable.write_predicate(0, &predicate).unwrap();
            scalable.write_ffr(&vec![0xa5; svl_bytes / 8]).unwrap();
            scalable
                .write_za(0, &vec![0x6d; svl_bytes * svl_bytes])
                .unwrap();
            scalable.write_zt0(0, &[0x35; LOOKUP_TABLE_BYTES]).unwrap();
            scalable.set_tpidr2_el0(0x1234_5678_9abc_def0);
            scalable.set_fpmr(0x2468_ace0);
            scalable.apply_mode(&mut registers, mode).unwrap();
            let system =
                SystemState::new(PSTATE_EL0T, 0, El1Registers::new(0, 0, 0, 0, 0)).unwrap();
            let context = ExecutionContext {
                memory: std::ptr::dangling_mut::<u8>().cast(),
                scalable: std::ptr::dangling_mut::<ScalableStateView>(),
                system: std::ptr::dangling_mut::<u8>().cast(),
                ..ExecutionContext::default()
            };
            Self {
                storage,
                domain,
                ids,
                controls,
                prepared,
                memory,
                system,
                registers,
                scalable,
                context,
                sca16: true,
                cpacr: ALL_ACCESS,
                svl_bytes,
            }
        }
        pub(super) fn execute(&mut self) -> Result<ScalableLeafExit, ScalableExecutionError> {
            let access = access(&self.ids, self.sca16, self.cpacr, self.svl_bytes);
            let policy = *self.memory.policy_mut();
            let pointers = (
                self.context.memory,
                self.context.scalable,
                self.context.system,
            );
            let system = self.system.clone();
            let host_mxcsr = mxcsr();
            // SAFETY: fixed terminating source, the same snapshot and domain, the
            // controls and disjoint pinned backing established above.
            let result = unsafe {
                self.controls.execute_scalable_leaf(
                    &access,
                    &self.prepared,
                    &mut self.system,
                    ScalableGuest {
                        registers: &mut self.registers,
                        scalable: &mut self.scalable,
                    },
                    &mut self.memory,
                    &mut self.context,
                )
            };
            assert_eq!(*self.memory.policy_mut(), policy);
            assert_eq!(
                (
                    self.context.memory,
                    self.context.scalable,
                    self.context.system
                ),
                pointers
            );
            assert_eq!(self.system, system);
            assert_eq!(mxcsr(), host_mxcsr);
            result
        }
    }

    fn mxcsr() -> u32 {
        let mut value = 0_u32;
        // SAFETY: STMXCSR writes exactly this live u32 and changes no host control.
        unsafe {
            std::arch::asm!("stmxcsr [{pointer}]", pointer=in(reg) &mut value, options(nostack,preserves_flags))
        };
        value
    }

    pub(super) fn wide_target() -> TargetCpu {
        TargetCpu::AtomicLoad16.with_cx16()
    }
    pub(super) fn unchanged(f: &Fixture, registers: &GuestState, before: &Banks, ram: &[u8]) {
        assert_eq!(&f.registers, registers);
        assert_eq!(&banks(&f.registers, &f.scalable), before);
        assert_eq!(f.storage.bytes(), ram);
    }
}
mod retained {
    //! Repeated scalable entry on one CPU.
    use super::super::ScalableGuest;
    use super::fixture::{Fixture, access};
    use crate::{
        memory::{domain::MemoryThread, policy::MemoryControls},
        scalable::{
            ScalableState,
            leaf::{PreparedScalableLeaf, ScalableLeafExit},
        },
        system::{
            process_memory::{FixedProcessMemoryControls, scalable::ScalableExecutionError},
            scalable_controls::ScalableControlOwner,
            state::SystemState,
        },
    };
    use stela_compiler::{GuestState, context::ExecutionContext};

    pub(super) struct RetainedEntry<'a> {
        access: ScalableControlOwner<'a>,
        controls: &'a FixedProcessMemoryControls,
        prepared: &'a PreparedScalableLeaf,
        system: &'a mut SystemState,
        registers: &'a mut GuestState,
        scalable: &'a mut ScalableState,
        memory: &'a mut MemoryThread<MemoryControls>,
        context: &'a mut ExecutionContext,
    }
    impl<'a> RetainedEntry<'a> {
        pub(super) fn new(fixture: &'a mut Fixture) -> Self {
            Self {
                access: access(
                    &fixture.ids,
                    fixture.sca16,
                    fixture.cpacr,
                    fixture.svl_bytes,
                ),
                controls: &fixture.controls,
                prepared: &fixture.prepared,
                system: &mut fixture.system,
                registers: &mut fixture.registers,
                scalable: &mut fixture.scalable,
                memory: &mut fixture.memory,
                context: &mut fixture.context,
            }
        }
        pub(super) fn execute(&mut self) -> Result<ScalableLeafExit, ScalableExecutionError> {
            // SAFETY: the exclusive fixture borrow keeps its pinned disjoint
            // backing, the snapshot, the domain and the fixed prepared source.
            // Native entry is synchronous, with no raw writer or state alias.
            unsafe {
                self.controls.execute_scalable_leaf(
                    &self.access,
                    self.prepared,
                    self.system,
                    ScalableGuest {
                        registers: self.registers,
                        scalable: self.scalable,
                    },
                    self.memory,
                    self.context,
                )
            }
        }
    }

    #[test]
    fn kept_owner_rechecks_state_before_each_native_call() {
        use super::fixture::{LD1B_Z1_P0_X5, VL, banks};
        use crate::system::{process_memory::ProcessMemoryError, state::PSTATE_IL_MASK};
        use stela_compiler::TargetCpu;
        let mut fixture = Fixture::new(
            LD1B_Z1_P0_X5,
            TargetCpu::Baseline,
            TargetCpu::Baseline,
            None,
        );
        {
            let mut entry = RetainedEntry::new(&mut fixture);
            assert_eq!(entry.execute().unwrap(), ScalableLeafExit::Returned);
            let registers = entry.registers.clone();
            let before = banks(entry.registers, entry.scalable);
            let pstate = entry.system.pstate(entry.registers) | PSTATE_IL_MASK;
            entry
                .system
                .transition_pstate(entry.registers, pstate)
                .unwrap();
            assert!(matches!(
                entry.execute(),
                Err(ScalableExecutionError::MemoryAuthority {
                    cause: ProcessMemoryError::IllegalExecutionState,
                    ..
                })
            ));
            assert_eq!(*entry.registers, registers);
            assert_eq!(banks(entry.registers, entry.scalable), before);
            assert_eq!(entry.scalable.vector_length().bytes(), VL);
        }
    }
}

#[test]
fn checked_entry_owns_source_and_executes_same_snapshot_domain() {
    for (word, bytes, target, ram_base) in [
        (LD1B_Z1_P0_X5, 2, TargetCpu::Baseline, RAM),
        (LD1D_Z1_P0_X5, 8, wide_target(), RAM),
        (LD1B_Z1_P0_X5, 2, TargetCpu::Baseline, 0x800_1400_7400),
    ] {
        let mut f = Fixture::build(Program {
            words: &[MOV_X3_SEVEN, word, RET_X30],
            guest_base: PC,
            ram_base,
            svl_bytes: VL,
            compiler_target: target,
            domain_target: target,
            split: None,
            sme_version: 1,
            mode: ScalableMode::new(true, true),
        });
        assert!(
            f.ids
                .same_snapshot(f.controls.identification_snapshot().unwrap())
        );
        assert_eq!(f.prepared.source_map()[0].0, GuestAddress(PC));
        assert_eq!(f.prepared.source_map()[1].0, GuestAddress(PC + 4));
        assert!(!f.prepared.identity().native_sha256.is_empty());
        let ram = f.storage.bytes();
        let mut expected = f.registers.clone();
        expected.x[3] = 7;
        let mut expected_scalable = f.scalable.clone();
        let mut output = [0; VL];
        output[..bytes].copy_from_slice(&ram[..bytes]);
        expected_scalable
            .write_z(&mut expected, 1, &output)
            .unwrap();
        assert_eq!(f.execute().unwrap(), ScalableLeafExit::Returned);
        assert_eq!(f.registers, expected);
        assert_eq!(
            banks(&f.registers, &f.scalable),
            banks(&expected, &expected_scalable)
        );
        assert_eq!(f.storage.bytes(), ram);
    }
    // Whole ZA-row and ZT0 transfers use their SME helpers even with SM = 0.
    for (word, bytes, lookup, write) in [
        (LDR_ZA_W12_X5, VL, false, false),
        (STR_ZA_W12_X5, VL, false, true),
        (
            LDR_ZT0_X5,
            stela_compiler::aarch64::scalable::LOOKUP_TABLE_BYTES,
            true,
            false,
        ),
        (
            STR_ZT0_X5,
            stela_compiler::aarch64::scalable::LOOKUP_TABLE_BYTES,
            true,
            true,
        ),
    ] {
        let mut f = Fixture::build(Program {
            words: &[MOV_X3_SEVEN, word, RET_X30],
            guest_base: PC,
            ram_base: RAM,
            svl_bytes: VL,
            compiler_target: TargetCpu::Baseline,
            domain_target: TargetCpu::Baseline,
            split: None,
            sme_version: 1,
            mode: ScalableMode::new(false, true),
        });
        let mut ram = f.storage.bytes();
        let mut expected = f.registers.clone();
        expected.x[3] = 7;
        let mut scalable = f.scalable.clone();
        if write {
            ram[..bytes].fill(if lookup { 0x35 } else { 0x6d });
        } else if lookup {
            scalable.write_zt0(0, &ram[..bytes]).unwrap();
        } else {
            scalable.write_za(0, &ram[..bytes]).unwrap();
        }
        assert_eq!(f.execute().unwrap(), ScalableLeafExit::Returned);
        assert_eq!(f.registers, expected);
        // With SM = 0, Z, P and FFR reads are unavailable, so Debug shows the
        // allocations without changing mode (re-enabling would zero ZA).
        assert_eq!(format!("{:?}", f.scalable), format!("{scalable:?}"));
        assert_eq!(f.storage.bytes(), ram);
    }
}

#[test]
fn same_domain_observation_excludes_scalable_entry_until_released() {
    let mut f = Fixture::new(
        LD1B_Z1_P0_X5,
        TargetCpu::Baseline,
        TargetCpu::Baseline,
        None,
    );
    let before = f.registers.clone();
    assert_ne!(before.x[3], 7);
    assert_eq!(&f.prepared.source()[..4], &MOV_X3_SEVEN.to_le_bytes());
    let state = banks(&f.registers, &f.scalable);
    let ram = f.storage.bytes();
    let generation = f.domain.generation().unwrap();
    // The observation holds the thread's domain service borrow, so admission
    // must refuse before any prefix or policy installation.
    let observation = f.memory.observation_loan().unwrap();
    assert!(matches!(
        f.execute(),
        Err(ScalableExecutionError::MemoryAuthority {
            cause: ProcessMemoryError::Memory(MemoryStatus::Domain),
            pc: GuestAddress(PC),
        })
    ));
    unchanged(&f, &before, &state, &ram);
    assert_eq!(f.domain.generation().unwrap(), generation);
    // Reuse the same prepared body, source witness, controls and state;
    // dropping a read-only borrow changes neither the mapping generation nor
    // the source.
    drop(observation);
    let mut expected = before;
    expected.x[3] = 7;
    let mut expected_scalable = f.scalable.clone();
    let mut output = [0; VL];
    output[..2].copy_from_slice(&ram[..2]);
    expected_scalable
        .write_z(&mut expected, 1, &output)
        .unwrap();
    assert_eq!(f.execute().unwrap(), ScalableLeafExit::Returned);
    assert_eq!(f.registers, expected);
    assert_eq!(
        banks(&f.registers, &f.scalable),
        banks(&expected, &expected_scalable)
    );
    assert_eq!(f.storage.bytes(), ram);
    assert_eq!(f.domain.generation().unwrap(), generation);
}

#[test]
fn distinct_snapshot_and_wrong_domain_decline_before_prefix() {
    let mut f = Fixture::new(
        LD1B_Z1_P0_X5,
        TargetCpu::Baseline,
        TargetCpu::Baseline,
        None,
    );
    let before = f.registers.clone();
    let state = banks(&f.registers, &f.scalable);
    let ram = f.storage.bytes();
    f.ids = snapshot(true, 1);
    assert!(matches!(
        f.execute(),
        Err(ScalableExecutionError::WrongIdentificationSnapshot {
            pc: GuestAddress(PC)
        })
    ));
    unchanged(&f, &before, &state, &ram);
    // Restore a single shared identification allocation, then use an empty
    // different domain solely for the negative identity control; no native
    // body is allowed to enter that owner.
    f.ids = snapshot(true, 1);
    f.controls = fixed(Arc::clone(&f.ids), &f.domain, true).unwrap();
    let wrong = MemoryDomain::new_for_address_space(
        7,
        MemorySystem::new(VL as u64, 4).unwrap(),
        Vec::new(),
        TargetCpu::Baseline,
    )
    .unwrap();
    f.memory = wrong.thread(*f.memory.policy_mut());
    assert!(matches!(
        f.execute(),
        Err(ScalableExecutionError::MemoryAuthority {
            cause: ProcessMemoryError::WrongMemoryDomain,
            ..
        })
    ));
    unchanged(&f, &before, &state, &ram);
}

#[test]
fn source_sca_and_lse2_requirements_decline_before_prefix() {
    let mut f = Fixture::new(
        LD1B_Z1_P0_X5,
        TargetCpu::Baseline,
        TargetCpu::Baseline,
        None,
    );
    let before = f.registers.clone();
    let state = banks(&f.registers, &f.scalable);
    let ram = f.storage.bytes();
    f.sca16 = false;
    assert!(matches!(
        f.execute(),
        Err(ScalableExecutionError::UnsupportedSourceAtomicity {
            actual: SourceAtomicity::Unspecified,
            ..
        })
    ));
    unchanged(&f, &before, &state, &ram);
    assert!(matches!(
        fixed(snapshot(false, 1), &f.domain, true),
        Err(ProcessMemoryError::UnsupportedFeature {
            register: "ID_AA64MMFR2_EL1",
            field: "AT",
            value: 0
        })
    ));
    unchanged(&f, &before, &state, &ram);
    for word in [LD1D_Z1_P0_X5, ST1Q_ZA_P0_X5] {
        let mut f = Fixture::new(word, wide_target(), TargetCpu::Baseline, None);
        let before = f.registers.clone();
        let state = banks(&f.registers, &f.scalable);
        let ram = f.storage.bytes();
        assert_eq!(
            f.execute().unwrap(),
            ScalableLeafExit::EntryDeclined(MemoryStatus::Unsupported)
        );
        unchanged(&f, &before, &state, &ram);
    }
}

#[test]
fn helper_za_sp_and_feature_failures_precede_prefix() {
    for cpacr in [
        ALL_ACCESS & !(3 << SMEN_SHIFT),
        ALL_ACCESS & !(3 << FPEN_SHIFT),
    ] {
        let mut f = Fixture::new(LD1Q_ZA_P0_X5, wide_target(), wide_target(), None);
        f.cpacr = cpacr;
        let before = f.registers.clone();
        let state = banks(&f.registers, &f.scalable);
        let ram = f.storage.bytes();
        assert!(matches!(
            f.execute(),
            Err(ScalableExecutionError::Control {
                cause: scalable_controls::Error::PreflightTrap(_),
                ..
            })
        ));
        unchanged(&f, &before, &state, &ram);
    }
    let mut f = Fixture::new(LD1Q_ZA_P0_X5, wide_target(), wide_target(), None);
    f.scalable
        .apply_mode(&mut f.registers, ScalableMode::new(true, false))
        .unwrap();
    let scalable_before = format!("{:?}", f.scalable);
    let before = f.registers.clone();
    let ram = f.storage.bytes();
    assert!(matches!(
        f.execute(),
        Err(ScalableExecutionError::Control {
            cause: scalable_controls::Error::PreflightTrap(_),
            ..
        })
    ));
    assert_eq!(f.registers, before);
    assert_eq!(format!("{:?}", f.scalable), scalable_before);
    assert_eq!(f.storage.bytes(), ram);
    let mut f = Fixture::new(
        LD1B_Z1_P0_SP,
        TargetCpu::Baseline,
        TargetCpu::Baseline,
        None,
    );
    f.controls = fixed(Arc::clone(&f.ids), &f.domain, false).unwrap();
    let before = f.registers.clone();
    let state = banks(&f.registers, &f.scalable);
    let ram = f.storage.bytes();
    assert_eq!(
        f.execute().unwrap(),
        ScalableLeafExit::EntryDeclined(MemoryStatus::Unsupported)
    );
    unchanged(&f, &before, &state, &ram);
    f.system = SystemState::new(
        PSTATE_EL0T | PSTATE_IL_MASK,
        0,
        El1Registers::new(0, 0, 0, 0, 0),
    )
    .unwrap();
    assert!(matches!(
        f.execute(),
        Err(ScalableExecutionError::MemoryAuthority {
            cause: ProcessMemoryError::IllegalExecutionState,
            ..
        })
    ));
    unchanged(&f, &before, &state, &ram);
}

#[test]
fn q16_native_aligned_residue8_and_other_residues() {
    for word in [LD1Q_ZA_P0_X5, ST1Q_ZA_P0_X5] {
        for residue in [0, 8, 1, 15] {
            let mut f = Fixture::new(word, wide_target(), wide_target(), None);
            f.registers.x[5] += residue as u64;
            let mut ram = f.storage.bytes();
            let mut expected = f.registers.clone();
            expected.x[3] = 7;
            let mut scalable = f.scalable.clone();
            if word == LD1Q_ZA_P0_X5 {
                scalable.write_za(0, &ram[residue..residue + VL]).unwrap();
            } else {
                ram[residue..residue + VL].fill(0x6d);
            }
            assert_eq!(f.execute().unwrap(), ScalableLeafExit::Returned);
            assert_eq!(f.registers, expected);
            assert_eq!(
                banks(&f.registers, &f.scalable),
                banks(&expected, &scalable)
            );
            assert_eq!(f.storage.bytes(), ram);
        }
    }
}

#[test]
fn checked_q16_translation_permission_order_and_prefix() {
    // SME keeps its descriptor and uses byte parts when an unaligned quadword
    // crosses a 16-byte granule; permission and translation still fault at the
    // first inaccessible byte.
    for word in [LD1Q_ZA_P0_X5, ST1Q_ZA_P0_X5, ST2Q_Z1_P0_X5] {
        for translation in [false, true] {
            let mut f = if word == ST2Q_Z1_P0_X5 {
                Fixture::new_program(
                    &[MOV_X3_SEVEN, word, RET_X30],
                    PC,
                    VL,
                    wide_target(),
                    wide_target(),
                    Some((11, translation)),
                )
            } else {
                Fixture::new(word, wide_target(), wide_target(), Some((11, translation)))
            };
            f.registers.x[5] += 8;
            let mut ram = f.storage.bytes();
            let mut expected = f.registers.clone();
            expected.x[3] = 7;
            let state = banks(&expected, &f.scalable);
            if word == ST1Q_ZA_P0_X5 {
                ram[8..11].fill(0x6d);
            }
            assert_eq!(
                f.execute().unwrap(),
                ScalableLeafExit::MemoryFault(crate::scalable::leaf::MemoryFault {
                    status: if translation {
                        MemoryStatus::Translation
                    } else {
                        MemoryStatus::Permission
                    },
                    address: GuestAddress(RAM + if word == ST2Q_Z1_P0_X5 { 8 } else { 11 }),
                    pc: GuestAddress(PC + 4),
                    completed_bytes: if word == ST2Q_Z1_P0_X5 { 0 } else { 3 },
                })
            );
            assert_eq!(f.registers, expected);
            assert_eq!(banks(&f.registers, &f.scalable), state);
            assert_eq!(f.storage.bytes(), ram);
        }
    }
}

#[test]
fn checked_callback_and_inactive_sp_faults_reset_next_entry() {
    for translation in [false, true] {
        let mut f = Fixture::new(
            LD1B_Z1_P0_X5,
            TargetCpu::Baseline,
            TargetCpu::Baseline,
            Some((1, translation)),
        );
        let ram = f.storage.bytes();
        let mut expected = f.registers.clone();
        expected.x[3] = 7;
        let state = banks(&expected, &f.scalable);
        assert_eq!(
            f.execute().unwrap(),
            ScalableLeafExit::MemoryFault(crate::scalable::leaf::MemoryFault {
                status: if translation {
                    MemoryStatus::Translation
                } else {
                    MemoryStatus::Permission
                },
                address: GuestAddress(RAM + 1),
                pc: GuestAddress(PC + 4),
                completed_bytes: 1,
            })
        );
        assert_eq!(f.registers, expected);
        assert_eq!(banks(&f.registers, &f.scalable), state);
        assert_eq!(f.storage.bytes(), ram);
    }
    let mut f = Fixture::new(
        LD1B_Z1_P0_SP,
        TargetCpu::Baseline,
        TargetCpu::Baseline,
        None,
    );
    f.scalable.write_predicate(0, &[0; VL / 8]).unwrap();
    f.registers.sp = RAM + 1;
    let ram = f.storage.bytes();
    let mut expected = f.registers.clone();
    expected.x[3] = 7;
    let mut scalable = f.scalable.clone();
    assert_eq!(
        f.execute().unwrap(),
        ScalableLeafExit::MemoryFault(crate::scalable::leaf::MemoryFault {
            status: MemoryStatus::StackAlignment,
            address: GuestAddress(RAM + 1),
            pc: GuestAddress(PC + 4),
            completed_bytes: 0,
        })
    );
    assert_eq!(f.registers, expected);
    assert_eq!(
        banks(&f.registers, &f.scalable),
        banks(&expected, &scalable)
    );
    assert_eq!(f.storage.bytes(), ram);
    f.registers.sp = RAM;
    expected.sp = RAM;
    scalable.write_z(&mut expected, 1, &[0; VL]).unwrap();
    assert_eq!(f.execute().unwrap(), ScalableLeafExit::Returned);
    assert_eq!(f.registers, expected);
    assert_eq!(
        banks(&f.registers, &f.scalable),
        banks(&expected, &scalable)
    );
    assert_eq!(f.storage.bytes(), ram);
}
