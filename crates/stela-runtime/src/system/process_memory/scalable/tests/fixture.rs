//! A software CPU and memory domain for scalable entry tests.
use super::super::super::{SCTLR_NATIVE_NORMAL_WB, SCTLR_SP_ALIGNMENT_EL0, SourceNormalWbDomain};
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
    extended::ScalableProfile,
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
// SAFETY: no byte references escape; Arc retains the allocation through entry.
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
    ScalableProfile::new_with_features(length, mode, features, ScalableControls::new(length, true))
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
        Self::new_program_at(
            &[MOV_X3_SEVEN, word, RET_X30],
            PC,
            RAM,
            VL,
            compiler_target,
            domain_target,
            split,
            1,
            ScalableMode::new(true, true),
        )
    }
    pub(super) fn new_program(
        words: &[u32],
        guest_base: u64,
        svl_bytes: usize,
        compiler_target: TargetCpu,
        domain_target: TargetCpu,
        split: Option<(usize, bool)>,
    ) -> Self {
        Self::new_program_at(
            words,
            guest_base,
            RAM,
            svl_bytes,
            compiler_target,
            domain_target,
            split,
            2,
            ScalableMode::new(true, true),
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new_program_at(
        words: &[u32],
        guest_base: u64,
        ram_base: u64,
        svl_bytes: usize,
        compiler_target: TargetCpu,
        domain_target: TargetCpu,
        split: Option<(usize, bool)>,
        sme_version: u64,
        mode: ScalableMode,
    ) -> Self {
        Self::new_program_at_with_lower_bits(
            words,
            guest_base,
            ram_base,
            svl_bytes,
            compiler_target,
            domain_target,
            split,
            sme_version,
            mode,
            LOWER_BITS,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new_program_at_with_lower_bits(
        words: &[u32],
        guest_base: u64,
        ram_base: u64,
        svl_bytes: usize,
        compiler_target: TargetCpu,
        domain_target: TargetCpu,
        split: Option<(usize, bool)>,
        sme_version: u64,
        mode: ScalableMode,
        lower_bits: u8,
    ) -> Self {
        Self::new_program_at_with_lower_bits_and_data_rights(
            words,
            guest_base,
            ram_base,
            svl_bytes,
            compiler_target,
            domain_target,
            split,
            sme_version,
            mode,
            lower_bits,
            DATA_RIGHTS,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new_program_at_with_lower_bits_and_data_rights(
        words: &[u32],
        guest_base: u64,
        ram_base: u64,
        svl_bytes: usize,
        compiler_target: TargetCpu,
        domain_target: TargetCpu,
        split: Option<(usize, bool)>,
        sme_version: u64,
        mode: ScalableMode,
        lower_bits: u8,
        data_rights: AccessPermissions,
    ) -> Self {
        Self::new_program_at_with_source_code_page(
            words,
            guest_base,
            ram_base,
            svl_bytes,
            compiler_target,
            domain_target,
            split,
            sme_version,
            mode,
            lower_bits,
            data_rights,
            None,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn new_program_at_with_source_code_page(
        words: &[u32],
        guest_base: u64,
        ram_base: u64,
        svl_bytes: usize,
        compiler_target: TargetCpu,
        domain_target: TargetCpu,
        split: Option<(usize, bool)>,
        sme_version: u64,
        mode: ScalableMode,
        lower_bits: u8,
        data_rights: AccessPermissions,
        original_code_page: Option<&[u8]>,
    ) -> Self {
        assert!(
            compiler_target.supported(),
            "actual host lacks required native test recipe"
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
                MemoryView::new(Arc::clone(&backing), ram_base, 0, boundary, data_rights).unwrap(),
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
        let controls = fixed_with_lower_bits(Arc::clone(&ids), &domain, true, lower_bits).unwrap();
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
        let system = SystemState::new(PSTATE_EL0T, 0, El1Registers::new(0, 0, 0, 0, 0)).unwrap();
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
                &mut self.registers,
                &mut self.scalable,
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
