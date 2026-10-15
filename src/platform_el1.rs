//! Input adapter for the generic owned software EL1 runtime. No raw native entry.

pub(super) const DEFAULT_BLOCK_BUDGET: usize = 1000;
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};
use stela_compiler::{GuestAddress, GuestState, TargetCpu};
use stela_runtime::{
    blocks::{
        OwnedRamExtent, PhysicalRamRange, SoftwareEl1Config, SoftwareEl1Machine,
        SoftwareEl1Profile, SoftwareEl1Request, SourceRamDeclaration, SourceRamPermissions,
        ThreadState,
    },
    system::{
        state::{El1Registers, SystemState},
        translation_controls::RegisterValues,
    },
};

const MAX_DECLARATION_BYTES: u64 = 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    address_space: u64,
    initial_pc: u64,
    pstate_misc: u64,
    sp_el0: u64,
    registers: super::RegisterInput,
    el1: El1,
    translation: Translation,
    capacity: Vec<Range>,
    initialized: Vec<Extent>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct El1 {
    elr: u64,
    spsr: u64,
    esr: u64,
    far: u64,
    vbar: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Translation {
    sctlr_el1: u64,
    tcr_el1: u64,
    ttbr0_el1: u64,
    ttbr1_el1: u64,
    mair_el1: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Range {
    source_pa: u64,
    bytes: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Extent {
    source_pa: u64,
    path: PathBuf,
    sha256: String,
    readable: bool,
    writable: bool,
    executable: bool,
}

pub(crate) fn run(
    input: &Path,
    profile: SoftwareEl1Profile,
    target: TargetCpu,
    cache_directory: PathBuf,
    request: SoftwareEl1Request,
) -> Result<serde_json::Value> {
    let mut bytes = Vec::new();
    File::open(input)?
        .take(MAX_DECLARATION_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_DECLARATION_BYTES,
        "software EL1 declaration exceeds input bound"
    );
    let declaration: Input = serde_json::from_slice(&bytes)?;
    let directory = input.parent().unwrap_or(Path::new("."));
    let mut initialized = Vec::new();
    let mut source_inputs = Vec::new();
    for extent in declaration.initialized {
        let path = directory.join(extent.path);
        let file = File::open(&path)?;
        ensure!(
            file.metadata()?.is_file(),
            "software EL1 source is not an ordinary file"
        );
        let mut data = Vec::new();
        file.take(stela_runtime::memory::MAX_IMAGE_MEMORY_BYTES + 1)
            .read_to_end(&mut data)?;
        ensure!(
            data.len() as u64 <= stela_runtime::memory::MAX_IMAGE_MEMORY_BYTES,
            "software EL1 source exceeds memory bound"
        );
        let actual = stela_core::sha256(&data);
        ensure!(
            actual == extent.sha256,
            "software EL1 source hash differs: {}",
            path.display()
        );
        source_inputs.push(serde_json::json!({"path":path,"sha256":actual,"bytes":data.len(),"source_pa":extent.source_pa}));
        initialized.push(OwnedRamExtent {
            source_pa: extent.source_pa,
            bytes: data,
            permissions: SourceRamPermissions {
                readable: extent.readable,
                writable: extent.writable,
                executable: extent.executable,
            },
        });
    }
    let registers = declaration.registers;
    let thread = ThreadState {
        pc: GuestAddress(declaration.initial_pc),
        registers: GuestState {
            x: registers.x,
            sp: registers.sp,
            nzcv: registers.nzcv,
            reserved: registers.reserved,
            v: registers.v,
            fpcr: registers.fpcr,
            fpsr: registers.fpsr,
        },
    };
    let system = SystemState::new(
        declaration.pstate_misc,
        declaration.sp_el0,
        El1Registers::new(
            declaration.el1.elr,
            declaration.el1.spsr,
            declaration.el1.esr,
            declaration.el1.far,
            declaration.el1.vbar,
        ),
    )
    .map_err(|error| anyhow::anyhow!("software EL1 initial System: {error:?}"))?;
    let values = declaration.translation;
    let machine = SoftwareEl1Machine::new(SoftwareEl1Config {
        profile,
        cache_directory,
        ram: SourceRamDeclaration {
            address_space: declaration.address_space,
            target,
            declared_capacity: declaration
                .capacity
                .into_iter()
                .map(|range| PhysicalRamRange {
                    source_pa: range.source_pa,
                    bytes: range.bytes,
                })
                .collect(),
            initialized,
        },
        thread,
        system,
        translation: RegisterValues {
            sctlr_el1: values.sctlr_el1,
            tcr_el1: values.tcr_el1,
            ttbr0_el1: values.ttbr0_el1,
            ttbr1_el1: values.ttbr1_el1,
            mair_el1: values.mair_el1,
        },
    })
    .context("create actual owned software EL1 machine")?;
    let report = machine.run_to_shutdown(request)?;
    let translation = match report.translation {
        Ok(values) => {
            serde_json::json!({"sctlr_el1":values.sctlr_el1,"tcr_el1":values.tcr_el1,"ttbr0_el1":values.ttbr0_el1,"ttbr1_el1":values.ttbr1_el1,"mair_el1":values.mair_el1})
        }
        Err(error) => serde_json::json!({"unavailable":error}),
    };
    let ram: Vec<_> = report.ram.into_iter().map(|range| serde_json::json!({"source_pa":range.source_pa,"bytes":range.bytes,"sha256":range.sha256})).collect();
    let declared_capacity: Vec<_> = report
        .declared_capacity
        .into_iter()
        .map(|range| serde_json::json!({"source_pa":range.source_pa,"bytes":range.bytes}))
        .collect();
    let initialized_ram: Vec<_> = report.initialized_ram.into_iter().map(|extent|serde_json::json!({"source_pa":extent.range.source_pa,"bytes":extent.range.bytes,"readable":extent.permissions.readable,"writable":extent.permissions.writable,"executable":extent.permissions.executable,"sha256":extent.sha256})).collect();
    Ok(serde_json::json!({
        "kind":"owned-software-el1-diagnostic","profile":format!("{profile:?}"),"target_cpu":target.id(),
        "declaration_sha256":stela_core::sha256(&bytes),"source_inputs":source_inputs,
        "stop":report.stop,"pc":report.thread.pc.0,"state":super::register_json(&report.thread.registers),
        "system":format!("{:#?}",report.system),"translation":translation,"accounting":report.accounting,
        "native_observation":report.native_observation,"memory_observation":report.memory_observation,"register_observation":report.register_observation,
        "compiler_source_sha256":report.compiler_source_sha256,"ram_after":ram,"declared_capacity":declared_capacity,"initialized_ram":initialized_ram,
        "scope":"Fresh declared software PE and actual owned initialized RAM. Unsupported effects decline explicitly; this does not establish native hardware-state adoption, full OS boot or installer compatibility."
    }))
}
