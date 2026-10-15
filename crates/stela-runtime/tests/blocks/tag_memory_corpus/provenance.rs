//! External original-frame provenance and effective-control validation.
//!
//! Expected outputs are owned by the outer comparator. The execution backend
//! receives only validated input state and controls from captured/source-verified
//! authority, never an expected result or a comparison classification.
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use stela_compiler::{
    GuestState,
    aarch64::{
        Register,
        tag_memory::{self, Operand},
    },
};
use stela_core::sha256;
use stela_runtime::memory::tags::TAG_GRANULE_BYTES;

pub(super) const STATE_BYTES: usize = 784;
pub(super) const RAM_BYTES: usize = 8192;
pub(super) const TAG_BYTES: usize = RAM_BYTES / TAG_GRANULE_BYTES;
pub(super) const PRIVILEGED: u32 = 1;
pub(super) const CHECK_SP: u32 = 2;
pub(super) const ALLOCATION_ENABLED: u32 = 4;
pub(super) const TAGGED: u32 = 8;
pub(super) const DENY_READ: u32 = 16;
pub(super) const DENY_WRITE: u32 = 32;
const KNOWN_FLAGS: u32 =
    PRIVILEGED | CHECK_SP | ALLOCATION_ENABLED | TAGGED | DENY_READ | DENY_WRITE;
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_ASSET_BYTES: u64 = 1024 * 1024 * 1024;
const INPUT_STRIDE: usize = 832;
const INPUT_STATE: usize = 8;
const RESULT_HEADER: usize = 1024;
const RESULT_SPSR: usize = 256;
const RESULT_ESR: usize = 280;
const RESULT_ELR: usize = 288;
const IRG_PRE_RGSR: usize = 848;
const IRG_PRE_GCR: usize = 856;
const IRG_POST_RGSR: usize = 864;
const IRG_POST_GCR: usize = 872;
const EL0_POST_SCTLR: usize = 848;
const EL0_POST_TCR: usize = 856;
const EL0_POST_MAIR: usize = 864;
const EL0_POST_TTBR: usize = 872;
const EL0_POST_RGSR: usize = 888;
const EL0_POST_GCR: usize = 896;
const BULK_POST_CONTROL: usize = 912;
const ORIGINAL_VECTOR_OFFSET: usize = 320;
const STATE_VECTOR_OFFSET: usize = 264;
const VECTOR_BYTES: usize = 512;
const ORIGINAL_FPCR: usize = 264;
const ORIGINAL_FPSR: usize = 272;
const SUCCESS_SVC_ESR: u64 = 0x5600_0123;
const DATA_ALIGNMENT_DFSC: u64 = 0x21;
const TRANSLATION_FAULT_MIN: u64 = 4;
const TRANSLATION_FAULT_MAX: u64 = 7;
const LOGICAL_TAG_SHIFT: u32 = 56;
const BLOCK_WORD_BYTES: u32 = 4;
const BLOCK_SIZE_MASK: u64 = 15;
const EL0_PRE_SCTLR: usize = 912;
const EL0_PRE_TCR: usize = 920;
const EL0_PRE_MAIR: usize = 928;
const EL0_PFR1: usize = 904;
const EL0_SECOND_PTE: usize = 936;
const EL0_FAR: usize = 880;
const BULK_PRE_CONTROL: usize = 848;
const BULK_FAR: usize = 976;
const BULK_PRE_PTE: usize = 984;
const PRE_TAG_PLANE: usize = RESULT_HEADER + RAM_BYTES;
const CONTROL_BYTES: usize = 8;
const BULK_SCTLR: usize = BULK_PRE_CONTROL;
const BULK_TCR: usize = BULK_PRE_CONTROL + CONTROL_BYTES;
const BULK_MAIR: usize = BULK_PRE_CONTROL + CONTROL_BYTES * 2;
const BULK_GMID: usize = BULK_PRE_CONTROL + CONTROL_BYTES * 3;
const BULK_DCZID: usize = BULK_PRE_CONTROL + CONTROL_BYTES * 4;
const BULK_GCR: usize = BULK_PRE_CONTROL + CONTROL_BYTES * 5;
const BULK_RGSR: usize = BULK_PRE_CONTROL + CONTROL_BYTES * 6;
const BULK_PFR1: usize = BULK_PRE_CONTROL + CONTROL_BYTES * 7;
const A64_RET: u32 = 0xd65f_03c0;
const INSTRUCTION_BYTES: usize = 4;
const INITIALIZER_SETUP_BYTES: usize = INSTRUCTION_BYTES * 5;
const MTE_FEATURE_SHIFT: u32 = 8;
const MTE_FEATURE_MASK: u64 = 15;
const MTE2_FEATURE: u64 = 2;
const MTE3_FEATURE: u64 = 3;
const INITIAL_TAG_SEED: u64 = 3;
const INITIAL_TAG_STEP: u64 = 7;
const TAG_VALUE_MASK: u64 = 15;
const TOP_BYTE_MASK: u64 = 255 << 56;
const PERMISSION_FAULT_MIN: u64 = 12;
const PERMISSION_FAULT_MAX: u64 = 15;
const FAULT_STATUS_MASK: u64 = 63;
const RESULT_PRE_FPCR: usize = 832;
const RESULT_PRE_FPSR: usize = 840;
const STATE_FPCR: usize = 776;
const STATE_FPSR: usize = 780;
const SCTLR_SA: u64 = 1 << 3;
const SCTLR_SA0: u64 = 1 << 4;
const SCTLR_ATA: u64 = 1 << 43;
const SCTLR_ATA0: u64 = 1 << 42;
const SCTLR_TCF: u64 = 3 << 40;
const SCTLR_TCF0: u64 = 3 << 38;
const TCR_T0SZ: u64 = 63;
const TCR_TBI0: u64 = 1 << 37;
const TCR_EPD1: u64 = 1 << 23;
const PSTATE_MODE: u64 = 31;
const PSTATE_EL0T: u64 = 0;
const PSTATE_EL1T: u64 = 4;
const NZCV_MASK: u64 = 15 << 28;
const PTE_EL0_ACCESS: u64 = 1 << 6;
const PTE_READ_ONLY: u64 = 1 << 7;
const PTE_ATTRIBUTE_SHIFT: u32 = 2;
const PTE_ATTRIBUTE_MASK: u64 = 7;
const MAIR_TAGGED_NORMAL: u64 = 0xf0;
const MAIR_NORMAL_WB: u64 = 0xff;
const HEADER_PFR1: usize = 4 * 8;
const HEADER_SCTLR: usize = 9 * 8;
const TAG_GRANULE: usize = TAG_GRANULE_BYTES;
const PAGE_BYTES: u64 = 4096;
const UNUSED_GEOMETRY: u32 = TAG_GRANULE as u32;

#[derive(Deserialize)]
pub(super) struct Asset {
    pub path: PathBuf,
    pub sha256: String,
    pub bytes: u64,
    pub role: String,
}
#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Layout {
    Irg,
    El0Tag,
    BulkTag,
}
#[derive(Deserialize)]
struct Authority {
    layout: Layout,
    receipt: String,
    inputs: String,
    results: String,
    cases: String,
    functions: String,
    subjects: String,
    elf: String,
    assembly: String,
    ram: Option<String>,
    configuration: String,
    verification: String,
}
#[derive(Deserialize)]
pub(super) struct HistoricalBridge {
    pub receipt: String,
    pub source_ledger: String,
    pub native_entries: String,
    pub native_inspection: String,
    pub review: String,
    pub current_source_review: String,
}
#[derive(Deserialize)]
pub(super) struct Manifest {
    schema_version: u32,
    kind: String,
    pub frame_count: usize,
    pub assets: BTreeMap<String, Asset>,
    converter_assets: Vec<String>,
    pub normalized_inputs: String,
    pub normalized_expected: String,
    authorities: BTreeMap<String, Authority>,
    pub historical_full_bridge: Option<HistoricalBridge>,
}
#[derive(Deserialize)]
struct Configuration {
    schema_version: u32,
    kind: String,
    original_receipt_sha256: String,
    assembly_sha256: String,
    elf_sha256: String,
    verification_sha256: String,
    fields: BTreeMap<String, u64>,
    unused_controls: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Input {
    pub case_id: String,
    authority_id: String,
    raw_case_index: usize,
    pub kind: String,
    pub word: u32,
    pub instruction_pc: u64,
    pub source_hex: String,
    pub state_hex: String,
    pub ram_hex: Option<String>,
    pub tags_hex: Option<String>,
    pub flags: Option<u32>,
    pub ram_address: Option<u64>,
    pub denied_start: Option<u64>,
    pub denied_end: Option<u64>,
    gmid_bytes: Option<u32>,
    dczid_bytes: Option<u32>,
    rgsr: Option<u64>,
    gcr: Option<u64>,
    allocation_enabled: Option<bool>,
}
#[derive(Deserialize)]
pub(super) struct Expected {
    pub case_id: String,
    pub status: String,
    pub state_hex: String,
    pub ram_hex: Option<String>,
    pub tags_hex: Option<String>,
    pub rgsr: Option<u64>,
    pub gcr: Option<u64>,
    pub classification: String,
    pub allowed_ram_hex: Option<String>,
    pub allowed_tags_hex: Option<String>,
    pub original_fault: Value,
    pub original_controls_post: Value,
}
#[derive(Clone, Copy)]
pub(super) struct OriginalGeneration {
    pub gcr: u64,
    pub rgsr: u64,
}
pub(super) struct Controls {
    pub pstate_misc: u64,
    pub privileged: bool,
    pub allocation_enabled: bool,
    pub check_sp: bool,
    pub address_bits: u8,
    pub top_byte_ignore: bool,
    pub feature: u64,
    /// None is explicitly unused storage for dedicated nonbulk operations, not
    /// an invented pre-execution RGSR/GCR readback.
    pub generation: Option<OriginalGeneration>,
    pub gmid_bytes: u32,
    pub dczid_bytes: u32,
}
pub(super) struct ValidatedInput {
    pub input: Input,
    pub registers: GuestState,
    pub controls: Controls,
    pub ram: Vec<u8>,
    pub tags: Vec<u8>,
}
pub(super) struct ComparisonAuthority {
    pub sp_oracle_excluded: bool,
    pub permitted_unknown: bool,
    pub raw_fault: Value,
}
pub(super) struct ValidatedFrame {
    pub execution: ValidatedInput,
    pub comparison: ComparisonAuthority,
}
struct Capture {
    layout: Layout,
    input: Vec<u8>,
    results: Vec<u8>,
    stride: usize,
    case_count: usize,
    functions: Vec<Value>,
    subjects: Vec<Value>,
    elf: Vec<u8>,
    ram: Vec<u8>,
    configuration: Configuration,
}
pub(super) struct Corpus {
    pub manifest: Manifest,
    pub manifest_sha256: String,
    directory: PathBuf,
    manifest_path: PathBuf,
    captures: BTreeMap<String, Capture>,
}

pub(super) fn unhex(text: &str) -> Result<Vec<u8>> {
    ensure!(text.len().is_multiple_of(2), "odd hex length");
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
        .collect()
}
pub(super) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(DIGITS[usize::from(byte >> 4)] as char);
        result.push(DIGITS[usize::from(byte & 15)] as char);
    }
    result
}
fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let file = std::fs::File::open(path)?;
    ensure!(
        file.metadata()?.is_file() && file.metadata()?.len() <= limit,
        "external file exceeds bounds"
    );
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= limit,
        "external file grew beyond bounds"
    );
    Ok(bytes)
}
fn u64_at(bytes: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..offset + 8)
            .context("truncated original control")?
            .try_into()?,
    ))
}
fn integer(value: &Value, key: &str) -> Result<u64> {
    value[key]
        .as_u64()
        .with_context(|| format!("missing original {key}"))
}
pub(super) fn state_bytes(state: &GuestState) -> &[u8] {
    assert_eq!(std::mem::size_of::<GuestState>(), STATE_BYTES);
    // SAFETY: the repr(C) GuestState is an initialized integer-only layout with
    // no padding. The returned immutable borrow ends before any service writes.
    unsafe { std::slice::from_raw_parts((state as *const GuestState).cast(), STATE_BYTES) }
}
fn state(bytes: &[u8]) -> Result<GuestState> {
    ensure!(
        bytes.len() == STATE_BYTES && std::mem::size_of::<GuestState>() == STATE_BYTES,
        "State layout mismatch"
    );
    let mut result = GuestState::default();
    // SAFETY: all fields accept every bit pattern; the destination is exclusive.
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            (&mut result as *mut GuestState).cast(),
            STATE_BYTES,
        )
    };
    Ok(result)
}
fn field(configuration: &Configuration, key: &str) -> Result<u64> {
    configuration
        .fields
        .get(key)
        .copied()
        .with_context(|| format!("missing source-verified {key}"))
}

impl Corpus {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = read_bounded(path, MAX_MANIFEST_BYTES)?;
        let manifest: Manifest = serde_json::from_slice(&bytes)?;
        ensure!(
            manifest.schema_version == 1 && manifest.kind == "stela_mte_original_corpus",
            "unsupported corpus schema"
        );
        ensure!(
            !manifest.converter_assets.is_empty()
                && manifest.normalized_inputs != manifest.normalized_expected,
            "missing converter or separated corpus assets"
        );
        let mut corpus = Self {
            manifest,
            manifest_sha256: sha256(&bytes),
            directory: path.parent().context("manifest has no parent")?.into(),
            manifest_path: path.into(),
            captures: BTreeMap::new(),
        };
        corpus.guard()?;
        for converter in &corpus.manifest.converter_assets {
            ensure!(
                corpus.manifest.assets.contains_key(converter),
                "unbound converter source"
            );
        }
        for (name, authority) in &corpus.manifest.authorities {
            let receipt: Value = serde_json::from_slice(&corpus.read(&authority.receipt)?)?;
            let mut original_assets = vec![
                (&authority.inputs, "inputs.bin"),
                (&authority.results, "results.bin"),
                (&authority.cases, "cases.json"),
                (&authority.functions, "functions.json"),
                (&authority.subjects, "subjects.json"),
                (&authority.elf, "guest.elf"),
                (&authority.assembly, "guest.S"),
            ];
            if let Some(ram) = &authority.ram {
                original_assets.push((ram, "memory.bin"));
            }
            for (id, name) in original_assets {
                let asset = corpus.asset(id)?;
                ensure!(
                    receipt["files"][name]["sha256"].as_str() == Some(asset.sha256.as_str())
                        && receipt["files"][name]["bytes"].as_u64() == Some(asset.bytes),
                    "original receipt does not bind authority file {name}"
                );
            }
            let configuration: Configuration =
                serde_json::from_slice(&corpus.read(&authority.configuration)?)?;
            ensure!(
                configuration.schema_version == 1
                    && configuration.kind == "stela_mte_source_configuration",
                "missing explicit source configuration"
            );
            for (id, identity) in [
                (&authority.receipt, &configuration.original_receipt_sha256),
                (&authority.assembly, &configuration.assembly_sha256),
                (&authority.elf, &configuration.elf_sha256),
                (&authority.verification, &configuration.verification_sha256),
            ] {
                ensure!(
                    &corpus.asset(id)?.sha256 == identity,
                    "source configuration authority mismatch"
                );
            }
            let verification: Value =
                serde_json::from_slice(&corpus.read(&authority.verification)?)?;
            ensure!(
                verification["kind"] == "independent_source_authority_and_fault_address_supplement"
                    && verification["status"] == "passed",
                "source verification audit is not successful"
            );
            if authority.layout == Layout::El0Tag {
                let proofs = verification["nonbulk_initializer_ELF_proofs"]
                    .as_array()
                    .context("missing source initializer verification")?;
                let proof = proofs
                    .iter()
                    .find(|proof| {
                        proof["receipt_sha256"] == configuration.original_receipt_sha256
                            && proof["assembly_sha256"] == configuration.assembly_sha256
                            && proof["elf_sha256"] == configuration.elf_sha256
                    })
                    .context("source verification does not bind this initializer")?;
                ensure!(
                    field(&configuration, "ram_address")? == integer(proof, "ram_address")?
                        && field(&configuration, "initial_tag_seed")? == INITIAL_TAG_SEED
                        && field(&configuration, "initial_tag_step")? == INITIAL_TAG_STEP,
                    "source-derived initializer differs from audited executable"
                );
                let elf = corpus.read(&authority.elf)?;
                let offset = usize::try_from(integer(proof, "seed_loop_elf_offset")?)?
                    .checked_sub(INITIALIZER_SETUP_BYTES)
                    .context("audited initializer setup offset underflows")?;
                let code = unhex(
                    proof["seed_complete_bytes"]
                        .as_str()
                        .context("missing initializer instruction bytes")?,
                )?;
                ensure!(
                    elf.get(offset..offset + code.len()) == Some(code.as_slice()),
                    "audited initializer bytes differ from original ELF"
                );
            }
            let cases: Vec<Value> = serde_json::from_slice(&corpus.read(&authority.cases)?)?;
            ensure!(!cases.is_empty(), "empty original capture");
            let input = corpus.read(&authority.inputs)?;
            let results = corpus.read(&authority.results)?;
            ensure!(
                input.len() == cases.len() * INPUT_STRIDE && results.len() > RESULT_HEADER,
                "original capture dimensions mismatch"
            );
            let stride = (results.len() - RESULT_HEADER) / cases.len();
            ensure!(
                results.len() == RESULT_HEADER + stride * cases.len(),
                "partial original frame"
            );
            let expected_stride = match authority.layout {
                Layout::Irg => RESULT_HEADER,
                Layout::El0Tag => RESULT_HEADER + RAM_BYTES + TAG_BYTES,
                Layout::BulkTag => RESULT_HEADER + RAM_BYTES + TAG_BYTES * 2,
            };
            ensure!(
                stride == expected_stride,
                "unsupported original frame layout"
            );
            let unused: BTreeSet<_> = configuration
                .unused_controls
                .iter()
                .map(String::as_str)
                .collect();
            let required = if authority.layout == Layout::El0Tag {
                BTreeSet::from(["GCR_EL1", "RGSR_EL1", "GMID_EL1", "DCZID_EL0"])
            } else {
                BTreeSet::new()
            };
            ensure!(
                unused == required,
                "unused control authority differs from instruction layout"
            );
            corpus.captures.insert(
                name.clone(),
                Capture {
                    layout: authority.layout,
                    input,
                    results,
                    stride,
                    case_count: cases.len(),
                    functions: serde_json::from_slice(&corpus.read(&authority.functions)?)?,
                    subjects: serde_json::from_slice(&corpus.read(&authority.subjects)?)?,
                    elf: corpus.read(&authority.elf)?,
                    ram: authority
                        .ram
                        .as_ref()
                        .map(|id| corpus.read(id))
                        .transpose()?
                        .unwrap_or_default(),
                    configuration,
                },
            );
        }
        Ok(corpus)
    }
    fn asset(&self, id: &str) -> Result<&Asset> {
        self.manifest
            .assets
            .get(id)
            .with_context(|| format!("unbound asset {id}"))
    }
    pub fn path(&self, id: &str) -> Result<PathBuf> {
        Ok(self.directory.join(&self.asset(id)?.path))
    }
    pub fn read(&self, id: &str) -> Result<Vec<u8>> {
        let asset = self.asset(id)?;
        ensure!(
            asset.bytes <= MAX_ASSET_BYTES && !asset.role.is_empty(),
            "invalid external asset bounds/role"
        );
        let bytes = read_bounded(&self.path(id)?, MAX_ASSET_BYTES)?;
        ensure!(
            bytes.len() as u64 == asset.bytes && sha256(&bytes) == asset.sha256,
            "external asset identity mismatch: {id}"
        );
        Ok(bytes)
    }
    pub fn guard(&self) -> Result<()> {
        ensure!(
            sha256(&read_bounded(&self.manifest_path, MAX_MANIFEST_BYTES)?) == self.manifest_sha256,
            "corpus manifest changed"
        );
        for id in self.manifest.assets.keys() {
            self.read(id)?;
        }
        Ok(())
    }
    pub fn validate(&self, input: Input) -> Result<ValidatedFrame> {
        let capture = self
            .captures
            .get(&input.authority_id)
            .context("missing input authority")?;
        ensure!(
            input.raw_case_index < capture.case_count,
            "case index outside captured authority"
        );
        ensure!(
            input.case_id == format!("{}:{}", input.authority_id, input.raw_case_index),
            "case identity mismatch"
        );
        let raw = capture
            .input
            .get(input.raw_case_index * INPUT_STRIDE..(input.raw_case_index + 1) * INPUT_STRIDE)
            .context("case outside original input")?;
        let record = capture
            .results
            .get(
                RESULT_HEADER + input.raw_case_index * capture.stride
                    ..RESULT_HEADER + (input.raw_case_index + 1) * capture.stride,
            )
            .context("case outside original output")?;
        let function = usize::try_from(u64_at(raw, 0)?)?;
        let op = capture
            .functions
            .get(function)
            .context("missing original function")?;
        let subject = capture
            .subjects
            .get(function)
            .context("missing original subject")?;
        ensure!(
            u64::from(input.word) == integer(op, "word")?
                && input.instruction_pc == integer(subject, "instruction_pc")?,
            "normalized source differs from original"
        );
        let elf_offset = usize::try_from(integer(subject, "elf_offset")?)?;
        ensure!(
            capture.elf.get(elf_offset..elf_offset + 4)
                == Some(input.word.to_le_bytes().as_slice()),
            "original ELF word differs"
        );
        let canonical = unhex(&input.source_hex)?;
        ensure!(
            canonical.len() == INSTRUCTION_BYTES * 2
                && canonical[..INSTRUCTION_BYTES] == input.word.to_le_bytes()
                && canonical[INSTRUCTION_BYTES..] == A64_RET.to_le_bytes(),
            "unsupported bounded original source sequence"
        );
        ensure!(
            subject["canonical_source_hex"].as_str() == Some(input.source_hex.as_str()),
            "normalized canonical source differs from bound original subject"
        );
        let mut initial = raw[INPUT_STATE..INPUT_STATE + STATE_BYTES].to_vec();
        initial[STATE_FPCR..STATE_FPCR + 4]
            .copy_from_slice(&(u64_at(record, RESULT_PRE_FPCR)? as u32).to_le_bytes());
        initial[STATE_FPSR..STATE_FPSR + 4]
            .copy_from_slice(&(u64_at(record, RESULT_PRE_FPSR)? as u32).to_le_bytes());
        ensure!(
            unhex(&input.state_hex)? == initial,
            "normalized initial State lacks original authority"
        );
        let registers = state(&initial)?;
        let spsr = u64_at(record, RESULT_SPSR)?;
        let privileged = match spsr & PSTATE_MODE {
            PSTATE_EL0T => false,
            PSTATE_EL1T => true,
            _ => anyhow::bail!("unsupported original guest mode"),
        };
        let operand = tag_memory::decode(input.word).context("original source is not MTE")?;
        ensure!(operand.is_valid(), "invalid original operands");
        let random = matches!(operand, Operand::RandomTag { .. });
        ensure!(
            random == (capture.layout == Layout::Irg) && random == (input.kind == "IRG"),
            "instruction/control authority mismatch"
        );
        ensure!(
            capture.layout == Layout::BulkTag || !matches!(operand, Operand::BulkTags { .. }),
            "missing required captured bulk controls"
        );
        let (sctlr, tcr, mair, feature, generation, geometry) = match capture.layout {
            Layout::Irg => (
                u64_at(&capture.results, HEADER_SCTLR)?,
                None,
                None,
                u64_at(&capture.results, HEADER_PFR1)?,
                Some(OriginalGeneration {
                    gcr: u64_at(record, IRG_PRE_GCR)?,
                    rgsr: u64_at(record, IRG_PRE_RGSR)?,
                }),
                (UNUSED_GEOMETRY, UNUSED_GEOMETRY),
            ),
            Layout::El0Tag => (
                u64_at(record, EL0_PRE_SCTLR)?,
                Some(u64_at(record, EL0_PRE_TCR)?),
                Some(u64_at(record, EL0_PRE_MAIR)?),
                u64_at(record, EL0_PFR1)?,
                None,
                (UNUSED_GEOMETRY, UNUSED_GEOMETRY),
            ),
            Layout::BulkTag => (
                u64_at(record, BULK_SCTLR)?,
                Some(u64_at(record, BULK_TCR)?),
                Some(u64_at(record, BULK_MAIR)?),
                u64_at(record, BULK_PFR1)?,
                Some(OriginalGeneration {
                    gcr: u64_at(record, BULK_GCR)?,
                    rgsr: u64_at(record, BULK_RGSR)?,
                }),
                (
                    BLOCK_WORD_BYTES << (u64_at(record, BULK_GMID)? & BLOCK_SIZE_MASK),
                    BLOCK_WORD_BYTES << (u64_at(record, BULK_DCZID)? & BLOCK_SIZE_MASK),
                ),
            ),
        };
        let feature = (feature >> MTE_FEATURE_SHIFT) & MTE_FEATURE_MASK;
        ensure!(
            matches!(feature, MTE2_FEATURE | MTE3_FEATURE),
            "unsupported original MTE feature authority"
        );
        let allocation_enabled = sctlr & if privileged { SCTLR_ATA } else { SCTLR_ATA0 } != 0;
        let check_sp = sctlr & if privileged { SCTLR_SA } else { SCTLR_SA0 } != 0;
        ensure!(
            sctlr & if privileged { SCTLR_TCF } else { SCTLR_TCF0 } == 0,
            "unsupported captured tag-check mode"
        );
        let (address_bits, top_byte_ignore) = if let Some(tcr) = tcr {
            ensure!(tcr & TCR_EPD1 != 0, "upper translation is not disabled");
            (u8::try_from(64 - (tcr & TCR_T0SZ))?, tcr & TCR_TBI0 != 0)
        } else {
            (0, false)
        };
        let mut ram = Vec::new();
        let mut tags = Vec::new();
        if random {
            let OriginalGeneration { gcr, rgsr } =
                generation.context("missing IRG pre-control capture")?;
            ensure!(
                input.gcr == Some(gcr)
                    && input.rgsr == Some(rgsr)
                    && input.allocation_enabled == Some(allocation_enabled),
                "normalized IRG controls differ from actual pre-readbacks"
            );
            ensure!(
                !privileged && gcr >> 16 == 0,
                "unsupported original IRG profile"
            );
            ensure!(
                input.flags.is_none() && input.ram_hex.is_none() && input.tags_hex.is_none(),
                "IRG has invented memory controls"
            );
        } else {
            ensure!(
                input.kind == "memory"
                    && input.gcr.is_none()
                    && input.rgsr.is_none()
                    && input.allocation_enabled.is_none(),
                "dedicated memory has invented generation inputs"
            );
            ram = unhex(input.ram_hex.as_deref().context("missing original RAM")?)?;
            tags = unhex(input.tags_hex.as_deref().context("missing original tags")?)?;
            ensure!(
                ram == capture.ram && ram.len() == RAM_BYTES && tags.len() == TAG_BYTES,
                "initial memory lacks original authority"
            );
            let address = field(&capture.configuration, "ram_address")?;
            ensure!(
                input.ram_address == Some(address),
                "RAM address lacks source authority"
            );
            let pte = u64_at(
                record,
                if capture.layout == Layout::BulkTag {
                    BULK_PRE_PTE
                } else {
                    EL0_SECOND_PTE
                },
            )?;
            let attribute = (mair.context("missing captured MAIR")?
                >> (((pte >> PTE_ATTRIBUTE_SHIFT) & PTE_ATTRIBUTE_MASK) * 8))
                & 255;
            ensure!(
                matches!(attribute, MAIR_NORMAL_WB | MAIR_TAGGED_NORMAL),
                "unsupported captured memory attribute"
            );
            let tagged = attribute == MAIR_TAGGED_NORMAL;
            if capture.layout == Layout::BulkTag {
                ensure!(
                    tags == record[PRE_TAG_PLANE..PRE_TAG_PLANE + TAG_BYTES],
                    "bulk initial tag plane differs from actual pre-capture"
                );
                ensure!(
                    input.gmid_bytes == Some(geometry.0) && input.dczid_bytes == Some(geometry.1),
                    "bulk geometry differs from captured GMID/DCZID"
                );
            } else {
                ensure!(
                    input.gmid_bytes.is_none() && input.dczid_bytes.is_none(),
                    "unused geometry mislabeled as original capture"
                );
                ensure!(
                    field(&capture.configuration, "first_page_tagged")? == u64::from(tagged),
                    "mapping source/captured attributes differ"
                );
                let seed = field(&capture.configuration, "initial_tag_seed")?;
                let step = field(&capture.configuration, "initial_tag_step")?;
                ensure!(
                    tags.iter().enumerate().all(|(index, tag)| u64::from(*tag)
                        == (seed + step * index as u64) & TAG_VALUE_MASK),
                    "initial tags differ from source-verified initializer"
                );
            }
            let readable = privileged || pte & PTE_EL0_ACCESS != 0;
            let writable = readable && pte & PTE_READ_ONLY == 0;
            let mut flags = if privileged { PRIVILEGED } else { 0 }
                | if check_sp { CHECK_SP } else { 0 }
                | if allocation_enabled {
                    ALLOCATION_ENABLED
                } else {
                    0
                }
                | if tagged { TAGGED } else { 0 };
            if !readable {
                flags |= DENY_READ;
            }
            if !writable {
                flags |= DENY_WRITE;
            }
            let denied = !readable || !writable;
            let start = if denied {
                address
                    + if capture.layout == Layout::El0Tag {
                        PAGE_BYTES
                    } else {
                        0
                    }
            } else {
                0
            };
            let end = if denied {
                address + RAM_BYTES as u64
            } else {
                0
            };
            ensure!(
                input.flags == Some(flags)
                    && flags & !KNOWN_FLAGS == 0
                    && input.denied_start == Some(start)
                    && input.denied_end == Some(end),
                "normalized permissions/flags differ from original controls"
            );
        }
        let base = match operand {
            Operand::RandomTag { .. } => None,
            Operand::LoadTag { base, .. }
            | Operand::StoreTags { base, .. }
            | Operand::BulkTags { base, .. }
            | Operand::StorePair { base, .. } => Some(base),
        };
        let sp_oracle_excluded = check_sp
            && base == Some(Register::Sp)
            && !registers.sp.is_multiple_of(TAG_GRANULE as u64)
            && (!operand.requires_privilege() || privileged);
        let esr = u64_at(record, RESULT_ESR)?;
        let far = if random {
            Value::Null
        } else {
            Value::from(u64_at(
                record,
                if capture.layout == Layout::BulkTag {
                    BULK_FAR
                } else {
                    EL0_FAR
                },
            )?)
        };
        let permitted_unknown = if let Operand::StoreTags {
            kind,
            base,
            displacement,
            mode,
            ..
        } = operand
        {
            let original_base = match base {
                Register::X(index) => registers.x[usize::from(index)],
                Register::Sp => registers.sp,
                Register::Zero => 0,
            };
            let effective = if mode == stela_compiler::aarch64::AddressMode::PostIndex {
                original_base
            } else {
                original_base.wrapping_add(displacement as u64)
            };
            let prefix_changes = kind == tag_memory::StoreKind::ZeroTagPair
                || (kind == tag_memory::StoreKind::TagPair
                    && allocation_enabled
                    && input.flags.is_some_and(|flags| flags & TAGGED != 0));
            !sp_oracle_excluded
                && prefix_changes
                && (PERMISSION_FAULT_MIN..=PERMISSION_FAULT_MAX)
                    .contains(&(esr & FAULT_STATUS_MASK))
                && input.ram_address.is_some_and(|address| {
                    (effective & !TOP_BYTE_MASK) == address + PAGE_BYTES - TAG_GRANULE as u64
                        && far
                            .as_u64()
                            .is_some_and(|far| (far & !TOP_BYTE_MASK) == address + PAGE_BYTES)
                })
        } else {
            false
        };
        let raw_fault = serde_json::json!({"esr": esr, "far": far, "elr": u64_at(record, RESULT_ELR)?, "spsr": spsr});
        Ok(ValidatedFrame {
            execution: ValidatedInput {
                input,
                registers,
                controls: Controls {
                    pstate_misc: spsr & !NZCV_MASK,
                    privileged,
                    allocation_enabled,
                    check_sp,
                    address_bits,
                    top_byte_ignore,
                    feature,
                    generation,
                    gmid_bytes: geometry.0,
                    dczid_bytes: geometry.1,
                },
                ram,
                tags,
            },
            comparison: ComparisonAuthority {
                sp_oracle_excluded,
                permitted_unknown,
                raw_fault,
            },
        })
    }
    pub fn validate_expected(&self, frame: &ValidatedFrame, expected: &Expected) -> Result<()> {
        let input = &frame.execution;
        let comparison = &frame.comparison;
        ensure!(
            expected.case_id == input.input.case_id
                && expected.original_fault == comparison.raw_fault,
            "expected frame lacks raw original fault authority"
        );
        let capture = self
            .captures
            .get(&input.input.authority_id)
            .context("missing expected capture")?;
        let start = RESULT_HEADER + input.input.raw_case_index * capture.stride;
        let record = &capture.results[start..start + capture.stride];
        let operand =
            tag_memory::decode(input.input.word).context("missing expected source operation")?;
        let esr = u64_at(record, RESULT_ESR)?;
        let dfsc = esr & FAULT_STATUS_MASK;
        let status = if operand.requires_privilege() && !input.controls.privileged {
            "undefined_privilege"
        } else if comparison.sp_oracle_excluded {
            "stack_alignment"
        } else if esr == SUCCESS_SVC_ESR {
            "success"
        } else if dfsc == DATA_ALIGNMENT_DFSC {
            "data_alignment"
        } else if (PERMISSION_FAULT_MIN..=PERMISSION_FAULT_MAX).contains(&dfsc) {
            "permission"
        } else if (TRANSLATION_FAULT_MIN..=TRANSLATION_FAULT_MAX).contains(&dfsc) {
            "translation"
        } else {
            anyhow::bail!("unsupported raw original fault syndrome")
        };
        ensure!(
            expected.status == status,
            "normalized expected status differs from raw/source authority"
        );
        let mut original = state_bytes(&input.registers).to_vec();
        original[..RESULT_SPSR].copy_from_slice(&record[..RESULT_SPSR]);
        original[RESULT_SPSR..RESULT_SPSR + 4]
            .copy_from_slice(&((u64_at(record, RESULT_SPSR)? & NZCV_MASK) as u32).to_le_bytes());
        original[STATE_VECTOR_OFFSET..STATE_VECTOR_OFFSET + VECTOR_BYTES].copy_from_slice(
            &record[ORIGINAL_VECTOR_OFFSET..ORIGINAL_VECTOR_OFFSET + VECTOR_BYTES],
        );
        original[STATE_FPCR..STATE_FPCR + 4]
            .copy_from_slice(&(u64_at(record, ORIGINAL_FPCR)? as u32).to_le_bytes());
        original[STATE_FPSR..STATE_FPSR + 4]
            .copy_from_slice(&(u64_at(record, ORIGINAL_FPSR)? as u32).to_le_bytes());
        let selected_state = if comparison.sp_oracle_excluded {
            state_bytes(&input.registers)
        } else {
            original.as_slice()
        };
        ensure!(
            unhex(&expected.state_hex)? == selected_state,
            "expected State differs from raw original/source-only SP rule"
        );
        if capture.layout == Layout::Irg {
            ensure!(
                expected.classification == "exact_original"
                    && expected.rgsr == Some(u64_at(record, IRG_POST_RGSR)?)
                    && expected.gcr == Some(u64_at(record, IRG_POST_GCR)?),
                "expected IRG controls differ from genuine post-readbacks"
            );
            ensure!(
                expected.ram_hex.is_none() && expected.tags_hex.is_none(),
                "IRG has expected memory effects"
            );
            ensure!(
                expected.original_controls_post
                    == serde_json::json!({"RGSR_EL1":u64_at(record,IRG_POST_RGSR)?,"GCR_EL1":u64_at(record,IRG_POST_GCR)?}),
                "IRG post-control metadata differs"
            );
        } else {
            ensure!(
                expected.rgsr.is_none() && expected.gcr.is_none(),
                "memory expectation invents generation comparison"
            );
            let ram = &record[RESULT_HEADER..RESULT_HEADER + RAM_BYTES];
            let tag_start = PRE_TAG_PLANE
                + if capture.layout == Layout::BulkTag {
                    TAG_BYTES
                } else {
                    0
                };
            let tags = &record[tag_start..tag_start + TAG_BYTES];
            let selected_ram = if comparison.sp_oracle_excluded {
                input.ram.as_slice()
            } else {
                ram
            };
            let selected_tags = if comparison.sp_oracle_excluded {
                input.tags.as_slice()
            } else {
                tags
            };
            ensure!(
                unhex(
                    expected
                        .ram_hex
                        .as_deref()
                        .context("missing expected RAM")?
                )? == selected_ram
                    && unhex(
                        expected
                            .tags_hex
                            .as_deref()
                            .context("missing expected tags")?
                    )? == selected_tags,
                "expected RAM/tags differ from genuine raw frame/source-only SP rule"
            );
            let classification = if comparison.sp_oracle_excluded {
                "sp_oracle_excluded"
            } else if comparison.permitted_unknown {
                "permitted_unknown"
            } else {
                "exact_original"
            };
            ensure!(
                expected.classification == classification,
                "policy classification differs from original source/control boundary"
            );
            let post = if capture.layout == Layout::BulkTag {
                let names = [
                    "SCTLR_EL1",
                    "TCR_EL1",
                    "MAIR_EL1",
                    "GMID_EL1",
                    "DCZID_EL0",
                    "GCR_EL1",
                    "RGSR_EL1",
                    "ID_AA64PFR1_EL1",
                ];
                let mut post = serde_json::Map::new();
                for (index, name) in names.iter().enumerate() {
                    post.insert(
                        (*name).into(),
                        Value::from(u64_at(record, BULK_POST_CONTROL + index * CONTROL_BYTES)?),
                    );
                }
                Value::Object(post)
            } else {
                serde_json::json!({"sctlr":u64_at(record,EL0_POST_SCTLR)?,"tcr":u64_at(record,EL0_POST_TCR)?,"mair":u64_at(record,EL0_POST_MAIR)?,"ttbr0":u64_at(record,EL0_POST_TTBR)?,"far":u64_at(record,EL0_FAR)?,"rgsr":u64_at(record,EL0_POST_RGSR)?,"gcr":u64_at(record,EL0_POST_GCR)?,"pfr1":u64_at(record,EL0_PFR1)?})
            };
            ensure!(
                expected.original_controls_post == post,
                "post-control metadata differs from raw capture"
            );
            if comparison.permitted_unknown {
                ensure!(
                    ram == input.ram && tags == input.tags,
                    "unsupported original aborted-prefix choice"
                );
                let mut allowed_ram = input.ram.clone();
                let mut allowed_tags = input.tags.clone();
                if let Operand::StoreTags { kind, source, .. } = operand {
                    if kind == tag_memory::StoreKind::ZeroTagPair {
                        allowed_ram[PAGE_BYTES as usize - TAG_GRANULE..PAGE_BYTES as usize].fill(0);
                    } else {
                        let value = match source {
                            Register::X(index) => input.registers.x[usize::from(index)],
                            Register::Sp => input.registers.sp,
                            Register::Zero => 0,
                        };
                        allowed_tags[PAGE_BYTES as usize / TAG_GRANULE - 1] =
                            ((value >> LOGICAL_TAG_SHIFT) & TAG_VALUE_MASK) as u8;
                    }
                }
                ensure!(
                    expected.allowed_ram_hex.as_deref().map(unhex).transpose()?
                        == Some(allowed_ram)
                        && expected
                            .allowed_tags_hex
                            .as_deref()
                            .map(unhex)
                            .transpose()?
                            == Some(allowed_tags),
                    "alternative memory effects exceed the permitted source-derived prefix"
                );
            }
        }
        if !comparison.permitted_unknown {
            ensure!(
                expected.allowed_ram_hex.is_none() && expected.allowed_tags_hex.is_none(),
                "unexpected alternative memory mask"
            );
        }
        Ok(())
    }

    pub fn validate_original_word(&self, pc: u64, word: u32) -> Result<()> {
        for capture in self.captures.values() {
            for (function, subject) in capture.functions.iter().zip(&capture.subjects) {
                if integer(function, "word")? == u64::from(word)
                    && integer(subject, "instruction_pc")? == pc
                {
                    let offset = usize::try_from(integer(subject, "elf_offset")?)?;
                    ensure!(
                        capture.elf.get(offset..offset + INSTRUCTION_BYTES)
                            == Some(word.to_le_bytes().as_slice()),
                        "historical source word differs from original ELF"
                    );
                    return Ok(());
                }
            }
        }
        anyhow::bail!("historical body is not bound to an original word/PC")
    }
}
