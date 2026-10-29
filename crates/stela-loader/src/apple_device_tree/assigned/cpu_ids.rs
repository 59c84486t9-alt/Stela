//! Explicit CPU-ID/count and watchdog-record projection. The caller checks
//! the original consumers; this recipe grants no hardware or execution owner.
use super::*;
use stela_soc_data::board::assigned::RegisterRange;

const TRIGGER: &str = "trigger-config";
const RECORD: usize = 16;

#[derive(Debug, Clone, Copy, Default)]
pub enum CpuIdRecipe<'a> {
    #[default]
    Preserve,
    /// Original AppleARMCPU indexes max_cpus by cpu-id; the watchdog selects
    /// a 16-byte record by that ID after translating reg to a logical PE.
    /// See iboot-handoff.md for the independently pinned original consumers.
    DenseWithWatchdog {
        original: &'a DeviceTree,
        /// Digest of the immutable original bytes. A source whose parsed
        /// representation does not serialize byte-exactly is refused.
        original_sha256: [u8; 32],
        watchdog_path: &'a str,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpuIdMapping {
    pub slot: GuestSlotId,
    pub path: String,
    pub reg: u32,
    pub original_id: u32,
    pub projected_id: u32,
    pub watchdog_record: [u8; RECORD],
    pub coresight: RegisterRange,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchdogProjection {
    pub path: String,
    pub original_tree_sha256: [u8; 32],
    pub original_sha256: [u8; 32],
    pub projected_sha256: [u8; 32],
    pub original_records: usize,
    pub projected_records: usize,
}

pub(super) struct Prepared {
    mappings: Vec<CpuIdMapping>,
    watchdog: Option<WatchdogProjection>,
    table: Vec<u8>,
}

fn range(node: &Node, property: &str) -> Result<RegisterRange> {
    let raw = bytes(node, property)?;
    ensure!(
        raw.len() == 16,
        "CPU ID recipe requires complete {property} range"
    );
    let (base, size) = (
        u64::from_le_bytes(raw[..8].try_into()?),
        u64::from_le_bytes(raw[8..].try_into()?),
    );
    ensure!(
        base != 0 && size >= 4 && base.checked_add(size).is_some(),
        "invalid CPU ID recipe {property} extent"
    );
    Ok(RegisterRange { base, bytes: size })
}
fn watchdog(node: &Node) -> bool {
    node.property("compatible")
        .is_some_and(|p| p.value.split(|b| *b == 0).any(|s| s == b"wdt,s5l8960x"))
}

impl Prepared {
    pub(super) fn prepare(
        plan: &Plan<'_>,
        tree: &DeviceTree,
        source: &SourceBindings<'_>,
    ) -> Result<Self> {
        let CpuIdRecipe::DenseWithWatchdog {
            original,
            original_sha256,
            watchdog_path,
        } = source.cpu_ids
        else {
            return Ok(Self {
                mappings: Vec::new(),
                watchdog: None,
                table: Vec::new(),
            });
        };
        ensure!(
            plan.profile().soc == 0x8112,
            "CPU ID/watchdog source family is unqualified"
        );
        ensure!(
            original_sha256 != [0; 32] && digest(original) == original_sha256,
            "CPU ID recipe original source identity mismatch"
        );
        validate_tree(&original.root, 0)?;
        ensure!(
            canonical_path(watchdog_path) && !watchdog_path.starts_with("/cpus/"),
            "noncanonical watchdog recipe path"
        );
        ensure!(
            source
                .counts
                .iter()
                .filter(|f| f.path == CPUS
                    && f.property == "max_cpus"
                    && matches!(f.count, Count::Pes))
                .count()
                == 1,
            "dense CPU IDs require the same-plan max_cpus count"
        );
        let original_cpus = original.node(CPUS).context("CPU ID source lacks /cpus")?;
        let current_cpus = tree.node(CPUS).context("CPU ID input lacks /cpus")?;
        ensure!(
            !original_cpus.children.is_empty()
                && original_cpus.children.len() <= 256
                && original_cpus.children.len() == current_cpus.children.len(),
            "CPU ID recipe requires the complete original CPU roster"
        );
        let original_wdt = original
            .node(watchdog_path)
            .context("CPU ID source lacks watchdog")?;
        let current_wdt = tree
            .node(watchdog_path)
            .context("CPU ID input lacks watchdog")?;
        ensure!(
            watchdog(original_wdt) && watchdog(current_wdt),
            "unqualified watchdog record consumer"
        );
        for field in ["name", "compatible", "reg", "AAPL,phandle"] {
            ensure!(
                bytes(original_wdt, field)? == bytes(current_wdt, field)?,
                "watchdog source identity/{field} changed"
            );
        }
        let reg = bytes(original_wdt, "reg")?;
        ensure!(
            !reg.is_empty() && reg.len().is_multiple_of(16),
            "watchdog register geometry is incomplete"
        );
        for pair in reg.as_chunks::<16>().0 {
            let base = u64::from_le_bytes(pair[..8].try_into()?);
            let size = u64::from_le_bytes(pair[8..].try_into()?);
            ensure!(
                base != 0
                    && base.is_multiple_of(4)
                    && size >= 4
                    && base.checked_add(size).is_some(),
                "watchdog register extent is invalid"
            );
        }
        let table = bytes(original_wdt, TRIGGER)?;
        ensure!(
            table.len() == original_cpus.children.len() * RECORD
                && bytes(current_wdt, TRIGGER)? == table,
            "watchdog table differs from complete original per-PE records"
        );
        // This bounded recipe accounts for one complete watchdog consumer. A
        // second such table must get its own jointly checked recipe.
        fn tables(node: &Node) -> usize {
            usize::from(watchdog(node) && node.property(TRIGGER).is_some())
                + node.children.iter().map(tables).sum::<usize>()
        }
        ensure!(
            tables(&original.root) == 1 && tables(&tree.root) == 1,
            "CPU ID recipe has unaccounted watchdog consumers"
        );
        let mut ids = BTreeSet::new();
        let mut physical = BTreeSet::new();
        let mut source_rows = Vec::new();
        for (original_cpu, current_cpu) in original_cpus.children.iter().zip(&current_cpus.children)
        {
            shape(original_cpu, plan.profile().soc)?;
            let name = original_cpu.name().context("CPU ID source lacks name")?;
            ensure!(
                current_cpu.name() == Some(name),
                "CPU ID input reordered original nodes"
            );
            for property in &original_cpu.properties {
                if !matches!(
                    property.name(),
                    "state" | "timebase-frequency" | "fixed-frequency" | "peripheral-frequency"
                ) {
                    ensure!(
                        current_cpu.property(property.name()) == Some(property),
                        "CPU ID source property {} changed",
                        property.name()
                    );
                }
            }
            let id = word(original_cpu, "cpu-id")?;
            ensure!(
                (id as usize) < original_cpus.children.len() && ids.insert(id),
                "original CPU IDs do not cover the complete watchdog table"
            );
            let range = range(original_cpu, "coresight-reg")?;
            let record: [u8; RECORD] =
                table[id as usize * RECORD..(id as usize + 1) * RECORD].try_into()?;
            let address = u64::from_le_bytes(record[..8].try_into()?);
            ensure!(
                address.is_multiple_of(4)
                    && address >= range.base
                    && address
                        .checked_add(4)
                        .is_some_and(|end| end <= range.base + range.bytes)
                    && physical.insert(address),
                "watchdog record is outside its unique original CPU range"
            );
            source_rows.push((name, id, record, range));
        }
        for (index, row) in source_rows.iter().enumerate() {
            ensure!(
                !source_rows[..index]
                    .iter()
                    .any(|previous| previous.3.base < row.3.base + row.3.bytes
                        && row.3.base < previous.3.base + previous.3.bytes),
                "original CPU watchdog ranges overlap"
            );
        }
        let mut mappings = Vec::new();
        let mut projected = Vec::new();
        for pe in plan.pes() {
            let binding = source
                .nodes
                .iter()
                .find(|b| b.slot == pe.slot)
                .context("CPU ID plan lacks source binding")?;
            let (name, id, record, coresight) = source_rows
                .iter()
                .find(|row| row.0 == binding.name)
                .context("CPU ID plan lacks original CPU")?;
            ensure!(
                word(original_cpus.child(name).unwrap(), "reg")? == pe.reg
                    && pe.logical == mappings.len()
                    && pe.logical < 256,
                "CPU ID plan differs from source/logical ordering"
            );
            projected.extend_from_slice(record);
            mappings.push(CpuIdMapping {
                slot: pe.slot,
                path: format!("{CPUS}/{name}"),
                reg: pe.reg,
                original_id: *id,
                projected_id: u32::try_from(pe.logical)?,
                watchdog_record: *record,
                coresight: *coresight,
            });
        }
        Ok(Self {
            watchdog: Some(WatchdogProjection {
                path: watchdog_path.into(),
                original_tree_sha256: original_sha256,
                original_sha256: Sha256::digest(table).into(),
                projected_sha256: Sha256::digest(&projected).into(),
                original_records: source_rows.len(),
                projected_records: mappings.len(),
            }),
            mappings,
            table: projected,
        })
    }
    pub(super) fn preserves_reference(&self, id: u32) -> bool {
        self.watchdog.is_none()
            || self
                .mappings
                .iter()
                .any(|m| m.original_id == id && m.projected_id == id)
    }
    pub(super) fn apply(
        self,
        tree: &mut DeviceTree,
    ) -> Result<(Vec<CpuIdMapping>, Option<WatchdogProjection>)> {
        if let Some(watchdog) = &self.watchdog {
            for mapping in &self.mappings {
                ensure!(
                    word(
                        tree.node(&mapping.path)
                            .context("projected CPU ID path disappeared")?,
                        "cpu-id"
                    )? == mapping.original_id,
                    "CPU ID candidate differs from verified source"
                );
            }
            for mapping in &self.mappings {
                tree.set_property(
                    &mapping.path,
                    "cpu-id",
                    mapping.projected_id.to_le_bytes().to_vec(),
                )?;
            }
            tree.set_property(&watchdog.path, TRIGGER, self.table)?;
        }
        Ok((self.mappings, self.watchdog))
    }
}
