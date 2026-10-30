//! The started executors that host guest PEs, joined to the assigned topology
//! `stela_boot_core::assigned_topology` plans from a boot bundle's source.
use crate::Result;
use alloc::vec::Vec;
pub(crate) use stela_boot_core::assigned_topology::*;
use stela_boot_core::{record::Capture, topology as native};
use stela_contracts::refuse;
use stela_soc_data::board::assigned::{AssignedCore, RetainedRoster};

/// A kept roster of started executors. Captured AP inventory alone
/// cannot construct this view: each selected AP must have acknowledged its
/// private installed Host and CPUID identity through Executors::start.
pub(crate) struct AssignedRoster<'a> {
    _bsp: BspRoster<'a>,
    _executors: &'a crate::native_smp::executor::Executors,
    cores: Vec<AssignedCore>,
}
impl<'a> AssignedRoster<'a> {
    pub(crate) fn new(
        capture: &'a Capture,
        executors: &'a crate::native_smp::executor::Executors,
        _owner: &super::host::HostOwner,
    ) -> Result<Self> {
        let bsp = BspRoster::current(capture, 0)?;
        let mut cores = bsp.cores().to_vec();
        for worker in 1..=executors.processors().len() {
            let processor = executors
                .processors()
                .iter()
                .find(|processor| processor.slot() == worker)
                .ok_or(refuse!("assigned started worker roster has a slot gap"))?;
            let index = *capture
                .selected
                .get(worker)
                .filter(|_| worker < capture.core_count as usize)
                .ok_or(refuse!("assigned worker exceeds captured physical cores"))?
                as usize;
            let source = *capture
                .processors
                .get(index)
                .filter(|_| index < capture.processor_count as usize)
                .ok_or(refuse!("assigned worker has no captured source processor"))?;
            if !source.available()
                || source.flags & native::BSP != 0
                || processor.apic_id() != source.apic_id
                || !processor.observation().matches(source)
            {
                return Err(refuse!(
                    "assigned worker differs from actual started AP identity"
                ));
            }
            cores.push(AssignedCore {
                worker,
                package: source.location.package,
                core: source.location.core,
                apic: u32::try_from(source.apic_id)
                    .map_err(|_| refuse!("assigned APIC exceeds transport width"))?,
                started: true,
            });
        }
        Ok(Self {
            _bsp: bsp,
            _executors: executors,
            cores,
        })
    }
    /// Select started workers before any Plan borrows this roster.
    /// Physical IDs stay unchanged; omitted executors remain held/parked.
    pub(crate) fn select(&mut self, workers: &[usize]) -> Result<()> {
        if workers.is_empty()
            || !workers.contains(&0)
            || workers.iter().enumerate().any(|(index, worker)| {
                workers[..index].contains(worker)
                    || !self.cores.iter().any(|core| core.worker == *worker)
            })
        {
            return Err(refuse!(
                "active source roster exceeds retained physical workers"
            ));
        }
        self.cores.retain(|core| workers.contains(&core.worker));
        Ok(())
    }
}
impl RetainedRoster for AssignedRoster<'_> {
    fn revision(&self) -> u64 {
        1
    }
    fn cores(&self) -> &[AssignedCore] {
        &self.cores
    }
}

impl AssignedRoster<'_> {
    /// Keep the workers `source` places its PEs on.
    pub(crate) fn select_for(&mut self, source: &Source<'_>, capture: &Capture) -> Result<()> {
        let workers = source.placement_workers(self, capture)?;
        self.select(&workers)
    }
}
