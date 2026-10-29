//! Quota programming and PTD publication in the native source order.
//! t8112pmp b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c,
//! VA1003cbc..1003ee8 interleaves each fourth group's response BEFORE that
//! group's hardware store. This component supplies neither command consumption
//! nor event housekeeping/ACK, native startup, IRQ admission or cache capacity.
use super::policy::{GROUPS, HardwareUpdate, Inputs, Policy};
use crate::Result;
use alloc::rc::Rc;
use stela_contracts::Refusal;
use stela_contracts::refuse;
use {
    crate::ptd::transport::notifications::LocalNotifications, stela_contracts::bus::Access,
    stela_contracts::bus::MmioDevice, stela_contracts::bus::Width, stela_soc_data::ptd::Range,
    stela_soc_data::ptd::UPDATE_OFFSET,
};

/// Exact backing identity, not execution/completion permission. The
/// cache constructs it once; moving that cache preserves the same identity.
#[derive(Clone)]
pub struct Identity(Rc<()>);
impl Identity {
    pub(crate) fn new() -> Self {
        Self(Rc::new(()))
    }
    fn same(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }
}

/// One cache/PTD association. The T8112 resource constructor checks
/// their same registered RAM and physical join before issuing this once.
/// Dropping this binding never reopens that cache's native publisher slot.
pub struct Binding {
    identity: Identity,
    local: LocalNotifications,
}
impl Binding {
    pub(crate) fn new(identity: Identity, local: LocalNotifications) -> Self {
        Self { identity, local }
    }
}

/// A live borrow of the quota owner, not a copied word array. Err must
/// precede a write's effect; successful writes modify that same AP-facing bank.
/// The production adapter borrows EmptyResource and checks its real lifecycle.
pub trait Bank {
    fn identity(&self) -> &Identity;
    fn validate(&self) -> Result<()>;
    fn read_quota(&mut self, group: u8) -> Result<u32>;
    fn write_quota(&mut self, group: u8, value: u32, access: &mut Access<'_>) -> Result<()>;
}

/// Selected range/counts and initialized native register/context mode.
/// Original context initialization VA1032ef4 clears suppression; nonzero or
/// unknown remains refused. This input is not an Apple handoff observation.
#[derive(Clone, Copy)]
pub struct Configuration {
    pub response_range: u32,
    pub response_words: u32,
    pub ack_words: u32,
    pub retain_attributes: bool,
    pub suppression: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Progress {
    pub completed_passes: u64,
    pub programmed_words: u64,
    pub response_publications: u64,
    pub current_group: Option<u8>,
}
struct Store {
    update: HardwareUpdate,
    word: Option<u32>,
}
struct Cursor {
    group: u8,
    response_done: bool,
    store: Option<Store>,
    allocate_after: bool,
}
impl Cursor {
    fn new(allocate_after: bool) -> Self {
        Self {
            group: 0,
            response_done: false,
            store: None,
            allocate_after,
        }
    }
}

/// Real effects. Failed stores/publications keep their exact cursor;
/// completed prefixes cannot replay. Policy is private while a pass is live.
pub struct Publisher {
    binding: Binding,
    range: Range,
    policy: Policy,
    configuration: Configuration,
    old_targets: [Option<u32>; GROUPS],
    weights: [u8; GROUPS],
    attributes: u32,
    cursor: Option<Cursor>,
    allocated: bool,
    progress: Progress,
    failed: Option<Refusal>,
}
impl Publisher {
    pub fn new(
        binding: Binding,
        bank: &mut impl Bank,
        rows: &[u8],
        mut inputs: Inputs,
        configuration: Configuration,
    ) -> Result<Self> {
        if !binding.identity.same(bank.identity()) {
            return Err(refuse!("native quota bank differs from its actual binding"));
        }
        bank.validate()?;
        if configuration.suppression != Some(0) {
            return Err(refuse!(
                "native quota hardware-write suppression mode is unqualified"
            ));
        }
        if !(1..=8).contains(&configuration.response_words) || configuration.ack_words != 1 {
            return Err(refuse!("native quota response/ACK format is not qualified"));
        }
        let range = binding
            .local
            .bank()
            .ranges()
            .into_iter()
            .find(|range| range.id == configuration.response_range)
            .ok_or(refuse!(
                "native quota response range has no actual PTD owner"
            ))?;
        if Some(range.count)
            != configuration
                .response_words
                .checked_add(configuration.ack_words)
        {
            return Err(refuse!(
                "native quota response counts differ from the actual PTD range"
            ));
        }
        // Parse/check rows before borrowing any real seed. Input seed numbers
        // are replaced by reads from this exact bank, not trusted as RAM.
        let parsed = Policy::new(rows, inputs)?;
        let active = parsed.active_groups();
        let covered = if configuration.response_words == 8 {
            u32::MAX
        } else {
            (1u32 << (configuration.response_words * 4)) - 1
        };
        if active & !covered != 0 {
            return Err(refuse!(
                "native quota response range does not cover every source group"
            ));
        }
        let mut old_targets = [None; GROUPS];
        for (group, old) in old_targets.iter_mut().enumerate() {
            if active & (1 << group) != 0 {
                let word = bank.read_quota(group as u8)?;
                inputs.quota_words[group] = word;
                *old = Some(word & 0x1ff);
            }
        }
        Ok(Self {
            binding,
            range,
            policy: Policy::new(rows, inputs)?,
            configuration,
            old_targets,
            weights: [0; GROUPS],
            attributes: 0,
            cursor: None,
            allocated: false,
            progress: Progress::default(),
            failed: None,
        })
    }
    pub fn policy(&self) -> &Policy {
        &self.policy
    }
    pub fn progress(&self) -> Progress {
        Progress {
            current_group: self.cursor.as_ref().map(|cursor| cursor.group),
            ..self.progress
        }
    }
    pub fn notifications(&self) -> &LocalNotifications {
        &self.binding.local
    }
    pub(super) fn response_range(&self) -> &Range {
        &self.range
    }
    pub(super) fn response_words(&self) -> u32 {
        self.configuration.response_words
    }
    pub(super) fn check_bank_identity(&self, bank: &impl Bank) -> Result<()> {
        if self.binding.identity.same(bank.identity()) {
            Ok(())
        } else {
            Err(refuse!(
                "native quota callback borrowed another actual cache owner"
            ))
        }
    }
    /// The sole MC service now keeps the source restart/event, including
    /// every existing dirty word. Defaults or commands may supersede startup's
    /// allocation before final publication; no effect completes here.
    pub(super) fn begin_service_pass(&mut self) -> Result<()> {
        if let Some(reason) = self.failed.clone() {
            return Err(reason);
        }
        if self.cursor.is_some() {
            return Err(refuse!("native quota publication prefix is still retained"));
        }
        self.allocated = false;
        Ok(())
    }
    pub(super) fn idle(&self) -> Result<()> {
        if let Some(reason) = self.failed.clone() {
            return Err(reason);
        }
        if self.cursor.is_some() {
            return Err(refuse!("native quota publication prefix is still retained"));
        }
        if self.allocated {
            return Err(refuse!(
                "native quota allocation still awaits final publication"
            ));
        }
        Ok(())
    }
    /// Only call after source new-data consumption. A lane supplies no
    /// command ID, hardware completion, capacity or independently owned effect.
    pub fn set_request(&mut self, group: u8, lane: u16) -> Result<bool> {
        self.idle()?;
        self.policy.set_request(group, lane)
    }
    pub fn allocate(&mut self) -> Result<()> {
        self.idle()?;
        self.policy.allocate()?;
        self.allocated = true;
        Ok(())
    }
    /// Execute source startup's request clear/default rebuild and schedule its
    /// real publisher. After advance completes, the service must perform any
    /// reached metric registrations before allocating. This does not mark it
    /// running, drain work, or authorize native command consumption.
    pub fn start_defaults(&mut self) -> Result<()> {
        self.idle()?;
        self.policy.start_defaults()?;
        self.cursor = Some(Cursor::new(false));
        Ok(())
    }
    /// Begin only the pending publisher work selected by the real source
    /// caller. Construction itself schedules no publication. Both MC startup
    /// and op1 call defaults, whose VA1003f7c tail-calls the publisher before
    /// allocation. Startup additionally registers reached metrics between the
    /// defaults publisher and allocator. This does not execute
    /// or certify the caller's independently owned lifecycle/housekeeping.
    pub fn publish_pending(&mut self) -> Result<()> {
        if let Some(reason) = self.failed.clone() {
            return Err(reason);
        }
        if self.cursor.is_some() {
            return Err(refuse!("native quota publication prefix is still retained"));
        }
        self.allocated = false;
        self.cursor = Some(Cursor::new(false));
        Ok(())
    }
    /// Start the final event publisher AFTER its independently owned source
    /// housekeeping. This component cannot check that other effect or ACK.
    pub fn publish_allocated(&mut self) -> Result<()> {
        if let Some(reason) = self.failed.clone() {
            return Err(reason);
        }
        if self.cursor.is_some() || !self.allocated {
            return Err(refuse!(
                "native quota final publication has no completed allocation"
            ));
        }
        self.publish_pending()
    }
    pub fn awaiting_publication(&self) -> bool {
        self.allocated
    }
    /// Source op1 has two real passes: publish/program the rebuilt defaults,
    /// then allocate. The caller must perform source event housekeeping before
    /// starting final publication with publish_allocated. Neither emits an ACK.
    pub fn set_budget_payload(&mut self, payload: u64) -> Result<()> {
        self.idle()?;
        self.policy.set_budget_payload(payload);
        if let Err(reason) = self.policy.defaults() {
            self.failed = Some(reason.clone());
            return Err(reason);
        }
        self.cursor = Some(Cursor::new(true));
        Ok(())
    }
    pub fn advance(&mut self, bank: &mut impl Bank, access: &mut Access<'_>) -> Result<()> {
        if let Some(reason) = self.failed.clone() {
            return Err(reason);
        }
        if !self.binding.identity.same(bank.identity()) {
            return Err(refuse!(
                "native quota callback borrowed another actual cache owner"
            ));
        }
        while let Some(cursor) = self.cursor.as_ref() {
            bank.validate()?;
            if cursor.group as usize == GROUPS {
                let count = next(self.progress.completed_passes)?;
                if cursor.allocate_after {
                    self.policy.allocate()?;
                    self.allocated = true;
                }
                self.cursor = None;
                self.progress.completed_passes = count;
                continue;
            }
            let group = cursor.group;
            let index = usize::from(group);
            if !cursor.response_done {
                if group % 4 == 3
                    && let Some(response) = self.policy.response_block(group / 4)?
                {
                    let count = next(self.progress.response_publications)?;
                    let entry = self.range.start + u32::from(response.block());
                    self.binding
                        .local
                        .bank()
                        .clone()
                        .write(
                            UPDATE_OFFSET + u64::from(entry) * 8,
                            Width::Double,
                            response.packed(),
                            access,
                        )
                        .map_err(|_| {
                            refuse!("native quota actual PTD response publication refused")
                        })?;
                    self.progress.response_publications = count;
                    if let Err(reason) = self.policy.complete_response(response) {
                        self.failed = Some(reason.clone());
                        return Err(reason);
                    }
                }
                self.cursor.as_mut().unwrap().response_done = true;
            }
            if self.cursor.as_ref().unwrap().store.is_none()
                && let Some(update) = self.policy.hardware_update(group)?
            {
                // VA1003e04 checks the all-ones sentinel before comparing
                // the unmasked target. A wrapped target can itself be MAX;
                // that value must never acquire unchanged-store permission.
                if self.old_targets[index] != Some(u32::MAX)
                    && self.old_targets[index] == Some(update.scaled_units())
                {
                    if let Err(reason) = self.policy.complete_hardware(update) {
                        self.failed = Some(reason.clone());
                        return Err(reason);
                    }
                } else {
                    // Keep the pending store BEFORE changing the native
                    // old-target cache, so a later read/store refusal cannot
                    // turn its retry into an unchanged-target skip.
                    let units = update.scaled_units();
                    self.cursor.as_mut().unwrap().store = Some(Store { update, word: None });
                    self.old_targets[index] = Some(units);
                }
            }
            if self.cursor.as_ref().unwrap().store.is_some() {
                if self
                    .cursor
                    .as_ref()
                    .unwrap()
                    .store
                    .as_ref()
                    .unwrap()
                    .word
                    .is_none()
                {
                    if self.configuration.retain_attributes && self.weights[index] == 0 {
                        let current = bank.read_quota(group)?;
                        self.weights[index] = ((current >> 16) & 0xff) as u8;
                        self.attributes |= ((current >> 30) & 1) << group;
                    }
                    let store = self.cursor.as_mut().unwrap().store.as_mut().unwrap();
                    let mut word = store.update.scaled_units() & 0x1ff;
                    if self.configuration.retain_attributes {
                        word |= u32::from(self.weights[index]) << 16;
                        word |= ((self.attributes >> group) & 1) << 30;
                    }
                    store.word = Some(word);
                }
                let count = next(self.progress.programmed_words)?;
                let word = self
                    .cursor
                    .as_ref()
                    .unwrap()
                    .store
                    .as_ref()
                    .unwrap()
                    .word
                    .unwrap();
                bank.write_quota(group, word, access)?;
                let store = self.cursor.as_mut().unwrap().store.take().unwrap();
                self.progress.programmed_words = count;
                if let Err(reason) = self.policy.complete_hardware(store.update) {
                    self.failed = Some(reason.clone());
                    return Err(reason);
                }
            }
            let cursor = self.cursor.as_mut().unwrap();
            cursor.group += 1;
            cursor.response_done = false;
        }
        Ok(())
    }
}
fn next(count: u64) -> Result<u64> {
    count.checked_add(1).ok_or(refuse!(
        "native quota publication accounting exhausted before effect"
    ))
}
