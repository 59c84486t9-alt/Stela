//! Block translations from and to the persistent translation store
//! (`crate::translations`): a fetch page is read and hashed once, its
//! record looked up once, and each block of it compiled in a context the
//! record has is rebased instead of compiled. A block the store's process
//! already prepared at the same PC (another thread's, or ahead-of-time
//! translation's) is installed as it is. A block compiled anew is offered
//! back, with what the host needs to compile it again at the probe
//! addresses (`translations::prove`).
use super::{Devices, FETCH_PAGE, Host, Machine, Preparation, Variant};
use crate::translations::{Digest, PAGE_BYTES, Record};
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use stela_compiler::block::CompiledBlock;

/// A same-process prepared block together with its complete admitted input.
/// The page key and context remain independent lookup bindings.
#[derive(Debug, Clone)]
pub struct SharedTranslation {
    pub(super) input: Vec<u8>,
    pub(super) block: CompiledBlock,
    pub(super) preparation: Arc<Preparation>,
    key: Digest,
    page: u64,
    pc: u64,
    context: Digest,
}
impl SharedTranslation {
    pub fn input(&self) -> &[u8] {
        &self.input
    }
    pub fn block(&self) -> &CompiledBlock {
        &self.block
    }
    pub fn preparation(&self) -> &Arc<Preparation> {
        &self.preparation
    }
    pub(super) fn matches(&self, key: &Digest, pc: u64, context: &Digest, source: &[u8]) -> bool {
        self.key == *key
            && self.pc == pc
            && self.context == *context
            && self.page == pc & !(PAGE_BYTES as u64 - 1)
            && self.preparation.context(self.page) == *context
            && source.get(..self.input.len()) == Some(self.input.as_slice())
            && self.block.source_bytes <= self.input.len()
            && self
                .block
                .native
                .source_map
                .first()
                .is_some_and(|(at, _)| at.0 == pc)
    }
}

/// The Arc payload/header and every privately owned vector allocation. This
/// excludes allocator bookkeeping and shared immutable preparation storage.
fn translation_bytes(input_capacity: usize, block: &CompiledBlock) -> usize {
    use core::mem::size_of;
    let bytes = [
        size_of::<SharedTranslation>() + 2 * size_of::<usize>(),
        input_capacity,
        block.native.x86_64_code.capacity(),
        block.native.source_map.capacity() * size_of::<(stela_compiler::GuestAddress, usize)>(),
        block.direct_exits.capacity() * size_of::<stela_compiler::x86_64::chain::DirectExit>(),
        block.fault_recovery.capacity() * size_of::<stela_compiler::block::FaultRecovery>(),
    ];
    block.fault_recovery.iter().fold(
        bytes.into_iter().fold(0usize, usize::saturating_add),
        |total, row| {
            total.saturating_add(
                row.bindings.capacity() * size_of::<stela_compiler::block::RecoveryBinding>(),
            )
        },
    )
}

/// The store a host keeps for the engine.
pub trait Translations {
    /// The record of the page whose bytes hash to `key`, if the store has
    /// a valid one.
    fn record(&mut self, key: &Digest) -> Option<Arc<Record>>;
    /// The block at `pc` of the page whose bytes hash to `key`, prepared
    /// in `context` at that very PC since the record was read, if the
    /// store has one: shared, so a store other machines reach copies none
    /// of it while they wait.
    fn prepared(
        &mut self,
        _key: &Digest,
        _pc: u64,
        _context: &Digest,
    ) -> Option<Arc<SharedTranslation>> {
        None
    }
    /// A block the engine compiled from a page the store had no entry for.
    fn offer(&mut self, offer: Offer);
}

/// A block compiled anew, and how it was compiled. Emission fields are private;
/// only read-only provenance and the sealed same-process handoff are exposed.
///
/// ```compile_fail
/// fn replace_source(offer: &mut stela_engine::machine::Offer) {
///     offer.input.clear();
/// }
/// ```
#[derive(Debug, Clone)]
pub struct Offer {
    pub(super) key: Digest,
    /// The guest address of its fetch page.
    pub(super) page: u64,
    pub(super) pc: u64,
    pub(super) context: Digest,
    /// The admitted words the compiler was given.
    pub(super) input: Vec<u8>,
    pub(super) preparation: Arc<Preparation>,
    /// The entry PCs of its static successors, for translation ahead of
    /// execution.
    pub(super) successors: Vec<u64>,
    pub(super) block: CompiledBlock,
}

impl Offer {
    pub(crate) fn retained_bytes(&self) -> usize {
        translation_bytes(self.input.capacity(), &self.block)
    }
    /// Off-path preparation from canonical immutable input. No native template
    /// or copied site can be supplied; this owner emits the block itself.
    pub(crate) fn compile(
        key: Digest,
        page: u64,
        pc: u64,
        context: Digest,
        input: Vec<u8>,
        preparation: Arc<Preparation>,
    ) -> Option<Self> {
        if page != pc & !(PAGE_BYTES as u64 - 1) || preparation.context(page) != context {
            return None;
        }
        let block = preparation.compile_input(&input, pc).ok()?;
        Some(Self {
            key,
            page,
            pc,
            context,
            input,
            preparation,
            successors: Vec::new(),
            block,
        })
    }
    pub fn key(&self) -> Digest {
        self.key
    }
    pub fn page(&self) -> u64 {
        self.page
    }
    pub fn pc(&self) -> u64 {
        self.pc
    }
    pub fn context(&self) -> Digest {
        self.context
    }
    pub fn input(&self) -> &[u8] {
        &self.input
    }
    pub fn preparation(&self) -> &Arc<Preparation> {
        &self.preparation
    }
    pub fn successors(&self) -> &[u64] {
        &self.successors
    }
    pub fn block(&self) -> &CompiledBlock {
        &self.block
    }

    /// Keep this same-process emission and its complete private
    /// source/profile/template binding. No factory accepts portable site tags.
    ///
    /// ```compile_fail
    /// fn substitute(shared: &mut stela_engine::machine::engine::SharedTranslation) {
    ///     shared.block.fault_recovery.clear();
    /// }
    /// ```
    pub fn shared(self) -> Arc<SharedTranslation> {
        Arc::new(SharedTranslation {
            input: self.input,
            block: self.block,
            preparation: self.preparation,
            key: self.key,
            page: self.page,
            pc: self.pc,
            context: self.context,
        })
    }

    /// Its block's stored form: the block compiled again at both probe
    /// addresses of its page, proven to move only by them
    /// ([`translations::prove`](crate::translations::prove)).
    pub fn prove(&self) -> Option<crate::translations::Entry> {
        let probes = crate::translations::probe_displacements(self.page).map(|displacement| {
            self.preparation
                .compile_input(&self.input, self.pc.wrapping_add(displacement))
                .ok()
        });
        let [Some(first), Some(second)] = &probes else {
            return None;
        };
        crate::translations::prove(
            &self.block,
            &self.input,
            self.page,
            self.pc,
            self.context,
            [first, second],
        )
    }
}

/// The fetch pages kept for their blocks at most; when full, or when the
/// host's memory runs low, the least recently used quarter is let go. A
/// page let go is read, hashed and looked up again for its next block,
/// which only a block not yet installed needs.
#[cfg(not(test))]
pub(super) const KEPT_PAGES: usize = 4096;
#[cfg(test)]
pub(super) const KEPT_PAGES: usize = 4;

/// A fetch page's bytes, as read for its first block, and its record.
pub(super) struct StoredPage {
    pub(super) key: Digest,
    pub(super) bytes: Box<[u8; PAGE_BYTES]>,
    pub(super) record: Option<Arc<Record>>,
    /// `Machine::page_uses` at its last use.
    used: u64,
}

impl<H: Host, D: Devices> Machine<H, D> {
    /// The stored page holding `pc` at `physical`, read and looked up on
    /// its first block; `None` without a store, when the page cannot be
    /// read whole or when a host breakpoint or trace point lies in it,
    /// which shortens blocks in ways no context names.
    ///
    /// `source` is the block's window as just read: a page whose kept
    /// bytes differ from it (guest memory written without the IC
    /// maintenance that invalidates the page) is read and hashed again, so
    /// a stored or offered block always has the bytes the guest holds now.
    pub(super) fn stored_page(
        &mut self,
        pc: u64,
        physical: u64,
        source: &[u8],
    ) -> Option<&StoredPage> {
        let frame = physical & !(FETCH_PAGE - 1);
        let offset = (physical - frame) as usize;
        if self
            .pages
            .get(&frame)
            .is_some_and(|stored| stored.bytes.get(offset..offset + source.len()) != Some(source))
        {
            self.pages.remove(&frame);
        }
        if !self.pages.contains_key(&frame) {
            self.host.translations()?;
            let page = pc & !(FETCH_PAGE - 1);
            if self
                .breakpoints
                .iter()
                .chain(&self.traces)
                .any(|&stop| stop & !(FETCH_PAGE - 1) == page)
            {
                return None;
            }
            let mut bytes = Box::new([0u8; PAGE_BYTES]);
            if !self.host.read_ram(frame, bytes.as_mut_slice()) {
                return None;
            }
            let key = Digest::of(bytes.as_slice());
            let record = self.host.translations()?.record(&key);
            if self.pages.len() >= self.kept_pages
                || (!self.pages.is_empty() && self.host.memory_low())
            {
                self.forget_least_used_pages();
            }
            self.pages.insert(
                frame,
                StoredPage {
                    key,
                    bytes,
                    record,
                    used: 0,
                },
            );
        }
        self.page_uses += 1;
        let page = self.pages.get_mut(&frame)?;
        page.used = self.page_uses;
        Some(page)
    }

    /// Keep `KEPT_PAGES` across `machines` machines, which each keep their
    /// own: an equal share each, but no fewer than a sixteenth.
    pub(super) fn share_kept_pages(&mut self, machines: usize) {
        self.kept_pages = (KEPT_PAGES / machines.max(1)).max(KEPT_PAGES.div_ceil(16));
    }

    /// Let the least recently used quarter of the kept pages go, at least
    /// one.
    fn forget_least_used_pages(&mut self) {
        let mut uses: Vec<u64> = self.pages.values().map(|page| page.used).collect();
        let quarter = (uses.len() / 4).max(1);
        if quarter == uses.len() {
            self.pages.clear();
            return;
        }
        let (_, &mut least_kept, _) = uses.select_nth_unstable(quarter);
        self.pages.retain(|_, page| page.used >= least_kept);
    }

    /// The entry context of blocks compiled for `variant` through
    /// `preparation` in the page at `page` ([`Preparation::context`]).
    pub(super) fn stored_context(
        &mut self,
        variant: Variant,
        preparation: &Preparation,
        page: u64,
    ) -> Digest {
        let class = crate::translations::address_class(page);
        let variant = Variant {
            guarded_page: false,
            ..variant
        };
        *self
            .stored_contexts
            .entry((variant, class))
            .or_insert_with(|| preparation.context(page))
    }
}

#[cfg(test)]
pub(super) mod tests;
