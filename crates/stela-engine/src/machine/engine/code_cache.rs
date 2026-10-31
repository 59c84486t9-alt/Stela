//! Invalidation and reclamation of compiled blocks when translation or code
//! changes.

use super::*;

/// The word and bit of the page of `pc` in a filter of [`FETCHED_PAGES`] bits.
fn fetched_page_bit(pc: u64) -> (usize, u64) {
    let page = pc / FETCH_PAGE;
    let bit = (page ^ page >> 16) as usize & (FETCHED_PAGES - 1);
    (bit / 64, 1 << (bit % 64))
}

impl<H: Host, D: Devices> Machine<H, D> {
    /// Check the next [`STALE_CHECKS`] reachable compiled blocks against
    /// the guest bytes they were compiled from, a sweep that goes on where
    /// the last call stopped: a diagnostic of code changed without the IC
    /// maintenance that would discard its blocks, bounded per call.
    pub fn stale_code(&mut self) -> StaleCode {
        let mut report = StaleCode::default();
        let mut bytes = Vec::new();
        let mut last = None;
        for (cursor, index) in self.index.sweep(self.stale_cursor).take(STALE_CHECKS) {
            let block = &self.blocks[index];
            bytes.resize(block.source_bytes as usize, 0);
            report.blocks += 1;
            if self.host.read_ram(block.physical, &mut bytes)
                && source_hash(&bytes) != block.source_hash
            {
                report.stale += 1;
                report.first.get_or_insert((block.pc, block.physical));
            }
            last = Some(cursor);
        }
        // A sweep that reached the last block starts over next time.
        self.stale_cursor = last.filter(|_| report.blocks == STALE_CHECKS);
        report
    }

    /// An architectural cache epoch must never wrap back to an old permission.
    pub(super) fn advance_translation_generation(&mut self) {
        self.translation_generation = self
            .translation_generation
            .checked_add(1)
            .expect("architectural translation generation exhausted");
    }

    /// The translations of the halves `halves` may have changed with no
    /// control value showing it: their lookup contexts go, so no lookup
    /// enters a block their entries name, nor does a cached fetch outlive
    /// what [`Self::fetched_through`] learnt of it.
    pub(super) fn forget_spaces(&mut self, halves: core::ops::RangeInclusive<usize>, cause: usize) {
        self.forget_contexts(halves, cause);
        self.advance_translation_generation();
    }

    /// Forget the contexts of `halves` that translate `asid`: what a TLBI of
    /// one process leaves of the others', which their entries stay good for.
    /// ASIDs compare by the eight bits every TCR.AS gives them.
    fn forget_asid(&mut self, halves: core::ops::RangeInclusive<usize>, asid: u16, cause: usize) {
        for half in halves {
            self.statistics.lookup_forgets[cause] += 1;
            self.spaces[half].retain(|space| !same_asid(&space.inputs.0, asid));
            self.recent[half] = [None; RECENT];
        }
        self.advance_translation_generation();
    }

    /// The live salts of `half`'s contexts that `asid` reaches.
    fn asid_salts(&self, half: usize, asid: u16) -> u64 {
        self.spaces[half]
            .iter()
            .filter(|space| same_asid(&space.inputs.0, asid))
            .fold(0, |salts, space| {
                salts | 1 << (space.number % chain::LOOKUP_SALTS as u64)
            })
    }

    /// [`Self::forget_spaces`] for a caller that advances the generation.
    fn forget_contexts(&mut self, halves: core::ops::RangeInclusive<usize>, cause: usize) {
        for half in halves {
            self.statistics.lookup_forgets[cause] += 1;
            self.spaces[half].clear();
            self.recent[half] = [None; RECENT];
            self.fetch_leaves[half] = 0;
            self.private_fetches[half] = false;
            self.fetched_pages[half].fill(0);
            if half == 0 {
                self.lower_globals = NO_GLOBALS;
            }
        }
    }

    /// A fetch in `half` translated through a leaf of `size` bytes. The
    /// upper half's contexts leave out the ASID until a fetch of it is
    /// non-global ([`Self::half_inputs`]): the first such fetch forgets
    /// them, as their entries may name blocks of another ASID's page.
    pub(super) fn fetched_through(&mut self, half: usize, pc: u64, size: u64, global: bool) {
        if half == 1 && !global && !self.private_fetches[1] {
            self.forget_spaces(1..=1, 3);
        }
        let (word, bit) = fetched_page_bit(pc);
        self.fetched_pages[half][word] |= bit;
        self.fetch_leaves[half] = self.fetch_leaves[half].max(size);
        self.private_fetches[half] |= !global;
        if half == 0 && global {
            let (first, last) = self.lower_globals;
            self.lower_globals = (first.min(pc), last.max(pc.saturating_add(size)));
        }
    }

    /// The span of `half` a TLBI of `first..=last` can reach of what it
    /// fetched: the leaves around them, as large as the largest one a fetch
    /// of the half translated through, if any page of those was fetched from.
    fn fetched_span(&self, half: usize, first: u64, last: u64) -> Option<(u64, u64)> {
        const UPPER: u64 = !0 << 55;
        let (low, high) = [(0, !UPPER), (UPPER, u64::MAX)][half];
        let leaf = self.fetch_leaves[half];
        if leaf == 0 || last < low || first > high {
            return None;
        }
        let mask = leaf.next_power_of_two() - 1;
        let (first, last) = (first.max(low) & !mask, last.min(high) | mask);
        let pages = (last - first) / FETCH_PAGE;
        let fetched = pages >= FETCHED_PAGES as u64
            || (0..=pages).any(|page| {
                let (word, bit) = fetched_page_bit(first + page * FETCH_PAGE);
                self.fetched_pages[half][word] & bit != 0
            });
        fetched.then_some((first, last))
    }

    /// Drop the cached fetches of the pages a TLBI reaches in the current
    /// translation: all of them if it reaches more than the cache holds.
    fn forget_fetches(&mut self, reach: mmu::tlbi::Reach) {
        let (first, last) = match reach {
            mmu::tlbi::Reach::Nothing => return,
            mmu::tlbi::Reach::All => return self.advance_translation_generation(),
            mmu::tlbi::Reach::Containing(address) => (address, address),
            mmu::tlbi::Reach::Overlapping { first, last } => (first, last),
        };
        for half in 0..2 {
            let Some((first, last)) = self.fetched_span(half, first, last) else {
                continue;
            };
            if (last - first) / FETCH_PAGE >= FETCH_CACHE as u64 {
                return self.advance_translation_generation();
            }
            for page in (first..=last).step_by(FETCH_PAGE as usize) {
                let slot = (page / FETCH_PAGE) as usize % FETCH_CACHE;
                if self.fetch[slot].is_some_and(|entry| (first..=last).contains(&entry.page)) {
                    self.fetch[slot] = None;
                }
            }
        }
    }

    /// Drop the lookup entries, of every context, of the PCs a TLBI by VA
    /// reaches ([`Self::fetched_span`]), or of `asid`'s contexts while no
    /// global page was fetched in its span of the lower half, which only
    /// such a page shares. A half whose span would cover the table forgets
    /// those contexts instead.
    pub(super) fn forget_lookups(&mut self, reach: mmu::tlbi::Reach, asid: Option<u16>) {
        let (first, last) = match reach {
            mmu::tlbi::Reach::Nothing => return,
            mmu::tlbi::Reach::All => return self.forget_spaces(0..=1, 1),
            mmu::tlbi::Reach::Containing(address) => (address, address),
            mmu::tlbi::Reach::Overlapping { first, last } => (first, last),
        };
        for half in 0..2 {
            let Some((first, last)) = self.fetched_span(half, first, last) else {
                continue;
            };
            let (global_first, global_last) = self.lower_globals;
            let scoped = asid.filter(|_| half == 0 && (last < global_first || first > global_last));
            if (last - first) / INSTRUCTION >= (chain::LOOKUP_ENTRIES / 8) as u64 {
                match scoped {
                    Some(asid) => self.forget_asid(half..=half, asid, 2),
                    None => self.forget_spaces(half..=half, 2),
                }
                continue;
            }
            let salts = match scoped {
                Some(asid) => self.asid_salts(half, asid),
                None => self.live_salts(half),
            };
            for salt in (0..chain::LOOKUP_SALTS as u64).filter(|salt| salts >> salt & 1 != 0) {
                for pc in (first..=last).step_by(INSTRUCTION as usize) {
                    self.targets
                        .forget(chain::lookup_slot(pc, salt), first..=last);
                }
            }
        }
    }

    /// A translation control changed: cached fetch translations go, and
    /// of the host's shadow what the new controls translate differently
    /// ([`Host::set_regime`]). Lookup contexts are keyed by the controls'
    /// values ([`Space`]), so a return to earlier ones finds theirs again.
    pub(super) fn controls_changed(&mut self) {
        self.derived_changed();
        self.permissions_changed();
    }

    /// Translation changed, but nothing derived from System registers:
    /// an SPRR_PERM write, which XNU makes around its writes to protected
    /// data and at thread switches, thousands of times a second.
    pub(super) fn permissions_changed(&mut self) {
        self.mirrors.close(SPRR_PERM_MIRROR);
        self.advance_translation_generation();
        self.statistics.translation_changes += 1;
        self.sync_host_regime();
    }

    /// Anything about translation may have changed: every lookup context
    /// goes too, and the whole shadow.
    pub(super) fn translations_changed(&mut self) {
        self.forget_contexts(0..=1, 3);
        self.host.invalidate_translations();
        self.controls_changed();
    }

    /// The host's answers to [`Host::fetch_permitted`] changed: every later
    /// fetch translates and asks again, and no cached, looked-up or chained
    /// transfer enters a block of another page before it has.
    pub fn fetch_permissions_changed(&mut self) {
        self.forget_spaces(0..=1, 3);
    }

    /// A TLBI: the fetch translations `reach` names go, and the host drops
    /// what it names of its shadow. Of the lookup table, which
    /// holds every context's entries, it drops what `everywhere` names: the
    /// entries at its VAs, or the contexts of the halves non-global entries
    /// were fetched through, or every context. No control changed, so the
    /// regime and what derives from System registers stay.
    pub(super) fn tlb_maintained(
        &mut self,
        reach: mmu::tlbi::Reach,
        everywhere: mmu::tlbi::Everywhere,
        asid: Option<u16>,
    ) {
        match everywhere {
            mmu::tlbi::Everywhere::Addresses(addresses) => {
                // Canonical memory's kept TLBs refresh on the generation.
                if self.canonical_memory_serves() {
                    self.advance_translation_generation();
                } else {
                    self.forget_fetches(reach);
                }
                self.forget_lookups(addresses, asid);
            }
            mmu::tlbi::Everywhere::NonGlobal => {
                let last = usize::from(self.private_fetches[1]);
                match asid {
                    Some(asid) => self.forget_asid(0..=last, asid, 0),
                    None => self.forget_spaces(0..=last, 0),
                }
            }
            mmu::tlbi::Everywhere::All => self.forget_spaces(0..=1, 1),
        }
        self.statistics.tlb_maintenance += 1;
        if reach != mmu::tlbi::Reach::All {
            self.statistics.scoped_maintenance += 1;
        }
        self.host.invalidate_reach(reach, everywhere);
    }

    /// A TTBR0 write, which changes the translation of the lower half
    /// alone: the regime's new controls tell the host so
    /// ([`Host::set_regime`]), which keeps the upper half's shadow. Lookup
    /// contexts are keyed by its value, as by every control's.
    pub(super) fn table_base_changed(&mut self) {
        self.advance_translation_generation();
        self.statistics.table_base_changes += 1;
        self.sync_host_regime();
    }

    /// Forget the blocks compiled from the page holding `physical`, which an
    /// IC IVAU made stale: a later fetch compiles the page again. Their code
    /// stays installed until the next full discard.
    pub(super) fn invalidate_code_page(&mut self, physical: u64) {
        self.pages.remove(&(physical & !(FETCH_PAGE - 1)));
        if !self.index.forget_page(physical & !(FETCH_PAGE - 1)) {
            return;
        }
        // The jump cache holds no generation per page.
        self.code_generation += 1;
        self.statistics.code_invalidations += 1;
    }

    /// Make room in the code arena: reclaim its oldest part, or discard
    /// every block on a host whose arena is one part.
    pub(super) fn reclaim_code(&mut self) {
        match self.host.reclaim_code() {
            Some(range) => self.evict_code(range),
            None => self.discard_code(Discard::Arena),
        }
    }

    /// Release local code owners under pressure before allocating compilation
    /// input and recovery metadata: the oldest arena part's blocks, or every
    /// block when the part new code fills holds them all.
    ///
    /// Memory another machine or the shared store holds stays low however
    /// much this one releases, so within one stretch of pressure a machine
    /// reclaims again only once it holds as many blocks as it did at its
    /// last reclaim: its growth stays bounded, and it does not release code
    /// before every block it installs. A machine holding fewer than
    /// [`MEMORY_RELEASE_BLOCKS`] keeps them: what they free would not
    /// relieve the heap.
    pub(super) fn reclaim_for_memory(&mut self) {
        if !self.host.memory_low() {
            self.reclaimed_at = None;
            return;
        }
        let live = self.blocks.len() - self.free_blocks.len();
        if live < self.memory_release_blocks.max(1)
            || self.reclaimed_at.is_some_and(|held| live < held)
        {
            return;
        }
        self.reclaimed_at = Some(live);
        match self.host.release_oldest_code() {
            Some(range) => self.evict_code(range),
            None => self.discard_code(Discard::Memory),
        }
    }

    /// Forget the blocks and leaves whose code lies in `range`, which the
    /// host reclaimed. A block of the same page may chain into an evicted
    /// one, so an evicted block's page is forgotten whole, as an IC IVAU
    /// forgets it: its other blocks become unreachable and are freed when
    /// their own code is reclaimed. A block no longer indexed has no live
    /// chain into it, as its page was forgotten whole then.
    pub(super) fn evict_code(&mut self, range: core::ops::Range<usize>) {
        let evicted: Vec<usize> = (0..self.blocks.len())
            .filter(|&slot| range.contains(&self.blocks[slot].code.0))
            .collect();
        for &slot in &evicted {
            let block = &self.blocks[slot];
            let found = self
                .index
                .get(&self.blocks, block.pc, block.physical, block.variant);
            if found == Some(slot) {
                self.index.forget_page(block.physical & !(FETCH_PAGE - 1));
            }
        }
        for &slot in &evicted {
            let block = &mut self.blocks[slot];
            if block.taken != 0 {
                *self.exit_words.entry(block.terminal).or_default() += u64::from(block.taken);
            }
            block.code = NativeCode(0);
            block.taken = 0;
            block.dynamic_site = None;
            block.successors = Box::default();
            self.fault_recovery.remove(&slot);
            self.free_blocks.push(slot);
        }
        self.scalable_leaves
            .retain(|_, leaf| !range.contains(&leaf.code.0));
        if !evicted.is_empty() {
            // The jump cache and lookup entries hold no generation per
            // block.
            self.code_generation += 1;
            self.statistics.code_evictions += 1;
        }
    }

    pub(super) fn discard_code(&mut self, cause: Discard) {
        self.exit_words = self.exit_words();
        self.host.discard_code();
        self.blocks.clear();
        self.free_blocks.clear();
        self.fault_recovery.clear();
        self.index.clear();
        self.pages.clear();
        self.scalable_leaves.clear();
        self.code_generation += 1;
        self.statistics.code_discards[cause as usize] += 1;
    }

    /// Discard every installed block, freeing its metadata, as a run that
    /// has ended does before work that needs the memory.
    pub fn discard_blocks(&mut self) {
        self.discard_code(Discard::Finished);
    }
}
