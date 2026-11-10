//! Invalidation and reclamation of compiled blocks when translation or code
//! changes.

use super::*;

/// The word and bit of the two positions of the leaf of `size` bytes at
/// `base` in a filter of [`FETCHED_LEAVES`] bits. A base's low bits are clear,
/// so the size's exponent keeps leaves of one base apart.
fn fetched_leaf_bits(base: u64, size: u64) -> [(usize, u64); 2] {
    let hash = (base | u64::from(size.trailing_zeros())).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    [hash >> 40, hash >> 16].map(|bits| {
        let bit = bits as usize & (FETCHED_LEAVES - 1);
        (bit / 64, 1 << (bit % 64))
    })
}

/// Whether `slot`'s bit is set in `bits`.
fn bit_set(bits: &[u64], slot: u32) -> bool {
    bits.get(slot as usize / 64)
        .is_some_and(|word| word & 1 << (slot % 64) != 0)
}

/// `marked`, a bit per slot below `len`, with the bits of `slots` set, the
/// rest clear: what [`unmark`] takes back.
fn mark(marked: &mut Vec<u64>, len: usize, slots: &[u32]) -> Vec<u64> {
    let mut marked = core::mem::take(marked);
    let words = len.div_ceil(64);
    if marked.len() < words {
        marked.resize(words, 0);
    }
    for &slot in slots {
        marked[slot as usize / 64] |= 1 << (slot % 64);
    }
    marked
}

/// Clear the bits of `slots` in `marked` and keep it in `kept` for the next.
fn unmark(kept: &mut Vec<u64>, mut marked: Vec<u64>, slots: &[u32]) {
    for &slot in slots {
        marked[slot as usize / 64] &= !(1 << (slot % 64));
    }
    *kept = marked;
}

/// The frame number of the 4 KiB frame holding `physical`, as block keys
/// name it.
fn frame_number(physical: u64) -> u64 {
    chain::key_frame(chain::block_key(physical, 1))
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
        let cache = self.code.cache();
        for (cursor, index) in cache.index.sweep(self.stale_cursor).take(STALE_CHECKS) {
            let block = &self.code.blocks[index];
            bytes.resize(block.source_bytes(), 0);
            report.blocks += 1;
            last = Some(cursor);
            if !self.host.read_ram(block.physical, &mut bytes) {
                continue;
            }
            let raw = source_hash(&bytes);
            // A block's hash is of the bytes its compile admitted.
            for word in bytes.as_chunks_mut::<4>().0 {
                *word = self.admit(u32::from_le_bytes(*word)).to_le_bytes();
            }
            let admitted = source_hash(&bytes);
            if admitted == block.source_hash && raw != admitted {
                report.admitted += 1;
            }
            if admitted != block.source_hash {
                report.stale += 1;
                if report.first.is_none() {
                    report.first = Some((block.pc, block.physical));
                    let part = self.code.arena.as_ref().and_then(|arena| {
                        let offset = block.code.0.checked_sub(arena.window.exec)?;
                        Some((offset / arena.part_bytes) as u32)
                    });
                    report.origin = Some(StaleOrigin {
                        pe: block.installer,
                        part,
                        noted: self
                            .parallel
                            .as_ref()
                            .map(|hub| hub.has_code(block.physical)),
                    });
                }
            }
        }
        // A sweep that reached the last block starts over next time.
        self.stale_cursor = last.filter(|_| report.blocks == STALE_CHECKS);
        report
    }

    /// An architectural cache epoch must never wrap back to an old permission.
    pub(super) fn advance_translation_generation(&mut self) {
        self.mirrors.close_code_page();
        self.translation_generation = self
            .translation_generation
            .checked_add(1)
            .expect("architectural translation generation exhausted");
    }

    /// What TTBR0 or its ASID selects may have changed.
    fn advance_table_generation(&mut self) {
        self.mirrors.close_code_page();
        self.table_generation = self
            .table_generation
            .checked_add(1)
            .expect("architectural table generation exhausted");
    }

    /// What `half`'s cached fetches and contexts last as long as: TTBR0
    /// selects the lower half's, and the upper half's once a fetch of it was
    /// non-global, by its ASID ([`Self::half_inputs`]).
    pub(super) fn fetch_epoch(&self, half: usize) -> FetchEpoch {
        let table = half == 0 || self.private_fetches[1];
        (
            self.translation_generation,
            if table { self.table_generation } else { 0 },
        )
    }

    /// The translations of the halves `halves` may have changed with no
    /// control value showing it: their lookup contexts go, so no lookup
    /// translates through their ITLB entries, nor does a cached fetch
    /// outlive what [`Self::fetched_through`] learnt of it. The block
    /// table's entries stay: they hold for a frame, whatever maps it.
    pub(super) fn forget_spaces(&mut self, halves: core::ops::RangeInclusive<usize>, cause: usize) {
        self.forget_contexts(halves, cause);
        self.advance_translation_generation();
    }

    /// Forget the contexts of `halves` that translate `asid`: what a TLBI of
    /// one process leaves of the others', which their ITLB entries stay good
    /// for.
    /// ASIDs compare by the eight bits every TCR.AS gives them.
    pub(super) fn forget_asid(&mut self, halves: core::ops::RangeInclusive<usize>, asid: u16) {
        for half in halves {
            self.statistics.lookup_forgets[0] += 1;
            self.spaces[half].retain(|space| !same_asid(&space.inputs.0, asid));
            self.recent[half] = [None; RECENT];
        }
        self.advance_table_generation();
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
            // Bits are inserted with a fetched size and only cleared here.
            if core::mem::take(&mut self.fetched_sizes[half]) != 0 {
                self.fetched_leaves[half].fill(0);
            }
            self.private_fetches[half] = false;
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
        let leaf = size.next_power_of_two();
        let filter = &mut self.fetched_leaves[half];
        if filter.is_empty() {
            *filter = vec![0; FETCHED_LEAVES / 64];
        }
        for (word, bit) in fetched_leaf_bits(pc & !(leaf - 1), leaf) {
            filter[word] |= bit;
        }
        self.fetched_sizes[half] |= leaf;
        self.private_fetches[half] |= !global;
        if half == 0 && global {
            let (first, last) = self.lower_globals;
            self.lower_globals = (first.min(pc), last.max(pc.saturating_add(size)));
        }
    }

    /// Whether a fetch of `half` translated through the leaf of `size` bytes
    /// at `base`, or through one that shares its filter bits.
    fn leaf_fetched(&self, half: usize, base: u64, size: u64) -> bool {
        fetched_leaf_bits(base, size)
            .iter()
            .all(|&(word, bit)| self.fetched_leaves[half][word] & bit != 0)
    }

    /// The span of `half` a TLBI of `first..=last` can reach of what it
    /// fetched: the leaves around them that fetches translated through, at
    /// each size such leaves had.
    fn fetched_span(&self, half: usize, first: u64, last: u64) -> Option<(u64, u64)> {
        const UPPER: u64 = !0 << 55;
        let (low, high) = [(0, !UPPER), (UPPER, u64::MAX)][half];
        if last < low || first > high {
            return None;
        }
        let (first, last) = (first.max(low), last.min(high));
        let mut span: Option<(u64, u64)> = None;
        let mut sizes = self.fetched_sizes[half];
        while sizes != 0 {
            let size = sizes.isolate_lowest_one();
            sizes &= sizes - 1;
            let (start, end) = (first & !(size - 1), last | (size - 1));
            let leaves = (end - start) / size;
            let fetched = leaves >= SCANNED_LEAVES
                || (0..=leaves).any(|leaf| self.leaf_fetched(half, start + leaf * size, size));
            if fetched {
                span = Some(span.map_or((start, end), |(lowest, highest)| {
                    (lowest.min(start), highest.max(end))
                }));
            }
        }
        span
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

    /// Drop the ITLB entries of the pages a TLBI by VA reaches
    /// ([`Self::fetched_span`]): those of every context, or of `asid`'s alone
    /// while no global page was fetched in its span of the lower half, which
    /// only such a page shares. A process's exit reaches the shared libraries
    /// this way, which every other process's entries still hold good for.
    /// The ITLB finds the entries of the span's pages in every context from
    /// its index of where each granule's went (`chain::LookupTable`).
    /// Contexts stay: the hot pages of one that went would each cost an exit
    /// on every PE that runs them. The block table's entries stay too: a
    /// page translated anew finds them again by its frame.
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
            let reached = match scoped {
                Some(asid) => self.asid_salts(half, asid),
                None => u64::MAX,
            };
            if self.itlb.forget_range(first..=last, reached) {
                self.statistics.lookup_forgets[2] += 1;
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
        self.mirrors.close_code_page();
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
                    Some(asid) => self.forget_asid(0..=last, asid),
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
        self.advance_table_generation();
        self.statistics.table_base_changes += 1;
        self.sync_host_regime();
    }

    /// Forget the blocks compiled from the page holding `physical`, which an
    /// IC IVAU made stale, and their lookup entries, which every address
    /// space mapping the frame shares: a later fetch compiles the page
    /// again. Their code stays installed until its part is reclaimed.
    pub(super) fn invalidate_code_page(&mut self, physical: u64) {
        let frame = frame_number(physical);
        let mut cache = self.code.cache_at(board::LockSite::Invalidate);
        cache.targets.forget_frames(frame..=frame, |_| true);
        let forgot = cache.index.forget_page(physical & !(FETCH_PAGE - 1));
        drop(cache);
        // Every PE's jump cache on a shared board still names its blocks.
        if forgot || self.code_hub.is_some() {
            self.forget_code_page_here(physical);
        } else {
            self.forget_page_caches(physical);
        }
    }

    /// Another PE's IC IVAU of the page holding `physical`. On a shared
    /// board the poster forgot the page already, but this PE may have read
    /// the old bytes before the write and published their block after that
    /// forget: a compile runs outside, so the post did not wait for it. It
    /// reads its mail only after it published, so forgetting the page again
    /// here takes such a block away.
    pub(super) fn invalidate_posted_code_page(&mut self, physical: u64) {
        self.invalidate_code_page(physical);
    }

    /// Forget this PE's caches of the page holding `physical`, and its jump
    /// cache.
    fn forget_code_page_here(&mut self, physical: u64) {
        self.forget_page_caches(physical);
        // The jump cache holds no generation per page.
        self.code_generation += 1;
        self.statistics.code_invalidations += 1;
    }

    /// Forget this PE's stored page, waiting direct exit and known key of
    /// the page holding `physical`.
    fn forget_page_caches(&mut self, physical: u64) {
        self.forget_stored_page(physical & !(FETCH_PAGE - 1));
        // A forgotten block's exit waits for no block of its page.
        if self.direct_exit.is_some_and(|(block, ..)| {
            (self.code.blocks[block].physical ^ physical) & !(FETCH_PAGE - 1) == 0
        }) {
            self.direct_exit = None;
        }
        self.forget_known_key(physical & !(FETCH_PAGE - 1));
    }

    /// Make room in the code arena: reclaim its oldest part, or discard
    /// every block on a host whose arena is one part.
    pub(super) fn reclaim_code(&mut self) {
        // A ring reclaims its parts as installs fill it.
        if self.code.arena.is_some() {
            return;
        }
        self.lookup_dispatchers = Default::default();
        match self.host.reclaim_code() {
            Some(range) => self.evict_code(range),
            None => self.discard_code(Discard::Arena),
        }
    }

    /// Make room in the host's own arena for a leaf. With the board's
    /// arena holding the blocks, the host's holds only leaves: its oldest
    /// part goes with the leaves in it.
    pub(super) fn reclaim_leaves(&mut self) {
        if self.code.arena.is_none() {
            return self.reclaim_code();
        }
        match self.host.reclaim_code() {
            Some(range) => self
                .scalable_leaves
                .retain(|_, leaf| !range.contains(&leaf.code.0)),
            None => {
                self.host.discard_code();
                self.scalable_leaves.clear();
            }
        }
    }

    /// Release local code owners under pressure before allocating compilation
    /// input and recovery metadata: the oldest arena part's blocks, or every
    /// block on a host whose arena is one part.
    ///
    /// Memory another machine or the shared store holds stays low however
    /// much this one releases, so within one stretch of pressure a machine
    /// reclaims again only once it holds as many blocks as it did at its
    /// last reclaim: its growth stays bounded, and it does not release code
    /// before every block it installs. A machine holding fewer than
    /// [`MEMORY_RELEASE_BLOCKS`] keeps them: what they free would not
    /// relieve the heap.
    pub(super) fn reclaim_for_memory(&mut self) {
        // A ring's blocks are bounded by its bytes.
        if self.code.arena.is_some() || !self.host.memory_low() {
            self.reclaimed_at = None;
            return;
        }
        let live = self.code.blocks.live();
        if live < self.memory_release_blocks.max(1)
            || self.reclaimed_at.is_some_and(|held| live < held)
        {
            return;
        }
        self.reclaimed_at = Some(live);
        self.statistics.code_releases += 1;
        match self.host.release_oldest_code() {
            Some(range) => self.evict_code(range),
            None => self.discard_code(Discard::Memory),
        }
    }

    /// The grace slots this machine releases go to limbo under, and the PE
    /// it is there: a machine that keeps its code alone has a grace of no
    /// PE, so its slots are free again at once.
    pub(super) fn grace(&self) -> (&board::Grace, Option<usize>) {
        match &self.code_hub {
            Some(hub) => (&hub.board.grace, Some(self.current)),
            None => (&self.alone, None),
        }
    }

    /// Install native `bytes`: in the board's arena when it has one, else
    /// in the host's. `retire` lets a full ring take away its oldest part's
    /// code to make room, for a caller outside the board's lock.
    pub(super) fn install_native(
        &mut self,
        bytes: &[u8],
        retire: bool,
    ) -> Result<NativeCode, InstallError> {
        let code = Arc::clone(&self.code);
        let Some(arena) = &code.arena else {
            return self.host.install(bytes);
        };
        if bytes.len() > arena.part_bytes {
            return Err(InstallError::Full);
        }
        #[cfg(debug_assertions)]
        self.assert_portable(bytes);
        loop {
            let full = match arena.ring.take(bytes.len(), 16) {
                Ok(place) => {
                    let address = arena.address(place);
                    arena.write(address, bytes);
                    self.host.serialize_code();
                    return Ok(NativeCode(address));
                }
                Err(full) => full,
            };
            if !retire {
                return Err(InstallError::Full);
            }
            let (grace, skip) = self.grace();
            match arena.ring.advance(full, grace, skip) {
                board::Advance::Moved => {}
                board::Advance::Busy => self.host.relax(),
                board::Advance::Retire(generation) => self.retire_part(generation),
                board::Advance::Wait(snapshot) => self.wait_grace(&snapshot),
            }
        }
    }

    /// Code in the board's arena runs on every PE: it names none of this
    /// PE's own data by address, only through its anchors, whose values
    /// differ by PE ([`Self::anchors`]).
    #[cfg(debug_assertions)]
    fn assert_portable(&self, bytes: &[u8]) {
        let anchors = self.anchors();
        let own = [
            anchors[Anchor::Control],
            anchors[Anchor::Mirrors],
            anchors[Anchor::Cells],
            anchors[Anchor::Pointer],
            anchors[Anchor::Memo],
            anchors[Anchor::Count],
            anchors[Anchor::StackZero],
            &self.cpu.state as *const _ as u64,
        ];
        for window in bytes.windows(8) {
            let value = u64::from_le_bytes(window.try_into().expect("eight bytes"));
            assert!(
                value == 0 || !own.contains(&value),
                "board code names PE {}'s own address {value:#x}",
                self.current
            );
        }
    }

    /// Overwrite installed code at `code` with `bytes`.
    pub(super) fn patch_native(&mut self, code: NativeCode, bytes: &[u8]) {
        match &self.code.arena {
            Some(arena) => {
                arena.write(code.0, bytes);
                self.host.serialize_code();
            }
            None => self.host.patch(code, bytes),
        }
    }

    /// Replace the instruction at patch point `code`, which a core may be
    /// running, in one store (`Host::patch_instruction`).
    pub(super) fn patch_point(&mut self, code: NativeCode, instruction: [u8; chain::PATCH_BYTES]) {
        match &self.code.arena {
            Some(arena) => {
                assert!(chain::patchable(code.0 as u64), "a patch point");
                arena.patch_point(code.0 as u64, instruction);
                self.host.serialize_code();
            }
            None => self.host.patch_instruction(code, instruction),
        }
    }

    /// With every block slot given, move the board's ring on before its
    /// parts are full, taking the oldest parts' blocks away and waiting for
    /// their grace, until a slot is free. The caller installs its code again
    /// after: its part may be one that went. A slot, if that freed one.
    pub(super) fn retire_for_slot(&mut self) -> Option<usize> {
        let code = Arc::clone(&self.code);
        let arena = code.arena.as_ref()?;
        for _ in 0..2 * arena.ring.parts {
            if let Some(slot) = self.take_slot() {
                return Some(slot);
            }
            let (grace, skip) = self.grace();
            match arena.ring.advance(arena.ring.generation(), grace, skip) {
                board::Advance::Moved => {}
                board::Advance::Busy => self.host.relax(),
                board::Advance::Retire(generation) => {
                    self.retire_part(generation);
                    board::Events::count(&code.events.forced);
                    let snapshot = self.grace().0.snapshot();
                    self.wait_grace(&snapshot);
                }
                board::Advance::Wait(snapshot) => self.wait_grace(&snapshot),
            }
        }
        self.take_slot()
    }

    /// Take away the code of the ring's part of `generation`, which this
    /// PE moved the ring past ([`board::Advance::Retire`]): its blocks go
    /// as in a reclaim, and its probes; the part is reused once every PE
    /// passed the grace taken after.
    fn retire_part(&mut self, generation: u32) {
        let code = Arc::clone(&self.code);
        let arena = code.arena.as_ref().expect("a ring retires its parts");
        let range = arena.range(generation);
        let part = arena.ring.part(generation) as u32;
        self.evict_code(range);
        code.cache().dispatchers.retain(|&(held, _)| held != part);
        let (grace, _) = self.grace();
        arena.ring.retired(generation, grace.snapshot());
        board::Events::count(&code.events.retired);
    }

    /// Wait until `snapshot`'s grace passed, in rounds bounded by the host
    /// counter; the board's first overrun is reported once. A PE inside
    /// its section leaves it to wait ([`board::Board::wait`]); outside (a
    /// compile), it holds nothing anyone waits on.
    fn wait_grace(&mut self, snapshot: &board::Snapshot) {
        let Some(hub) = self.code_hub.clone() else {
            return;
        };
        let events = &self.code.events;
        board::Events::count(&events.grace_waits);
        let ticks = (self.profile.counter_frequency / 10).max(1);
        let pe = self.current;
        let waited = if hub.board.grace.inside(pe) {
            hub.board.wait(pe, snapshot, ticks, || self.host.counter())
        } else {
            let start = self.host.counter();
            loop {
                if hub.board.grace.passed(snapshot, None) {
                    break board::Waited::Passed;
                }
                if self.host.counter().wrapping_sub(start) >= ticks {
                    break board::Waited::Overdue {
                        first: hub.board.overdue(),
                    };
                }
                self.host.relax();
            }
        };
        if let board::Waited::Overdue { .. } = waited {
            board::Events::count(&self.code.events.overdue);
        }
        if let board::Waited::Overdue { first: true } = waited {
            let requirement = self.requirement(RequirementKind::Native(
                "a code part's grace ran past its deadline: its reuse waits",
            ));
            self.degrade(requirement);
        }
    }

    /// What the board's machines share: every index entry and block table
    /// entry goes, so no fetch, lookup or jump cache entry reaches a block
    /// installed before; their code goes as the ring reaches its parts.
    fn forget_shared_code(&mut self) {
        let mut cache = self.code.cache();
        cache.index.clear();
        cache.targets.clear();
        drop(cache);
        self.code.epoch.fetch_add(1, Ordering::AcqRel);
    }

    /// What jump cache entries are valid in: this machine's code
    /// generation and the board's epoch ([`Self::forget_shared_code`]).
    pub(super) fn jump_generation(&self) -> u64 {
        self.code_generation
            .wrapping_add(self.code.epoch.load(Ordering::Acquire) << 40)
    }

    /// Forget the blocks and leaves whose code lies in `range`, which the
    /// host reclaimed. The other blocks of their pages stay: they chain into
    /// them no more ([`Self::detach`]), and take an exit to the engine
    /// there until it links them to the blocks compiled again. Only indexed
    /// blocks are reached: one replaced in the index was detached then,
    /// and the blocks of a page an IC IVAU forgot whole reach only each
    /// other, with no lookup entry and in a code generation no jump cache
    /// entry names since. Their slots are given again once the grace
    /// passed ([`board::Blocks::release`]).
    pub(super) fn evict_code(&mut self, range: core::ops::Range<usize>) {
        // A host with nothing to release says so with an empty range, and
        // while memory stays low that comes before every compile.
        if range.is_empty() {
            return;
        }
        let started = self.host.counter();
        let code = Arc::clone(&self.code);
        let shared = self.code_hub.is_some();
        let mut cache = code.cache_at(board::LockSite::Evict);
        let mut evicted = cache.code_slots.take(&range).unwrap_or_else(|| {
            code.blocks
                .iter()
                .filter(|&(slot, block)| {
                    code.blocks.record(slot).live() && range.contains(&block.code.0)
                })
                .map(|(slot, _)| slot as u32)
                .collect()
        });
        evicted.sort_unstable();
        // An evicted block's slot holds the next block compiled.
        if self
            .direct_exit
            .is_some_and(|(block, ..)| evicted.binary_search(&(block as u32)).is_ok())
        {
            self.direct_exit = None;
        }
        self.detach(&mut cache, &evicted);
        // The exits in the range go, and with them their cells.
        cache
            .targets
            .release_cells(range.start as u64..=range.end as u64 - 1);
        // A page's evicted blocks leave its index entries in one pass.
        let mut pages: Vec<(u64, u32)> = evicted
            .iter()
            .map(|&slot| {
                (
                    code.blocks[slot as usize].physical & !(FETCH_PAGE - 1),
                    slot,
                )
            })
            .collect();
        pages.sort_unstable();
        let marked = mark(&mut cache.marked, code.blocks.len(), &evicted);
        for page in pages.chunk_by(|a, b| a.0 == b.0) {
            cache
                .index
                .forget_marked(page[0].0, |slot| bit_set(&marked, slot));
        }
        unmark(&mut cache.marked, marked, &evicted);
        for slot in evicted.iter().map(|&slot| slot as usize) {
            // On a shared board its rows stay until the slot takes its next
            // block: another PE still inside its section may be running the
            // block and fault in it. A machine alone runs none of it now.
            let bytes = match shared {
                true => cache.recovery.get(&slot).map(|owner| owner.code_bytes()),
                false => cache.recovery.remove(&slot).map(|owner| owner.code_bytes()),
            }
            .unwrap_or(0);
            self.census_evicted(&mut cache, slot, bytes, started);
            let taken = code.blocks.record(slot).taken.load(Ordering::Relaxed);
            if taken != 0 {
                *self
                    .exit_words
                    .entry(code.blocks[slot].terminal)
                    .or_default() += u64::from(taken);
            }
            code.blocks.retire(slot);
        }
        let (grace, _) = self.grace();
        code.blocks.release(evicted.clone(), grace.snapshot());
        cache.code_slots.give_back(evicted);
        drop(cache);
        if !self.scalable_leaves.is_empty() {
            self.scalable_leaves
                .retain(|_, leaf| !range.contains(&leaf.code.0));
        }
        if !pages.is_empty() {
            self.statistics.code_evictions += 1;
        }
        self.install_causes.evict_ticks += self.host.counter().wrapping_sub(started);
    }

    /// Make the blocks in the sorted `slots` unreachable: the indexed blocks
    /// of their pages undo their links to their PCs (a link names the
    /// block a PC and variant have, so any of the page's blocks of the PC
    /// may be the one it reached), and their lookup and jump cache
    /// entries go. Under the board's lock, `cache`.
    pub(super) fn detach(&mut self, cache: &mut board::Cache, slots: &[u32]) {
        let blocks = &self.code.blocks;
        let marked = mark(&mut cache.marked, blocks.len(), slots);
        let detached = |slot: usize| bit_set(&marked, slot as u32);
        let mut gone: Vec<(u64, u64)> = slots
            .iter()
            .map(|&slot| {
                let block = &blocks[slot as usize];
                (block.physical & !(FETCH_PAGE - 1), block.pc)
            })
            .collect();
        gone.sort_unstable();
        gone.dedup();
        let mut sources = core::mem::take(&mut cache.page_blocks);
        let mut unlinks = Vec::new();
        for page in gone.chunk_by(|a, b| a.0 == b.0) {
            sources.extend(cache.index.page(page[0].0));
            for &source in &sources {
                if detached(source) {
                    continue;
                }
                let record = blocks.record(source);
                for (position, exit) in blocks[source].successors.iter().enumerate() {
                    if record.chained(position)
                        && page.binary_search(&(page[0].0, exit.target.0)).is_ok()
                    {
                        record.set_linked(position, false, false);
                        // Linked, so its point is patchable and in reach.
                        let unlink = chain::unlinked(exit.site, exit.slot.into())
                            .expect("a linked exit's patch point");
                        unlinks.push(unlink);
                    }
                }
            }
            sources.clear();
        }
        cache.page_blocks = sources;
        // One store each, which a core running the exit may meet.
        for (point, instruction) in unlinks {
            self.patch_point(NativeCode(point as usize), instruction);
            self.statistics.unlinks += 1;
        }
        // Lookup entries go by the frames their keys name, in runs.
        let mut frames: Vec<u64> = gone.iter().map(|&(page, _)| frame_number(page)).collect();
        frames.dedup();
        for run in frames.chunk_by(|a, b| a + 1 == *b) {
            cache
                .targets
                .forget_frames(run[0]..=run[run.len() - 1], |entry| {
                    detached(entry.block as usize)
                });
        }
        // A jump cache entry sits in its PC's slot alone.
        for &(_, pc) in &gone {
            let entry = &mut self.jump[(pc / INSTRUCTION) as usize % JUMP_CACHE];
            if entry.as_ref().is_some_and(|entry| detached(entry.block)) {
                *entry = None;
            }
        }
        unmark(&mut cache.marked, marked, slots);
    }

    pub(super) fn discard_code(&mut self, cause: Discard) {
        self.exit_words = self.exit_words();
        let code = Arc::clone(&self.code);
        let mut cache = code.cache();
        if self.census.is_some() || cache.census.is_some() {
            let now = self.host.counter();
            for slot in 0..code.blocks.len() {
                if code.blocks.record(slot).live() {
                    let bytes = cache
                        .recovery
                        .get_mut(&slot)
                        .map_or(0, |owner| owner.code_bytes());
                    self.census_evicted(&mut cache, slot, bytes, now);
                }
            }
        }
        drop(cache);
        drop(code);
        self.host.discard_code();
        self.lookup_dispatchers = Default::default();
        self.direct_exit = None;
        // A worker built on the hub's code holds it before it joins.
        if self.code_hub.is_some() || Arc::get_mut(&mut self.code).is_none() {
            // Other PEs run the board's code: it becomes unreachable now
            // and goes as the ring reaches it.
            self.forget_shared_code();
            self.pages.clear();
            self.known_keys.fill(None);
            self.scalable_leaves.clear();
            self.code_generation += 1;
            self.statistics.code_discards[cause as usize] += 1;
            return;
        }
        // The block table goes with the code; the ITLB, which names no
        // block, keeps its translations. A running guest normally fills the
        // chunks again after a discard: their storage goes back when
        // freeing memory is the reason to discard.
        let free = matches!(cause, Discard::Memory | Discard::Finished);
        Arc::get_mut(&mut self.code)
            .expect("a machine that keeps its code alone discards it")
            .clear(free);
        if free {
            self.spare_pages = Vec::new();
        }
        self.pages.clear();
        self.known_keys.fill(None);
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
