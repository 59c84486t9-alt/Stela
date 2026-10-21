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

/// The store a host keeps for the engine.
pub trait Translations {
    /// The record of the page whose bytes hash to `key`, if the store has
    /// a valid one.
    fn record(&mut self, key: &Digest) -> Option<Arc<Record>>;
    /// The block at `pc` of the page whose bytes hash to `key`, prepared
    /// in `context` at that very PC since the record was read, if the
    /// store has one.
    fn prepared(&mut self, _key: &Digest, _pc: u64, _context: &Digest) -> Option<CompiledBlock> {
        None
    }
    /// A block the engine compiled from a page the store had no entry for.
    fn offer(&mut self, offer: Offer);
}

/// A block compiled anew, and how it was compiled.
#[derive(Debug, Clone)]
pub struct Offer {
    pub key: Digest,
    /// The guest address of its fetch page.
    pub page: u64,
    pub pc: u64,
    pub context: Digest,
    /// The admitted words the compiler was given.
    pub input: Vec<u8>,
    pub preparation: Arc<Preparation>,
    /// The entry PCs of its static successors, for translation ahead of
    /// execution.
    pub successors: Vec<u64>,
    pub block: CompiledBlock,
}

impl Offer {
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
            self.page,
            self.pc,
            self.context,
            [first, second],
        )
    }
}

/// The fetch pages kept for their blocks at most: a page let go is read,
/// hashed and looked up again for its next block, which only a block not
/// yet installed needs.
#[cfg(not(test))]
const KEPT_PAGES: usize = 4096;
#[cfg(test)]
const KEPT_PAGES: usize = 2;

/// A fetch page's bytes, as read for its first block, and its record.
pub(super) struct StoredPage {
    pub(super) key: Digest,
    pub(super) bytes: Box<[u8; PAGE_BYTES]>,
    pub(super) record: Option<Arc<Record>>,
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
            if self.pages.len() == KEPT_PAGES {
                self.pages.pop_first();
            }
            self.pages.insert(frame, StoredPage { key, bytes, record });
        }
        self.pages.get(&frame)
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
pub(super) mod tests {
    use super::super::{
        FETCH_PAGE, FIRST_WINDOW_BYTES, Fetched, INSTRUCTION, tests::BASE, tests::machine,
    };
    use super::*;
    use crate::translations;
    use alloc::collections::BTreeMap;

    /// A store in memory: records by key, the blocks offered to it, and
    /// the blocks it has prepared by key, PC and context.
    #[derive(Default)]
    pub(crate) struct MemoryStore {
        pub(crate) records: BTreeMap<Digest, Arc<Record>>,
        pub(crate) offers: Vec<Offer>,
        pub(crate) prepared: BTreeMap<(Digest, u64, Digest), CompiledBlock>,
    }

    impl Translations for MemoryStore {
        fn record(&mut self, key: &Digest) -> Option<Arc<Record>> {
            self.records.get(key).cloned()
        }
        fn prepared(&mut self, key: &Digest, pc: u64, context: &Digest) -> Option<CompiledBlock> {
            self.prepared.get(&(*key, pc, *context)).cloned()
        }
        fn offer(&mut self, offer: Offer) {
            self.offers.push(offer);
        }
    }

    #[test]
    fn a_block_another_thread_prepared_at_the_same_pc_is_installed_as_it_is() {
        // adr x0, #8; add x0, x0, #1; svc #0
        let words = [0x1000_0040, 0x9100_0400, 0xd400_0001];
        let mut first = machine(&words);
        first.host.store = Some(MemoryStore::default());
        assert!(first.fetch_block(BASE + 4, false).is_ok());
        let offer = first.host.store.as_mut().unwrap().offers.pop().unwrap();
        let mut store = MemoryStore::default();
        store
            .prepared
            .insert((offer.key, offer.pc, offer.context), offer.block.clone());
        let mut second = machine(&words);
        second.host.store = Some(store);
        let Ok(Fetched::Block(index)) = second.fetch_block(BASE + 4, false) else {
            panic!("shared block")
        };
        assert_eq!(
            (second.statistics.compiled, second.statistics.shared),
            (0, 1)
        );
        assert_eq!(
            second.host.installed[second.blocks[index].code.0 - 1],
            offer.block.native.x86_64_code
        );
        // Another PC of the same page is compiled.
        assert!(second.fetch_block(BASE, false).is_ok());
        assert_eq!(second.statistics.compiled, 1);
    }

    /// What the hosted store's workers do with an offer.
    fn proven(offer: &Offer) -> translations::Entry {
        offer.prove().unwrap()
    }

    #[test]
    fn a_stored_block_of_the_same_page_bytes_is_installed_without_compiling() {
        // adr x0, #8; add x0, x0, #1; svc #0
        let words = [0x1000_0040, 0x9100_0400, 0xd400_0001];
        let mut first = machine(&words);
        first.host.store = Some(MemoryStore::default());
        let Ok(Fetched::Block(compiled)) = first.fetch_block(BASE + 4, false) else {
            panic!("block")
        };
        assert_eq!(
            (first.statistics.compiled, first.statistics.offered),
            (1, 1)
        );
        let offer = first.host.store.as_mut().unwrap().offers.pop().unwrap();
        assert_eq!((offer.page, offer.pc), (BASE, BASE + 4));
        let mut record = Record::new(translations::translator_id(), offer.key);
        record.insert(proven(&offer));
        let mut store = MemoryStore::default();
        store.records.insert(offer.key, Arc::new(record));
        let mut second = machine(&words);
        second.host.store = Some(store);
        let Ok(Fetched::Block(stored)) = second.fetch_block(BASE + 4, false) else {
            panic!("stored block")
        };
        assert_eq!(
            (second.statistics.compiled, second.statistics.stored),
            (0, 1)
        );
        let installed = |machine: &super::super::Machine<
            super::super::tests::FakeHost,
            crate::machine::NoDevices,
        >,
                         index: usize| {
            let block = &machine.blocks[index];
            (
                machine.host.installed[block.code.0 - 1].clone(),
                block.source_map.clone(),
                block.terminal,
                block.successors.len(),
            )
        };
        assert_eq!(installed(&first, compiled), installed(&second, stored));
        // Another entry PC, or the same page with other bytes, is compiled.
        assert!(matches!(
            second.fetch_block(BASE, false),
            Ok(Fetched::Block(_))
        ));
        assert_eq!(second.statistics.compiled, 1);
        let mut changed = machine(&[0x1000_0040, 0x9100_0800, 0xd400_0001]);
        changed.host.store = second.host.store.take();
        assert!(matches!(
            changed.fetch_block(BASE + 4, false),
            Ok(Fetched::Block(_))
        ));
        assert_eq!(
            (changed.statistics.compiled, changed.statistics.stored),
            (1, 0)
        );
    }

    #[test]
    fn a_block_longer_than_the_first_window_compiles_and_is_stored_whole() {
        // 40 × add x0, x0, #1; svc #0
        const ADDS: usize = 40;
        let mut words = vec![0x9100_0400; ADDS];
        words.push(0xd400_0001);
        let block_bytes = (ADDS + 1) * INSTRUCTION as usize;
        assert!(block_bytes > FIRST_WINDOW_BYTES);
        let mut first = machine(&words);
        first.host.store = Some(MemoryStore::default());
        let Ok(Fetched::Block(index)) = first.fetch_block(BASE, false) else {
            panic!("block")
        };
        assert_eq!(first.blocks[index].source_bytes, block_bytes);
        let offer = first.host.store.as_mut().unwrap().offers.pop().unwrap();
        assert_eq!(offer.input.len(), block_bytes);
        let mut record = Record::new(translations::translator_id(), offer.key);
        record.insert(proven(&offer));
        let mut store = MemoryStore::default();
        store.records.insert(offer.key, Arc::new(record));
        let mut second = machine(&words);
        second.host.store = Some(store);
        let Ok(Fetched::Block(stored)) = second.fetch_block(BASE, false) else {
            panic!("stored block")
        };
        assert_eq!(
            (second.statistics.compiled, second.statistics.stored),
            (0, 1)
        );
        assert_eq!(second.blocks[stored].source_bytes, block_bytes);
        // A changed word past the first window, inside the block: the stored
        // block's bytes no longer match, and it is compiled.
        words[ADDS - 1] = 0x9100_0800;
        let mut changed = machine(&words);
        changed.host.store = second.host.store.take();
        assert!(changed.fetch_block(BASE, false).is_ok());
        assert_eq!(
            (changed.statistics.compiled, changed.statistics.stored),
            (1, 0)
        );
    }

    #[test]
    fn a_page_written_without_invalidation_is_read_and_hashed_again() {
        // add x0, x0, #1; svc #0; add x0, x0, #2; svc #0
        let mut machine = machine(&[0x9100_0400, 0xd400_0001, 0x9100_0800, 0xd400_0001]);
        machine.host.store = Some(MemoryStore::default());
        assert!(machine.fetch_block(BASE, false).is_ok());
        let key = machine.pages[&BASE].key;
        // The guest rewrites the second block (add x0, x0, #3) with no IC
        // IVAU: it is compiled from, and offered with, the new bytes.
        machine.host.ram[8..12].copy_from_slice(&0x9100_0c00u32.to_le_bytes());
        assert!(machine.fetch_block(BASE + 8, false).is_ok());
        let offer = machine.host.store.as_mut().unwrap().offers.pop().unwrap();
        assert_ne!(offer.key, key);
        assert_eq!(offer.key, machine.pages[&BASE].key);
        assert_eq!(offer.input[..4], 0x9100_0c00u32.to_le_bytes());
    }

    #[test]
    fn an_invalidated_page_is_read_and_looked_up_again() {
        let mut machine = machine(&[0x9100_0400, 0xd400_0001]);
        machine.host.store = Some(MemoryStore::default());
        assert!(machine.fetch_block(BASE, false).is_ok());
        let key = machine.pages[&BASE].key;
        machine.host.ram[0] ^= 1;
        machine.invalidate_code_page(BASE);
        assert!(machine.pages.is_empty());
        assert!(machine.fetch_block(BASE, false).is_ok());
        assert_ne!(machine.pages[&BASE].key, key);
    }

    #[test]
    fn only_the_latest_pages_are_kept() {
        // A block in each of three pages: add x0, x0, #1; svc #0.
        const PAGE_WORDS: usize = FETCH_PAGE as usize / INSTRUCTION as usize;
        let mut words = vec![0; 2 * PAGE_WORDS + 2];
        for page in 0..3 {
            words[page * PAGE_WORDS..page * PAGE_WORDS + 2]
                .copy_from_slice(&[0x9100_0400, 0xd400_0001]);
        }
        let mut machine = machine(&words);
        machine.host.store = Some(MemoryStore::default());
        for page in 0..3 {
            assert!(machine.fetch_block(BASE + page * FETCH_PAGE, false).is_ok());
        }
        assert_eq!(
            machine.pages.keys().copied().collect::<Vec<_>>(),
            [BASE + FETCH_PAGE, BASE + 2 * FETCH_PAGE]
        );
    }
}
