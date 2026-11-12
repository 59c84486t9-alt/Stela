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
    /// Record lookups made.
    pub(crate) lookups: usize,
    pub(crate) offers: Vec<Offer>,
    pub(crate) prepared: BTreeMap<(Digest, u64, Digest), Arc<SharedTranslation>>,
}

impl Translations for MemoryStore {
    fn record(&mut self, key: &Digest) -> Option<Arc<Record>> {
        self.lookups += 1;
        self.records.get(key).cloned()
    }
    fn prepared(
        &mut self,
        key: &Digest,
        pc: u64,
        context: &Digest,
    ) -> Option<Arc<SharedTranslation>> {
        self.prepared.get(&(*key, pc, *context)).cloned()
    }
    fn offer(&mut self, offer: Offer) {
        self.offers.push(offer);
    }
}

#[test]
fn sealed_shared_handoff_rejects_other_source_pc_and_profile_before_install() {
    let words = [0x91000400, 0xd4000001];
    let mut sender = machine(&words);
    sender.host.store = Some(MemoryStore::default());
    assert!(matches!(
        sender.fetch_block(BASE, false),
        Ok(Fetched::Block(_))
    ));
    let genuine = sender.host.store.as_mut().unwrap().offers.pop().unwrap();
    assert!(genuine.clone().shared().matches(
        &genuine.key,
        genuine.pc,
        &genuine.context,
        genuine.input()
    ));

    let mut different = machine(&[0x91000800, 0xd4000001]);
    different.host.store = Some(MemoryStore::default());
    assert!(matches!(
        different.fetch_block(BASE, false),
        Ok(Fetched::Block(_))
    ));
    let other_source = different
        .host
        .store
        .as_mut()
        .unwrap()
        .offers
        .pop()
        .unwrap()
        .shared();
    let other_pc = Offer::compile(
        genuine.key,
        genuine.page,
        genuine.pc + 4,
        genuine.context,
        genuine.input().to_vec(),
        Arc::clone(genuine.preparation()),
    )
    .unwrap()
    .shared();
    let mut description = genuine.preparation().description();
    description.fp = !description.fp;
    let other_preparation = Arc::new(Preparation::from_description(&description).unwrap());
    let other_context = other_preparation.context(genuine.page);
    let other_profile = Offer::compile(
        genuine.key,
        genuine.page,
        genuine.pc,
        other_context,
        genuine.input().to_vec(),
        other_preparation,
    )
    .unwrap()
    .shared();
    assert_eq!(
        other_profile.block().native.x86_64_code,
        genuine.block().native.x86_64_code,
        "identical scalar bytes do not prove profile identity"
    );
    assert!(
        Offer::compile(
            genuine.key,
            genuine.page,
            genuine.pc,
            other_context,
            genuine.input().to_vec(),
            Arc::clone(genuine.preparation())
        )
        .is_none()
    );

    for wrong in [other_source, other_pc, other_profile] {
        assert!(!wrong.matches(&genuine.key, genuine.pc, &genuine.context, genuine.input()));
        let mut store = MemoryStore::default();
        store
            .prepared
            .insert((genuine.key, genuine.pc, genuine.context), wrong);
        let mut receiver = machine(&words);
        receiver.host.store = Some(store);
        assert!(matches!(
            receiver.fetch_block(BASE, false),
            Ok(Fetched::Block(_))
        ));
        assert_eq!(
            (receiver.statistics.shared, receiver.statistics.compiled),
            (0, 1)
        );
        // The block compiled anew, then the SVC's thunk.
        assert_eq!(
            receiver.host.installed.first(),
            Some(&genuine.block().native.x86_64_code),
            "wrong handoff never reaches installation"
        );
        assert_eq!(receiver.host.installed.len(), 2);
    }
}

#[test]
fn cached_blocks_do_not_cross_presented_instruction_features() {
    use {
        crate::machine::identification, crate::machine::registers::encodings::ID_AA64ISAR1_EL1,
        stela_contracts::Chip,
    };
    use {crate::machine::system::Register, stela_contracts::Feature};

    const SMMLA: u32 = 0x4e9b_a781;
    let words = [0x9100_0400, SMMLA, 0xd400_0001];
    let build = |masked| {
        let template = super::super::tests::machine_on(Chip::AppleM2, &words);
        let mut profile = template.profile;
        profile.fixed = identification::derive(
            Chip::AppleM2,
            stela_compiler::TargetCpu::Baseline,
            true,
            identification::Speculation::NONE,
        );
        if masked {
            for (register, value) in &mut profile.fixed {
                if *register == ID_AA64ISAR1_EL1 {
                    *value &= !(0xf << 52);
                }
            }
        }
        let mut machine = Machine::new(
            template.cpu,
            template.host,
            crate::machine::NoDevices,
            profile,
            stela_compiler::TargetCpu::Baseline,
        );
        machine.cpu.registers.set(Register::CPACR_EL1, 0, 3 << 20);
        assert_eq!(
            machine.admit_table.withheld() & (1 << Feature::FEAT_I8MM as u64) != 0,
            masked
        );
        machine
    };
    for first_masked in [false, true] {
        let mut first = build(first_masked);
        first.host.store = Some(MemoryStore::default());
        assert!(matches!(
            first.fetch_block(BASE, false),
            Ok(Fetched::Block(_))
        ));
        let offer = first.host.store.as_mut().unwrap().offers.pop().unwrap();
        let mut record = Record::new(translations::translator_id(), offer.key);
        record.insert(offer.entry().unwrap());
        for shared in [false, true] {
            for same_profile in [false, true] {
                let mut store = MemoryStore::default();
                if shared {
                    store
                        .prepared
                        .insert((offer.key, offer.pc, offer.context), offer.clone().shared());
                } else {
                    store.records.insert(offer.key, Arc::new(record.clone()));
                }
                let mut next = build(if same_profile {
                    first_masked
                } else {
                    !first_masked
                });
                next.host.store = Some(store);
                assert!(matches!(
                    next.fetch_block(BASE, false),
                    Ok(Fetched::Block(_))
                ));
                assert_eq!(next.statistics.compiled, u64::from(!same_profile));
                assert_eq!(next.statistics.shared, u64::from(shared && same_profile));
                assert_eq!(next.statistics.stored, u64::from(!shared && same_profile));
            }
        }
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
        .insert((offer.key, offer.pc, offer.context), offer.clone().shared());
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
        second.host.installed
            [second.code.blocks[index].code.0 / super::super::tests::NATIVE_CODE_STRIDE - 1],
        offer.block().native.x86_64_code
    );
    // Another PC of the same page is compiled.
    assert!(second.fetch_block(BASE, false).is_ok());
    assert_eq!(second.statistics.compiled, 1);
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
    record.insert(offer.entry().unwrap());
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
        let block = &machine.code.blocks[index];
        (
            machine.host.installed[block.code.0 / super::super::tests::NATIVE_CODE_STRIDE - 1]
                .clone(),
            block.instructions,
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
    assert_eq!(first.code.blocks[index].source_bytes(), block_bytes);
    let offer = first.host.store.as_mut().unwrap().offers.pop().unwrap();
    assert_eq!(offer.input().len(), block_bytes);
    let mut record = Record::new(translations::translator_id(), offer.key);
    record.insert(offer.entry().unwrap());
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
    assert_eq!(second.code.blocks[stored].source_bytes(), block_bytes);
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
    assert_eq!(offer.input()[..4], 0x9100_0c00u32.to_le_bytes());
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
fn the_least_recently_used_pages_are_let_go() {
    // A block in each of five pages: add x0, x0, #1; svc #0.
    const PAGE_WORDS: usize = FETCH_PAGE as usize / INSTRUCTION as usize;
    let mut words = vec![0; 4 * PAGE_WORDS + 2];
    for page in 0..5 {
        words[page * PAGE_WORDS..page * PAGE_WORDS + 2]
            .copy_from_slice(&[0x9100_0400, 0xd400_0001]);
    }
    let mut machine = machine(&words);
    machine.host.store = Some(MemoryStore::default());
    let page = |n: u64| BASE + n * FETCH_PAGE;
    for n in 0..4 {
        assert!(machine.fetch_block(page(n), false).is_ok());
    }
    // Page 0's second block uses it again: page 1 is the least
    // recently used when page 4 needs room.
    assert!(machine.fetch_block(page(0) + 4, false).is_ok());
    assert!(machine.fetch_block(page(4), false).is_ok());
    assert_eq!(
        machine.pages.keys().copied().collect::<Vec<_>>(),
        [page(0), page(2), page(3), page(4)]
    );
}

#[test]
fn a_page_let_go_and_read_again_takes_its_known_key_unless_it_changed() {
    // A block in each of five pages: add x0, x0, #1; svc #0.
    const PAGE_WORDS: usize = FETCH_PAGE as usize / INSTRUCTION as usize;
    let mut words = vec![0; 4 * PAGE_WORDS + 2];
    for page in 0..5 {
        words[page * PAGE_WORDS..page * PAGE_WORDS + 2]
            .copy_from_slice(&[0x9100_0400, 0xd400_0001]);
    }
    let mut machine = machine(&words);
    machine.host.store = Some(MemoryStore::default());
    let page = |n: u64| BASE + n * FETCH_PAGE;
    for n in 0..5 {
        assert!(machine.fetch_block(page(n), false).is_ok());
    }
    // Page 0 was let go; its second block reads it again.
    assert!(!machine.pages.contains_key(&page(0)));
    let key = Digest::of(&machine.host.ram[..FETCH_PAGE as usize]);
    assert!(machine.fetch_block(page(0) + 4, false).is_ok());
    assert_eq!(machine.statistics.known_keys, 1);
    assert_eq!(machine.pages[&page(0)].key, key);
    // A page written while let go is hashed again.
    for n in 1..5 {
        assert!(machine.fetch_block(page(n) + 4, false).is_ok());
    }
    assert!(!machine.pages.contains_key(&page(0)));
    let known = machine.statistics.known_keys;
    machine.host.ram[100] ^= 1;
    assert!(machine.fetch_block(page(0) + 8, false).is_ok());
    assert_eq!(machine.statistics.known_keys, known);
    let changed = Digest::of(&machine.host.ram[..FETCH_PAGE as usize]);
    assert_eq!(machine.pages[&page(0)].key, changed);
    // An IC IVAU forgets the known key too.
    machine.invalidate_code_page(page(0));
    assert!(machine.fetch_block(page(0) + 12, false).is_ok());
    assert_eq!(machine.statistics.known_keys, known);
}

#[test]
#[ignore = "manual: opt-in"]
fn page_hash_costs() {
    // What a fetch page read again costs: its check, and the SHA-256 a key
    // not known takes.
    let mut page = Box::new([0u8; PAGE_BYTES]);
    for (at, byte) in page.iter_mut().enumerate() {
        *byte = (at as u32).wrapping_mul(2_654_435_761).to_le_bytes()[3];
    }
    const ROUNDS: u32 = 100_000;
    let started = std::time::Instant::now();
    let mut checks = 0u64;
    for round in 0..ROUNDS {
        page[0] = round as u8;
        checks ^= super::page_check(&page);
    }
    let check = started.elapsed().as_nanos() / u128::from(ROUNDS);
    let started = std::time::Instant::now();
    let mut keys = 0u8;
    for round in 0..ROUNDS {
        page[0] = round as u8;
        keys ^= Digest::of(page.as_slice()).0[0];
    }
    let hash = started.elapsed().as_nanos() / u128::from(ROUNDS);
    let keys_table = crate::machine::engine::known_keys::KnownKeys::default();
    let started = std::time::Instant::now();
    for round in 0..u64::from(ROUNDS) {
        let frame = (round % 200_000) << 12;
        if keys_table.get(1 << 18, frame, round).is_none() {
            keys_table.put(
                1 << 18,
                frame,
                round,
                crate::machine::engine::known_keys::Known {
                    key: Digest([round as u8; 32]),
                    absent: false,
                },
            );
        }
    }
    let table = started.elapsed().as_nanos() / u128::from(ROUNDS);
    std::println!(
        "4 KiB page: check {check} ns, SHA-256 {hash} ns, known-key table {table} ns ({checks:x} {keys})"
    );
}

#[test]
fn a_page_read_again_whose_record_was_absent_is_not_looked_up_again() {
    // A block in each of five pages: add x0, x0, #1; svc #0.
    const PAGE_WORDS: usize = FETCH_PAGE as usize / INSTRUCTION as usize;
    let mut words = vec![0; 4 * PAGE_WORDS + 2];
    for page in 0..5 {
        words[page * PAGE_WORDS..page * PAGE_WORDS + 2]
            .copy_from_slice(&[0x9100_0400, 0xd400_0001]);
    }
    let mut machine = machine(&words);
    machine.host.store = Some(MemoryStore::default());
    let page = |n: u64| BASE + n * FETCH_PAGE;
    let lookups = |store: &Option<MemoryStore>| store.as_ref().unwrap().lookups;
    for n in 0..5 {
        assert!(machine.fetch_block(page(n), false).is_ok());
    }
    assert_eq!(lookups(&machine.host.store), 5);
    // Page 0 was let go; read again, its absent record is not asked for.
    assert!(!machine.pages.contains_key(&page(0)));
    assert!(machine.fetch_block(page(0) + 4, false).is_ok());
    assert_eq!(lookups(&machine.host.store), 5);
    assert_eq!(machine.statistics.known_absent, 1);
    // Its bytes changed: a new key, looked up.
    for n in 1..5 {
        assert!(machine.fetch_block(page(n) + 4, false).is_ok());
    }
    let before = lookups(&machine.host.store);
    machine.host.ram[100] ^= 1;
    assert!(machine.fetch_block(page(0) + 8, false).is_ok());
    assert_eq!(lookups(&machine.host.store), before + 1);
}

#[test]
fn a_stored_install_relocates_into_the_machines_own_buffers() {
    // adr x0, #8; add x0, x0, #1; svc #0, twice in the page.
    let words = [
        0x1000_0040,
        0x9100_0400,
        0xd400_0001,
        0x1000_0040,
        0x9100_0400,
        0xd400_0001,
    ];
    let mut first = machine(&words);
    first.host.store = Some(MemoryStore::default());
    assert!(first.fetch_block(BASE, false).is_ok());
    assert!(first.fetch_block(BASE + 12, false).is_ok());
    let offers = core::mem::take(&mut first.host.store.as_mut().unwrap().offers);
    let mut record = Record::new(translations::translator_id(), offers[0].key);
    for offer in &offers {
        record.insert(offer.entry().unwrap());
    }
    let mut store = MemoryStore::default();
    store.records.insert(offers[0].key, Arc::new(record));
    let mut second = machine(&words);
    second.host.store = Some(store);
    assert!(second.fetch_block(BASE, false).is_ok());
    let buffer = second.relocated.code.as_ptr();
    assert!(second.fetch_block(BASE + 12, false).is_ok());
    assert_eq!(second.statistics.stored, 2);
    assert_eq!(second.relocated.code.as_ptr(), buffer);
    // Each block's code is what the compiling machine installed.
    assert_eq!(second.host.installed, first.host.installed);
}

#[test]
fn with_memory_low_pages_stay_and_nothing_is_offered() {
    // A block in each of two pages: add x0, x0, #1; svc #0.
    const PAGE_WORDS: usize = FETCH_PAGE as usize / INSTRUCTION as usize;
    let mut words = vec![0; PAGE_WORDS + 2];
    for page in 0..2 {
        words[page * PAGE_WORDS..page * PAGE_WORDS + 2]
            .copy_from_slice(&[0x9100_0400, 0xd400_0001]);
    }
    let mut machine = machine(&words);
    machine.host.store = Some(MemoryStore::default());
    // Nothing to reclaim yet, which would forget the first page's block.
    machine.memory_release_blocks = usize::MAX;
    assert!(machine.fetch_block(BASE, false).is_ok());
    assert_eq!(machine.statistics.offered, 1);
    machine.host.memory_low = true;
    assert!(machine.fetch_block(BASE + FETCH_PAGE, false).is_ok());
    assert_eq!(
        machine.pages.keys().copied().collect::<Vec<_>>(),
        [BASE, BASE + FETCH_PAGE]
    );
    assert_eq!(machine.statistics.offered, 1);
    assert_eq!(machine.host.store.as_ref().unwrap().offers.len(), 1);
}

/// `PES STORE`: every install counts once, at its level, by where its
/// block came from: compiled with a store page, compiled without one,
/// relocated from the pack, or taken from another PE.
#[test]
fn installs_count_where_their_block_came_from_at_their_level() {
    use super::super::StoreSource;
    const USER: usize = 0;
    const KERNEL: usize = 1;
    let count = |source: StoreSource| source as usize;
    // adr x0, #8; add x0, x0, #1; svc #0
    let words = [0x1000_0040, 0x9100_0400, 0xd400_0001];
    let mut first = machine(&words);
    first.host.store = Some(MemoryStore::default());
    assert!(first.fetch_block(BASE + 4, false).is_ok());
    let mut sources = [[0; StoreSource::COUNT]; 2];
    sources[KERNEL][count(StoreSource::Compiled)] = 1;
    assert_eq!(first.statistics.store_sources, sources);

    let offer = first.host.store.as_mut().unwrap().offers.pop().unwrap();
    let mut record = Record::new(translations::translator_id(), offer.key);
    record.insert(offer.entry().unwrap());
    let mut store = MemoryStore::default();
    store.records.insert(offer.key, Arc::new(record));
    store
        .prepared
        .insert((offer.key, BASE + 8, offer.context), {
            let input = offer.input()[4..].to_vec();
            Offer::compile(
                offer.key,
                offer.page,
                BASE + 8,
                offer.context,
                input,
                Arc::clone(offer.preparation()),
            )
            .unwrap()
            .shared()
        });
    let mut second = machine(&words);
    second.host.store = Some(store);
    assert!(second.fetch_block(BASE + 4, false).is_ok());
    assert!(second.fetch_block(BASE + 8, false).is_ok());
    let mut sources = [[0; StoreSource::COUNT]; 2];
    sources[KERNEL][count(StoreSource::Pack)] = 1;
    sources[KERNEL][count(StoreSource::Shared)] = 1;
    assert_eq!(second.statistics.store_sources, sources);
    assert_eq!((second.statistics.stored, second.statistics.shared), (1, 1));

    // Without a store no page is keyed; at EL0 the counts go to the user row.
    let mut user = machine(&words);
    super::super::tests::normal_memory(&mut user, true);
    user.cpu.pstate.el = 0;
    assert!(matches!(
        user.fetch_block(BASE + 4, false),
        Ok(Fetched::Block(_))
    ));
    let mut sources = [[0; StoreSource::COUNT]; 2];
    sources[USER][count(StoreSource::Unstorable)] = 1;
    assert_eq!(user.statistics.store_sources, sources);
    assert_eq!(user.statistics.compiled, 1);
}

/// The same page content at four addresses: compiled at the first,
/// compiled and kept at the second, rebased at the third, where it is
/// what a compile there installs. A rewritten page is compiled again.
#[test]
fn a_block_compiled_at_two_addresses_is_rebased_at_a_third() {
    use super::super::tests::{FakeHost, NATIVE_CODE_STRIDE};
    const PAGE_WORDS: usize = FETCH_PAGE as usize / INSTRUCTION as usize;
    // adr x0, #8; add x0, x0, #1; svc #0, at the start of each page.
    let block = [0x1000_0040, 0x9100_0400, 0xd400_0001];
    let mut words = vec![0; 3 * PAGE_WORDS + block.len()];
    for page in 0..4 {
        words[page * PAGE_WORDS..page * PAGE_WORDS + block.len()].copy_from_slice(&block);
    }
    let page = |n: u64| BASE + n * FETCH_PAGE;
    let mut reusing = machine(&words);
    reusing.host.store = Some(MemoryStore::default());
    assert!(reusing.fetch_block(page(0), false).is_ok());
    assert_eq!(reusing.code.rebases.counts().kept, 0);
    assert!(reusing.fetch_block(page(1), false).is_ok());
    assert_eq!(reusing.statistics.compiled, 2);
    assert_eq!(reusing.code.rebases.counts().kept, 1);
    let Ok(Fetched::Block(rebased)) = reusing.fetch_block(page(2), false) else {
        panic!("rebased block")
    };
    assert_eq!(reusing.statistics.compiled, 2);
    let counts = reusing.code.rebases.counts();
    assert_eq!((counts.hits, counts.kept, counts.unstorable), (1, 1, 0));
    assert_eq!(
        reusing.statistics.store_sources[1][super::super::StoreSource::Rebased as usize],
        1
    );

    type Fake = super::super::Machine<FakeHost, crate::machine::NoDevices>;
    let installed = |machine: &Fake, index: usize| {
        let block = &machine.code.blocks[index];
        (
            machine.host.installed[block.code.0 / NATIVE_CODE_STRIDE - 1].clone(),
            block.pc,
            block.source_bytes(),
            block.instructions,
            block.terminal,
            block.successors.len(),
        )
    };
    let mut fresh = machine(&words);
    let Ok(Fetched::Block(compiled)) = fresh.fetch_block(page(2), false) else {
        panic!("compiled block")
    };
    assert_eq!(installed(&reusing, rebased), installed(&fresh, compiled));

    // The third page rewritten (add x0, x0, #2): another key, compiled.
    words[2 * PAGE_WORDS + 1] = 0x9100_0800;
    let at = 2 * FETCH_PAGE as usize + 4;
    reusing.host.ram[at..at + 4].copy_from_slice(&0x9100_0800u32.to_le_bytes());
    reusing.invalidate_code_page(page(2));
    let Ok(Fetched::Block(changed)) = reusing.fetch_block(page(2), false) else {
        panic!("compiled block")
    };
    assert_eq!(reusing.statistics.compiled, 3);
    assert_eq!(reusing.code.rebases.counts().hits, 1);
    let mut fresh = machine(&words);
    let Ok(Fetched::Block(compiled)) = fresh.fetch_block(page(2), false) else {
        panic!("compiled block")
    };
    assert_eq!(installed(&reusing, changed), installed(&fresh, compiled));
    // The fourth page still holds the kept content.
    assert!(reusing.fetch_block(page(3), false).is_ok());
    assert_eq!(
        (
            reusing.statistics.compiled,
            reusing.code.rebases.counts().hits
        ),
        (3, 2)
    );
}

/// What fetching every block of a code image costs, as the engine
/// prepares them: `STELA_COMPILE_BENCH` names a file of A64 code
/// (`STELA_COMPILE_OFFSET`, `STELA_COMPILE_BYTES` choose a part), swept
/// block after block from its start. Prints per-block costs of the
/// compile, the store's proof and its record encoding and decoding.
/// A preparation as a boot's kernel PEs compile with: system mode with its
/// range checks, exclusives, pointer cells and self loops.
fn system_preparation(target: stela_compiler::TargetCpu) -> Preparation {
    use stela_compiler::x86_64::{MemoryChecks, NativeSystem, RangeCheck};
    let chip = crate::machine::test_chip();
    let checks = MemoryChecks::system(true, false, true, false)
        .with_range(RangeCheck::four_level(4).one_sided(true));
    let system = NativeSystem {
        exclusive: true,
        pointer: Some(super::super::pointer::CELLS),
        self_loops: true,
        ..NativeSystem::NONE
    };
    Preparation::new(
        chip,
        Arc::new(chip.admit_table(0).expect("admit")),
        target,
        true,
        checks,
        None,
        system,
    )
}

/// One instruction word of a kind whose code may name its own address or
/// fold a value derived from it: PC-relative addresses, additions and wide
/// moves over them, literal loads and prefetches, branches and links, and
/// ordinary memory and register work between them. Registers come from a
/// few, so that the words depend on each other.
fn address_word(random: &mut impl FnMut() -> u32) -> u32 {
    let register = |value: u32| value % 4;
    let (r, n, value) = (register(random()), register(random()), random());
    match random() % 16 {
        0 => 0x1000_0000 | ((value & 3) << 29) | (((value >> 2) & 0x7ffff) << 5) | r,
        1 => 0x9000_0000 | ((value & 3) << 29) | (((value >> 2) & 0x7ffff) << 5) | r,
        2 | 3 => 0x9100_0000 | ((value & 0xfff) << 10) | (n << 5) | r,
        4 => 0x1100_0000 | ((value & 0xfff) << 10) | (n << 5) | r,
        5 => 0xd100_0000 | ((value & 0xfff) << 10) | (n << 5) | r,
        6 => 0xd280_0000 | ((value & 3) << 21) | (((value >> 2) & 0xffff) << 5) | r,
        7 => 0xf280_0000 | ((value & 3) << 21) | (((value >> 2) & 0xffff) << 5) | r,
        8 => 0x7280_0000 | ((value & 1) << 21) | (((value >> 2) & 0xffff) << 5) | r,
        9 => {
            [0x5800_0000, 0x1800_0000, 0x9800_0000, 0x9c00_0000][value as usize % 4]
                | (((value >> 2) & 0x3ff) << 5)
                | r
        }
        10 => 0xd800_0000 | (((value >> 2) & 0x3ff) << 5),
        11 => 0xf940_0000 | ((value & 0x3f) << 10) | (n << 5) | r,
        12 => 0xf900_0000 | ((value & 0x3f) << 10) | (n << 5) | r,
        13 => 0x8b00_0000 | ((value & 3) << 16) | (n << 5) | r,
        14 => 0xd503_201f,
        _ => 0xaa00_03e0 | (n << 16) | r,
    }
}

/// A word that ends a block: conditional, compare and test branches near
/// and far, direct and linked branches, a register call, a return or a
/// trap.
fn ending_word(random: &mut impl FnMut() -> u32) -> u32 {
    let (r, value) = (random() % 4, random());
    match random() % 8 {
        0 => 0x5400_0000 | (((value >> 4) & 0x7ffff) << 5) | (value % 14),
        1 => 0xb400_0000 | (((value >> 4) & 0x7ffff) << 5) | r,
        2 => 0x3600_0000 | ((value & 0x1f) << 19) | (((value >> 5) & 0x3fff) << 5) | r,
        3 => 0x1400_0000 | (value >> 6),
        4 => 0x9400_0000 | (value >> 6),
        5 => 0xd63f_0000 | (r << 5),
        6 => 0xd65f_03c0,
        _ => 0xd400_0001,
    }
}

/// Every block's stored form, made from the relocations its compiler
/// recorded, is what compiling it again at other pages proves: the fields
/// that move are those, each by its page's displacement, and nothing else
/// moves. Blocks of every kind above, in a process's preparation and a
/// kernel's, at several places in their page.
#[test]
fn recorded_relocations_are_the_fields_that_move_with_the_page() {
    use super::super::Prepared;
    let mut state = 0x9e37_79b9u32;
    let mut random = move || {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        state
    };
    let preparations = [
        crate::machine::test_preparation(),
        system_preparation(stela_compiler::TargetCpu::Baseline),
    ];
    let page = 0x1_8000_4000u64;
    let (mut stored, mut checked) = (0, 0);
    for block in 0..4000 {
        let mut words: Vec<u32> = (0..1 + random() % 8)
            .map(|_| address_word(&mut random))
            .collect();
        words.push(ending_word(&mut random));
        let mut source: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let preparation = &preparations[block % 2];
        preparation.admit(&mut source);
        let pc = page + u64::from(random() % 64) * 4;
        let Ok(Prepared::Block {
            compiled, input, ..
        }) = preparation.prepare(&source, pc, source.len())
        else {
            continue;
        };
        let input = &source[..input];
        let context = preparation.context(page);
        let entry = translations::Entry::stored(&compiled, input, page, pc, context);
        let probes = translations::probe_displacements(page)
            .map(|displacement| preparation.compile_input(input, pc.wrapping_add(displacement)));
        let [Ok(first), Ok(second)] = &probes else {
            panic!("{words:08x?} compiles at every page");
        };
        let proven = translations::prove(&compiled, input, page, pc, context, [first, second]);
        assert_eq!(
            entry.as_ref().map(|entry| &entry.relocations),
            proven.as_ref().map(|entry| &entry.relocations),
            "{words:08x?} at {pc:#x}"
        );
        assert_eq!(entry, proven, "{words:08x?} at {pc:#x}");
        checked += 1;
        stored += usize::from(entry.is_some());
    }
    // Every block has a stored form.
    assert!(checked > 3500 && stored == checked, "{stored} of {checked}");
}

#[test]
#[ignore = "manual: opt-in"]
fn compile_bench() {
    use super::super::{Prepared, window};
    let path = std::env::var("STELA_COMPILE_BENCH").expect("STELA_COMPILE_BENCH");
    let number = |name: &str, default: usize| {
        std::env::var(name)
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(default)
    };
    let offset = number("STELA_COMPILE_OFFSET", 0);
    let bytes = number("STELA_COMPILE_BYTES", 4 << 20);
    let image = std::fs::read(path).expect("the code image");
    let image = &image[offset.min(image.len())..(offset + bytes).min(image.len())];
    let preparation = system_preparation(stela_compiler::TargetCpu::detect());
    let base = 0x1_8000_0000u64;
    let (mut blocks, mut instructions, mut code, mut refused) = (0u64, 0u64, 0u64, 0u64);
    let mut kept = Vec::new();
    let started = std::time::Instant::now();
    let mut at = 0usize;
    while at + 4 <= image.len() {
        let pc = base + at as u64;
        let page_end = (at as u64 | (FETCH_PAGE - 1)) + 1;
        let end = (page_end as usize).min(image.len()).min(at + window(pc));
        let mut source = image[at..end].to_vec();
        preparation.admit(&mut source);
        match preparation.prepare(&source, pc, source.len()) {
            Ok(Prepared::Block {
                compiled, input, ..
            }) => {
                blocks += 1;
                instructions += compiled.source_bytes as u64 / 4;
                code += compiled.native.x86_64_code.len() as u64;
                at += compiled.source_bytes.max(4);
                if kept.len() < 20_000 {
                    kept.push((pc, source[..input].to_vec(), compiled));
                }
            }
            _ => {
                refused += 1;
                at += 4;
            }
        }
    }
    let compile = started.elapsed();
    // Each kept block's stored form as the compiler made it, then the
    // block compiled again at both probe pages: the fields that moved
    // must be the relocations it recorded.
    let started = std::time::Instant::now();
    let mut entries = Vec::new();
    for (pc, input, compiled) in &kept {
        let page = pc & !(FETCH_PAGE - 1);
        let context = preparation.context(page);
        if let Some(entry) = translations::Entry::stored(compiled, input, page, *pc, context) {
            entries.push((page, *pc, entry));
        }
    }
    let store = started.elapsed();
    let (mut differed, mut provable_unstorable) = (0, 0);
    for (pc, input, compiled) in &kept {
        let page = pc & !(FETCH_PAGE - 1);
        let context = preparation.context(page);
        let probes = translations::probe_displacements(page)
            .map(|displacement| preparation.compile_input(input, pc.wrapping_add(displacement)));
        let proven = match &probes {
            [Ok(first), Ok(second)] => {
                translations::prove(compiled, input, page, *pc, context, [first, second])
            }
            _ => None,
        };
        let stored = entries
            .iter()
            .find(|(_, at, _)| at == pc)
            .map(|(_, _, entry)| entry);
        match (stored, &proven) {
            (Some(stored), proven) if proven.as_ref() != Some(stored) => {
                differed += 1;
                println!("DIFFERED {pc:#x}");
            }
            (None, Some(_)) => provable_unstorable += 1,
            _ => {}
        }
    }
    let entries: Vec<(u64, translations::Entry)> = entries
        .into_iter()
        .map(|(page, _, entry)| (page, entry))
        .collect();
    let translator = translations::translator_id();
    let mut records = std::collections::BTreeMap::new();
    for (page, entry) in &entries {
        records
            .entry(*page)
            .or_insert_with(|| {
                translations::Record::new(translator, Digest::of(&page.to_le_bytes()))
            })
            .insert(entry.clone());
    }
    let started = std::time::Instant::now();
    let encoded: Vec<(Digest, Vec<u8>)> = records
        .values()
        .map(|record| (record.key, record.encode()))
        .collect();
    let encode = started.elapsed();
    let started = std::time::Instant::now();
    for (key, bytes) in &encoded {
        translations::Record::decode(bytes, &translator, key).expect("a record");
    }
    let decode = started.elapsed();
    let encoded_bytes: usize = encoded.iter().map(|(_, bytes)| bytes.len()).sum();
    let retained: usize = entries
        .iter()
        .map(|(_, entry)| entry.retained_bytes())
        .sum();
    let per =
        |time: std::time::Duration, count: usize| time.as_secs_f64() * 1e6 / count.max(1) as f64;
    println!(
        "blocks={blocks} refused={refused} instructions={instructions} \
         host_bytes_per_instruction={:.1} compile_us_per_block={:.2}",
        code as f64 / instructions.max(1) as f64,
        per(compile, blocks as usize),
    );
    println!(
        "stored={} of {} differed={differed} provable_unstorable={provable_unstorable} \
         store_us_per_block={:.2} records={} encode_us_per_entry={:.2} \
         decode_us_per_entry={:.2} encoded_bytes_per_entry={} retained_bytes_per_entry={}",
        entries.len(),
        kept.len(),
        per(store, kept.len()),
        encoded.len(),
        per(encode, entries.len()),
        per(decode, entries.len()),
        encoded_bytes / entries.len().max(1),
        retained / entries.len().max(1),
    );
}
