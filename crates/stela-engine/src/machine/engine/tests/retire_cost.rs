//! Host timing of a ring part's retirement: the code-lock time it takes
//! per block, with and without links into the part's blocks. Manual:
//! `cargo test -p stela-engine --release --lib retire_cost -- --ignored --nocapture`.

use super::super::board;
use super::*;
use std::time::Instant;

const RET: u32 = 0xd65f_03c0;
const B8: u32 = 0x1400_0002; // b .+8

struct Measured {
    blocks: usize,
    ns: u128,
    steps: u64,
    visits: u64,
}

fn retire_one_part(pages: usize, link: bool) -> Measured {
    let words: Vec<u32> = [B8, 0, RET, 0]
        .iter()
        .copied()
        .cycle()
        .take(pages * FETCH_PAGE as usize / 4)
        .collect();
    let mut memory = vec![0u8; 16 << 20];
    let mut machine = machine(&words);
    let address = memory.as_mut_ptr() as usize;
    machine.code = Arc::new(board::Code::new(
        board::slot_capacity(Some(memory.len())),
        chain::MIN_LOOKUP_ENTRIES,
        Some(CodeWindow {
            exec: address,
            write: address,
            bytes: memory.len(),
        }),
    ));
    let base = machine.cpu.pc;
    let mut first = None;
    for group in 0..FETCH_PAGE / 16 {
        for page in 0..pages as u64 {
            let pc = base + page * FETCH_PAGE + 16 * group;
            let Ok(Fetched::Block(from)) = machine.fetch_block(pc, false) else {
                panic!("a block")
            };
            assert!(matches!(
                machine.fetch_block(pc + 8, false),
                Ok(Fetched::Block(_))
            ));
            if link {
                machine.link(from, pc + 8, ExitKind::Direct);
            }
            first.get_or_insert(from);
        }
    }
    let first = first.expect("blocks");
    let arena = machine.code.arena.as_ref().expect("an arena");
    let code = machine.code.blocks[first].code.0;
    let part = (code - arena.window.exec) / arena.part_bytes;
    let start = arena.window.exec + part * arena.part_bytes;
    let range = start..start + arena.part_bytes;
    let blocks = (0..machine.code.blocks.len())
        .filter(|&slot| {
            machine
                .code
                .blocks
                .installed(slot)
                .is_some_and(|block| range.contains(&block.code.0))
        })
        .count();
    let started = Instant::now();
    machine.evict_code(range);
    let ns = started.elapsed().as_nanos();
    let events = &machine.code.events;
    Measured {
        blocks,
        ns,
        steps: events
            .retire_steps
            .load(core::sync::atomic::Ordering::Relaxed),
        visits: events
            .retire_visits
            .load(core::sync::atomic::Ordering::Relaxed),
    }
}

#[test]
#[ignore = "manual: opt-in"]
fn retire_cost() {
    for pages in [4, 12] {
        for link in [false, true] {
            let m = retire_one_part(pages, link);
            std::println!(
                "pages={pages} linked={link} blocks={} ns/block={} steps={} visits={}",
                m.blocks,
                m.ns / m.blocks.max(1) as u128,
                m.steps,
                m.visits
            );
        }
    }
}
