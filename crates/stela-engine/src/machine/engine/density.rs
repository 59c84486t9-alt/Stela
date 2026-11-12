//! Code density measurements, run by hand: the native code blocks of a
//! sample compile to, and the chain machinery's pieces, as hex for offline
//! counting. Ignored tests, so `cargo test` never runs them; neither reads
//! anything a translation depends on.
use super::prepare::{Preparation, Prepared};
use alloc::{format, string::String, sync::Arc, vec::Vec};
use stela_compiler::{
    TargetCpu,
    x86_64::{MemoryChecks, NativeSystem, RangeCheck, chain},
};

/// Prepare each block of the sample `DENSITY_IN` names, one line each:
/// its hex PC, a weight and its hex bytes. `DENSITY_OUT` gets a line per
/// block: the PC, the weight, the source bytes it took, its hex code and
/// its source map (`pc:offset`), or why it was refused.
#[test]
#[ignore = "manual: opt-in"]
fn density_dump() {
    use std::io::Write;
    let input = std::env::var("DENSITY_IN").expect("DENSITY_IN names the sample");
    let output = std::env::var("DENSITY_OUT").expect("DENSITY_OUT names the output");
    let chip = crate::machine::test_chip();
    let checks = MemoryChecks::system(true, false, true, false)
        .with_range(RangeCheck::four_level(4).one_sided(true));
    let system = NativeSystem {
        exclusive: true,
        pointer: Some(super::pointer::CELLS),
        self_loops: true,
        ..NativeSystem::NONE
    };
    let preparation = Preparation::new(
        chip,
        Arc::new(chip.admit_table(0).expect("the test chip's admit table")),
        TargetCpu::detect(),
        true,
        checks,
        None,
        system,
    );
    let mut out = std::fs::File::create(output).expect("the output");
    let sample = std::fs::read_to_string(input).expect("the sample");
    for line in sample.lines() {
        let mut fields = line.split(' ');
        let (Some(pc), Some(weight), Some(hex)) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let pc = u64::from_str_radix(pc, 16).expect("a hex PC");
        let bytes: Vec<u8> = (0..hex.len() / 2)
            .map(|at| u8::from_str_radix(&hex[2 * at..2 * at + 2], 16).expect("hex bytes"))
            .collect();
        match preparation.prepare_window(&bytes, pc, bytes.len(), true) {
            Some(Ok(Prepared::Block { compiled, .. })) => {
                let map: Vec<String> = compiled
                    .native
                    .source_map
                    .iter()
                    .map(|(pc, offset)| format!("{:x}:{offset}", pc.0))
                    .collect();
                writeln!(
                    out,
                    "{pc:x} {weight} {} {} {}",
                    compiled.source_bytes,
                    hex_of(&compiled.native.x86_64_code),
                    map.join(",")
                )
                .expect("written");
            }
            other => writeln!(out, "{pc:x} {weight} refused {other:?}").expect("written"),
        }
    }
}

/// The chain machinery's pieces to `DENSITY_OUT`, a line each: a link's
/// body, the cell and table probes, a stamped tail and a lookup tail.
#[test]
#[ignore = "manual: opt-in"]
fn chain_dump() {
    use stela_compiler::block::ExitKind;
    let output = std::env::var("DENSITY_OUT").expect("DENSITY_OUT names the output");
    let mut text = String::new();
    let (_, body) = chain::link(0x10_0000, chain::LINK_BYTES, 5, 7, 0x20_0000).expect("a link");
    text += &format!("link {}\n", hex_of(&body));
    let dispatcher = chain::lookup_dispatcher(0).expect("the probes");
    text += &format!("cell {}\n", hex_of(&dispatcher[..chain::PROBE_ENTRY]));
    let probe = &dispatcher[chain::PROBE_ENTRY..chain::STAMPING_PROBE_ENTRY];
    text += &format!("probe {}\n", hex_of(probe));
    let stamped = chain::stamped_tail(
        0x10_0000,
        0x30_0000,
        9,
        0x4000,
        ExitKind::Direct,
        5,
        7,
        0x20_0000,
        0x10_8000,
    )
    .expect("a stamped tail");
    text += &format!("stamped {}\n", hex_of(&stamped));
    let lookup =
        chain::lookup_tail(0x10_0000, ExitKind::Return, 5, 0x10_8000, 0).expect("a lookup tail");
    text += &format!("lookup {}\n", hex_of(&lookup));
    std::fs::write(output, text).expect("written");
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
