//! Manual cost report of compiled FP conversion blocks on every target rung
//! the host runs: ns per conversion in a block of 16 independent ones less a
//! block of 16 NOPs (the fastest of 15 samples each), `exit` when the first
//! conversion leaves for the software completion (about 1 us per exit in the
//! guest), or `end` when it ends its block. Exactness is tested by
//! `fast_conversion_tests`.
use crate::{
    GuestAddress, GuestState, Options, TargetCpu,
    block::{BlockProfile, CompilationPlan},
    context::ExecutionContext,
    x86_64::{asm::vector_extensions::execution::Native, native::run},
};
use alloc::{format, string::String, vec::Vec};
use std::{hint::black_box, time::Instant};

const PC: GuestAddress = GuestAddress(0x1000_0000);
const RETURN: u64 = 0x4000;
const INPUT: usize = 16;
const OPERATIONS: u32 = 16;
const NOP: u32 = 0xd503_201f;

/// (name, word with Rd = 0 and Rn = 16, single-precision inputs).
const FORMS: &[(&str, u32, bool)] = &[
    ("fcvtzs x,d", 0x9e78_0200, false),
    ("fcvtas x,d", 0x9e64_0200, false),
    ("fcvtau x,d", 0x9e65_0200, false),
    ("fcvtas w,s", 0x1e24_0200, true),
    ("fcvtas d,d", 0x5e61_ca00, false),
    ("fcvt h,s", 0x1e23_c200, true),
    ("fcvtn 4h", 0x0e21_6a00, true),
    ("fcvtn2 8h", 0x4e21_6a00, true),
];

/// Input classes: a fractional magnitude in [1, 1024) of either sign, or
/// zero, in every lane of V16.
const INPUTS: &[(&str, f64)] = &[("+", 300.7), ("-", -300.7), ("0", 0.0)];

fn state(single: bool, value: f64) -> GuestState {
    let mut state = GuestState::default();
    state.x[30] = RETURN;
    state.v[INPUT] = if single {
        let lane = u64::from((value as f32).to_bits());
        [lane | lane << 32; 2]
    } else {
        [value.to_bits(); 2]
    };
    state
}

/// A block of 16 `word`s with Rd = 0 to 15 (16 NOPs for a NOP), then RET.
fn compile(word: u32, target: TargetCpu) -> Vec<u8> {
    let mut words: Vec<u32> = (0..OPERATIONS)
        .map(|rd| if word == NOP { NOP } else { word | rd })
        .collect();
    words.push(0xd65f_03c0);
    let source: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
    CompilationPlan::new(&source, PC, &Options::new(BlockProfile::ORDINARY, target))
        .unwrap()
        .compile()
        .unwrap()
        .native
        .x86_64_code
}

/// ns per run of the block of `word`, or why it does not run through.
fn block(word: u32, single: bool, value: f64, target: TargetCpu) -> Result<f64, &'static str> {
    let code = compile(word, target);
    let initial = state(single, value);
    let mut probe = initial.clone();
    match run(&code, &mut probe) {
        RETURN => {}
        exit if exit == PC.0 => return Err("exit"),
        _ => return Err("end"),
    }
    let native = Native::new(&code);
    let mut context = ExecutionContext::default();
    let iterations = 50_000_u32;
    let mut best = f64::INFINITY;
    for _ in 0..15 {
        let mut state = initial.clone();
        let start = Instant::now();
        for _ in 0..iterations {
            native.run(&mut state, &mut context);
            black_box(&mut state);
        }
        best = best.min(start.elapsed().as_nanos() as f64 / f64::from(iterations));
    }
    Ok(best)
}

fn measure(word: u32, single: bool, value: f64, target: TargetCpu) -> String {
    match block(word, single, value, target) {
        Ok(ns) => {
            let empty = block(NOP, single, value, target).unwrap();
            format!("{:>5.2}ns", (ns - empty) / f64::from(OPERATIONS))
        }
        Err(why) => format!("{why:>7}"),
    }
}

#[test]
#[ignore = "manual: opt-in"]
fn conversion_costs() {
    let host = TargetCpu::detect();
    let mut targets = alloc::vec![
        ("base", TargetCpu::Baseline),
        ("v2", TargetCpu::X86_64_V2),
        ("v2+f16c", TargetCpu::X86_64_V2.with_f16c()),
        ("v3", TargetCpu::X86_64_V3),
        ("v4", TargetCpu::X86_64_V4),
    ];
    targets.retain(|(_, target)| host.supports(*target));
    targets.push(("host", host));
    std::println!(
        "CONVERSION_COSTS SOURCE_SHA256={} host={}",
        crate::SOURCE_SHA256,
        host.id()
    );
    let mut header = format!("{:<13}", "form");
    for (name, _) in &targets {
        header += &format!(" {name:>7}");
    }
    std::println!("{header}");
    for &(name, word, single) in FORMS {
        for &(label, value) in INPUTS {
            let mut row = format!("{:<13}", format!("{name} {label}"));
            for &(_, target) in &targets {
                row += &format!(" {}", measure(word, single, value, target));
            }
            std::println!("{row}");
        }
    }
}
