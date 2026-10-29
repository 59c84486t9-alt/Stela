//! Independent Arm execution oracle; the emulator and LLVM tools are inputs.
use super::*;
use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};
use std::{fs, path::PathBuf, process::Command};

fn instruction(operand: Operand) -> String {
    let Operand {
        kind,
        destination: d,
        left: n,
        right: m,
    } = operand;
    match kind {
        Kind::Schedule1 => format!("sm3partw1 v{d}.4s, v{n}.4s, v{m}.4s"),
        Kind::Schedule2 => format!("sm3partw2 v{d}.4s, v{n}.4s, v{m}.4s"),
        Kind::Sum { third: a } => format!("sm3ss1 v{d}.4s, v{n}.4s, v{m}.4s, v{a}.4s"),
        Kind::Round {
            second,
            nonlinear,
            lane,
        } => format!(
            "sm3tt{}{} v{d}.4s, v{n}.4s, v{m}.s[{lane}]",
            if second { 2 } else { 1 },
            if nonlinear { 'b' } else { 'a' }
        ),
    }
}
fn run(command: &mut Command) {
    let result = command.output().unwrap();
    assert!(
        result.status.success(),
        "{command:?}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
#[ignore = "oracle: STELA_TEST_LLD, STELA_TEST_LLVM_MC, STELA_TEST_SM3_QEMU"]
fn baseline_sm3_matches_stock_aarch64_qemu() {
    let input = |key| PathBuf::from(std::env::var_os(key).expect(key));
    let qemu = input("STELA_TEST_SM3_QEMU");
    let llvm = input("STELA_TEST_LLVM_MC");
    let linker = input("STELA_TEST_LLD");
    let output = std::env::temp_dir().join(format!("stela-sm3-oracle-{}", std::process::id()));
    fs::create_dir_all(&output).unwrap();
    let mut text = String::from(
        ".text\n.global _start\n_start:\nadrp x19, inputs\nadd x19,x19,:lo12:inputs\nadrp x20, results\nadd x20,x20,:lo12:results\n",
    );
    let mut inputs = Vec::new();
    let mut expected = Vec::new();
    let mut random = 0xbb67ae8584caa73b_u64;
    let mut count = 0_usize;
    for destination in [0, 31] {
        for left in [destination, 1] {
            for right in [destination, left, 2] {
                for third in [destination, left, right, 3] {
                    let mut kinds =
                        alloc::vec![Kind::Schedule1, Kind::Schedule2, Kind::Sum { third }];
                    for lane in 0..4 {
                        for second in [false, true] {
                            for nonlinear in [false, true] {
                                kinds.push(Kind::Round {
                                    second,
                                    nonlinear,
                                    lane,
                                });
                            }
                        }
                    }
                    for kind in kinds {
                        let operand = Operand {
                            kind,
                            destination,
                            left,
                            right,
                        };
                        let mut code = Code::new();
                        emit(&mut code, &operand);
                        code.asm().ret();
                        if (destination, left, right, third) == (0, 1, 2, 3) {
                            fs::write(
                                output.join(format!("lowered-{kind:?}.bin")),
                                code.as_slice(),
                            )
                            .unwrap();
                        }
                        let native = Native::new(&code);
                        for sample in 0..8 {
                            let mut state = GuestState::default();
                            for v in &mut state.v {
                                for word in v {
                                    random ^= random << 13;
                                    random ^= random >> 7;
                                    random ^= random << 17;
                                    *word = match sample {
                                        0 => 0,
                                        1 => u64::MAX,
                                        2 => 0x8000000080000000,
                                        3 => 0x7fffffff7fffffff,
                                        _ => random,
                                    };
                                    inputs.extend(word.to_le_bytes());
                                }
                            }
                            let result = reference(
                                kind,
                                words(state.v[usize::from(destination)]),
                                words(state.v[usize::from(left)]),
                                words(state.v[usize::from(right)]),
                                words(state.v[usize::from(third)]),
                            );
                            let result = vector(result);
                            native.run(&mut state, &mut ExecutionContext::default());
                            assert_eq!(state.v[usize::from(destination)], result);
                            for word in result {
                                expected.extend(word.to_le_bytes());
                            }
                            for register in [destination, left, right, third] {
                                text.push_str(&format!(
                                    "ldr q{register}, [x19,#{}]\n",
                                    u32::from(register) * 16
                                ));
                            }
                            text.push_str(&instruction(operand));
                            text.push_str("\nstr q");
                            text.push_str(&destination.to_string());
                            text.push_str(",[x20],#16\nadd x19,x19,#512\n");
                            count += 1;
                        }
                    }
                }
            }
        }
    }
    // One Linux write emits the complete bounded result buffer; failures cannot
    // become a partial successful comparison. There are no libc/runtime helpers.
    text.push_str(&format!("mov x0,#1\nadrp x1,results\nadd x1,x1,:lo12:results\nmov x2,#{}\nmovk x2,#{},lsl #16\nmov x8,#64\nsvc #0\nmov x0,#0\nmov x8,#93\nsvc #0\n.data\n.balign 16\ninputs:\n.incbin \"{}\"\n.bss\n.balign 16\nresults: .skip {}\n",(count*16)&0xffff,(count*16)>>16,output.join("inputs.bin").display(),count*16));
    fs::write(output.join("inputs.bin"), inputs).unwrap();
    fs::write(output.join("oracle.S"), text).unwrap();
    fs::write(output.join("expected.bin"), &expected).unwrap();
    run(Command::new(llvm)
        .args(["-triple=aarch64", "-mattr=+sm4", "-filetype=obj"])
        .arg(output.join("oracle.S"))
        .arg("-o")
        .arg(output.join("oracle.o")));
    run(Command::new(linker)
        .args(["-m", "aarch64elf", "-static", "-e", "_start"])
        .arg(output.join("oracle.o"))
        .arg("-o")
        .arg(output.join("oracle")));
    let result = Command::new(qemu)
        .args(["-cpu", "max"])
        .arg(output.join("oracle"))
        .output()
        .unwrap();
    fs::write(output.join("qemu-results.bin"), &result.stdout).unwrap();
    fs::write(output.join("qemu-stderr.txt"), &result.stderr).unwrap();
    assert!(
        result.status.success(),
        "QEMU {:?}: {}",
        result.status,
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(result.stdout.len(), expected.len());
    for (index, (got, want)) in result
        .stdout
        .as_chunks::<16>()
        .0
        .iter()
        .zip(expected.as_chunks::<16>().0.iter())
        .enumerate()
    {
        assert_eq!(got, want, "case={index}");
    }
    std::println!(
        "SM3_ARM_QEMU_CASES={count} OUTPUT={} SOURCE_SHA256={}",
        output.display(),
        crate::SOURCE_SHA256
    );
}
