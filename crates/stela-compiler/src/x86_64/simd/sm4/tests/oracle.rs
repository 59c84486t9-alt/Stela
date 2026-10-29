//! Stock AArch64 execution comparison, using declared LLVM tool inputs.
use super::*;
use alloc::{format, string::String, vec::Vec};
use std::{fs, path::PathBuf, process::Command};
fn run(command: &mut Command) {
    let result = command.output().unwrap();
    assert!(
        result.status.success(),
        "{command:?}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
}
#[test]
#[ignore = "oracle: STELA_TEST_LLD, STELA_TEST_LLVM_MC, STELA_TEST_SM4_QEMU"]
fn baseline_and_gfni_sm4_match_stock_aarch64_qemu() {
    let tool = |key| PathBuf::from(std::env::var_os(key).expect(key));
    let qemu = tool("STELA_TEST_SM4_QEMU");
    let llvm = tool("STELA_TEST_LLVM_MC");
    let linker = tool("STELA_TEST_LLD");
    let output = std::env::temp_dir().join(format!("stela-sm4-oracle-{}", std::process::id()));
    fs::create_dir_all(&output).unwrap();
    let mut text = String::from(
        ".text\n.global _start\n_start:\nadrp x19,inputs\nadd x19,x19,:lo12:inputs\nadrp x20,results\nadd x20,x20,:lo12:results\n",
    );
    let mut inputs = Vec::new();
    let mut expected = Vec::new();
    let mut count = 0;
    let mut random = 0xa54ff53a5f1d36f1_u64;
    for kind in [Kind::Encrypt, Kind::ExpandKey] {
        for destination in [0, 31] {
            for input in [destination, 1] {
                for keys in [destination, input, 2] {
                    if kind == Kind::Encrypt && input != destination {
                        continue;
                    }
                    let operand = Operand {
                        kind,
                        destination,
                        input,
                        keys,
                    };
                    let natives: Vec<_> = [false, true]
                        .into_iter()
                        .filter(|gfni| !*gfni || TargetCpu::detect().supports(TargetCpu::Gfni))
                        .map(|gfni| {
                            let mut code = Code::new();
                            emit_with_sbox(&mut code, &operand, gfni);
                            code.asm().ret();
                            fs::write(
                                output.join(format!(
                                    "lowered-{kind:?}-{destination}-{input}-{keys}-gfni{gfni}.bin"
                                )),
                                code.as_slice(),
                            )
                            .unwrap();
                            Native::new(&code)
                        })
                        .collect();
                    for sample in 0..32 {
                        let mut state = GuestState::default();
                        for v in &mut state.v {
                            for word in v {
                                random ^= random << 13;
                                random ^= random >> 7;
                                random ^= random << 17;
                                *word = match sample {
                                    0 => 0,
                                    1 => u64::MAX,
                                    _ => random,
                                };
                                inputs.extend(word.to_le_bytes());
                            }
                        }
                        let result = vector(model::reference(
                            kind,
                            words(state.v[usize::from(input)]),
                            words(state.v[usize::from(keys)]),
                        ));
                        for native in &natives {
                            let mut actual = state.clone();
                            native.run(&mut actual, &mut ExecutionContext::default());
                            assert_eq!(actual.v[usize::from(destination)], result);
                        }
                        for word in result {
                            expected.extend(word.to_le_bytes());
                        }
                        for register in [destination, input, keys] {
                            text.push_str(&format!(
                                "ldr q{register},[x19,#{}]\n",
                                u32::from(register) * 16
                            ));
                        }
                        text.push_str(&match kind {
                            Kind::Encrypt => format!("sm4e v{destination}.4s,v{keys}.4s\n"),
                            Kind::ExpandKey => {
                                format!("sm4ekey v{destination}.4s,v{input}.4s,v{keys}.4s\n")
                            }
                        });
                        text.push_str(&format!("str q{destination},[x20],#16\nadd x19,x19,#512\n"));
                        count += 1;
                    }
                }
            }
        }
    }
    text.push_str(&format!("mov x0,#1\nadrp x1,results\nadd x1,x1,:lo12:results\nmov x2,#{}\nmovk x2,#{},lsl #16\nmov x8,#64\nsvc #0\nmov x0,#0\nmov x8,#93\nsvc #0\n.data\n.balign 16\ninputs:\n.incbin \"{}\"\n.bss\n.balign 16\nresults:.skip {}\n",(count*16)&0xffff,(count*16)>>16,output.join("inputs.bin").display(),count*16));
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
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(result.stdout.len(), expected.len());
    for (index, (got, want)) in result
        .stdout
        .as_chunks::<16>()
        .0
        .iter()
        .zip(expected.as_chunks::<16>().0)
        .enumerate()
    {
        assert_eq!(got, want, "case={index}");
    }
    std::println!(
        "SM4_ARM_QEMU_CASES={count} OUTPUT={} SOURCE_SHA256={}",
        output.display(),
        crate::SOURCE_SHA256
    );
}
