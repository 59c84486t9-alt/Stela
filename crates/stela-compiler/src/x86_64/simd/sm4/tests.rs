mod costs;
mod model;
mod oracle;
use super::*;
use crate::{
    GuestState, TargetCpu,
    context::ExecutionContext,
    x86_64::asm::{Gpr, Mem, Size, vector_extensions::execution::Native},
};
fn words(v: [u64; 2]) -> [u32; 4] {
    [
        v[0] as u32,
        (v[0] >> 32) as u32,
        v[1] as u32,
        (v[1] >> 32) as u32,
    ]
}
fn vector(v: [u32; 4]) -> [u64; 2] {
    [
        u64::from(v[0]) | (u64::from(v[1]) << 32),
        u64::from(v[2]) | (u64::from(v[3]) << 32),
    ]
}
#[test]
fn baseline_and_gfni_sboxes_match_every_arm_table_entry_in_each_byte_position() {
    for gfni in [false, true] {
        if gfni && !TargetCpu::detect().supports(TargetCpu::Gfni) {
            continue;
        }
        let mut code = Code::new();
        code.asm().mov_load(
            Size::Dword,
            Gpr::R8,
            Mem::base(Gpr::Rdi, core::mem::offset_of!(GuestState, x) as i32),
        );
        sbox::emit(&mut code, gfni);
        code.asm().mov_store(
            Size::Qword,
            Mem::base(Gpr::Rdi, core::mem::offset_of!(GuestState, x) as i32),
            Gpr::R8,
        );
        code.asm().ret();
        let native = Native::new(&code);
        for value in 0..=255u8 {
            let input = [value, value.wrapping_add(1), value ^ 0xa5, !value];
            let mut state = GuestState::default();
            state.x[0] = u64::from(u32::from_le_bytes(input));
            let mut expected = state.clone();
            expected.x[0] = u64::from(u32::from_le_bytes(
                input.map(|x| model::SBOX[usize::from(x)]),
            ));
            native.run(&mut state, &mut ExecutionContext::default());
            assert_eq!(state, expected, "gfni={gfni} input={input:?}");
        }
    }
}
#[test]
fn four_round_encryption_and_key_recipes_keep_aliases_flags_and_unrelated_state() {
    let mut random = 0x3c6ef372fe94f82b_u64;
    let mut cases = 0;
    for gfni in [false, true] {
        if gfni && !TargetCpu::detect().supports(TargetCpu::Gfni) {
            continue;
        }
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
                        let mut code = Code::new();
                        emit_with_sbox(&mut code, &operand, gfni);
                        code.asm().ret();
                        let native = Native::new(&code);
                        for sample in 0..64 {
                            let mut state = GuestState {
                                nzcv: 0xa0000000,
                                fpsr: 0x0800001f,
                                fpcr: 0x1234,
                                ..GuestState::default()
                            };
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
                                }
                            }
                            state.x = core::array::from_fn(|i| random.wrapping_mul(i as u64 + 1));
                            let mut expected = state.clone();
                            expected.v[usize::from(destination)] = vector(model::reference(
                                kind,
                                words(state.v[usize::from(input)]),
                                words(state.v[usize::from(keys)]),
                            ));
                            native.run(&mut state, &mut ExecutionContext::default());
                            assert_eq!(state, expected, "{operand:?} gfni={gfni} sample={sample}");
                            cases += 1;
                        }
                    }
                }
            }
        }
    }
    std::println!(
        "SM4_NATIVE_CASES={cases} SOURCE_SHA256={}",
        crate::SOURCE_SHA256
    );
}

#[test]
fn key_schedule_and_eight_encrypt_groups_match_the_standard_sm4_known_answer() {
    for gfni in [false, true] {
        if gfni && !TargetCpu::detect().supports(TargetCpu::Gfni) {
            continue;
        }
        let build = |kind| {
            let mut code = Code::new();
            emit_with_sbox(
                &mut code,
                &Operand {
                    kind,
                    destination: 0,
                    input: 0,
                    keys: 1,
                },
                gfni,
            );
            code.asm().ret();
            Native::new(&code)
        };
        let keys = build(Kind::ExpandKey);
        let encrypt = build(Kind::Encrypt);
        let key = [0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210];
        let fk = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc];
        let mut state = GuestState::default();
        state.v[0] = vector(core::array::from_fn(|i| key[i] ^ fk[i]));
        let mut rounds = [[0; 2]; 8];
        for (group, round) in rounds.iter_mut().enumerate() {
            let constants = core::array::from_fn(|lane| {
                u32::from_be_bytes(core::array::from_fn(|byte| {
                    ((group * 16 + lane * 4 + byte) * 7) as u8
                }))
            });
            state.v[1] = vector(constants);
            keys.run(&mut state, &mut ExecutionContext::default());
            *round = state.v[0];
        }
        state.v[0] = vector(key);
        for round in rounds {
            state.v[1] = round;
            encrypt.run(&mut state, &mut ExecutionContext::default());
        }
        let output = words(state.v[0]);
        let output: [u8; 16] =
            core::array::from_fn(|index| output[3 - index / 4].to_be_bytes()[index % 4]);
        assert_eq!(
            output,
            [
                0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e,
                0x42, 0x46
            ],
            "gfni={gfni}"
        );
    }
}

#[test]
fn inverse_affine_matches_gnu_register_and_sib_forms_and_counts_one_instruction() {
    use crate::x86_64::asm::Rm;
    for (destination, matrix, expected) in [
        (
            0,
            Rm::Xmm(1),
            alloc::vec![0x66, 0x0f, 0x3a, 0xcf, 0xc1, 0xd3],
        ),
        (
            8,
            Rm::Xmm(15),
            alloc::vec![0x66, 0x45, 0x0f, 0x3a, 0xcf, 0xc7, 0xd3],
        ),
        (
            8,
            Rm::Mem(Mem::indexed(Gpr::R12, Gpr::R13, 2, 0x1234)),
            alloc::vec![
                0x66, 0x47, 0x0f, 0x3a, 0xcf, 0x84, 0x6c, 0x34, 0x12, 0, 0, 0xd3
            ],
        ),
    ] {
        let mut code = Code::new();
        code.asm().gf2p8affineinvqb(destination, matrix, 0xd3);
        assert_eq!(code.as_slice(), expected);
        assert_eq!(code.instructions(), 1);
    }
}
