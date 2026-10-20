//! Arm's FP, SVE and SME access checks for the running PE, without EL3 and
//! with HCR_EL2.E2H RES1: `AArch64_CheckFPEnabled`,
//! `AArch64_CheckFPAdvSIMDEnabled`, `CheckSVEEnabled`,
//! `CheckNonStreamingSVEEnabled`, `CheckStreamingSVEEnabled`,
//! `CheckStreamingSVEAndZAEnabled`, `CheckSMEEnabled`, `CheckSMEAndZAEnabled`
//! and `CheckSMEZT0Enabled`, applied in the order an instruction's pseudocode
//! calls them ([`Chip::checks`](super::Chip::checks)). No Apple chip has
//! FEAT_SVE or FEAT_SME_FA64, so streaming mode is what admits SVE, and
//! there it makes the AdvSIMD and non-streaming SVE forms illegal.
use super::{chip::Check, cpu::Cpu, system::Register};

/// `SMEExceptionType`, as ISS[2:0] (SMTC) of EC 0x1D.
pub const SMTC_ACCESS: u32 = 0;
pub const SMTC_STREAMING: u32 = 1;
pub const SMTC_NOT_STREAMING: u32 = 2;
pub const SMTC_INACTIVE_ZA: u32 = 3;
pub const SMTC_INACCESSIBLE_ZT0: u32 = 4;

const CPACR_FPEN: u32 = 20;
const SMEN: u32 = 24;
const SMCR_EZT0: u32 = 30;

/// SMIDR_EL1.Implementer: Apple's code, as MIDR_EL1 has it.
const SMIDR_IMPLEMENTER_APPLE: u64 = 0x61 << 24;
/// SMIDR_EL1.SMPS: streaming execution priority is supported, so SMPRI_EL1,
/// SMPRIMAP_EL2 and HCRX_EL2.SMPME hold their fields.
const SMIDR_SMPS: u64 = 1 << 15;
/// SMIDR_EL1.SH 0b11: the PE shares its implementation of Streaming SVE
/// mode with other PEs.
const SMIDR_SHARED: u64 = 0b11 << 13;
/// SMIDR_EL1.Affinity, bits 11:0, and Affinity2, bits 51:32: the low and
/// high parts of the 32-bit SMCU affinity.
const SMIDR_AFFINITY_BITS: u32 = 12;
const SMIDR_AFFINITY2_SHIFT: u32 = 32;
/// MPIDR_EL1.Aff1 and Aff2, which Apple's PEs number their cluster with.
const MPIDR_CLUSTER_SHIFT: u32 = 8;
const MPIDR_CLUSTER_MASK: u64 = 0xffff;

/// SMIDR_EL1 of a PE with MPIDR_EL1 `mpidr`. The architecture leaves
/// Revision and the affinity IMPLEMENTATION DEFINED and Apple publishes
/// neither: Revision reads 0, and the PEs of one cluster (MPIDR_EL1 Aff2 and
/// Aff1) share one SMCU (SH 0b11, NSMC 0), as Apple's per-cluster matrix
/// unit is shared by that cluster's cores (inference). Priorities are held
/// (SMPS 1); with one PE executing at a time none changes execution, whose
/// effect the architecture leaves IMPLEMENTATION DEFINED.
pub fn smidr(mpidr: u64) -> u64 {
    let affinity = (mpidr >> MPIDR_CLUSTER_SHIFT) & MPIDR_CLUSTER_MASK;
    SMIDR_IMPLEMENTER_APPLE
        | SMIDR_SMPS
        | SMIDR_SHARED
        | (affinity & ((1 << SMIDR_AFFINITY_BITS) - 1))
        | (affinity >> SMIDR_AFFINITY_BITS) << SMIDR_AFFINITY2_SHIFT
}

/// Why a check denies an instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denial {
    /// `AArch64_AdvSIMDFPAccessTrap` to this EL (EC 0x07).
    FloatingPoint(u8),
    /// `SMEAccessTrap` (EC 0x1D) with this SMTC, to this EL.
    Sme { el: u8, smtc: u32 },
    /// A check of a feature the engine does not implement.
    Unimplemented(&'static str),
}

/// Apply `checks` in order; the first that fails denies.
pub fn check(cpu: &Cpu, checks: &[Check]) -> Result<(), Denial> {
    checks.iter().try_for_each(|check| one(cpu, *check))
}

fn one(cpu: &Cpu, check: Check) -> Result<(), Denial> {
    let streaming = cpu.svcr() & 1 != 0;
    // Traps that `SMEAccessTrap` takes at PSTATE.EL: EL0's go to EL1, or to
    // EL2 under HCR_EL2.TGE.
    let here = |smtc| Denial::Sme {
        el: cpu.route(),
        smtc,
    };
    match check {
        Check::Fp => floating_point(cpu),
        Check::FpAdvSimd | Check::NonStreamingSve => {
            if check == Check::FpAdvSimd {
                floating_point(cpu)?;
            } else {
                sve(cpu)?;
            }
            if streaming {
                return Err(here(SMTC_STREAMING));
            }
            Ok(())
        }
        Check::Sve => sve(cpu),
        Check::StreamingSve => streaming_sve(cpu),
        Check::StreamingSveAndZa => {
            streaming_sve(cpu)?;
            za(cpu)
        }
        Check::Sme => sme(cpu),
        Check::SmeAndZa => {
            sme(cpu)?;
            za(cpu)
        }
        Check::SmeZt0 => {
            za(cpu)?;
            if cpu.pstate.el <= 1
                && !cpu.in_host()
                && cpu.field(Register::SMCR_EL1, SMCR_EZT0, 1) == 0
            {
                return Err(Denial::Sme {
                    el: 1,
                    smtc: SMTC_INACCESSIBLE_ZT0,
                });
            }
            if cpu.field(Register::SMCR_EL2, SMCR_EZT0, 1) == 0 {
                return Err(Denial::Sme {
                    el: 2,
                    smtc: SMTC_INACCESSIBLE_ZT0,
                });
            }
            Ok(())
        }
        Check::Fpmr => Err(Denial::Unimplemented("FPMR (FEAT_FPMR)")),
    }
}

fn za(cpu: &Cpu) -> Result<(), Denial> {
    if cpu.svcr() & 2 == 0 {
        return Err(Denial::Sme {
            el: cpu.route(),
            smtc: SMTC_INACTIVE_ZA,
        });
    }
    Ok(())
}

/// `CheckSVEEnabled` with FEAT_SME and without FEAT_SVE.
fn sve(cpu: &Cpu) -> Result<(), Denial> {
    if cpu.scalable.is_none() {
        return Err(Denial::Unimplemented("SVE without FEAT_SME (FEAT_SVE)"));
    }
    if cpu.svcr() & 1 != 0 {
        sme(cpu)
    } else {
        streaming_sve(cpu)
    }
}

fn streaming_sve(cpu: &Cpu) -> Result<(), Denial> {
    sme(cpu)?;
    if cpu.svcr() & 1 == 0 {
        return Err(Denial::Sme {
            el: cpu.route(),
            smtc: SMTC_NOT_STREAMING,
        });
    }
    Ok(())
}

/// The CPACR_EL1 or CPTR_EL2 two-bit enable at `shift`: '11' enables, '01'
/// enables all but EL0 (in the host, for CPTR_EL2), 'x0' disables.
fn disabled(cpu: &Cpu, register: Register, shift: u32) -> bool {
    let enable = cpu.field(register, shift, 2);
    let el0 = cpu.pstate.el == 0 && (register == Register::CPACR_EL1 || cpu.in_host());
    enable & 1 == 0 || (enable == 0b01 && el0)
}

/// `CheckSMEEnabled`: SMEN, then FPEN, of CPACR_EL1 at EL0 and EL1 outside
/// the host, then of CPTR_EL2.
fn sme(cpu: &Cpu) -> Result<(), Denial> {
    if cpu.scalable.is_none() {
        return Err(Denial::Unimplemented("SME (FEAT_SME)"));
    }
    if cpu.pstate.el <= 1 && !cpu.in_host() {
        if disabled(cpu, Register::CPACR_EL1, SMEN) {
            return Err(Denial::Sme {
                el: 1,
                smtc: SMTC_ACCESS,
            });
        }
        if disabled(cpu, Register::CPACR_EL1, CPACR_FPEN) {
            return Err(Denial::FloatingPoint(1));
        }
    }
    if disabled(cpu, Register::CPTR_EL2, SMEN) {
        return Err(Denial::Sme {
            el: 2,
            smtc: SMTC_ACCESS,
        });
    }
    if disabled(cpu, Register::CPTR_EL2, CPACR_FPEN) {
        return Err(Denial::FloatingPoint(2));
    }
    Ok(())
}

/// `AArch64_CheckFPEnabled`.
fn floating_point(cpu: &Cpu) -> Result<(), Denial> {
    match cpu.floating_point_trap() {
        Some(el) => Err(Denial::FloatingPoint(el)),
        None => Ok(()),
    }
}

/// The SIMD&FP registers an instruction whose only access check is
/// `CheckFPEnabled` writes, in order: Arm's `V[]` and `Vpart[]` setters
/// zero-extend each write to the vector length, so in streaming mode it
/// clears the register's Z bits above 128. `None` for a word outside the
/// classes these forms fall in (FP and SIMD&FP loads and stores, scalar FP
/// data processing and conversions, AdvSIMD scalar FP estimates and steps,
/// SMOV and UMOV), which the engine refuses rather than guess.
pub fn vector_destinations(word: u32) -> Option<VectorDestinations> {
    const NONE: VectorDestinations = VectorDestinations([None, None]);
    let bits = |high: u32, low: u32| (word >> low) & ((1 << (high - low + 1)) - 1);
    let rd = Some(VectorDestinations([Some(bits(4, 0) as u8), None]));
    let load = bits(22, 22) == 1;
    // LDR (literal, SIMD&FP); opc 0b11 is unallocated.
    if word & 0x3f00_0000 == 0x1c00_0000 {
        return if bits(31, 30) == 0b11 { None } else { rd };
    }
    // LDP, STP, LDNP, STNP (SIMD&FP), and LDTP, STTP (SIMD&FP).
    if word & 0x3e00_0000 == 0x2c00_0000 {
        return Some(match load {
            true => VectorDestinations([Some(bits(4, 0) as u8), Some(bits(14, 10) as u8)]),
            false => NONE,
        });
    }
    // LDR, STR, LDUR, STUR (SIMD&FP): unsigned offset, register offset,
    // unscaled, post- and pre-index. Bit 22 is the load bit for every size,
    // the 128-bit forms included.
    if word & 0x3e00_0000 == 0x3c00_0000 {
        return match (bits(25, 24), bits(21, 21), bits(11, 10)) {
            (0b01, _, _) | (0b00, 0, 0b00 | 0b01 | 0b11) | (0b00, 1, 0b10) => {
                if load {
                    rd
                } else {
                    Some(NONE)
                }
            }
            _ => None,
        };
    }
    // Scalar FP data processing (M 0 S 11110).
    if word & 0x7f00_0000 == 0x1e00_0000 {
        if bits(21, 21) == 0 {
            // Conversion between FP and fixed point: SCVTF and UCVTF write
            // the register, FCVTZS and FCVTZU a general-purpose one.
            return match (bits(20, 19), bits(18, 16)) {
                (0b00, 0b010 | 0b011) => rd,
                (0b11, 0b000 | 0b001) => Some(NONE),
                _ => None,
            };
        }
        return match bits(11, 10) {
            // FCCMP and FCCMPE write NZCV.
            0b01 => Some(NONE),
            // Two-source data processing and FCSEL.
            0b10 | 0b11 => rd,
            // FMOV (scalar, immediate).
            _ if bits(12, 10) == 0b100 => rd,
            // FCMP and FCMPE write NZCV.
            _ if bits(13, 10) == 0b1000 => Some(NONE),
            // One-source data processing.
            _ if bits(14, 10) == 0b1_0000 => rd,
            _ if bits(15, 10) == 0 => match (bits(20, 19), bits(18, 16)) {
                // FCVT[NPMZA][SU] and FMOV to a general-purpose register.
                (_, 0b000 | 0b001 | 0b100 | 0b101) | (0b00 | 0b01, 0b110) => Some(NONE),
                // SCVTF, UCVTF and FMOV from a general-purpose register,
                // into the low or (FMOV Vd.D[1]) the high half.
                (0b00, 0b010 | 0b011) | (0b00 | 0b01, 0b111) => rd,
                _ => None,
            },
            _ => None,
        };
    }
    // FP data processing, three source.
    if word & 0x7f00_0000 == 0x1f00_0000 {
        return rd;
    }
    // AdvSIMD scalar (01 U 11110): FMULX, FRECPE, FRECPS, FRECPX, FRSQRTE
    // and FRSQRTS write a scalar register.
    if word & 0xdf00_0000 == 0x5e00_0000 {
        return rd;
    }
    // SMOV and UMOV write a general-purpose register.
    if matches!(word & 0xbfe0_fc00, 0x0e00_2c00 | 0x0e00_3c00) {
        return Some(NONE);
    }
    None
}

/// The SIMD&FP registers an instruction writes ([`vector_destinations`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VectorDestinations(pub [Option<u8>; 2]);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::{Chip, exception::Pstate};

    #[test]
    fn every_scalar_fp_form_of_the_sme_chips_names_its_vector_destinations() {
        for chip in [Chip::AppleM4, Chip::AppleM5, Chip::AppleM6] {
            let forms: alloc::vec::Vec<_> = chip
                .check_forms()
                .into_iter()
                .filter(|(_, _, checks)| *checks == [Check::Fp])
                .map(|(mask, value, _)| (mask, value))
                .collect();
            assert!(forms.len() > 400, "{chip:?}");
            let mut checked = 0;
            for (mask, value) in forms {
                // Each form with its operand fields filled in 32 ways.
                let mut seed = value ^ 0x9e37_79b9;
                for _ in 0..32 {
                    seed ^= seed << 13;
                    seed ^= seed >> 17;
                    seed ^= seed << 5;
                    let word = value | (seed & !mask);
                    if chip.admit(word) != word || chip.checks(word) != [Check::Fp] {
                        continue;
                    }
                    checked += 1;
                    assert!(vector_destinations(word).is_some(), "{chip:?} {word:#010x}");
                }
            }
            assert!(checked > 1000, "{chip:?} {checked}");
        }
        // FADD s7, s1, s2 writes s7; LDP q7, q9, [x0] both; FMOV x7, d1 and
        // FCMP s1, s2 none; STR q7, [x0] none.
        for (word, expected) in [
            (0x1e22_2827, [Some(7), None]),
            (0xad40_2407, [Some(7), Some(9)]),
            (0x9e66_0027, [None, None]),
            (0x1e22_2020, [None, None]),
            (0x3d80_0007, [None, None]),
        ] {
            assert_eq!(
                vector_destinations(word),
                Some(VectorDestinations(expected)),
                "{word:#010x}"
            );
        }
    }

    const ENABLED: u64 = 0b11 << SMEN | 0b11 << CPACR_FPEN;

    fn cpu(chip: Chip, el: u8) -> Cpu {
        let mut cpu = Cpu::of(chip, 0, Pstate::reset(el.max(1)));
        cpu.pstate.el = el;
        cpu.registers.set(Register::CPACR_EL1, 0, ENABLED);
        cpu.registers.set(Register::CPTR_EL2, 0, ENABLED);
        cpu
    }

    #[test]
    fn streaming_mode_decides_what_sve_sme_and_advsimd_may_do() {
        let chip = crate::machine::test_chip();
        let mut cpu = cpu(chip, 1);
        if cpu.scalable.is_none() {
            // Without SME the SVE and SME forms are absent; FP is unaffected.
            assert_eq!(check(&cpu, &[Check::FpAdvSimd]), Ok(()));
            assert!(matches!(
                check(&cpu, &[Check::Sme]),
                Err(Denial::Unimplemented(_))
            ));
            return;
        }
        let sme = |smtc| Err(Denial::Sme { el: 1, smtc });
        // Outside streaming mode SVE is NotStreaming and ZA instructions
        // need PSTATE.ZA, but AdvSIMD runs.
        assert_eq!(check(&cpu, &[Check::Sve]), sme(SMTC_NOT_STREAMING));
        assert_eq!(check(&cpu, &[Check::SmeAndZa]), sme(SMTC_INACTIVE_ZA));
        assert_eq!(check(&cpu, &[Check::Sme]), Ok(()));
        assert_eq!(check(&cpu, &[Check::FpAdvSimd]), Ok(()));
        cpu.state.x[0] = 0;
        cpu.scalable
            .as_mut()
            .unwrap()
            .apply_mode(
                &mut cpu.state,
                stela_compiler::aarch64::scalable::ScalableMode::new(true, true),
            )
            .unwrap();
        // In streaming mode the AdvSIMD and non-streaming SVE forms trap,
        // while SVE, scalar FP and the ZA forms run.
        assert_eq!(check(&cpu, &[Check::FpAdvSimd]), sme(SMTC_STREAMING));
        assert_eq!(check(&cpu, &[Check::NonStreamingSve]), sme(SMTC_STREAMING));
        for checks in [
            &[Check::Sve][..],
            &[Check::Fp],
            &[Check::StreamingSveAndZa],
            &[Check::SmeAndZa],
        ] {
            assert_eq!(check(&cpu, checks), Ok(()), "{checks:?}");
        }
        // ZT0 needs SMCR_EL1.EZT0 and SMCR_EL2.EZT0.
        assert_eq!(
            check(&cpu, &[Check::Sme, Check::SmeZt0]),
            sme(SMTC_INACCESSIBLE_ZT0)
        );
        cpu.registers.set(Register::SMCR_EL1, 0, 1 << SMCR_EZT0);
        assert_eq!(
            check(&cpu, &[Check::SmeZt0]),
            Err(Denial::Sme {
                el: 2,
                smtc: SMTC_INACCESSIBLE_ZT0
            })
        );
        // SMEN before FPEN, CPACR_EL1 before CPTR_EL2.
        cpu.registers.set(Register::CPACR_EL1, 0, 0b11 << SMEN);
        assert_eq!(check(&cpu, &[Check::Sme]), Err(Denial::FloatingPoint(1)));
        cpu.registers.set(Register::CPTR_EL2, 0, 0);
        assert_eq!(check(&cpu, &[Check::Sme]), Err(Denial::FloatingPoint(1)));
        cpu.registers.set(Register::CPACR_EL1, 0, ENABLED);
        assert_eq!(
            check(&cpu, &[Check::Sme]),
            Err(Denial::Sme { el: 2, smtc: 0 })
        );
        // An EL0 trap at PSTATE.EL goes to EL2 under HCR_EL2.TGE.
        cpu.registers.set(Register::CPTR_EL2, 0, ENABLED);
        cpu.registers.set(Register::HCR_EL2, 0, 1 << 27);
        cpu.pstate.el = 0;
        assert_eq!(
            check(&cpu, &[Check::FpAdvSimd]),
            Err(Denial::Sme {
                el: 2,
                smtc: SMTC_STREAMING
            })
        );
    }
}
