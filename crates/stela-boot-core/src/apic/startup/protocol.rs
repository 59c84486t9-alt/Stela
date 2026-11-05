use super::*;
use core::sync::atomic::{Ordering, compiler_fence};
const MASK: u32 = 1 << 16;
const MODE: u32 = 3 << 17;
const DEADLINE: u32 = 2 << 17;
const ENABLE: u32 = 1 << 8;
const TIMER: u32 = MASK | 64;

fn read<I: OriginalController>(io: &I, register: Register) -> Result<u32, Cause<I::Error>> {
    io.read(register).map_err(Cause::Source)
}
fn same<I: OriginalController>(io: &I, profile: Profile) -> Result<(), Cause<I::Error>> {
    if io.check().map_err(Cause::Source)? != profile {
        return Err(Cause::ChangedProfile);
    }
    Ok(())
}
fn capture<I: OriginalController>(io: &I) -> Result<OriginalImage, Cause<I::Error>> {
    let profile = io.check().map_err(Cause::Source)?;
    let version = read(io, Register::Version)?;
    let maximum = (version >> 16) & 255;
    // This supported profile has the integrated timer, thermal/performance,
    // both LINTs and error LVT, optionally CMCI. No invented register access.
    if version == u32::MAX || version & 255 < 0x10 || !(5..=6).contains(&maximum) {
        return Err(Cause::InvalidVersion);
    }
    let id = read(io, Register::Id)?;
    let target = match profile.mode {
        Mode::Xapic => id >> 24,
        Mode::X2apic => id,
    };
    if target >= 255 {
        return Err(Cause::InvalidTarget);
    }
    let svr = read(io, Register::Svr)?;
    // This modern x86-64 profile does not admit legacy focus-checking bit9.
    // Refuse it before effects; preserve every admitted policy bit, notably12.
    if svr & !0x11ff != 0 || svr & (1 << 12) != 0 && version & (1 << 24) == 0 {
        return Err(Cause::InvalidSvr);
    }
    let tpr = read(io, Register::Tpr)?;
    if tpr != 0 {
        return Err(Cause::NonzeroTpr);
    }
    let mut lvt = [0; 7];
    for n in 0..=maximum {
        lvt[n as usize] = read(io, Register::Lvt(n as u8))?;
    }
    // SDM08512.9: no LVT may use the spurious vector, even masked.
    // We preserve non-timer LVTs; refuse the collision rather than repair them.
    // Timer255 is also refused before this protocol changes SVR to255.
    for n in 0..=maximum {
        if lvt[n as usize] & 255 == 255 {
            return Err(Cause::SpuriousCollision {
                lvt: n as u8,
                observed: lvt[n as usize],
            });
        }
    }
    let timer_mode = lvt[0] & MODE;
    if lvt[0] & !0x710ff != 0 || timer_mode == MODE || timer_mode == DEADLINE && !profile.deadline {
        return Err(Cause::UnsupportedTimer);
    }
    let deadline = if timer_mode == DEADLINE {
        Some(io.read_deadline().map_err(Cause::Source)?)
    } else {
        None
    };
    let mut isr = [0; 8];
    let mut irr = [0; 8];
    let mut tmr = [0; 8];
    for n in 0..8 {
        isr[n] = read(io, Register::Isr(n as u8))?;
        irr[n] = read(io, Register::Irr(n as u8))?;
        tmr[n] = read(io, Register::Tmr(n as u8))?;
    }
    let image = OriginalImage {
        profile,
        id,
        version,
        svr,
        tpr,
        lvt,
        deadline,
        isr,
        irr,
        tmr,
        divide: read(io, Register::Divide)?,
        initial: read(io, Register::Initial)?,
        current: read(io, Register::Current)?,
    };
    same(io, profile)?;
    Ok(image)
}
fn expect<I: OriginalController>(
    io: &I,
    register: Register,
    value: u32,
    mask: u32,
) -> Result<(), Cause<I::Error>> {
    let observed = read(io, register)?;
    if observed & mask != value & mask {
        return Err(Cause::Readback {
            register,
            expected: value,
            observed,
            mask,
        });
    }
    Ok(())
}
fn apply<I: OriginalController>(
    io: &mut I,
    effect: &Cell<Effect>,
    profile: Profile,
    ordinal: &mut u8,
    operation: Operation,
    verify: impl FnOnce(&I) -> Result<(), Cause<I::Error>>,
) -> Result<(), Cause<I::Error>> {
    same(io, profile)?;
    // The number is bounded by this fixed program, never supplied as authority.
    *ordinal += 1;
    effect.set(Effect::MayHaveWritten {
        ordinal: *ordinal,
        operation,
    });
    compiler_fence(Ordering::SeqCst);
    io.apply(operation).map_err(Cause::Source)?;
    verify(io)?;
    same(io, profile)?;
    effect.set(Effect::ConfirmedCurrentState {
        ordinal: *ordinal,
        operation,
    });
    Ok(())
}
pub(super) fn configure<I: OriginalController>(
    io: &mut I,
    effect: &Cell<Effect>,
    original: &mut Option<OriginalImage>,
) -> Result<(), Cause<I::Error>> {
    let image = capture(io)?;
    *original = Some(image);
    // Refuse unsupported currently active service BEFORE the first write. It
    // says nothing about pending IRR, special events, or previously issued work.
    if image.isr.iter().any(|word| *word != 0) {
        return Err(Cause::ActiveService);
    }
    let profile = image.profile;
    let mut ordinal = 0;
    let masked = image.lvt[0] | MASK;
    apply(
        io,
        effect,
        profile,
        &mut ordinal,
        Operation::MaskOriginalTimer(masked),
        |io| expect(io, Register::Lvt(0), masked, !0x1000),
    )?;
    if image.lvt[0] & MODE == DEADLINE {
        if profile.mode == Mode::Xapic {
            apply(
                io,
                effect,
                profile,
                &mut ordinal,
                Operation::OrderDeadline,
                |_| Ok(()),
            )?;
        }
        apply(
            io,
            effect,
            profile,
            &mut ordinal,
            Operation::DisarmDeadline,
            |io| {
                let observed = io.read_deadline().map_err(Cause::Source)?;
                if observed != 0 {
                    return Err(Cause::DeadlineReadback { observed });
                }
                Ok(())
            },
        )?;
    } else {
        apply(
            io,
            effect,
            profile,
            &mut ordinal,
            Operation::StopCount,
            |io| {
                expect(io, Register::Initial, 0, u32::MAX)?;
                expect(io, Register::Current, 0, u32::MAX)
            },
        )?;
    }
    let svr = image.svr & !255 | ENABLE | 255;
    apply(
        io,
        effect,
        profile,
        &mut ordinal,
        Operation::ConfigureSvr(svr),
        |io| expect(io, Register::Svr, svr, u32::MAX),
    )?;
    apply(
        io,
        effect,
        profile,
        &mut ordinal,
        Operation::ConfigureTimer,
        |io| expect(io, Register::Lvt(0), TIMER, !0x1000),
    )?;
    // In deadline mode INITIAL writes were ignored. Stop the new one-shot
    // mechanism too after changing mode, rather than assuming old register data.
    if image.lvt[0] & MODE == DEADLINE {
        apply(
            io,
            effect,
            profile,
            &mut ordinal,
            Operation::StopCount,
            |io| {
                expect(io, Register::Initial, 0, u32::MAX)?;
                expect(io, Register::Current, 0, u32::MAX)
            },
        )?;
    }
    apply(
        io,
        effect,
        profile,
        &mut ordinal,
        Operation::ConfigureDivide,
        |io| expect(io, Register::Divide, 11, u32::MAX),
    )?;
    expect(io, Register::Initial, 0, u32::MAX)?;
    expect(io, Register::Current, 0, u32::MAX)?;
    expect(io, Register::Tpr, image.tpr, u32::MAX)?;
    expect(io, Register::Lvt(3), image.lvt[3], u32::MAX)?;
    expect(io, Register::Lvt(4), image.lvt[4], u32::MAX)?;
    same(io, profile)
}
