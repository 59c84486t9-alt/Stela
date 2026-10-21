//! Actual SGX/private-firmware sink for the common render-context program.

use super::{FirmwareWork, Run, Word};
use crate::platform::apple::agx::{
    channel::Kind,
    work_decode::{
        Frame, Submission,
        render_context::{self, Access, Identity, Program},
        resources::{Lease, Policy},
        scene, ta, three_d,
    },
};
use crate::platform::dma::Port;
use alloc::rc::Rc;
use core::cell::Cell;

#[derive(Debug)]
pub(super) struct Owner {
    program: Program,
    identity: Identity,
    pub(super) committed: u8,
    mask: Option<u64>,
    mirror: Option<u64>,
}
impl Drop for Owner {
    fn drop(&mut self) {
        self.identity.invalidate();
    }
}
#[derive(Debug, Default)]
pub(super) struct Book {
    program: Option<Program>,
    // Zero comes from the original loaded __DATA.__zerofill bytes, not a
    // native register reset/readback. Retained gates never reinitialize it.
    pub(super) epochs: [u8; 2],
    pub(super) status: [Option<u32>; 9],
}
fn new_run(submission: &Submission, frame: &Frame, lease: Lease, policy: Policy) -> Run {
    Run {
        submission: submission.clone(),
        frame: frame.clone(),
        lease,
        next: 0,
        words: if lease.pipe == 0 {
            ta::words(policy)
        } else {
            three_d::words(policy)
        },
        valid: Rc::new(Cell::new(true)),
        binding_issued: Cell::new(false),
        prefix: None,
    }
}
pub struct ContextAccess<'a, 'p, 'm> {
    owner: &'a FirmwareWork,
    port: &'a mut Port<'p, 'm>,
    program: Program,
}
impl FirmwareWork {
    pub fn render_context_access<'a, 'p, 'm>(
        &'a self,
        port: &'a mut Port<'p, 'm>,
        program: Program,
    ) -> ContextAccess<'a, 'p, 'm> {
        ContextAccess {
            owner: self,
            port,
            program,
        }
    }
}
impl Access for ContextAccess<'_, '_, '_> {
    fn program(&self) -> Program {
        self.program
    }
    fn memory(&mut self) -> &mut dyn crate::platform::apple::agx::ring::Shared {
        self.port
    }
    fn begin(
        &mut self,
        input: &Submission,
        frame: &Frame,
        lease: Lease,
        identity: &Identity,
        committed: u8,
    ) -> Result<(), &'static str> {
        self.owner.available()?;
        if self.program.policy() != self.owner.policy {
            return Err("GFX common context program differs from its actual SGX family");
        }
        let pipe = match input.command.kind {
            Kind::Ta => 0,
            Kind::ThreeD => 1,
            _ => return Err("GFX common context requires render work"),
        };
        if pipe != lease.pipe || lease.slot >= 6 {
            return Err("GFX common context has a foreign execution lease");
        }
        scene::Key::read(input, frame)?;
        let mut native = self.owner.power.native.borrow_mut();
        if native.work.run.is_some() {
            return Err("GFX common context still belongs to accepted CL work");
        }
        let registers = &mut native.work.render;
        if registers
            .context
            .program
            .is_some_and(|program| program != self.program)
        {
            return Err(
                "GFX retained render context belongs to another initialized firmware program",
            );
        }
        if registers.run.is_none() {
            if committed != 0 {
                return Err("GFX common context lost its committed native owner");
            }
            registers.run = Some(new_run(input, frame, lease, self.owner.policy));
        }
        let run = registers.run.as_mut().unwrap();
        if run.submission != *input || run.frame != *frame || run.lease != lease || run.next != 0 {
            return Err("GFX common context differs from its accepted setup or follows parameters");
        }
        if run.prefix.is_none() {
            if committed != 0 {
                return Err("GFX common context lost its committed native prefix");
            }
            registers.context.program = Some(self.program);
            run.prefix = Some(Owner {
                program: self.program,
                identity: identity.clone(),
                committed: 0,
                mask: None,
                mirror: None,
            });
        }
        if run.prefix.as_ref().unwrap().committed != committed
            || run.prefix.as_ref().unwrap().program != self.program
            || !run.prefix.as_ref().unwrap().identity.same(identity)
        {
            return Err("GFX common context retry differs from its committed native prefix");
        }
        Ok(())
    }
    fn read_epoch(&mut self, pipe: u8) -> Result<u8, &'static str> {
        self.owner.available()?;
        let native = self.owner.power.native.borrow();
        let run = native
            .work
            .render
            .run
            .as_ref()
            .ok_or("GFX epoch read has no native owner")?;
        if run.lease.pipe != pipe || run.prefix.as_ref().is_none_or(|p| p.committed != 0) {
            return Err("GFX epoch read differs from its source phase");
        }
        Ok(native.work.render.context.epochs[usize::from(pipe)])
    }
    fn write_epoch(&mut self, pipe: u8, value: u8) -> Result<(), &'static str> {
        self.owner.available()?;
        let mut native = self.owner.power.native.borrow_mut();
        let run = native
            .work
            .render
            .run
            .as_mut()
            .ok_or("GFX epoch store has no native owner")?;
        let prefix = run
            .prefix
            .as_mut()
            .ok_or("GFX epoch store has no context phase")?;
        if run.lease.pipe != pipe || prefix.committed != 0 {
            return Err("GFX epoch store differs from its source phase");
        }
        prefix.committed += 1;
        native.work.render.context.epochs[usize::from(pipe)] = value;
        Ok(())
    }
    fn read_mask(&mut self) -> Result<u64, &'static str> {
        self.owner.available()?;
        {
            let native = self.owner.power.native.borrow();
            let run = native
                .work
                .render
                .run
                .as_ref()
                .ok_or("GFX context mask read has no native owner")?;
            if run.prefix.as_ref().is_none_or(|p| p.committed != 2) {
                return Err("GFX context mask read differs from source order");
            }
        }
        self.owner.target_word(self.port, 0x17610, 8, false)?;
        let mut native = self.owner.power.native.borrow_mut();
        let value = native
            .work
            .context_mask
            .ok_or("GFX render native context-mask initial value is not qualified")?;
        native
            .work
            .render
            .run
            .as_mut()
            .unwrap()
            .prefix
            .as_mut()
            .unwrap()
            .mask = Some(value);
        Ok(value)
    }
    fn read_mirror(&mut self) -> Result<u64, &'static str> {
        self.owner.available()?;
        {
            let native = self.owner.power.native.borrow();
            let run = native
                .work
                .render
                .run
                .as_ref()
                .ok_or("GFX mirror read has no native owner")?;
            let prefix = run
                .prefix
                .as_ref()
                .ok_or("GFX mirror read has no context phase")?;
            if prefix.committed != 4 || !prefix.program.merge_mirror() {
                return Err("GFX mirror read differs from the selected source program");
            }
        }
        self.owner.target_word(self.port, 0x7610, 8, false)?;
        let mut native = self.owner.power.native.borrow_mut();
        let value = native
            .work
            .legacy_mask
            .ok_or("GFX render native mirror-mask initial value is not qualified")?;
        native
            .work
            .render
            .run
            .as_mut()
            .unwrap()
            .prefix
            .as_mut()
            .unwrap()
            .mirror = Some(value);
        Ok(value)
    }
    fn write_native(&mut self, word: Word, value: u64) -> Result<(), &'static str> {
        self.owner.available()?;
        {
            let native = self.owner.power.native.borrow();
            let run = native
                .work
                .render
                .run
                .as_ref()
                .ok_or("GFX context store has no native owner")?;
            let prefix = run
                .prefix
                .as_ref()
                .ok_or("GFX context store has no accepted prefix")?;
            let words = render_context::native_words(self.owner.policy, run.lease.pipe);
            if prefix.committed == 0 || words.get(usize::from(prefix.committed - 1)) != Some(&word)
            {
                return Err("GFX common context native store differs from source order");
            }
            let (offset, width) = word.range();
            let expected = match offset {
                0x10208 | 0x10210 => {
                    let low = if self.owner.policy == Policy::G13X {
                        u32::from(run.lease.slot) | (u32::from(run.lease.pipe) << 4)
                    } else {
                        run.frame
                            .u32(if run.lease.pipe == 0 { 0x44 } else { 0x5c })?
                            & 0x3f
                    };
                    u64::from(low | (run.submission.context << 8))
                }
                0x17000 => 0x100,
                0x17610 | 0x7610 => {
                    let old = prefix
                        .mask
                        .ok_or("GFX common context store precedes its original mask read")?;
                    let flag = run
                        .frame
                        .u32(if run.lease.pipe == 0 { 0x40 } else { 0x58 })?;
                    let bit = 1u64 << run.submission.context;
                    let primary = if flag == 0 { old & !bit } else { old | bit };
                    if offset == 0x7610 && prefix.program.merge_mirror() {
                        primary
                            | prefix
                                .mirror
                                .ok_or("GFX mirror store precedes its source read")?
                            | bit
                    } else {
                        primary
                    }
                }
                _ => return Err("GFX common context native word is not qualified"),
            };
            if expected != value || (width == 4 && value > u64::from(u32::MAX)) {
                return Err("GFX common context native value differs from its accepted source");
            }
        }
        let (offset, width) = word.range();
        self.owner.target_word(self.port, offset, width, true)?;
        let mut native = self.owner.power.native.borrow_mut();
        let registers = &mut native.work.render;
        if let Some((_, old)) = registers.stored.iter_mut().find(|(w, _)| *w == word) {
            *old = value;
        } else {
            registers.stored.push((word, value));
        }
        registers
            .run
            .as_mut()
            .unwrap()
            .prefix
            .as_mut()
            .unwrap()
            .committed += 1;
        match offset {
            0x17610 => native.work.context_mask = Some(value),
            0x17000 => native.work.legacy_setup = Some(value),
            0x7610 => native.work.legacy_mask = Some(value),
            _ => {}
        }
        Ok(())
    }
    fn write_slot_status(&mut self, lease: Lease, value: u32) -> Result<(), &'static str> {
        self.owner.available()?;
        let mut native = self.owner.power.native.borrow_mut();
        let run = native
            .work
            .render
            .run
            .as_mut()
            .ok_or("GFX private slot store has no native owner")?;
        let expected = render_context::native_words(self.owner.policy, lease.pipe).len() as u8 + 1;
        let prefix = run
            .prefix
            .as_mut()
            .ok_or("GFX private slot store has no context phase")?;
        if run.lease != lease
            || prefix.committed != expected
            || value != run.frame.u32(if lease.pipe == 0 { 0x48 } else { 0x60 })?
        {
            return Err("GFX private slot store differs from its accepted source phase");
        }
        prefix.committed += 1;
        let index = usize::from(lease.slot) + usize::from(lease.pipe) * 3;
        native.work.render.context.status[index] = Some(value);
        Ok(())
    }
}
