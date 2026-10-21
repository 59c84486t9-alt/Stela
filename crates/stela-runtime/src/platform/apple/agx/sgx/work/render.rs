//! The actual SGX sink for the original fixed TA/3D parameter phases. Stored
//! native values have no reset readback; only source stores make them known.
//! No trigger or backend invocation is provided by this configuration phase.

use super::FirmwareWork;
use crate::platform::apple::agx::{
    channel::Kind,
    exec::render::{GeometryInputs, SampleStorage, SamplerHeap, Zls, ZlsPair},
    work_decode::{
        Frame, Submission,
        resources::{Lease, Outcome},
        scene,
        ta::{self, Word},
    },
};
use crate::platform::dma::Port;
use alloc::vec::Vec;

#[derive(Debug)]
struct Run {
    submission: Submission,
    lease: Lease,
    frame: Frame,
    next: usize,
    words: Vec<Word>,
}
#[derive(Debug, Default)]
pub(super) struct Registers {
    run: Option<Run>,
    // An absent word remains unknown. This is native configuration, not a
    // RAM substitute or readable register image.
    stored: Vec<(Word, u64)>,
    #[cfg(test)]
    pub(super) writes: usize,
}
impl Registers {
    pub(super) fn active(&self) -> bool {
        self.run.is_some()
    }
    fn committed(&self, word: Word) -> Option<u64> {
        self.stored
            .iter()
            .find(|(stored, _)| *stored == word)
            .map(|(_, value)| *value)
    }
    #[cfg(test)]
    pub(super) fn value(&self, word: Word) -> Option<u64> {
        self.committed(word)
    }
}

/// Source-committed 3D ZLS configuration, without start/completion authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZlsBindings {
    pub control: u64,
    pub pixels: u32,
    pub depth: ZlsPair,
    pub stencil: ZlsPair,
}

pub struct ParameterAccess<'a, 'p, 'm> {
    owner: &'a FirmwareWork,
    port: &'a mut Port<'p, 'm>,
    pipeline: Kind,
}
impl FirmwareWork {
    /// Decode only TA configuration committed by this exact accepted owner.
    /// No native trigger, TVB/resource authority or hardware readback follows.
    /// A sampler heap must come from its separate actual context binding.
    pub fn ta_geometry_inputs(
        &self,
        submission: &Submission,
        lease: Lease,
        sampler_heap: Option<SamplerHeap>,
    ) -> Result<GeometryInputs, &'static str> {
        self.available()?;
        let native = self.power.native.borrow();
        let registers = &native.work.render;
        let run = registers
            .run
            .as_ref()
            .ok_or("GFX TA configuration has no native owner")?;
        if run.submission != *submission
            || run.lease != lease
            || submission.command.kind != Kind::Ta
            || run.next != run.words.len()
        {
            return Err("GFX TA configuration requires its complete accepted parameter phase");
        }
        let word = |offset, width| {
            registers
                .committed(Word::new(offset, width))
                .ok_or("GFX TA configuration word has not been programmed")
        };
        // Original tiling +8/+c and second-block VDM/USC stores. The packed
        // PPP screen holds inclusive x/y maxima; no future 3D field is read.
        let screen = word(0x10128, 4)? as u32;
        let inputs = GeometryInputs {
            vdm_stream: word(0x16880, 8)?,
            usc_base: word(0x10060, 8)?,
            vm_slot: submission.context,
            ppp_control: word(0x10120, 4)? as u32,
            width: (screen & 0xffff) + 1,
            height: (screen >> 16) + 1,
            sampler_heap,
        };
        inputs
            .check()
            .map_err(|_| "GFX TA configuration has unsupported PPP clip/control inputs")?;
        Ok(inputs)
    }
    /// Decode independent load/store registers only after the actual 3D
    /// parameter phase. Inactive bindings remain explicit source values.
    pub fn three_d_zls_bindings(
        &self,
        submission: &Submission,
        lease: Lease,
    ) -> Result<ZlsBindings, &'static str> {
        self.available()?;
        let native = self.power.native.borrow();
        let registers = &native.work.render;
        let run = registers
            .run
            .as_ref()
            .ok_or("GFX 3D ZLS configuration has no native owner")?;
        if run.submission != *submission
            || run.lease != lease
            || submission.command.kind != Kind::ThreeD
            || run.next != run.words.len()
        {
            return Err("GFX 3D ZLS configuration requires its complete accepted parameter phase");
        }
        let word = |offset| {
            registers
                .committed(Word::new(offset, 8))
                .ok_or("GFX 3D ZLS configuration word has not been programmed")
        };
        let scalar = |offset| {
            u32::try_from(word(offset)?).map_err(|_| "GFX 3D ZLS scalar has unqualified upper bits")
        };
        let surface = |base, stride, meta, meta_stride| {
            Ok::<_, &'static str>(Zls {
                base: word(base)?,
                stride: scalar(stride)?,
                meta: word(meta)?,
                meta_stride: scalar(meta_stride)?,
            })
        };
        Ok(ZlsBindings {
            control: word(0x15318)?,
            pixels: scalar(0x15320)?,
            depth: ZlsPair {
                load: surface(0x15328, 0x15400, 0x153c0, 0x15410)?,
                store: surface(0x15330, 0x15420, 0x153c8, 0x15430)?,
            },
            stencil: ZlsPair {
                load: surface(0x15338, 0x15408, 0x153d0, 0x15418)?,
                store: surface(0x15340, 0x15428, 0x153d8, 0x15438)?,
            },
        })
    }
    /// Native TIB capacity is allocated in 2KiB blocks. The actual shader's
    /// USC Shared view must still bind its stride within that allocation.
    pub fn three_d_sample_storage(
        &self,
        submission: &Submission,
        lease: Lease,
    ) -> Result<SampleStorage, &'static str> {
        self.available()?;
        let native = self.power.native.borrow();
        let registers = &native.work.render;
        let run = registers
            .run
            .as_ref()
            .ok_or("GFX 3D sample storage has no native owner")?;
        if run.submission != *submission
            || run.lease != lease
            || submission.command.kind != Kind::ThreeD
            || run.next != run.words.len()
        {
            return Err("GFX 3D sample storage requires its complete accepted parameter phase");
        }
        let blocks = registers
            .committed(Word::new(0x10050, 4))
            .ok_or("GFX 3D TIB allocation has not been programmed")?;
        Ok(SampleStorage::native(
            u32::try_from(blocks).map_err(|_| "GFX 3D TIB allocation width is invalid")?,
        ))
    }
    pub fn ta_parameter_access<'a, 'p, 'm>(
        &'a self,
        port: &'a mut Port<'p, 'm>,
    ) -> ParameterAccess<'a, 'p, 'm> {
        ParameterAccess {
            owner: self,
            port,
            pipeline: Kind::Ta,
        }
    }
    pub fn three_d_parameter_access<'a, 'p, 'm>(
        &'a self,
        port: &'a mut Port<'p, 'm>,
    ) -> ParameterAccess<'a, 'p, 'm> {
        ParameterAccess {
            owner: self,
            port,
            pipeline: Kind::ThreeD,
        }
    }
    pub fn cancel_ta_parameters(
        &self,
        submission: &Submission,
        lease: Lease,
        settlement: &Outcome,
    ) -> Result<(), &'static str> {
        if submission.command.kind != Kind::Ta {
            return Err("GFX TA cancellation requires TA ownership");
        }
        self.cancel_render_parameters(submission, lease, settlement)
    }
    pub fn cancel_three_d_parameters(
        &self,
        submission: &Submission,
        lease: Lease,
        settlement: &Outcome,
    ) -> Result<(), &'static str> {
        if submission.command.kind != Kind::ThreeD {
            return Err("GFX 3D cancellation requires 3D ownership");
        }
        self.cancel_render_parameters(submission, lease, settlement)
    }
    /// The outer source owner settles resources/TVB before cancelling native
    /// ownership. This preserves committed configuration stores.
    fn cancel_render_parameters(
        &self,
        submission: &Submission,
        lease: Lease,
        settlement: &Outcome,
    ) -> Result<(), &'static str> {
        self.available()?;
        if !matches!(settlement, Outcome::Aborted) {
            return Err("GFX render cancellation requires settled resource abort ownership");
        }
        let mut native = self.power.native.borrow_mut();
        let run = native
            .work
            .render
            .run
            .as_ref()
            .ok_or("GFX render cancellation has no native owner")?;
        if run.submission != *submission || run.lease != lease {
            return Err("GFX render cancellation differs from its accepted native owner");
        }
        native.work.render.run = None;
        Ok(())
    }
}
impl ta::Access for ParameterAccess<'_, '_, '_> {
    fn policy(&self) -> crate::platform::apple::agx::work_decode::resources::Policy {
        self.owner.policy
    }
    fn memory(&mut self) -> &mut dyn crate::platform::apple::agx::ring::Shared {
        self.port
    }
    fn begin(
        &mut self,
        submission: &Submission,
        lease: Lease,
        frame: &Frame,
    ) -> Result<(), &'static str> {
        self.owner.available()?;
        let pipe = match self.pipeline {
            Kind::Ta => 0,
            Kind::ThreeD => 1,
            _ => unreachable!(),
        };
        if submission.command.kind != self.pipeline
            || lease.pipe != pipe
            || lease.slot >= 6
            || submission.context >= 64
        {
            return Err(
                "GFX render native parameters require their accepted pipeline lease/context",
            );
        }
        scene::Key::read(submission, frame)?;
        let mut native = self.owner.power.native.borrow_mut();
        if native.work.run.is_some() {
            return Err("GFX native parameter bank still belongs to accepted CL work");
        }
        let registers = &mut native.work.render;
        if let Some(run) = &registers.run {
            return if run.submission == *submission && run.lease == lease && run.frame == *frame {
                Ok(())
            } else {
                Err("GFX render native parameters still belong to another command")
            };
        }
        registers.run = Some(Run {
            submission: submission.clone(),
            lease,
            frame: frame.clone(),
            next: 0,
            words: match self.pipeline {
                Kind::Ta => ta::words(self.owner.policy),
                Kind::ThreeD => {
                    crate::platform::apple::agx::work_decode::three_d::words(self.owner.policy)
                }
                _ => unreachable!(),
            },
        });
        Ok(())
    }
    fn write_native(&mut self, word: Word, value: u64) -> Result<(), &'static str> {
        let (offset, width) = word.range();
        self.owner.target_word(self.port, offset, width, true)?;
        let mut native = self.owner.power.native.borrow_mut();
        let registers = &mut native.work.render;
        let run = registers
            .run
            .as_mut()
            .ok_or("GFX render native parameter store has no accepted owner")?;
        if run.submission.command.kind != self.pipeline
            || run.words.get(run.next) != Some(&word)
            || (width == 4 && value > u64::from(u32::MAX))
            || (offset == 0x11000 && value != 0x100)
        {
            return Err("GFX render native parameter store differs from its source order/width");
        }
        if let Some((_, stored)) = registers
            .stored
            .iter_mut()
            .find(|(known, _)| *known == word)
        {
            *stored = value;
        } else {
            registers.stored.push((word, value));
        }
        run.next += 1;
        #[cfg(test)]
        {
            registers.writes += 1;
        }
        if offset == 0x11000 {
            native.work.setup = value;
        }
        Ok(())
    }
}
