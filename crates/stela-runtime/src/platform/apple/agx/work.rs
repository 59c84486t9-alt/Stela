//! Retained GPU backend execution in the submitting UAT context.
//!
//! An original accepted submission owns the decoded engine inputs and the
//! complete backend result. GPU reads/writes may precede an error, so every
//! result, including a refusal/fault, is terminal for this execution owner.
//! Completion DMA and firmware resource release must never restart the helper.
//! TA owns the geometry product; a distinct 3D owner consumes it once. These
//! engine phases do not themselves publish stamps, events or ring retirement.
//! Native setup/start, timing, resource and abort obligations remain with the
//! stock firmware consumer; a decoded job is not a completed Apple command.

use super::channel::Kind;
use super::exec::WorkError;
use super::exec::compute::{self, Job};
use super::exec::render::{self, FragmentInputs, GeometryInputs, RenderPass};
use super::isa::machine::{Fault, Memory};
use super::ring::Shared;
use super::uat::CONTEXTS;
use super::work_decode::{Frame, Submission, scene};
use crate::platform::dma::DmaError;
use alloc::boxed::Box;

/// The engine's [`Memory`] over the firmware's shared view in one UAT
/// context, with the GPU's permissions. A fault in the walk is a [`Fault`]
/// the engine reports as a GPU fault (FW-14 at the engine; the firmware's
/// report to the kext is separate).
pub struct GpuView<'a> {
    shared: &'a mut dyn Shared,
    context: usize,
}

impl<'a> GpuView<'a> {
    pub fn new(shared: &'a mut dyn Shared, context: usize) -> Self {
        Self { shared, context }
    }
}

impl Memory for GpuView<'_> {
    fn read(&mut self, address: u64, buffer: &mut [u8]) -> Result<(), Fault> {
        self.shared
            .gpu_read(self.context, address, buffer)
            .map_err(|error| fault(error, address, false))
    }
    fn write(&mut self, address: u64, data: &[u8]) -> Result<(), Fault> {
        self.shared
            .gpu_write(self.context, address, data)
            .map_err(|error| fault(error, address, true))
    }
}

/// A DMA error as the engine's [`Fault`]: the faulting address and direction.
fn fault(_error: DmaError, address: u64, write: bool) -> Fault {
    Fault { address, write }
}

/// A backend outcome whose memory effects have settled. The geometry
/// product stays in its execution owner until transferred to a 3D owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultKind {
    Compute(compute::Stats),
    Geometry(render::Stats),
    Fragment(render::Stats),
}

/// A linear TA product, retaining the exact parameters under which vertices
/// were shaded and binned. This is deliberately not Clone: a second 3D start
/// cannot reuse ownership by copying a private tiled-buffer representation.
pub struct GeometryProduct(Box<GeometryData>);

struct GeometryData {
    producer: Submission,
    scene: Option<scene::Key>,
    pass: GeometryInputs,
    binned: render::geometry::Binned,
    stats: render::Stats,
}

impl GeometryProduct {
    pub fn producer(&self) -> &Submission {
        &self.0.producer
    }
    fn matches(&self, pass: &FragmentInputs) -> bool {
        self.0.pass.vm_slot == pass.vm_slot
            && self.0.pass.width == pass.width
            && self.0.pass.height == pass.height
    }
}

enum JobKind {
    Compute(Job),
    Geometry(Box<GeometryInputs>),
    Fragment {
        pass: Box<FragmentInputs>,
        product: GeometryProduct,
    },
}

enum Output {
    Compute(compute::Stats),
    Geometry(GeometryProduct),
    Fragment(render::Stats),
}
impl Output {
    fn kind(&self) -> ResultKind {
        match self {
            Self::Compute(stats) => ResultKind::Compute(*stats),
            Self::Geometry(product) => ResultKind::Geometry(product.0.stats),
            Self::Fragment(stats) => ResultKind::Fragment(*stats),
        }
    }
}

enum Phase {
    Ready,
    Settled(Result<Output, WorkError>),
    Transferred,
}

/// One accepted backend invocation. The outer stock consumer must finish
/// its native setup before `run` and retain this owner through all later
/// resource, DMA and publication phases. Neither success nor failure here
/// grants permission to retire a command or to reset outstanding ownership.
pub struct Execution {
    submission: Submission,
    job: JobKind,
    scene: Option<scene::Key>,
    phase: Phase,
}
impl Execution {
    pub fn compute(submission: Submission, job: Job) -> Result<Self, WorkError> {
        if submission.command.kind != Kind::Cl {
            return Err(WorkError::Refused(
                "GFX compute execution requires an accepted CL command",
            ));
        }
        check_context(submission.context as usize, job.vm_slot)?;
        Ok(Self {
            submission,
            job: JobKind::Compute(job),
            scene: None,
            phase: Phase::Ready,
        })
    }

    pub fn geometry(submission: Submission, pass: RenderPass) -> Result<Self, WorkError> {
        if submission.command.kind != Kind::Ta {
            return Err(WorkError::Refused(
                "GFX geometry execution requires an accepted TA command",
            ));
        }
        pass.check()?;
        Self::geometry_inputs(submission, pass.geometry_inputs())
    }
    fn geometry_inputs(submission: Submission, pass: GeometryInputs) -> Result<Self, WorkError> {
        if submission.command.kind != Kind::Ta {
            return Err(WorkError::Refused(
                "GFX geometry execution requires an accepted TA command",
            ));
        }
        check_context(submission.context as usize, pass.vm_slot)?;
        pass.check()?;
        Ok(Self {
            submission,
            job: JobKind::Geometry(Box::new(pass)),
            scene: None,
            phase: Phase::Ready,
        })
    }

    /// Bind actual TA geometry to its original accepted shared scene. This
    /// proves association only; native setup/TVB/resource effects still belong
    /// to the stock consumer before it invokes the backend.
    pub fn geometry_for_setup(
        submission: Submission,
        frame: &Frame,
        pass: GeometryInputs,
    ) -> Result<Self, WorkError> {
        let key = scene::Key::read(&submission, frame).map_err(WorkError::Refused)?;
        let mut owner = Self::geometry_inputs(submission, pass)?;
        owner.scene = Some(key);
        Ok(owner)
    }

    /// Return the still-owned product on every pre-execution refusal. A
    /// same-sized render pass or a caller-supplied helper product supplies no
    /// proof that this distinct 3D setup belongs to the original TA scene.
    pub fn fragment_for_setup(
        submission: Submission,
        frame: &Frame,
        pass: FragmentInputs,
        product: GeometryProduct,
    ) -> Result<Self, (WorkError, GeometryProduct)> {
        let key = match scene::Key::read(&submission, frame) {
            Ok(key) => key,
            Err(reason) => return Err((WorkError::Refused(reason), product)),
        };
        if product.0.scene != Some(key) {
            return Err((
                WorkError::Refused("GFX 3D setup does not own the source TA scene"),
                product,
            ));
        }
        let mut owner = Self::fragment_inner(submission, pass, product)?;
        owner.scene = Some(key);
        Ok(owner)
    }

    /// A refused 3D binding returns the still-owned TA product to its caller.
    /// Association to the original scene/queue must be established by the
    /// source-qualified firmware consumer before calling this constructor.
    pub fn fragment(
        submission: Submission,
        pass: FragmentInputs,
        product: GeometryProduct,
    ) -> Result<Self, (WorkError, GeometryProduct)> {
        if product.0.scene.is_some() {
            return Err((
                WorkError::Refused("GFX source TA geometry requires its original 3D setup"),
                product,
            ));
        }
        Self::fragment_inner(submission, pass, product)
    }

    fn fragment_inner(
        submission: Submission,
        pass: FragmentInputs,
        product: GeometryProduct,
    ) -> Result<Self, (WorkError, GeometryProduct)> {
        let check = || {
            if submission.command.kind != Kind::ThreeD {
                return Err(WorkError::Refused(
                    "GFX fragment execution requires an accepted 3D command",
                ));
            }
            check_context(submission.context as usize, pass.vm_slot)?;
            pass.check()?;
            if !product.matches(&pass) {
                return Err(WorkError::Refused(
                    "GFX 3D geometry does not match its TA context or tiling extent",
                ));
            }
            Ok(())
        };
        if let Err(error) = check() {
            return Err((error, product));
        }
        Ok(Self {
            submission,
            job: JobKind::Fragment {
                pass: Box::new(pass),
                product,
            },
            scene: None,
            phase: Phase::Ready,
        })
    }

    pub fn submission(&self) -> &Submission {
        &self.submission
    }

    /// Execute at most once. An engine error can follow committed GPU writes
    /// and is retained with exactly the same identity as a successful result.
    /// Subsequent firmware DMA faults may retry only the later firmware phase.
    pub fn run(&mut self, memory: &mut dyn Shared) -> Result<ResultKind, WorkError> {
        if matches!(self.phase, Phase::Ready) {
            let mut view = GpuView::new(memory, self.submission.context as usize);
            let result = match &self.job {
                JobKind::Compute(job) => compute::run(&mut view, job).map(Output::Compute),
                JobKind::Geometry(pass) => {
                    let mut stats = render::Stats::default();
                    render::geometry::run(&mut view, pass, &mut stats).map(|binned| {
                        Output::Geometry(GeometryProduct(Box::new(GeometryData {
                            producer: self.submission.clone(),
                            scene: self.scene,
                            pass: **pass,
                            binned,
                            stats,
                        })))
                    })
                }
                JobKind::Fragment { pass, product } => {
                    let mut stats = product.0.stats;
                    render::fragment::run(&mut view, pass, &product.0.binned, &mut stats)
                        .map(|()| Output::Fragment(stats))
                }
            };
            self.phase = Phase::Settled(result);
        }
        match &self.phase {
            Phase::Settled(Ok(output)) => Ok(output.kind()),
            Phase::Settled(Err(error)) => Err(*error),
            Phase::Transferred => Err(WorkError::Refused(
                "GFX TA geometry ownership was already transferred",
            )),
            Phase::Ready => unreachable!(),
        }
    }

    /// Inspect a retained result without issuing GPU accesses or replaying work.
    pub fn outcome(&self) -> Option<Result<ResultKind, WorkError>> {
        match &self.phase {
            Phase::Ready => None,
            Phase::Settled(Ok(output)) => Some(Ok(output.kind())),
            Phase::Settled(Err(error)) => Some(Err(*error)),
            Phase::Transferred => Some(Err(WorkError::Refused(
                "GFX TA geometry ownership was already transferred",
            ))),
        }
    }

    pub fn take_geometry(&mut self) -> Result<GeometryProduct, &'static str> {
        if !matches!(self.phase, Phase::Settled(Ok(Output::Geometry(_)))) {
            return Err("GFX TA has no successful owned geometry product");
        }
        let Phase::Settled(Ok(Output::Geometry(product))) =
            core::mem::replace(&mut self.phase, Phase::Transferred)
        else {
            unreachable!()
        };
        Ok(product)
    }
}

/// The shader's advertised slot and the memory view must identify the same
/// admitted UAT context, before the work can access any memory or complete.
fn check_context(context: usize, vm_slot: u32) -> Result<(), WorkError> {
    if context >= CONTEXTS {
        return Err(WorkError::Refused("GPU work context outside the UAT TTBAT"));
    }
    if context != vm_slot as usize {
        return Err(WorkError::Refused(
            "GPU work vm_slot does not match its UAT context",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::agx::channel::{Command, Kind, Stamp};
    use crate::platform::apple::agx::ring::tests::Flat;
    use crate::platform::apple::agx::work_decode::Encoding;
    use alloc::vec::Vec;

    // A low GPU VA: the USC uniform and texture words pack an address into a
    // bounded field, so the engine's own stream tests use a low base too.
    const BASE: u64 = 0x1_0000_0000;
    const COMMAND: u64 = BASE;

    /// A memory holding a one-launch CDM stream and its USC list, built from
    /// the engine's own encodings (as the observe tests do).
    fn compute_memory() -> (Flat, Job) {
        let mut memory = Flat::new(BASE, 0x8000);
        let (stream, pipeline, code, uniforms, output) = (
            BASE + 0x2000,
            BASE + 0x100,
            BASE + 0x200,
            BASE + 0x800,
            BASE + 0x1000,
        );
        // USC: a uniform load of the output address, the shader and its
        // register bound.
        let mut usc = Vec::new();
        usc.extend_from_slice(&(0x8d_u32 | 8 << 8).to_le_bytes());
        let uniform = 0x1d_u64 | 4 << 20 | (uniforms >> 2) << 26;
        usc.extend_from_slice(&uniform.to_le_bytes());
        usc.extend_from_slice(&[0x0d, 0]);
        usc.extend_from_slice(&((code - BASE) as u32).to_le_bytes());
        usc.extend_from_slice(&[0x88, 0]);
        memory.put(pipeline, &usc);
        memory.put(
            code,
            &crate::platform::apple::agx::isa::assemble::program(
                "mov r2, thread_in_grid_x\n\
                 store r2, du0, r2, i32, x, a\n\
                 stop",
            ),
        );
        memory.put_u64(uniforms, output);
        let mut words: Vec<u32> = alloc::vec![1 << 1, ((pipeline - BASE) as u32 >> 6) << 6];
        words.extend([4, 1, 1, 4, 1, 1, 2 << 29]);
        for (i, word) in words.iter().enumerate() {
            memory.put_u32(stream + 4 * i as u64, *word);
        }
        let job = Job {
            stream,
            usc_base: BASE,
            vm_slot: 5,
        };
        (memory, job)
    }
    fn accepted(kind: Kind) -> Submission {
        Submission {
            command: Command { va: COMMAND, kind },
            encoding: Encoding::Fixed,
            counter: 0x1234,
            context: 5,
            stamp: Stamp {
                driver: BASE + 0x40,
                firmware: BASE + 0x48,
                value: 0x900,
                index: 4,
            },
            stream: BASE + 0x3000,
            stream_bytes: 0x400,
        }
    }

    struct CountMemory {
        flat: Flat,
        gpu_reads: usize,
        gpu_writes: usize,
        fail_gpu_write: Option<usize>,
        fail_firmware_write: bool,
    }
    impl CountMemory {
        fn new(flat: Flat) -> Self {
            Self {
                flat,
                gpu_reads: 0,
                gpu_writes: 0,
                fail_gpu_write: None,
                fail_firmware_write: false,
            }
        }
        fn counts(&self) -> (usize, usize) {
            (self.gpu_reads, self.gpu_writes)
        }
    }
    impl Shared for CountMemory {
        fn read(&mut self, address: u64, buffer: &mut [u8]) -> Result<(), &'static str> {
            self.flat.read(address, buffer)
        }
        fn write(&mut self, address: u64, data: &[u8]) -> Result<(), &'static str> {
            if self.fail_firmware_write {
                self.fail_firmware_write = false;
                return Err("injected later firmware DMA fault");
            }
            self.flat.write(address, data)
        }
        fn gpu_read(
            &mut self,
            context: usize,
            address: u64,
            buffer: &mut [u8],
        ) -> Result<(), DmaError> {
            assert_eq!(context, 5);
            self.gpu_reads += 1;
            self.flat.gpu_read(context, address, buffer)
        }
        fn gpu_write(&mut self, context: usize, address: u64, data: &[u8]) -> Result<(), DmaError> {
            assert_eq!(context, 5);
            let index = self.gpu_writes;
            self.gpu_writes += 1;
            if self.fail_gpu_write == Some(index) {
                self.fail_gpu_write = None;
                return Err(DmaError::Memory);
            }
            self.flat.gpu_write(context, address, data)
        }
    }

    #[test]
    fn a_compute_result_survives_later_firmware_dma_faults_and_input_changes() {
        let (flat, job) = compute_memory();
        let mut memory = CountMemory::new(flat);
        let input = accepted(Kind::Cl);
        let mut work = Execution::compute(input.clone(), job).unwrap();
        let result = work.run(&mut memory).unwrap();
        let ResultKind::Compute(stats) = result else {
            panic!("compute result lost")
        };
        assert_eq!((stats.launches, stats.threadgroups), (1, 1));
        let counts = memory.counts();
        assert_eq!(counts.1, 4);
        // A later firmware phase can fault without reopening GPU execution.
        memory.fail_firmware_write = true;
        assert_eq!(
            memory.write(input.stamp.firmware, &input.stamp.value.to_le_bytes()),
            Err("injected later firmware DMA fault")
        );
        memory.flat.put_u32(job.stream, u32::MAX);
        memory.flat.put(BASE + 0x200, &[0xff; 16]);
        for _ in 0..3 {
            assert_eq!(work.run(&mut memory), Ok(result));
        }
        assert_eq!(memory.counts(), counts);
        for i in 0..4 {
            assert_eq!(memory.flat.read_u32(BASE + 0x1000 + 4 * i), Ok(i as u32));
        }
        assert_eq!(work.submission(), &input);
        // Backend success alone never publishes command completion.
        assert_eq!(memory.flat.read_u32(input.stamp.driver), Ok(0));
        assert_eq!(memory.flat.read_u32(input.stamp.firmware), Ok(0));
    }

    #[test]
    fn a_terminal_gpu_fault_keeps_its_committed_prefix_and_cannot_replay() {
        let (flat, job) = compute_memory();
        let mut memory = CountMemory::new(flat);
        memory.fail_gpu_write = Some(2);
        let mut work = Execution::compute(accepted(Kind::Cl), job).unwrap();
        let error = work.run(&mut memory).unwrap_err();
        let counts = memory.counts();
        assert_eq!(counts.1, 3);
        assert_eq!(memory.flat.read_u32(BASE + 0x1004), Ok(1));
        memory.flat.put_u32(BASE + 0x1000, 777);
        for _ in 0..3 {
            assert_eq!(work.run(&mut memory), Err(error));
        }
        assert_eq!(memory.counts(), counts);
        assert_eq!(memory.flat.read_u32(BASE + 0x1000), Ok(777));
        assert_eq!(memory.flat.read_u32(BASE + 0x40), Ok(0));
        assert_eq!(memory.flat.read_u32(BASE + 0x48), Ok(0));
        assert!(work.take_geometry().is_err());
    }

    fn render_memory() -> (CountMemory, RenderPass) {
        let mut memory = Flat::new(BASE, 0x8000);
        memory.put_u32(BASE + 0x2000, 6 << 29); // VDM terminate, no draws
        let code = crate::platform::apple::agx::isa::assemble::program("stop");
        memory.put(BASE + 0x200, &code);
        let mut usc = Vec::new();
        usc.extend_from_slice(&0x8d_u32.to_le_bytes());
        usc.extend_from_slice(&[0x0d, 0]);
        usc.extend_from_slice(&0x200u32.to_le_bytes());
        usc.extend_from_slice(&[0x88, 0]);
        memory.put(BASE + 0x100, &usc);
        let pass = RenderPass {
            vdm_stream: BASE + 0x2000,
            usc_base: BASE,
            vm_slot: 5,
            ppp_control: render::ppp_control::FIXED_POINT_FORMAT,
            width: 16,
            height: 16,
            layers: 1,
            samples: 1,
            tile: (16, 16),
            sample_bytes: 16,
            background: render::Program {
                usc: 0x100,
                counts: 0,
            },
            end_of_tile: render::Program {
                usc: 0x100,
                counts: 0,
            },
            ..RenderPass::default()
        };
        (CountMemory::new(memory), pass)
    }

    #[test]
    fn ta_transfers_its_geometry_once_and_3d_runs_its_own_phase_once() {
        let (mut memory, pass) = render_memory();
        let mut ta = Execution::geometry(accepted(Kind::Ta), pass).unwrap();
        assert!(ta.take_geometry().is_err());
        let geometry = ta.run(&mut memory).unwrap();
        assert!(matches!(geometry, ResultKind::Geometry(_)));
        let ta_counts = memory.counts();
        assert_eq!(ta_counts.1, 0);
        memory.flat.put_u32(pass.vdm_stream, u32::MAX);
        assert_eq!(ta.run(&mut memory), Ok(geometry));
        assert_eq!(memory.counts(), ta_counts);
        let product = ta.take_geometry().unwrap();
        assert!(ta.take_geometry().is_err());
        assert!(ta.run(&mut memory).is_err());
        // A mismatched 3D constructor returns the product without memory effects.
        let bad = RenderPass { width: 32, ..pass };
        let Err((_, product)) =
            Execution::fragment(accepted(Kind::ThreeD), bad.fragment_inputs(), product)
        else {
            panic!("mismatched tiling accepted")
        };
        assert_eq!(memory.counts(), ta_counts);
        let mut fragment =
            match Execution::fragment(accepted(Kind::ThreeD), pass.fragment_inputs(), product) {
                Ok(work) => work,
                Err(_) => panic!("matching TA/3D product refused"),
            };
        let result = fragment.run(&mut memory).unwrap();
        let ResultKind::Fragment(stats) = result else {
            panic!("3D phase result lost")
        };
        assert_eq!((stats.draws, stats.primitives, stats.tiles), (0, 0, 1));
        let counts = memory.counts();
        assert!(counts.0 > ta_counts.0);
        memory.flat.put(BASE + 0x200, &[0xff; 16]);
        assert_eq!(fragment.run(&mut memory), Ok(result));
        assert_eq!(memory.counts(), counts);
        assert_eq!(memory.flat.read_u32(BASE + 0x40), Ok(0));
    }

    fn scene_frame(submission: &Submission, buffer: u64) -> Frame {
        let (record, at, context) = match submission.command.kind {
            Kind::Ta => (
                crate::platform::apple::agx::channel::Record::SetupTa,
                0x1c,
                0x3c,
            ),
            Kind::ThreeD => (
                crate::platform::apple::agx::channel::Record::Setup3d,
                0x14,
                0x54,
            ),
            _ => unreachable!(),
        };
        let mut source = Flat::new(BASE, 0x8000);
        source.put_u32(
            submission.stream,
            if submission.command.kind == Kind::Ta {
                5
            } else {
                7
            },
        );
        source.put_u64(submission.stream + at, buffer);
        source.put_u32(submission.stream + context, submission.context);
        let frame = submission.cursor().next(&mut source).unwrap().unwrap();
        assert_eq!(frame.record, record);
        frame
    }
    #[test]
    fn source_scene_identity_returns_geometry_on_wrong_scene_and_retains_real_fragment_outcome() {
        let (mut memory, pass) = render_memory();
        let input = accepted(Kind::Ta);
        let ta_frame = scene_frame(&input, BASE + 0x6000);
        let mut ta =
            Execution::geometry_for_setup(input.clone(), &ta_frame, pass.geometry_inputs())
                .unwrap();
        ta.run(&mut memory).unwrap();
        let product = ta.take_geometry().unwrap();
        assert_eq!(product.producer(), &input);
        let before = memory.counts();
        let mut consumer = accepted(Kind::ThreeD);
        consumer.counter += 1;
        let wrong = scene_frame(&consumer, BASE + 0x6800);
        let Err((error, product)) = Execution::fragment_for_setup(
            consumer.clone(),
            &wrong,
            pass.fragment_inputs(),
            product,
        ) else {
            panic!("equal dimensions exchanged different scenes")
        };
        assert_eq!(
            error,
            WorkError::Refused("GFX 3D setup does not own the source TA scene")
        );
        assert_eq!(memory.counts(), before);
        assert_eq!(product.producer(), &input);
        let Err((error, product)) =
            Execution::fragment(consumer.clone(), pass.fragment_inputs(), product)
        else {
            panic!("legacy helper bypassed the source scene binding")
        };
        assert_eq!(
            error,
            WorkError::Refused("GFX source TA geometry requires its original 3D setup")
        );
        assert_eq!(memory.counts(), before);
        let correct = scene_frame(&consumer, BASE + 0x6000);
        let mut fragment = match Execution::fragment_for_setup(
            consumer.clone(),
            &correct,
            pass.fragment_inputs(),
            product,
        ) {
            Ok(owner) => owner,
            Err(_) => panic!("matching source scene refused"),
        };
        let outcome = fragment.run(&mut memory).unwrap();
        let counts = memory.counts();
        memory.fail_firmware_write = true;
        assert!(
            memory
                .write(consumer.stamp.firmware, &consumer.stamp.value.to_le_bytes())
                .is_err()
        );
        memory.flat.put(BASE + 0x200, &[0xff; 16]);
        assert_eq!(fragment.run(&mut memory), Ok(outcome));
        assert_eq!(memory.counts(), counts);
        assert_eq!(memory.flat.read_u32(consumer.stamp.firmware), Ok(0));
    }
    #[test]
    fn caller_supplied_geometry_does_not_acquire_source_scene_authority() {
        let (mut memory, pass) = render_memory();
        let mut ta = Execution::geometry(accepted(Kind::Ta), pass).unwrap();
        ta.run(&mut memory).unwrap();
        let product = ta.take_geometry().unwrap();
        let before = memory.counts();
        let consumer = accepted(Kind::ThreeD);
        let frame = scene_frame(&consumer, BASE + 0x6000);
        let Err((_, product)) =
            Execution::fragment_for_setup(consumer, &frame, pass.fragment_inputs(), product)
        else {
            panic!("helper product manufactured source authority")
        };
        assert_eq!(memory.counts(), before);
        assert_eq!(product.producer().command.kind, Kind::Ta);
    }

    #[test]
    fn backend_constructors_check_original_kind_and_context_before_memory_access() {
        let (_, job) = compute_memory();
        assert!(matches!(
            Execution::compute(accepted(Kind::Ta), job),
            Err(WorkError::Refused(
                "GFX compute execution requires an accepted CL command"
            ))
        ));
        let mut input = accepted(Kind::Cl);
        input.context = 6;
        assert!(matches!(
            Execution::compute(input, job),
            Err(WorkError::Refused(
                "GPU work vm_slot does not match its UAT context"
            ))
        ));
        let mut input = accepted(Kind::Cl);
        input.context = CONTEXTS as u32;
        assert!(matches!(
            Execution::compute(input, job),
            Err(WorkError::Refused("GPU work context outside the UAT TTBAT"))
        ));
    }
}
