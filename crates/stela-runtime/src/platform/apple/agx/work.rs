//! Executing the GPU-work channel commands (TA, 3D, CL, fast blit) on the
//! engine and completing them with the stamps and events the kext waits on
//! (docs/research/agx.md §5.1, FW-4, FW-6..FW-9, FW-17).
//!
//! A work command names a control stream (a CDM stream for CL compute, a VDM
//! stream for TA/3D render) and the state the engine needs, in the submitting
//! address space. This module is the bridge between the firmware's channel
//! commands ([`super::channel`]) and the execution engine ([`super::exec`]):
//!
//! - [`GpuView`] gives the engine [`Memory`] over the firmware's shared view
//!   ([`Shared`]) in one UAT context, with the GPU's own permissions
//!   ([`super::uat::gpu_stream`]). The firmware and the GPU it drives are one
//!   bus master behind one UAT (Decision; docs/research/agx.md §3): the engine
//!   therefore reaches the same memory the kext built the streams in, faulting
//!   exactly where a real GPU unit would.
//! - [`complete`] finishes a work command the way the firmware's completion
//!   path does and the signal commands already do ([`super::signal`]): it
//!   writes the stamp value to the firmware stamp and the driver stamp, then
//!   returns a Flag event for the stamp index. **Public** (Asahi
//!   `FinalizeCompute`/`FinalizeFragment`/`FinalizeVertex` write `fw_stamp =
//!   stamp_value` and the kext drains one Flag per completed stamp);
//!   **Inferred** that a work command completes exactly as a signal command,
//!   the path [`super::signal`] cites.
//! - [`run_compute`] and [`run_render`] run a decoded job or render pass in
//!   the submitting context and complete it.
//!
//! What this module does **not** do is read a work command's Apple SKU-stream
//! setup/start records to recover the engine inputs (the CDM/VDM stream base,
//! the USC execution base, the framebuffer and tile parameters, the ZLS
//! buffers). Those record field offsets are Apple's own and are not recovered
//! statically; the matrix leaves FW-6..FW-9 refused by name until the
//! observation route (docs/research/agx.md §5.1a) confirms each offset by
//! following it to a structure the engine decodes. The decode that would call
//! [`run_compute`]/[`run_render`] from a real command is therefore gated on
//! observation; here the two run from inputs a caller supplies, and the tests
//! build those inputs from the engine's own stream encodings.

use super::channel::{Command, Stamp};
use super::event::Event;
use super::exec::WorkError;
use super::exec::compute::{self, Job};
use super::exec::render::{self, RenderPass};
use super::isa::machine::{Fault, Memory};
use super::ring::Shared;
use crate::platform::dma::DmaError;
use alloc::vec::Vec;

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

/// Complete `command`: write its stamp value to the firmware and driver
/// stamps, then return the Flag event for its stamp index. The caller posts
/// the event and sends the 0x42 message, exactly as for a signal command.
pub fn complete(memory: &mut dyn Shared, command: &Command) -> Result<Vec<Event>, &'static str> {
    let stamp = command.stamp(memory)?;
    write_stamps(memory, &stamp)?;
    Ok(alloc::vec![Event::Flag(1 << stamp.index)])
}

fn write_stamps(memory: &mut dyn Shared, stamp: &Stamp) -> Result<(), &'static str> {
    memory.write(stamp.firmware, &stamp.value.to_le_bytes())?;
    memory.write(stamp.driver, &stamp.value.to_le_bytes())
}

/// Run a decoded compute job in `context` and complete `command`.
pub fn run_compute(
    memory: &mut dyn Shared,
    command: &Command,
    context: usize,
    job: &Job,
) -> Result<Vec<Event>, WorkError> {
    {
        let mut view = GpuView::new(memory, context);
        compute::run(&mut view, job)?;
    }
    complete(memory, command).map_err(WorkError::Refused)
}

/// Run a decoded render pass in `context` and complete `command`.
pub fn run_render(
    memory: &mut dyn Shared,
    command: &Command,
    context: usize,
    pass: &RenderPass,
) -> Result<Vec<Event>, WorkError> {
    {
        let mut view = GpuView::new(memory, context);
        render::run(&mut view, pass)?;
    }
    complete(memory, command).map_err(WorkError::Refused)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::agx::channel::{Command, Kind};
    use crate::platform::apple::agx::ring::tests::Flat;

    // A low GPU VA: the USC uniform and texture words pack an address into a
    // bounded field, so the engine's own stream tests use a low base too.
    const BASE: u64 = 0x1_0000_0000;
    const COMMAND: u64 = BASE;

    /// A CL command for stamp 4 (value 0x900) whose firmware and driver
    /// stamps sit at the engine-recovered CL offset (0x2a8).
    fn cl_command(memory: &mut Flat) -> Command {
        memory.put_u32(COMMAND, 3);
        memory.put_u64(COMMAND + 0x2a8 - 0x10, COMMAND + 0x40); // driver
        memory.put_u64(COMMAND + 0x2a8 - 0x8, COMMAND + 0x48); // firmware
        memory.put_u32(COMMAND + 0x2a8, 0x900); // value
        memory.put_u32(COMMAND + 0x2a8 + 4, 4); // index
        Command::read(memory, COMMAND).unwrap()
    }

    #[test]
    fn completion_writes_both_stamps_and_posts_one_flag() {
        let mut memory = Flat::new(BASE, 0x1000);
        let command = cl_command(&mut memory);
        let events = complete(&mut memory, &command).unwrap();
        assert_eq!(events, [Event::Flag(1 << 4)]);
        assert_eq!(memory.read_u32(COMMAND + 0x40), Ok(0x900));
        assert_eq!(memory.read_u32(COMMAND + 0x48), Ok(0x900));
        // A command type that carries no stamp cannot complete this way.
        memory.put_u32(COMMAND, 4);
        let barrier = Command::read(&mut memory, COMMAND).unwrap();
        assert_eq!(barrier.kind, Kind::Barrier);
        assert!(complete(&mut memory, &barrier).is_err());
    }

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

    #[test]
    fn a_compute_job_runs_in_its_context_and_completes_the_command() {
        let (mut memory, job) = compute_memory();
        let command = cl_command(&mut memory);
        let events = run_compute(&mut memory, &command, 5, &job).unwrap();
        assert_eq!(events, [Event::Flag(1 << 4)]);
        // The four grid threads wrote their index to the output buffer.
        for i in 0..4 {
            assert_eq!(memory.read_u32(BASE + 0x1000 + 4 * i), Ok(i as u32));
        }
        // The command's stamps completed.
        assert_eq!(memory.read_u32(COMMAND + 0x40), Ok(0x900));
    }

    #[test]
    fn a_faulting_stream_refuses_and_leaves_the_stamps_untouched() {
        let mut memory = Flat::new(BASE, 0x8000);
        let command = cl_command(&mut memory);
        // A CDM stream pointer into unmapped memory: the walk faults.
        let job = Job {
            stream: BASE + 0x7000,
            usc_base: BASE,
            vm_slot: 5,
        };
        // The engine refuses (a stream that does not terminate within the
        // flat memory); the stamps stay at zero.
        assert!(run_compute(&mut memory, &command, 5, &job).is_err());
        assert_eq!(memory.read_u32(COMMAND + 0x40), Ok(0));
    }
}
