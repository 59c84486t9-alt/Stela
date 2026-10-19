//! The Apple AGX G14G GPU (`sgx`, `gfx-asc`) of the T8112, modeled as a native
//! coprocessor at its AP-facing firmware protocol plus a GPU execution engine.
//! Apple's `armfw_g14g` is not executed. The chosen route, the full 26A434
//! interface inventory and the Known/Inferred/Unknown status are in
//! docs/research/agx.md.
//!
//! Layers, each its own submodule:
//! - [`firmware`]: the GFX RTKit application endpoints (0x20 message, 0x21
//!   doorbell) and the firmware-protocol state (initdata pointer, work and
//!   firmware-control doorbells).
//! - [`sgx`]: the `sgx` register block the AP touches directly (identity,
//!   core mask, GPC controls, the MMU configuration that roots the UAT).
//! - [`uat`]: the GPU address translator (16 KiB pages, three levels, paired
//!   TTBRs per context), its page-table encodings and faults, and the stream
//!   IOMMU the firmware and GPU reach memory through.
//! - [`initdata`]: the initdata root, the objects it names and the ring
//!   directory.
//! - [`ring`]: the shared-memory ring layout (state block, 256 entries,
//!   descriptors) and the firmware's consume.
//! - [`channel`]: a channel's command queue, the commands it names (type,
//!   stream, completion stamp) and the command-stream records.
//! - [`signal`]: the commands that need no GPU work (shared-event and
//!   dashboard signals), run to completion.
//! - [`event`]: the firmware event ring's producer and the entries the kext
//!   reads (Flag, shared-event signal, CLPC notice).
//! - [`isa`]: the AGX2 shader ISA, decoded from tables generated out of
//!   Mesa's `AGX2.xml` and interpreted a SIMD group at a time.
//! - [`format`]: pixel and texture formats.
//! - [`stream`]: the CDM, VDM, PPP and USC control streams.
//! - [`exec`]: the execution engine that runs those streams' work.
//!
//! The requirement matrix and its statuses are docs/research/agx.md §5.

pub mod channel;
pub mod event;
pub mod exec;

pub mod firmware;
pub mod format;
pub mod initdata;
pub mod isa;
pub mod ring;
pub mod sgx;
pub mod signal;
pub mod stream;
pub mod uat;
