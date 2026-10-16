//! Host services are separate from canonical runtime resources.
//! Freestanding code requires ring 0, aborting panic and a real loader heap.
//! No service below supplies guest CPU, source or execution admission.
pub(crate) mod cpu;
pub(crate) mod memory;
pub(crate) mod sync;
pub(crate) mod unwind;
