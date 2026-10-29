//! Native PMP PTD transport over canonical immutable bank geometry.
pub mod transport;
use stela_soc_data::ptd::MAX_ENTRIES;
#[cfg(test)]
use stela_soc_data::ptd::PTD_BYTES;
use stela_soc_data::ptd::Range;
use stela_soc_data::ptd::UPDATE_OFFSET;
pub use transport::Ptd;
