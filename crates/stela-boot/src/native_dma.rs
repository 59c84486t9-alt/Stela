//! Native IOMMU backends. Discovery/ownership must supply a qualified unit;
//! there is no identity-mapping substitute for an unavailable domain.
pub(crate) mod diagnostic;
pub mod dmar;
pub mod vtd;
