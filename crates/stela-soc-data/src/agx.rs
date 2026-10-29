//! Immutable AGX family and register-interface descriptions.
//! No firmware execution, mapping ownership or native GPU engine admission.
pub mod generation;
pub mod registers;
pub mod uat;
/// A GPU's identification registers ([`generation`] states each
/// SoC's values and their sources).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Identity {
    pub generation: u8,
    pub variant: u8,
    pub revision: u8,
    /// Dies the clusters span; only [`generation::Identification::Dies`] reports them.
    pub dies: u8,
    /// Clusters over every die.
    pub clusters: u8,
    pub cores: u8,
    pub frags: u8,
    pub gps: u8,
    /// Enabled cores, cluster 0 first, packed `cores` bits per cluster, one
    /// word per core-mask register of the family.
    pub core_mask: [u32; 3],
}

use generation::Identification;
impl Identity {
    pub fn version(&self) -> u32 {
        u32::from(self.generation) << 24
            | u32::from(self.variant) << 16
            | u32::from(self.revision) << 8
    }
    pub fn counts_1(&self, identification: Identification) -> u32 {
        let middle = match identification {
            Identification::Clusters => u32::from(self.frags) << 8,
            Identification::Dies => {
                u32::from(self.dies) << 16 | u32::from(self.clusters / self.dies) << 8
            }
        };
        middle | u32::from(self.cores)
    }
    pub fn counts_2(&self) -> u32 {
        u32::from(self.gps) << 16
    }
    pub fn clusters(&self, identification: Identification) -> u32 {
        match identification {
            Identification::Clusters => u32::from(self.clusters) << 12,
            Identification::Dies => 0,
        }
    }
}
