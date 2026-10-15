//! Current ORIGINAL bank/source storage validation for the exact EL1 B cohort.
//! No independent bank, caller snapshot, CPU permit or native call is created.
use super::TranslationControls;
use crate::blocks::InstalledEl1SourceScope;

impl TranslationControls {
    pub(crate) fn validate_installed_el1_source(
        &self,
        scope: &InstalledEl1SourceScope<'_>,
    ) -> Result<(), &'static str> {
        if self.poisoned {
            return Err("EL1 control owner is poisoned");
        }
        let installed = scope.installed_snapshot();
        if !std::sync::Arc::ptr_eq(&self.memory, scope.physical_space().memory_system()) {
            return Err("EL1 controls and physical source have different MemorySystem owners");
        }
        if !std::sync::Arc::ptr_eq(&self.identity, &installed.identity)
            || self.generation != installed.generation()
            || self.profile.cpu != scope.installed_cpu()
            || self.readbacks != installed.readbacks()
            || self.profile.consumers(self.readbacks) != installed.consumer_inputs()
            || self.profile.facts != installed.feature_facts()
            || self.profile.provenance != installed.policy_provenance()
        {
            return Err("EL1 installed context differs from the actual control owner");
        }
        Ok(())
    }
}
