//! Actual consumed source-plan intent for the generic retained EL1 route.
//! None memory metadata is accepted only together with this exact typed plan.
use super::BoundSource;
use stela_compiler::{
    block::{BlockProfile, CompilationPlan, el1_m0::Intent},
    context::memory::profile_requirements,
};

impl BoundSource<'_> {
    pub(in crate::blocks::retirement::checked) fn el1_m0_intent(&self) -> anyhow::Result<Intent> {
        self.recheck()?;
        anyhow::ensure!(
            self.runtime.profile() == BlockProfile::El1M0IntegerV1,
            "actual source is not the typed EL1 integer profile"
        );
        let plan = CompilationPlan::new(
            self.source,
            self.entry.entry(),
            self.runtime.profile(),
            self.runtime.target_cpu(),
        )?;
        anyhow::ensure!(
            plan.source_bytes() == self.source.len()
                && plan.memory_requirements() == self.requirements,
            "actual EL1 consumed source/requirements changed"
        );
        let intent = plan
            .el1_m0_intent()
            .ok_or_else(|| anyhow::anyhow!("actual typed EL1 intent absent"))?;
        match intent {
            Intent::Registers => anyhow::ensure!(
                self.requirements.is_none(),
                "register-only EL1 source unexpectedly requires memory"
            ),
            Intent::LiteralRead64(read) => {
                let requirements = self.memory_requirements()?;
                anyhow::ensure!(
                    self.source.len() == size_of::<u32>()
                        && read.source_pc == self.entry.entry()
                        && requirements.required_profile
                            == profile_requirements::M0_DEVICE_RAM_READ64
                        && requirements.required_flags == 0
                        && requirements.required_host_caps == 0,
                    "literal source/quantity association differs"
                );
            }
        }
        Ok(intent)
    }
}

impl BoundSource<'_> {
    pub(in crate::blocks::retirement::checked) fn el1_register_intent(&self) -> anyhow::Result<()> {
        match self.runtime.profile() {
            BlockProfile::El1DirectBranchV1 => {
                self.direct_branch_target()?;
            }
            BlockProfile::El1M0IntegerV1 => anyhow::ensure!(
                self.el1_m0_intent()? == Intent::Registers,
                "EL1 register consumer cannot read memory"
            ),
            _ => anyhow::bail!("actual source is not a typed EL1 register profile"),
        }
        Ok(())
    }
}
