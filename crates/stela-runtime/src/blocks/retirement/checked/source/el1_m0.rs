//! Actual consumed source-plan intent for the generic retained EL1 route.
//! None memory metadata is accepted only together with this exact typed plan.
use super::BoundSource;
use stela_compiler::{
    block::{BlockProfile, el1_m0::Intent},
    context::memory::profile_requirements,
};

impl BoundSource<'_> {
    pub(in crate::blocks::retirement::checked) fn el1_m0_intent(&self) -> anyhow::Result<Intent> {
        if self.runtime.profile() == BlockProfile::El1PlatformV1 {
            return match self.el1_platform_intent()? {
                stela_compiler::block::el1_platform::Intent::Registers => Ok(Intent::Registers),
                stela_compiler::block::el1_platform::Intent::LiteralRead64(read) => {
                    Ok(Intent::LiteralRead64(read))
                }
                stela_compiler::block::el1_platform::Intent::ScalarLoad(_)
                | stela_compiler::block::el1_platform::Intent::System(_)
                | stela_compiler::block::el1_platform::Intent::Write64Pair(_)
                | stela_compiler::block::el1_platform::Intent::Read64Pair(_) => {
                    anyhow::bail!("source has no legacy M0 read intent")
                }
            };
        }
        anyhow::ensure!(
            self.runtime.profile() == BlockProfile::El1M0IntegerV1,
            "actual source is not the typed EL1 integer profile"
        );
        let intent = self
            .el1_m0
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
            BlockProfile::El1PlatformV1 => anyhow::ensure!(
                self.el1_platform_intent()?
                    == stela_compiler::block::el1_platform::Intent::Registers,
                "EL1 register consumer cannot apply System or memory effects"
            ),
            BlockProfile::El1M0IntegerV1 => anyhow::ensure!(
                self.el1_m0_intent()? == Intent::Registers,
                "EL1 register consumer cannot read memory"
            ),
            _ => anyhow::bail!("actual source is not a typed EL1 register profile"),
        }
        Ok(())
    }
}

impl BoundSource<'_> {
    pub(in crate::blocks::retirement::checked) fn el1_platform_intent(
        &self,
    ) -> anyhow::Result<stela_compiler::block::el1_platform::Intent> {
        anyhow::ensure!(
            self.runtime.profile() == BlockProfile::El1PlatformV1,
            "source is not the actual mixed platform profile"
        );
        self.el1_platform
            .ok_or_else(|| anyhow::anyhow!("mixed EL1 source intent absent"))
    }
    pub(in crate::blocks::retirement::checked) fn el1_carrier_intent(
        &self,
    ) -> anyhow::Result<Option<stela_compiler::block::SystemInstruction>> {
        if self.runtime.profile() == BlockProfile::El1PlatformV1 {
            anyhow::ensure!(
                self.requirements.is_none(),
                "effect-free native carrier cannot access memory"
            );
            return match self.el1_platform_intent()? {
                stela_compiler::block::el1_platform::Intent::Registers => Ok(None),
                stela_compiler::block::el1_platform::Intent::System(instruction) => {
                    Ok(Some(instruction))
                }
                _ => anyhow::bail!("memory source is not an effect-free native carrier"),
            };
        }
        self.el1_register_intent()?;
        Ok(None)
    }
}
