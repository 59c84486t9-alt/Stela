//! Counter reads (MRS CNT*) completed on the Active after the native System
//! carrier, context restoration and finalizer have ended.
use super::*;
const ZERO_REGISTER: u8 = 31;

impl<B: provider::Owner> Active<'_, '_, B> {
    pub(in crate::blocks::retirement::checked) fn complete_hosted_counter(
        &mut self,
        bound: &BoundSource<'_>,
        instruction: SystemInstruction,
    ) -> anyhow::Result<WaitStep> {
        anyhow::ensure!(
            self.pe.authority.system_attempt(self.attempt),
            "counter requires SystemActive"
        );
        anyhow::ensure!(
            self.pe.thread.pc == instruction.instruction_pc,
            "counter PC differs"
        );
        let stela_compiler::block::el1_platform::Intent::System(original) =
            bound.el1_platform_intent()?
        else {
            anyhow::bail!("source has no System counter terminal");
        };
        anyhow::ensure!(original == instruction, "counter differs from bound source");
        let stage = self.pe.backend.prepare_hosted_counter(
            bound,
            instruction,
            self.pe.system,
            self.outer
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("counter outer missing"))?,
        )?;
        anyhow::ensure!(
            stage.instruction() == instruction,
            "staged counter source differs"
        );
        self.pe.backend.qualify(
            bound,
            self.pe.system,
            &mut self.pe.thread.registers,
            self.outer
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("counter recheck outer missing"))?,
        )?;
        self.pe
            .authority
            .start_retirement(&ConsumerKey(()), self.attempt)
            .map_err(|()| anyhow::anyhow!("counter retirement authority failed"))?;
        // The register and PC stores cannot fail and happen together. An XZR
        // destination still performed the counter read above.
        if stage.destination() != ZERO_REGISTER {
            self.pe.thread.registers.x[usize::from(stage.destination())] = stage.value();
        }
        self.pe.thread.pc = instruction.next_pc;
        self.pe.backend.post_retirement(
            bound,
            self.pe.system,
            &mut self.pe.thread.registers,
            self.outer
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("counter retirement outer missing"))?,
        )?;
        self.finish_retirement(false)?;
        Ok(self.retired_wait_step(instruction))
    }
}
