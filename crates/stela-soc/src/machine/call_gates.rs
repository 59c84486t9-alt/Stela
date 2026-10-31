//! The StelaGPU call gate's placement on the board.

use super::*;
use alloc::sync::Arc;

impl AppleDevices {
    /// StelaGPU's call gate over `service`, its window at `physical` and
    /// its completion interrupt at `irq`.
    pub fn add_gpu_gate(
        &mut self,
        physical: u64,
        irq: AicInput,
        service: Arc<dyn stela_contracts::gate::GateService>,
    ) -> Result<(), String> {
        if self.gpu_gate.is_some() {
            return Err("the board has one StelaGPU gate".into());
        }
        let device = self.bus.add(Box::new(gpu_gate::Gate::new(service, irq)));
        self.bus
            .map(device, physical, stela_contracts::gate::window::BYTES, 0)
            .map_err(|error| format!("StelaGPU gate placement: {error:?}"))?;
        self.gpu_gate = Some(device);
        Ok(())
    }
}
