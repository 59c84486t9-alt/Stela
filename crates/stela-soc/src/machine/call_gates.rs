//! The StelaGPU call gates' placement on the board: one for each GPU.

use super::*;
use alloc::sync::Arc;

impl AppleDevices {
    /// A StelaGPU call gate over `service`, its window at `physical` and
    /// its completion interrupt at `irq`.
    pub fn add_gpu_gate(
        &mut self,
        physical: u64,
        irq: AicInput,
        service: Arc<dyn stela_contracts::gate::GateService>,
    ) -> Result<(), String> {
        let window = self.gpu_gates.len();
        let device = self
            .bus
            .add(Box::new(gpu_gate::Gate::new(window, service, irq)));
        self.bus
            .map(device, physical, stela_contracts::gate::window::BYTES, 0)
            .map_err(|error| format!("StelaGPU gate placement: {error:?}"))?;
        self.gpu_gates.push(device);
        Ok(())
    }
}
