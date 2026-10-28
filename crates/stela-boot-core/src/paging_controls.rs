//! Controls Stela must establish rather than inherit from UEFI.

const CR0_MONITOR_FPU: u64 = 1 << 1;
const CR0_EMULATE_FPU: u64 = 1 << 2;
const CR0_TASK_SWITCHED: u64 = 1 << 3;
const CR0_NATIVE_EXCEPTIONS: u64 = 1 << 5;
const CR0_WRITE_PROTECT: u64 = 1 << 16;

pub const fn native_cr0(firmware: u64) -> u64 {
    // Intel SDM Vol. 3A, CR0.NE: deliver native x87 exceptions through #MF,
    // not the legacy external FERR#/IGNNE# interface. The canonical runtime
    // requires this on the BSP just as the owned AP bootstrap does.
    (firmware | CR0_MONITOR_FPU | CR0_NATIVE_EXCEPTIONS | CR0_WRITE_PROTECT)
        & !(CR0_EMULATE_FPU | CR0_TASK_SWITCHED)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_firmware_exception_mode_gets_the_same_native_floor_as_aps() {
        // Paging/protected mode are already live. UEFI's incoming exception
        // mode and lazy-FPU bits must not decide canonical RAM admission.
        for firmware_fpu in 0..16 {
            let firmware = 0x8000_0011
                | (firmware_fpu & 1) << 1
                | (firmware_fpu & 2) << 1
                | (firmware_fpu & 4) << 1
                | (firmware_fpu & 8) << 2;
            assert_eq!(native_cr0(firmware), 0x8001_0033);
        }
    }

    #[test]
    fn takeover_preserves_other_controls_and_is_idempotent() {
        let owned = CR0_MONITOR_FPU
            | CR0_EMULATE_FPU
            | CR0_TASK_SWITCHED
            | CR0_NATIVE_EXCEPTIONS
            | CR0_WRITE_PROTECT;
        for bit in 0..64 {
            let firmware = 1u64 << bit;
            let native = native_cr0(firmware);
            assert_eq!(native & !owned, firmware & !owned);
            assert_eq!(native_cr0(native), native);
        }
    }
}
