//! What a dead firmware says of why: `iwl_fwrt_dump_error_logs`, read from the
//! tables its ALIVE named.

use super::{
    boot::AliveReport,
    firmware::Family,
    power::{self, Csr, Error},
};
use alloc::{format, string::String, vec::Vec};

/// `FW_ADDR_CACHE_CONTROL`: the bits of an address that do not locate it.
const CACHE_CONTROL: u32 = 0xc000_0000;
/// `FW_SYSASSERT_CPU_MASK`: which processor asserted, not what.
const CPU: u32 = 0xf000_0000;
/// The words of `iwl_error_event_table` and `iwl_umac_error_event_table`.
const LMAC_WORDS: usize = 38;
const UMAC_WORDS: usize = 15;

/// `iwl_fw_lookup_assert_desc`.
fn describe(error: u32) -> &'static str {
    match error & !CPU {
        0x34 => "NMI_INTERRUPT_WDG",
        0x35 => "SYSASSERT",
        0x37 => "UCODE_VERSION_MISMATCH",
        0x38 | 0x39 => "BAD_COMMAND",
        0x3c => "NMI_INTERRUPT_DATA_ACTION_PT",
        0x3d => "FATAL_ERROR",
        0x46 => "NMI_TRM_HW_ERR",
        0x4c => "NMI_INTERRUPT_TRM",
        0x54 => "NMI_INTERRUPT_BREAK_POINT",
        0x5c => "NMI_INTERRUPT_WDG_RXF_FULL",
        0x64 => "NMI_INTERRUPT_WDG_NO_RBD_RXF_FULL",
        0x66 => "NMI_INTERRUPT_HOST",
        0x70 => "NMI_INTERRUPT_LMAC_FATAL",
        0x71 => "NMI_INTERRUPT_UMAC_FATAL",
        0x73 => "NMI_INTERRUPT_OTHER_LMAC_FATAL",
        0x7c => "NMI_INTERRUPT_ACTION_PT",
        0x84 => "NMI_INTERRUPT_UNKNOWN",
        0x86 => "NMI_INTERRUPT_INST_ACTION_PT",
        0x88 => "NMI_INTERRUPT_PREG",
        0x0010_070d => "PNVM_MISSING",
        _ => "ADVANCED_SYSASSERT",
    }
}

/// Where one firmware keeps its logs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Tables {
    lmac: [u32; 2],
    umac: u32,
}

impl Tables {
    fn new(lmac: [u32; 2], umac: u32) -> Self {
        Self {
            lmac,
            umac: umac & !CACHE_CONTROL,
        }
    }

    pub fn of(alive: &AliveReport) -> Self {
        Self::new(
            alive.lmac.map(|lmac| lmac.debug_addresses[0]),
            alive.umac.debug_addresses[0],
        )
    }

    /// What the logs hold, in one line. A device too far gone to answer says
    /// so in place of its logs, and Linux's reset to read them anyway is left
    /// to the restart that follows: the logs do not survive either.
    pub fn read<C: Csr + Clone>(self, io: &C, family: Family) -> String {
        match self.logs(io, family) {
            Ok(logs) if logs.is_empty() => String::from("no error log"),
            Ok(logs) => logs.join("; "),
            Err(error) => format!("error log unreadable: {error:?}"),
        }
    }

    fn logs<C: Csr + Clone>(self, io: &C, family: Family) -> Result<Vec<String>, Error> {
        let mut logs = Vec::new();
        for (cpu, base) in self.lmac.into_iter().enumerate() {
            if base != 0 {
                let table = power::read_memory::<C, LMAC_WORDS>(io.clone(), family, base)?;
                logs.extend(lmac(cpu, &table));
            }
        }
        if self.umac != 0 {
            let table = power::read_memory::<C, UMAC_WORDS>(io.clone(), family, self.umac)?;
            logs.extend(umac(&table));
        }
        Ok(logs)
    }
}

/// `iwl_fwrt_dump_lmac_error_log`, for a table that holds an entry.
fn lmac(cpu: usize, table: &[u32; LMAC_WORDS]) -> Option<String> {
    if power::is_hardware_error(table[0]) {
        return Some(format!("lmac{cpu} reads {:#010x}", table[0]));
    }
    (table[0] != 0).then(|| {
        format!(
            "lmac{cpu} {} {:#010x} at {:#x} blink2 {:#x} ilink {:#x} {:#x} \
             data {:#x} {:#x} {:#x} host command {:#x} last {:#x} firmware {}.{}",
            describe(table[1]),
            table[1],
            table[20],
            table[4],
            table[5],
            table[6],
            table[7],
            table[8],
            table[9],
            table[23],
            table[29],
            table[16],
            table[17],
        )
    })
}

/// `iwl_fwrt_dump_umac_error_log`, likewise.
fn umac(table: &[u32; UMAC_WORDS]) -> Option<String> {
    if power::is_hardware_error(table[0]) {
        return Some(format!("umac reads {:#010x}", table[0]));
    }
    (table[0] != 0).then(|| {
        format!(
            "umac {} {:#010x} blink {:#x} {:#x} ilink {:#x} {:#x} data {:#x} {:#x} {:#x} \
             host command {:#x} firmware {}.{}",
            describe(table[1]),
            table[1],
            table[2],
            table[3],
            table[4],
            table[5],
            table[6],
            table[7],
            table[8],
            table[13],
            table[9],
            table[10],
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wifi::intel::power::AccessError;
    use alloc::{collections::BTreeMap, rc::Rc};
    use core::cell::RefCell;

    /// Device memory behind `HBUS_TARG_MEM_RADDR`, with the MAC always awake.
    #[derive(Clone, Default)]
    struct Sram(Rc<RefCell<(BTreeMap<u32, u32>, u32)>>);

    impl Sram {
        fn holding(words: &[(u32, u32)]) -> Self {
            let sram = Self::default();
            sram.0.borrow_mut().0.extend(words.iter().copied());
            sram
        }
    }

    impl Csr for Sram {
        fn read32(&mut self, register: u32) -> Result<u32, AccessError> {
            let (memory, cursor) = &mut *self.0.borrow_mut();
            Ok(match register {
                0x24 => 1,
                0x41c => {
                    *cursor += 4;
                    memory.get(&(*cursor - 4)).copied().unwrap_or(0)
                }
                _ => 0,
            })
        }
        fn write32(&mut self, register: u32, value: u32) -> Result<(), AccessError> {
            if register == 0x40c {
                self.0.borrow_mut().1 = value;
            }
            Ok(())
        }
        fn delay_us(&mut self, _: u32) -> Result<(), AccessError> {
            Ok(())
        }
    }

    #[test]
    fn a_dead_firmware_s_tables_name_the_assert_of_each_processor() {
        let sram = Sram::holding(&[
            (0x1000, 1),
            (0x1004, 0x2000_0035),
            (0x1000 + 7 * 4, 0xabc),
            (0x1000 + 20 * 4, 0x4242),
            (0x2000, 1),
            (0x2004, 0x0010_070d),
            (0x2000 + 13 * 4, 0x77),
        ]);
        let tables = Tables::new([0x1000, 0], 0xc000_2000);
        let log = tables.read(&sram, Family::Ax210);
        assert!(
            log.starts_with("lmac0 SYSASSERT 0x20000035 at 0x4242"),
            "{log}"
        );
        assert!(log.contains("data 0xabc 0x0 0x0"), "{log}");
        assert!(log.contains("; umac PNVM_MISSING 0x0010070d"), "{log}");
        assert!(log.contains("host command 0x77 firmware 0.0"), "{log}");
    }

    #[test]
    fn empty_tables_say_so_and_a_gone_device_is_not_read_as_a_log() {
        let tables = Tables::new([0x1000, 0], 0x2000);
        assert_eq!(tables.read(&Sram::default(), Family::Ax210), "no error log");
        assert_eq!(
            Tables::default().read(&Sram::default(), Family::Ax210),
            "no error log"
        );
        let sram = Sram::holding(&[(0x1000, 0xa5a5_a5a2)]);
        let log = tables.read(&sram, Family::Ax210);
        assert_eq!(log, "lmac0 reads 0xa5a5a5a2");
    }
}
