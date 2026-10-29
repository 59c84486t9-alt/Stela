//! ANS debug-service configuration (admin opcode 0xc2, no DMA).
//!
//! The AP builders at kernel file 0x3dec424/0x3dec458 put read/write (0/1)
//! in CDW12, selector in CDW13 and a write value in CDW14. SetNANDDebug
//! (0x3dfc174) splits its diagnostic mask across selectors 0xb00/0xb01.
//! Firmware's setter (VA 0x16fb6c) merges the selected half of its mask.
//! Stela admits the canonical builder encoding only: firmware tests just
//! CDW12 bit 0 (0x16d128..0x16d134) and ignores CDW14 on reads. Refusing
//! other operation bits or a nonzero read value is conservative admission,
//! not a recovered firmware Invalid Field response.
//! Only bit 0 is admitted: it enables extra NAND register/error diagnostics
//! (0x32fa4), which this die has no physical NAND failures to produce.
//! Other bits change timeout/error handling and debug capture, so mere
//! retention would discard effects. Stela keeps the supported diagnostic
//! control across controller resets, until the die is recreated.
use crate::Result;
use stela_contracts::refuse;

pub(super) const READ: u32 = 0;
pub(super) const WRITE: u32 = 1;
const NAND_DEBUG_LOW: u32 = 0xb00;
const NAND_DEBUG_HIGH: u32 = 0xb01;
const NAND_ERROR_DIAGNOSTICS: u32 = 1;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Reply {
    Value(u32),
    InvalidField,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct DebugService {
    mask: [u32; 2],
}

impl DebugService {
    pub fn execute(&mut self, operation: u32, selector: u32, value: u32) -> Result<Reply> {
        if !matches!(operation, READ | WRITE) || (operation == READ && value != 0) {
            return Err(refuse!(
                "ANS debug-service operation or read value is unsupported"
            ));
        }
        let (word, supported) = match selector {
            NAND_DEBUG_LOW => (&mut self.mask[0], NAND_ERROR_DIAGNOSTICS),
            NAND_DEBUG_HIGH => (&mut self.mask[1], 0),
            // Both original ANS/rANS reject these selectors: 0x16f068
            // reaches the completion's Invalid Field status at 0x16f090.
            0x100 | 0x301 | 0xb20 | 0xb21 => return Ok(Reply::InvalidField),
            0x300 => {
                return Err(refuse!(
                    "ANS power gating timeout debug selector is not modeled"
                ));
            }
            0x600 => {
                return Err(refuse!(
                    "ANS I/O log level debug selector (0x600) is not modeled"
                ));
            }
            // Firmware's lane query returns zero at 0x16f9a8; a write
            // takes Invalid Field at 0x16dc08..0x16dc30.
            0xa20 => {
                return Ok(if operation == READ {
                    Reply::Value(0)
                } else {
                    Reply::InvalidField
                });
            }
            _ => return Err(refuse!("ANS debug-service selector is not modeled")),
        };
        if operation == WRITE {
            if value & !supported != 0 {
                return Err(refuse!(
                    "ANS NAND debug flags require unmodeled timeout or capture effects"
                ));
            }
            *word = value;
            Ok(Reply::Value(0))
        } else {
            Ok(Reply::Value(*word))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_mask_words_are_independent_and_refusals_preserve_them() {
        let mut service = DebugService::default();
        for selector in [NAND_DEBUG_LOW, NAND_DEBUG_HIGH] {
            assert_eq!(service.execute(READ, selector, 0), Ok(Reply::Value(0)));
        }
        assert_eq!(
            service.execute(WRITE, NAND_DEBUG_LOW, NAND_ERROR_DIAGNOSTICS),
            Ok(Reply::Value(0))
        );
        assert_eq!(
            service.execute(WRITE, NAND_DEBUG_HIGH, 0),
            Ok(Reply::Value(0))
        );
        for selector in [0, 0xaff, 0xb02, u32::MAX] {
            for operation in [READ, WRITE] {
                assert!(service.execute(operation, selector, 0).is_err());
            }
        }
        assert!(service.execute(2, NAND_DEBUG_LOW, 0).is_err());
        assert!(service.execute(READ, NAND_DEBUG_LOW, 1).is_err());
        for bit in 1..32 {
            assert!(service.execute(WRITE, NAND_DEBUG_LOW, 1 << bit).is_err());
        }
        for bit in 0..32 {
            assert!(service.execute(WRITE, NAND_DEBUG_HIGH, 1 << bit).is_err());
        }
        assert_eq!(
            service.execute(READ, NAND_DEBUG_LOW, 0),
            Ok(Reply::Value(NAND_ERROR_DIAGNOSTICS))
        );
        assert_eq!(
            service.execute(READ, NAND_DEBUG_HIGH, 0),
            Ok(Reply::Value(0))
        );
        for selector in [0x100, 0x301, 0xb20, 0xb21] {
            for operation in [READ, WRITE] {
                assert_eq!(
                    service.execute(operation, selector, 0),
                    Ok(Reply::InvalidField)
                );
            }
        }
        assert_eq!(service.execute(READ, 0xa20, 0), Ok(Reply::Value(0)));
        assert_eq!(service.execute(WRITE, 0xa20, 0), Ok(Reply::InvalidField));
    }
}
