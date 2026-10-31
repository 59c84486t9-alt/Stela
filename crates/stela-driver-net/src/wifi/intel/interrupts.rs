// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2005-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
//! One MSI-X vector for every cause, as `iwl_pcie_conf_msix_hw` maps them on
//! a function that shares its first vector between its fallback receive queue
//! and everything else. A shared vector's causes stay set until the host
//! clears them.
use super::{
    firmware::Family,
    power::{AccessError, Csr},
};
use alloc::vec::Vec;

pub const FH_CAUSES: u32 = 0x2800;
pub const FH_MASK: u32 = 0x2804;
pub const HW_CAUSES: u32 = 0x2808;
pub const HW_MASK: u32 = 0x280c;
pub const AUTOMASK: u32 = 0x2810;
const RX_IVAR: u32 = 0x2880;
const IVAR: u32 = 0x2890;
pub const UREG_CHICK: u32 = 0xa05c00;
pub const MSIX_ENABLE: u32 = 1 << 25;
/// `MSIX_NON_AUTO_CLEAR_CAUSE` on vector 0.
pub const SHARED: u8 = 1 << 7;
const QUEUE_0: u32 = 1;
/// `causes_list_common`'s FH bits: both D2S channels, S2D and FH_ERR.
const FH: [u32; 4] = [16, 17, 19, 21];
/// Its HW bits: ALIVE, WAKEUP, RESET_DONE, TOP_FATAL_ERR, CT_KILL, RF_KILL,
/// PERIODIC, SCD, FH_TX, HW_ERR and HAP.
const HW: [u32; 11] = [0, 1, 2, 3, 6, 7, 8, 26, 27, 29, 30];
const SW_ERR: u32 = 25;
const SW_ERR_BZ: u32 = 5;
const ALIVE: u32 = 0;
const TOP_FATAL_ERR: u32 = 3;
const HW_ERR: u32 = 29;
const FH_ERR: u32 = 21;
const INT: u32 = 8;
/// `CSR_INT`'s firmware and hardware error bits.
pub const INT_SW_ERR: u32 = 1 << 25;
pub const INT_HW_ERR: u32 = 1 << 29;

fn sw_err(family: Family) -> u32 {
    if family >= Family::Bz {
        SW_ERR_BZ
    } else {
        SW_ERR
    }
}

/// `iwl_pcie_irq_msix_handler`'s and `iwl_pcie_irq_handler`'s look for errors,
/// ahead of the look at the rings: clear what fired the vector and let it fire
/// again, so nothing arriving after that look goes unsignalled. Whether the
/// firmware or NIC died.
pub fn acknowledge(io: &mut impl Csr, family: Family, vector: bool) -> Result<bool, AccessError> {
    let fatal = io.read32(INT)? & (INT_SW_ERR | INT_HW_ERR);
    if fatal != 0 {
        io.write32(INT, fatal)?;
    }
    if !vector {
        return Ok(fatal != 0);
    }
    let causes = take(io, family)?;
    io.write32(AUTOMASK, 1)?;
    Ok(fatal != 0 || causes & (INT_SW_ERR | INT_HW_ERR) != 0)
}

/// Clear the causes of a function in MSI-X mode, which reports through them
/// rather than `CSR_INT`, as `iwl_pcie_irq_msix_handler` reads them: what they
/// held in `CSR_INT`'s bits.
pub fn take(io: &mut impl Csr, family: Family) -> Result<u32, AccessError> {
    let fh = io.read32(FH_CAUSES)?;
    io.write32(FH_CAUSES, fh)?;
    let hw = io.read32(HW_CAUSES)?;
    io.write32(HW_CAUSES, hw)?;
    let mut causes = hw & 1 << ALIVE;
    if hw & 1 << sw_err(family) != 0 {
        causes |= INT_SW_ERR;
    }
    if fh & 1 << FH_ERR != 0 || hw & (1 << HW_ERR | 1 << TOP_FATAL_ERR) != 0 {
        causes |= INT_HW_ERR;
    }
    Ok(causes)
}

/// What a family's causes need of the MSI-X registers.
#[derive(Debug, PartialEq, Eq)]
pub struct Routes {
    /// Each byte-wide IVAR register a cause's vector goes in.
    pub ivars: Vec<u32>,
    pub fh_mask: u32,
    pub hw_mask: u32,
}

pub fn routes(family: Family) -> Routes {
    let hw = HW.iter().copied().chain([sw_err(family)]);
    let mut ivars = Vec::from([RX_IVAR]);
    // IWL_CAUSE: an FH cause's IVAR is its bit less 16, an HW one's plus 16.
    ivars.extend(FH.iter().map(|bit| IVAR + bit - 16));
    ivars.extend(hw.clone().map(|bit| IVAR + bit + 16));
    let mask = |bits: u32, causes: &mut dyn Iterator<Item = u32>| {
        !causes.fold(bits, |mask, bit| mask | 1 << bit)
    };
    Routes {
        ivars,
        fh_mask: mask(QUEUE_0, &mut FH.iter().copied()),
        hw_mask: mask(0, &mut hw.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;

    impl Csr for BTreeMap<u32, u32> {
        fn read32(&mut self, register: u32) -> Result<u32, AccessError> {
            Ok(self.get(&register).copied().unwrap_or(0))
        }
        fn write32(&mut self, register: u32, value: u32) -> Result<(), AccessError> {
            let held = self.entry(register).or_default();
            *held &= !value;
            Ok(())
        }
        fn delay_us(&mut self, _: u32) -> Result<(), AccessError> {
            Ok(())
        }
    }

    #[test]
    fn only_an_error_ends_the_firmware_and_a_vector_fires_again() {
        let mut io = BTreeMap::from([(INT, 1 | INT_SW_ERR), (AUTOMASK, 1)]);
        assert!(acknowledge(&mut io, Family::Ax200, false).unwrap());
        assert_eq!((io[&INT], io[&AUTOMASK]), (1, 1));
        assert!(!acknowledge(&mut io, Family::Ax200, false).unwrap());
        io.insert(FH_CAUSES, 1 << 21);
        assert!(acknowledge(&mut io, Family::Ax200, true).unwrap());
        assert_eq!(io[&AUTOMASK], 0, "the model clears what is written");
        assert!(!acknowledge(&mut io, Family::Ax200, true).unwrap());
    }

    #[test]
    fn an_msix_function_says_in_its_causes_what_csr_int_would() {
        let take = |family, fh: u32, hw: u32| {
            let mut io = BTreeMap::from([(FH_CAUSES, fh), (HW_CAUSES, hw)]);
            let causes = take(&mut io, family).unwrap();
            assert_eq!((io[&FH_CAUSES], io[&HW_CAUSES]), (0, 0));
            causes
        };
        assert_eq!(take(Family::Ax200, 1, 0x100), 0);
        assert_eq!(take(Family::Ax200, 0, 1), 1);
        assert_eq!(take(Family::Ax210, 0, 1 << 25), INT_SW_ERR);
        assert_eq!(take(Family::Bz, 0, 1 << 5), INT_SW_ERR);
        assert_eq!(take(Family::Ax200, 0, 1 << 5), 0);
        assert_eq!(take(Family::Ax200, 1 << 21, 0), INT_HW_ERR);
        assert_eq!(take(Family::Ax200, 0, 1 << 29), INT_HW_ERR);
        assert_eq!(take(Family::Bz, 0, 1 << 3), INT_HW_ERR);
    }

    #[test]
    fn every_cause_reaches_the_vector_and_a_family_keeps_its_own_firmware_error() {
        let before = routes(Family::Ax210);
        assert_eq!(before.fh_mask, !0x002b_0001);
        assert_eq!(before.hw_mask, !0x6e00_01cf);
        assert_eq!(before.ivars[..2], [0x2880, 0x2890]);
        assert_eq!(before.ivars.last(), Some(&(0x2890 + 41)));
        let bz = routes(Family::Bz);
        assert_eq!(bz.hw_mask, !0x6c00_01ef);
        assert_eq!(bz.ivars.last(), Some(&(0x2890 + 21)));
        assert_eq!(routes(Family::Ax200), before);
    }
}
