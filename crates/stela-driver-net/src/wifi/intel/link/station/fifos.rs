// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2024-2026 Intel Corporation
//! The transmit FIFOs firmware reports, `iwl_get_shared_mem_conf`, and what
//! they leave an A-MSDU, `iwl_mld_get_amsdu_size_of_tid`.
use super::*;

/// `iwl_shared_mem_cfg`: where `lmac_num` and `lmac_smem` lie.
const LMAC_COUNT: usize = 32;
const FIRST_LMAC: usize = 36;
/// `iwl_shared_mem_lmac_cfg`: its size, and where `txfifo_size` lies.
const LMAC_BYTES: usize = 72;
const SIZES: usize = 4;
/// `TX_FIFO_MAX_NUM`.
const FIFOS: usize = 15;
/// `IWL_LMAC_24G_INDEX` and `IWL_LMAC_5G_INDEX`.
const LMACS: usize = 2;
/// `IWL_UCODE_TLV_CAPA_EXTEND_SHARED_MEM_CFG`.
const EXTENDED: u32 = 80;
/// `IWL_UCODE_TLV_CAPA_CDB_SUPPORT`.
const CDB: u32 = 40;
/// `SHARED_MEM_CFG_CMD` in `SYSTEM_GROUP`, and `SHARED_MEM_CFG`.
const SHARED_MEMORY: command::Id = command::Id {
    group: 2,
    opcode: 0,
    version: 0,
};
const SHARED_MEMORY_LEGACY: command::Id = command::Id {
    group: 0,
    opcode: 0x25,
    version: 0,
};
/// Room for the TX command, its headers and the start of the next frame.
const MARGIN: u32 = 256;
/// `tid_to_mac80211_ac`, as VO, VI, BE and BK count.
const TID_CATEGORY: [usize; 8] = [2, 3, 3, 2, 1, 1, 0, 0];
/// `iwl_mld_mac80211_ac_to_fw_tx_fifo`: EDCA's, then the trigger-based ones.
const CATEGORY_FIFO: [usize; 8] = [3, 2, 1, 0, 7, 6, 5, 4];

/// `smem_cfg`, whose zeros bound nothing, as Linux's unsigned margin reads.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Fifos {
    sizes: [[u32; FIFOS]; LMACS],
    /// `iwl_gen2_tx_fifo` counts the command FIFO first, `iwl_bz_tx_fifo` not.
    command_fifo: usize,
    cdb: bool,
}

impl Fifos {
    /// `iwl_parse_shared_mem_22000`.
    fn parse(raw: &[u8], command_fifo: usize, cdb: bool) -> Option<Self> {
        if raw.len() < FIRST_LMAC + LMACS * LMAC_BYTES {
            return None;
        }
        let word = |at: usize| u32::from_le_bytes(raw[at..at + 4].try_into().unwrap());
        let lmacs = word(LMAC_COUNT) as usize;
        if lmacs > LMACS {
            return None;
        }
        let mut sizes = [[0; FIFOS]; LMACS];
        for (lmac, fifos) in sizes.iter_mut().take(lmacs).enumerate() {
            for (fifo, size) in fifos.iter_mut().enumerate() {
                *size = word(FIRST_LMAC + lmac * LMAC_BYTES + SIZES + fifo * 4);
            }
        }
        Some(Self {
            sizes,
            command_fifo,
            cdb,
        })
    }

    /// `iwl_mld_get_amsdu_size_of_tid`'s bound on `tid`, whose traffic goes to
    /// the trigger-based FIFOs under `he`.
    pub(super) fn amsdu_limit(&self, tid: u8, he: bool, band: Band, multi_link: bool) -> u32 {
        let category = TID_CATEGORY[usize::from(tid & 7)] + if he { 4 } else { 0 };
        let fifo = CATEGORY_FIFO[category] + self.command_fifo;
        let room = |lmac: usize| self.sizes[lmac][fifo].wrapping_sub(MARGIN);
        match (multi_link, self.cdb) {
            (true, true) => room(0).min(room(1)),
            (true, false) => room(0),
            (false, cdb) => room(usize::from(cdb && band != Band::Ghz2)),
        }
    }
}

impl<Q: BootIo, B: BiosIo> Wifi<Q, B> {
    /// `iwl_get_shared_mem_conf`, once for the firmware.
    pub(super) fn read_fifos(&mut self, queue: &mut Queue<Q, B>) {
        if self.client.fifos.is_some() {
            return;
        }
        let id = if queue.firmware().supports_capability(EXTENDED) {
            SHARED_MEMORY
        } else {
            SHARED_MEMORY_LEGACY
        };
        self.client.fifos = Some(Fifos::default());
        self.client.steps.push_back(Step::Command {
            id,
            bytes: Vec::new(),
            then: Then::Fifos,
        });
    }

    pub(super) fn fifos_answered(
        &mut self,
        queue: &mut Queue<Q, B>,
        response: &boot::CommandResponse,
    ) {
        let cdb = queue.firmware().supports_capability(CDB);
        let command_fifo = usize::from(self.family < Family::Bz);
        match Fifos::parse(&response.raw, command_fifo, cdb) {
            Some(fifos) => self.client.fifos = Some(fifos),
            None => self
                .client
                .unsupported("a shared memory answer out of firmware's API"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer(lmacs: u32) -> Vec<u8> {
        let mut raw = vec![0; FIRST_LMAC + 3 * LMAC_BYTES + 8];
        raw[LMAC_COUNT..LMAC_COUNT + 4].copy_from_slice(&lmacs.to_le_bytes());
        for lmac in 0..2 {
            for fifo in 0..FIFOS {
                let at = FIRST_LMAC + lmac * LMAC_BYTES + SIZES + fifo * 4;
                let size = 1000 * (lmac as u32 + 1) + fifo as u32;
                raw[at..at + 4].copy_from_slice(&size.to_le_bytes());
            }
        }
        raw
    }

    #[test]
    fn a_tid_takes_its_categorys_fifo_less_the_margin() {
        let fifos = Fifos::parse(&answer(1), 0, false).unwrap();
        assert_eq!(fifos.amsdu_limit(0, false, Band::Ghz5, false), 1001 - 256);
        assert_eq!(fifos.amsdu_limit(1, false, Band::Ghz5, false), 1000 - 256);
        assert_eq!(fifos.amsdu_limit(5, false, Band::Ghz5, false), 1002 - 256);
        assert_eq!(fifos.amsdu_limit(7, false, Band::Ghz5, false), 1003 - 256);
        assert_eq!(fifos.amsdu_limit(0, true, Band::Ghz5, false), 1005 - 256);
        let counted = Fifos::parse(&answer(1), 1, false).unwrap();
        assert_eq!(counted.amsdu_limit(0, false, Band::Ghz5, false), 1002 - 256);
    }

    #[test]
    fn two_lmacs_serve_by_band_and_bind_a_multi_link_station_together() {
        let fifos = Fifos::parse(&answer(2), 0, true).unwrap();
        assert_eq!(fifos.amsdu_limit(0, false, Band::Ghz2, false), 1001 - 256);
        assert_eq!(fifos.amsdu_limit(0, false, Band::Ghz5, false), 2001 - 256);
        assert_eq!(fifos.amsdu_limit(0, false, Band::Ghz5, true), 1001 - 256);
    }

    #[test]
    fn an_unread_or_impossible_answer_bounds_nothing() {
        assert_eq!(
            Fifos::default().amsdu_limit(0, false, Band::Ghz5, false),
            0u32.wrapping_sub(256)
        );
        assert!(Fifos::parse(&answer(3), 0, false).is_none());
        assert!(Fifos::parse(&[0; 179], 0, false).is_none());
    }
}
