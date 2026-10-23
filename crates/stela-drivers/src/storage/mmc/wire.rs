// SPDX-License-Identifier: GPL-2.0-or-later
//! Card command and response wire meanings, independent of host-controller registers.

/// Command wire encodings shared by the native transport and card protocols.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::storage) struct Opcode(u8);
impl Opcode {
    pub(in crate::storage) fn number(self) -> u8 {
        self.0
    }
}
pub(in crate::storage) const GO_IDLE: Opcode = Opcode(0);
pub(in crate::storage) const MMC_SEND_OP_COND: Opcode = Opcode(1);
pub(in crate::storage) const ALL_SEND_CID: Opcode = Opcode(2);
pub(in crate::storage) const SET_RELATIVE_ADDRESS: Opcode = Opcode(3);
pub(in crate::storage) const SWITCH: Opcode = Opcode(6);
pub(in crate::storage) const SELECT_CARD: Opcode = Opcode(7);
pub(in crate::storage) const SD_SEND_IF_COND: Opcode = Opcode(8);
pub(in crate::storage) const MMC_SEND_EXT_CSD: Opcode = Opcode(8);
pub(in crate::storage) const SEND_CSD: Opcode = Opcode(9);
pub(in crate::storage) const SD_SWITCH_VOLTAGE: Opcode = Opcode(11);
pub(in crate::storage) const SD_SEND_TUNING: Opcode = Opcode(19);
pub(in crate::storage) const STOP_TRANSMISSION: Opcode = Opcode(12);
pub(in crate::storage) const SEND_STATUS: Opcode = Opcode(13);
pub(in crate::storage) const SET_BLOCK_LENGTH: Opcode = Opcode(16);
pub(in crate::storage) const READ_SINGLE: Opcode = Opcode(17);
pub(in crate::storage) const READ_MULTIPLE: Opcode = Opcode(18);
pub(in crate::storage) const WRITE_SINGLE: Opcode = Opcode(24);
pub(in crate::storage) const WRITE_MULTIPLE: Opcode = Opcode(25);
pub(in crate::storage) const SD_SEND_OP_COND: Opcode = Opcode(41);
pub(in crate::storage) const SD_SEND_SCR: Opcode = Opcode(51);
pub(in crate::storage) const APP_CMD: Opcode = Opcode(55);

const R1_STATUS_ERRORS: u32 = 0xfff9_a000;
const R1_UNDERRUN: u32 = 1 << 18;
const R1_OVERRUN: u32 = 1 << 17;
const R1_SWITCH_ERROR: u32 = 1 << 7;
const SD_AKE_SEQUENCE_ERROR: u32 = 1 << 3;
pub(in crate::storage) const R1_ERRORS: u32 =
    R1_STATUS_ERRORS | R1_UNDERRUN | R1_OVERRUN | R1_SWITCH_ERROR | SD_AKE_SEQUENCE_ERROR;
#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::storage) enum Response {
    None,
    Status,
    Busy,
    Long,
    Ocr,
    Rca,
    Echo,
}
