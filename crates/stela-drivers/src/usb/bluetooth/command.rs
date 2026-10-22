// SPDX-License-Identifier: MIT
//! HCI command events during vendor initialization (Bluetooth Core v5.4
//! Vol 4 Part E 4.4, 7.7.14 and 7.7.15): the commands the vendor engines
//! send, and what a Command Complete or Command Status event says about the
//! one in flight. A completion that grants no credits is valid; the host
//! waits for a later event, such as a NOP completion, before sending more.
use alloc::vec::Vec;

pub(super) const COMMAND_COMPLETE: u8 = 0x0e;
pub(super) const COMMAND_STATUS: u8 = 0x0f;
/// The opcode of a completion that only grants credits.
const NOP: u16 = 0;
const MAX_PARAMETERS: usize = 255;

/// What an event says to a command in flight.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Response<'a> {
    /// Its Command Complete: the credits granted, then the return
    /// parameters, starting with the status.
    Complete { credits: u8, returned: &'a [u8] },
    /// Its Command Status.
    Status { credits: u8, status: u8 },
    /// A NOP completion: credits for the next command.
    Credits(u8),
    /// Not a command event.
    Other,
}

/// The command packet for `opcode` and its parameters.
pub(super) fn packet(opcode: u16, parameters: &[u8]) -> Result<Vec<u8>, &'static str> {
    if parameters.len() > MAX_PARAMETERS {
        return Err("command parameters exceed HCI maximum");
    }
    let mut packet = Vec::with_capacity(3 + parameters.len());
    packet.extend_from_slice(&opcode.to_le_bytes());
    packet.push(parameters.len() as u8);
    packet.extend_from_slice(parameters);
    Ok(packet)
}

/// Read `event` against the command `opcode` in flight.
pub(super) fn response(event: &[u8], opcode: u16) -> Result<Response<'_>, &'static str> {
    let (credits, returned_opcode) = match event {
        [COMMAND_COMPLETE, _, credits, low, high, _, ..] => {
            (*credits, u16::from_le_bytes([*low, *high]))
        }
        [COMMAND_STATUS, 4, _, credits, low, high] => (*credits, u16::from_le_bytes([*low, *high])),
        [COMMAND_COMPLETE | COMMAND_STATUS, ..] => return Err("malformed command event"),
        _ => return Ok(Response::Other),
    };
    if returned_opcode == NOP {
        return Ok(Response::Credits(credits));
    }
    if returned_opcode != opcode {
        return Err("command event for another opcode");
    }
    Ok(match event[0] {
        COMMAND_COMPLETE => Response::Complete {
            credits,
            returned: &event[5..],
        },
        _ => Response::Status {
            credits,
            status: event[2],
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_events_are_matched_to_their_opcode_and_credits_kept() {
        let reset = 0x0c03;
        assert_eq!(packet(reset, &[]).unwrap(), [3, 0x0c, 0]);
        assert!(packet(reset, &[0; 256]).is_err());
        assert_eq!(
            response(&[0x0e, 4, 0, 3, 0x0c, 0], reset),
            Ok(Response::Complete {
                credits: 0,
                returned: &[0]
            })
        );
        assert_eq!(
            response(&[0x0f, 4, 0x0c, 1, 3, 0x0c], reset),
            Ok(Response::Status {
                credits: 1,
                status: 0x0c
            })
        );
        assert_eq!(
            response(&[0x0e, 3, 2, 0, 0, 0], reset),
            Ok(Response::Credits(2))
        );
        assert_eq!(
            response(&[0x0e, 4, 1, 1, 0x10, 0], reset),
            Err("command event for another opcode")
        );
        assert_eq!(
            response(&[0x0e, 2, 1], reset),
            Err("malformed command event")
        );
        assert_eq!(response(&[0xff, 1, 6], reset), Ok(Response::Other));
    }
}
