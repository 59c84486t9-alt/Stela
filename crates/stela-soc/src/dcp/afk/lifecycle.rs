//! AFKEPV2 interface-zero transport lifecycle, independent of EPIC services.
//!
//! Both peers implement the same four internal commands: AP
//! `AFKEPV2::handleInternalPacket` at `0xfffffe00094c415c`, DCP restore
//! firmware `0x311a4` (dispatch `0x3125c`, table `0x313a8`). Pause waits
//! for the local service notification to complete, then sends PauseDone;
//! clearing pause sends UnpauseDone and notification 1 to local services. With no
//! published interfaces those notifications have no outstanding work.
//! The model never initiates a pause/unpause request. Original states 1/3
//! (waiting for peer completion) therefore cannot arise here. Both handlers
//! accept 3/5 without checking an outstanding request: 2/3 set the same
//! handshake byte to 2; 4/5 clear it to 0. We preserve that behavior.
//! Unpause names the observed inverse of Pause: the original command names
//! for 4/5 are not present in this stripped firmware or kernel symbols.
use crate::Result;
use stela_contracts::refuse;

pub const PACKET_BYTES: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Pause = 2,
    PauseDone = 3,
    Unpause = 4,
    UnpauseDone = 5,
}

impl Command {
    pub fn decode(packet: &[u8; PACKET_BYTES]) -> Result<Self> {
        // AFKEPV2::processSendMessage prepends sequence, flags, interface
        // number and payload length (kernel 0x94c3b6c..0x94c3b84).
        if packet[2..4] != [0, 0] {
            return Err(refuse!(
                "DCP AFKEPV2 AP message targets an unpublished interface"
            ));
        }
        if packet[4..8] != 4u32.to_le_bytes() {
            return Err(refuse!(
                "DCP AFKEPV2 internal packet length is not four bytes"
            ));
        }
        // Both original handlers dispatch on the low byte, reserving the
        // other three command bytes; they carry no architectural effect.
        match packet[8] {
            2 => Ok(Self::Pause),
            3 => Ok(Self::PauseDone),
            4 => Ok(Self::Unpause),
            5 => Ok(Self::UnpauseDone),
            _ => Err(refuse!("DCP AFKEPV2 unknown internal command")),
        }
    }

    pub fn packet(self, sequence: u8) -> [u8; PACKET_BYTES] {
        let mut packet = [0; PACKET_BYTES];
        packet[0] = sequence;
        packet[4] = 4;
        packet[8] = self as u8;
        packet
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PeerState {
    #[default]
    Running,
    Paused,
}

impl PeerState {
    pub fn receive(&mut self, command: Command) -> Option<Command> {
        match command {
            Command::Pause | Command::PauseDone => *self = Self::Paused,
            Command::Unpause | Command::UnpauseDone => *self = Self::Running,
        }
        match command {
            Command::Pause => Some(Command::PauseDone),
            Command::Unpause => Some(Command::UnpauseDone),
            Command::PauseDone | Command::UnpauseDone => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_internal_commands_update_the_peer_and_only_requests_reply() {
        let mut peer = PeerState::default();
        for (command, expected, reply) in [
            (Command::Pause, PeerState::Paused, Some(Command::PauseDone)),
            (Command::PauseDone, PeerState::Paused, None),
            (
                Command::Unpause,
                PeerState::Running,
                Some(Command::UnpauseDone),
            ),
            (Command::UnpauseDone, PeerState::Running, None),
        ] {
            assert_eq!(Command::decode(&command.packet(0x92)), Ok(command));
            assert_eq!(peer.receive(command), reply);
            assert_eq!(peer, expected);
        }
    }

    #[test]
    fn unknown_interfaces_lengths_and_commands_refuse() {
        let packet = Command::Pause.packet(0);
        for (offset, value) in [(2, 1), (4, 8), (8, 1)] {
            let mut bad = packet;
            bad[offset] = value;
            assert!(Command::decode(&bad).is_err());
        }
        let mut reserved = packet;
        reserved[1] = 0xa5; // Original AFKEPV2 receiver ignores this byte.
        reserved[9..].fill(0xa5);
        assert_eq!(Command::decode(&reserved), Ok(Command::Pause));
    }
}
