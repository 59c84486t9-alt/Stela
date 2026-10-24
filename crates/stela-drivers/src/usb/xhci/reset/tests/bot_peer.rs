// SPDX-License-Identifier: GPL-2.0-only
//! Independent CBW/data/CSW peer on the actual command/context/TD DMA model.
use super::*;

struct Command {
    tag: u32,
    length: usize,
    input: bool,
    data: Vec<u8>,
    transferred: bool,
    moved: usize,
    lba: u32,
    write: bool,
}
#[derive(Default)]
pub(super) struct Peer {
    command: Option<Command>,
}
impl Peer {
    pub(super) fn reset(&mut self) {
        self.command = None;
    }
    pub(super) fn bulk(&mut self, h: &mut Hardware, slot: u8, dci: u8, stream: u16) {
        assert_eq!(stream, 0);
        assert!(matches!(dci, 2 | 3));
        let (trb, buffer, status, control) =
            Hardware::take(h.cursors.get_mut(&(slot, dci, 0)).unwrap());
        assert_eq!(control >> 10 & 63, NORMAL);
        let length = (status & 0x1ffff) as usize;
        let actual;
        if self.command.is_none() {
            assert_eq!(dci, 2);
            assert_eq!(length, 31);
            let cbw = bytes(buffer, length);
            assert_eq!(&cbw[..4], b"USBC");
            assert_eq!(cbw[13], 0);
            assert!((1..=16).contains(&cbw[14]));
            let requested = u32::from_le_bytes(cbw[8..12].try_into().unwrap()) as usize;
            let cdb = &cbw[15..];
            let mut command = Command {
                tag: u32::from_le_bytes(cbw[4..8].try_into().unwrap()),
                length: requested,
                input: cbw[12] & 0x80 != 0,
                data: Vec::new(),
                transferred: requested == 0,
                moved: 0,
                lba: 0,
                write: false,
            };
            h.scsi.push((h.resets, cdb[0]));
            match cdb[0] {
                0 | 0x35 => assert_eq!(requested, 0),
                0x12 => {
                    command.data = vec![0; 36];
                    command.data[2] = 6;
                    command.data[4] = 31;
                    command.data[8..16].copy_from_slice(b"STELAUSB");
                    command.data[16..32].copy_from_slice(b"BOT RESET MODEL ");
                }
                0x25 => {
                    command.data.extend_from_slice(&1023u32.to_be_bytes());
                    command.data.extend_from_slice(&512u32.to_be_bytes());
                }
                0x1a => {
                    command.data = vec![0; 24];
                    command.data[0] = 23;
                    command.data[4] = 8;
                    command.data[5] = 18;
                    command.data[6] = 4; // genuine caching mode page, WCE.
                }
                0x28 | 0x2a => {
                    command.lba = u32::from_be_bytes(cdb[2..6].try_into().unwrap());
                    assert_eq!(
                        requested,
                        usize::from(u16::from_be_bytes(cdb[7..9].try_into().unwrap())) * 512
                    );
                    command.write = cdb[0] == 0x2a;
                    assert_eq!(command.input, !command.write);
                    if command.input {
                        command.data = h
                            .writes
                            .iter()
                            .rev()
                            .find(|(lba, data)| {
                                *lba == u64::from(command.lba) && data.len() == requested
                            })
                            .map_or_else(|| vec![0x6d; requested], |(_, data)| data.clone());
                    }
                }
                other => panic!("unimplemented BOT peer CDB {other:#x}"),
            }
            if command.input {
                command.data.truncate(requested);
            }
            self.command = Some(command);
            actual = length;
        } else {
            let mut command = self.command.take().unwrap();
            if !command.transferred {
                assert_eq!(length, command.length);
                assert_eq!(dci, if command.input { 3 } else { 2 });
                if command.input {
                    copy(buffer, &command.data);
                } else {
                    assert!(command.write);
                    h.writes
                        .push((u64::from(command.lba), bytes(buffer, length)));
                }
                command.transferred = true;
                actual = if command.input {
                    command.data.len()
                } else {
                    length
                };
                command.moved = actual;
                self.command = Some(command);
            } else {
                assert_eq!((dci, length), (3, 13));
                let mut csw = vec![0u8; 13];
                csw[..4].copy_from_slice(b"USBS");
                csw[4..8].copy_from_slice(&command.tag.to_le_bytes());
                csw[8..12]
                    .copy_from_slice(&((command.length - command.moved) as u32).to_le_bytes());
                copy(buffer, &csw);
                actual = 13;
            }
        }
        h.event(
            trb,
            (if actual < length {
                SHORT_PACKET
            } else {
                SUCCESS
            }) << 24
                | (length - actual) as u32,
            TRANSFER_EVENT,
            slot,
            dci,
        );
    }
}
pub(super) fn configuration(speed: u8) -> Vec<u8> {
    let mut raw = vec![9, 2, 0, 0, 1, 1, 0, 0x80, 0, 9, 4, 0, 0, 2, 8, 6, 0x50, 0];
    let packet = if speed >= SUPER_SPEED { 1024u16 } else { 512 };
    for address in [1, 0x81] {
        raw.extend_from_slice(&[7, 5, address, 2, packet as u8, (packet >> 8) as u8, 0]);
        if speed >= SUPER_SPEED {
            raw.extend_from_slice(&[6, 48, 0, 0, 0, 0]);
        }
    }
    let length = raw.len() as u16;
    raw[2..4].copy_from_slice(&length.to_le_bytes());
    raw
}
