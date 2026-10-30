use super::*;
use crate::{
    dwc3::xhci::tests::host,
    usb::{
        Speed,
        control::{
            SET_ADDRESS, SET_CONFIGURATION,
            tests::{setup, transfer},
        },
        hub::{Hub, Ports},
    },
};
use stela_drivers::{
    block::{BlockError, RamDisk, Sense},
    usb::storage::Data,
};

const SERIAL: &str = "0123456789ABCDEF";

fn device(blocks: u64, block_size: u32, read_only: bool) -> MassStorage {
    let mut disk = RamDisk::new("host", blocks, block_size);
    disk.identity.read_only = read_only;
    for (n, byte) in disk.bytes.iter_mut().enumerate() {
        *byte = (n / block_size as usize) as u8;
    }
    let mut d = MassStorage::new(Box::new(disk), SERIAL, "Host Disk").unwrap();
    transfer(&mut d, setup(0, SET_ADDRESS, 2, 0, 0), &[]).unwrap();
    transfer(&mut d, setup(0, SET_CONFIGURATION, 1, 0, 0), &[]).unwrap();
    d
}

fn cbw(tag: u32, length: u32, input: bool, cdb: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0u8; CBW_BYTES];
    bytes[..4].copy_from_slice(&CBW_SIGNATURE.to_le_bytes());
    bytes[4..8].copy_from_slice(&tag.to_le_bytes());
    bytes[8..12].copy_from_slice(&length.to_le_bytes());
    bytes[12] = if input { 0x80 } else { 0 };
    bytes[14] = cdb.len() as u8;
    bytes[15..15 + cdb.len()].copy_from_slice(cdb);
    bytes
}

/// One command: its IN data (read until a short packet or STALL), and
/// its CSW's residue and status.
fn run(
    d: &mut MassStorage,
    tag: u32,
    length: u32,
    input: bool,
    cdb: &[u8],
    out: &[u8],
) -> (Vec<u8>, u32, u8) {
    let mut wrapper = cbw(tag, length, input, cdb);
    assert_eq!(
        d.packet(BULK_OUT, Token::Out, &mut wrapper),
        Ok(Reply::Ack(CBW_BYTES))
    );
    let mut data = Vec::new();
    if input {
        loop {
            if data.len() == length as usize {
                break;
            }
            let mut packet = [0u8; 512];
            match d.packet(BULK_IN, Token::In, &mut packet).unwrap() {
                Reply::Ack(n) => {
                    data.extend_from_slice(&packet[..n]);
                    if n < 512 {
                        break;
                    }
                }
                Reply::Stall => {
                    transfer(d, setup(0x02, CLEAR_FEATURE, 0, u16::from(BULK_IN), 0), &[]).unwrap();
                    break;
                }
                Reply::Nak => panic!("data NAK"),
            }
        }
    } else {
        for chunk in out.chunks(512) {
            match d.packet(BULK_OUT, Token::Out, &mut chunk.to_vec()).unwrap() {
                Reply::Ack(_) => {}
                Reply::Stall => {
                    transfer(
                        d,
                        setup(0x02, CLEAR_FEATURE, 0, u16::from(BULK_OUT), 0),
                        &[],
                    )
                    .unwrap();
                    break;
                }
                Reply::Nak => panic!("data NAK"),
            }
        }
    }
    let mut csw = [0u8; 512];
    let reply = d.packet(BULK_IN, Token::In, &mut csw).unwrap();
    if reply == Reply::Stall {
        transfer(d, setup(0x02, CLEAR_FEATURE, 0, u16::from(BULK_IN), 0), &[]).unwrap();
        assert_eq!(d.packet(BULK_IN, Token::In, &mut csw), Ok(Reply::Ack(13)));
    } else {
        assert_eq!(reply, Reply::Ack(13));
    }
    assert_eq!(
        u32::from_le_bytes(csw[..4].try_into().unwrap()),
        CSW_SIGNATURE
    );
    assert_eq!(u32::from_le_bytes(csw[4..8].try_into().unwrap()), tag);
    (
        data,
        u32::from_le_bytes(csw[8..12].try_into().unwrap()),
        csw[12],
    )
}

fn sense(d: &mut MassStorage) -> (u8, u8) {
    let (data, _, status) = run(d, 99, 18, true, &[REQUEST_SENSE, 0, 0, 0, 18, 0], &[]);
    assert_eq!(status, PASSED);
    (data[2], data[12])
}

#[test]
fn descriptors_and_class_requests_describe_a_bulk_only_scsi_disk() {
    let mut d = device(64, 512, false);
    let config = transfer(&mut d, setup(0x80, 6, 0x200, 0, 255), &[]).unwrap();
    assert_eq!(&config[9..18], &[9, INTERFACE, 0, 0, 2, 8, 6, 0x50, 0]);
    assert_eq!(&config[18..25], &[7, ENDPOINT, BULK_IN, 2, 0, 2, 0]);
    let other = transfer(&mut d, setup(0x80, 6, 0x700, 0, 255), &[]).unwrap();
    assert_eq!(
        u16::from_le_bytes([other[22], other[23]]),
        FULL_SPEED_PACKET
    );
    assert_eq!(
        transfer(&mut d, setup(0xa1, GET_MAX_LUN, 0, 0, 1), &[]).unwrap(),
        [0]
    );
    transfer(&mut d, setup(0x21, RESET, 0, 0, 0), &[]).unwrap();
    assert!(MassStorage::new(Box::new(RamDisk::new("", 8, 512)), "short", "x").is_err());
}

#[test]
fn inquiry_capacity_and_mode_pages_report_the_backing_disk() {
    let mut d = device(64, 4096, false);
    let (data, residue, status) = run(&mut d, 1, 36, true, &[INQUIRY, 0, 0, 0, 36, 0], &[]);
    assert_eq!((residue, status), (0, PASSED));
    assert_eq!(data[0], 0);
    assert_eq!(&data[8..16], b"STELA   ");
    assert_eq!(&data[16..32], b"Host Disk       ");
    let (serial, _, _) = run(&mut d, 2, 255, true, &[INQUIRY, 1, 0x80, 0, 255, 0], &[]);
    assert_eq!(&serial[4..], SERIAL.as_bytes());
    let (capacity, _, _) = run(
        &mut d,
        3,
        8,
        true,
        &[READ_CAPACITY_10, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        &[],
    );
    assert_eq!(capacity, [0, 0, 0, 63, 0, 0, 0x10, 0]);
    let mut cdb16 = [0u8; 16];
    cdb16[0] = SERVICE_ACTION_IN_16;
    cdb16[1] = READ_CAPACITY_16;
    cdb16[13] = 32;
    let (long, _, _) = run(&mut d, 4, 32, true, &cdb16, &[]);
    assert_eq!(&long[..12], &[0, 0, 0, 0, 0, 0, 0, 63, 0, 0, 0x10, 0]);
    let (mode, _, _) = run(
        &mut d,
        5,
        192,
        true,
        &[MODE_SENSE_6, 0, ALL_PAGES, 0, 192, 0],
        &[],
    );
    assert_eq!(&mode[..4], &[23, 0, 0, 0]);
    assert_eq!((mode[4], mode[6]), (CACHING_PAGE, 0x04));
    // Asking for fewer bytes than the reply has trims it: residue 0.
    let (short, residue, _) = run(&mut d, 6, 4, true, &[INQUIRY, 0, 0, 0, 4, 0], &[]);
    assert_eq!((short.len(), residue), (4, 0));
}

#[test]
fn reads_and_writes_move_whole_blocks_through_chunks() {
    let mut d = device(64, 512, false);
    // 150 blocks cross a 128-block chunk.
    let mut d2 = device(160, 512, false);
    let (data, residue, status) = run(
        &mut d2,
        1,
        150 * 512,
        true,
        &[READ_10, 0, 0, 0, 0, 5, 0, 0, 150, 0],
        &[],
    );
    assert_eq!((data.len(), residue, status), (150 * 512, 0, PASSED));
    assert_eq!((data[0], data[512 * 149]), (5, 154));
    let payload: Vec<u8> = (0..3 * 512).map(|n| (n % 251) as u8).collect();
    let (_, residue, status) = run(
        &mut d,
        2,
        3 * 512,
        false,
        &[WRITE_10, 0, 0, 0, 0, 7, 0, 0, 3, 0],
        &payload,
    );
    assert_eq!((residue, status), (0, PASSED));
    let (back, _, _) = run(
        &mut d,
        3,
        3 * 512,
        true,
        &[READ_10, 0, 0, 0, 0, 7, 0, 0, 3, 0],
        &[],
    );
    assert_eq!(back, payload);
    let (_, _, status) = run(
        &mut d,
        4,
        0,
        false,
        &[SYNCHRONIZE_CACHE_10, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        &[],
    );
    assert_eq!(status, PASSED);
}

#[test]
fn errors_report_sense_and_mismatched_lengths_follow_the_thirteen_cases() {
    let mut d = device(64, 512, false);
    let (_, _, status) = run(&mut d, 1, 0, false, &[0x04, 0, 0, 0, 0, 0], &[]);
    assert_eq!(status, FAILED);
    assert_eq!(sense(&mut d), (5, 0x20));
    let (_, _, status) = run(
        &mut d,
        2,
        512,
        true,
        &[READ_10, 0, 0, 0, 0, 64, 0, 0, 1, 0],
        &[],
    );
    assert_eq!(status, FAILED);
    assert_eq!(sense(&mut d), (5, 0x21));
    // Case 5: the host asks for more than the device sends; the full
    // last packet is followed by a STALL and the residue.
    let (data, residue, status) = run(
        &mut d,
        3,
        1024,
        true,
        &[READ_10, 0, 0, 0, 0, 1, 0, 0, 1, 0],
        &[],
    );
    assert_eq!((data.len(), residue, status), (512, 512, PASSED));
    // Case 7: the device intends more than the host takes.
    let (data, _, status) = run(
        &mut d,
        4,
        512,
        true,
        &[READ_10, 0, 0, 0, 0, 1, 0, 0, 2, 0],
        &[],
    );
    assert_eq!((data.len(), status), (512, PHASE_ERROR));
    // Case 2: the host expects no data but the device intends some.
    let (_, _, status) = run(
        &mut d,
        5,
        0,
        false,
        &[READ_10, 0, 0, 0, 0, 1, 0, 0, 1, 0],
        &[],
    );
    assert_eq!(status, PHASE_ERROR);
    // Case 10: the host sends data to a command that reads.
    let (_, _, status) = run(
        &mut d,
        6,
        512,
        false,
        &[READ_10, 0, 0, 0, 0, 1, 0, 0, 1, 0],
        &[0; 512],
    );
    assert_eq!(status, PHASE_ERROR);
    // Case 11: the host sends more than the write takes; the device
    // absorbs the rest and reports it as residue.
    let (_, residue, status) = run(
        &mut d,
        8,
        1024,
        false,
        &[WRITE_10, 0, 0, 0, 0, 1, 0, 0, 1, 0],
        &[7; 1024],
    );
    assert_eq!((residue, status), (512, PASSED));
    let mut ro = device(64, 512, true);
    let (_, _, status) = run(
        &mut ro,
        7,
        512,
        false,
        &[WRITE_10, 0, 0, 0, 0, 1, 0, 0, 1, 0],
        &[0; 512],
    );
    assert_eq!(status, FAILED);
    assert_eq!(sense(&mut ro), (7, 0x27));
}

#[test]
fn an_invalid_cbw_stalls_both_pipes_until_reset_recovery() {
    let mut d = device(64, 512, false);
    let mut bad = cbw(1, 0, false, &[TEST_UNIT_READY]);
    bad[0] = 0;
    assert_eq!(d.packet(BULK_OUT, Token::Out, &mut bad), Ok(Reply::Stall));
    transfer(
        &mut d,
        setup(0x02, CLEAR_FEATURE, 0, u16::from(BULK_OUT), 0),
        &[],
    )
    .unwrap();
    let mut good = cbw(2, 0, false, &[TEST_UNIT_READY]);
    assert_eq!(d.packet(BULK_OUT, Token::Out, &mut good), Ok(Reply::Stall));
    transfer(&mut d, setup(0x21, RESET, 0, 0, 0), &[]).unwrap();
    for endpoint in [BULK_IN, BULK_OUT] {
        transfer(
            &mut d,
            setup(0x02, CLEAR_FEATURE, 0, u16::from(endpoint), 0),
            &[],
        )
        .unwrap();
    }
    let (_, _, status) = run(&mut d, 3, 0, false, &[TEST_UNIT_READY, 0, 0, 0, 0, 0], &[]);
    assert_eq!(status, PASSED);
}

struct Disks(Vec<MassStorage>);
impl Ports for Disks {
    fn count(&self) -> usize {
        self.0.len()
    }
    fn speed(&self, _: usize) -> Speed {
        Speed::High
    }
    fn function(&mut self, port: usize) -> &mut dyn Function {
        &mut self.0[port]
    }
    fn function_ref(&self, port: usize) -> &dyn Function {
        &self.0[port]
    }
}

fn disk(serial: &str, blocks: u64, read_only: bool) -> MassStorage {
    let mut ram = RamDisk::new(serial, blocks, 512);
    ram.identity.read_only = read_only;
    for (n, byte) in ram.bytes.iter_mut().enumerate() {
        *byte = (n / 512) as u8 ^ (n % 7) as u8;
    }
    MassStorage::new(Box::new(ram), "00000000000A", "Native Disk").unwrap()
}

#[test]
fn a_disk_on_the_root_port_needs_no_hub() {
    let mut bench = host::bench(disk("c", 8, false));
    let mut found = host::run(&mut bench);
    assert!(found.failures.is_empty(), "{:?}", found.failures);
    let mut disk = found.disks.remove(0);
    assert_eq!(
        disk.identity().location,
        "xhci test port 1 interface 0 LUN 0"
    );
    let mut block = [0u8; 512];
    disk.read(7, &mut block).unwrap();
    assert_eq!(block[1], 7 ^ ((7 * 512 + 1) % 7) as u8);
}

#[test]
fn disks_behind_a_hub_enumerate_read_write_and_flush() {
    let hub = Hub::new(
        Disks(vec![disk("a", 300, false), disk("b", 16, true)]),
        "HUB",
    )
    .unwrap();
    let mut bench = host::bench(hub);
    let mut found = host::run(&mut bench);
    assert!(found.failures.is_empty(), "{:?}", found.failures);
    assert_eq!(found.disks.len(), 2);
    let mut first = found.disks.remove(0);
    let identity = first.identity().clone();
    assert_eq!((identity.blocks, identity.block_size), (300, 512));
    assert_eq!(identity.model, "STELA Native Disk");
    assert_eq!(identity.serial, "00000000000A");
    assert_eq!(identity.location, "xhci test port 1.1 interface 0 LUN 0");
    assert_eq!(
        found.disks[0].identity().location,
        "xhci test port 1.2 interface 0 LUN 0"
    );
    assert!(!identity.read_only);
    // 200 blocks: two chunks of at most 64 KiB.
    let mut bytes = vec![0u8; 200 * 512];
    first.read(50, &mut bytes).unwrap();
    let expected = |at: usize| (at / 512) as u8 ^ (at % 7) as u8;
    assert_eq!(bytes[0], expected(50 * 512));
    assert_eq!(bytes[512 * 199 + 3], expected(249 * 512 + 3));
    let payload: Vec<u8> = (0..3 * 512).map(|n| (n % 253) as u8).collect();
    first.write(7, &payload).unwrap();
    let mut back = vec![0u8; 3 * 512];
    first.read(7, &mut back).unwrap();
    assert_eq!(back, payload);
    first.flush().unwrap();
    // Out of range fails before the bus; the device's own refusals
    // report their sense.
    assert!(first.read(300, &mut [0u8; 512]).is_err());
    let mut second = found.disks.remove(0);
    assert!(second.identity().read_only);
    assert!(matches!(
        second.write(0, &[0u8; 512]),
        Err(BlockError::ReadOnly)
    ));
    assert_eq!(
        second.command(&[0x04, 0, 0, 0, 0, 0], Data::None),
        Err(BlockError::Sense(Sense {
            key: Sense::ILLEGAL_REQUEST,
            asc: 0x20,
            ascq: 0
        }))
    );
    // The device still answers after the failed command.
    let mut block = [0u8; 512];
    second.read(15, &mut block).unwrap();
    assert_eq!(block[0], expected(15 * 512));
}
