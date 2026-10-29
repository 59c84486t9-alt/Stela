use super::super::Description;
use super::*;
use alloc::boxed::Box;
use stela_contracts::refuse;
use stela_drivers::block::{BlockDevice, RamDisk};
use {
    crate::platform::apple::sart::Sart, stela_contracts::bus::Access,
    stela_contracts::dma::Physical, stela_contracts::dma::test_support::Ram,
    stela_contracts::interrupt::InterruptLatch, stela_soc_data::sart::Bounds,
};

#[test]
fn os_build_tunnel_stores_only_the_recovered_message_and_checks_extensions() {
    use {stela_contracts::bus::MmioDevice, stela_contracts::bus::Width};
    let mut ans = Ans::new(
        Box::new(RamDisk::new("", 4, 4096)),
        &[Description {
            id: 1,
            kind: 1,
            blocks: 0,
        }],
        None,
    )
    .unwrap();
    let mut memory = Ram::new(0x1000, 8192);
    let mut sart = Sart::new(Bounds::Exclusive);
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    for (offset, value) in [(0x40, 1), (0x80, 2), (0, 0xff)] {
        sart.write(offset, Width::Word, value, &mut access).unwrap();
    }
    let mut port = Port {
        iommu: &mut Physical,
        stream: 0,
        memory: &mut memory,
        access: &mut access,
    };
    let mut request = [0; 80];
    request[12..16].copy_from_slice(&0x120u32.to_le_bytes());
    request[24..30].copy_from_slice(b"26A434");
    request[76..80].fill(0xff);
    port.write(0x1000, &request).unwrap();
    let mut command = Command([0; 64]);
    command.0[0] = APPLE_TUNNEL;
    command.0[40] = 1;
    command.0[44..52].copy_from_slice(&0x1000u64.to_le_bytes());
    assert_eq!(
        ans.execute(0, &command, &mut port, &mut sart)
            .unwrap()
            .status,
        SUCCESS
    );
    assert_eq!(&ans.os_build[..6], b"26A434");
    let mut status = [1; 4];
    port.read(0x104c, &mut status).unwrap();
    assert_eq!(status, [0; 4]);
    request[16] = 1;
    request[24..30].fill(b'X');
    port.write(0x1000, &request).unwrap();
    assert!(ans.execute(0, &command, &mut port, &mut sart).is_err());
    assert_eq!(&ans.os_build[..6], b"26A434");
    port.read(0x104c, &mut status).unwrap();
    assert_eq!(status, [0xff; 4]);
    request.fill(0);
    request[12..16].copy_from_slice(&0x38u32.to_le_bytes());
    port.write(0x1000, &request).unwrap();
    port.write(0x2000, &[0xa5; 4096]).unwrap();
    command.0[52..60].copy_from_slice(&0x2000u64.to_le_bytes());
    // The driver's 4 KiB request travels as one 16 KiB tunnel buffer.
    assert_eq!(tunnel_buffer(4096), 0x4000);
    assert_eq!(tunnel_buffer(0x4001), 0x8000);
    command.0[60..64].copy_from_slice(&4096u32.to_le_bytes());
    assert!(ans.execute(0, &command, &mut port, &mut sart).is_err());
    command.0[60..64].copy_from_slice(&tunnel_buffer(4096).to_le_bytes());
    ans.execute(0, &command, &mut port, &mut sart).unwrap();
    let mut output = [0; 16];
    port.read(0x2000, &mut output).unwrap();
    assert_eq!(&output[..8], &die::NAND_ID.to_le_bytes());
    assert_eq!(
        &output[8..],
        &[0xa5; 8],
        "unconsumed fields have no invented content"
    );
    request[12..16].copy_from_slice(&0xbau32.to_le_bytes());
    port.write(0x1000, &request).unwrap();
    port.write(0x2000, &[0xa5; 4096]).unwrap();
    ans.execute(0, &command, &mut port, &mut sart).unwrap();
    let mut geometry = [0; 0x80];
    port.read(0x2000, &mut geometry).unwrap();
    let field = |offset| u32::from_le_bytes(geometry[offset..offset + 4].try_into().unwrap());
    assert_eq!(field(8), 1);
    assert_eq!(field(0x14) << 12, BLOCK_BYTES);
    assert!(u64::from(field(0x10)) * u64::from(field(0x28)) >= ans.medium.namespaces[0].blocks);
    assert_eq!(field(0x38), field(0x10));
    assert_eq!(field(0x18), field(0x24) * field(0x14));
    assert_eq!(field(0x1c), field(0x28) * field(0x14));
    assert_eq!(&geometry[..4], &[0xa5; 4]);
    assert_eq!(&geometry[0x44..0x60], &[0xa5; 28]);
    assert_eq!(&geometry[0x60..0x62], &[1, 0xa5]);
    assert_eq!(&geometry[0x70..0x72], &[0, 0xa5]);
    // Tunnel buffers outside the SART's allow-list refuse.
    sart.write(0, Width::Word, 0, port.access).unwrap();
    assert!(ans.execute(0, &command, &mut port, &mut sart).is_err());
    // An unknown request type refuses and leaves the request it read
    // in the submission record.
    sart.write(0, Width::Word, 0xff, port.access).unwrap();
    request[12..16].copy_from_slice(&0x77u32.to_le_bytes());
    port.write(0x1000, &request).unwrap();
    ans.last_submission = Some(super::super::Submission {
        queue: 0,
        tag: 0,
        command: command.0,
        tcb: [0; 128],
        tunnel: None,
    });
    assert!(ans.execute(0, &command, &mut port, &mut sart).is_err());
    assert_eq!(ans.last_submission.as_ref().unwrap().tunnel, Some(request));
}

#[test]
fn device_time_tunnel_records_the_recovery_request_and_unserved_types_refuse_by_name() {
    use {stela_contracts::bus::MmioDevice, stela_contracts::bus::Width};
    let mut ans = Ans::new(
        Box::new(RamDisk::new("", 4, 4096)),
        &[Description {
            id: 1,
            kind: 1,
            blocks: 0,
        }],
        None,
    )
    .unwrap();
    // The recoveryOS boot's request buffer: one 16 KiB tunnel buffer.
    const REQUEST: u64 = 0x8_08f8_c000;
    let mut memory = Ram::new(REQUEST, 0x8000);
    let mut sart = Sart::new(Bounds::Exclusive);
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    for (offset, value) in [(0x40, REQUEST >> 12), (0x80, 4), (0, 0xff)] {
        sart.write(offset, Width::Word, value, &mut access).unwrap();
    }
    let mut port = Port {
        iommu: &mut Physical,
        stream: 0,
        memory: &mut memory,
        access: &mut access,
    };
    // Admin SQ tag 8 of the recoveryOS boot, after IONVMeFamily logged
    // the nvram sync system event.
    let mut request = [0u8; 80];
    request[12] = 6;
    request[0x1c..0x24].copy_from_slice(&[0xea, 0xb5, 0xd6, 0x6a, 0x7f, 0, 0, 0]);
    request[0x24..0x2c].copy_from_slice(&[0x71, 0xe0, 0xbc, 0x8f, 0, 0, 0, 0]);
    request[0x2c..0x34].copy_from_slice(&[0x71, 0xe0, 0xbc, 0x8f, 0, 0, 0, 0]);
    request[0x4c..].fill(0xff);
    port.write(REQUEST, &request).unwrap();
    let mut command = Command([0; 64]);
    command.0[..4].copy_from_slice(&[APPLE_TUNNEL, 0, 8, 0]);
    command.0[40] = 1;
    command.0[44..52].copy_from_slice(&REQUEST.to_le_bytes());
    let outcome = ans.execute(0, &command, &mut port, &mut sart).unwrap();
    assert_eq!(outcome.status, SUCCESS);
    let mut status = [1; 4];
    port.read(REQUEST + 0x4c, &mut status).unwrap();
    assert_eq!(status, [0; 4]);
    let recorded = DeviceTime {
        calendar_seconds: 0x6ad6_b5ea,
        prtc_seconds: 0x7f,
        absolute: 0x8fbc_e071,
        continuous: 0x8fbc_e071,
    };
    assert_eq!(ans.device_time, Some(recorded));
    // The request is only read.
    let mut after = [0u8; 0x4c];
    port.read(REQUEST, &mut after).unwrap();
    assert_eq!(after, request[..0x4c]);

    // An output buffer or a nonzero extension field refuses without a
    // status or a new record.
    let refused = |ans: &mut Ans,
                   port: &mut Port<'_, '_>,
                   sart: &mut Sart,
                   request: [u8; 80],
                   command: Command| {
        port.write(REQUEST, &request).unwrap();
        let error = ans.execute(0, &command, port, sart).err().unwrap();
        let mut status = [0; 4];
        port.read(REQUEST + 0x4c, &mut status).unwrap();
        assert_eq!(status, [0xff; 4]);
        assert_eq!(ans.device_time, Some(recorded));
        error
    };
    let mut changed = request;
    changed[0x1c] ^= 1;
    let mut output = Command(command.0);
    output.0[52..60].copy_from_slice(&(REQUEST + 0x4000).to_le_bytes());
    output.0[60..64].copy_from_slice(&tunnel_buffer(1).to_le_bytes());
    let error = refused(&mut ans, &mut port, &mut sart, changed, output);
    assert_eq!(
        error,
        refuse!("ANS device-time tunnel fields are not modeled")
    );
    for extension in [0, 0x18, 0x34, 0x4b] {
        let mut extended = changed;
        extended[extension] = 1;
        let error = refused(&mut ans, &mut port, &mut sart, extended, Command(command.0));
        assert_eq!(
            error,
            refuse!("ANS device-time tunnel fields are not modeled")
        );
    }

    // Every census type the die does not serve refuses by its own name
    // before any status write.
    for kind in [
        3u32, 7, 0x0a, 0x0b, 0x0c, 0x0e, 0x11, 0x16, 0x22, 0x37, 0x52, 0x91, 0x97, 0xb1, 0xdd,
        0x309, 0x30a, 0x311,
    ] {
        let mut other = [0u8; 80];
        other[12..16].copy_from_slice(&kind.to_le_bytes());
        other[0x4c..].fill(0xff);
        let error = refused(&mut ans, &mut port, &mut sart, other, Command(command.0));
        assert_eq!(error, unserved_tunnel(kind).into());
        assert_ne!(
            error,
            unserved_tunnel(0x77).into(),
            "type {kind:#x} has a named refusal"
        );
    }
    assert_eq!(
        unserved_tunnel(0x77),
        "ANS tunnel request type or output is not modeled"
    );
}

#[test]
fn sanitize_counter_tunnel_fills_its_whole_output_with_zero_counters() {
    use {stela_contracts::bus::MmioDevice, stela_contracts::bus::Width};
    let mut ans = Ans::new(
        Box::new(RamDisk::new("", 4, 4096)),
        &[Description {
            id: 1,
            kind: 1,
            blocks: 0,
        }],
        None,
    )
    .unwrap();
    let bytes = die::SANITIZE_COUNTER_BYTES as usize;
    let mut memory = Ram::new(0x1000, 0x1000 + bytes);
    let mut sart = Sart::new(Bounds::Exclusive);
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    for (offset, value) in [(0x40, 1), (0x80, 0x101), (0, 0xff)] {
        sart.write(offset, Width::Word, value, &mut access).unwrap();
    }
    let mut port = Port {
        iommu: &mut Physical,
        stream: 0,
        memory: &mut memory,
        access: &mut access,
    };
    let mut request = [0; 80];
    request[12] = 0x0d;
    request[0x4c..].fill(0xff);
    port.write(0x1000, &request).unwrap();
    port.write(0x2000, &alloc::vec![0xa5; bytes]).unwrap();
    let mut command = Command([0; 64]);
    command.0[0] = APPLE_TUNNEL;
    command.0[40] = 1;
    command.0[44..52].copy_from_slice(&0x1000u64.to_le_bytes());
    command.0[52..60].copy_from_slice(&0x2000u64.to_le_bytes());
    command.0[60..64].copy_from_slice(&die::SANITIZE_COUNTER_BYTES.to_le_bytes());
    let status = ans.execute(0, &command, &mut port, &mut sart).unwrap();
    assert_eq!(status.status, SUCCESS);
    let mut output = alloc::vec![0xffu8; bytes];
    port.read(0x2000, &mut output).unwrap();
    // Walk the records as ParseSanitizeCounters does.
    let word = |i: usize| u64::from_le_bytes(output[8 * i..8 * i + 8].try_into().unwrap());
    let (mut i, mut found) = (0, alloc::vec::Vec::new());
    while i < bytes / 8 {
        let (key, count) = (word(i) as u32, (word(i) >> 32) as usize);
        for value in 1..=count {
            found.push((key, word(i + value)));
        }
        i += 1 + count;
    }
    assert_eq!(i, bytes / 8);
    assert_eq!(found, die::SANITIZE_COUNTERS);
    let mut status = [1; 4];
    port.read(0x104c, &mut status).unwrap();
    assert_eq!(status, [0; 4]);
    // Another output size refuses.
    command.0[60..64].copy_from_slice(&4096u32.to_le_bytes());
    assert!(ans.execute(0, &command, &mut port, &mut sart).is_err());
}

#[test]
fn tunable_table_tunnel_records_its_buffer_and_refuses_other_shapes() {
    use {stela_contracts::bus::MmioDevice, stela_contracts::bus::Width};
    let mut ans = Ans::new(
        Box::new(RamDisk::new("", 4, 4096)),
        &[Description {
            id: 1,
            kind: 1,
            blocks: 0,
        }],
        None,
    )
    .unwrap();
    let bytes = tunnel_buffer(1) as usize;
    let mut memory = Ram::new(0x1000, 0x1000 + bytes + 0x1000);
    let mut sart = Sart::new(Bounds::Exclusive);
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    for (offset, value) in [(0x40, 1), (0x80, 6), (0, 0xff)] {
        sart.write(offset, Width::Word, value, &mut access).unwrap();
    }
    let mut port = Port {
        iommu: &mut Physical,
        stream: 0,
        memory: &mut memory,
        access: &mut access,
    };
    // A synthetic 40-byte table at the start of a zeroed buffer, as
    // `SendANS2Table` places it; the type is TT's request type.
    let mut buffer = alloc::vec![0u8; bytes];
    for (i, byte) in buffer[..40].iter_mut().enumerate() {
        *byte = i as u8 ^ 0x5a;
    }
    port.write(0x2000, &buffer).unwrap();
    let mut request = [0; 80];
    request[12..16].copy_from_slice(&110u32.to_le_bytes());
    request[0x4c..].fill(0xff);
    port.write(0x1000, &request).unwrap();
    let mut command = Command([0; 64]);
    command.0[0] = APPLE_TUNNEL;
    command.0[40] = 1;
    command.0[44..52].copy_from_slice(&0x1000u64.to_le_bytes());
    command.0[52..60].copy_from_slice(&0x2000u64.to_le_bytes());
    command.0[60..64].copy_from_slice(&tunnel_buffer(1).to_le_bytes());
    let outcome = ans.execute(0, &command, &mut port, &mut sart).unwrap();
    assert_eq!(outcome.status, SUCCESS);
    let mut status = [1; 4];
    port.read(0x104c, &mut status).unwrap();
    assert_eq!(status, [0; 4]);
    assert_eq!(ans.tunable_tables(), &[(110, bfh::identity(&buffer))]);
    // The table is only read: the buffer is unchanged.
    let mut after = alloc::vec![0u8; bytes];
    port.read(0x2000, &mut after).unwrap();
    assert_eq!(after, buffer);
    // Another length, a request extension field, a V5 kind and a
    // buffer outside the allow-list each refuse without a record.
    let refused = |ans: &mut Ans, port: &mut Port<'_, '_>, sart: &mut Sart, command| {
        assert!(ans.execute(0, &command, port, sart).is_err());
        assert_eq!(ans.tunable_tables().len(), 1);
    };
    let mut other = Command(command.0);
    other.0[60..64].copy_from_slice(&4096u32.to_le_bytes());
    refused(&mut ans, &mut port, &mut sart, other);
    request[20] = 1;
    port.write(0x1000, &request).unwrap();
    refused(&mut ans, &mut port, &mut sart, Command(command.0));
    request[20] = 0;
    request[12..16].copy_from_slice(&332u32.to_le_bytes());
    port.write(0x1000, &request).unwrap();
    refused(&mut ans, &mut port, &mut sart, Command(command.0));
    request[12..16].copy_from_slice(&110u32.to_le_bytes());
    port.write(0x1000, &request).unwrap();
    let mut outside = Command(command.0);
    outside.0[52..60].copy_from_slice(&0x5000u64.to_le_bytes());
    refused(&mut ans, &mut port, &mut sart, outside);
}

#[test]
fn same_layout_format_erases_data_and_preserves_fixed_auxiliary_namespaces() {
    let records = [(1, 1, 0), (2, 8, 3), (3, 13, 2)].map(|(id, kind, blocks)| Description {
        id,
        kind,
        blocks,
    });
    let mut ans = Ans::new(Box::new(RamDisk::new("", 12, 4096)), &records, None).unwrap();
    let mut memory = Ram::new(0x1000, 0x2000);
    let mut sart = Sart::new(Bounds::Exclusive);
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    let mut port = Port {
        iommu: &mut Physical,
        stream: 0,
        memory: &mut memory,
        access: &mut access,
    };
    let io = |ans: &mut Ans, port: &mut Port<'_, '_>, opcode, nsid: u32, lba: u64| {
        let mut command = Command([0; 64]);
        command.0[0] = opcode;
        command.0[4..8].copy_from_slice(&nsid.to_le_bytes());
        command.0[24..32].copy_from_slice(&0x2000u64.to_le_bytes());
        command.0[40..48].copy_from_slice(&lba.to_le_bytes());
        let mut sart = Sart::new(Bounds::Exclusive);
        ans.execute(1, &command, port, &mut sart).unwrap().status
    };
    let mut block = [0; 4096];
    for (nsid, lba, fill) in [
        (1, 6, 0x11),
        (2, 0, 0x22),
        (2, 2, 0x33),
        (3, 0, 0x34),
        (3, 1, 0x35),
    ] {
        port.write(0x2000, &[fill; 4096]).unwrap();
        assert_eq!(io(&mut ans, &mut port, WRITE, nsid, lba), SUCCESS);
    }
    let mut create = Command([0; 64]);
    create.0[0] = APPLE_NAMESPACES;
    create.0[24..32].copy_from_slice(&0x1000u64.to_le_bytes());
    // The provisioned layout, the growable namespace sized either as
    // zero (doFormatMedia without a burn-in count) or its extent.
    let request = |sizes: [u32; 3]| {
        let mut data = alloc::vec![0; 4096];
        data[..4].copy_from_slice(&3u32.to_le_bytes());
        for (i, (record, blocks)) in records.iter().zip(sizes).enumerate() {
            for (j, word) in [record.id, record.kind, blocks].into_iter().enumerate() {
                let at = 4 + 12 * i + 4 * j;
                data[at..at + 4].copy_from_slice(&word.to_le_bytes());
            }
        }
        data
    };
    // Another layout, or creation options, refuse without an erase.
    for (sizes, cdw10) in [([0, 4, 2], 0), ([6, 4, 2], 0), ([0, 3, 2], 1)] {
        port.write(0x1000, &request(sizes)).unwrap();
        create.0[40] = cdw10;
        assert!(ans.execute(0, &create, &mut port, &mut sart).is_err());
        assert_eq!(ans.medium.erased_blocks(), 0);
    }
    create.0[40] = 0;
    for sizes in [[0, 3, 2], [7, 3, 2]] {
        port.write(0x1000, &request(sizes)).unwrap();
        let outcome = ans.execute(0, &create, &mut port, &mut sart).unwrap();
        assert_eq!(outcome.status, SUCCESS);
        assert_eq!(ans.medium.erased_blocks(), 7);
    }
    for (nsid, lba, fill) in [
        (1, 6, 0),
        (2, 0, 0x22),
        (2, 2, 0x33),
        (3, 0, 0x34),
        (3, 1, 0x35),
    ] {
        port.write(0x2000, &[0xff; 4096]).unwrap();
        assert_eq!(io(&mut ans, &mut port, READ, nsid, lba), SUCCESS);
        port.read(0x2000, &mut block).unwrap();
        assert_eq!(block, [fill; 4096], "namespace {nsid} block {lba}");
    }
    port.write(0x2000, &[0x44; 4096]).unwrap();
    assert_eq!(io(&mut ans, &mut port, WRITE, 2, 1), SUCCESS);
    port.write(0x2000, &[0; 4096]).unwrap();
    assert_eq!(io(&mut ans, &mut port, READ, 2, 1), SUCCESS);
    port.read(0x2000, &mut block).unwrap();
    assert_eq!(block, [0x44; 4096]);
    for (nsid, lba, fill) in [(2, 0, 0x22), (2, 1, 0x44), (2, 2, 0x33)] {
        assert_eq!(io(&mut ans, &mut port, READ, nsid, lba), SUCCESS);
        port.read(0x2000, &mut block).unwrap();
        assert_eq!(block, [fill; 4096]);
    }
}

/// With a host executor, an I/O command waits for its transfer, which
/// runs without the controller, and completes once it has.
/// A queued disk whose requests complete once released.
struct Later {
    disk: RamDisk,
    started: Option<stela_drivers::block::Command>,
    released: alloc::sync::Arc<core::sync::atomic::AtomicBool>,
}

impl BlockDevice for Later {
    fn identity(&self) -> &stela_drivers::block::Identity {
        self.disk.identity()
    }
    fn read(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        self.disk.read(lba, buffer)
    }
    fn write(&mut self, lba: u64, data: &[u8]) -> Result<(), BlockError> {
        self.disk.write(lba, data)
    }
    fn depth(&self) -> usize {
        1
    }
    fn room(&self) -> bool {
        self.started.is_none()
    }
    fn start(&mut self, command: stela_drivers::block::Command) -> Result<u32, BlockError> {
        self.started = Some(command);
        Ok(0)
    }
    fn finish(&mut self, _tag: u32) -> Option<Finished> {
        if !self.released.load(core::sync::atomic::Ordering::Relaxed) {
            return None;
        }
        Some(self.disk.execute(self.started.take()?))
    }
    fn posted(&self) -> bool {
        self.started.is_some() && self.released.load(core::sync::atomic::Ordering::Relaxed)
    }
    fn signals(&self) -> bool {
        true
    }
}

#[test]
fn a_queued_host_disk_completes_io_transfers_after_the_doorbell() {
    let records = [Description {
        id: 1,
        kind: 1,
        blocks: 0,
    }];
    let released = alloc::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
    let disk = Later {
        disk: RamDisk::new("", 16, 4096),
        started: None,
        released: released.clone(),
    };
    let mut ans = Ans::new(Box::new(disk), &records, None).unwrap();
    let mut memory = Ram::new(0x1000, 0x3000);
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    let mut port = Port {
        iommu: &mut Physical,
        stream: 0,
        memory: &mut memory,
        access: &mut access,
    };
    let mut sart = Sart::new(Bounds::Exclusive);
    let command = |opcode| {
        let mut command = Command([0; 64]);
        command.0[0] = opcode;
        command.0[4..8].copy_from_slice(&1u32.to_le_bytes());
        command.0[24..32].copy_from_slice(&0x3000u64.to_le_bytes());
        command.0[40..48].copy_from_slice(&3u64.to_le_bytes());
        command
    };
    let mut run = |ans: &mut Ans, port: &mut Port<'_, '_>, opcode| {
        let Ok(Executed::Host(wait)) = ans.execute(1, &command(opcode), port, &mut sart) else {
            panic!("the command waits for its host transfer");
        };
        assert!(
            ans.medium.device.poll(0).is_empty(),
            "the disk has not completed it"
        );
        assert!(!ans.medium.device.posted());
        // The disk signals its completion: a look waits only for a
        // lost signal.
        assert_eq!(ans.medium.device.next_look(0), 24_000);
        released.store(true, core::sync::atomic::Ordering::Relaxed);
        assert!(ans.medium.device.posted());
        let mut done = ans.medium.device.poll(0);
        released.store(false, core::sync::atomic::Ordering::Relaxed);
        assert_eq!(done.len(), 1);
        let (key, done) = done.pop().unwrap();
        assert_eq!(key, 1 << 16, "queue 1, tag 0");
        ans.finish(wait, Some(done), port).unwrap().status
    };
    port.write(0x3000, &[0x5a; 4096]).unwrap();
    assert_eq!(run(&mut ans, &mut port, WRITE), SUCCESS);
    port.write(0x3000, &[0; 4096]).unwrap();
    assert_eq!(run(&mut ans, &mut port, READ), SUCCESS);
    let mut block = [0; 4096];
    port.read(0x3000, &mut block).unwrap();
    assert_eq!(block, [0x5a; 4096]);
}

#[test]
fn dataset_management_deallocates_checked_ranges_and_reads_zero() {
    let records =
        [(1, 1, 0), (2, 0xd, 8)].map(|(id, kind, blocks)| Description { id, kind, blocks });
    let mut ans = Ans::new(Box::new(RamDisk::new("", 16, 4096)), &records, None).unwrap();
    let mut memory = Ram::new(0x1000, 0x3000);
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    let mut port = Port {
        iommu: &mut Physical,
        stream: 0,
        memory: &mut memory,
        access: &mut access,
    };
    let mut sart = Sart::new(Bounds::Exclusive);
    let rw = |ans: &mut Ans, port: &mut Port<'_, '_>, opcode, lba: u64| {
        let mut command = Command([0; 64]);
        command.0[0] = opcode;
        command.0[4..8].copy_from_slice(&2u32.to_le_bytes());
        command.0[24..32].copy_from_slice(&0x3000u64.to_le_bytes());
        command.0[40..48].copy_from_slice(&lba.to_le_bytes());
        let mut sart = Sart::new(Bounds::Exclusive);
        ans.execute(1, &command, port, &mut sart).unwrap().status
    };
    for lba in 0..8 {
        port.write(0x3000, &[0x5a; 4096]).unwrap();
        assert_eq!(rw(&mut ans, &mut port, WRITE, lba), SUCCESS);
    }
    // The range list as `unmapBlocks` and `doUnmapNVMe` fill it.
    let list = |ranges: &[(u32, u32, u64)]| {
        let mut data = alloc::vec![0; 4096];
        for (i, &(context, blocks, lba)) in ranges.iter().enumerate() {
            let at = i * RANGE_BYTES;
            data[at..at + 4].copy_from_slice(&context.to_le_bytes());
            data[at + 4..at + 8].copy_from_slice(&blocks.to_le_bytes());
            data[at + 8..at + 16].copy_from_slice(&lba.to_le_bytes());
        }
        data
    };
    let dsm = |count: u32, attributes: u32| {
        let mut command = Command([0; 64]);
        command.0[0] = DATASET_MANAGEMENT;
        command.0[4..8].copy_from_slice(&2u32.to_le_bytes());
        command.0[24..32].copy_from_slice(&0x2000u64.to_le_bytes());
        command.0[40..44].copy_from_slice(&count.to_le_bytes());
        command.0[44..48].copy_from_slice(&attributes.to_le_bytes());
        command
    };
    assert_eq!(dsm(0, DEALLOCATE).direction(1), Ok(2));
    // A range past the namespace fails the whole command unchanged.
    port.write(0x2000, &list(&[(0, 2, 0), (0, 2, 7)])).unwrap();
    let outcome = ans
        .execute(1, &dsm(1, DEALLOCATE), &mut port, &mut sart)
        .unwrap();
    assert_eq!(outcome.status, LBA_RANGE);
    assert_eq!(ans.erased_blocks(), 0);
    // Hints, reserved fields and context attributes refuse.
    for (count, attributes) in [(0, 1 | DEALLOCATE), (0, 0), (0x100, DEALLOCATE)] {
        assert!(
            ans.execute(1, &dsm(count, attributes), &mut port, &mut sart)
                .is_err()
        );
    }
    port.write(0x2000, &list(&[(1, 1, 0)])).unwrap();
    assert!(
        ans.execute(1, &dsm(0, DEALLOCATE), &mut port, &mut sart)
            .is_err()
    );
    assert_eq!(ans.erased_blocks(), 0);
    // eanFormat's whole-namespace range, then two ranges of one command.
    port.write(0x2000, &list(&[(0, 8, 0)])).unwrap();
    let outcome = ans
        .execute(1, &dsm(0, DEALLOCATE), &mut port, &mut sart)
        .unwrap();
    assert_eq!(outcome.status, SUCCESS);
    assert_eq!(ans.erased_blocks(), 8);
    let mut block = [0; 4096];
    for lba in [0, 7] {
        port.write(0x3000, &[0xff; 4096]).unwrap();
        assert_eq!(rw(&mut ans, &mut port, READ, lba), SUCCESS);
        port.read(0x3000, &mut block).unwrap();
        assert_eq!(block, [0; 4096]);
    }
    port.write(0x3000, &[0x77; 4096]).unwrap();
    assert_eq!(rw(&mut ans, &mut port, WRITE, 3), SUCCESS);
    assert_eq!(ans.erased_blocks(), 7);
    port.write(0x2000, &list(&[(0, 1, 3), (0, 0, 5)])).unwrap();
    let outcome = ans
        .execute(1, &dsm(1, DEALLOCATE), &mut port, &mut sart)
        .unwrap();
    assert_eq!(outcome.status, SUCCESS);
    assert_eq!(ans.erased_blocks(), 8);
    assert_eq!(rw(&mut ans, &mut port, READ, 3), SUCCESS);
    port.read(0x3000, &mut block).unwrap();
    assert_eq!(block, [0; 4096]);
}

/// Deallocated blocks read as zeros past a restart (DLFEAT 001b) only
/// where the host's Write Zeroes deallocates them.
#[test]
fn identify_reports_dataset_management_and_zero_reads() {
    for unmap in [false, true] {
        let mut disk = RamDisk::new("", 4, 4096);
        disk.identity.features.write_zeroes =
            Some(stela_drivers::block::WriteZeroes { blocks: 4, unmap });
        identify_dataset_management(disk, if unmap { DLFEAT_READ_ZEROS } else { 0 });
    }
}

fn identify_dataset_management(disk: RamDisk, dlfeat: u8) {
    let mut ans = Ans::new(
        Box::new(disk),
        &[Description {
            id: 1,
            kind: 1,
            blocks: 0,
        }],
        None,
    )
    .unwrap();
    let mut memory = Ram::new(0x1000, 4096);
    let mut sart = Sart::new(Bounds::Exclusive);
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    let mut port = Port {
        iommu: &mut Physical,
        stream: 0,
        memory: &mut memory,
        access: &mut access,
    };
    let mut data = [0; 4096];
    for (cns, nsid) in [(1u8, 0u32), (0, 1)] {
        let mut command = Command([0; 64]);
        command.0[0] = IDENTIFY;
        command.0[4..8].copy_from_slice(&nsid.to_le_bytes());
        command.0[24..32].copy_from_slice(&0x1000u64.to_le_bytes());
        command.0[40] = cns;
        let outcome = ans.execute(0, &command, &mut port, &mut sart).unwrap();
        assert_eq!(outcome.status, SUCCESS);
        port.read(0x1000, &mut data).unwrap();
        if cns == 1 {
            assert_eq!(u16::from_le_bytes([data[520], data[521]]), ONCS);
        } else {
            assert_eq!(data[33], dlfeat);
        }
    }
}

#[test]
fn firmware_uuid_identify_refuses_by_name() {
    let mut command = Command([0; 64]);
    command.0[0] = APPLE_IDENTIFY_STORAGE;
    let refusal = command.direction(0).unwrap_err();
    assert!(
        refusal
            .to_string()
            .contains("Identify Storage Device (0xc8)")
    );
}

#[test]
fn queue_commands_carry_no_nvmmu_dma_permission() {
    for opcode in [CREATE_SQ, CREATE_CQ, DELETE_SQ, DELETE_CQ] {
        let mut command = Command([0; 64]);
        command.0[0] = opcode;
        assert_eq!(command.direction(0), Ok(0));
    }
}

#[test]
fn unknown_vendor_effects_refuse_without_dma() {
    let mut ans = Ans::new(
        Box::new(RamDisk::new("", 4, 4096)),
        &[Description {
            id: 1,
            kind: 1,
            blocks: 0,
        }],
        None,
    )
    .unwrap();
    let mut memory = Ram::new(0x1000, 4096);
    let mut sart = Sart::new(Bounds::Exclusive);
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    let mut port = Port {
        iommu: &mut Physical,
        stream: 0,
        memory: &mut memory,
        access: &mut access,
    };
    let mut command = Command([0; 64]);
    command.0[0] = APPLE_TUNNEL;
    assert!(ans.execute(0, &command, &mut port, &mut sart).is_err());
    assert_eq!(ans.os_build, [0; 16]);
    command.0[0] = 0xc2;
    assert!(ans.execute(0, &command, &mut port, &mut sart).is_err());
}

#[test]
fn queue_count_and_feature_refusals_do_not_invent_effects() {
    let mut ans = Ans::new(
        Box::new(RamDisk::new("", 4, 4096)),
        &[Description {
            id: 1,
            kind: 1,
            blocks: 0,
        }],
        None,
    )
    .unwrap();
    let mut command = Command([0; 64]);
    command.0[0] = SET_FEATURES;
    command.0[40] = 7;
    let outcome = ans.feature(&command).unwrap();
    assert_eq!(outcome.result, 0);
    assert_eq!(outcome.status, SUCCESS);
    command.0[40] = 6;
    command.0[44] = 1;
    assert!(ans.feature(&command).is_err());
    assert_eq!(ans.features[6], 0);
    command.0[44] = 0;
    command.0[43] = 0x80;
    assert!(ans.feature(&command).is_err());
    command.0[43] = 0;
    command.0[1] = 0x40;
    assert!(command.validate().is_err());
}
