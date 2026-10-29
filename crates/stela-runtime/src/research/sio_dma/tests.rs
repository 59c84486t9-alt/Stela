use super::*;
use {
    stela_contracts::dma::Physical, stela_contracts::dma::test_support::Ram,
    stela_contracts::interrupt::InterruptLatch,
};

const RAM: u64 = 0x8000;
const BUFFER: u64 = RAM + 0x2000;

fn descriptor(ram: &mut Ram, slot: u32, segments: &[(u64, u32)]) {
    let start = slot as usize * SLOT_BYTES as usize;
    ram.bytes[start + COUNT_OFFSET..start + COUNT_OFFSET + 4]
        .copy_from_slice(&(segments.len() as u32).to_le_bytes());
    for (index, &(address, bytes)) in segments.iter().enumerate() {
        let start = start + HEADER_BYTES + index * SEGMENT_BYTES;
        ram.bytes[start..start + 8].copy_from_slice(&address.to_le_bytes());
        ram.bytes[start + 8..start + 12].copy_from_slice(&bytes.to_le_bytes());
    }
}

fn pool() -> Pool {
    Pool {
        iova: RAM,
        slots: 0xaaa,
        layout: DescriptorLayout::ScatterGather72,
    }
}

#[test]
fn original_scatter_gather_reports_only_after_peripheral_delivery() {
    let mut ram = Ram::new(RAM, 0x8000);
    ram.bytes[0x2000..0x2008].copy_from_slice(b"abcdefgh");
    descriptor(&mut ram, 8, &[(BUFFER, 3), (BUFFER + 3, 5)]);
    let mut channel = Channel::transmit(100, 4).unwrap();
    let mut latch = InterruptLatch::new();
    let mut access = stela_contracts::bus::Access::new(0, 0, &mut latch);
    let mut physical = Physical;
    let mut port = Port {
        iommu: &mut physical,
        stream: 2,
        memory: &mut ram,
        access: &mut access,
    };
    channel.submit(pool(), 8, 0x82, &mut port).unwrap();
    assert_eq!(channel.advance(&mut port), Ok(4));
    assert_eq!(channel.remaining_bytes(), Some(4));
    assert_eq!(channel.completion(), None);
    assert_eq!(channel.advance(&mut port), Ok(0));
    let mut samples = [0; 8];
    assert_eq!(channel.consume(&mut samples[..4]), 4);
    assert_eq!(channel.advance(&mut port), Ok(4));
    assert_eq!(channel.remaining_bytes(), Some(0));
    assert_eq!(channel.remaining_delivery_bytes(), Some(4));
    assert_eq!(channel.completion(), None);
    assert_eq!(channel.consume(&mut samples[4..]), 4);
    assert_eq!(&samples, b"abcdefgh");
    let completion = channel.completion().unwrap();
    assert_eq!(
        completion,
        Completion {
            channel: 100,
            tag: 0x82,
            bytes: 8
        }
    );
    assert_eq!(completion.report(), 0x0000000880688264);
    assert!(channel.submit(pool(), 8, 0x82, &mut port).is_err());
    assert!(
        channel
            .acknowledge_completion(Completion {
                tag: 0x83,
                ..completion
            })
            .is_err()
    );
    assert_eq!(channel.completion(), Some(completion));
    channel.acknowledge_completion(completion).unwrap();
    assert_eq!(channel.completion(), None);
}

#[test]
fn kept_clock_and_quiesce_pause_dma_and_fifo_without_completing_work() {
    let mut ram = Ram::new(RAM, 0x8000);
    ram.bytes[0x2000..0x2004].copy_from_slice(b"data");
    descriptor(&mut ram, 1, &[(BUFFER, 4)]);
    let mut channel = Channel::transmit(102, 2).unwrap();
    let mut latch = InterruptLatch::new();
    let mut access = stela_contracts::bus::Access::new(0, 0, &mut latch);
    let mut physical = Physical;
    let mut port = Port {
        iommu: &mut physical,
        stream: 2,
        memory: &mut ram,
        access: &mut access,
    };
    channel.submit(pool(), 1, 1, &mut port).unwrap();
    channel.advance(&mut port).unwrap();
    let initial = channel.state;
    for state in [
        LifecycleState {
            clocked: false,
            ..initial
        },
        LifecycleState {
            quiesced: true,
            ..initial
        },
        LifecycleState {
            powered: false,
            retention: true,
            ..initial
        },
    ] {
        channel.check_lifecycle(state).unwrap();
        channel.set_lifecycle(state);
        assert_eq!(channel.advance(&mut port), Ok(0));
        assert_eq!(channel.consume(&mut [0; 2]), 0);
        assert_eq!(channel.pending_bytes(), 2);
        assert_eq!(channel.remaining_bytes(), Some(2));
        assert_eq!(channel.completion(), None);
    }
    for state in [
        LifecycleState {
            reset: true,
            ..initial
        },
        LifecycleState {
            powered: false,
            ..initial
        },
    ] {
        assert!(channel.check_lifecycle(state).is_err());
        assert_eq!(channel.remaining_bytes(), Some(2));
        assert_eq!(channel.pending_bytes(), 2);
    }
    channel.set_lifecycle(initial);
    let mut samples = [0; 4];
    assert_eq!(channel.consume(&mut samples[..2]), 2);
    assert_eq!(channel.advance(&mut port), Ok(2));
    assert_eq!(channel.consume(&mut samples[2..]), 2);
    assert_eq!(&samples, b"data");
    assert_eq!(channel.completion().unwrap().bytes, 4);
}

#[test]
fn later_dma_fault_preserves_committed_chunks_and_pinned_scatter_gather_ownership() {
    let mut ram = Ram::new(RAM, 0x3000);
    ram.bytes[0x2000..0x2004].copy_from_slice(b"once");
    descriptor(&mut ram, 1, &[(BUFFER, 4), (RAM + 0x3000, 4)]);
    let mut channel = Channel::transmit(100, 8).unwrap();
    let mut latch = InterruptLatch::new();
    let mut access = stela_contracts::bus::Access::new(0, 0, &mut latch);
    let mut physical = Physical;
    let mut port = Port {
        iommu: &mut physical,
        stream: 2,
        memory: &mut ram,
        access: &mut access,
    };
    channel.submit(pool(), 1, 7, &mut port).unwrap();
    assert_eq!(
        channel.advance(&mut port),
        Err(Error::Dma(DmaError::Memory))
    );
    assert_eq!(channel.pending_bytes(), 4);
    assert_eq!(channel.remaining_bytes(), Some(4));
    assert_eq!(channel.completion(), None);
    // Alter the guest table after acquisition, then make only the original
    // second segment available. Retry must not duplicate or redirect it.
    descriptor(&mut ram, 1, &[(BUFFER + 100, 4)]);
    ram.bytes.resize(0x4000, 0);
    ram.bytes[0x3000..0x3004].copy_from_slice(b"next");
    let mut port = Port {
        iommu: &mut physical,
        stream: 2,
        memory: &mut ram,
        access: &mut access,
    };
    assert_eq!(channel.advance(&mut port), Ok(4));
    let mut samples = [0; 8];
    assert_eq!(channel.consume(&mut samples), 8);
    assert_eq!(&samples, b"oncenext");
    assert_eq!(channel.completion().unwrap().bytes, 8);
}

#[test]
fn configure_and_issue_ack_real_effects_and_unknown_controls_never_ack() {
    let mut ram = Ram::new(RAM, 0x8000);
    ram.bytes[0x2000..0x2004].copy_from_slice(b"word");
    descriptor(&mut ram, 8, &[(BUFFER, 4)]);
    let mut channel = Channel::transmit(100, 8).unwrap();
    let mut latch = InterruptLatch::new();
    let mut access = stela_contracts::bus::Access::new(0, 0, &mut latch);
    let mut physical = Physical;
    let configure = 100 | 7 << 8 | 5 << 16;
    let issue = 100 | 9 << 8 | 6 << 16 | 8 << 32;
    {
        let mut port = Port {
            iommu: &mut physical,
            stream: 2,
            memory: &mut ram,
            access: &mut access,
        };
        assert!(channel.command(pool(), issue, &mut port).is_err());
    }
    for (index, word) in [2u32, 0, 8, 8, 8, 0].into_iter().enumerate() {
        ram.bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    {
        let mut port = Port {
            iommu: &mut physical,
            stream: 2,
            memory: &mut ram,
            access: &mut access,
        };
        assert_eq!(
            channel.command(pool(), configure, &mut port),
            Ok(100 | 7 << 8 | 0x65 << 16 | 5 << 32)
        );
        assert_eq!(channel.configuration().unwrap().word_bytes, 4);
        for unsupported in [
            100 | 2 << 16,
            100 | 3 << 16,
            100 | 8 << 16 | 1 << 32,
            issue | 1 << 24,
            issue ^ 1,
        ] {
            assert!(channel.command(pool(), unsupported, &mut port).is_err());
            assert_eq!(channel.remaining_bytes(), None);
        }
        assert_eq!(
            channel.command(pool(), issue, &mut port),
            Ok(100 | 9 << 8 | 0x65 << 16 | 6 << 32)
        );
        assert_eq!(channel.completion(), None);
        assert!(channel.command(pool(), configure, &mut port).is_err());
        assert_eq!(channel.advance(&mut port), Ok(4));
    }
    let mut samples = [0; 4];
    assert_eq!(channel.consume(&mut samples), 4);
    assert_eq!(&samples, b"word");
    let completion = channel.completion().unwrap();
    channel.acknowledge_completion(completion).unwrap();
    let before = channel.configuration();
    // A nonzero extra original word must not disappear behind an ACK.
    ram.bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    let mut port = Port {
        iommu: &mut physical,
        stream: 2,
        memory: &mut ram,
        access: &mut access,
    };
    assert!(channel.command(pool(), configure, &mut port).is_err());
    assert_eq!(channel.configuration(), before);
    assert_eq!(channel.remaining_bytes(), None);
}

#[test]
fn software_termination_reports_peripheral_delivery_and_keeps_undelivered_fifo_ownership() {
    let mut ram = Ram::new(RAM, 0x8000);
    ram.bytes[0x2000..0x2008].copy_from_slice(b"keeprest");
    descriptor(&mut ram, 1, &[(BUFFER, 8)]);
    let mut channel = Channel::transmit(100, 4).unwrap();
    let mut latch = InterruptLatch::new();
    let mut access = stela_contracts::bus::Access::new(0, 0, &mut latch);
    let mut physical = Physical;
    let mut port = Port {
        iommu: &mut physical,
        stream: 2,
        memory: &mut ram,
        access: &mut access,
    };
    channel.submit(pool(), 1, 17, &mut port).unwrap();
    channel.advance(&mut port).unwrap();
    let mut consumed = [0; 2];
    assert_eq!(channel.consume(&mut consumed), 2);
    assert_eq!(&consumed, b"ke");
    assert_eq!(channel.remaining_delivery_bytes(), Some(6));
    assert_eq!(
        channel.command(pool(), 100 | 99 << 8 | 8 << 16, &mut port),
        Ok(100 | 99 << 8 | 0x65 << 16 | 8 << 32)
    );
    let report = Completion {
        channel: 100,
        tag: 17,
        bytes: 2,
    };
    assert_eq!(channel.completion(), Some(report));
    assert_eq!(channel.remaining_bytes(), None);
    assert_eq!(channel.advance(&mut port), Ok(0));
    assert_eq!(channel.pending_bytes(), 2);
    assert_eq!(channel.fifo.iter().copied().collect::<Vec<_>>(), b"ep");
    assert_eq!(channel.consume(&mut [0; 8]), 0);
    assert!(channel.submit(pool(), 1, 17, &mut port).is_err());
    channel.terminate().unwrap();
    assert_eq!(channel.completions.len(), 1);
    channel.acknowledge_completion(report).unwrap();
    assert_eq!(channel.completion(), None);
    // Clock/power resume cannot undo a software stop or discard its FIFO.
    let initial = channel.state;
    for paused in [
        LifecycleState {
            clocked: false,
            ..initial
        },
        LifecycleState {
            powered: false,
            retention: true,
            ..initial
        },
        LifecycleState {
            quiesced: true,
            ..initial
        },
    ] {
        channel.check_lifecycle(paused).unwrap();
        channel.set_lifecycle(paused);
        channel.set_lifecycle(initial);
        assert_eq!(channel.consume(&mut [0; 8]), 0);
        assert_eq!(channel.advance(&mut port), Ok(0));
        assert_eq!(channel.pending_bytes(), 2);
        assert!(channel.submit(pool(), 1, 18, &mut port).is_err());
    }
    // A distinct command canceled before any delivery reports zero,
    // even when all its DMA bytes already reached the FIFO.
    let mut channel = Channel::transmit(100, 8).unwrap();
    channel.submit(pool(), 1, 17, &mut port).unwrap();
    channel.advance(&mut port).unwrap();
    assert_eq!(channel.remaining_bytes(), Some(0));
    assert_eq!(channel.completion(), None);
    channel.terminate().unwrap();
    assert_eq!(channel.completion().unwrap().bytes, 0);
    assert_eq!(channel.pending_bytes(), 8);
}

#[test]
fn dart_clock_and_stream_faults_cannot_be_substituted_for_dma_success() {
    use {
        crate::platform::apple::dart::Dart, stela_contracts::bus::Access,
        stela_contracts::bus::MmioDevice, stela_contracts::bus::Width,
    };
    let mut ram = Ram::new(RAM, 0x8000);
    ram.bytes[0x2000..0x2004].copy_from_slice(b"real");
    descriptor(&mut ram, 1, &[(BUFFER, 4)]);
    let mut channel = Channel::transmit(100, 4).unwrap();
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    let mut dart = Dart::new(16, None);
    {
        let mut port = Port {
            iommu: &mut dart,
            stream: 2,
            memory: &mut ram,
            access: &mut access,
        };
        assert!(matches!(
            channel.submit(pool(), 1, 9, &mut port),
            Err(Error::Dma(DmaError::Fault(_)))
        ));
        assert_eq!(channel.remaining_bytes(), None);
        assert_eq!(channel.completion(), None);
    }
    dart.write(0xc00, Width::Word, 4, &mut access).unwrap();
    dart.write(0x1008, Width::Word, 6, &mut access).unwrap();
    let mut port = Port {
        iommu: &mut dart,
        stream: 2,
        memory: &mut ram,
        access: &mut access,
    };
    channel.submit(pool(), 1, 9, &mut port).unwrap();
    dart.set_clock(false);
    let mut port = Port {
        iommu: &mut dart,
        stream: 2,
        memory: &mut ram,
        access: &mut access,
    };
    assert!(matches!(
        channel.advance(&mut port),
        Err(Error::Dma(DmaError::Unsupported(_)))
    ));
    assert_eq!(channel.pending_bytes(), 0);
    assert_eq!(channel.remaining_bytes(), Some(4));
    assert_eq!(channel.completion(), None);
    dart.set_clock(true);
    let mut port = Port {
        iommu: &mut dart,
        stream: 2,
        memory: &mut ram,
        access: &mut access,
    };
    assert_eq!(channel.advance(&mut port), Ok(4));
    let mut samples = [0; 4];
    assert_eq!(channel.consume(&mut samples), 4);
    assert_eq!(&samples, b"real");
}

#[test]
#[ignore = "oracle: STELA_TEST_SIO_KERNELCACHE"]
fn original_controller_proves_pool_header_segments_and_terminal_report_layout() {
    use sha2::{Digest, Sha256};
    let path =
        std::env::var("STELA_TEST_SIO_KERNELCACHE").expect("pinned original kernelcache path");
    let bytes = std::fs::read(path).unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&bytes)),
        "06846c718a67715f540c7f5a5d5a183da6185d94b6fc01f1ce57a30b601be44d"
    );
    // Original instructions are source-integrity evidence for this
    // ABI. Production dispatch never consults offsets or input hashes.
    for (offset, opcode) in [
        (0x2e660f4, 0x52800189),
        (0x2e66134, 0x11001829),
        (0x2e66a84, 0x2907201f),
        (0x2e67568, 0xf9000161),
        (0x2e67584, 0xb9000162),
        (0x2e66a98, 0x528000c8),
        (0x2e67804, 0x7101a11f),
        (0x2e67810, 0x36f803c8),
        (0x2e650f0, 0x52815542),
        (0x2e64f7c, 0x528fff02),
        (0x2e673e8, 0xb9001409),
    ] {
        assert_eq!(
            u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()),
            opcode,
            "original SIO driver at {offset:#x}"
        );
    }
}

#[test]
#[ignore = "oracle: STELA_TEST_SIO_FIRMWARE"]
fn original_firmware_excludes_undelivered_fifo_bytes_from_tx_stop_report() {
    use sha2::{Digest, Sha256};
    let path = std::env::var("STELA_TEST_SIO_FIRMWARE").expect("pinned original SIO firmware path");
    let bytes = std::fs::read(path).unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&bytes)),
        "356dbeba0e7f5d0a36e3db2eddce66dca6869e8629aa322f4da1addf0a9780cc"
    );
    // Original PRELOAD __TEXT VA0 has file offset0x1000. The stop path
    // queries progress adjusted for TX FIFO occupancy before REPORT.
    // These bounded source-integrity checks never affect production.
    for (address, opcode) in [
        (0x17f8, 0xf9410809),
        (0x1804, 0xb9402120),
        (0x1828, 0x11007108),
        (0x182c, 0xb8684928),
        (0x1830, 0x12003908),
        (0x1834, 0x4b080148),
        (0x1838, 0x4b282000),
        (0x31c4, 0x97fff99f),
        (0x31cc, 0x97fff98b),
        (0x31d4, 0x36f81840),
        (0x3e14, 0x52900d08),
        (0x3e28, 0x3940c029),
        (0x3e2c, 0xb940142a),
        (0x3e3c, 0xb9000fea),
        (0x3e4c, 0x3d800000),
        (0x45b8, 0x39400823),
        (0x45d4, 0xaa03814a),
    ] {
        let offset = address + 0x1000;
        assert_eq!(
            u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()),
            opcode,
            "original SIO firmware at VA{address:#x}"
        );
    }
}

#[test]
fn malformed_or_out_of_pool_descriptors_refuse_before_command_ownership() {
    let mut ram = Ram::new(RAM, 0x8000);
    let mut channel = Channel::transmit(100, 8).unwrap();
    let mut latch = InterruptLatch::new();
    let mut access = stela_contracts::bus::Access::new(0, 0, &mut latch);
    let mut physical = Physical;
    for segments in [
        vec![],
        vec![(u64::MAX - 1, 4)],
        vec![(BUFFER, 0)],
        vec![(BUFFER, u32::MAX), (BUFFER, 1)],
    ] {
        descriptor(&mut ram, 1, &segments);
        let mut port = Port {
            iommu: &mut physical,
            stream: 2,
            memory: &mut ram,
            access: &mut access,
        };
        assert!(channel.submit(pool(), 1, 1, &mut port).is_err());
        assert_eq!(channel.remaining_bytes(), None);
        assert_eq!(channel.pending_bytes(), 0);
    }
    let mut port = Port {
        iommu: &mut physical,
        stream: 2,
        memory: &mut ram,
        access: &mut access,
    };
    assert!(channel.submit(pool(), 0xaaa, 1, &mut port).is_err());
    for invalid in [
        Pool {
            slots: u32::MAX,
            ..pool()
        },
        Pool {
            iova: u64::MAX - 0xfff,
            ..pool()
        },
        Pool {
            iova: RAM + 1,
            ..pool()
        },
    ] {
        assert!(channel.submit(invalid, 1, 1, &mut port).is_err());
        assert_eq!(channel.remaining_bytes(), None);
    }
    assert!(Channel::transmit(101, 8).is_err());
    assert!(Channel::transmit(0xe6, 8).is_err());
}
