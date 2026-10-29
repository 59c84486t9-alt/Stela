// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2003-2015, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
//! Source scheduler queue wire preparation and unpublished canonical DMA.
//! No method publishes addresses, installs a firmware station, grants queue
//! ownership or treats a parsed firmware reply as HCMD completion.
use crate::{
    bus::dma::{
        mapping::{Direction, DmaDomain},
        memory::PageSource,
    },
    net::wifi::intel::{
        command::{Id, Tfd},
        context::Region,
        dma::{self, Chunk},
        firmware::{Family, Firmware},
    },
};
use alloc::{sync::Arc, vec};
mod native;
pub(in crate::net::wifi::intel) use native::NativeMemory;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Version,
    StationMask,
    Tid,
    Slots,
    Region,
    ReplyLength,
    Rejected(u16),
    Queue(u16),
    Dma(dma::Error),
    Descriptor(crate::net::wifi::intel::command::Error),
}
fn negotiate(fw: &Firmware<'_>) -> Result<(), Error> {
    if !fw
        .command_version(5, 0x17)
        .is_some_and(|v| v.command_version == 3 && v.notification_version == 2)
    {
        return Err(Error::Version);
    }
    Ok(())
}
fn initial_slots(family: Family) -> u16 {
    if family == Family::Ax200 { 16 } else { 128 }
}
fn bc_bytes(family: Family) -> usize {
    if family == Family::Ax200 { 640 } else { 2048 }
}
fn range(region: Region, bytes: usize, alignment: u64) -> Result<core::ops::Range<u64>, Error> {
    if region.bytes != bytes || region.address & (alignment - 1) != 0 {
        return Err(Error::Region);
    }
    Ok(region.address
        ..region
            .address
            .checked_add(bytes as u64)
            .ok_or(Error::Region)?)
}
fn geometry(
    family: Family,
    slots: usize,
    byte_counts: Region,
    descriptors: Region,
) -> Result<(), Error> {
    let maximum = if family == Family::Ax200 { 256 } else { 1024 };
    if !(16..=maximum).contains(&slots) || !slots.is_power_of_two() {
        return Err(Error::Slots);
    }
    let bc = range(byte_counts, bc_bytes(family), 256)?;
    let tfd = range(descriptors, slots * 256, 4096)?;
    if bc.start < tfd.end && tfd.start < bc.end {
        return Err(Error::Region);
    }
    Ok(())
}
/// Copied source inputs, never firmware-station or DMA ownership.
#[derive(Clone, Copy, Debug)]
pub struct Parameters {
    pub station_mask: u32,
    /// Source TIDs 0..15; IWL_MGMT_TID=15 represents non-QoS/management.
    pub tid: u8,
    pub slots: u16,
    /// Source byte-count pool alignment256, with complete family table size.
    pub byte_counts: Region,
    /// Initial native coherent ring profile keeps source page alignment.
    pub descriptors: Region,
}
pub struct Configuration {
    family: Family,
    bytes: [u8; 36],
}
impl Configuration {
    pub fn prepare(
        fw: &Firmware<'_>,
        family: Family,
        parameters: Parameters,
    ) -> Result<Self, Error> {
        negotiate(fw)?;
        Self::encode(family, parameters)
    }
    fn encode(family: Family, p: Parameters) -> Result<Self, Error> {
        if p.station_mask == 0 {
            return Err(Error::StationMask);
        }
        if p.tid > 15 {
            return Err(Error::Tid);
        }
        let slots = usize::from(p.slots);
        geometry(family, slots, p.byte_counts, p.descriptors)?;
        let mut bytes = [0; 36]; // operation ADD=0; reserved bytes/short-TFD flags zero
        bytes[4..8].copy_from_slice(&p.station_mask.to_le_bytes());
        bytes[8] = p.tid;
        bytes[16..20].copy_from_slice(&(slots.ilog2() - 3).to_le_bytes());
        bytes[20..28].copy_from_slice(&p.byte_counts.address.to_le_bytes());
        bytes[28..36].copy_from_slice(&p.descriptors.address.to_le_bytes());
        Ok(Self { family, bytes })
    }
    /// Source call site uses WIDE_ID(group5,0x17), without CMD version bits.
    /// The negotiated command3 chooses this body; the wire header stays zero.
    pub fn id(&self) -> Id {
        Id {
            group: 5,
            opcode: 0x17,
            version: 0,
        }
    }
    pub fn payload(&self) -> &[u8; 36] {
        &self.bytes
    }
    pub fn parse_reply(&self, bytes: &[u8]) -> Result<Reply, Error> {
        if bytes.len() != 8 {
            return Err(Error::ReplyLength);
        }
        let half = |at| u16::from_le_bytes([bytes[at], bytes[at + 1]]);
        let flags = half(2);
        // txq.h explicitly documents flags as set on failure. Do not repeat
        // Linux alloc_response's omission of this semantic refusal.
        if flags != 0 {
            return Err(Error::Rejected(flags));
        }
        let queue = half(0);
        if queue >= 512 {
            return Err(Error::Queue(queue));
        }
        let raw_write_pointer = half(4);
        Ok(Reply {
            queue,
            raw_write_pointer,
            write_pointer: if self.family == Family::Ax200 {
                raw_write_pointer & 255
            } else {
                raw_write_pointer
            },
            reserved: half(6),
        })
    }
}
/// Pure reply fields. The owner must first match the real HCMD ticket,
/// native epoch and unique queue registry (including existing command queue0).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reply {
    pub queue: u16,
    pub raw_write_pointer: u16,
    pub write_pointer: u16,
    pub reserved: u16,
}

/// Four kept native DMA allocations which have never been published.
/// This type has no publish/doorbell API. A future real firmware
/// station/queue owner must consume and keep it with the BAR/requester
/// before exposing any address, then use completion/stop/CPU handoffs.
/// Queue creation completion does not retire its persistent maps; removal or
/// stopped-requester proof and relevant work drain must end their ownership.
/// Bidirectional permissions/WB attributes alone do not check requester
/// coherence, NoSnoop or ATS; the publisher must establish those too.
/// Copying its diagnostic layout never grants that permission. Construction
/// and final Drop run in process/deferred context, never a hard IRQ handler.
pub struct UnpublishedQueue {
    family: Family,
    byte_counts: Chunk,
    descriptors: Chunk,
    first: Chunk,
    invalid: Chunk,
}
#[derive(Clone, Copy, Debug)]
pub struct Layout {
    pub byte_counts: Region,
    pub descriptors: Region,
    pub first: Region,
    pub invalid: Region,
}
impl UnpublishedQueue {
    /// Initial non-QoS/management window: source16 entries, raised to
    /// the AX210 family minimum128 by mvm/sta.c::iwl_mvm_tvqm_enable_txq.
    pub fn slots(&self) -> u16 {
        initial_slots(self.family)
    }
    pub fn prepare(
        fw: &Firmware<'_>,
        family: Family,
        source: &dyn PageSource,
        domain: Arc<dyn DmaDomain>,
    ) -> Result<Self, Error> {
        negotiate(fw)?; // no native allocation when the ABI is absent
        let allocate = |bytes: &[u8]| {
            Chunk::allocate(source, domain.clone(), bytes, Direction::Bidirectional)
                .map_err(Error::Dma)
        };
        let byte_counts = allocate(&vec![0; bc_bytes(family)])?;
        let descriptors = allocate(&vec![0; usize::from(initial_slots(family)) * 256])?;
        let first = allocate(&vec![0; usize::from(initial_slots(family)) * 64])?;
        let invalid = allocate(&[6, 0xf, 0xff, 0xff, 0, 0, 0, 0])?;
        let tfd = Tfd::encode(&[invalid.region()]).map_err(Error::Descriptor)?;
        let mut ring = alloc::vec::Vec::with_capacity(usize::from(initial_slots(family)) * 256);
        for _ in 0..initial_slots(family) {
            ring.extend(tfd.bytes());
        }
        // SAFETY: Fresh exclusive host allocation; no address has been published.
        unsafe {
            descriptors.write_owned(0, &ring).map_err(Error::Dma)?;
        }
        let prepared = Self {
            family,
            byte_counts,
            descriptors,
            first,
            invalid,
        };
        let layout = prepared.layout();
        geometry(
            family,
            usize::from(initial_slots(family)),
            layout.byte_counts,
            layout.descriptors,
        )?;
        if layout.first.address & 63 != 0 || layout.invalid.address & 63 != 0 {
            return Err(Error::Region);
        }
        Ok(prepared)
    }
    pub fn layout(&self) -> Layout {
        Layout {
            byte_counts: self.byte_counts.region(),
            descriptors: self.descriptors.region(),
            first: self.first.region(),
            invalid: self.invalid.region(),
        }
    }
    pub fn configuration(&self, station_mask: u32, tid: u8) -> Result<Configuration, Error> {
        Configuration::encode(
            self.family,
            Parameters {
                station_mask,
                tid,
                slots: initial_slots(self.family),
                byte_counts: self.byte_counts.region(),
                descriptors: self.descriptors.region(),
            },
        )
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::super::tests::firmware;
    use super::*;
    use crate::net::wifi::intel::dma::tests::{Domain, Records, Source};
    use core::sync::atomic::Ordering;
    fn parameters(family: Family, slots: u16) -> Parameters {
        Parameters {
            station_mask: 1,
            tid: 15,
            slots,
            byte_counts: Region {
                address: 0xabcde000,
                bytes: bc_bytes(family),
            },
            descriptors: Region {
                address: 0x12345678000,
                bytes: usize::from(slots) * 256,
            },
        }
    }
    #[test]
    fn exact_queue_abi_geometry_failure_flags_and_raw_write_pointer_boundaries() {
        let bytes = firmware(&[[0x17, 5, 3, 2]]);
        let fw = Firmware::parse(&bytes).unwrap();
        for family in [Family::Ax200, Family::Ax210] {
            let config = Configuration::prepare(&fw, family, parameters(family, 128)).unwrap();
            assert_eq!(
                config.id(),
                Id {
                    group: 5,
                    opcode: 0x17,
                    version: 0
                }
            );
            assert_eq!(
                &config.payload()[..20],
                &[0, 0, 0, 0, 1, 0, 0, 0, 15, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0]
            );
            for len in 0..=12 {
                if len != 8 {
                    assert_eq!(config.parse_reply(&vec![0; len]), Err(Error::ReplyLength));
                }
            }
            for flags in [1u16, 0x8000, u16::MAX] {
                let mut reply = [0; 8];
                reply[2..4].copy_from_slice(&flags.to_le_bytes());
                assert_eq!(config.parse_reply(&reply), Err(Error::Rejected(flags)));
            }
            let reply = config
                .parse_reply(&[0xff, 1, 0, 0, 0xff, 0xff, 0x55, 0xaa])
                .unwrap();
            assert_eq!(reply.queue, 511);
            assert_eq!(reply.raw_write_pointer, u16::MAX);
            assert_eq!(
                reply.write_pointer,
                if family == Family::Ax200 {
                    255
                } else {
                    u16::MAX
                }
            );
            assert_eq!(reply.reserved, 0xaa55);
            for queue in [512u16, u16::MAX] {
                let mut raw = [0; 8];
                raw[..2].copy_from_slice(&queue.to_le_bytes());
                assert_eq!(config.parse_reply(&raw), Err(Error::Queue(queue)));
            }
            for slots in [0, 1, 8, 15, 17, 127, 129, 2048] {
                assert!(matches!(
                    Configuration::prepare(&fw, family, parameters(family, slots)),
                    Err(Error::Slots)
                ));
            }
            for mask in [0, 1] {
                for tid in [0, 15, 16, 255] {
                    let mut p = parameters(family, 128);
                    p.station_mask = mask;
                    p.tid = tid;
                    assert_eq!(
                        Configuration::prepare(&fw, family, p).is_ok(),
                        mask != 0 && tid <= 15
                    );
                }
            }
            for bad in 0..6 {
                let mut p = parameters(family, 128);
                match bad {
                    0 => p.descriptors.address += 1,
                    1 => p.byte_counts.address += 1,
                    2 => p.descriptors.bytes -= 1,
                    3 => p.byte_counts.bytes -= 1,
                    4 => p.byte_counts.address = p.descriptors.address,
                    _ => p.descriptors.address = !4095u64,
                }
                assert!(matches!(
                    Configuration::prepare(&fw, family, p),
                    Err(Error::Region)
                ));
            }
        }
        for rows in [
            vec![],
            vec![[0x17, 5, 0, 2]],
            vec![[0x17, 5, 3, 0]],
            vec![[0x17, 5, 4, 2]],
        ] {
            let b = firmware(&rows);
            let fw = Firmware::parse(&b).unwrap();
            let source = Source::default();
            let domain = Arc::new(Domain::default());
            assert!(matches!(
                UnpublishedQueue::prepare(&fw, Family::Ax200, &source, domain.clone()),
                Err(Error::Version)
            ));
            assert_eq!(source.calls.load(Ordering::Relaxed), 0);
            assert_eq!(domain.records.lock().unwrap().maps, 0);
        }
    }
    #[test]
    fn unpublished_native_rings_initialize_invalid_targets_and_keep_real_dma_failures() {
        let bytes = firmware(&[[0x17, 5, 3, 2]]);
        let fw = Firmware::parse(&bytes).unwrap();
        for family in [Family::Ax200, Family::Ax210] {
            let source = Source::default();
            let domain = Arc::new(Domain::default());
            let queue = UnpublishedQueue::prepare(&fw, family, &source, domain.clone()).unwrap();
            let layout = queue.layout();
            assert_eq!(layout.descriptors.bytes, usize::from(queue.slots()) * 256);
            assert_eq!(layout.first.bytes, usize::from(queue.slots()) * 64);
            assert_eq!(layout.byte_counts.bytes, bc_bytes(family));
            assert_eq!(layout.invalid.bytes, 8);
            let config = queue.configuration(0x80000000, 15).unwrap();
            assert_eq!(&config.payload()[4..8], &0x80000000u32.to_le_bytes());
            let records = domain.records.lock().unwrap();
            assert_eq!(records.directions, vec![Direction::Bidirectional; 4]);
            assert_eq!(records.cpu_syncs, 0);
            assert_eq!(records.copied[3], [6, 0xf, 0xff, 0xff, 0, 0, 0, 0]);
            let ring = records.copied.last().unwrap();
            assert_eq!(ring.len(), usize::from(queue.slots()) * 256);
            for descriptor in ring.as_chunks::<256>().0 {
                assert_eq!(&descriptor[..4], &[1, 0, 8, 0]);
                assert_eq!(&descriptor[4..12], &layout.invalid.address.to_le_bytes());
                assert!(descriptor[12..].iter().all(|v| *v == 0));
            }
            drop(records);
            drop(queue);
            assert!(domain.records.lock().unwrap().live.is_empty());
            assert_eq!(source.released.load(Ordering::Relaxed), 4);
            for kind in 0..3 {
                for fail in 0..if kind == 2 { 5 } else { 4 } {
                    let source = Source {
                        fail_at: (kind == 0).then_some(fail),
                        ..Source::default()
                    };
                    let domain = Arc::new(Domain {
                        records: std::sync::Mutex::new(Records {
                            map_fail: (kind == 1).then_some(fail),
                            sync_fail: (kind == 2).then_some(fail),
                            ..Records::default()
                        }),
                    });
                    assert!(
                        UnpublishedQueue::prepare(&fw, family, &source, domain.clone()).is_err()
                    );
                    assert!(domain.records.lock().unwrap().live.is_empty());
                }
            }
            // Failed real unmap keeps the map/domain/pin even though these
            // allocations were never exposed. No identity fallback or pretend
            // invalidation releases the last lease.
            let source = Source::default();
            let domain = Arc::new(Domain::default());
            let queue = UnpublishedQueue::prepare(&fw, family, &source, domain.clone()).unwrap();
            domain.records.lock().unwrap().unmap_fail = Some(0);
            drop(queue);
            assert_eq!(domain.records.lock().unwrap().live.len(), 1);
            assert_eq!(source.released.load(Ordering::Relaxed), 3);
            assert!(Arc::strong_count(&domain) > 1);
        }
    }
    #[test]
    #[ignore = "oracle: STELA_IWLWIFI_IMAGES"]
    fn images_select_queue_command3_reply2_and_stage_canonical_native_maps() {
        for family in [Family::Ax200, Family::Ax210] {
            let root = std::env::var("STELA_IWLWIFI_IMAGES").unwrap();
            let bytes =
                std::fs::read(std::path::Path::new(&root).join(family.firmware_name())).unwrap();
            let fw = Firmware::parse(&bytes).unwrap();
            let source = Source::default();
            let domain = Arc::new(Domain::default());
            let queue = UnpublishedQueue::prepare(&fw, family, &source, domain.clone()).unwrap();
            assert_eq!(queue.configuration(1, 15).unwrap().id().version, 0);
            drop(queue);
            assert!(domain.records.lock().unwrap().live.is_empty());
        }
    }
    #[test]
    #[ignore = "oracle: STELA_IWLWIFI_TX_QUEUE_ORACLE"]
    fn unchanged_linux_queue_allocation_and_reply_helpers_match_exact_wire_bytes() {
        use sha2::{Digest, Sha256};
        let trace = std::fs::read(std::env::var("STELA_IWLWIFI_TX_QUEUE_ORACLE").unwrap()).unwrap();
        assert_eq!(
            std::format!("{:x}", Sha256::digest(&trace)),
            "4c80c65cd1d3cde98cd9843493c183d778e7f951e469d0a0f096c7e2ec6abe63"
        );
        let bytes = firmware(&[[0x17, 5, 3, 2]]);
        let fw = Firmware::parse(&bytes).unwrap();
        let mut counts = [0; 3];
        for line in core::str::from_utf8(&trace).unwrap().lines() {
            let f: alloc::vec::Vec<_> = line.split_whitespace().collect();
            let n = |i: usize| f[i].parse::<u32>().unwrap();
            let family = if n(1) == 0 {
                Family::Ax200
            } else {
                Family::Ax210
            };
            match f[0] {
                "queue" => {
                    counts[0] += 1;
                    if f[6].parse::<i32>().unwrap() < 0 {
                        continue;
                    }
                    let mut p = parameters(family, n(9) as u16);
                    p.station_mask = n(3);
                    p.tid = n(4) as u8;
                    let config = Configuration::prepare(&fw, family, p).unwrap();
                    assert_eq!(n(11), 0x517);
                    assert_eq!(
                        config
                            .payload()
                            .iter()
                            .map(|v| alloc::format!("{v:02x}"))
                            .collect::<alloc::string::String>(),
                        f[12]
                    );
                }
                "reply" => {
                    counts[1] += 1;
                    let queue = n(2) as u16;
                    let flags = n(3) as u16;
                    let pointer = n(4) as u16;
                    let busy = n(5);
                    let config =
                        Configuration::prepare(&fw, family, parameters(family, 128)).unwrap();
                    let raw = [
                        queue.to_le_bytes(),
                        flags.to_le_bytes(),
                        pointer.to_le_bytes(),
                        [0, 0],
                    ]
                    .concat();
                    let parsed = config.parse_reply(&raw);
                    assert_eq!(f[6].parse::<i32>().unwrap() >= 0, queue < 512 && busy == 0); // Linux raw helper ignores failure flags
                    if flags != 0 {
                        assert_eq!(parsed, Err(Error::Rejected(flags)));
                    } else if queue >= 512 {
                        assert_eq!(parsed, Err(Error::Queue(queue)));
                    } else {
                        let parsed = parsed.unwrap();
                        assert_eq!(parsed.queue, queue);
                        assert_eq!(parsed.raw_write_pointer, pointer);
                        if busy == 0 {
                            assert_eq!(u32::from(parsed.write_pointer), n(7));
                        }
                    }
                }
                "tx" => counts[2] += 1,
                _ => panic!("unknown oracle record"),
            }
        }
        assert_eq!(counts, [324, 648, 1024]);
    }
}
