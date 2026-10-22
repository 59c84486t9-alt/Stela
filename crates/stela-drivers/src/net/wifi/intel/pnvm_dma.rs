// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2018-2026 Intel Corporation
//! Native PNVM/reduced-power payload mappings from pcie/ctxt-info-v2.c.
//! These are prepared bytes, not an actual ALIVE-selected source receipt or
//! a firmware PNVM completion. The owning ROM epoch must bind source/SKU,
//! retain the actual requester/BAR, publish scratch then ring the doorbell.
//! Every payload/descriptor mapping survives PNVM notification until stop.
use super::{
    context::Region,
    dma::{self, Chunk},
    pnvm,
};
use crate::bus::dma::{
    mapping::{Direction, DmaDomain, DmaError},
    memory::PageSource,
};
use alloc::{sync::Arc, vec::Vec};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    PayloadCount,
    PayloadSize,
    Dma(dma::Error),
    State,
}
impl From<dma::Error> for Error {
    fn from(value: dma::Error) -> Self {
        Self::Dma(value)
    }
}

/// Serialization data only; no DMA ownership, completion or source authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Configuration {
    pub address: u64,
    pub bytes: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Prepared,
    Exposed,
    Stopped,
}
pub struct MappedTable {
    payloads: Vec<Chunk>,
    descriptors: Option<Chunk>,
    configuration: Configuration,
    state: State,
}
impl MappedTable {
    /// Source-backed capability selection: fragmented is firmware capability
    /// bit 32. Without it, exactly two chunks are concatenated in source order.
    /// This allocator profile bounds each allocation to 32 KiB and 64 payloads.
    /// # Safety
    /// Source allocations are fresh exclusive real native RAM with no aliases.
    /// The domain is the actual isolated requester domain, not identity DMA.
    /// Until publication all returned bytes remain exclusively CPU-owned.
    pub unsafe fn prepare(
        chunks: &[pnvm::Chunk<'_>],
        fragmented: bool,
        source: &dyn PageSource,
        domain: Option<Arc<dyn DmaDomain>>,
    ) -> Result<Self, Error> {
        if chunks.is_empty() || chunks.len() > 64 || (!fragmented && chunks.len() != 2) {
            return Err(Error::PayloadCount);
        }
        let mut total = 0u32;
        for chunk in chunks {
            if chunk.data.is_empty() || chunk.data.len() > 32768 {
                return Err(Error::PayloadSize);
            }
            total = total
                .checked_add(chunk.data.len() as u32)
                .ok_or(Error::PayloadSize)?;
        }
        if !fragmented && total > 32768 {
            return Err(Error::PayloadSize);
        }
        let domain = domain.ok_or(Error::Dma(dma::Error::Dma(DmaError::IommuUnavailable)))?;
        let allocate =
            |bytes: &[u8]| Chunk::allocate(source, domain.clone(), bytes, Direction::Bidirectional);
        let (payloads, descriptors, address) = if fragmented {
            let descriptors = allocate(&[0; 512])?;
            let mut payloads = Vec::new();
            let mut addresses = [0; 512];
            for (index, chunk) in chunks.iter().enumerate() {
                let payload = allocate(chunk.data)?;
                addresses[index * 8..index * 8 + 8]
                    .copy_from_slice(&payload.region().address.to_le_bytes());
                payloads.push(payload);
            }
            // SAFETY: this private descriptor buffer has never been published.
            unsafe {
                descriptors.write_owned(0, &addresses)?;
            }
            let address = descriptors.region().address;
            (payloads, Some(descriptors), address)
        } else {
            let mut bytes = Vec::with_capacity(total as usize);
            for chunk in chunks {
                bytes.extend_from_slice(chunk.data);
            }
            let payload = allocate(&bytes)?;
            let address = payload.region().address;
            (alloc::vec![payload], None, address)
        };
        Ok(Self {
            payloads,
            descriptors,
            configuration: Configuration {
                address,
                bytes: total,
            },
            state: State::Prepared,
        })
    }
    /// Conservative lifetime transition before the first possible scratch
    /// pointer store. The actual owner must retain this table and its real PCI
    /// claim through uncertain publication. Calling this does not publish DMA.
    pub fn expose_for_scratch(&mut self) -> Result<Configuration, Error> {
        if self.state != State::Prepared {
            return Err(Error::State);
        }
        for chunk in &mut self.payloads {
            chunk.expose();
        }
        if let Some(descriptors) = self.descriptors.as_mut() {
            descriptors.expose();
        }
        self.state = State::Exposed;
        Ok(self.configuration)
    }
    /// # Safety
    /// Actual requester master-disable/reset or a stronger device fence proves
    /// no further table reads/writes; all submission/IRQ work has drained.
    /// PNVM notification/ALIVE/timeouts alone do not satisfy this contract.
    pub unsafe fn release_after_stop(&mut self) -> Result<(), Error> {
        if self.state != State::Exposed {
            return Err(Error::State);
        }
        for chunk in &mut self.payloads {
            unsafe {
                chunk.release().map_err(dma::Error::Dma)?;
            }
        }
        if let Some(descriptors) = self.descriptors.as_mut() {
            unsafe {
                descriptors.release().map_err(dma::Error::Dma)?;
            }
        }
        self.state = State::Stopped;
        Ok(())
    }
    pub fn payloads(&self) -> impl Iterator<Item = Region> + '_ {
        self.payloads.iter().map(Chunk::region)
    }
    pub fn fragmented(&self) -> bool {
        self.descriptors.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        dma::tests::{Domain, Records, Source},
        identity::{Observed, Profile},
    };
    use super::*;
    use core::sync::atomic::Ordering;
    use std::sync::Mutex;
    extern crate std;
    fn chunks(bytes: &[Vec<u8>]) -> Vec<pnvm::Chunk<'_>> {
        bytes
            .iter()
            .enumerate()
            .map(|(index, data)| pnvm::Chunk {
                kind: pnvm::ChunkKind::MemoryDescriptor {
                    address: 0xf0000000 + index as u32,
                },
                data,
                tlv_index: index,
            })
            .collect()
    }
    fn prepare(
        chunks: &[pnvm::Chunk<'_>],
        fragmented: bool,
        source: &Source,
        domain: &Arc<Domain>,
    ) -> Result<MappedTable, Error> {
        // SAFETY: the source owns fresh real RAM and the isolated model domain
        // grants no competing access; publication below is a model-only event.
        unsafe { MappedTable::prepare(chunks, fragmented, source, Some(domain.clone())) }
    }
    #[test]
    fn contiguous_order_fragment_addresses_zero_unused_and_coherent_permissions() {
        for fragmented in [false, true] {
            for count in if fragmented {
                vec![1, 2, 3, 64]
            } else {
                vec![2]
            } {
                let bytes: Vec<_> = (0..count).map(|i| vec![i as u8 + 1; 17 + i]).collect();
                let source = Source::default();
                let domain = Arc::new(Domain::default());
                let mut table = prepare(&chunks(&bytes), fragmented, &source, &domain).unwrap();
                let config = table.expose_for_scratch().unwrap();
                assert_eq!(
                    config.bytes as usize,
                    bytes.iter().map(Vec::len).sum::<usize>()
                );
                let records = domain.records.lock().unwrap();
                assert!(
                    records
                        .directions
                        .iter()
                        .all(|d| *d == Direction::Bidirectional)
                );
                if fragmented {
                    assert_eq!(records.maps, count + 1);
                    assert_eq!(records.syncs, count + 2);
                    let desc = records.copied.last().unwrap();
                    assert_eq!(desc.len(), 512);
                    for (i, region) in table.payloads().enumerate() {
                        assert_eq!(
                            u64::from_le_bytes(desc[i * 8..i * 8 + 8].try_into().unwrap()),
                            region.address
                        );
                        assert_eq!(records.copied[i + 1], bytes[i]);
                    }
                    assert!(desc[count * 8..].iter().all(|b| *b == 0));
                    assert_eq!(
                        config.address,
                        table.descriptors.as_ref().unwrap().region().address
                    );
                } else {
                    assert_eq!(records.maps, 1);
                    assert_eq!(records.copied[0], bytes.concat());
                    assert_eq!(config.address, table.payloads().next().unwrap().address);
                }
                drop(records);
                assert_eq!(table.expose_for_scratch(), Err(Error::State));
                // No device was submitted in this model, so actual accesses
                // and workers are already drained; this is not a notification.
                unsafe {
                    table.release_after_stop().unwrap();
                }
                assert_eq!(unsafe { table.release_after_stop() }, Err(Error::State));
                assert!(domain.records.lock().unwrap().live.is_empty());
                drop(table);
                assert_eq!(
                    source.calls.load(Ordering::Relaxed),
                    source.released.load(Ordering::Relaxed)
                );
            }
        }
    }
    #[test]
    fn all_staging_faults_unwind_and_stop_invalidation_failure_retains_for_retry() {
        let bytes = vec![vec![1; 16], vec![2; 32], vec![3; 64]];
        let chunks = chunks(&bytes);
        for stage in 0..3 {
            for fail in 0..if stage == 2 { 5 } else { 4 } {
                let source = Source {
                    fail_at: (stage == 0).then_some(fail),
                    ..Default::default()
                };
                let domain = Arc::new(Domain {
                    records: Mutex::new(Records {
                        map_fail: (stage == 1).then_some(fail),
                        sync_fail: (stage == 2).then_some(fail),
                        ..Default::default()
                    }),
                });
                assert!(matches!(
                    prepare(&chunks, true, &source, &domain),
                    Err(Error::Dma(_))
                ));
                assert!(domain.records.lock().unwrap().live.is_empty());
            }
        }
        for fail in 0..4 {
            let source = Source::default();
            let domain = Arc::new(Domain::default());
            let mut table = prepare(&chunks, true, &source, &domain).unwrap();
            table.expose_for_scratch().unwrap();
            domain.records.lock().unwrap().unmap_fail = Some(fail);
            assert_eq!(
                unsafe { table.release_after_stop() },
                Err(Error::Dma(dma::Error::Dma(DmaError::InvalidationFailed)))
            );
            assert_eq!(table.state, State::Exposed);
            assert!(!domain.records.lock().unwrap().live.is_empty());
            unsafe {
                table.release_after_stop().unwrap();
            }
            assert!(domain.records.lock().unwrap().live.is_empty());
            drop(table);
            assert_eq!(
                source.calls.load(Ordering::Relaxed),
                source.released.load(Ordering::Relaxed)
            );
        }
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let mut table = prepare(&chunks, true, &source, &domain).unwrap();
        table.expose_for_scratch().unwrap();
        drop(table);
        assert_eq!(domain.records.lock().unwrap().live.len(), 4);
        assert_eq!(source.released.load(Ordering::Relaxed), 0);
    }
    #[test]
    fn invalid_shape_and_missing_domain_never_allocate() {
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        for (fragmented, data) in [
            (false, vec![vec![1]]),
            (true, vec![]),
            (true, vec![vec![1]; 65]),
            (true, vec![vec![]]),
            (true, vec![vec![1; 32769]]),
            (false, vec![vec![1; 32768]; 2]),
        ] {
            assert!(prepare(&chunks(&data), fragmented, &source, &domain).is_err());
        }
        assert!(matches!(
            unsafe { MappedTable::prepare(&chunks(&[vec![1], vec![2]]), true, &source, None) },
            Err(Error::Dma(dma::Error::Dma(DmaError::IommuUnavailable)))
        ));
        assert_eq!(source.calls.load(Ordering::Relaxed), 0);
    }
    #[test]
    #[ignore = "requires pinned actual PNVM asset; see THIRD_PARTY.md"]
    fn actual_pnvm_all_four_skus_stage_both_source_layouts_without_payload_changes() {
        use sha2::{Digest, Sha256};
        let root = std::env::var("STELA_IWLWIFI_IMAGES").unwrap();
        let bytes =
            std::fs::read(std::path::Path::new(&root).join("iwlwifi-ty-a0-gf-a0.pnvm")).unwrap();
        let sha: alloc::string::String = Sha256::digest(&bytes)
            .iter()
            .map(|b| alloc::format!("{b:02x}"))
            .collect();
        assert_eq!(
            sha,
            "9697e327f8171454b3c19b1ec9449753d5b934d4e91722f469616818a6d477b0"
        );
        let profile = Profile::select(Observed {
            vendor: 0x8086,
            device: 0x2725,
            subsystem_vendor: 0x8086,
            subsystem_device: 0x84,
            pci_revision: 0x1a,
            hardware_revision: 0x420,
            radio_id: 0x10d000,
        })
        .unwrap();
        let pnvm = pnvm::Pnvm::parse(&bytes).unwrap();
        for sku in [0x610d0, 0x510d0, 0x4510d0, 0x4610d0] {
            let selection = pnvm.select(&profile, [sku, 0, 0]).unwrap();
            for fragmented in [false, true] {
                let source = Source::default();
                let domain = Arc::new(Domain::default());
                let mut table = prepare(selection.chunks(), fragmented, &source, &domain).unwrap();
                let config = table.expose_for_scratch().unwrap();
                let expected: Vec<_> = selection
                    .chunks()
                    .iter()
                    .flat_map(|c| c.data)
                    .copied()
                    .collect();
                assert_eq!(config.bytes as usize, expected.len());
                let records = domain.records.lock().unwrap();
                if fragmented {
                    for (i, chunk) in selection.chunks().iter().enumerate() {
                        assert_eq!(records.copied[i + 1], chunk.data);
                    }
                } else {
                    assert_eq!(records.copied[0], expected);
                }
                drop(records);
                unsafe {
                    table.release_after_stop().unwrap();
                }
                drop(table);
                assert!(domain.records.lock().unwrap().live.is_empty());
            }
        }
    }
    #[test]
    #[ignore = "requires actual PNVM and unchanged Linux payload/setter helper oracle; see THIRD_PARTY.md"]
    fn unchanged_linux_pnvm_and_reduced_power_contiguous_fragmented_dma() {
        use sha2::{Digest, Sha256};
        fn hex(bytes: &[u8]) -> alloc::string::String {
            bytes.iter().map(|b| alloc::format!("{b:02x}")).collect()
        }
        fn read(domain: &Domain, address: u64, n: usize) -> Vec<u8> {
            let r = domain.records.lock().unwrap();
            let id = (address - 0x100000) / 0x10000;
            let p = r.live[&id].address(0, n).unwrap();
            // Synchronous model has no real device reader/writer or references.
            unsafe { core::slice::from_raw_parts(p.as_ptr(), n) }.to_vec()
        }
        fn fnv(bytes: &[u8]) -> u64 {
            bytes.iter().fold(0xcbf29ce484222325u64, |h, b| {
                (h ^ u64::from(*b)).wrapping_mul(0x100000001b3)
            })
        }
        let trace = std::fs::read(std::env::var("STELA_IWLWIFI_PNVM_DMA_ORACLE").unwrap()).unwrap();
        assert_eq!(
            hex(&Sha256::digest(&trace)),
            "481d0fbbaf87aab52e178dd56c25743a7cb8eaab2fd49c093e426801b52a72f5"
        );
        let root = std::env::var("STELA_IWLWIFI_IMAGES").unwrap();
        let bytes =
            std::fs::read(std::path::Path::new(&root).join("iwlwifi-ty-a0-gf-a0.pnvm")).unwrap();
        assert_eq!(
            hex(&Sha256::digest(&bytes)),
            "9697e327f8171454b3c19b1ec9449753d5b934d4e91722f469616818a6d477b0"
        );
        let pnvm = pnvm::Pnvm::parse(&bytes).unwrap();
        let profile = Profile::select(Observed {
            vendor: 0x8086,
            device: 0x2725,
            subsystem_vendor: 0x8086,
            subsystem_device: 0x84,
            pci_revision: 0x1a,
            hardware_revision: 0x420,
            radio_id: 0x10d000,
        })
        .unwrap();
        let text = core::str::from_utf8(&trace).unwrap();
        let mut lines = text.lines();
        let mut cases = 0;
        while let Some(line) = lines.next() {
            let fields: Vec<_> = line.split_whitespace().collect();
            assert_eq!(fields[0], "case");
            let sku = u32::from_str_radix(fields[1], 16).unwrap();
            let fragmented = fields[2] == "1";
            let selection = pnvm.select(&profile, [sku, 0, 0]).unwrap();
            let source = Source::default();
            let domain = Arc::new(Domain::default());
            let mut tables = Vec::new();
            for kind in 0..2 {
                let mut table = prepare(selection.chunks(), fragmented, &source, &domain).unwrap();
                let config = table.expose_for_scratch().unwrap();
                let fields: Vec<_> = lines.next().unwrap().split_whitespace().collect();
                assert_eq!(fields[0], "table");
                assert_eq!(fields[1].parse::<u32>().unwrap(), kind);
                assert_eq!(u64::from_str_radix(fields[2], 16).unwrap(), config.address);
                assert_eq!(fields[3].parse::<u32>().unwrap(), config.bytes);
                assert_eq!(fields[4].parse::<usize>().unwrap(), table.payloads.len());
                if fragmented {
                    assert_eq!(
                        lines.next().unwrap(),
                        alloc::format!("descriptor {}", hex(&read(&domain, config.address, 512)))
                    );
                }
                for payload in table.payloads() {
                    let fields: Vec<_> = lines.next().unwrap().split_whitespace().collect();
                    assert_eq!(fields[0], "payload");
                    assert_eq!(u64::from_str_radix(fields[1], 16).unwrap(), payload.address);
                    assert_eq!(fields[2].parse::<usize>().unwrap(), payload.bytes);
                    assert_eq!(
                        u64::from_str_radix(fields[3], 16).unwrap(),
                        fnv(&read(&domain, payload.address, payload.bytes))
                    );
                }
                tables.push(table);
            }
            for table in &mut tables {
                unsafe {
                    table.release_after_stop().unwrap();
                }
            }
            assert!(domain.records.lock().unwrap().live.is_empty());
            cases += 1;
        }
        assert_eq!(cases, 8);
    }
}
