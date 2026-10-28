use super::*;

#[test]
fn payload_order_and_fragment_descriptors_preserve_coherent_mapping() {
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
            // SAFETY: Source owns these allocations and Domain only records
            // synchronous mappings; this fixture has no requester, DMA engine
            // or IRQ worker that could access the exposed table.
            unsafe {
                table.release_after_stop().unwrap();
            }
            // SAFETY: the same no-device fixture remains quiescent after its
            // first stop; the repeated call exercises only the stopped state.
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
fn staging_failures_unwind_and_failed_stop_invalidation_retries() {
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
            // SAFETY: the fixture has no device or asynchronous worker. The
            // injected IOMMU invalidation failure does not create a DMA user;
            // its live mappings remain retained for the following retry.
            unsafe { table.release_after_stop() },
            Err(Error::Dma(dma::Error::Dma(DmaError::InvalidationFailed)))
        );
        assert_eq!(table.state, State::Exposed);
        assert!(!domain.records.lock().unwrap().live.is_empty());
        // SAFETY: the same no-device fixture is still quiescent; the failed
        // invalidation retained the allocation and domain mapping for retry.
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
fn invalid_shapes_and_missing_domain_allocate_nothing() {
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
        // SAFETY: Source would allocate uniquely owned host RAM with no device
        // aliases; the absent domain is rejected before any allocation or DMA.
        unsafe { MappedTable::prepare(&chunks(&[vec![1], vec![2]]), true, &source, None) },
        Err(Error::Dma(dma::Error::Dma(DmaError::IommuUnavailable)))
    ));
    assert_eq!(source.calls.load(Ordering::Relaxed), 0);
}
