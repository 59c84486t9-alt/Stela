//! Controller identity exhaustion and DMA address reuse.
use super::*;

#[test]
fn controller_identity_exhaustion_refuses_before_register_or_dma_effects() {
    let identities = AtomicU64::new(u64::MAX);
    let mut fixture = Fixture::new();
    let model = analog_model();
    let before = access_counts(&model);
    let timer = model.borrow().clock.clone();
    // SAFETY: isolated stopped model and unique live fixture; the exhausted
    // private namespace must refuse before consulting either provider.
    let result = unsafe {
        Host::new_with_identities(
            ModelRegisters(model.clone()),
            timer,
            &mut fixture.allocator,
            config(),
            &identities,
        )
    };
    assert!(matches!(result, Err(Error::ControllerIdentitiesExhausted)));
    assert_eq!(identities.load(Ordering::Relaxed), u64::MAX);
    assert_eq!(access_counts(&model), before);
}

#[test]
fn recycled_controller_dma_storage_does_not_revive_stream_or_graph_handles() {
    let mut fixture = Fixture::new();
    let first_model = analog_model();
    let mut first = create(&first_model, &mut fixture, config()).unwrap();
    let graph = first.enumerate_codec(0).unwrap();
    let route = graph.analog_route(Direction::Playback, 4, 2).unwrap();
    let old = first
        .allocate_stream(
            Direction::Playback,
            stereo(),
            128,
            2,
            &mut fixture.allocator,
        )
        .unwrap();
    let old_cpu = first.corb.as_ptr();
    let old_bus = first.corb.bus_address();
    let old_owner = first.token.owner;
    first.shutdown().unwrap();
    drop(first);
    let base = fixture._backing.as_mut_ptr() as u64;
    // SAFETY: actual modeled shutdown acknowledged all engines stopped;
    // the old controller and all buffer handles have been dropped. Only
    // copied graph/stream metadata remains, with no CPU/DMA storage rights.
    fixture.allocator =
        unsafe { RegionAllocator::new(base..base + (fixture._backing.len() * 8) as u64) };
    let model = analog_model();
    let mut controller = create(&model, &mut fixture, config()).unwrap();
    assert_eq!(controller.corb.as_ptr(), old_cpu);
    assert_eq!(controller.corb.bus_address(), old_bus);
    assert_ne!(controller.token.owner, old_owner);
    let fresh_graph = controller.enumerate_codec(0).unwrap();
    let fresh = controller
        .allocate_stream(
            Direction::Playback,
            stereo(),
            128,
            2,
            &mut fixture.allocator,
        )
        .unwrap();
    assert_eq!(fresh.descriptor_index(), old.descriptor_index());
    assert_eq!(fresh.tag(), old.tag());
    assert_ne!(fresh, old);
    let before = access_counts(&model);
    assert_eq!(controller.start(old), Err(Error::InvalidStream));
    assert_eq!(controller.stop(old), Err(Error::InvalidStream));
    assert_eq!(controller.status(old), Err(Error::InvalidStream));
    assert_eq!(controller.position(old), Err(Error::InvalidStream));
    assert_eq!(
        controller.write_pcm(old, 0, &[1]),
        Err(Error::InvalidStream)
    );
    assert_eq!(
        controller.bind_converter(&graph, 2, fresh, 0),
        Err(Error::InvalidCodecGraph)
    );
    let options = PinOptions::Playback {
        headphone: false,
        eapd: None,
    };
    assert_eq!(
        controller.configure_analog_route(&graph, &route, fresh, 0, options),
        Err(Error::InvalidCodecGraph)
    );
    assert_eq!(access_counts(&model), before);
    let fresh_route = fresh_graph.analog_route(Direction::Playback, 4, 2).unwrap();
    controller
        .configure_analog_route(&fresh_graph, &fresh_route, fresh, 0, options)
        .unwrap();
    controller.start(fresh).unwrap();
}

