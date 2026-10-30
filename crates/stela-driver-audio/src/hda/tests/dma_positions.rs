// SPDX-License-Identifier: GPL-2.0-only
//! dma positions behavior tests.
use super::*;

#[test]
fn direction_tags_have_disjoint_handles() {
    for policy in [StreamTagPolicy::Global, StreamTagPolicy::PerDirection] {
        let mut fixture = Fixture::new();
        let model = Model::new(16);
        model.borrow_mut().set(GCAP, 0xff01, 2); //15capture+15playback,64bitDMA.
        model.borrow_mut().set(INPAY, 100, 2);
        model.borrow_mut().set(OUTPAY, 100, 2);
        let mut controller = create(
            &model,
            &mut fixture,
            Config {
                stream_tag_policy: policy,
                ..config()
            },
        )
        .unwrap();
        let mut capture = Vec::new();
        for tag in 1..=15 {
            let id = controller
                .allocate_stream(Direction::Capture, pcm(), 128, 2, &mut fixture.allocator)
                .unwrap();
            assert_eq!(id.tag(), tag);
            assert_eq!(id.descriptor_index(), tag - 1);
            capture.push(id);
        }
        if policy == StreamTagPolicy::Global {
            let before = access_counts(&model);
            let remaining = fixture.allocator.remaining();
            assert_eq!(
                controller.allocate_stream(
                    Direction::Playback,
                    pcm(),
                    128,
                    2,
                    &mut fixture.allocator
                ),
                Err(Error::NoStream)
            );
            assert_eq!(access_counts(&model), before);
            assert_eq!(fixture.allocator.remaining(), remaining);
            continue;
        }
        let mut playback = Vec::new();
        for tag in 1..=15 {
            let id = controller
                .allocate_stream(Direction::Playback, pcm(), 128, 2, &mut fixture.allocator)
                .unwrap();
            assert_eq!(id.tag(), tag);
            assert_eq!(id.descriptor_index(), 14 + tag);
            assert_ne!(id, capture[usize::from(tag - 1)]);
            let control = model
                .borrow()
                .get(stream_base(id.descriptor_index()) + SD_CTL + 2, 1);
            assert_eq!(control >> 4, u32::from(tag));
            playback.push(id);
        }
        assert_eq!(
            controller.allocate_stream(Direction::Capture, pcm(), 128, 2, &mut fixture.allocator),
            Err(Error::NoStream)
        );
        assert_eq!(
            controller.allocate_stream(Direction::Playback, pcm(), 128, 2, &mut fixture.allocator),
            Err(Error::NoStream)
        );
        controller.fill_capture(capture[0], 0xa5).unwrap();
        controller.write_pcm(playback[0], 0, &[0x5a; 256]).unwrap();
        let mut bytes = [0; 256];
        controller.read_pcm(capture[0], 0, &mut bytes).unwrap();
        assert_eq!(bytes, [0xa5; 256]);
        controller.start(capture[0]).unwrap();
        controller.start(playback[0]).unwrap();
        assert_eq!(
            model
                .borrow()
                .get(stream_base(capture[0].descriptor_index()) + SD_CTL, 1)
                & u32::from(SD_RUN),
            u32::from(SD_RUN)
        );
        assert_eq!(
            model
                .borrow()
                .get(stream_base(playback[0].descriptor_index()) + SD_CTL, 1)
                & u32::from(SD_RUN),
            u32::from(SD_RUN)
        );
    }
}

#[test]
fn fifo_capture_position_correction() {
    let mut fixture = Fixture::new();
    let model = Model::new(256);
    let mut controller = create(
        &model,
        &mut fixture,
        Config {
            position_policy: PositionPolicy::AmdFifo32,
            ..config()
        },
    )
    .unwrap();
    let capture = controller
        .allocate_stream(Direction::Capture, stereo(), 128, 2, &mut fixture.allocator)
        .unwrap();
    let base = stream_base(capture.descriptor_index());
    for (raw, pcm, delay, frames) in [
        (0, 0, 0, 0),
        (5, 0, 5, 1),
        (127, 0, 127, 31),
        (128, 0, 128, 32),
        (200, 72, 128, 32),
        (10, 138, 128, 32),
        (256, 128, 128, 32),
    ] {
        model.borrow_mut().set(base + SD_LPIB, raw, 4);
        let info = controller.position_info(capture).unwrap();
        assert_eq!(
            info,
            PositionInfo {
                raw_link_bytes: raw,
                transport_bytes: if raw == 256 { 0 } else { raw },
                pcm_bytes: pcm,
                fifo_delay_bytes: delay,
                fifo_delay_frames: frames
            }
        );
        assert_eq!(controller.link_position(capture).unwrap(), raw);
        assert_eq!(controller.position(capture).unwrap(), info.transport_bytes);
        let status = controller.status(capture).unwrap();
        assert_eq!(status.position_bytes, info.transport_bytes);
        assert_eq!(status.position.pcm_bytes, pcm);
    }
    model.borrow_mut().set(base + SD_LPIB, 257, 4);
    assert_eq!(
        controller.position_info(capture),
        Err(Error::InvalidPosition(257))
    );
}

#[test]
fn fifo_playback_delay_and_restart() {
    let mut fixture = Fixture::new();
    let model = Model::new(256);
    let mut controller = create(
        &model,
        &mut fixture,
        Config {
            position_policy: PositionPolicy::AmdFifo32,
            ..config()
        },
    )
    .unwrap();
    let playback = controller
        .allocate_stream(
            Direction::Playback,
            stereo(),
            128,
            2,
            &mut fixture.allocator,
        )
        .unwrap();
    let capture = controller
        .allocate_stream(Direction::Capture, stereo(), 128, 2, &mut fixture.allocator)
        .unwrap();
    let pbase = stream_base(playback.descriptor_index());
    let cbase = stream_base(capture.descriptor_index());
    model.borrow_mut().set(pbase + SD_LPIB, 5, 4);
    let info = controller.position_info(playback).unwrap();
    assert_eq!(
        (info.transport_bytes, info.pcm_bytes, info.fifo_delay_bytes),
        (5, 5, 5)
    );
    model.borrow_mut().set(pbase + SD_LPIB, 128, 4);
    let info = controller.position_info(playback).unwrap();
    assert_eq!(
        (info.transport_bytes, info.pcm_bytes, info.fifo_delay_frames),
        (128, 128, 32)
    );
    controller.start(capture).unwrap();
    model.borrow_mut().set(cbase + SD_LPIB, 200, 4);
    assert_eq!(controller.position_info(capture).unwrap().pcm_bytes, 72);
    controller.stop(capture).unwrap();
    model.borrow_mut().set(cbase + SD_LPIB, 0, 4);
    controller.start(capture).unwrap();
    model.borrow_mut().set(cbase + SD_LPIB, 5, 4);
    let info = controller.position_info(capture).unwrap();
    assert_eq!(
        (info.transport_bytes, info.pcm_bytes, info.fifo_delay_bytes),
        (5, 0, 5)
    );
    controller.stop(capture).unwrap();
}

#[test]
fn fifo_endpoint_and_small_ring_bounds() {
    let mut fixture = Fixture::new();
    let model = Model::new(256);
    let mut controller = create(
        &model,
        &mut fixture,
        Config {
            position_policy: PositionPolicy::AmdFifo32,
            ..config()
        },
    )
    .unwrap();
    let capture = controller
        .allocate_stream(Direction::Capture, stereo(), 128, 2, &mut fixture.allocator)
        .unwrap();
    model
        .borrow_mut()
        .set(stream_base(capture.descriptor_index()) + SD_LPIB, 256, 4);
    let info = controller.position_info(capture).unwrap();
    assert_eq!(
        (
            info.raw_link_bytes,
            info.transport_bytes,
            info.pcm_bytes,
            info.fifo_delay_bytes
        ),
        (256, 0, 128, 128)
    );
    let before = fixture.allocator.remaining();
    let writes = model.borrow().writes.len();
    let wide = PcmFormat {
        channels: 16,
        ..stereo()
    };
    assert_eq!(
        controller.allocate_stream(Direction::Playback, wide, 512, 2, &mut fixture.allocator),
        Err(Error::InvalidBuffer)
    );
    assert_eq!(fixture.allocator.remaining(), before);
    assert_eq!(model.borrow().writes.len(), writes);
    controller
        .allocate_stream(Direction::Playback, wide, 640, 2, &mut fixture.allocator)
        .unwrap();
}
