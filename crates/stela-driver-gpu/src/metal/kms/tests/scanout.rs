use super::*;

#[test]
fn a_failed_flip_keeps_the_front_and_retries_the_hidden_buffer() {
    let mut card = Card::new(vec![mode(2, 2, PREFERRED)]);
    card.flip_error = Some(-5);
    let framebuffer;
    {
        let mut display = Display::take(&mut card, (2, 2)).unwrap();
        let front = display.front();
        framebuffer = display.buffers[2].framebuffer;
        assert_eq!(display.present(&[1; 16]), Err(Error::Request(-5)));
        assert_eq!(display.front(), front);
        display.present(&[2; 16]).unwrap();
        assert_eq!(display.buffers[0].framebuffer, framebuffer);
    }
    assert_eq!(card.flips, [framebuffer]);
    assert_eq!(&card.memory[2][..8], &[2; 8]);
}

#[test]
fn takeover_clears_every_scanout_buffer_before_modesetting() {
    let mut card = Card::new(vec![mode(2, 2, PREFERRED)]);
    Display::take(&mut card, (2, 2)).unwrap();
    assert_eq!(card.memory.len(), 3);
    assert!(card.memory.iter().flatten().all(|byte| *byte == 0));
}

#[test]
fn each_buffer_keeps_its_own_pitch() {
    let mut card = Card::new(vec![mode(2, 2, PREFERRED)]);
    card.pitches = vec![8, 16, 32];
    {
        let mut display = Display::take(&mut card, (2, 2)).unwrap();
        assert_eq!(display.front().1, 8);
        display.present(&[1; 16]).unwrap();
        assert_eq!(display.front().1, 32);
        display.present(&[2; 16]).unwrap();
        assert_eq!(display.front().1, 16);
    }
    assert_eq!(&card.memory[2][32..40], &[1; 8]);
    assert_eq!(&card.memory[1][16..24], &[2; 8]);
    assert!(card.memory[2][8..32].iter().all(|byte| *byte == 0));
}

#[test]
fn incomplete_or_oversized_frames_do_not_touch_or_flip_a_buffer() {
    let mut card = Card::new(vec![mode(2, 2, PREFERRED)]);
    {
        let mut display = Display::take(&mut card, (2, 2)).unwrap();
        for actual in [0, 1, 15, 17, 32] {
            assert_eq!(
                display.present(&vec![1; actual]),
                Err(Error::FrameSize {
                    expected: 16,
                    actual
                })
            );
        }
    }
    assert!(card.flips.is_empty());
    assert!(card.memory.iter().flatten().all(|byte| *byte == 0));
}

#[test]
fn invalid_pitch_or_extent_prevents_mapping_and_modesetting() {
    for allocation in [(7, 16), (8, 15), (u32::MAX, 16)] {
        let mut card = Card::new(vec![mode(2, 2, PREFERRED)]);
        card.invalid_buffer = Some(allocation);
        assert_eq!(
            Display::take(&mut card, (2, 2)).err(),
            Some(Error::InvalidBuffer)
        );
        assert!(card.set.is_none());
        assert!(card.memory.is_empty());
    }
}

#[test]
fn enumeration_retries_hotplugged_resource_and_mode_lists() {
    let mut card = Card::new(vec![mode(2, 2, PREFERRED)]);
    card.resource_changes = 2;
    card.mode_changes = 2;
    let display = Display::take(&mut card, (2, 2)).unwrap();
    assert_eq!(display.size(), (2, 2));
    assert_eq!(card.resource_changes, 0);
    assert_eq!(card.mode_changes, 0);
}

#[test]
fn unstable_resource_or_mode_lists_stop_without_modesetting() {
    for (resource_changes, mode_changes) in [(ENUMERATION_ATTEMPTS, 0), (0, ENUMERATION_ATTEMPTS)] {
        let mut card = Card::new(vec![mode(2, 2, PREFERRED)]);
        card.resource_changes = resource_changes;
        card.mode_changes = mode_changes;
        assert_eq!(Display::take(&mut card, (2, 2)).err(), Some(Error::Changed));
        assert!(card.set.is_none());
    }
}
