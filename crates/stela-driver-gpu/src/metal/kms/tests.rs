use super::*;
use alloc::{vec, vec::Vec};

mod scanout;

fn mode(width: u16, height: u16, kind: u32) -> ModeInfo {
    ModeInfo {
        hdisplay: width,
        vdisplay: height,
        kind,
        ..ModeInfo::default()
    }
}

/// A GPU of two connectors, the second connected with `modes`.
struct Card {
    modes: Vec<ModeInfo>,
    possible_crtcs: u32,
    /// The mode and framebuffer the controller was set to.
    set: Option<(ModeInfo, u32)>,
    /// Requests to answer `EBUSY` before a flip succeeds.
    busy: u32,
    flip_error: Option<i64>,
    relaxed: u32,
    flips: Vec<u32>,
    next: u32,
    memory: Vec<Vec<u8>>,
    pitches: Vec<u32>,
    invalid_buffer: Option<(u32, u64)>,
    resource_changes: usize,
    mode_changes: usize,
}

impl Card {
    fn new(modes: Vec<ModeInfo>) -> Self {
        Self {
            modes,
            possible_crtcs: 0b10,
            set: None,
            busy: 0,
            flip_error: None,
            relaxed: 0,
            flips: Vec::new(),
            next: 100,
            memory: Vec::new(),
            pitches: Vec::new(),
            invalid_buffer: None,
            resource_changes: 0,
            mode_changes: 0,
        }
    }

    fn id(&mut self) -> u32 {
        self.next += 1;
        self.next
    }
}

// SAFETY: each mapping owns a separate Vec whose allocation stays put in
// `memory` until the card is dropped, after the borrowing display.
unsafe impl Drm for &mut Card {
    fn control(&mut self, request: u32, argument: *mut c_void) -> i64 {
        // SAFETY: each arm reads the record its request carries.
        unsafe {
            match request {
                GET_RESOURCES => {
                    let resources = &mut *argument.cast::<CardResources>();
                    if resources.crtc_count != 0 {
                        let crtcs = resources.crtcs as *mut u32;
                        crtcs.write(40);
                        crtcs.add(1).write(41);
                        let connectors = resources.connectors as *mut u32;
                        connectors.write(50);
                        connectors.add(1).write(51);
                    }
                    resources.crtc_count = 2;
                    resources.connector_count = 2;
                    if resources.crtcs != 0 && self.resource_changes != 0 {
                        self.resource_changes -= 1;
                        resources.connector_count = 3;
                    }
                }
                GET_CONNECTOR => {
                    let connector = &mut *argument.cast::<Connector>();
                    let connected = connector.id == 51;
                    connector.connection = if connected { CONNECTED } else { 2 };
                    let modes: &[ModeInfo] = if connected { &self.modes } else { &[] };
                    // Linux fills a list only when all of it fits.
                    if connector.mode_count as usize >= modes.len() && connector.mode_count != 0 {
                        let list = connector.modes as *mut ModeInfo;
                        ptr::copy_nonoverlapping(modes.as_ptr(), list, modes.len());
                    }
                    if connector.encoder_count != 0 {
                        (connector.encoders as *mut u32).write(60);
                    }
                    assert!(
                        connector.mode_count == 0 || connector.mode_count == modes.len() as u32
                    );
                    connector.mode_count = modes.len() as u32;
                    connector.encoder_count = 1;
                    if connected && connector.modes != 0 && self.mode_changes != 0 {
                        self.mode_changes -= 1;
                        connector.mode_count += 1;
                    }
                }
                GET_ENCODER => {
                    let encoder = &mut *argument.cast::<Encoder>();
                    assert_eq!(encoder.id, 60);
                    encoder.possible_crtcs = self.possible_crtcs;
                }
                CREATE_DUMB => {
                    let dumb = &mut *argument.cast::<CreateDumb>();
                    dumb.pitch = self
                        .pitches
                        .get(self.memory.len())
                        .copied()
                        .unwrap_or(dumb.width * BYTES_PER_PIXEL + 16);
                    dumb.size = u64::from(dumb.pitch) * u64::from(dumb.height);
                    if let Some((pitch, size)) = self.invalid_buffer {
                        dumb.pitch = pitch;
                        dumb.size = size;
                    }
                    dumb.handle = self.id();
                }
                ADD_FB2 => {
                    let framebuffer = &mut *argument.cast::<FramebufferCommand>();
                    assert_eq!(framebuffer.format, XRGB8888);
                    assert_ne!(framebuffer.pitches[0], 0);
                    framebuffer.id = self.id();
                }
                MAP_DUMB => (*argument.cast::<MapDumb>()).offset = 0x1000,
                SET_CRTC => {
                    let crtc = &*argument.cast::<Crtc>();
                    assert_eq!(crtc.id, 41);
                    assert_eq!((crtc.connectors as *const u32).read(), 51);
                    self.set = Some((crtc.mode, crtc.framebuffer));
                }
                PAGE_FLIP => {
                    if let Some(error) = self.flip_error.take() {
                        return error;
                    }
                    if self.busy != 0 {
                        self.busy -= 1;
                        return BUSY;
                    }
                    self.flips.push((*argument.cast::<PageFlip>()).framebuffer);
                }
                other => panic!("request {other:#x}"),
            }
        }
        0
    }

    fn map(&mut self, _: u64, bytes: usize) -> Option<NonNull<u8>> {
        self.memory.push(vec![0xa5; bytes]);
        NonNull::new(self.memory.last_mut()?.as_mut_ptr())
    }

    fn relax(&mut self) {
        self.relaxed += 1;
    }
}

#[test]
fn requests_match_linux() {
    assert_eq!(GET_RESOURCES, 0xc040_64a0);
    assert_eq!(GET_CONNECTOR, 0xc050_64a7);
    assert_eq!(GET_ENCODER, 0xc014_64a6);
    assert_eq!(SET_CRTC, 0xc068_64a2);
    assert_eq!(PAGE_FLIP, 0xc018_64b0);
    assert_eq!(CREATE_DUMB, 0xc020_64b2);
    assert_eq!(MAP_DUMB, 0xc010_64b3);
    assert_eq!(ADD_FB2, 0xc068_64b8);
}

#[test]
fn the_firmwares_size_wins_then_the_preferred_mode() {
    let modes = [
        mode(1280, 720, 0),
        mode(3840, 2160, PREFERRED),
        mode(1920, 1080, 0),
    ];
    assert_eq!(choose(&modes, (1920, 1080)), Some(modes[2]));
    assert_eq!(choose(&modes, (800, 600)), Some(modes[1]));
    assert_eq!(choose(&modes[..1], (800, 600)), Some(modes[0]));
    assert_eq!(choose(&[], (800, 600)), None);
}

#[test]
fn the_connected_output_runs_on_a_controller_it_can_reach() {
    let modes = vec![mode(4, 2, PREFERRED)];
    let mut card = Card::new(modes.clone());
    let front = {
        let display = Display::take(&mut card, (4, 2)).unwrap();
        assert_eq!(display.size(), (4, 2));
        display.buffers[0].framebuffer
    };
    assert_eq!(card.set, Some((modes[0], front)));
}

#[test]
fn an_output_with_no_mode_or_controller_is_not_taken() {
    let mut card = Card::new(Vec::new());
    assert_eq!(
        Display::take(&mut card, (4, 2)).err(),
        Some(Error::NoOutput)
    );
    let mut card = Card::new(vec![mode(4, 2, 0)]);
    card.possible_crtcs = 0;
    assert_eq!(
        Display::take(&mut card, (4, 2)).err(),
        Some(Error::NoOutput)
    );
}

#[test]
fn frames_fill_the_hidden_buffer_and_flip_past_a_busy_engine() {
    let mut card = Card::new(vec![mode(2, 2, PREFERRED)]);
    card.busy = 2;
    let (mut first, mut second, flips);
    {
        let mut display = Display::take(&mut card, (2, 2)).unwrap();
        let (back, spare) = (
            display.buffers[1].framebuffer,
            display.buffers[2].framebuffer,
        );
        let rows: Vec<u8> = (0..16).collect();
        display.present(&rows).unwrap();
        assert_eq!(display.buffers[0].framebuffer, spare);
        display.present(&rows).unwrap();
        assert_eq!(display.buffers[0].framebuffer, back);
        flips = [spare, back];
        first = Vec::new();
        second = Vec::new();
        first.extend_from_slice(&rows[..8]);
        second.extend_from_slice(&rows[8..]);
    }
    assert_eq!(card.flips, flips);
    assert_eq!(card.relaxed, 2);
    // The rows land `pitch` apart.
    let filled = &card.memory[2];
    assert_eq!(&filled[..8], first);
    assert_eq!(&filled[24..32], second);
}
