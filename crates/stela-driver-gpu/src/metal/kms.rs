//! The host display over DRM's mode setting, once a GPU's driver owns it.
//!
//! Binding a GPU ends what the firmware left: its framebuffer sits behind a
//! BAR the driver remaps, and its display engine is the driver's to program.
//! [`Display`] takes the first connected output and scans out one of three
//! linear buffers of video memory, each a DRM dumb buffer: the one a flip last
//! named, the one before it, which shows until that flip lands, and the one a
//! frame fills.
//!
//! NVIDIA's display engine reads only video memory, so a guest surface in
//! guest RAM cannot be scanned out in place: frames copy in, top to bottom.
//! A flip the engine has not finished answers `EBUSY` and retries, so a frame
//! waits at most for the next vertical blank.
use alloc::vec::Vec;
use core::ffi::c_void;
use core::ptr::{self, NonNull};

/// `_IOWR('d', number, T)`.
const fn request<T>(number: u32) -> u32 {
    3 << 30 | (size_of::<T>() as u32) << 16 | 0x64 << 8 | number
}

const GET_RESOURCES: u32 = request::<CardResources>(0xa0);
const SET_CRTC: u32 = request::<Crtc>(0xa2);
const GET_ENCODER: u32 = request::<Encoder>(0xa6);
const GET_CONNECTOR: u32 = request::<Connector>(0xa7);
const PAGE_FLIP: u32 = request::<PageFlip>(0xb0);
const CREATE_DUMB: u32 = request::<CreateDumb>(0xb2);
const MAP_DUMB: u32 = request::<MapDumb>(0xb3);
const ADD_FB2: u32 = request::<FramebufferCommand>(0xb8);

/// `DRM_MODE_CONNECTED`.
const CONNECTED: u32 = 1;
/// `DRM_MODE_TYPE_PREFERRED`.
const PREFERRED: u32 = 1 << 3;
/// `DRM_FORMAT_XRGB8888`: blue in the low byte of the little-endian pixel.
const XRGB8888: u32 = u32::from_le_bytes(*b"XR24");
const BYTES_PER_PIXEL: u32 = 4;
/// `EBUSY`, as a negative result.
const BUSY: i64 = -16;

/// `struct drm_mode_card_res`.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
struct CardResources {
    framebuffers: u64,
    crtcs: u64,
    connectors: u64,
    encoders: u64,
    framebuffer_count: u32,
    crtc_count: u32,
    connector_count: u32,
    encoder_count: u32,
    limits: [u32; 4],
}

/// `struct drm_mode_modeinfo`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct ModeInfo {
    clock: u32,
    hdisplay: u16,
    timing_h: [u16; 4],
    vdisplay: u16,
    timing_v: [u16; 4],
    vrefresh: u32,
    flags: u32,
    kind: u32,
    name: [[u8; 8]; 4],
}

/// `struct drm_mode_get_connector`.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
struct Connector {
    encoders: u64,
    modes: u64,
    properties: u64,
    property_values: u64,
    mode_count: u32,
    property_count: u32,
    encoder_count: u32,
    encoder: u32,
    id: u32,
    kind: u32,
    kind_id: u32,
    connection: u32,
    size_mm: [u32; 2],
    subpixel: u32,
    pad: u32,
}

/// `struct drm_mode_get_encoder`.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
struct Encoder {
    id: u32,
    kind: u32,
    crtc: u32,
    possible_crtcs: u32,
    possible_clones: u32,
}

/// `struct drm_mode_crtc`.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
struct Crtc {
    connectors: u64,
    connector_count: u32,
    id: u32,
    framebuffer: u32,
    x: u32,
    y: u32,
    gamma_size: u32,
    mode_valid: u32,
    mode: ModeInfo,
}

/// `struct drm_mode_create_dumb`.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
struct CreateDumb {
    height: u32,
    width: u32,
    bits_per_pixel: u32,
    flags: u32,
    handle: u32,
    pitch: u32,
    size: u64,
}

/// `struct drm_mode_map_dumb`.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
struct MapDumb {
    handle: u32,
    pad: u32,
    offset: u64,
}

/// `struct drm_mode_fb_cmd2`.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
struct FramebufferCommand {
    id: u32,
    width: u32,
    height: u32,
    format: u32,
    flags: u32,
    handles: [u32; 4],
    pitches: [u32; 4],
    offsets: [u32; 4],
    modifiers: [u64; 4],
}

/// `struct drm_mode_crtc_page_flip`.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
struct PageFlip {
    crtc: u32,
    framebuffer: u32,
    flags: u32,
    reserved: u32,
    user_data: u64,
}

/// What stops the display.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// No output is connected, or none has a mode or a controller to run it.
    NoOutput,
    /// A request failed, with its negative errno.
    Request(i64),
    /// A buffer could not be mapped.
    Map,
}

/// A DRM primary node of the bound GPU.
pub trait Drm {
    /// The ioctl `request` on `argument`: zero or a negative errno.
    fn control(&mut self, request: u32, argument: *mut c_void) -> i64;
    /// Maps `bytes` at `offset`, what `MAP_DUMB` answered.
    fn map(&mut self, offset: u64, bytes: usize) -> Option<NonNull<u8>>;
    /// Waits a moment, as a flip's vertical blank needs.
    fn relax(&mut self);
}

/// A scanned-out buffer.
#[derive(Debug)]
struct Buffer {
    framebuffer: u32,
    pixels: NonNull<u8>,
}

/// The output a [`Display`] runs.
#[derive(Debug)]
pub struct Display<D> {
    drm: D,
    crtc: u32,
    width: u32,
    height: u32,
    pitch: usize,
    /// What the engine reads, then the one the next frame fills.
    /// The newest frame, the one before it and the one that shows neither.
    buffers: [Buffer; 3],
}

// SAFETY: the buffers' mappings go with the display, which one PE uses at a
// time through the board's lock.
unsafe impl<D: Send> Send for Display<D> {}

fn call<D: Drm, T>(drm: &mut D, request: u32, argument: &mut T) -> Result<(), Error> {
    match drm.control(request, ptr::from_mut(argument).cast()) {
        0 => Ok(()),
        error => Err(Error::Request(error)),
    }
}

/// A list a second `control` fills, which Linux does only whole, once the
/// first says how long it is.
fn list<T: Copy + Default>(count: u32) -> Vec<T> {
    alloc::vec![T::default(); count as usize]
}

/// A connector: its state, its modes and its encoders.
struct Output {
    connected: bool,
    modes: Vec<ModeInfo>,
    encoders: Vec<u32>,
}

fn output<D: Drm>(drm: &mut D, id: u32) -> Result<Output, Error> {
    let mut sized = Connector {
        id,
        ..Connector::default()
    };
    call(drm, GET_CONNECTOR, &mut sized)?;
    let mut modes = list::<ModeInfo>(sized.mode_count);
    let mut encoders = list::<u32>(sized.encoder_count);
    let mut described = Connector {
        id,
        modes: modes.as_mut_ptr() as u64,
        mode_count: modes.len() as u32,
        encoders: encoders.as_mut_ptr() as u64,
        encoder_count: encoders.len() as u32,
        ..Connector::default()
    };
    call(drm, GET_CONNECTOR, &mut described)?;
    Ok(Output {
        connected: described.connection == CONNECTED,
        modes,
        encoders,
    })
}

/// The first of `crtcs` one of `encoders` can drive.
fn controller<D: Drm>(drm: &mut D, encoders: &[u32], crtcs: &[u32]) -> Result<Option<u32>, Error> {
    for &id in encoders {
        let mut encoder = Encoder {
            id,
            ..Encoder::default()
        };
        call(drm, GET_ENCODER, &mut encoder)?;
        let reachable = crtcs
            .iter()
            .enumerate()
            .find(|(index, _)| encoder.possible_crtcs >> index & 1 != 0);
        if let Some((_, &crtc)) = reachable {
            return Ok(Some(crtc));
        }
    }
    Ok(None)
}

/// The mode of `wanted` size, else the preferred one, else the first.
fn choose(modes: &[ModeInfo], wanted: (u32, u32)) -> Option<ModeInfo> {
    let size = |mode: &&ModeInfo| (u32::from(mode.hdisplay), u32::from(mode.vdisplay));
    modes
        .iter()
        .find(|mode| size(mode) == wanted)
        .or_else(|| modes.iter().find(|mode| mode.kind & PREFERRED != 0))
        .or(modes.first())
        .copied()
}

/// One buffer of the mode's size, with its framebuffer and mapping.
fn buffer<D: Drm>(drm: &mut D, width: u32, height: u32) -> Result<(Buffer, u32), Error> {
    let mut dumb = CreateDumb {
        width,
        height,
        bits_per_pixel: BYTES_PER_PIXEL * 8,
        ..CreateDumb::default()
    };
    call(drm, CREATE_DUMB, &mut dumb)?;
    let mut framebuffer = FramebufferCommand {
        width,
        height,
        format: XRGB8888,
        ..FramebufferCommand::default()
    };
    framebuffer.handles[0] = dumb.handle;
    framebuffer.pitches[0] = dumb.pitch;
    call(drm, ADD_FB2, &mut framebuffer)?;
    let mut map = MapDumb {
        handle: dumb.handle,
        ..MapDumb::default()
    };
    call(drm, MAP_DUMB, &mut map)?;
    let pixels = drm.map(map.offset, dumb.size as usize).ok_or(Error::Map)?;
    Ok((
        Buffer {
            framebuffer: framebuffer.id,
            pixels,
        },
        dumb.pitch,
    ))
}

impl<D: Drm> Display<D> {
    /// Takes the first connected output of `drm`, showing a black frame in
    /// the mode of `wanted` pixels if it has one, as the firmware's did.
    pub fn take(mut drm: D, wanted: (u32, u32)) -> Result<Self, Error> {
        let mut resources = CardResources::default();
        call(&mut drm, GET_RESOURCES, &mut resources)?;
        let mut crtcs = list::<u32>(resources.crtc_count);
        let mut connectors = list::<u32>(resources.connector_count);
        let mut lists = CardResources {
            crtcs: crtcs.as_mut_ptr() as u64,
            crtc_count: crtcs.len() as u32,
            connectors: connectors.as_mut_ptr() as u64,
            connector_count: connectors.len() as u32,
            ..CardResources::default()
        };
        call(&mut drm, GET_RESOURCES, &mut lists)?;
        for &id in &connectors {
            let found = output(&mut drm, id)?;
            let Some(mode) = choose(&found.modes, wanted).filter(|_| found.connected) else {
                continue;
            };
            if let Some(crtc) = controller(&mut drm, &found.encoders, &crtcs)? {
                return Self::run(drm, crtc, id, mode);
            }
        }
        Err(Error::NoOutput)
    }

    fn run(mut drm: D, crtc: u32, connector: u32, mode: ModeInfo) -> Result<Self, Error> {
        let (width, height) = (u32::from(mode.hdisplay), u32::from(mode.vdisplay));
        let (front, pitch) = buffer(&mut drm, width, height)?;
        let (back, _) = buffer(&mut drm, width, height)?;
        let (spare, _) = buffer(&mut drm, width, height)?;
        let mut connectors = connector;
        let mut set = Crtc {
            connectors: ptr::from_mut(&mut connectors) as u64,
            connector_count: 1,
            id: crtc,
            framebuffer: front.framebuffer,
            mode_valid: 1,
            mode,
            ..Crtc::default()
        };
        call(&mut drm, SET_CRTC, &mut set)?;
        Ok(Self {
            drm,
            crtc,
            width,
            height,
            pitch: pitch as usize,
            buffers: [front, back, spare],
        })
    }

    /// Pixels across and down.
    pub fn size(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    /// The buffer on screen and the bytes between its rows, for what draws
    /// before the first frame.
    pub fn front(&self) -> (NonNull<u8>, usize) {
        (self.buffers[0].pixels, self.pitch)
    }

    /// Shows `rows`, blue-low pixels of [`Self::size`] top to bottom, at the
    /// next vertical blank.
    pub fn present(&mut self, rows: &[u8]) -> Result<(), Error> {
        let row = self.width as usize * BYTES_PER_PIXEL as usize;
        let target = self.buffers[2].pixels.as_ptr();
        for (y, line) in rows
            .chunks_exact(row)
            .take(self.height as usize)
            .enumerate()
        {
            // SAFETY: `y` is a row of the mapped buffer, whose rows are
            // `pitch` apart and hold `row` bytes, and the engine reads
            // another buffer.
            unsafe {
                ptr::copy_nonoverlapping(line.as_ptr(), target.add(y * self.pitch), row);
            }
        }
        let mut flip = PageFlip {
            crtc: self.crtc,
            framebuffer: self.buffers[2].framebuffer,
            ..PageFlip::default()
        };
        loop {
            match self.drm.control(PAGE_FLIP, ptr::from_mut(&mut flip).cast()) {
                0 => break,
                BUSY => self.drm.relax(),
                error => return Err(Error::Request(error)),
            }
        }
        self.buffers.rotate_right(1);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
