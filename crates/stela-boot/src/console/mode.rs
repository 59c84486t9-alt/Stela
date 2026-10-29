//! The screen's graphics mode. The first [`select`] chooses among the GOP's
//! modes (`stela_runtime::pc::display`, which also gives the guest's cap)
//! and switches to it; the panel's native resolution comes from the EDID the
//! firmware read from it. A mode that cannot be set, or whose framebuffer is
//! too small for it, leaves the firmware's. Each choice is logged.
use super::{Framebuffer, encoding};
use crate::output::{self, Global};
use alloc::{format, string::String, vec::Vec};
use core::cell::RefCell;
use stela_contracts::refuse;
use stela_runtime::pc::display;
use uefi::{
    Handle,
    boot::{self, OpenProtocolAttributes, OpenProtocolParams, SearchType},
    proto::{
        ProtocolPointer,
        console::gop::{EdidDiscovered, GraphicsOutput, Mode, ModeInfo},
        unsafe_protocol,
    },
};

/// `EFI_EDID_ACTIVE_PROTOCOL` (UEFI 2.10 section 12.9, EDK2
/// `MdePkg/Include/Protocol/EdidActive.h`): the EDID the display runs
/// with, an override's or the one discovered from the panel.
#[repr(C)]
#[unsafe_protocol("bd8c1056-9f36-44ec-92a8-a6337f817986")]
struct EdidActive {
    size: u32,
    edid: *const u8,
}

impl EdidActive {
    fn edid(&self) -> Option<&[u8]> {
        // SAFETY: the firmware keeps `size` bytes at `edid` while the
        // protocol is installed, which outlives `self`.
        (!self.edid.is_null())
            .then(|| unsafe { core::slice::from_raw_parts(self.edid, self.size as usize) })
    }
}

/// Whether [`select`] has chosen the mode.
static SELECTED: Global<bool> = Global(RefCell::new(false));

/// `1920x1080 Bgr`.
fn describe(mode: &ModeInfo) -> String {
    let (width, height) = mode.resolution();
    format!("{width}x{height} {:?}", mode.pixel_format())
}

/// Run `gop`, on `handle`, in the best mode, chosen on the first call.
pub(super) fn select(handle: Handle, gop: &mut GraphicsOutput) {
    if let Ok(mut selected) = SELECTED.0.try_borrow_mut()
        && !*selected
    {
        *selected = true;
        choose(handle, gop);
    }
}

fn choose(handle: Handle, gop: &mut GraphicsOutput) {
    let listed: Vec<Mode> = gop.modes().collect();
    let info = gop.current_mode_info();
    let firmware = listed.iter().position(|mode| *mode.info() == info);
    let candidates: Vec<display::Mode> = listed
        .iter()
        .zip(0..)
        .map(|(mode, index)| {
            let (width, height) = mode.info().resolution();
            display::Mode {
                index,
                width: u32::try_from(width).unwrap_or(u32::MAX),
                height: u32::try_from(height).unwrap_or(u32::MAX),
                drawable: encoding(mode.info()).is_some(),
            }
        })
        .collect();
    let edid = edid(handle);
    let native = edid.as_ref().and_then(|(bytes, _)| display::native(bytes));
    output::arguments(format_args!("DISPLAY firmware mode {}\n", describe(&info)));
    let mut line = String::from("DISPLAY modes");
    for mode in &listed {
        line.push(' ');
        line.push_str(&describe(mode.info()));
    }
    output::arguments(format_args!("{line}\n"));
    match (&edid, native) {
        (Some((_, source)), Some((width, height))) => output::arguments(format_args!(
            "DISPLAY EDID ({source}) prefers {width}x{height}\n"
        )),
        (Some((bytes, source)), None) => output::arguments(format_args!(
            "DISPLAY EDID ({source}, {} bytes) has no preferred timing\n",
            bytes.len()
        )),
        (None, _) => output::arguments(format_args!("DISPLAY no EDID\n")),
    }
    let current = firmware.map_or(u32::MAX, |index| index as u32);
    let firmware = firmware.map(|index| listed[index]);
    let Some((choice, reason)) = display::choose(&candidates, current, native) else {
        output::arguments(format_args!(
            "DISPLAY keeps the firmware's mode: no listed mode is drawable and fits the guest\n"
        ));
        return;
    };
    let mode = listed[choice.index as usize];
    let chosen = if choice.index == current {
        Ok(())
    } else if gop.set_mode(&mode).is_err() {
        Err(refuse!("the firmware refused it"))
    } else if Framebuffer::current(gop).is_none() {
        // The mode was set; go back to the firmware's.
        let _ = firmware.map(|firmware| gop.set_mode(&firmware));
        Err(refuse!("its framebuffer is too small for it"))
    } else {
        Ok(())
    };
    match chosen {
        Ok(()) => output::arguments(format_args!(
            "DISPLAY runs {}: {reason}\n",
            describe(mode.info())
        )),
        Err(why) => output::arguments(format_args!(
            "DISPLAY keeps the firmware's mode: {} ({reason}) failed, {why}\n",
            describe(mode.info())
        )),
    }
}

/// The EDID of the display on `handle`, and which it is: the active one,
/// else the discovered one, from the GOP's own handle or, when that has
/// none (a console splitter's), from the only display that has one.
fn edid(handle: Handle) -> Option<(Vec<u8>, &'static str)> {
    let active = |handle| read::<EdidActive>(handle, EdidActive::edid);
    let discovered = |handle| read::<EdidDiscovered>(handle, EdidDiscovered::edid);
    let only = |handles: Option<Vec<Handle>>| match handles.as_deref() {
        Some(&[handle]) => Some(handle),
        _ => None,
    };
    active(handle)
        .map(|edid| (edid, "active"))
        .or_else(|| discovered(handle).map(|edid| (edid, "discovered")))
        .or_else(|| {
            active(only(handles::<EdidActive>())?).map(|edid| (edid, "active, the only display's"))
        })
        .or_else(|| {
            discovered(only(handles::<EdidDiscovered>())?)
                .map(|edid| (edid, "discovered, the only display's"))
        })
}

fn handles<P: ProtocolPointer + ?Sized>() -> Option<Vec<Handle>> {
    let buffer = boot::locate_handle_buffer(SearchType::from_proto::<P>()).ok()?;
    Some(buffer.iter().copied().collect())
}

/// `P`'s bytes on `handle`, copied, when it has any.
fn read<P: ProtocolPointer + ?Sized>(
    handle: Handle,
    bytes: impl Fn(&P) -> Option<&[u8]>,
) -> Option<Vec<u8>> {
    // SAFETY: the protocol is only read, and only while boot services run.
    let protocol = unsafe {
        boot::open_protocol::<P>(
            OpenProtocolParams {
                handle,
                agent: boot::image_handle(),
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
    }
    .ok()?;
    let bytes = bytes(&protocol)?;
    (!bytes.is_empty()).then(|| bytes.to_vec())
}
