//! Host keyboards and pointers, read as [`Input`] changes for the native
//! USB peripheral: virtio-input ([`virtio`]). USB HID devices are in
//! [`usb::hid`](crate::usb::hid).
pub mod virtio;

/// The largest absolute pointer coordinate on either axis.
pub const POINTER_MAX: u16 = 0x7fff;

/// One host input change, in HID usages, the pointer's absolute range and
/// the mouse's counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Input {
    /// A Keyboard/Keypad page usage: 04h..DDh, or a modifier E0h..E7h.
    Key { usage: u8, pressed: bool },
    /// The pointer's position, each axis 0..=[`POINTER_MAX`].
    Move { x: u16, y: u16 },
    /// The pointer's buttons 1..3 held, as bits 0..2.
    Buttons(u8),
    /// Pointer wheel detents, positive away from the user.
    Wheel(i8),
    /// Mouse motion in counts, positive right and down.
    Motion { dx: i16, dy: i16 },
    /// The mouse's buttons 1..3 held, as bits 0..2.
    MouseButtons(u8),
    /// Mouse wheel detents, positive away from the user.
    MouseWheel(i8),
}
