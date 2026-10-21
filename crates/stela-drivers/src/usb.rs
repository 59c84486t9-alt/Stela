//! USB devices behind the host's xHCI controllers ([`xhci`]), each
//! interface bound to its class driver when the controller attaches: HID
//! keyboards and pointers ([`hid`]), Bulk-Only mass storage ([`storage`])
//! and CDC Ethernet adapters ([`cdc`]).
pub mod bluetooth;
pub mod cdc;
pub mod hid;
pub mod storage;
pub mod xhci;
