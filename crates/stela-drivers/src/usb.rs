//! USB devices behind the host's xHCI controllers ([`xhci`]), each
//! interface bound to its class driver when the controller attaches: HID
//! keyboards and pointers ([`hid`]), Bulk-Only and UAS mass storage
//! ([`storage`]), CDC ECM/NCM and vendor Ethernet adapters ([`cdc`],
//! [`ethernet`]), Bluetooth HCI transports ([`bluetooth`]) and UAC2 audio
//! ([`audio`]). [`typec`] holds the UCSI and Type-C mux library, which the
//! mount does not attach yet.
pub mod audio;
pub mod bluetooth;
pub mod cdc;
pub mod ethernet;
pub mod forwarding;
pub mod hid;
pub mod storage;
pub mod typec;
pub mod xhci;
