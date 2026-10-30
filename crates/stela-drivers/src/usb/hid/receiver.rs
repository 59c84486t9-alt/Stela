// SPDX-License-Identifier: GPL-2.0-only
// Linux HID++/receiver reference: Copyright (c) 2011 Logitech;
// 2012-2013 Google; 2013-2014 Red Hat Inc. Exact identities: ../THIRD_PARTY.md.
//! Descriptor-checked c539 HID++ side-channel on the existing native HID owner.
//! Standard input remains canonical and has no invented paired-slot identity.
use super::*;
use alloc::rc::{Rc, Weak};
use core::cell::RefCell;

#[cfg(test)]
mod tests;
pub(in crate::usb) mod transport;

const SHORT: u8 = 0x10;
const LONG: u8 = 0x11;
const SHORT_BYTES: usize = 7;
const LONG_BYTES: usize = 20;
const RECEIVER: u8 = 0xff;
const CONNECTION: u8 = 0x41;
const SET_REGISTER: u8 = 0x80;
const NOTIFICATION_REGISTER: u8 = 0;
const NOTIFICATION_FLAGS: u8 = 0x09;
const CONNECTION_REGISTER: u8 = 0x02;
const FAKE_ARRIVAL: u8 = 0x02;
const RAP_ERROR: u8 = 0x8f;
const FAP_ERROR: u8 = 0xff;
const INVALID_SUBID: u8 = 1;
const ROOT: u8 = 0;
const VERSION_FUNCTION: u8 = 0x10;
const FEATURE_FUNCTION: u8 = 0;
const WIRELESS_STATUS: u16 = 0x1d4b;
const RESPONSE_US: u64 = 5_000_000;
const ROUTES: usize = 7;
const SIGNATURES: u16 = 0x7fff;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Stopped,
    Transport,
    RejectedReport,
    ExternalControl,
    Timeout,
    InvalidNonce,
    InvalidVersion,
    UnsupportedNotification,
    Protocol(u8),
    SignatureExhausted,
    EpochExhausted,
}

/// These acknowledgements describe USB status stages, not HID++ success.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Initialization {
    ArmInput,
    Enabling,
    EnableAcknowledged,
    Querying,
    QueryAcknowledged,
    Unavailable(Error),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    Version,
    WirelessFeature,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pending {
    pub slot: u8,
    pub epoch: u64,
    pub command: Command,
    pub software_id: u8,
    pub deadline_us: u64,
    /// The USB output status stage completed. A reply is still required.
    pub usb_acknowledged: bool,
    nonce: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Version {
    pub major: u8,
    pub minor: u8,
}

/// Discovery only; no wireless event, input or battery behavior is granted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Feature {
    pub id: u16,
    /// Zero is an observed absent feature, never a usable feature index.
    pub index: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    pub slot: u8,
    pub epoch: u64,
    /// Original notification protocol/type/link/equad bytes, without guesses.
    pub notification: Option<[u8; 4]>,
    pub version: Option<Version>,
    pub feature: Option<Feature>,
    pub error: Option<Error>,
    pub version_signatures_used: u8,
    pub feature_signatures_used: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub vendor_interface: u8,
    pub member_interfaces: Vec<u8>,
    pub initialization: Initialization,
    pub pending: Option<Pending>,
    pub routes: Vec<Route>,
    pub first_error: Option<Error>,
}

#[derive(Clone)]
pub(super) struct Link {
    group: Rc<RefCell<Group>>,
    member: usize,
}
struct Member {
    interface: u8,
    endpoint: Endpoint,
    descriptor: Vec<u8>,
    active: bool,
}
struct Logical {
    view: Route,
    version_used: u16,
    feature_used: u16,
    needs_version: bool,
    needs_feature: bool,
}
impl Logical {
    fn new(slot: u8) -> Self {
        Self {
            view: Route {
                slot,
                epoch: 0,
                notification: None,
                version: None,
                feature: None,
                error: None,
                version_signatures_used: 0,
                feature_signatures_used: 0,
            },
            version_used: 0,
            feature_used: 0,
            needs_version: false,
            needs_feature: false,
        }
    }
    fn revoke(&mut self, error: Option<Error>) {
        self.view.version = None;
        self.view.feature = None;
        self.view.error = error;
        self.needs_version = false;
        self.needs_feature = false;
    }
    fn signature(&mut self, command: Command) -> Option<u8> {
        let used = match command {
            Command::Version => &mut self.version_used,
            Command::WirelessFeature => &mut self.feature_used,
        };
        if *used == SIGNATURES {
            return None;
        }
        let bit = (!*used & SIGNATURES).trailing_zeros();
        *used |= 1 << bit;
        self.view.version_signatures_used = self.version_used.count_ones() as u8;
        self.view.feature_signatures_used = self.feature_used.count_ones() as u8;
        Some(bit as u8 + 1)
    }
}
struct Group {
    controller: Weak<RefCell<Controller>>,
    id: SlotId,
    configuration: u8,
    configuration_descriptor: Vec<u8>,
    members: Vec<Member>,
    vendor: usize,
    initialization: Initialization,
    routes: Vec<Logical>,
    pending: Option<Pending>,
    first_error: Option<Error>,
}
struct Output {
    bytes: Vec<u8>,
    command: Option<Command>,
}
impl Group {
    fn invalidate(&mut self, error: Error) {
        self.pending = None;
        self.first_error.get_or_insert(error);
        self.initialization = Initialization::Unavailable(error);
        for route in &mut self.routes {
            route.revoke(Some(error));
        }
    }
    fn expire(&mut self, now: u64) {
        if self.pending.as_ref().is_some_and(|p| now >= p.deadline_us) {
            let pending = self.pending.take().unwrap();
            self.routes[usize::from(pending.slot - 1)].revoke(Some(Error::Timeout));
            self.first_error.get_or_insert(Error::Timeout);
        }
    }
    fn snapshot(&self) -> Snapshot {
        Snapshot {
            vendor_interface: self.members[self.vendor].interface,
            member_interfaces: self.members.iter().map(|m| m.interface).collect(),
            initialization: self.initialization,
            pending: self.pending.clone(),
            routes: self
                .routes
                .iter()
                .filter(|r| r.view.notification.is_some())
                .map(|r| r.view.clone())
                .collect(),
            first_error: self.first_error,
        }
    }
    fn notify(&mut self, bytes: &[u8]) {
        // Only source-backed equad keyboard/mouse families schedule discovery.
        // A changed unsupported observation still revokes an existing route.
        let supported = matches!(
            bytes[3],
            0x03 | 0x04 | 0x06 | 0x07 | 0x0a | 0x0c | 0x0d | 0x0f | 0x11
        ) && matches!(bytes[4] & 0x0f, 1 | 2);
        let index = usize::from(bytes[1] - 1);
        let observation = [bytes[3], bytes[4], bytes[5], bytes[6]];
        let route = &mut self.routes[index];
        if route.view.notification.is_none() && !supported {
            return;
        }
        let pending = self.pending.as_ref().is_some_and(|p| p.slot == bytes[1]);
        if route.view.notification == Some(observation)
            && (!supported || pending || route.view.version.is_some() || route.needs_version)
        {
            return;
        }
        if pending {
            self.pending = None;
        }
        route.revoke(None);
        route.view.notification = Some(observation);
        let Some(epoch) = route.view.epoch.checked_add(1) else {
            route.view.error = Some(Error::EpochExhausted);
            return;
        };
        route.view.epoch = epoch;
        if supported {
            route.needs_version = true;
        } else {
            route.view.error = Some(Error::UnsupportedNotification);
        }
        // Link bit6 remains an observation, not online permission. Only a
        // correlated root reply can establish protocol reachability.
    }
    fn observe(&mut self, bytes: &[u8], now: u64) {
        self.expire(now);
        if !matches!(
            (bytes.first(), bytes.len()),
            (Some(&SHORT), SHORT_BYTES) | (Some(&LONG), LONG_BYTES)
        ) {
            return;
        }
        let slot = bytes[1];
        if !(1..=ROUTES as u8).contains(&slot) {
            return;
        }
        if bytes[0] == SHORT && bytes[2] == CONNECTION {
            self.notify(bytes);
            return;
        }
        let Some(pending) = self.pending.as_ref() else {
            return;
        };
        let route = &self.routes[usize::from(slot - 1)];
        if slot != pending.slot || pending.epoch != route.view.epoch || !pending.usb_acknowledged {
            return;
        }
        let function = match pending.command {
            Command::Version => VERSION_FUNCTION,
            Command::WirelessFeature => FEATURE_FUNCTION,
        } | pending.software_id;
        let positive = bytes[2] == ROOT
            && bytes[3] == function
            && (pending.command == Command::Version || bytes[0] == LONG);
        let negative = ((bytes[0] == SHORT && bytes[2] == RAP_ERROR)
            || (bytes[0] == LONG && bytes[2] == FAP_ERROR))
            && bytes[3] == ROOT
            && bytes[4] == function;
        if !positive && !negative {
            return;
        }
        let pending = self.pending.take().unwrap();
        let route = &mut self.routes[usize::from(slot - 1)];
        if negative {
            let code = bytes[5];
            if pending.command == Command::Version && bytes[0] == SHORT && code == INVALID_SUBID {
                route.view.version = Some(Version { major: 1, minor: 0 });
                route.view.error = None;
            } else {
                route.revoke(Some(Error::Protocol(code)));
            }
            return;
        }
        match pending.command {
            Command::Version => {
                if bytes[6] != pending.nonce {
                    route.revoke(Some(Error::InvalidNonce));
                } else if bytes[4] == 0 {
                    route.revoke(Some(Error::InvalidVersion));
                } else {
                    route.view.version = Some(Version {
                        major: bytes[4],
                        minor: bytes[5],
                    });
                    route.view.error = None;
                    route.needs_feature = bytes[4] >= 2;
                }
            }
            Command::WirelessFeature => {
                route.view.feature = Some(Feature {
                    id: WIRELESS_STATUS,
                    index: bytes[4],
                });
                route.view.error = None;
            }
        }
    }
    fn next(&mut self, now: u64) -> Option<Output> {
        self.expire(now);
        if !self.members.iter().all(|m| m.active) {
            return None;
        }
        match self.initialization {
            Initialization::ArmInput => {
                self.initialization = Initialization::Enabling;
                return Some(Output {
                    bytes: alloc::vec![
                        SHORT,
                        RECEIVER,
                        SET_REGISTER,
                        NOTIFICATION_REGISTER,
                        0,
                        NOTIFICATION_FLAGS,
                        0
                    ],
                    command: None,
                });
            }
            Initialization::EnableAcknowledged => {
                self.initialization = Initialization::Querying;
                return Some(Output {
                    bytes: alloc::vec![
                        SHORT,
                        RECEIVER,
                        SET_REGISTER,
                        CONNECTION_REGISTER,
                        FAKE_ARRIVAL,
                        0,
                        0
                    ],
                    command: None,
                });
            }
            Initialization::QueryAcknowledged => {}
            _ => return None,
        }
        if self.pending.is_some() {
            return None;
        }
        for route in &mut self.routes {
            let command = if route.needs_version {
                Command::Version
            } else if route.needs_feature {
                Command::WirelessFeature
            } else {
                continue;
            };
            let Some(software_id) = route.signature(command) else {
                route.revoke(Some(Error::SignatureExhausted));
                continue;
            };
            let Some(deadline_us) = now.checked_add(RESPONSE_US) else {
                route.revoke(Some(Error::Timeout));
                continue;
            };
            let nonce = software_id; // Never reused for this slot/version class.
            let bytes = match command {
                Command::Version => {
                    route.needs_version = false;
                    alloc::vec![
                        SHORT,
                        route.view.slot,
                        ROOT,
                        VERSION_FUNCTION | software_id,
                        0,
                        0,
                        nonce
                    ]
                }
                Command::WirelessFeature => {
                    route.needs_feature = false;
                    let mut bytes = alloc::vec![0;LONG_BYTES];
                    bytes[..6].copy_from_slice(&[
                        LONG,
                        route.view.slot,
                        ROOT,
                        FEATURE_FUNCTION | software_id,
                        (WIRELESS_STATUS >> 8) as u8,
                        WIRELESS_STATUS as u8,
                    ]);
                    bytes
                }
            };
            self.pending = Some(Pending {
                slot: route.view.slot,
                epoch: route.view.epoch,
                command,
                software_id,
                deadline_us,
                usb_acknowledged: false,
                nonce,
            });
            return Some(Output {
                bytes,
                command: Some(command),
            });
        }
        None
    }
    fn acknowledge(&mut self, output: &Output, now: u64) {
        if output.command.is_some() {
            if let Some(pending) = &mut self.pending {
                pending.usb_acknowledged = true;
            }
            self.expire(now);
        } else {
            self.initialization = match self.initialization {
                Initialization::Enabling => Initialization::EnableAcknowledged,
                Initialization::Querying => Initialization::QueryAcknowledged,
                other => other,
            };
        }
    }
}
