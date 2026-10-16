//! The guest Mach port namespace (XNU `ipc/mach_port.c`, `ipc_right.c`). No
//! send-right transfer or notifications.
use super::{HOST_SELF_TRAP, REPLY_PORT_TRAP, Request, TASK_SELF_TRAP, THREAD_SELF_TRAP};
use alloc::rc::Rc;
#[cfg(not(feature = "std"))]
use alloc::{string::String, string::ToString, vec::Vec};
use anyhow::{Context, Result, bail, ensure};
use core::marker::PhantomData;
use serde::Serialize;

pub(crate) mod host;

pub const LIFECYCLE_PROFILE: &str = "darwin-owned-mach-port-lifecycle-v1";
pub const ALLOCATE_TRAP: u32 = 16;
pub const DEALLOCATE_TRAP: u32 = 18;
pub const MOD_REFS_TRAP: u32 = 19;
pub const TYPE_TRAP: u32 = 76;
pub const MACH_PORT_NULL: u32 = 0;
pub const MACH_PORT_DEAD: u32 = u32::MAX;
pub const MACH_PORT_UREFS_MAX: u32 = (1 << 16) - 1;
pub const KERN_SUCCESS: i32 = 0;
pub const KERN_INVALID_NAME: i32 = 15;
pub const KERN_INVALID_RIGHT: i32 = 17;
pub const KERN_INVALID_VALUE: i32 = 18;
pub const MACH_SEND_INVALID_DEST: i32 = 0x1000_0003;
const MAX_PORT_ACQUISITIONS: usize = 4096;
const FIRST_GUEST_PORT: u32 = 0x101;
const GUEST_PORT_STRIDE: u32 = 0x100;
const RIGHT_LABEL_HANDLE: u32 = 5;
const RIGHT_NUMBER: u32 = 6;

/// Bootstrap provenance, independent of the rights currently held. Legacy
/// variant spellings are retained for existing public snapshots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PortKind {
    ReplyReceive,
    ThreadSend,
    TaskSend,
    HostSend,
    Ordinary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[repr(u32)]
#[serde(rename_all = "snake_case")]
pub enum RightKind {
    Send = 0,
    Receive = 1,
    SendOnce = 2,
    PortSet = 3,
    DeadName = 4,
}
impl RightKind {
    fn decode(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Send),
            1 => Some(Self::Receive),
            2 => Some(Self::SendOnce),
            3 => Some(Self::PortSet),
            4 => Some(Self::DeadName),
            _ => None,
        }
    }
    const fn type_bit(self) -> u32 {
        1 << (16 + self as u32)
    }
}

/// The legal combinations share one uref count: SEND for SendReceive,
/// SEND/DEAD_NAME otherwise; receive/set/send-once have exactly one reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RightState {
    Receive,
    Send,
    SendReceive,
    SendOnce,
    PortSet,
    DeadName,
}
impl RightState {
    pub const fn type_bits(self) -> u32 {
        match self {
            Self::Receive => RightKind::Receive.type_bit(),
            Self::Send => RightKind::Send.type_bit(),
            Self::SendReceive => RightKind::Send.type_bit() | RightKind::Receive.type_bit(),
            Self::SendOnce => RightKind::SendOnce.type_bit(),
            Self::PortSet => RightKind::PortSet.type_bit(),
            Self::DeadName => RightKind::DeadName.type_bit(),
        }
    }
    pub const fn has_send(self) -> bool {
        matches!(self, Self::Send | Self::SendReceive)
    }
}

#[derive(Debug, Serialize)]
pub struct PortRight {
    pub guest_name: u32,
    pub kind: PortKind,
    pub references: u32,
    pub state: RightState,
    #[serde(skip)]
    host_name: u32,
    /// Known outstanding references only. Attempted uncertain releases are
    /// counted separately and never retried; neither count follows guest urefs.
    #[serde(skip)]
    retained_references: u32,
    #[serde(skip)]
    uncertain_releases: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Operation {
    Allocate {
        task: u32,
        right: u32,
        destination: u64,
    },
    Deallocate {
        task: u32,
        name: u32,
    },
    ModRefs {
        task: u32,
        name: u32,
        right: u32,
        delta: i32,
    },
    Type {
        task: u32,
        name: u32,
        destination: u64,
    },
}
impl Operation {
    pub fn from_request(request: &Request) -> Result<Self> {
        let args = &request.arguments;
        let operation = match (request.number, args.as_slice()) {
            (ALLOCATE_TRAP, [task, right, destination]) => Self::Allocate {
                task: *task as u32,
                right: *right as u32,
                destination: *destination,
            },
            (DEALLOCATE_TRAP, [task, name]) => Self::Deallocate {
                task: *task as u32,
                name: *name as u32,
            },
            (MOD_REFS_TRAP, [task, name, right, delta]) => Self::ModRefs {
                task: *task as u32,
                name: *name as u32,
                right: *right as u32,
                delta: *delta as u32 as i32,
            },
            (TYPE_TRAP, [task, name, destination]) => Self::Type {
                task: *task as u32,
                name: *name as u32,
                destination: *destination,
            },
            _ => bail!("not an admitted Mach port lifecycle prototype"),
        };
        Ok(operation)
    }
    fn task(self) -> u32 {
        match self {
            Self::Allocate { task, .. }
            | Self::Deallocate { task, .. }
            | Self::ModRefs { task, .. }
            | Self::Type { task, .. } => task,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Effect {
    HostAcquisition { role: PortKind, available: bool },
    HostTemporaryReleased { role: PortKind },
    HostReleaseAttempt { observation: ReleaseObservation },
    Allocated { name: u32, right: RightKind },
    References { name: u32, before: u32, after: u32 },
    DeadConversion { name: u32 },
    Released { name: u32, state: RightState },
}

/// An allocation or query has happened, but the syscall is not complete: the
/// memory adapter must attempt this write next, and the effects stand even if
/// it faults.
#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Outcome {
    NoEffect {
        reason: String,
    },
    Complete {
        value: i32,
        effects: Vec<Effect>,
    },
    Copyout {
        destination: u64,
        value: u32,
        effects: Vec<Effect>,
    },
    Indeterminate {
        error: String,
        effects: Vec<Effect>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReleaseObservation {
    pub guest_name: u32,
    pub state: RightState,
    pub status: Option<i32>,
    pub unavailable: Option<String>,
    pub reason: ReleaseReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseReason {
    DuplicateBootstrap,
    FinalReference,
    Teardown,
}
impl Outcome {
    fn complete(value: i32, effects: Vec<Effect>) -> Self {
        Self::Complete { value, effects }
    }
    fn refusal(reason: &str) -> Self {
        Self::NoEffect {
            reason: reason.into(),
        }
    }
}

/// Owner of host port rights, confined to one thread. Each entry holds one host
/// resource; guest user-reference counts never drive host releases.
pub struct HostPorts {
    address_space: u64,
    rights: Vec<PortRight>,
    acquisitions: usize,
    next_guest_name: u32,
    failed: bool,
    closed: bool,
    teardown: Vec<ReleaseObservation>,
    _thread: PhantomData<Rc<()>>,
}
impl HostPorts {
    pub fn new(address_space: u64) -> Result<Self> {
        ensure!(
            cfg!(target_os = "macos"),
            "host Mach port services require macOS"
        );
        Ok(Self {
            address_space,
            rights: Vec::new(),
            acquisitions: 0,
            next_guest_name: FIRST_GUEST_PORT,
            failed: false,
            closed: false,
            teardown: Vec::new(),
            _thread: PhantomData,
        })
    }
    pub fn address_space(&self) -> u64 {
        self.address_space
    }
    pub fn rights(&self) -> &[PortRight] {
        &self.rights
    }
    pub fn is_usable(&self) -> bool {
        !self.failed
    }
    pub fn has_task_send(&self, name: u32) -> bool {
        !self.failed
            && self.rights.iter().any(|right| {
                right.guest_name == name
                    && right.kind == PortKind::TaskSend
                    && right.state.has_send()
            })
    }
    fn reserve_name(&mut self) -> Result<u32> {
        ensure!(
            self.acquisitions < MAX_PORT_ACQUISITIONS,
            "host port acquisition budget exhausted"
        );
        ensure!(
            self.next_guest_name < i32::MAX as u32,
            "guest port namespace exhausted"
        );
        self.rights
            .try_reserve(1)
            .context("reserve owned port ledger")?;
        Ok(self.next_guest_name)
    }
    fn insert(&mut self, guest_name: u32, kind: PortKind, state: RightState, host_name: u32) {
        self.rights.push(PortRight {
            guest_name,
            kind,
            references: 1,
            state,
            host_name,
            retained_references: 1,
            uncertain_releases: 0,
        });
        self.next_guest_name += GUEST_PORT_STRIDE;
        self.acquisitions += 1;
    }
    fn terminal(&mut self, error: impl core::fmt::Display, effects: Vec<Effect>) -> Outcome {
        self.failed = true;
        Outcome::Indeterminate {
            error: error.to_string(),
            effects,
        }
    }

    pub fn bootstrap(&mut self, request: &Request) -> Outcome {
        if self.failed {
            return Outcome::refusal("owned Mach namespace is terminal");
        }
        if !request.arguments.is_empty() {
            return Outcome::refusal("bootstrap port traps take no arguments");
        }
        let role = match request.number {
            REPLY_PORT_TRAP => PortKind::ReplyReceive,
            THREAD_SELF_TRAP => PortKind::ThreadSend,
            TASK_SELF_TRAP => PortKind::TaskSend,
            HOST_SELF_TRAP => PortKind::HostSend,
            _ => return Outcome::refusal("not an admitted bootstrap port trap"),
        };
        let name = match self.reserve_name() {
            Ok(name) => name,
            Err(error) => return Outcome::refusal(&error.to_string()),
        };
        let host_name = match host::acquire(role) {
            Ok(name) => name,
            Err(error) => return Outcome::refusal(&error.to_string()),
        };
        let mut effects = vec![Effect::HostAcquisition {
            role,
            available: host_name != MACH_PORT_NULL,
        }];
        if host_name == MACH_PORT_NULL {
            return Outcome::complete(0, effects);
        }
        // Reply receive rights are separate allocations. Duplicated bootstrap
        // send rights are normalized before the guest reference count changes.
        if let Some(index) = self.rights.iter().position(|right| {
            right.host_name == host_name && right.kind == role && right.state == RightState::Send
        }) {
            self.acquisitions += 1;
            // Release only the newly acquired reference; the retained one stays
            // owned for cleanup.
            let result = host::deallocate(host_name);
            let observation = ReleaseObservation::new(
                self.rights[index].guest_name,
                RightState::Send,
                ReleaseReason::DuplicateBootstrap,
                result,
            );
            let released = observation.status == Some(KERN_SUCCESS);
            effects.push(Effect::HostReleaseAttempt {
                observation: observation.clone(),
            });
            self.teardown.push(observation);
            if !released {
                self.rights[index].uncertain_releases += 1;
                return self.terminal(
                    "duplicate cleanup failed; attempted temporary is not retryable",
                    effects,
                );
            }
            effects.push(Effect::HostTemporaryReleased { role });
            let right = &mut self.rights[index];
            let before = right.references;
            right.references = before.saturating_add(1).min(MACH_PORT_UREFS_MAX);
            effects.push(Effect::References {
                name: right.guest_name,
                before,
                after: right.references,
            });
            return Outcome::complete(right.guest_name as i32, effects);
        }
        let state = if role == PortKind::ReplyReceive {
            RightState::Receive
        } else {
            RightState::Send
        };
        self.insert(name, role, state, host_name);
        Outcome::complete(name as i32, effects)
    }

    /// Compatibility API; checked service dispatch should consume `bootstrap`
    /// to retain its acquisition/release observations on terminal failure.
    pub fn request(&mut self, request: &Request) -> Result<i32> {
        match self.bootstrap(request) {
            Outcome::Complete { value, .. } => Ok(value),
            Outcome::NoEffect { reason } => bail!("{reason}"),
            Outcome::Indeterminate { error, .. } => bail!("terminal Mach namespace: {error}"),
            Outcome::Copyout { .. } => unreachable!("bootstrap has no guest copyout"),
        }
    }

    pub fn thread_identifier(&self, guest_name: u32) -> Result<u64> {
        ensure!(!self.failed, "owned Mach namespace is terminal");
        let right = self
            .rights
            .iter()
            .find(|right| {
                right.guest_name == guest_name
                    && right.kind == PortKind::ThreadSend
                    && right.state.has_send()
            })
            .context("guest name is not an owned thread send right")?;
        host::thread_identifier(right.host_name)
    }

    pub fn execute(&mut self, operation: Operation) -> Outcome {
        if self.failed {
            return Outcome::refusal("owned Mach namespace is terminal");
        }
        // All four pinned fast traps resolve current-task control first.
        if !self.has_task_send(operation.task()) {
            return Outcome::complete(MACH_SEND_INVALID_DEST, vec![]);
        }
        match operation {
            Operation::Allocate {
                right, destination, ..
            } => self.allocate(right, destination),
            Operation::Type {
                name, destination, ..
            } => self.port_type(name, destination),
            Operation::Deallocate { name, .. } => self.deallocate(name),
            Operation::ModRefs {
                name, right, delta, ..
            } => self.mod_refs(name, right, delta),
        }
    }

    fn allocate(&mut self, raw: u32, destination: u64) -> Outcome {
        let right = match RightKind::decode(raw) {
            Some(right @ (RightKind::Receive | RightKind::PortSet | RightKind::DeadName)) => right,
            _ => return Outcome::complete(KERN_INVALID_VALUE, vec![]),
        };
        let name = match self.reserve_name() {
            Ok(name) => name,
            Err(error) => return Outcome::refusal(&error.to_string()),
        };
        let (status, host_name) = match host::allocate(right) {
            Ok(result) => result,
            Err(error) => return Outcome::refusal(&error.to_string()),
        };
        if status != KERN_SUCCESS {
            return Outcome::complete(status, vec![]);
        }
        if host_name == MACH_PORT_NULL || host_name == MACH_PORT_DEAD {
            return self.terminal("host allocation succeeded with invalid name", vec![]);
        }
        let state = match right {
            RightKind::Receive => RightState::Receive,
            RightKind::PortSet => RightState::PortSet,
            RightKind::DeadName => RightState::DeadName,
            _ => unreachable!("admitted allocation right"),
        };
        self.insert(name, PortKind::Ordinary, state, host_name);
        Outcome::Copyout {
            destination,
            value: name,
            effects: vec![Effect::Allocated { name, right }],
        }
    }

    fn refresh(&mut self, index: usize, effects: &mut Vec<Effect>) -> Result<()> {
        if matches!(
            self.rights[index].state,
            RightState::Send | RightState::SendOnce
        ) {
            let (status, bits) = host::port_type(self.rights[index].host_name)?;
            ensure!(
                status == KERN_SUCCESS,
                "query retained host right failed: {status}"
            );
            if bits & RightKind::DeadName.type_bit() != 0 {
                self.rights[index].state = RightState::DeadName;
                effects.push(Effect::DeadConversion {
                    name: self.rights[index].guest_name,
                });
            }
        }
        Ok(())
    }
    fn port_type(&mut self, name: u32, destination: u64) -> Outcome {
        if name == MACH_PORT_NULL {
            return Outcome::complete(KERN_INVALID_NAME, vec![]);
        }
        if name == MACH_PORT_DEAD {
            return Outcome::Copyout {
                destination,
                value: RightKind::DeadName.type_bit(),
                effects: vec![],
            };
        }
        let Some(index) = self
            .rights
            .iter()
            .position(|right| right.guest_name == name)
        else {
            return Outcome::complete(KERN_INVALID_NAME, vec![]);
        };
        let mut effects = vec![];
        if let Err(error) = self.refresh(index, &mut effects) {
            return self.terminal(error, effects);
        }
        Outcome::Copyout {
            destination,
            value: self.rights[index].state.type_bits(),
            effects,
        }
    }
    fn deallocate(&mut self, name: u32) -> Outcome {
        if name == MACH_PORT_NULL || name == MACH_PORT_DEAD {
            return Outcome::complete(KERN_SUCCESS, vec![]);
        }
        let Some(index) = self
            .rights
            .iter()
            .position(|right| right.guest_name == name)
        else {
            return Outcome::refusal(
                "unknown-name deallocation requires guest guard exception delivery",
            );
        };
        let mut effects = vec![];
        if let Err(error) = self.refresh(index, &mut effects) {
            return self.terminal(error, effects);
        }
        let right = &self.rights[index];
        match right.state {
            RightState::Send | RightState::DeadName => {
                if right.references > 1 {
                    let before = right.references;
                    let after = if before == MACH_PORT_UREFS_MAX {
                        before
                    } else {
                        before - 1
                    };
                    self.rights[index].references = after;
                    effects.push(Effect::References {
                        name,
                        before,
                        after,
                    });
                    Outcome::complete(KERN_SUCCESS, effects)
                } else if right.state == RightState::Send && right.kind != PortKind::Ordinary {
                    // No host destructive probe against unproved pinned rights.
                    Outcome::refusal("final bootstrap send removal requires a pinned-right policy")
                } else {
                    self.release(index, effects)
                }
            }
            RightState::PortSet => self.release(index, effects),
            _ => Outcome::refusal(
                "deallocation of this right requires a reviewed guard/transfer policy",
            ),
        }
    }
    fn mod_refs(&mut self, name: u32, raw: u32, delta: i32) -> Outcome {
        if raw >= RIGHT_NUMBER {
            return Outcome::complete(KERN_INVALID_VALUE, vec![]);
        }
        if name == MACH_PORT_NULL || name == MACH_PORT_DEAD {
            let value = if matches!(
                RightKind::decode(raw),
                Some(RightKind::Send | RightKind::SendOnce)
            ) {
                KERN_SUCCESS
            } else {
                KERN_INVALID_NAME
            };
            return Outcome::complete(value, vec![]);
        }
        let Some(index) = self
            .rights
            .iter()
            .position(|right| right.guest_name == name)
        else {
            return Outcome::refusal(
                "unknown-name mod_refs requires guest guard exception delivery",
            );
        };
        // LABELH branches directly to invalid_right without checking port death.
        if raw == RIGHT_LABEL_HANDLE {
            return Outcome::complete(KERN_INVALID_RIGHT, vec![]);
        }
        let requested = RightKind::decode(raw);
        let mut effects = vec![];
        if matches!(requested, Some(RightKind::Send | RightKind::DeadName))
            && let Err(error) = self.refresh(index, &mut effects)
        {
            return self.terminal(error, effects);
        }
        let right = &self.rights[index];
        if requested == Some(RightKind::Send) && right.state == RightState::DeadName {
            return Outcome::complete(KERN_INVALID_RIGHT, effects);
        }
        let matching = matches!(
            (requested, right.state),
            (Some(RightKind::Send), RightState::Send)
                | (Some(RightKind::Receive), RightState::Receive)
                | (Some(RightKind::PortSet), RightState::PortSet)
                | (Some(RightKind::DeadName), RightState::DeadName)
        );
        if !matching {
            if effects.is_empty() {
                return Outcome::refusal(
                    "wrong-right mod_refs requires guest guard exception delivery",
                );
            }
            return self.terminal("right changed before unsupported mod_refs form", effects);
        }
        match right.state {
            RightState::Send | RightState::DeadName => {
                let before = right.references;
                let Some(after) = reference_delta(before, delta) else {
                    if effects.is_empty() {
                        return Outcome::refusal(
                            "invalid reference delta requires guest guard exception delivery",
                        );
                    }
                    return self.terminal("right changed before invalid reference delta", effects);
                };
                if after == 0 {
                    if right.state == RightState::Send && right.kind != PortKind::Ordinary {
                        return Outcome::refusal(
                            "final bootstrap send removal requires a pinned-right policy",
                        );
                    }
                    return self.release(index, effects);
                }
                self.rights[index].references = after;
                effects.push(Effect::References {
                    name,
                    before,
                    after,
                });
                Outcome::complete(KERN_SUCCESS, effects)
            }
            RightState::Receive | RightState::PortSet => {
                if delta == 0 {
                    return Outcome::complete(KERN_SUCCESS, effects);
                }
                if delta == -1 && right.kind == PortKind::Ordinary {
                    return self.release(index, effects);
                }
                Outcome::refusal("receive/set delta requires a reviewed guard policy")
            }
            _ => unreachable!("matched first-profile right state"),
        }
    }
    fn release(&mut self, index: usize, mut effects: Vec<Effect>) -> Outcome {
        let right = &mut self.rights[index];
        // Consume this outstanding obligation before its single attempt. On
        // failure it moves to uncertain and can never enter cleanup again.
        right.retained_references -= 1;
        let result = host::release(right.host_name, right.state);
        let observation = ReleaseObservation::new(
            right.guest_name,
            right.state,
            ReleaseReason::FinalReference,
            result,
        );
        let released = observation.status == Some(KERN_SUCCESS);
        effects.push(Effect::HostReleaseAttempt {
            observation: observation.clone(),
        });
        self.teardown.push(observation);
        if !released {
            self.rights[index].uncertain_releases += 1;
            return self.terminal(
                "final host release failed; attempted obligation is not retryable",
                effects,
            );
        }
        let right = self.rights.remove(index);
        effects.push(Effect::Released {
            name: right.guest_name,
            state: right.state,
        });
        Outcome::complete(KERN_SUCCESS, effects)
    }

    /// Tear down and return the release results. A failed release is recorded,
    /// never retried. Drop does this when no one reads the report.
    pub fn close(&mut self) -> &[ReleaseObservation] {
        if !self.closed {
            self.failed = true;
            self.closed = true;
            for right in &mut self.rights {
                while right.retained_references != 0 {
                    right.retained_references -= 1;
                    let result = host::release(right.host_name, right.state);
                    let observation = ReleaseObservation::new(
                        right.guest_name,
                        right.state,
                        ReleaseReason::Teardown,
                        result,
                    );
                    if observation.status != Some(KERN_SUCCESS) {
                        right.uncertain_releases += 1;
                    }
                    self.teardown.push(observation);
                }
            }
        }
        &self.teardown
    }
}

impl ReleaseObservation {
    fn new(guest_name: u32, state: RightState, reason: ReleaseReason, result: Result<i32>) -> Self {
        let (status, unavailable) = match result {
            Ok(status) => (Some(status), None),
            Err(error) => (None, Some(error.to_string())),
        };
        Self {
            guest_name,
            state,
            status,
            unavailable,
            reason,
        }
    }
}

/// None denotes a source guard-exception path, not an ordinary kernel error.
fn reference_delta(before: u32, delta: i32) -> Option<u32> {
    if delta < -(MACH_PORT_UREFS_MAX as i32) || delta > MACH_PORT_UREFS_MAX as i32 {
        return None;
    }
    if before == MACH_PORT_UREFS_MAX {
        return Some(if delta == -(MACH_PORT_UREFS_MAX as i32) {
            0
        } else {
            before
        });
    }
    let after = i64::from(before) + i64::from(delta);
    if after < 0 {
        None
    } else {
        Some((after as u32).min(MACH_PORT_UREFS_MAX))
    }
}

impl Drop for HostPorts {
    fn drop(&mut self) {
        // One host resource per entry, irrespective of guest saturation. No
        // guest name is passed to the host; no unrelated host refs are dropped.
        self.close();
    }
}

#[cfg(test)]
mod tests;
