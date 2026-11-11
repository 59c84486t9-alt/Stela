//! Policy nonce commands from the unchanged 26A434 AP builder.
//!
//! libbootpolicy __TEXT +0x64ac, +0xc8c8 and +0xcae0 select the recoveryOS
//! commands 8, 9 and 10, and +0x43d8, +0x55dc and +0x59d8 the local 2, 3 and
//! 4. Their common builder `_update_policy_nonce` +0x4538..0x4670 sends 0x124
//! bytes (the transport fills the 32-byte header), an optional ACM's u16
//! length at +0x20 and bytes at +0x22, and expects 32 back; restored passes
//! no ACM. The proposed/blessed digest getters +0xec7c/+0xe1b4 select 13/16,
//! and +0xe754/+0xe3c8 the local 11/14; helper +0xe8a8..0xe93c sends 32
//! bytes and copies exactly 48 after the reply header. Commands 5..7, 12 and
//! 15 are the remote nonce's, which stays refused.
//!
//! The native trust policy permits one unauthenticated proposal per nonce
//! at a time, only for these empty bodies. A proposal belongs to
//! the current store generation. Any intervening store mutation requires
//! a fresh transaction, so erase and cross-service writes cannot commit a
//! stale proposal. This conservative conflict refusal is not evidence of
//! Apple's private SEP arbitration or authorization rules.
use super::{HEADER_BYTES, SUCCESS, delivered, not_supported, reply_header};
use crate::sep::{
    Entropy,
    message::Frame,
    policy::{self, Update},
    store::{Backend, Nonces, POLICY_NONCE_BYTES, PolicyNonce},
    transaction::{Payload, Refusal},
};
use stela_contracts::refuse;
use zeroize::Zeroizing;

const MUTATION_BYTES: usize = 0x124;
const DIGEST_REPLY_BYTES: usize = HEADER_BYTES + policy::DIGEST_BYTES;

/// One policy nonce's commands.
struct Commands {
    which: PolicyNonce,
    begin: u32,
    end: u32,
    reset: u32,
    proposed: u32,
    blessed: u32,
}

const LOCAL: Commands = Commands {
    which: PolicyNonce::MacOs,
    begin: 2,
    end: 3,
    reset: 4,
    proposed: 11,
    blessed: 14,
};
const RECOVERY: Commands = Commands {
    which: PolicyNonce::Recovery,
    begin: 8,
    end: 9,
    reset: 10,
    proposed: 13,
    blessed: 16,
};

fn commands(command: u32) -> Option<&'static Commands> {
    [&LOCAL, &RECOVERY].into_iter().find(|nonce| {
        [
            nonce.begin,
            nonce.end,
            nonce.reset,
            nonce.proposed,
            nonce.blessed,
        ]
        .contains(&command)
    })
}

pub(super) fn accepts(command: u32) -> bool {
    commands(command).is_some()
}

struct Proposal {
    generation: u64,
    update: Update,
}

#[derive(Default)]
pub(super) struct PolicyNonces {
    local: Option<Proposal>,
    recovery: Option<Proposal>,
    /// The nonce the next recoveryOS `begin` proposes instead of drawing
    /// one, used once ([`PolicyNonces::set_first_recovery`]).
    first_recovery: Option<Zeroizing<[u8; POLICY_NONCE_BYTES]>>,
}

impl PolicyNonces {
    fn proposal(&mut self, which: PolicyNonce) -> &mut Option<Proposal> {
        match which {
            PolicyNonce::MacOs => &mut self.local,
            PolicyNonce::Recovery => &mut self.recovery,
        }
    }

    /// Propose `nonce` at the next recoveryOS `begin` only: an install boot
    /// whose recoveryOS LocalPolicy setup had Apple sign for its digest.
    pub(super) fn set_first_recovery(&mut self, nonce: [u8; POLICY_NONCE_BYTES]) {
        self.first_recovery = Some(Zeroizing::new(nonce));
    }

    /// The digest of the local nonce update in progress, which a policy made
    /// during it binds as `lpnh`.
    pub(super) fn proposed_local<B: Backend>(
        &self,
        store: &Nonces<B>,
    ) -> crate::Result<[u8; policy::DIGEST_BYTES]> {
        let proposal = self.local.as_ref().ok_or(refuse!(
            "SEP LocalPolicy creation is outside a local policy nonce update"
        ))?;
        if proposal.generation != store.generation()? {
            return Err(refuse!(
                "SEP policy nonce proposal belongs to an older store generation"
            ));
        }
        Ok(proposal.update.proposed_digest())
    }

    pub(super) fn request<B: Backend>(
        &mut self,
        command: u32,
        frame: Frame,
        payload: &mut dyn Payload,
        store: &mut Nonces<B>,
        entropy: &mut dyn Entropy,
    ) -> Result<Frame, Refusal> {
        let unsupported =
            |reason: stela_contracts::Refusal| Refusal::answered(reason, not_supported(frame));
        let nonce = commands(command)
            .ok_or_else(|| unsupported(refuse!("SEP policy nonce command is not implemented")))?;
        let mutation = [nonce.begin, nonce.end, nonce.reset].contains(&command);
        let expected = if mutation {
            MUTATION_BYTES
        } else {
            HEADER_BYTES
        };
        if frame.data as usize != expected {
            return Err(unsupported(refuse!(
                "SEP policy nonce request has an unsupported length"
            )));
        }
        if mutation {
            let mut body = [0; MUTATION_BYTES - HEADER_BYTES];
            payload.input(&mut body).map_err(unsupported)?;
            if body.iter().any(|&byte| byte != 0) {
                return Err(unsupported(refuse!(
                    "SEP policy nonce owner or authorization body is not implemented"
                )));
            }
        }
        let generation = store.generation().map_err(unsupported)?;
        let header = reply_header(SUCCESS);
        if command == nonce.begin {
            if self.proposal(nonce.which).is_some() {
                return Err(unsupported(refuse!(
                    "SEP policy nonce update is already in progress"
                )));
            }
            let chosen = match nonce.which {
                PolicyNonce::Recovery => self.first_recovery.clone(),
                PolicyNonce::MacOs => None,
            };
            let update = match &chosen {
                Some(chosen) => policy::begin_with(nonce.which, chosen),
                None => policy::begin(nonce.which, entropy).map_err(unsupported)?,
            };
            // Output failure does not leave an invisible new proposal, nor
            // spend the chosen nonce.
            payload.output(&header).map_err(unsupported)?;
            if chosen.is_some() {
                self.first_recovery = None;
            }
            *self.proposal(nonce.which) = Some(Proposal { generation, update });
        } else if command == nonce.end {
            let proposal = self
                .proposal(nonce.which)
                .take()
                .ok_or_else(|| unsupported(refuse!("SEP policy nonce end has no proposal")))?;
            if proposal.generation != generation {
                return Err(unsupported(refuse!(
                    "SEP policy nonce proposal belongs to an older store generation"
                )));
            }
            // An error may mean the commit reached stable storage. Neither
            // retry nor a failure answer is valid after this boundary.
            policy::commit(store, proposal.update).map_err(Refusal::unanswerable)?;
            payload.output(&header).map_err(Refusal::unanswerable)?;
        } else if command == nonce.reset {
            // Withdraw the policy nonce and discard the live proposal. The
            // store owns uncertain commit poisoning, including failed reset.
            *self.proposal(nonce.which) = None;
            policy::reset(store, nonce.which).map_err(Refusal::unanswerable)?;
            payload.output(&header).map_err(Refusal::unanswerable)?;
        } else {
            let digest = if command == nonce.proposed {
                let proposal = self
                    .proposal(nonce.which)
                    .as_ref()
                    .ok_or_else(|| unsupported(refuse!("SEP policy nonce has no proposal")))?;
                if proposal.generation != generation {
                    return Err(unsupported(refuse!(
                        "SEP policy nonce proposal belongs to an older store generation"
                    )));
                }
                proposal.update.proposed_digest()
            } else {
                policy::committed_digest(store, nonce.which)
                    .map_err(unsupported)?
                    .ok_or_else(|| {
                        unsupported(refuse!("SEP policy nonce has not been committed"))
                    })?
            };
            let mut reply = [0; DIGEST_REPLY_BYTES];
            reply[..HEADER_BYTES].copy_from_slice(&header);
            reply[HEADER_BYTES..].copy_from_slice(&digest);
            payload.output(&reply).map_err(unsupported)?;
            return Ok(delivered(frame, DIGEST_REPLY_BYTES));
        }
        Ok(delivered(frame, HEADER_BYTES))
    }
}

#[cfg(test)]
mod tests;
