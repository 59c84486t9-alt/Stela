//! RecoveryOS policy nonce commands from the unchanged 26A434 AP builder.
//!
//! libbootpolicy __TEXT +0x64ac, +0xc8c8 and +0xcae0 select commands 8, 9
//! and 10. Their common builder +0x4538..0x4670 sends 0x124 zeroed bytes
//! (the transport fills the 32-byte header) and expects 32 back. The
//! proposed/blessed digest getters +0xec7c/+0xe1b4 select 13/16; helper
//! +0xe8a8..0xe93c sends 32 bytes and copies exactly 48 after the reply
//! header. Source SHA-256 and the Stela policy are in docs/research/sep.md.
//!
//! The native trust policy permits one unauthenticated recovery nonce
//! proposal at a time, only for these empty bodies. A proposal belongs to
//! the current store generation. Any intervening store mutation requires
//! a fresh transaction, so erase and cross-service writes cannot commit a
//! stale proposal. This conservative conflict refusal is not evidence of
//! Apple's private SEP arbitration or authorization rules.
use super::{HEADER_BYTES, SUCCESS, delivered, not_supported, reply_header};
use crate::platform::apple::sep::{
    Entropy,
    message::Frame,
    policy::{self, Update},
    store::{Backend, Nonces, PolicyNonce},
    transaction::{Payload, Refusal},
};
use stela_contracts::refuse;

const BEGIN: u32 = 8;
const END: u32 = 9;
const RESET: u32 = 10;
const PROPOSED_DIGEST: u32 = 13;
const BLESSED_DIGEST: u32 = 16;
const MUTATION_BYTES: usize = 0x124;
const DIGEST_REPLY_BYTES: usize = HEADER_BYTES + policy::DIGEST_BYTES;

pub(super) fn accepts(command: u32) -> bool {
    matches!(
        command,
        BEGIN | END | RESET | PROPOSED_DIGEST | BLESSED_DIGEST
    )
}

struct Proposal {
    generation: u64,
    update: Update,
}

#[derive(Default)]
pub(super) struct RecoveryNonce {
    proposal: Option<Proposal>,
}

impl RecoveryNonce {
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
        let mutation = matches!(command, BEGIN | END | RESET);
        let expected = if mutation {
            MUTATION_BYTES
        } else {
            HEADER_BYTES
        };
        if frame.data as usize != expected {
            return Err(unsupported(refuse!(
                "SEP recovery policy nonce request has an unsupported length"
            )));
        }
        if mutation {
            let mut body = [0; MUTATION_BYTES - HEADER_BYTES];
            payload.input(&mut body).map_err(unsupported)?;
            if body.iter().any(|&byte| byte != 0) {
                return Err(unsupported(refuse!(
                    "SEP recovery policy nonce owner or authorization body is not implemented"
                )));
            }
        }
        let generation = store.generation().map_err(unsupported)?;
        let header = reply_header(SUCCESS);
        match command {
            BEGIN => {
                if self.proposal.is_some() {
                    return Err(unsupported(refuse!(
                        "SEP recovery policy nonce update is already in progress"
                    )));
                }
                let update = policy::begin(PolicyNonce::Recovery, entropy).map_err(unsupported)?;
                // Output failure does not leave an invisible new proposal.
                payload.output(&header).map_err(unsupported)?;
                self.proposal = Some(Proposal { generation, update });
            }
            END => {
                let proposal = self.proposal.take().ok_or_else(|| {
                    unsupported(refuse!("SEP recovery policy nonce end has no proposal"))
                })?;
                if proposal.generation != generation {
                    return Err(unsupported(refuse!(
                        "SEP recovery policy nonce proposal belongs to an older store generation"
                    )));
                }
                // An error may mean the commit reached stable storage. Neither
                // retry nor a failure answer is valid after this boundary.
                policy::commit(store, proposal.update).map_err(Refusal::unanswerable)?;
                payload.output(&header).map_err(Refusal::unanswerable)?;
            }
            RESET => {
                // Withdraw the policy nonce and discard the live proposal. The
                // store owns uncertain commit poisoning, including failed reset.
                self.proposal = None;
                policy::reset(store, PolicyNonce::Recovery).map_err(Refusal::unanswerable)?;
                payload.output(&header).map_err(Refusal::unanswerable)?;
            }
            PROPOSED_DIGEST | BLESSED_DIGEST => {
                let digest = if command == PROPOSED_DIGEST {
                    let proposal = self.proposal.as_ref().ok_or_else(|| {
                        unsupported(refuse!("SEP recovery policy nonce has no proposal"))
                    })?;
                    if proposal.generation != generation {
                        return Err(unsupported(refuse!(
                            "SEP recovery policy nonce proposal belongs to an older store generation"
                        )));
                    }
                    proposal.update.proposed_digest()
                } else {
                    policy::committed_digest(store, PolicyNonce::Recovery)
                        .map_err(unsupported)?
                        .ok_or_else(|| {
                            unsupported(refuse!("SEP recovery policy nonce has not been committed"))
                        })?
                };
                let mut reply = [0; DIGEST_REPLY_BYTES];
                reply[..HEADER_BYTES].copy_from_slice(&header);
                reply[HEADER_BYTES..].copy_from_slice(&digest);
                payload.output(&reply).map_err(unsupported)?;
                return Ok(delivered(frame, DIGEST_REPLY_BYTES));
            }
            _ => unreachable!("command selected by accepts"),
        }
        Ok(delivered(frame, HEADER_BYTES))
    }
}

#[cfg(test)]
mod tests;
