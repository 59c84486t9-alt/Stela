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
        let unsupported = |reason| Refusal::answered(reason, not_supported(frame));
        let mutation = matches!(command, BEGIN | END | RESET);
        let expected = if mutation {
            MUTATION_BYTES
        } else {
            HEADER_BYTES
        };
        if frame.data as usize != expected {
            return Err(unsupported(
                "SEP recovery policy nonce request has an unsupported length",
            ));
        }
        if mutation {
            let mut body = [0; MUTATION_BYTES - HEADER_BYTES];
            payload.input(&mut body).map_err(unsupported)?;
            if body.iter().any(|&byte| byte != 0) {
                return Err(unsupported(
                    "SEP recovery policy nonce owner or authorization body is not implemented",
                ));
            }
        }
        let generation = store.generation().map_err(unsupported)?;
        let header = reply_header(SUCCESS);
        match command {
            BEGIN => {
                if self.proposal.is_some() {
                    return Err(unsupported(
                        "SEP recovery policy nonce update is already in progress",
                    ));
                }
                let update = policy::begin(PolicyNonce::Recovery, entropy).map_err(unsupported)?;
                // Output failure does not leave an invisible new proposal.
                payload.output(&header).map_err(unsupported)?;
                self.proposal = Some(Proposal { generation, update });
            }
            END => {
                let proposal = self
                    .proposal
                    .take()
                    .ok_or_else(|| unsupported("SEP recovery policy nonce end has no proposal"))?;
                if proposal.generation != generation {
                    return Err(unsupported(
                        "SEP recovery policy nonce proposal belongs to an older store generation",
                    ));
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
                    let proposal = self
                        .proposal
                        .as_ref()
                        .ok_or_else(|| unsupported("SEP recovery policy nonce has no proposal"))?;
                    if proposal.generation != generation {
                        return Err(unsupported(
                            "SEP recovery policy nonce proposal belongs to an older store generation",
                        ));
                    }
                    proposal.update.proposed_digest()
                } else {
                    policy::committed_digest(store, PolicyNonce::Recovery)
                        .map_err(unsupported)?
                        .ok_or_else(|| {
                            unsupported("SEP recovery policy nonce has not been committed")
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
mod tests {
    use super::super::{BootPolicy, HEADER_BYTES, REQUEST_MAGIC};
    use super::*;
    use crate::platform::apple::sep::{
        keys::Roots,
        store::{Head, Volatile},
    };
    use alloc::{rc::Rc, vec, vec::Vec};
    use core::cell::Cell;

    struct Buffers {
        input: Vec<u8>,
        read: usize,
        output: Vec<u8>,
        fail_output: bool,
    }

    impl Payload for Buffers {
        fn input(&mut self, bytes: &mut [u8]) -> Result<(), &'static str> {
            let source = self
                .input
                .get(self.read..self.read + bytes.len())
                .ok_or("short input")?;
            bytes.copy_from_slice(source);
            self.read += bytes.len();
            Ok(())
        }
        fn output(&mut self, bytes: &[u8]) -> Result<(), &'static str> {
            if self.fail_output {
                return Err("output DMA failed");
            }
            self.output = bytes.to_vec();
            Ok(())
        }
    }

    fn command(op: u32) -> Buffers {
        let length = if matches!(op, BEGIN | END | RESET) {
            MUTATION_BYTES
        } else {
            HEADER_BYTES
        };
        let mut input = vec![0; length];
        input[..4].copy_from_slice(&REQUEST_MAGIC.to_le_bytes());
        input[4..8].copy_from_slice(&op.to_le_bytes());
        Buffers {
            input,
            read: 0,
            output: Vec::new(),
            fail_output: false,
        }
    }

    fn roots() -> Roots {
        Roots::provisioned([1; 32], [2; 32], 0x1234).unwrap()
    }

    fn store() -> Nonces<Volatile> {
        Nonces::provision(&roots(), Volatile::default()).unwrap()
    }

    fn entropy(bytes: &mut [u8]) -> Result<(), &'static str> {
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = i as u8 + 1;
        }
        Ok(())
    }

    fn ask<B: Backend>(
        policy: &mut BootPolicy,
        store: &mut Nonces<B>,
        buffers: &mut Buffers,
    ) -> Result<Frame, Refusal> {
        let frame = Frame {
            service: super::super::ID,
            tag: 2,
            opcode: 0,
            parameter: 0,
            data: buffers.input.len() as u32,
        };
        policy.request(frame, buffers, store, &mut entropy)
    }

    fn success<B: Backend>(policy: &mut BootPolicy, store: &mut Nonces<B>, op: u32) -> Vec<u8> {
        let mut buffers = command(op);
        let reply = ask(policy, store, &mut buffers).unwrap();
        assert_eq!(reply.data as usize, buffers.output.len());
        assert_eq!(buffers.read, buffers.input.len());
        assert_eq!(&buffers.output[..HEADER_BYTES], &reply_header(SUCCESS));
        buffers.output
    }

    #[test]
    #[ignore = "requires unchanged 26A434 libbootpolicy __TEXT via STELA_TEST_BOOTPOLICY_TEXT"]
    fn original_recovery_nonce_builders_select_the_recovered_commands_and_buffer_sizes() {
        use sha2::{Digest, Sha256};
        let text = std::fs::read(std::env::var("STELA_TEST_BOOTPOLICY_TEXT").unwrap()).unwrap();
        assert_eq!(text.len(), 291_536);
        assert_eq!(
            alloc::format!("{:x}", Sha256::digest(&text)),
            "992b85e6dedb76167c73b693e864f5920cc6dca780cf22933f4e1b60666b8536"
        );
        // Decode the ISA's MOVZ Wd,#imm16 form at the original AP builders;
        // no Apple instructions or guest image are committed as a fixture.
        let movz = |offset: usize, register: u32, immediate: u32| {
            let word = u32::from_le_bytes(text[offset..offset + 4].try_into().unwrap());
            assert_eq!(word & 0xffe0_001f, 0x5280_0000 | register);
            assert_eq!((word >> 5) & 0xffff, immediate);
        };
        for (at, command) in [
            (0x64ac, BEGIN),
            (0xc8c8, END),
            (0xcae0, RESET),
            (0xec7c, PROPOSED_DIGEST),
            (0xe1b4, BLESSED_DIGEST),
        ] {
            movz(at, 0, command);
        }
        movz(0x4610, 1, MUTATION_BYTES as u32);
        movz(0x4664, 2, MUTATION_BYTES as u32);
        movz(0x466c, 4, HEADER_BYTES as u32);
        movz(0xe8dc, 1, HEADER_BYTES as u32);
        movz(0xe900, 1, DIGEST_REPLY_BYTES as u32);
        movz(0xe918, 2, HEADER_BYTES as u32);
        movz(0xe920, 4, DIGEST_REPLY_BYTES as u32);
    }

    #[test]
    fn recovered_recovery_commands_bind_the_durable_nonce_and_exact_reply_lengths() {
        let mut policy = BootPolicy::new(None);
        let mut store = store();
        let generation = store.generation().unwrap();
        assert_eq!(success(&mut policy, &mut store, BEGIN).len(), HEADER_BYTES);
        assert_eq!(store.generation(), Ok(generation));
        assert_eq!(store.policy_nonce(PolicyNonce::Recovery), Ok(None));
        let proposed = success(&mut policy, &mut store, PROPOSED_DIGEST);
        assert_eq!(proposed.len(), DIGEST_REPLY_BYTES);
        assert!(ask(&mut policy, &mut store, &mut command(BLESSED_DIGEST)).is_err());
        success(&mut policy, &mut store, END);
        assert_eq!(store.generation(), Ok(generation + 1));
        assert_eq!(success(&mut policy, &mut store, BLESSED_DIGEST), proposed);
        assert_eq!(store.policy_nonce(PolicyNonce::MacOs), Ok(None));
        assert!(ask(&mut policy, &mut store, &mut command(PROPOSED_DIGEST)).is_err());
        let mut reopened = Nonces::open(&roots(), store.into_backend()).unwrap();
        let mut policy = BootPolicy::new(None);
        assert_eq!(
            success(&mut policy, &mut reopened, BLESSED_DIGEST),
            proposed
        );
        success(&mut policy, &mut reopened, RESET);
        assert_eq!(reopened.policy_nonce(PolicyNonce::Recovery), Ok(None));
        assert!(ask(&mut policy, &mut reopened, &mut command(BLESSED_DIGEST)).is_err());
    }

    #[test]
    fn duplicate_begin_and_bad_bodies_leave_the_proposal_and_durable_state_unchanged() {
        let mut policy = BootPolicy::new(None);
        let mut store = store();
        success(&mut policy, &mut store, BEGIN);
        let proposed = success(&mut policy, &mut store, PROPOSED_DIGEST);
        let generation = store.generation().unwrap();
        let mut requests = vec![command(BEGIN), command(END), command(RESET), command(END)];
        requests[1].input[HEADER_BYTES] = 1;
        requests[2].input[MUTATION_BYTES - 1] = 1;
        requests[3].input.pop();
        for mut request in requests {
            let refused = ask(&mut policy, &mut store, &mut request).unwrap_err();
            assert!(refused.answer.is_some());
            assert!(request.output.is_empty());
            assert_eq!(store.generation(), Ok(generation));
            assert_eq!(success(&mut policy, &mut store, PROPOSED_DIGEST), proposed);
        }
        success(&mut policy, &mut store, END);
        assert_eq!(success(&mut policy, &mut store, BLESSED_DIGEST), proposed);
    }

    #[test]
    fn entropy_and_begin_output_failures_never_publish_a_proposal() {
        let mut policy = BootPolicy::new(None);
        let mut store = store();
        let mut buffers = command(BEGIN);
        let frame = Frame {
            service: super::super::ID,
            tag: 2,
            opcode: 0,
            parameter: 0,
            data: MUTATION_BYTES as u32,
        };
        let mut broken_entropy = |_: &mut [u8]| Err("entropy unavailable");
        assert!(
            policy
                .request(frame, &mut buffers, &mut store, &mut broken_entropy)
                .is_err()
        );
        assert!(buffers.output.is_empty());
        assert!(ask(&mut policy, &mut store, &mut command(PROPOSED_DIGEST)).is_err());
        let mut buffers = command(BEGIN);
        buffers.fail_output = true;
        assert!(ask(&mut policy, &mut store, &mut buffers).is_err());
        assert!(ask(&mut policy, &mut store, &mut command(PROPOSED_DIGEST)).is_err());
        success(&mut policy, &mut store, BEGIN);
    }

    #[test]
    fn an_intervening_xart_mutation_or_erase_cannot_commit_a_stale_proposal() {
        for erase in [false, true] {
            let mut policy = BootPolicy::new(None);
            let mut store = store();
            success(&mut policy, &mut store, BEGIN);
            if erase {
                store.erase().unwrap();
            } else {
                store.generate(0, &mut entropy).unwrap();
            }
            let generation = store.generation().unwrap();
            assert!(ask(&mut policy, &mut store, &mut command(PROPOSED_DIGEST)).is_err());
            assert!(ask(&mut policy, &mut store, &mut command(END)).is_err());
            assert_eq!(store.generation(), Ok(generation));
            assert_eq!(store.policy_nonce(PolicyNonce::Recovery), Ok(None));
            success(&mut policy, &mut store, BEGIN);
        }
    }

    #[test]
    fn successful_commit_with_failed_output_is_not_answered_or_replayed() {
        let mut policy = BootPolicy::new(None);
        let mut store = store();
        success(&mut policy, &mut store, BEGIN);
        let proposed = success(&mut policy, &mut store, PROPOSED_DIGEST);
        let mut buffers = command(END);
        buffers.fail_output = true;
        let refusal = ask(&mut policy, &mut store, &mut buffers).unwrap_err();
        assert!(refusal.answer.is_none());
        assert_eq!(success(&mut policy, &mut store, BLESSED_DIGEST), proposed);
        let generation = store.generation().unwrap();
        assert!(ask(&mut policy, &mut store, &mut command(END)).is_err());
        assert_eq!(store.generation(), Ok(generation));
    }

    #[test]
    fn reset_cancels_a_live_proposal_and_failed_reset_output_never_acknowledges() {
        let mut policy = BootPolicy::new(None);
        let mut store = store();
        success(&mut policy, &mut store, BEGIN);
        success(&mut policy, &mut store, END);
        success(&mut policy, &mut store, BEGIN);
        let mut buffers = command(RESET);
        buffers.fail_output = true;
        assert!(
            ask(&mut policy, &mut store, &mut buffers)
                .unwrap_err()
                .answer
                .is_none()
        );
        assert_eq!(store.policy_nonce(PolicyNonce::Recovery), Ok(None));
        assert!(ask(&mut policy, &mut store, &mut command(PROPOSED_DIGEST)).is_err());
        assert!(ask(&mut policy, &mut store, &mut command(END)).is_err());
        success(&mut policy, &mut store, BEGIN);
    }

    struct Uncertain {
        inner: Volatile,
        fail: Rc<Cell<bool>>,
    }
    impl Backend for Uncertain {
        fn load(&mut self) -> Result<Option<Head>, &'static str> {
            self.inner.load()
        }
        fn commit(&mut self, expected: u64, next: Head) -> Result<(), &'static str> {
            self.inner.commit(expected, next)?;
            if self.fail.get() {
                Err("commit acknowledgement lost")
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn uncertain_end_or_reset_poison_the_shared_store_without_an_acknowledgement() {
        for op in [END, RESET] {
            let fail = Rc::new(Cell::new(false));
            let mut store = Nonces::provision(
                &roots(),
                Uncertain {
                    inner: Volatile::default(),
                    fail: fail.clone(),
                },
            )
            .unwrap();
            let mut policy = BootPolicy::new(None);
            success(&mut policy, &mut store, BEGIN);
            let proposed = success(&mut policy, &mut store, PROPOSED_DIGEST);
            fail.set(true);
            let refusal = ask(&mut policy, &mut store, &mut command(op)).unwrap_err();
            assert!(refusal.answer.is_none());
            assert!(store.generation().is_err());
            assert!(ask(&mut policy, &mut store, &mut command(BEGIN)).is_err());
            fail.set(false);
            let mut reopened = Nonces::open(&roots(), store.into_backend()).unwrap();
            if op == END {
                assert_eq!(
                    success(&mut BootPolicy::new(None), &mut reopened, BLESSED_DIGEST),
                    proposed
                );
            } else {
                assert_eq!(reopened.policy_nonce(PolicyNonce::Recovery), Ok(None));
            }
        }
    }
}
