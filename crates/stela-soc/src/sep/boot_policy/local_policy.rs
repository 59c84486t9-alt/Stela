//! LocalPolicy creation: the commands behind restored's
//! `ramrod_generate_default_local_policy` (26A434 R 0x1000413e0).
//!
//! **Order.** restored begins a local nonce update (R 0x1000417a8), creates
//! the paired recoveryOS policy, command 0x52 (R 0x1000418c8), then the macOS
//! policy, 0x55 with a splat manifest or 0x4e without (R 0x100041954,
//! 0x10004192c), and ends the update. A failure in any of those fails the step
//! with 0x5a, and the install's next boot would be recoveryOS. SIP flags
//! and Boolean tags between them are logged "Choosing not to fail".
//!
//! **When.** The step block (R 0x1000156ec) logs "Skipping local policy
//! generation." unless `create_production_ucrt` succeeded: that step alone
//! clears the flag (R 0x100015514), which starts true (R 0x10000dbd0). A
//! production UCRT needs Apple to accept the machine's SEP identity, so an
//! erase install here skips these commands; they serve a caller that reaches
//! them, and no run has yet.
//!
//! **Wire** (libbootpolicy B 0x15818..0x15884, 0x1611c..0x16198,
//! 0x168a4..0x16940). After the 32-byte header come a u32 DER length (B
//! 0xffe4) and the DER: ccder implicit context tags, written last to first,
//! so in order: [8] the integer 1, [1] the OS manifest, on 0x55 [15] the
//! splat manifest, on 0x4e and 0x55 [2] the paired recoveryOS policy file
//! just written (B 0x16010 `_input_local_policy`), [4] the volume group UUID,
//! [3] the boot policy and [5] the ACM. The reply repeats the framing after a
//! reply header (B 0x10a08 `__create_decode_blob`): [7] the policy file and
//! [6] the 48-byte nonce digest (B 0x161e4, 0x161f8), which libbootpolicy
//! writes unchecked under that digest's name (B 0x1df8).
//!
//! **Boot policy.** restored asks 1 for Full, 2 for Reduced and 3 for
//! Permissive Security, and 2 for the paired policy of any downgrade
//! (R 0x100041838..0x1000418a0).
//!
//! The SEP checks the paired policy it is shown is its own for this
//! nonce update and volume group. A request with an ACM needs authorization
//! this SEP does not model, so it refuses.
use super::{HEADER_BYTES, SUCCESS, delivered, nonces::PolicyNonces, not_supported, reply_header};
use crate::Result;
use crate::sep::{
    message::Frame,
    policy::PolicyKey,
    store::{Backend, Nonces},
    transaction::{Payload, Refusal},
};
use alloc::{vec, vec::Vec};
use sha2::{Digest, Sha384};
use stela_contracts::refuse;
use stela_formats::{
    der::{self, Cursor},
    local_policy::{self, DIGEST_BYTES, Policy, Security, UUID_BYTES},
};

const CREATE: u32 = 0x4e;
const CREATE_PAIRED: u32 = 0x52;
const CREATE_WITH_SPLAT: u32 = 0x55;

/// Request and reply field tags.
const OS_MANIFEST: usize = 1;
const PAIRED_POLICY: usize = 2;
const BOOT_POLICY: usize = 3;
const VOLUME_GROUP: usize = 4;
const AUTHORIZATION: usize = 5;
const REPLY_NONCE: u8 = 6;
const REPLY_POLICY: u8 = 7;
const FORMAT: usize = 8;
const SPLAT_MANIFEST: usize = 15;
const FIELDS: usize = SPLAT_MANIFEST + 1;
/// A context-specific primitive tag.
const CONTEXT: u8 = 0x80;
/// The DER's u32 length after the header.
const LENGTH_BYTES: usize = 4;

pub(super) fn accepts(command: u32) -> bool {
    matches!(command, CREATE | CREATE_PAIRED | CREATE_WITH_SPLAT)
}

/// The fields of `bytes` by tag: each once, context-specific and primitive.
fn fields(mut bytes: &[u8]) -> Result<[Option<&[u8]>; FIELDS]> {
    let mut fields = [None; FIELDS];
    while !bytes.is_empty() {
        let mut cursor = Cursor(bytes);
        let element = cursor.next_element()?;
        bytes = cursor.0;
        let field = fields
            .get_mut(element.tag as usize)
            .filter(|_| element.class == 2 && !element.constructed)
            .ok_or(refuse!("SEP LocalPolicy request has an unmodeled field"))?;
        if field.replace(element.value).is_some() {
            return Err(refuse!("SEP LocalPolicy request repeats a field"));
        }
    }
    Ok(fields)
}

fn integer(bytes: &[u8]) -> Result<u64> {
    let digits = der::unsigned(bytes)?;
    if digits.len() > 8 {
        return Err(refuse!("SEP LocalPolicy request integer is too large"));
    }
    Ok(digits.iter().fold(0, |value, &b| value << 8 | u64::from(b)))
}

/// The policy `body`, the request after its header, asks for.
fn policy(command: u32, body: &[u8], nonce: [u8; DIGEST_BYTES], key: &PolicyKey) -> Result<Policy> {
    let (length, encoded) = body
        .split_first_chunk::<LENGTH_BYTES>()
        .ok_or(refuse!("SEP LocalPolicy request has no DER length"))?;
    if u32::from_le_bytes(*length) as usize != encoded.len() {
        return Err(refuse!("SEP LocalPolicy request's DER length is wrong"));
    }
    let mut fields = fields(encoded)?;
    let mut take = |tag: usize| {
        fields[tag]
            .take()
            .ok_or(refuse!("SEP LocalPolicy request lacks a field"))
    };
    if integer(take(FORMAT)?)? != 1 {
        return Err(refuse!("SEP LocalPolicy request format is not modeled"));
    }
    if !take(AUTHORIZATION)?.is_empty() {
        return Err(refuse!(
            "SEP LocalPolicy request's authorization is not implemented"
        ));
    }
    let security = match (integer(take(BOOT_POLICY)?)?, command) {
        (1, _) => Security::Full,
        (2, _) => Security::Reduced,
        (3, CREATE | CREATE_WITH_SPLAT) => Security::Permissive,
        _ => return Err(refuse!("SEP LocalPolicy boot policy is not modeled")),
    };
    let volume_group: [u8; UUID_BYTES] = take(VOLUME_GROUP)?
        .try_into()
        .map_err(|_| refuse!("SEP LocalPolicy volume group is not a UUID"))?;
    let digest = |bytes: &[u8]| <[u8; DIGEST_BYTES]>::from(Sha384::digest(bytes));
    let next_stage = digest(take(OS_MANIFEST)?);
    let splat = (command == CREATE_WITH_SPLAT)
        .then(|| take(SPLAT_MANIFEST).map(digest))
        .transpose()?;
    let paired = (command != CREATE_PAIRED)
        .then(|| {
            let file = take(PAIRED_POLICY)?;
            let shown = local_policy::verify(file, key.public())
                .map_err(|_| refuse!("SEP LocalPolicy's paired policy is not this SEP's"))?;
            if shown.volume_group != volume_group || shown.nonce != nonce {
                return Err(refuse!(
                    "SEP LocalPolicy's paired policy is of another update or volume group"
                ));
            }
            Ok(digest(file))
        })
        .transpose()?;
    if fields.iter().any(Option::is_some) {
        return Err(refuse!("SEP LocalPolicy request has an unmodeled field"));
    }
    Ok(Policy {
        volume_group,
        next_stage,
        nonce,
        splat,
        paired,
        security,
    })
}

/// Sign the policy the request asks for, during the local nonce update.
pub(super) fn request<B: Backend>(
    command: u32,
    frame: Frame,
    payload: &mut dyn Payload,
    store: &Nonces<B>,
    nonces: &PolicyNonces,
) -> core::result::Result<Frame, Refusal> {
    let unsupported =
        |reason: stela_contracts::Refusal| Refusal::answered(reason, not_supported(frame));
    let mut body = vec![0; frame.data as usize - HEADER_BYTES];
    payload.input(&mut body).map_err(unsupported)?;
    let reply = (|| {
        let nonce = nonces.proposed_local(store)?;
        let key = PolicyKey::derive(&*store.policy_key_seed()?)?;
        let file = key.sign(&policy(command, &body, nonce, &key)?);
        let mut encoded = der::encode(CONTEXT | REPLY_POLICY, &file);
        encoded.extend(der::encode(CONTEXT | REPLY_NONCE, &nonce));
        let mut reply: Vec<u8> = reply_header(SUCCESS).to_vec();
        reply.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
        reply.extend(encoded);
        Ok(reply)
    })()
    .map_err(unsupported)?;
    payload.output(&reply).map_err(unsupported)?;
    Ok(delivered(frame, reply.len()))
}

#[cfg(test)]
mod tests;
