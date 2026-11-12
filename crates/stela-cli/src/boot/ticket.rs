//! The restore's tickets from Apple's signing service (TSS).
//! Stela plays the boot ROM and the SEP ROM, so it draws their nonces here;
//! the bundle boots under the ticket Apple personalizes for them, and the
//! restore host answers restored's `RootTicket` with it, whose SHA-384
//! `update_ticket` requires to be `/chosen/boot-manifest-hash`.
//!
//! An erase install's other three requests (the recoveryOS root ticket, the
//! Cryptex1 ticket and the recoveryOS LocalPolicy) bind only values known
//! here once the AP ticket is signed, and a recoveryOS policy nonce the
//! install's SEP takes from the bundle; setup asks for them too
//! ([`staged`]), so the install needs no network.
use anyhow::{Context, Result, anyhow};
use reqwest::blocking::Client;
use std::time::Duration;
use stela_contracts::refuse;
use stela_runtime::restore::{
    self, answers, plist,
    plist::{Limits, Value},
    store::Identity,
    ticket::Ticket,
    tss,
};

/// A failure of Apple's signing service in words: a lost connection or a
/// bad answer says its cause, a refusal its reason without the request.
fn signing_service(error: restore::Error) -> anyhow::Error {
    match error {
        restore::Error::Transport(why) | restore::Error::Payload(why) => {
            anyhow!("Apple's signing service: {why}")
        }
        other => anyhow!("Apple's signing service: {}", other.summary()),
    }
}

/// How long one signing request may take.
const TIMEOUT: Duration = Duration::from_secs(60);

/// Apple's signing service over HTTP; the command waits for each answer.
struct Apple(Client);

impl tss::Transport for Apple {
    fn exchange(
        &mut self,
        host: &str,
        path: &str,
        headers: &[(&str, &str)],
        content_type: &str,
        body: &[u8],
    ) -> restore::Result<Option<Vec<u8>>> {
        let failed = |error: String| restore::Error::Transport(refuse!("{error}", %error));
        // The same body asks for the same ticket, so a lost request is
        // asked again.
        let response = crate::net::send(&format!("Apple's signing server ({host})"), || {
            let mut request = self
                .0
                .post(format!("http://{host}{path}"))
                .header(reqwest::header::CONTENT_TYPE, content_type)
                .body(body.to_vec());
            for (name, value) in headers {
                request = request.header(*name, *value);
            }
            request
        })
        .map_err(|error| failed(format!("{error:#}")))?;
        let status = response.status();
        if !status.is_success() {
            return Err(failed(format!(
                "{host} answered HTTP status {}",
                status.as_u16()
            )));
        }
        let bytes = response
            .bytes()
            .map_err(|error| failed(crate::net::explain(&error)))?;
        signing_answer(host, &bytes).map_err(failed)?;
        Ok(Some(bytes.to_vec()))
    }
}

/// Refuse an answer that is not the signing server's: a network that shows
/// its sign-in page answers every plain-HTTP request with that page.
fn signing_answer(host: &str, bytes: &[u8]) -> Result<(), String> {
    if bytes.starts_with(b"STATUS=") {
        return Ok(());
    }
    Err(format!(
        "the network answered for {host} with something other than Apple's signing server \
         ({} bytes{}). A network that wants a sign-in first does this: open a web page on this \
         computer, sign in to the network, and run setup again",
        bytes.len(),
        if bytes.windows(5).any(|w| w.eq_ignore_ascii_case(b"<html")) {
            ", a web page"
        } else {
            ""
        }
    ))
}

fn apple() -> Result<Box<dyn tss::Transport>> {
    Ok(Box::new(Apple(Client::builder().timeout(TIMEOUT).build()?)))
}

/// Build identity `index` of the BuildManifest `manifest`, and every
/// `macOS Customer` identity, among which is the one it installs.
fn identities(manifest: &[u8], index: usize) -> Result<(Identity, Vec<Identity>)> {
    let mut selected = None;
    let mut customers = Vec::new();
    let mut sink = |at: usize, value: Value| {
        let identity = Identity { index: at, value };
        if identity.variant().ok() == Some("macOS Customer") {
            customers.push(identity.clone());
        }
        if at == index {
            selected = Some(identity);
        }
        Ok(())
    };
    plist::decode_streaming(
        manifest,
        Limits {
            bytes: manifest.len(),
            nodes: 2_000_000,
            depth: 64,
        },
        plist::Stream {
            path: &["BuildIdentities"],
            sink: &mut sink,
        },
    )
    .map_err(|error| anyhow!("BuildManifest: {error}"))?;
    let selected = selected.with_context(|| format!("BuildManifest has no identity {index}"))?;
    Ok((selected, customers))
}

/// Apple's AP root ticket for build identity `index` of the BuildManifest
/// `manifest` and the machine `ecid`, under nonces drawn from the OS.
pub fn personalized(manifest: &[u8], index: u32, ecid: u64) -> Result<Vec<u8>> {
    personalized_with(manifest, index, ecid, &mut *apple()?)
}

fn personalized_with(
    manifest: &[u8],
    index: u32,
    ecid: u64,
    transport: &mut dyn tss::Transport,
) -> Result<Vec<u8>> {
    let (identity, _) = identities(manifest, usize::try_from(index)?)?;
    let mut nonces = tss::Nonces {
        ap: [0; 32],
        sep: [0; 20],
    };
    getrandom::getrandom(&mut nonces.ap).context("the system's random generator failed")?;
    getrandom::getrandom(&mut nonces.sep).context("the system's random generator failed")?;
    let request = tss::root_ticket_request(&identity, ecid, &nonces, tss::Root::Ap)
        .map_err(signing_service)?;
    let body = plist::encode_xml(&request, Limits::default())
        .map_err(|error| anyhow!("the AP ticket request: {error}"))?;
    let response = transport
        .exchange(
            tss::HOST,
            tss::PATH,
            &tss::HEADERS,
            tss::CONTENT_TYPE,
            &body,
        )
        .map_err(signing_service)?
        .context("Apple's signing service gave no answer")?;
    let bytes = tss::ticket(&response).map_err(signing_service)?;
    Ticket::personalized(bytes.clone(), &identity, ecid, Some(&nonces))
        .map_err(|error| anyhow!("Apple's root ticket: {error}"))?;
    Ok(bytes)
}

/// Apple's answers to the erase install's recoveryOS root ticket, Cryptex1
/// ticket and recoveryOS LocalPolicy requests for the machine `ecid` booted
/// under `ap_ticket` with build identity `index`, and the recoveryOS policy
/// nonce they bind, drawn from the OS: the bundle file
/// [`tss::staged::FILE`].
pub fn staged(manifest: &[u8], index: u32, ecid: u64, ap_ticket: &[u8]) -> Result<Vec<u8>> {
    staged_with(manifest, index, ecid, ap_ticket, &mut *apple()?)
}

fn staged_with(
    manifest: &[u8],
    index: u32,
    ecid: u64,
    ap_ticket: &[u8],
    transport: &mut dyn tss::Transport,
) -> Result<Vec<u8>> {
    let (restore, customers) = identities(manifest, usize::try_from(index)?)?;
    let installed = answers::installed_identity(&customers, &restore)
        .map_err(|error| anyhow!("BuildManifest: {error}"))?;
    let mut policy_nonce = [0; 32];
    getrandom::getrandom(&mut policy_nonce).context("the system's random generator failed")?;
    let set = tss::staged::Setup {
        restore: &restore,
        installed: &installed,
        ecid,
        ap_ticket,
        policy_nonce: &policy_nonce,
    }
    .stage(transport)
    .map_err(signing_service)?;
    set.encode()
        .map_err(|error| anyhow!("the staged signing answers: {error}"))
}

#[cfg(test)]
mod tests;
