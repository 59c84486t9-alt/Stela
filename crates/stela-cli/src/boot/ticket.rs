//! The restore's AP root ticket from Apple's signing service (`--tss`).
//! Stela plays the boot ROM and the SEP ROM, so it draws their nonces here;
//! the bundle boots under the ticket Apple personalizes for them, and the
//! restore host answers restored's `RootTicket` with it, whose SHA-384
//! `update_ticket` requires to be `/chosen/boot-manifest-hash`.
use anyhow::{Context, Result, anyhow};
use reqwest::blocking::Client;
use std::time::Duration;
use stela_runtime::restore::{
    self, plist,
    plist::{Limits, Value},
    store::Identity,
    ticket::Ticket,
    tss,
};

/// How long one signing request may take.
const TIMEOUT: Duration = Duration::from_secs(60);

/// Apple's signing service over HTTP.
struct Apple(Client);

impl tss::Transport for Apple {
    fn post(
        &mut self,
        host: &str,
        path: &str,
        headers: &[(&str, &str)],
        content_type: &str,
        body: &[u8],
    ) -> restore::Result<Vec<u8>> {
        let failed = |error: reqwest::Error| restore::Error::Transport(format!("{error}"));
        let mut request = self
            .0
            .post(format!("http://{host}{path}"))
            .header(reqwest::header::CONTENT_TYPE, content_type)
            .body(body.to_vec());
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let response = request.send().map_err(failed)?;
        let status = response.status();
        if !status.is_success() {
            return Err(restore::Error::Transport(format!(
                "HTTP status {}",
                status.as_u16()
            )));
        }
        Ok(response.bytes().map_err(failed)?.to_vec())
    }
}

/// Apple's AP root ticket for build identity `index` of the BuildManifest
/// `manifest` and the machine `ecid`, under nonces drawn from the OS.
pub fn personalized(manifest: &[u8], index: u32, ecid: u64) -> Result<Vec<u8>> {
    let index = usize::try_from(index)?;
    let mut selected = None;
    let mut sink = |at: usize, value: Value| {
        if at == index {
            selected = Some(value);
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
    let identity = Identity {
        index,
        value: selected.with_context(|| format!("BuildManifest has no identity {index}"))?,
    };
    let mut nonces = tss::Nonces {
        ap: [0; 32],
        sep: [0; 20],
    };
    getrandom::getrandom(&mut nonces.ap).context("the system's random generator failed")?;
    getrandom::getrandom(&mut nonces.sep).context("the system's random generator failed")?;
    let mut signer = tss::Signer {
        ecid,
        nonces: nonces.clone(),
        transport: Box::new(Apple(Client::builder().timeout(TIMEOUT).build()?)),
    };
    let bytes = tss::request_root_ticket(&mut signer, &identity, tss::Root::Ap)
        .map_err(|error| anyhow!("Apple's signing service: {error}"))?;
    Ticket::personalized(bytes.clone(), &identity, ecid, Some(&nonces))
        .map_err(|error| anyhow!("Apple's root ticket: {error}"))?;
    Ok(bytes)
}
