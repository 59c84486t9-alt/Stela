//! The restore's AP root ticket from Apple's signing service (TSS).
//! Stela plays the boot ROM and the SEP ROM, so it draws their nonces here;
//! the bundle boots under the ticket Apple personalizes for them, and the
//! restore host answers restored's `RootTicket` with it, whose SHA-384
//! `update_ticket` requires to be `/chosen/boot-manifest-hash`.
use anyhow::{Context, Result, anyhow};
use reqwest::blocking::Client;
use std::time::Duration;
use stela_contracts::refuse;
use stela_runtime::restore::{
    self, plist,
    plist::{Limits, Value},
    store::Identity,
    ticket::Ticket,
    tss,
};

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

#[cfg(test)]
mod tests {
    use super::*;
    use stela_runtime::restore::tss::Transport as _;

    #[test]
    fn signing_requests_are_asked_again_and_a_sign_in_page_is_named() {
        let tss = "STATUS=0&MESSAGE=SUCCESS&REQUEST_STRING=<?xml version=\"1.0\"?>";
        let reply = |status: &str, body: &str| {
            format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
        };
        let (url, _) = crate::net::tests::serve(vec![
            reply("502 Bad Gateway", ""),
            reply("200 OK", tss),
            reply("200 OK", "<html><body>Sign in to Guest Wi-Fi</body></html>"),
        ]);
        let host = url
            .strip_prefix("http://")
            .and_then(|rest| rest.split('/').next())
            .unwrap()
            .to_owned();
        let mut apple = Apple(Client::new());
        let answer = apple
            .exchange(&host, "/TSS/controller", &[], "text/xml", b"<plist/>")
            .unwrap();
        assert_eq!(answer.as_deref(), Some(tss.as_bytes()));
        let error = apple
            .exchange(&host, "/TSS/controller", &[], "text/xml", b"<plist/>")
            .unwrap_err()
            .to_string();
        assert!(error.contains("sign in to the network"), "{error}");
        assert!(error.contains("a web page"), "{error}");
    }
}
