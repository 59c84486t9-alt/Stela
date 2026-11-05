//! Carrying the plan to a Stela guest and its results back, over the
//! guest's network: the guest's LAN peer relays every TCP connection it
//! opens to the same address from the host, so a plain HTTP exchange with
//! this process needs no medium, and none of macOS's privacy checks on
//! removable volumes, which refuse a console shell.
//!
//! `serve` packs DIR/plan (runner, metallibs, inputs) as plan.tar, writes
//! the guest's commands to DIR/guest.sh, answers `GET /plan.tar` and
//! `PUT /results.tar`, extracts the results into DIR/results and exits.
use super::plan;
use anyhow::{Context, Result, bail};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream, UdpSocket},
    path::Path,
    process::Command,
};

/// The guest's commands: fetch and unpack the plan, keep the results an
/// earlier boot left for the same plan (a case it crashed in stays
/// "running" and is not retried), run, send the results back, and print
/// one line with the guest's status counts, ending METAL_SUITE_DONE.
pub fn script(address: &str, only: &[String]) -> String {
    let selection: String = only.iter().map(|o| format!(" --only {o}")).collect();
    [
        format!(
            "H=http://{address}; /bin/mkdir -p /var/stela/md && cd /var/stela/md && /bin/rm -rf plan && \
/usr/bin/curl -fsS $H/plan.tar | /usr/bin/tar -xf -; echo tar=$?; P=$(/sbin/md5 -q plan/plan.json); \
[ \"$(/bin/cat results/plan.id 2>/dev/null)\" = \"$P\" ] || {{ /bin/rm -rf results; /bin/mkdir -p results; echo $P > results/plan.id; }}"
        ),
        format!("cd /var/stela/md && ./plan/runner plan results/guest --skip-done{selection}; echo runner=$?"),
        "cd /var/stela/md && /usr/bin/tar -cf /tmp/results.tar results && /usr/bin/curl -fsS -T /tmp/results.tar $H/results.tar; echo sent=$?".into(),
        "cd /var/stela/md/results/guest && for s in ok error unsupported running; do echo \"$s=$(/usr/bin/grep -l \"\\\"status\\\" *: *\\\"$s\\\"\" */status.json | /usr/bin/wc -l | /usr/bin/tr -d ' ')\"; done | /usr/bin/paste -sd' ' - | /usr/bin/sed 's/$/ METAL_SUITE_DONE/'".into(),
    ]
    .join("\n")
        + "\n"
}

/// This host's address on its default route, which the guest's relayed
/// connections reach. No packet is sent.
fn local_address() -> Result<String> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("192.0.2.1:9")?;
    Ok(socket.local_addr()?.ip().to_string())
}

/// A request's method, path and body.
struct Request {
    method: String,
    path: String,
    body: Vec<u8>,
}

fn read_request(stream: &TcpStream) -> Result<Request> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let mut parts = line.split_whitespace();
    let (method, path) = (
        parts.next().unwrap_or_default().to_string(),
        parts.next().unwrap_or_default().to_string(),
    );
    let (mut length, mut chunked) = (None, false);
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header)? == 0 || header.trim().is_empty() {
            break;
        }
        let (name, value) = header.split_once(':').unwrap_or((&header, ""));
        match name.trim().to_ascii_lowercase().as_str() {
            "content-length" => length = Some(value.trim().parse::<usize>()?),
            "transfer-encoding" => chunked = value.to_ascii_lowercase().contains("chunked"),
            "expect" => stream
                .try_clone()?
                .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?,
            _ => {}
        }
    }
    let mut body = vec![];
    if chunked {
        loop {
            let mut size = String::new();
            reader.read_line(&mut size)?;
            let size = usize::from_str_radix(size.trim().split(';').next().unwrap_or("0"), 16)?;
            let mut chunk = vec![0; size + 2];
            reader.read_exact(&mut chunk)?;
            if size == 0 {
                break;
            }
            body.extend(&chunk[..size]);
        }
    } else if let Some(length) = length {
        body.resize(length, 0);
        reader.read_exact(&mut body)?;
    }
    Ok(Request { method, path, body })
}

fn respond(mut stream: &TcpStream, status: &str, body: &[u8]) -> Result<()> {
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)?;
    Ok(())
}

/// Serves DIR/plan to the guest on `port` until it sends its results.
pub fn serve(out: &Path, port: u16, only: &[String]) -> Result<()> {
    let dir = out.join("plan");
    if !dir.join("runner").exists() {
        bail!("no runner: run `mac` first, which builds the runner and libraries");
    }
    let plan = plan::load(&dir)?;
    let missing: Vec<&String> = plan["libraries"]
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(_, w)| w.as_str().is_some_and(|w| !dir.join(w).exists()))
        .map(|(n, _)| n)
        .collect();
    if !missing.is_empty() {
        bail!("libraries not built: {missing:?}; run `mac` for this plan first");
    }
    let archive = out.join("plan.tar");
    super::remote::run(
        Command::new("tar")
            .args([
                "--format=ustar",
                "--exclude=*.air",
                "--exclude=runner.m",
                "--exclude=build.sh",
                "-C",
            ])
            .arg(out)
            .arg("-cf")
            .arg(&archive)
            .arg("plan"),
    )?;
    let tarball = fs::read(&archive)?;
    let address = format!("{}:{port}", local_address()?);
    let commands = script(&address, only);
    fs::write(out.join("guest.sh"), &commands)?;
    let listener = TcpListener::bind(("0.0.0.0", port)).with_context(|| format!("port {port}"))?;
    println!(
        "serving plan {} ({} bytes) at {address}; type into the guest's root shell:\n{commands}",
        plan["digest"],
        tarball.len()
    );
    for stream in listener.incoming() {
        let stream = stream?;
        let request = match read_request(&stream) {
            Ok(r) => r,
            Err(error) => {
                eprintln!("bad request: {error}");
                continue;
            }
        };
        println!(
            "{} {} ({} bytes)",
            request.method,
            request.path,
            request.body.len()
        );
        match (request.method.as_str(), request.path.as_str()) {
            ("GET", "/plan.tar") => respond(&stream, "200 OK", &tarball)?,
            ("GET", "/guest.sh") => respond(&stream, "200 OK", commands.as_bytes())?,
            ("PUT", "/results.tar") => {
                let received = out.join("results.tar");
                fs::write(&received, &request.body)?;
                respond(&stream, "201 Created", b"")?;
                super::remote::run(
                    Command::new("tar")
                        .arg("-xf")
                        .arg(&received)
                        .arg("-C")
                        .arg(out)
                        .arg("results"),
                )?;
                println!("{}", out.join("results").display());
                return Ok(());
            }
            _ => respond(&stream, "404 Not Found", b"")?,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn script_selects_resumes_and_reports() {
        let s = script("10.0.0.1:8765", &["render".into()]);
        assert!(s.contains("H=http://10.0.0.1:8765;"));
        assert!(s.contains("--skip-done --only render"));
        assert!(s.contains("results/plan.id"));
        assert!(s.ends_with("METAL_SUITE_DONE/'\n"));
    }

    #[test]
    fn requests_read_sized_and_chunked_bodies() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let client = thread::spawn(move || {
            for request in [
                &b"PUT /a HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc"[..],
                &b"PUT /b HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n1\r\nc\r\n0\r\n\r\n"[..],
            ] {
                TcpStream::connect(address).unwrap().write_all(request).unwrap();
            }
        });
        for path in ["/a", "/b"] {
            let (stream, _) = listener.accept().unwrap();
            let request = read_request(&stream).unwrap();
            assert_eq!(
                (
                    request.method.as_str(),
                    request.path.as_str(),
                    &request.body[..]
                ),
                ("PUT", path, &b"abc"[..])
            );
        }
        client.join().unwrap();
    }
}
