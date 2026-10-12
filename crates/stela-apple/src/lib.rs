//! Read Apple's public macOS IPSW feed and download original images.
pub mod restore;
use anyhow::{Context, Result, bail, ensure};
use plist::Value;
use reqwest::{Url, blocking::Client, header, redirect::Policy};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

pub const CATALOG_URL: &str =
    "https://mesu.apple.com/assets/macos/com_apple_macOSIPSW/com_apple_macOSIPSW.xml";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Image {
    pub version: String,
    pub build: String,
    pub models: Vec<String>,
    pub url: String,
    pub sha1: Option<String>,
}

pub fn apple_url(url: &Url) -> bool {
    url.scheme() == "https"
        && url.host_str().is_some_and(|h| {
            h == "apple.com"
                || h.ends_with(".apple.com")
                || h == "cdn-apple.com"
                || h.ends_with(".cdn-apple.com")
        })
        && url.username().is_empty()
        && url.password().is_none()
}

fn client() -> Result<Client> {
    Ok(Client::builder()
        .user_agent(concat!("stela/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(30))
        .timeout(Duration::from_secs(24 * 60 * 60))
        .redirect(Policy::custom(|attempt| {
            if attempt.previous().len() >= 5 {
                attempt.error("too many redirects")
            } else if !apple_url(attempt.url()) {
                attempt.error("redirect outside Apple's HTTPS servers")
            } else {
                attempt.follow()
            }
        }))
        .build()?)
}

pub fn catalog() -> Result<Vec<Image>> {
    // Bound metadata responses; image downloads are streamed separately.
    let response = client()?
        .get(CATALOG_URL)
        .timeout(Duration::from_secs(60))
        .send()?
        .error_for_status()?;
    let mut bytes = Vec::new();
    response
        .take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 16 * 1024 * 1024, "catalog too large");
    parse_catalog(&bytes)
}

fn string(dict: &plist::Dictionary, key: &str) -> Result<String> {
    dict.get(key)
        .and_then(Value::as_string)
        .map(str::to_owned)
        .with_context(|| format!("catalog is missing {key}"))
}

pub fn parse_catalog(bytes: &[u8]) -> Result<Vec<Image>> {
    let value = Value::from_reader(std::io::Cursor::new(bytes))?;
    let versions = value
        .as_dictionary()
        .and_then(|d| d.get("MobileDeviceSoftwareVersionsByVersion"))
        .and_then(Value::as_dictionary)
        .context("unrecognized Apple catalog schema")?;
    let mut images: BTreeMap<(String, String), Image> = BTreeMap::new();
    for version in versions.values() {
        let Some(models) = version
            .as_dictionary()
            .and_then(|v| v.get("MobileDeviceSoftwareVersions"))
            .and_then(Value::as_dictionary)
        else {
            continue;
        };
        for (model, builds) in models {
            let Some(builds) = builds.as_dictionary() else {
                continue;
            };
            for (key, build) in builds {
                let Some(mut build) = build.as_dictionary() else {
                    continue;
                };
                if key == "Unknown" {
                    let Some(universal) = build.get("Universal").and_then(Value::as_dictionary)
                    else {
                        continue;
                    };
                    build = universal;
                }
                let Some(restore) = build.get("Restore").and_then(Value::as_dictionary) else {
                    continue;
                };
                let url = string(restore, "FirmwareURL")?;
                ensure!(
                    apple_url(&Url::parse(&url)?),
                    "catalog supplied a non-Apple HTTPS URL"
                );
                let build = string(restore, "BuildVersion")?;
                let version = string(restore, "ProductVersion")?;
                let sha1 = restore
                    .get("FirmwareSHA1")
                    .and_then(Value::as_string)
                    .map(str::to_lowercase);
                if let Some(digest) = &sha1 {
                    ensure!(
                        digest.len() == 40 && digest.bytes().all(|b| b.is_ascii_hexdigit()),
                        "invalid catalog SHA-1"
                    );
                }
                let entry = images.entry((build.clone(), url.clone())).or_insert(Image {
                    version: version.clone(),
                    build,
                    models: vec![],
                    url,
                    sha1: sha1.clone(),
                });
                ensure!(entry.version == version, "inconsistent catalog version");
                match (&entry.sha1, &sha1) {
                    (Some(existing), Some(new)) => {
                        ensure!(existing == new, "conflicting catalog digests")
                    }
                    (None, Some(_)) => entry.sha1 = sha1,
                    _ => {}
                }
                if !entry.models.contains(model) {
                    entry.models.push(model.clone());
                }
            }
        }
    }
    ensure!(
        !images.is_empty(),
        "Apple catalog contains no restore images"
    );
    let mut result: Vec<_> = images.into_values().collect();
    for image in &mut result {
        image.models.sort();
    }
    Ok(result)
}

pub fn select(images: &[Image], build: Option<&str>, model: Option<&str>) -> Result<Image> {
    let candidates: Vec<_> = images
        .iter()
        .filter(|i| {
            build.is_none_or(|b| b == i.build)
                && model.is_none_or(|m| i.models.iter().any(|v| v == m))
        })
        .collect();
    ensure!(
        !candidates.is_empty(),
        "no matching image; run `stela images list`"
    );
    if build.is_some() {
        ensure!(
            candidates.len() == 1,
            "build has multiple images; specify --model"
        );
        return Ok(candidates[0].clone());
    }
    // Numeric version ordering avoids 27.10 sorting below 27.9.
    fn version(v: &str) -> Vec<u64> {
        v.split('.').map(|p| p.parse().unwrap_or(0)).collect()
    }
    let newest = candidates
        .iter()
        .map(|i| version(&i.version))
        .max()
        .unwrap();
    let latest: Vec<_> = candidates
        .into_iter()
        .filter(|i| version(&i.version) == newest)
        .collect();
    ensure!(
        latest.len() == 1,
        "latest version has multiple builds/images; specify --build and --model"
    );
    Ok(latest[0].clone())
}

#[derive(Debug, Serialize, Deserialize)]
struct Partial {
    image: Image,
    total_bytes: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Receipt {
    pub schema_version: u32,
    pub image: Image,
    pub bytes: u64,
    pub sha256: String,
    pub catalog_sha1_verified: bool,
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_owned();
    value.push(suffix);
    value.into()
}

/// A Content-Range must cover exactly the remaining suffix of the image.
fn range_total(value: &str, offset: u64) -> Result<u64> {
    let (span, total) = value
        .strip_prefix("bytes ")
        .context("invalid Content-Range unit")?
        .split_once('/')
        .context("invalid Content-Range")?;
    let (start, end) = span.split_once('-').context("invalid Content-Range span")?;
    let (start, end, total): (u64, u64, u64) = (start.parse()?, end.parse()?, total.parse()?);
    ensure!(
        start == offset && end >= start && end.checked_add(1) == Some(total),
        "incorrect or incomplete resumed range"
    );
    Ok(total)
}

pub fn download(image: &Image, output: &Path) -> Result<Receipt> {
    let url = Url::parse(&image.url)?;
    ensure!(
        apple_url(&url),
        "image must be hosted on Apple's HTTPS servers"
    );
    download_with_client(image, output, &client()?)
}

fn download_with_client(image: &Image, output: &Path, client: &Client) -> Result<Receipt> {
    ensure!(
        !output.exists() && !sidecar(output, ".json").exists(),
        "output or receipt already exists; choose another path"
    );
    if let Some(parent) = output.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let part = sidecar(output, ".part");
    let metadata = sidecar(output, ".part.json");
    let mut offset = 0;
    let mut previous_total = None;
    if part.exists() {
        let previous: Partial =
            stela_core::read_json(&metadata).context("partial image has no valid metadata")?;
        ensure!(
            previous.image == *image,
            "partial image belongs to a different catalog entry"
        );
        offset = part.metadata()?.len();
        previous_total = previous.total_bytes;
        ensure!(
            previous_total.is_none_or(|total| offset <= total),
            "partial file exceeds expected image size"
        );
        if offset > 0 && previous_total == Some(offset) {
            // Recover interruption after the last byte but before publishing.
            return publish(image, output, &part, &metadata, offset);
        }
    }
    let mut request = client
        .get(&image.url)
        .header(header::ACCEPT_ENCODING, "identity");
    if offset > 0 {
        request = request.header(header::RANGE, format!("bytes={offset}-"));
    }
    let mut response = request.send()?.error_for_status()?;
    let total;
    if response.status() == reqwest::StatusCode::PARTIAL_CONTENT {
        total = Some(range_total(
            response
                .headers()
                .get(header::CONTENT_RANGE)
                .context("missing Content-Range")?
                .to_str()?,
            offset,
        )?);
        ensure!(
            previous_total.is_none() || total == previous_total,
            "image size changed during resume"
        );
        if let Some(length) = response.content_length() {
            ensure!(
                length.checked_add(offset) == total,
                "range length disagrees with Content-Length"
            );
        }
    } else if response.status() == reqwest::StatusCode::OK {
        offset = 0; // Server ignored Range: safely restart, never append a full image.
        total = response.content_length();
    } else {
        bail!("unexpected download status: {}", response.status());
    }
    stela_core::write_json(
        &metadata,
        &Partial {
            image: image.clone(),
            total_bytes: total,
        },
    )?;
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(offset == 0)
        .append(offset > 0)
        .open(&part)?;
    eprintln!(
        "Downloading {} {} from byte {offset}; partial: {}",
        image.version,
        image.build,
        part.display()
    );
    let mut written = offset;
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let n = response.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        file.write_all(&buffer[..n])?;
        written += n as u64;
        ensure!(
            total.is_none_or(|t| written <= t),
            "response exceeds advertised size"
        );
    }
    file.sync_all()?;
    drop(file);
    ensure!(
        written > 0 && total.is_none_or(|t| t == written),
        "incomplete image; rerun to resume"
    );
    publish(image, output, &part, &metadata, written)
}

fn publish(
    image: &Image,
    output: &Path,
    part: &Path,
    metadata: &Path,
    written: u64,
) -> Result<Receipt> {
    let mut file = File::open(part)?;
    let mut buffer = vec![0u8; 1024 * 1024];
    let mut sha256 = Sha256::new();
    let mut sha1 = sha1::Sha1::new();
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        sha256.update(&buffer[..n]);
        sha1.update(&buffer[..n]);
    }
    if let Some(expected) = &image.sha1 {
        ensure!(
            hex::encode(sha1.finalize()) == *expected,
            "Apple catalog SHA-1 mismatch; delete the .part and .part.json files before retrying"
        );
    }
    let receipt = Receipt {
        schema_version: 1,
        image: image.clone(),
        bytes: written,
        sha256: hex::encode(sha256.finalize()),
        catalog_sha1_verified: image.sha1.is_some(),
    };
    // Do not clobber an output created while the download was running.
    std::fs::hard_link(part, output).context("publish completed image")?;
    stela_core::write_json(&sidecar(output, ".json"), &receipt)?;
    std::fs::remove_file(part)?;
    std::fs::remove_file(metadata)?;
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_hosts_and_ranges() {
        assert!(apple_url(
            &Url::parse("https://updates.cdn-apple.com/file").unwrap()
        ));
        assert!(!apple_url(
            &Url::parse("https://apple.com.evil.test/file").unwrap()
        ));
        assert!(!apple_url(
            &Url::parse("http://updates.cdn-apple.com/file").unwrap()
        ));
        assert_eq!(range_total("bytes 5-9/10", 5).unwrap(), 10);
        assert!(range_total("bytes 0-9/10", 5).is_err());
        assert!(range_total("bytes 5-8/10", 5).is_err());
    }
    #[test]
    fn parses_real_feed_structure_and_unknown_universal() -> Result<()> {
        let bytes = include_bytes!("../../../tests/fixtures/catalog.plist");
        let images = parse_catalog(bytes)?;
        assert_eq!(images.len(), 2);
        assert_eq!(
            select(&images, None, Some("VirtualMac2,1"))?.version,
            "27.10"
        );
        assert_eq!(select(&images, Some("TEST1"), None)?.models.len(), 2);
        assert_eq!(
            select(&images, Some("TEST1"), None)?.sha1,
            Some("1".repeat(40))
        );
        assert!(parse_catalog(b"invalid").is_err());
        Ok(())
    }
    fn serve(reply: String) -> (String, std::thread::JoinHandle<String>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let thread = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = vec![];
            let mut byte = [0];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            stream.write_all(reply.as_bytes()).unwrap();
            String::from_utf8(request).unwrap()
        });
        (format!("http://{address}/fixture.ipsw"), thread)
    }
    #[test]
    fn resumes_and_verifies_image() -> Result<()> {
        let (url, server) = serve("HTTP/1.1 206 Partial Content\r\nContent-Length: 5\r\nContent-Range: bytes 5-9/10\r\nConnection: close\r\n\r\n56789".into());
        let image = Image {
            version: "test".into(),
            build: "TEST".into(),
            models: vec![],
            url,
            sha1: Some(hex::encode(sha1::Sha1::digest(b"0123456789"))),
        };
        let dir = tempfile::tempdir()?;
        let out = dir.path().join("test.ipsw");
        std::fs::write(sidecar(&out, ".part"), b"01234")?;
        stela_core::write_json(
            &sidecar(&out, ".part.json"),
            &Partial {
                image: image.clone(),
                total_bytes: Some(10),
            },
        )?;
        let receipt = download_with_client(&image, &out, &Client::new())?;
        assert_eq!(std::fs::read(&out)?, b"0123456789");
        assert!(receipt.catalog_sha1_verified);
        assert!(
            server
                .join()
                .unwrap()
                .to_lowercase()
                .contains("range: bytes=5-")
        );
        Ok(())
    }

    #[test]
    fn completed_partial_is_published_without_another_request() -> Result<()> {
        let image = Image {
            version: "test".into(),
            build: "TEST".into(),
            models: vec![],
            url: "http://127.0.0.1:1/unused".into(),
            sha1: Some(hex::encode(sha1::Sha1::digest(b"complete"))),
        };
        let dir = tempfile::tempdir()?;
        let out = dir.path().join("test.ipsw");
        std::fs::write(sidecar(&out, ".part"), b"complete")?;
        stela_core::write_json(
            &sidecar(&out, ".part.json"),
            &Partial {
                image: image.clone(),
                total_bytes: Some(8),
            },
        )?;
        let receipt = download_with_client(&image, &out, &Client::new())?;
        assert_eq!(receipt.bytes, 8);
        assert_eq!(std::fs::read(out)?, b"complete");
        Ok(())
    }
    #[test]
    fn ignored_range_restarts_and_bad_digest_never_publishes() -> Result<()> {
        for bad in [false, true] {
            let (url, server) = serve(
                "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc".into(),
            );
            let image = Image {
                version: "test".into(),
                build: "TEST".into(),
                models: vec![],
                url,
                sha1: bad.then(|| "0".repeat(40)),
            };
            let dir = tempfile::tempdir()?;
            let out = dir.path().join("test.ipsw");
            std::fs::write(sidecar(&out, ".part"), b"old")?;
            stela_core::write_json(
                &sidecar(&out, ".part.json"),
                &Partial {
                    image: image.clone(),
                    total_bytes: None,
                },
            )?;
            let result = download_with_client(&image, &out, &Client::new());
            if bad {
                assert!(result.is_err());
                assert!(!out.exists());
            } else {
                result?;
                assert_eq!(std::fs::read(out)?, b"abc");
            }
            server.join().unwrap();
        }
        Ok(())
    }
}
