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
    let bytes = include_bytes!("../../tests/fixtures/catalog.plist");
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
    stela_runtime::write_json(
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
    stela_runtime::write_json(
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
        let (url, server) =
            serve("HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc".into());
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
        stela_runtime::write_json(
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
