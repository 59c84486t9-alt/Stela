use super::*;
use crate::{EntropySource, RandomUnavailable};
use core::sync::atomic::{AtomicBool, Ordering};

struct Random;
impl EntropySource for Random {
    fn fill(&self, output: &mut [u8]) -> Result<(), RandomUnavailable> {
        let mut bytes = zeroize::Zeroizing::new(alloc::vec![0; output.len()]);
        getrandom::getrandom(&mut bytes).map_err(|_| RandomUnavailable)?;
        output.copy_from_slice(&bytes);
        Ok(())
    }
}
fn owner() -> &'static ProviderOwner {
    static OWNER: std::sync::OnceLock<ProviderOwner> = std::sync::OnceLock::new();
    OWNER.get_or_init(|| ProviderOwner::new(Arc::new(Random)))
}
#[derive(Debug)]
struct Source {
    valid: AtomicBool,
    bounds: UtcInterval,
}
impl UtcSource for Source {
    fn interval(&self) -> Result<UtcInterval, TimeError> {
        if !self.valid.load(Ordering::Acquire) {
            return Err(TimeError::SourceChanged);
        }
        Ok(self.bounds)
    }
}
fn source(earliest: u64, latest: u64) -> Arc<Source> {
    Arc::new(Source {
        valid: AtomicBool::new(true),
        bounds: UtcInterval::new(earliest, latest).unwrap(),
    })
}
fn roots() -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(
            &include_bytes!("../../tests/fixtures/ec-ca.der")[..],
        ))
        .unwrap();
    roots
}
fn verify(bounds: (u64, u64), name: &'static str) -> Result<ServerCertVerified, Error> {
    let provider = Arc::new(owner().provider());
    let roots = Arc::new(roots());
    let inner = WebPkiServerVerifier::builder_with_provider(roots.clone(), provider)
        .build()
        .unwrap();
    let verifier = IntervalVerifier {
        inner,
        roots,
        source: source(bounds.0, bounds.1),
    };
    verifier.verify_server_cert(
        &CertificateDer::from(&include_bytes!("../../tests/fixtures/ec-leaf.der")[..]),
        &[],
        &ServerName::try_from(name).unwrap(),
        &[],
        UnixTime::since_unix_epoch(Duration::from_secs(bounds.0)),
    )
}
#[test]
fn interval_ordering_and_revocation_refuse_without_a_timestamp_fallback() {
    assert_eq!(UtcInterval::new(2, 1), Err(TimeError::InvalidInterval));
    let source = source(1, 2);
    let time = IntervalTime(source.clone());
    assert_eq!(time.current_time().unwrap().as_secs(), 1);
    source.valid.store(false, Ordering::Release);
    assert!(time.current_time().is_none());
    assert_eq!(source.interval(), Err(TimeError::SourceChanged));
}
#[test]
fn both_certificate_validity_bounds_and_the_normal_name_check_are_required() {
    let _serial = crate::allocator::observation::SERIAL.lock().unwrap();
    let now = 1_793_232_000;
    assert!(verify((now - 86_400, now + 86_400), "localhost").is_ok());
    for (bounds, name) in [
        ((1_735_689_600, now), "localhost"),
        ((now, 1_830_297_600), "localhost"),
        ((now, now), "bad.test"),
    ] {
        assert!(matches!(
            verify(bounds, name),
            Err(Error::InvalidCertificate(_))
        ));
    }
}
#[test]
fn revoked_correlation_refuses_configuration_before_key_generation() {
    let source = source(1_793_232_000, 1_793_232_001);
    source.valid.store(false, Ordering::Release);
    assert!(matches!(
        client_config_with_roots(owner(), source, roots()),
        Err(PolicyError::Utc(TimeError::SourceChanged))
    ));
}
#[test]
fn lost_correlation_erases_encoded_output_and_permanently_refuses() {
    let _serial = crate::allocator::observation::SERIAL.lock().unwrap();
    let source = source(1_793_232_000, 1_793_232_001);
    let config = client_config_with_roots(owner(), source.clone(), roots()).unwrap();
    let mut channel =
        crate::channel::Channel::new(config, ServerName::try_from("localhost").unwrap()).unwrap();
    assert!(matches!(
        channel.advance(&[]),
        Ok(crate::channel::Progress::NeedWrite)
    ));
    assert!(!channel.output().is_empty());
    source.valid.store(false, Ordering::Release);
    assert!(matches!(
        channel.advance(&[]),
        Err(crate::channel::ChannelError::TimeUnavailable)
    ));
    assert!(channel.output().is_empty());
    source.valid.store(true, Ordering::Release);
    assert!(matches!(
        channel.advance(&[]),
        Err(crate::channel::ChannelError::TimeUnavailable)
    ));
}

fn chain_cert(name: &str) -> CertificateDer<'static> {
    let bytes: &'static [u8] = match name {
        "root" => include_bytes!("../../tests/fixtures/utc-chain/root.der"),
        "leaf" => include_bytes!("../../tests/fixtures/utc-chain/leaf.der"),
        "early" => include_bytes!("../../tests/fixtures/utc-chain/early.der"),
        "late" => include_bytes!("../../tests/fixtures/utc-chain/late.der"),
        "cover" => include_bytes!("../../tests/fixtures/utc-chain/cover.der"),
        "overlap" => include_bytes!("../../tests/fixtures/utc-chain/overlap.der"),
        _ => unreachable!(),
    };
    CertificateDer::from(bytes)
}
fn chain_verifier(source: Arc<dyn UtcSource>) -> IntervalVerifier {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(chain_cert("root")).unwrap();
    let roots = Arc::new(roots);
    let inner =
        WebPkiServerVerifier::builder_with_provider(roots.clone(), Arc::new(owner().provider()))
            .build()
            .unwrap();
    IntervalVerifier {
        inner,
        roots,
        source,
    }
}
#[test]
fn disjoint_or_partially_overlapping_paths_cannot_bridge_the_utc_interval() {
    let _serial = crate::allocator::observation::SERIAL.lock().unwrap();
    let bounds = UtcInterval::new(1_767_571_200, 1_769_299_200).unwrap(); // 2026 January5..25 UTC.
    for intermediate in ["early", "overlap"] {
        let source = source(bounds.earliest().as_secs(), bounds.latest().as_secs());
        let verifier = chain_verifier(source);
        let leaf = chain_cert("leaf");
        let chain = [chain_cert(intermediate), chain_cert("late")];
        let name = ServerName::try_from("localhost").unwrap();
        // Ordinary endpoint verification can pick two different valid paths.
        assert!(
            verifier
                .inner
                .verify_server_cert(&leaf, &chain, &name, &[], bounds.earliest())
                .is_ok()
        );
        assert!(
            verifier
                .inner
                .verify_server_cert(&leaf, &chain, &name, &[], bounds.latest())
                .is_ok()
        );
        assert!(matches!(
            verifier.verify_server_cert(&leaf, &chain, &name, &[], bounds.earliest()),
            Err(Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure
            ))
        ));
    }
}
#[test]
fn path_search_finds_a_single_covering_chain_independent_of_alternative_order() {
    let _serial = crate::allocator::observation::SERIAL.lock().unwrap();
    let verifier = chain_verifier(source(1_767_571_200, 1_769_299_200));
    let leaf = chain_cert("leaf");
    let name = ServerName::try_from("localhost").unwrap();
    for order in [
        ["early", "late", "cover"],
        ["late", "cover", "early"],
        ["cover", "early", "late"],
    ] {
        let chain = order.map(chain_cert);
        assert!(
            verifier
                .verify_server_cert(
                    &leaf,
                    &chain,
                    &name,
                    &[],
                    UnixTime::since_unix_epoch(Duration::from_secs(1_767_571_200))
                )
                .is_ok()
        );
    }
}
#[derive(Debug)]
struct Widening(core::sync::atomic::AtomicU64);
impl UtcSource for Widening {
    fn interval(&self) -> Result<UtcInterval, TimeError> {
        UtcInterval::new(1_767_571_200, self.0.load(Ordering::Acquire))
    }
}
#[test]
fn wider_current_uncertainty_rechecks_the_same_path_instead_of_old_readiness() {
    let _serial = crate::allocator::observation::SERIAL.lock().unwrap();
    let source = Arc::new(Widening(core::sync::atomic::AtomicU64::new(1_767_571_200)));
    let verifier = chain_verifier(source.clone());
    let leaf = chain_cert("leaf");
    let chain = [chain_cert("early"), chain_cert("late")];
    let name = ServerName::try_from("localhost").unwrap();
    let now = UnixTime::since_unix_epoch(Duration::from_secs(1_767_571_200));
    assert!(
        verifier
            .verify_server_cert(&leaf, &chain, &name, &[], now)
            .is_ok()
    );
    source.0.store(1_769_299_200, Ordering::Release);
    assert!(
        verifier
            .verify_server_cert(&leaf, &chain, &name, &[], now)
            .is_err()
    );
}

#[cfg(feature = "native-reference-peer")]
mod peer;
