//! Conservative certificate time checks over a caller-owned UTC correlation.
use crate::{PolicyError, ProviderOwner};
use alloc::{sync::Arc, vec::Vec};
use core::{fmt, time::Duration};
use rustls::{
    ClientConfig, DigitallySignedStruct, DistinguishedName, Error, SignatureScheme,
    client::{
        WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    pki_types::{CertificateDer, ServerName, UnixTime},
    time_provider::TimeProvider,
};

/// Inclusive outward-rounded UTC seconds. Construction checks ordering only;
/// it cannot establish the firmware, counter or clock-source ownership.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UtcInterval {
    earliest: UnixTime,
    latest: UnixTime,
}
impl UtcInterval {
    pub fn new(earliest: u64, latest: u64) -> Result<Self, TimeError> {
        if earliest > latest {
            return Err(TimeError::InvalidInterval);
        }
        Ok(Self {
            earliest: UnixTime::since_unix_epoch(Duration::from_secs(earliest)),
            latest: UnixTime::since_unix_epoch(Duration::from_secs(latest)),
        })
    }
    pub fn earliest(self) -> UnixTime {
        self.earliest
    }
    pub fn latest(self) -> UnixTime {
        self.latest
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeError {
    Unavailable,
    SourceChanged,
    InvalidInterval,
}
impl fmt::Display for TimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unavailable => "UTC correlation is unavailable",
            Self::SourceChanged => "UTC correlation source changed",
            Self::InvalidInterval => "UTC interval is inverted",
        })
    }
}
impl core::error::Error for TimeError {}

/// Retains the actual admitted clock and UTC correlation. Implementations must
/// include RTC resolution, capture bracketing and elapsed counter uncertainty,
/// round bounds outward, and refuse source/epoch loss or arithmetic failure.
/// Copying a timestamp or counter frequency does not fulfill this contract.
/// No firmware runtime-service pointer needs to cross this Send+Sync boundary.
pub trait UtcSource: fmt::Debug + Send + Sync {
    fn interval(&self) -> Result<UtcInterval, TimeError>;
}
#[derive(Debug)]
struct IntervalTime(Arc<dyn UtcSource>);
impl TimeProvider for IntervalTime {
    fn current_time(&self) -> Option<UnixTime> {
        self.0.interval().ok().map(UtcInterval::earliest)
    }
}
#[derive(Debug)]
struct IntervalVerifier {
    inner: Arc<WebPkiServerVerifier>,
    roots: Arc<rustls::RootCertStore>,
    source: Arc<dyn UtcSource>,
}
impl ServerCertVerifier for IntervalVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let interval = self
            .source
            .interval()
            .map_err(|_| Error::FailedToGetCurrentTime)?;
        // The same mature chain/name/time verifier accepts BOTH inclusive bounds.
        // There is no midpoint selection or relaxed validity/name/trust policy.
        self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            interval.earliest,
        )?;
        let verified = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            interval.latest,
        )?;
        // Endpoint searches may choose different cross-signed intermediates.
        // WebPKI's path callback restricts the second check to the first path's
        // actual DER chain and anchor. A refusal lets its mature path builder
        // try another candidate; only one path spanning BOTH bounds succeeds.
        let failure =
            || Error::InvalidCertificate(rustls::CertificateError::ApplicationVerificationFailure);
        let cert = webpki::EndEntityCert::try_from(end_entity).map_err(|_| failure())?;
        let covers_latest = |path: &webpki::VerifiedPath<'_>| {
            let chain: Vec<_> = path
                .intermediate_certificates()
                .map(|cert| cert.der())
                .collect();
            cert.verify_for_usage(
                crate::verification::ALGORITHMS.all,
                core::slice::from_ref(path.anchor()),
                &chain,
                interval.latest,
                webpki::KeyUsage::server_auth(),
                None,
                None,
            )
            .map(|_| ())
        };
        cert.verify_for_usage(
            crate::verification::ALGORITHMS.all,
            &self.roots.roots,
            intermediates,
            interval.earliest,
            webpki::KeyUsage::server_auth(),
            None,
            Some(&covers_latest),
        )
        .map_err(|_| failure())?;
        Ok(verified)
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
    fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> {
        self.inner.root_hint_subjects()
    }
}
pub(crate) fn client_config_with_roots(
    owner: &'static ProviderOwner,
    source: Arc<dyn UtcSource>,
    roots: rustls::RootCertStore,
) -> Result<Arc<ClientConfig>, PolicyError> {
    source.interval().map_err(PolicyError::Utc)?;
    if roots.is_empty() {
        return Err(PolicyError::TrustUnavailable);
    }
    let provider = Arc::new(owner.provider());
    let roots = Arc::new(roots);
    let verifier = WebPkiServerVerifier::builder_with_provider(roots.clone(), provider.clone())
        .build()
        .map_err(PolicyError::Verifier)?;
    let time = Arc::new(IntervalTime(source.clone()));
    let mut config = ClientConfig::builder_with_details(provider, time)
        .with_safe_default_protocol_versions()
        .map_err(PolicyError::Configuration)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(IntervalVerifier {
            inner: verifier,
            roots,
            source,
        }))
        .with_no_client_auth();
    // Resumption skips fresh certificate verification. A prior interval/path
    // admission cannot substitute for the current correlation on a new session.
    config.resumption = rustls::client::Resumption::disabled();
    Ok(Arc::new(config))
}
/// Mozilla trust with normal WebPKI checks at both admitted UTC bounds.
/// Source refusal prevents configuration/ClientHello publication; Channel keeps
/// checking that same retained source before every protocol/output advance.
pub fn client_config_with_interval(
    owner: &'static ProviderOwner,
    source: Arc<dyn UtcSource>,
) -> Result<Arc<ClientConfig>, PolicyError> {
    client_config_with_roots(
        owner,
        source,
        rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        },
    )
}
#[cfg(test)]
mod tests;
