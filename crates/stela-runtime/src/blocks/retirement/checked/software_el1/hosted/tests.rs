use super::*;
#[test]
fn source_installation_cannot_be_released_and_recreated() {
    let (mut installation, _) = unsafe { HostedWaitInstallation::fresh() }.unwrap();
    let events = EventDomain::new();
    let mut endpoint = events.register(false, None).unwrap();
    {
        let resources = installation.resources(&events, &mut endpoint).unwrap();
        resources.check_resources().unwrap();
    }
    assert!(installation.resources(&events, &mut endpoint).is_err());
    assert!(matches!(
        installation.domain.lease_no_sources(),
        Err(AsyncError::RegisteredProducer)
    ));
}
