use super::*;
#[test]
fn colliding_numeric_source_sequence_word_never_cross_domains() {
    let mut a = unsafe { SoftwareAsyncDomain::fresh_software_pe() };
    let mut b = unsafe { SoftwareAsyncDomain::fresh_software_pe() };
    let ak = [a.register_debug().unwrap()];
    let bk = [b.register_debug().unwrap()];
    a.enqueue_editr(&ak[0], 0xd6bf03e0).unwrap();
    b.enqueue_editr(&bk[0], 0xd6bf03e0).unwrap();
    let event = a
        .lease_debug_sources(&ak)
        .unwrap()
        .next_editr()
        .unwrap()
        .unwrap();
    {
        let mut lease = b.lease_debug_sources(&bk).unwrap();
        assert_eq!(lease.consume_editr(&event), Err(AsyncError::WrongProducer));
        assert!(lease.next_editr().unwrap().is_some());
    }
    // The keys survive the lease and still identify later injections.
    b.enqueue_editr(&bk[0], 0xd6bf03e0).unwrap();
    assert!(b.lease_debug_sources(&bk).is_ok());
}
