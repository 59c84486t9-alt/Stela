use super::*;

#[test]
#[ignore = "oracle: STELA_IWLWIFI_IMAGES"]
fn actual_pnvm_skus_preserve_payloads_in_both_layouts() {
    use sha2::{Digest, Sha256};
    let root = std::env::var("STELA_IWLWIFI_IMAGES").unwrap();
    let bytes =
        std::fs::read(std::path::Path::new(&root).join("iwlwifi-ty-a0-gf-a0.pnvm")).unwrap();
    let sha: alloc::string::String = Sha256::digest(&bytes)
        .iter()
        .map(|b| alloc::format!("{b:02x}"))
        .collect();
    assert_eq!(
        sha,
        "9697e327f8171454b3c19b1ec9449753d5b934d4e91722f469616818a6d477b0"
    );
    let profile = Profile::select(Observed {
        vendor: 0x8086,
        device: 0x2725,
        subsystem_vendor: 0x8086,
        subsystem_device: 0x84,
        pci_revision: 0x1a,
        hardware_revision: 0x420,
        radio_id: 0x10d000,
    })
    .unwrap();
    let pnvm = pnvm::Pnvm::parse(&bytes).unwrap();
    for sku in [0x610d0, 0x510d0, 0x4510d0, 0x4610d0] {
        let selection = pnvm.select(&profile, [sku, 0, 0]).unwrap();
        for fragmented in [false, true] {
            let source = Source::default();
            let domain = Arc::new(Domain::default());
            let mut table = prepare(selection.chunks(), fragmented, &source, &domain).unwrap();
            let config = table.expose_for_scratch().unwrap();
            let expected: Vec<_> = selection
                .chunks()
                .iter()
                .flat_map(|c| c.data)
                .copied()
                .collect();
            assert_eq!(config.bytes as usize, expected.len());
            let records = domain.records.lock().unwrap();
            if fragmented {
                for (i, chunk) in selection.chunks().iter().enumerate() {
                    assert_eq!(records.copied[i + 1], chunk.data);
                }
            } else {
                assert_eq!(records.copied[0], expected);
            }
            drop(records);
            // SAFETY: the source-backed bytes were staged into a synchronous
            // model domain only; no device or worker can retain DMA access.
            unsafe {
                table.release_after_stop().unwrap();
            }
            drop(table);
            assert!(domain.records.lock().unwrap().live.is_empty());
        }
    }
}
#[test]
#[ignore = "oracle: STELA_IWLWIFI_IMAGES, STELA_IWLWIFI_PNVM_DMA_ORACLE"]
fn pnvm_and_reduced_power_tables_match_linux_for_both_layouts() {
    use sha2::{Digest, Sha256};
    fn hex(bytes: &[u8]) -> alloc::string::String {
        bytes.iter().map(|b| alloc::format!("{b:02x}")).collect()
    }
    fn read(domain: &Domain, address: u64, n: usize) -> Vec<u8> {
        let r = domain.records.lock().unwrap();
        let id = (address - 0x100000) / 0x10000;
        let p = r.live[&id].address(0, n).unwrap();
        // SAFETY: address() checked this range within a live initialized
        // allocation. The domain lock retains its mapping through the copy,
        // and this synchronous model has no device or concurrent writer.
        unsafe { core::slice::from_raw_parts(p.as_ptr(), n) }.to_vec()
    }
    fn fnv(bytes: &[u8]) -> u64 {
        bytes.iter().fold(0xcbf29ce484222325u64, |h, b| {
            (h ^ u64::from(*b)).wrapping_mul(0x100000001b3)
        })
    }
    let trace = std::fs::read(std::env::var("STELA_IWLWIFI_PNVM_DMA_ORACLE").unwrap()).unwrap();
    assert_eq!(
        hex(&Sha256::digest(&trace)),
        "481d0fbbaf87aab52e178dd56c25743a7cb8eaab2fd49c093e426801b52a72f5"
    );
    let root = std::env::var("STELA_IWLWIFI_IMAGES").unwrap();
    let bytes =
        std::fs::read(std::path::Path::new(&root).join("iwlwifi-ty-a0-gf-a0.pnvm")).unwrap();
    assert_eq!(
        hex(&Sha256::digest(&bytes)),
        "9697e327f8171454b3c19b1ec9449753d5b934d4e91722f469616818a6d477b0"
    );
    let pnvm = pnvm::Pnvm::parse(&bytes).unwrap();
    let profile = Profile::select(Observed {
        vendor: 0x8086,
        device: 0x2725,
        subsystem_vendor: 0x8086,
        subsystem_device: 0x84,
        pci_revision: 0x1a,
        hardware_revision: 0x420,
        radio_id: 0x10d000,
    })
    .unwrap();
    let text = core::str::from_utf8(&trace).unwrap();
    let mut lines = text.lines();
    let mut cases = 0;
    while let Some(line) = lines.next() {
        let fields: Vec<_> = line.split_whitespace().collect();
        assert_eq!(fields[0], "case");
        let sku = u32::from_str_radix(fields[1], 16).unwrap();
        let fragmented = fields[2] == "1";
        let selection = pnvm.select(&profile, [sku, 0, 0]).unwrap();
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let mut tables = Vec::new();
        for kind in 0..2 {
            let mut table = prepare(selection.chunks(), fragmented, &source, &domain).unwrap();
            let config = table.expose_for_scratch().unwrap();
            let fields: Vec<_> = lines.next().unwrap().split_whitespace().collect();
            assert_eq!(fields[0], "table");
            assert_eq!(fields[1].parse::<u32>().unwrap(), kind);
            assert_eq!(u64::from_str_radix(fields[2], 16).unwrap(), config.address);
            assert_eq!(fields[3].parse::<u32>().unwrap(), config.bytes);
            assert_eq!(fields[4].parse::<usize>().unwrap(), table.payloads.len());
            if fragmented {
                assert_eq!(
                    lines.next().unwrap(),
                    alloc::format!("descriptor {}", hex(&read(&domain, config.address, 512)))
                );
            }
            for payload in table.payloads() {
                let fields: Vec<_> = lines.next().unwrap().split_whitespace().collect();
                assert_eq!(fields[0], "payload");
                assert_eq!(u64::from_str_radix(fields[1], 16).unwrap(), payload.address);
                assert_eq!(fields[2].parse::<usize>().unwrap(), payload.bytes);
                assert_eq!(
                    u64::from_str_radix(fields[3], 16).unwrap(),
                    fnv(&read(&domain, payload.address, payload.bytes))
                );
            }
            tables.push(table);
        }
        for table in &mut tables {
            // SAFETY: both tables belong to the same synchronous no-device
            // model; the oracle comparison finished before either is released.
            unsafe {
                table.release_after_stop().unwrap();
            }
        }
        assert!(domain.records.lock().unwrap().live.is_empty());
        cases += 1;
    }
    assert_eq!(cases, 8);
}
