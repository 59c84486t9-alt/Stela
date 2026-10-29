use super::*;

#[test]
fn carveouts_pack_from_the_dram_base_and_the_managed_range_starts_on_a_block() {
    let plan = reserve(T8112, 0x8_0000_0000, 1 << 30).unwrap();
    let placed = plan.regions();
    assert_eq!(placed[0].base, 0x8_0000_0000);
    assert_eq!(placed[1].base, 0x8_0004_0000);
    assert!(placed.iter().all(|c| c.base % PAGE_BYTES == 0));
    let end = placed.last().map(|c| c.base + c.bytes).unwrap();
    assert!(end <= plan.managed_floor());
    assert_eq!(plan.managed_floor(), 0x8_0200_0000);
    assert_eq!(
        reserve(&[], 0x8_0000_0000, 1 << 30)
            .unwrap()
            .managed_floor(),
        0x8_0000_0000
    );
}

#[test]
fn reservation_checks_bounds_protocol_extents_and_alignment_padding() {
    let base = 0x100_0000_0000;
    let table = for_chip(0x6000);
    let plan = reserve(&table, base, MANAGED_ALIGNMENT + PAGE_BYTES).unwrap();
    let payload: u64 = plan.regions().iter().map(|region| region.bytes).sum();
    assert_eq!(payload, 3_342_336);
    assert_eq!(plan.managed_floor() - base, MANAGED_ALIGNMENT);
    assert_eq!(plan.managed_floor() - base - payload, 30_212_096);
    assert!(reserve(&table, base, MANAGED_ALIGNMENT).is_err());
    assert!(reserve(&table, base, PAGE_BYTES).is_err());
    assert!(reserve(&[], u64::MAX - PAGE_BYTES + 1, PAGE_BYTES).is_err());
    assert!(reserve(&[], u64::MAX - 2 * PAGE_BYTES + 1, PAGE_BYTES).is_err());
    assert!(reserve(&[], base + 1, MANAGED_ALIGNMENT).is_err());
    assert!(reserve(&[], base, PAGE_BYTES + 1).is_err());
    for bytes in [0, PAGE_BYTES - 1, PAGE_BYTES * 0x10000] {
        assert!(reserve(&[carveout(1, bytes)], base, 1 << 32).is_err());
    }
    assert!(reserve(&[PANIC, PANIC], base, 1 << 30).is_err());
}

#[test]
fn every_region_meets_sptm_io_range_rules_and_sgx_names_one_page_l2() {
    for (index, family) in FAMILIES.iter().enumerate() {
        let table = family.fixed;
        for c in table {
            assert!(c.bytes > 0 && c.bytes % PAGE_BYTES == 0);
            assert!(c.bytes / PAGE_BYTES < 0x10000);
            assert!(!family.special.contains(&c.id));
        }
        let l2 = table.iter().find(|c| c.id == 0xd9).unwrap();
        assert_eq!(l2.bytes, PAGE_BYTES);
        for (id, _) in SGX_REGIONS {
            assert!(table.iter().any(|c| c.id == id));
        }
        // Each ApChipID has one table, and the table with the panic
        // region still leaves managed DRAM past the first block.
        for chip_id in family.chips {
            assert!(FAMILIES[..index].iter().all(|f| !f.chips.contains(chip_id)));
            let plan = reserve(&for_chip(*chip_id), 0x100_0000_0000, 1 << 30).unwrap();
            assert_eq!(plan.managed_floor(), 0x100_0000_0000 + MANAGED_ALIGNMENT);
        }
    }
}

#[test]
fn publishes_region_ids_and_the_gpu_uat_regions() -> Result<()> {
    let mut tree = DeviceTree {
        root: crate::apple_device_tree::Node::named("device-tree")?,
    };
    tree.ensure_child("/", "chosen")?;
    tree.ensure_child("/chosen", "carveout-memory-map")?;
    tree.ensure_child("/", "arm-io")?;
    tree.ensure_child("/arm-io", "sgx")?;
    let placed = reserve(T8112, 0x8_0000_0000, 1 << 30)
        .unwrap()
        .into_regions();
    publish(&mut tree, &placed)?;
    let handoff = placed.iter().find(|c| c.id == 0x38).unwrap();
    assert_eq!(
        tree.property(MEMORY_MAP, "region-id-56").unwrap().value,
        range(handoff.base, 0x4000)
    );
    assert_eq!(
        tree.property(SGX, "gfx-handoff-base").unwrap().as_u64(),
        Some(handoff.base)
    );
    assert_eq!(
        tree.property(SGX, "gfx-shared-l2-region-size")
            .unwrap()
            .as_u64(),
        Some(0x4000)
    );
    Ok(())
}

#[test]
fn every_soc_with_handoff_facts_gets_the_panic_region_after_its_table() {
    let t8112 = for_chip(0x8112);
    assert_eq!(&t8112[..T8112.len()], T8112);
    assert_eq!(t8112[T8112.len()..], [PANIC]);
    assert_eq!(PANIC, carveout(98, 0x18_8000));
    // Every SoC row's table comes first; an unknown SoC gets none.
    for chip_id in [
        0x8103, 0x8122, 0x6040, 0x6041, 0x8140, 0x8142, 0x6050, 0x8152,
    ] {
        let carveouts = for_chip(chip_id);
        assert_eq!(carveouts.last(), Some(&PANIC));
        assert_eq!(&carveouts[..carveouts.len() - 1], table(chip_id).unwrap());
    }
    assert!(for_chip(0x8101).is_empty());
    assert!(table(0x8101).is_none());
    // It meets SPTM's I/O range rules and leaves physBase where it was.
    assert!(PANIC.bytes.is_multiple_of(PAGE_BYTES) && PANIC.bytes / PAGE_BYTES < 0x10000);
    assert_eq!(
        reserve(&t8112, 0x8_0000_0000, 1 << 30)
            .unwrap()
            .managed_floor(),
        0x8_0200_0000
    );
    assert_eq!(
        reserve(&[PANIC], 0x10_0000_0000, 1 << 30)
            .unwrap()
            .managed_floor(),
        0x10_0200_0000
    );
}

#[test]
fn t6000_places_and_publishes_reserved_nonoverlapping_regions() -> Result<()> {
    let dram = 0x100_0000_0000;
    let table = for_chip(0x6000);
    assert_eq!(table.last(), Some(&PANIC));
    let plan = reserve(&table, dram, 1 << 30).unwrap();
    let managed = plan.managed_floor();
    let placed = plan.into_regions();
    for (index, region) in placed.iter().enumerate() {
        assert!(region.base.is_multiple_of(PAGE_BYTES));
        assert!(region.base >= dram && region.base + region.bytes <= managed);
        assert!(
            placed[..index].iter().all(|before| {
                before.id != region.id && before.base + before.bytes <= region.base
            })
        );
    }
    let mut tree = tree_with(&["chosen", "pram", "arm-io"])?;
    tree.ensure_child("/arm-io", "sgx")?;
    publish(&mut tree, &placed)?;
    for (id, name) in SGX_REGIONS {
        let region = placed.iter().find(|region| region.id == id).unwrap();
        assert_eq!(
            tree.property(SGX, &format!("{name}-base"))
                .unwrap()
                .as_u64(),
            Some(region.base)
        );
        assert_eq!(
            tree.property(SGX, &format!("{name}-size"))
                .unwrap()
                .as_u64(),
            Some(region.bytes)
        );
    }
    assert!(!placed.iter().any(|region| region.id == 0x108));
    assert!(
        gaps(&tree, Some(0x6000))
            .iter()
            .any(|gap| gap.contains("0x108"))
    );
    Ok(())
}

/// Every 26A434 board's decoded iBoot: its ApChipID, file name, SHA-256,
    /// table offset, record stride and the record count its descriptor states.
    #[rustfmt::skip]
    const ORIGINAL_TABLES: [(u32, &str, &str, usize, usize, usize); 59] = [
        (0x8103, "iBoot.j274.bin", "c46ab86ad89c568c05d09ebf3ad741a9dc6b29f4a4701180ab6952eb38865d8c", 0x14e5c8, 0x28, 100),
        (0x8103, "iBoot.j293.bin", "bae3e17daa49389315b73b23e779fc7b2444f76e0eca37663fc8c9291867dff3", 0x15a7c8, 0x28, 103),
        (0x8103, "iBoot.j313.bin", "82d03e03e52f3e8e7425e2b4405f417cd220106f52a602f0b85323a18cec3c7b", 0x1565c8, 0x28, 103),
        (0x8103, "iBoot.j456.bin", "068860431fc49518cfb655116dfdc18c97f03406aa7920bc5d119e819ff1a480", 0x14e5c8, 0x28, 100),
        (0x8103, "iBoot.j457.bin", "d397c67a7cc6e690d978e71fb18b10fbaa970d59985e5ed155331776940d4edc", 0x14e5c8, 0x28, 100),
        (0x6000, "iBoot.j314s.bin", "20dfa3a5e6d4e4b2844c7558e6d4f8ab74397d11eae63312f00a559cf9612b03", 0x1ffce8, 0x40, 112),
        (0x6000, "iBoot.j316s.bin", "f2a79cbfafe24081b93454423d4529ab756a5b7fae8fdd0d0178ccb17a3f04d8", 0x1ffce8, 0x40, 112),
        (0x6001, "iBoot.j314c.bin", "3365086e4ae0166e5f142aed59c2479021934af2ad547d4b70cdefc85336d6a0", 0x218938, 0x40, 122),
        (0x6001, "iBoot.j316c.bin", "e60131aa5a590b4c6a26d95587cf1b1e8aceedfb0e7a2435b88358320ba30caf", 0x218938, 0x40, 122),
        (0x6001, "iBoot.j375c.bin", "03e857032d03c7231de90f72692f804ba69898d53dee2762622b274bb64c6bcc", 0x20c850, 0x40, 119),
        (0x6002, "iBoot.j375d.bin", "8e5217f10d34f0f37a7f0132986e4342c383e8e9138866bcb555b6e04498fca0", 0x238e88, 0x40, 139),
        (0x8112, "iBoot.j413.bin", "4b12bbc28d69033e97662864ad1647ec687c85c640a5dd06fdc5907123caf6ab", 0x1e2388, 0x40, 103),
        (0x8112, "iBoot.j415.bin", "6e1e1fead67e79e760f6fcb2abae675afd3ba2080adbd1cb99e03f7d24e8c236", 0x1e2388, 0x40, 103),
        (0x8112, "iBoot.j473.bin", "082cf7b48f9827daefcb5a58e7fd0038aae00b3fe6d36db9ff1528ba3f3a3a3b", 0x1d6288, 0x40, 100),
        (0x8112, "iBoot.j493.bin", "1160583e3d2febf985842609a4519f58c3c2d17188ca5a4e878f63c5ea5dbfbc", 0x1ea830, 0x40, 103),
        (0x6020, "iBoot.j414s.bin", "44d3dba9be9dbb9fc3fcae509874051908443906aa4df11e71f9aa1316aedc28", 0x210268, 0x40, 118),
        (0x6020, "iBoot.j416s.bin", "7a00a5aba2b30f0b708efe98272a6a11bbacb1f803db3b5294f26b7b1e52a112", 0x20c268, 0x40, 118),
        (0x6020, "iBoot.j474s.bin", "4dab60a0b6c6f8e08e8b6e1815d6798eb576f95333eb5e1d3a8027c15084fd21", 0x204180, 0x40, 115),
        (0x6021, "iBoot.j414c.bin", "6f81ed1a78894893aded2ee2fb10b6ceb06668e94077102e27fdd862be8d95b5", 0x222b00, 0x40, 128),
        (0x6021, "iBoot.j416c.bin", "04a1af958d61bcaafc82115c7b367f6b9f3bd34e215bc5e6fee8481d6bc964b5", 0x222b00, 0x40, 128),
        (0x6021, "iBoot.j475c.bin", "605970409865041f0a9a80b51eb29aead591628e64e11db7ddf4c15a7e199c5b", 0x216a18, 0x40, 125),
        (0x6022, "iBoot.j180d.bin", "a7572e2a529ea05e5e2c30def13b46a42e900ca997dd3f341b40411beaa0487c", 0x25eb20, 0x40, 142),
        (0x6022, "iBoot.j475d.bin", "13f0ffb7c358e4158441fb626e247c0e8afffdadb79e960016bbad00fba2d15e", 0x25eb20, 0x40, 142),
        (0x8122, "iBoot.j433.bin", "d16a02e01bfbca28e7be6318f3166008f0fdde37595d0631b54decaa9adc3a4d", 0x1fa800, 0x40, 101),
        (0x8122, "iBoot.j434.bin", "1b26ef7432c3f0c129f349387eb4338eb6d2e4f6557d7583dc93613948dbd4b9", 0x1fa800, 0x40, 101),
        (0x8122, "iBoot.j504.bin", "de5cd179a632900276e1921e6d7a6ebaf8a676705a5b553428a29efbce5683b3", 0x2027e0, 0x40, 105),
        (0x8122, "iBoot.j613.bin", "bd5334713a831911d85a966c21474c22e4f0b193e85a5441f77fa01deb6ccf36", 0x2027e0, 0x40, 105),
        (0x8122, "iBoot.j615.bin", "05b91da05c7b34cd4ba6fb18fbb33a83353a09293a629cdf271c9aafe9cd88de", 0x2027e0, 0x40, 105),
        (0x6030, "iBoot.j514s.bin", "dfbe29bd7e3b5d36e7b42fcdaee120a2ea10279e3881a805d9be9acea88c514d", 0x20f750, 0x40, 109),
        (0x6030, "iBoot.j516s.bin", "f658effaea515ed926cb39c024348fae7a4d9d03ee3368bf43450380d18d37ac", 0x20f750, 0x40, 109),
        (0x6031, "iBoot.j514c.bin", "5abdbfe1a4cdeafb50aaed6f03b55b71cd08fb2c8617cc46ea1af8663128691b", 0x277280, 0x40, 123),
        (0x6031, "iBoot.j516c.bin", "01b2d51812d393242e26351fa6c6a6eba746ca1cd59ea6cbb2311a2db6f8af2d", 0x277280, 0x40, 123),
        (0x6034, "iBoot.j514m.bin", "0dbfd3074e3fb8c76235081d89bd65bfd26928cd153c06b7a6cc53fdb58e3499", 0x277278, 0x40, 122),
        (0x6034, "iBoot.j516m.bin", "906fc5d642652c21e8674934eb8eff8f8d0da11ab80324016f18c21a944c02fb", 0x277278, 0x40, 122),
        (0x6032, "iBoot.j575d.bin", "bed91c680ce5471ed1210be017ef9a33542e47c83bb7721f03e0aac209ca1c9e", 0x2d6f20, 0x40, 154),
        (0x8132, "iBoot.j604.bin", "a53b470628e4d2e56a1673aa707f6d9b912643ded14e83cd347541e4a82722b6", 0x28dfe8, 0x40, 117),
        (0x8132, "iBoot.j623.bin", "dce550ed5dfd710d9f7c2a6e6f747afe55883e91c3cad7ec6caac0d6bbb1c19a", 0x281ff0, 0x40, 114),
        (0x8132, "iBoot.j624.bin", "3b2b06b02e3f48b00ed884ff5f71873b0f088c470ec244d4c8cfde1b22630363", 0x281ff0, 0x40, 114),
        (0x8132, "iBoot.j713.bin", "7b2479b7a144672edd4415894a6258455d2c52e50ee0c09f2a182fe5a90c388e", 0x28dfe8, 0x40, 117),
        (0x8132, "iBoot.j715.bin", "f77bd464cc90dce5a82b8a932e67699385fdcf6b0572877be0f976ccc13229da", 0x28dfe8, 0x40, 117),
        (0x8132, "iBoot.j773g.bin", "bd73a522761d8317ce925abc31c32e2704aac787b83f5e26b6ed60653b806112", 0x281ff0, 0x40, 114),
        (0x6040, "iBoot.j614s.bin", "5d33fed4267cac43a155a3b6ec86b7c28b197b885a185d3ce1a51fbd796b76b3", 0x2cb360, 0x40, 138),
        (0x6040, "iBoot.j616s.bin", "baf62bb56545a91f5efddc5104b4625d07660cd5ad5354cdc17c7e582d550973", 0x2cb360, 0x40, 138),
        (0x6040, "iBoot.j773s.bin", "0791e19b660687f979e3e410f23896f204656a62e57d8859b559bde19c81a703", 0x2bf298, 0x40, 134),
        (0x6041, "iBoot.j575c.bin", "5e467551dfc5737a06a8716a4572e5c4d705f5ed0a94bcc697f30180a1bb95ef", 0x2ff4b0, 0x40, 134),
        (0x6041, "iBoot.j614c.bin", "538c53c4b68b5300b2aa0bbffa0c0534717e9e355fb832820b2eac4e27d1ff40", 0x30b590, 0x40, 138),
        (0x6041, "iBoot.j616c.bin", "6cf669f4d6e8357af41e7ea1c8f5e1a32b411241f251bf7963b3e413b61e19ee", 0x30b590, 0x40, 138),
        (0x8140, "iBoot.j700.bin", "786f3ad285e69c2a1b01d73357ed9962743791872913755dda11440881b1c72e", 0x2e3dd8, 0x40, 144),
        (0x8142, "iBoot.j704.bin", "d81b58f9c9ba30c1d30fc166c6ad77a21935e3498f8bf33c9e99dea0b3403752", 0x295d60, 0x40, 161),
        (0x8142, "iBoot.j813.bin", "db365eda2041e05d16fb741210166cdff34066e3f776d6de7143f29e73753ea4", 0x291d58, 0x40, 161),
        (0x8142, "iBoot.j815.bin", "8dca10917a4717b522140350e066f507d1a8ef80f0a82fee8f0a8bcac7ec1177", 0x291d58, 0x40, 161),
        (0x6050, "iBoot.j714c.bin", "4a9a98b80802adfe6d7d36ed299226bbfc2c4a62c61e9c9a4cd90254b6a93692", 0x3abb08, 0x40, 255),
        (0x6050, "iBoot.j714s.bin", "2f0b8037ad7163923a72214e4652baa5c0d8df65aa225cac69400393cee44b07", 0x37bb20, 0x40, 255),
        (0x6050, "iBoot.j716c.bin", "9348d4ec5a47136a37500eaa6c63ce327bdbfdeb1ade746040a14b5a1d177f3f", 0x3abb08, 0x40, 255),
        (0x6050, "iBoot.j716s.bin", "b05bbd8626eb10838413ca0a83ff1c43743344f7eb5f338671e8a680a74ea5bb", 0x37bb20, 0x40, 255),
        (0x6050, "iBoot.j775c.bin", "8b18306d647afaf6953ce3e983c9a94db4318ddb000b9e74dba603e07ec45e6e", 0x39ba10, 0x40, 252),
        (0x6050, "iBoot.j775d.bin", "3ad884aba9cd9e73d75ef2a08ad5ef7a493bb40b3b2b61a10580217245483f3d", 0x3ebb38, 0x40, 252),
        (0x6050, "iBoot.j873s.bin", "d1e51ce36c03f261039fbdcfd6b77a81447ac5719044922a5478ec1580782b35", 0x36fa10, 0x40, 252),
        (0x8152, "iBoot.j873g.bin", "b41c9f04a5c458f013316c082703a426ad483f6d2cfb08acba295ab13f6f92c4", 0x3794e8, 0x40, 203),
    ];

#[test]
#[ignore = "oracle: STELA_TEST_IBOOT_DIR"]
fn every_table_matches_every_original_iboot_of_its_chips() {
    let directory = std::path::PathBuf::from(std::env::var_os("STELA_TEST_IBOOT_DIR").unwrap());
    for (chip_id, file, sha256, offset, stride, count) in ORIGINAL_TABLES {
        let input = std::fs::read(directory.join(file)).unwrap();
        assert_eq!(stela_formats::sha256(&input), sha256, "{file}");
        let (mut fixed, mut special) = (Vec::new(), Vec::new());
        for record in input[offset..offset + count * stride].chunks_exact(stride) {
            let word = |at: usize| u64::from_le_bytes(record[at..at + 8].try_into().unwrap());
            let (base, bytes, attributes) = (word(0), word(16), word(24));
            if base != u64::MAX || bytes == 0 || bytes == u64::MAX {
                continue;
            }
            if attributes >> 16 == 0x8000_0009 {
                fixed.push(carveout(attributes as u16, bytes));
            } else {
                special.push(attributes as u16);
            }
        }
        let family = family(chip_id).unwrap();
        assert_eq!(family.fixed, fixed, "{file}");
        assert_eq!(family.special, special, "{file}");
    }
}

fn tree_with(nodes: &[&str]) -> Result<DeviceTree> {
    let mut tree = DeviceTree {
        root: crate::apple_device_tree::Node::named("device-tree")?,
    };
    for node in nodes {
        tree.ensure_child("/", node)?;
    }
    Ok(tree)
}

#[test]
fn the_panic_region_is_pram_reg_region_98_and_the_panic_log_size() -> Result<()> {
    let mut tree = tree_with(&["chosen", "pram"])?;
    tree.set_property(PRAM, "reg", vec![0; 16])?;
    let placed = reserve(&for_chip(0x8112), 0x8_0000_0000, 1 << 30)
        .unwrap()
        .into_regions();
    publish(&mut tree, &placed)?;
    let panic = placed.last().unwrap();
    assert_eq!(panic.id, 98);
    let reg = range(panic.base, 0x18_8000);
    assert_eq!(tree.property(PRAM, "reg").unwrap().value, reg);
    assert_eq!(
        tree.property(MEMORY_MAP, "region-id-98").unwrap().value,
        reg
    );
    assert_eq!(
        tree.property("/chosen", PANIC_LOG_SIZE).unwrap().as_u32(),
        Some(0x18_8000)
    );
    assert!(!gaps(&tree, Some(0x8112)).iter().any(|g| g.contains(PRAM)));

    // As iBoot, a template without /pram gets no node, only the size.
    let mut bare = tree_with(&["chosen"])?;
    publish(&mut bare, &placed)?;
    assert!(bare.node(PRAM).is_none());
    assert!(bare.property("/chosen", PANIC_LOG_SIZE).is_some());
    assert!(
        gaps(&bare, Some(0x8112))
            .iter()
            .any(|g| g.contains("no /pram node"))
    );
    let unknown = gaps(&bare, Some(0x8101));
    assert!(unknown.iter().any(|g| g.contains("no hand-off facts")));
    Ok(())
}
