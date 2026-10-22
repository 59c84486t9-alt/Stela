use super::*;

fn extract(id: u8, body: &[u8]) -> u8 {
    let mut bytes = vec![159, 1, 0x21, id, body.len() as u8];
    bytes.extend_from_slice(body);
    addba_extension(&bytes, true)
}

#[test]
fn generic_errors_suppress_all_extension_data_without_strict_policy_substitutes() {
    for tail in [
        vec![3, 0],
        vec![0, 0, 0, 0],
        vec![196, 0],
        vec![159, 0],
        vec![1],
        vec![222, 2, 0],
    ] {
        let mut bytes = vec![159, 1, 0x21];
        bytes.extend_from_slice(&tail);
        assert_eq!(addba_extension(&bytes, true), 0, "{tail:?}");
    }
    for tail in [
        vec![222, 0, 222, 0],
        vec![255, 0],
        vec![255, 1, 35],
        vec![132, 2, 0, 0],
        vec![150, 4, 1, 2, 3, 4],
        vec![211, 0],
        vec![221, 1, 0],
        vec![195, 0],
        vec![242, 0],
        vec![0, 33].into_iter().chain([0; 33]).collect(),
    ] {
        let mut bytes = vec![159, 1, 0x21];
        bytes.extend_from_slice(&tail);
        assert_eq!(addba_extension(&bytes, true), 0x21, "{tail:?}");
    }
    assert_eq!(addba_extension(&[159, 1, 0x21, 159, 1, 0x41], true), 0x41);
    assert_eq!(addba_extension(&[159, 1, 0x21], false), 0);
}

#[test]
fn each_source_fixed_size_boundary_and_cisco_discriminator_is_preserved() {
    for (id, size, exact) in [
        (3, 1, false),
        (42, 1, false),
        (159, 1, false),
        (199, 1, false),
        (5, 4, false),
        (104, 4, false),
        (45, 26, false),
        (61, 22, false),
        (191, 12, false),
        (56, 5, false),
        (192, 5, false),
        (101, 18, false),
        (113, 7, false),
        (118, 6, false),
        (126, 21, false),
        (37, 3, true),
        (60, 4, true),
        (32, 1, true),
        (62, 1, true),
        (194, 3, false),
    ] {
        // ADDBA159 is repeatable; its body supplies the final data byte.
        let body = vec![0x21; size];
        assert_eq!(extract(id, &body[..size - 1]), 0, "id{id} short");
        assert_eq!(extract(id, &body), 0x21, "id{id} minimum");
        assert_eq!(
            extract(id, &vec![0x21; size + 1]),
            if exact { 0 } else { 0x21 },
            "id{id} long"
        );
    }
    assert_eq!(extract(150, &[1, 2, 3]), 0);
    for length in [4, 5, 6, 7] {
        let mut known = vec![0; length];
        known[..4].copy_from_slice(&[0, 0x40, 0x96, 0]);
        assert_eq!(extract(150, &known), if length == 6 { 0x21 } else { 0 });
        known[0] = 1;
        assert_eq!(extract(150, &known), 0x21);
    }
    assert_eq!(extract(196, &[194, 3, 0, 0, 0]), 0);
}

#[test]
fn exactly_the_source_forty_ids_are_duplicate_restricted() {
    let ids = [
        0, 1, 2, 3, 4, 5, 6, 7, 16, 32, 37, 42, 45, 48, 50, 56, 60, 61, 62, 90, 101, 104, 113, 114,
        117, 118, 126, 127, 130, 131, 132, 191, 192, 194, 211, 213, 214, 217, 232, 244,
    ];
    for id in 0..=255 {
        assert_eq!(unique(id), ids.contains(&id));
    }
    for id in ids {
        let length = match id {
            3 | 32 | 42 | 62 => 1,
            5 | 60 | 104 => 4,
            37 | 194 => 3,
            45 => 26,
            56 | 192 => 5,
            61 => 22,
            101 => 18,
            113 => 7,
            118 => 6,
            126 => 21,
            130 => 37,
            131 => 31,
            132 => 2,
            191 => 12,
            _ => 0,
        };
        let mut body = vec![0; length];
        if id == 130 {
            body[25] = 1;
        }
        assert_eq!(extract(id, &body), 0x21, "id{id} first must be valid");
        let mut bytes = vec![159, 1, 0x21];
        for _ in 0..2 {
            bytes.extend_from_slice(&[id, length as u8]);
            bytes.extend_from_slice(&body);
        }
        assert_eq!(addba_extension(&bytes, true), 0, "id{id} duplicate");
    }
    assert_eq!(
        addba_extension(&[159, 1, 0x21, 199, 1, 0, 199, 1, 0], true),
        0x21
    );
}

#[test]
fn mesh_content_checks_keep_valid_address_extensions_and_zero_destination_perr() {
    for extra in [0, 6] {
        for count in [1, 2] {
            let mut body = vec![0; 26 + extra + 11 * count];
            if extra != 0 {
                body[0] = ADDRESS_EXTENSION;
            }
            body[25 + extra] = count as u8;
            assert_eq!(extract(130, &body), 0x21);
            assert_eq!(extract(130, &body[..body.len() - 1]), 0);
            body.push(0);
            assert_eq!(extract(130, &body), 0);
        }
        let mut body = vec![0; 31 + extra];
        if extra != 0 {
            body[0] = ADDRESS_EXTENSION;
        }
        assert_eq!(extract(131, &body), 0x21);
        assert_eq!(extract(131, &body[..body.len() - 1]), 0);
        body.push(0);
        assert_eq!(extract(131, &body), 0);
    }
    assert_eq!(extract(130, &[0; 26]), 0);
    assert_eq!(extract(132, &[0, 0]), 0x21);
    assert_eq!(extract(132, &[0, 0, 0]), 0);
    let mut mixed = vec![0; 2 + 13 + 19];
    mixed[1] = 2;
    mixed[15] = ADDRESS_EXTENSION;
    assert_eq!(extract(132, &mixed), 0x21);
    for length in 0..mixed.len() {
        assert_eq!(extract(132, &mixed[..length]), 0);
    }
    mixed.push(0);
    assert_eq!(extract(132, &mixed), 0);
}
