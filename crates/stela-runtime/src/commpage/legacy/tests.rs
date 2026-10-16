use super::*;

#[test]
fn opaque_configuration_requires_admission_and_preserves_old_profile_ids() -> Result<()> {
    let old = Configuration::default();
    assert_eq!(
        serde_json::to_value(old)?,
        serde_json::json!({"kdebug": null})
    );
    assert_eq!(
        serde_json::to_value(Configuration {
            kdebug: Some(KdebugState::Disabled),
            ..old
        })?,
        serde_json::json!({"kdebug": "disabled"})
    );
    assert_eq!(old.profile_id(), CLOCK_PROFILE_ID);
    assert!(old.require_dyld_flags().is_err());
    assert_eq!(
        Configuration {
            kdebug: Some(KdebugState::Disabled),
            ..old
        }
        .profile_id(),
        CLOCK_DISABLED_KDEBUG_PROFILE_ID
    );
    for value in [0, u64::MAX, 0x800000, 0xfedcba9876543210] {
        let flags = DyldFlags {
            value,
            thread_protection: ThreadProtection::Disabled,
        };
        let configuration = Configuration {
            dyld_flags: Some(flags),
            ..old
        };
        assert_eq!(configuration.require_dyld_flags()?, flags);
        let serialized = serde_json::to_vec(&configuration)?;
        let roundtrip: serde_json::Value = serde_json::from_slice(&serialized)?;
        assert_eq!(
            roundtrip,
            serde_json::json!({
                "kdebug": null,
                "dyld_flags": {"value": value, "thread_protection": "disabled"}
            })
        );
        assert_eq!(configuration.profile_id(), CLOCK_DYLD_FLAGS_PROFILE_ID);
        assert_eq!(
            Configuration {
                kdebug: Some(KdebugState::Disabled),
                ..configuration
            }
            .profile_id(),
            CLOCK_DISABLED_KDEBUG_DYLD_FLAGS_PROFILE_ID
        );
    }
    Ok(())
}

#[test]
fn explicit_static_field_survives_clock_publication_and_owner_collisions() -> Result<()> {
    let _guard = crate::clock::TEST_CONTEXT_LOCK.lock().unwrap();
    let configuration = Configuration {
        kdebug: Some(KdebugState::Disabled),
        dyld_flags: Some(DyldFlags {
            value: 0xfedcba9876543210,
            thread_protection: ThreadProtection::Disabled,
        }),
    };
    let mut page = Page::map(&[0xa5; CLOCK_FIELD_BYTES], configuration)?;
    assert_eq!(page.configuration(), configuration);
    assert_ne!(
        configuration.profile_id(),
        Configuration::default().profile_id()
    );
    assert!(Page::map(&[0; CLOCK_FIELD_BYTES], Configuration::default()).is_err());
    assert!(page.region().readable && !page.region().writable && !page.region().executable);
    let before = page.read_snapshot(0, GUEST_BYTES)?;
    page.publish_clock(&[0x5a; CLOCK_FIELD_BYTES])?;
    let after = page.read_snapshot(0, GUEST_BYTES)?;
    assert_eq!(
        &after[CLOCK_FIELD_START..CLOCK_FIELD_END],
        &[0x5a; CLOCK_FIELD_BYTES]
    );
    assert_eq!(
        &after[KDEBUG_ENABLE..KDEBUG_ENABLE + size_of::<u32>()],
        &KDEBUG_DISABLED.to_le_bytes()
    );
    assert_eq!(
        &after[DYLD_FLAGS..DYLD_FLAGS + size_of::<u64>()],
        &configuration.require_dyld_flags()?.value.to_le_bytes()
    );
    assert_eq!(&after[..CLOCK_FIELD_START], &before[..CLOCK_FIELD_START]);
    assert_eq!(&after[CLOCK_FIELD_END..], &before[CLOCK_FIELD_END..]);
    assert!(page.read_snapshot(GUEST_BYTES, 1).is_err());
    drop(page);
    let clock_only = Page::map(&[0; CLOCK_FIELD_BYTES], Configuration::default())?;
    assert_eq!(clock_only.configuration().kdebug, None);
    assert!(clock_only.configuration().require_dyld_flags().is_err());
    Ok(())
}
