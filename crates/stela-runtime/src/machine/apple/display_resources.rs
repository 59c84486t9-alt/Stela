//! A display's broad physical windows retain their actual nested devices.
use super::*;

impl AppleDevices {
    /// Mount all original physical display views in one transaction, leaving
    /// the selected coprocessor and explicitly supplied complete DART groups
    /// at their existing routes. No display register gains fabricated meaning.
    pub fn add_display_with_darts(
        &mut self,
        regions: &[(&'static str, Range)],
        role: &'static str,
        darts: &[DartId],
    ) -> Result<(), String> {
        let mut controllers = self.coprocessors.iter().filter(|(name, _)| *name == role);
        let &(_, asc) = controllers
            .next()
            .ok_or("display has no mounted coprocessor")?;
        if controllers.next().is_some() {
            return Err("display coprocessor role is ambiguous".into());
        }
        let master = self
            .dcp_masters
            .iter()
            .find(|master| master.asc == asc)
            .ok_or("display coprocessor has no actual DMA owner")?;
        if !darts.iter().any(|id| id.0 == master.dart)
            || master
                .surface
                .is_some_and(|(owner, _)| !darts.iter().any(|id| id.0 == owner))
        {
            return Err("display container omits a selected DART owner".into());
        }
        let mut children = vec![asc];
        for dart in darts {
            if self.bus.device::<Dart>(dart.0).is_none() {
                return Err("display container child is not an actual DART".into());
            }
            if !children.contains(&dart.0) {
                children.push(dart.0);
            }
        }
        let views = regions
            .iter()
            .map(|&(name, range)| (name, range.physical, range.bytes))
            .collect();
        let model = display_hw::Region::physical(views).map_err(String::from)?;
        let spans = regions
            .iter()
            .map(|(_, range)| (range.physical, range.bytes))
            .collect::<Vec<_>>();
        let bindings = self.bus.container_bindings(&spans, &children).map_err(|error| {
            let owner = match error {
                MapError::Overlap { existing } => self.bus.device_name(existing).unwrap_or("unknown"),
                _ => "none",
            };
            format!("display container placement: {error:?}; existing owner={owner}; requested={spans:#x?}")
        })?;
        if !bindings.is_empty() {
            self.bus
                .install(Box::new(model), &bindings)
                .map_err(|error| format!("display container publication: {error:?}"))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const PRIMARY: u64 = 0x2_8800_0000;
    const WRAPPER: u64 = 0x2_89c0_0000;
    const TRAD: u64 = 0x2_8930_4000;
    const UMMS: u64 = 0x2_8930_0000;
    const FIRMWARE: u64 = 0x2_8930_c000;
    const SHARED: u64 = 0x2_8e3d_0000;

    struct Screen;
    impl Scanout for Screen {
        fn mode(&self) -> ScanoutMode {
            ScanoutMode {
                width: 1,
                height: 1,
                format: ScanoutFormat::Bgra8888,
            }
        }
        fn present(&mut self, _: &[u8]) -> Result<(), &'static str> {
            panic!("aperture mounting must not present a frame")
        }
    }

    fn placement() -> (AppleDevices, Vec<DartId>, Vec<(&'static str, Range)>) {
        let mut devices = AppleDevices::new();
        let mut owners = Vec::new();
        for physical in [TRAD, FIRMWARE] {
            owners.push(
                devices
                    .add_dart_group_for_profile(
                        dart::Profile::T6000,
                        &[Range {
                            physical,
                            bytes: 0x4000,
                        }],
                        16,
                        None,
                        None,
                    )
                    .unwrap()[0],
            );
        }
        devices
            .add_dart_smmu(
                owners[0],
                Range {
                    physical: UMMS,
                    bytes: 0x4000,
                },
            )
            .unwrap();
        devices
            .add_dcpext(
                Range {
                    physical: WRAPPER,
                    bytes: 0x6c000,
                },
                [873; 4],
                false,
                "DCPEXT0",
                dcp::ExternalIdentity::Numbered(0),
                Box::new(Screen),
                (owners[1], 5),
                None,
                Some((owners[0], 0)),
            )
            .unwrap();
        let views = [
            (PRIMARY, 0x3000000),
            (0x2_8932_0000, 0x4000),
            (0x2_8934_4000, 0x4000),
            (0x2_8980_0000, 0x800000),
            (SHARED, 0x4000),
        ]
        .into_iter()
        .map(|(physical, bytes)| ("dispext0", Range { physical, bytes }))
        .collect();
        (devices, owners, views)
    }

    #[test]
    fn complete_display_views_preserve_trad_umms_mailbox_and_shared_bank_ownership() {
        let (mut devices, owners, views) = placement();
        let addresses = [
            TRAD,
            TRAD + 0x100,
            UMMS,
            UMMS + 0x100,
            FIRMWARE,
            WRAPPER + 0x8114,
        ];
        let before = addresses.map(|pa| devices.bus.route(pa, Width::Word).unwrap());
        devices
            .add_display_with_darts(&views, "DCPEXT0", &owners)
            .unwrap();
        assert_eq!(
            addresses.map(|pa| devices.bus.route(pa, Width::Word).unwrap()),
            before
        );
        for pa in [
            PRIMARY,
            PRIMARY + 0x2ff_fffc,
            0x2_8932_0000,
            0x2_8934_4000,
            0x2_8980_0000,
            SHARED + 0x3ffc,
        ] {
            let error = devices.read(0, pa, 4, 0).unwrap_err();
            assert!(format!("{error:?}").contains("dispext0"));
        }
        assert!(devices.bus.route(SHARED + 0x4000, Width::Word).is_err());
        assert!(devices.bus.route(PRIMARY + 0x3000000, Width::Word).is_err());
    }

    #[test]
    fn invalid_or_unrelated_owners_refuse_before_any_display_route_is_published() {
        let (mut devices, owners, views) = placement();
        assert!(
            devices
                .add_display_with_darts(&views, "DCPEXT0", &owners[..1])
                .is_err()
        );
        assert!(
            devices
                .add_display_with_darts(&views, "SMC", &owners)
                .is_err()
        );
        let mut invalid = views.clone();
        invalid.push((
            "dispext0",
            Range {
                physical: u64::MAX,
                bytes: 4,
            },
        ));
        assert!(
            devices
                .add_display_with_darts(&invalid, "DCPEXT0", &owners)
                .is_err()
        );
        assert!(devices.bus.route(PRIMARY, Width::Word).is_err());
        devices
            .add_watchdog(
                &[Range {
                    physical: PRIMARY + 0x100000,
                    bytes: 0x4000,
                }],
                None,
                0,
            )
            .unwrap();
        let old = devices.bus.route(PRIMARY + 0x100000, Width::Word).unwrap();
        let owner_name = devices.bus.device_name(old.0).unwrap();
        let error = devices
            .add_display_with_darts(&views, "DCPEXT0", &owners)
            .unwrap_err();
        assert!(error.contains(owner_name));
        assert_eq!(devices.bus.route(PRIMARY + 0x100000, Width::Word), Ok(old));
        assert!(devices.bus.route(PRIMARY, Width::Word).is_err());
        assert!(devices.bus.route(SHARED, Width::Word).is_err());
    }
}
