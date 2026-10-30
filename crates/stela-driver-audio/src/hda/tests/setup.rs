// SPDX-License-Identifier: GPL-2.0-only
//! Bind-time codec setup selection.
use super::*;

#[test]
fn cirrus_identity_selects_its_vendor_setup() {
    let mut fixture = Fixture::new();
    let model = cirrus::cs4208_device(false, false);
    let mut controller = create(&model, &mut fixture, config()).unwrap();
    let graph = controller.enumerate_codec(0).unwrap();
    let Ok(CodecSetup::Cirrus(report)) = controller.initialize_codec(&graph) else {
        panic!("CS4208 did not select the Cirrus setup");
    };
    assert_eq!(report.profile, CirrusProfile::Cs4208);
}

#[test]
fn unlisted_codec_keeps_its_standard_widgets() {
    let mut fixture = Fixture::new();
    let model = analog_model();
    let mut controller = create(&model, &mut fixture, config()).unwrap();
    let graph = controller.enumerate_codec(0).unwrap();
    let commands = model.borrow().commands.len();
    assert_eq!(
        controller.initialize_codec(&graph),
        Ok(CodecSetup::Standard)
    );
    assert_eq!(model.borrow().commands.len(), commands);
}
