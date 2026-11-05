use super::*;
use crate::linux_capture::Scope;

// Real policy identities, with deliberately sparse model ordinals owned here.
// These values never become a production image's global ordering decision.
fn selected() -> Vec<UnitSpec> {
    let mut group = "";
    let mut group_ordinal = 500;
    identities()
        .enumerate()
        .map(|(index, identity)| {
            if identity.group != group {
                group = identity.group;
                group_ordinal += 1;
            }
            UnitSpec {
                scope: Scope {
                    slice: identity.slice,
                    group: identity.group,
                    group_ordinal,
                    unit_ordinal: identity.unit_ordinal,
                    global_ordinal: 1000 + u32::try_from(index).unwrap() * 2,
                },
                source: identity.source,
                module: identity.module,
                file: identity.file,
            }
        })
        .collect()
}

#[test]
fn complete_radio_selection_keeps_the_callers_sparse_global_ordinals() {
    let selected = selected();
    assert_eq!(selected.len(), 291);
    assert_eq!(slice_names().len(), 23);
    assert!(validate_selection(&selected).is_ok());
    assert_eq!(selected.last().unwrap().scope.global_ordinal, 1580);
}

#[test]
fn missing_original_unit_cannot_be_treated_as_a_complete_class() {
    let mut selected = selected();
    selected.pop();
    assert!(matches!(
        validate_selection(&selected),
        Err(ImportError::Schema(
            "complete exact294 radio cohort required"
        ))
    ));
}

#[test]
fn another_class_source_cannot_enter_through_a_valid_scope() {
    let mut selected = selected();
    selected[0].source = "drivers/gpu/drm/drm_drv";
    assert!(matches!(
        validate_selection(&selected),
        Err(ImportError::Identity {
            index: 0,
            field: "source-owned radio selection"
        })
    ));
}

#[test]
fn missing_slice_digests_refuse_before_any_producer_files_are_opened() {
    let selected = selected();
    let unopened = Path::new("this-producer-must-not-be-opened");
    assert!(matches!(
        read(
            Layout {
                directory: unopened,
                linux: unopened,
                compat: unopened,
                output: unopened,
                input_roots: &[]
            },
            &selected,
            &[]
        ),
        Err(ImportError::Schema(
            "exact radio slice digest count required"
        ))
    ));
}
