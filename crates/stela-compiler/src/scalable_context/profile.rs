//! Scalable profiles: the guest vector length, mode, features and controls a leaf is specialized for.

use super::{DECLARED_PROFILE_ID, PROFILE_ID};
use crate::{
    CompileError, GuestAddress,
    aarch64::scalable::{
        ScalableMode, VectorLength,
        features::{FeatureRequirement, ScalableFeature, ScalableFeatures},
        profile::ScalableControls,
    },
    context::{ExecutionContext, ScalableStateView},
};

/// Guest features and controls are immutable specialization identity.
/// Host capability selection remains a separate TargetCpu value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScalableProfile {
    length: VectorLength,
    mode: ScalableMode,
    kind: ScalableProfileKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum ScalableProfileKind {
    V1,
    V2 {
        features: ScalableFeatures,
        controls: ScalableControls,
    },
}

impl ScalableProfile {
    /// The fixed SME2 profile, keeping its artifact identity.
    pub const fn new(length: VectorLength, mode: ScalableMode) -> Self {
        Self {
            length,
            mode,
            kind: ScalableProfileKind::V1,
        }
    }

    /// Declare guest features and controls explicitly; no hardware is inferred
    /// and no feature dependency is added. Version 2 requires PSTATE.DIT clear,
    /// which the caller validates.
    pub fn new_with_features(
        length: VectorLength,
        mode: ScalableMode,
        features: ScalableFeatures,
        controls: ScalableControls,
    ) -> Result<Self, CompileError> {
        if !features.contains(ScalableFeature::Sme) {
            return Err(CompileError::new(
                crate::CompileErrorKind::ScalableRequiresSme,
            ));
        }
        if features.contains(ScalableFeature::Sme2p1) && !features.contains(ScalableFeature::Sme2) {
            return Err(CompileError::new(
                crate::CompileErrorKind::Sme2p1RequiresSme2,
            ));
        }
        if controls.fpmr_enabled() && !features.contains(ScalableFeature::Fpmr) {
            return Err(CompileError::new(
                crate::CompileErrorKind::FpmrRequiresFeature,
            ));
        }
        if controls.zt0_enabled() && !features.contains(ScalableFeature::Sme2) {
            return Err(CompileError::new(crate::CompileErrorKind::Zt0RequiresSme2));
        }
        if length > controls.max_vector_length() {
            return Err(CompileError::new(
                crate::CompileErrorKind::VectorLengthExceedsMaximum,
            ));
        }
        Ok(Self {
            length,
            mode,
            kind: ScalableProfileKind::V2 { features, controls },
        })
    }

    pub const fn id(self) -> &'static str {
        match self.kind {
            ScalableProfileKind::V1 => PROFILE_ID,
            ScalableProfileKind::V2 { .. } => DECLARED_PROFILE_ID,
        }
    }

    pub const fn vector_length(self) -> VectorLength {
        self.length
    }

    pub const fn mode(self) -> ScalableMode {
        self.mode
    }

    pub const fn features(self) -> ScalableFeatures {
        match self.kind {
            ScalableProfileKind::V1 => {
                ScalableFeatures::of(ScalableFeature::Sme).with(ScalableFeature::Sme2)
            }
            ScalableProfileKind::V2 { features, .. } => features,
        }
    }

    /// Decline unavailable guest instructions before emission or execution.
    pub fn require_features(
        self,
        requirement: FeatureRequirement,
        pc: GuestAddress,
    ) -> Result<(), CompileError> {
        let available = self.features();
        if requirement.is_satisfied_by(available) {
            return Ok(());
        }
        Err(
            CompileError::new(crate::CompileErrorKind::GuestFeaturesUnavailable {
                available,
                required: requirement,
            })
            .at(pc),
        )
    }

    /// Only version 2 manifests list declared features; version 1 artifacts
    /// keep their fixed profile ID.
    pub const fn declared_features(self) -> Option<ScalableFeatures> {
        match self.kind {
            ScalableProfileKind::V1 => None,
            ScalableProfileKind::V2 { features, .. } => Some(features),
        }
    }

    pub const fn controls(self) -> ScalableControls {
        match self.kind {
            ScalableProfileKind::V1 => ScalableControls::new(self.length, false),
            ScalableProfileKind::V2 { controls, .. } => controls,
        }
    }

    /// V2 mappings require DIT=0. DIT is not stored in the borrowed context;
    /// the execution caller validates this requirement before entering native code.
    pub const fn required_dit(self) -> Option<bool> {
        match self.kind {
            ScalableProfileKind::V1 => None,
            ScalableProfileKind::V2 { .. } => Some(false),
        }
    }

    /// Validate borrowed metadata before native entry. Ownership, bounds and
    /// guest-RAM separation remain requirements of the unsafe execution caller.
    /// This view does not contain DIT; the caller must also check required_dit().
    pub fn validate_view(
        self,
        context: &ExecutionContext,
        view: &ScalableStateView,
    ) -> Result<(), CompileError> {
        let valid = context.has_supported_header()
            && core::ptr::eq(context.scalable.cast_const(), view)
            && usize::from(view.svl_bytes) == self.length.bytes()
            && view.reserved == [0; 6]
            && view.svcr == self.mode.svcr()
            && (!self.mode.streaming()
                || ((!view.z_upper.is_null() || self.length.chunks() == 1)
                    && !view.predicates.is_null()
                    && !view.ffr.is_null()))
            && (!self.mode.za_enabled()
                || (!view.za.is_null()
                    && match self.kind {
                        ScalableProfileKind::V1 => !view.zt0.is_null(),
                        ScalableProfileKind::V2 { controls, .. } => {
                            !controls.zt0_enabled() || !view.zt0.is_null()
                        }
                    }));
        if valid {
            Ok(())
        } else {
            Err(CompileError::new(
                crate::CompileErrorKind::ExecutionContextMismatch,
            ))
        }
    }
}
