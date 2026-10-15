//! Immutable architectural controls for scalable compilation specializations.

use super::VectorLength;

/// Declared controls, distinct from feature availability and current SVCR.
/// Profile construction validates the current length and required features.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScalableControls {
    max_vector_length: VectorLength,
    zt0_enabled: bool,
    fpmr_enabled: bool,
}

impl ScalableControls {
    pub const fn new(max_vector_length: VectorLength, zt0_enabled: bool) -> Self {
        Self {
            max_vector_length,
            zt0_enabled,
            fpmr_enabled: false,
        }
    }

    /// Declare effective indirect FPMR access after all applicable EnFPM
    /// controls have been resolved for the actual guest EL/host configuration.
    /// FPMR readback and FEAT_FP8 availability do not grant this permission.
    pub const fn with_fpmr_enabled(mut self, enabled: bool) -> Self {
        self.fpmr_enabled = enabled;
        self
    }

    pub const fn fpmr_enabled(self) -> bool {
        self.fpmr_enabled
    }

    pub const fn max_vector_length(self) -> VectorLength {
        self.max_vector_length
    }

    pub const fn zt0_enabled(self) -> bool {
        self.zt0_enabled
    }
}
