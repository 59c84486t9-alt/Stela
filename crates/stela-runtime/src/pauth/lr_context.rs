//! QARMA5 key service for FEAT_PAuth_LR.
use super::{
    AuthResult, AuthenticationError, Context, Key, TwoModifierError,
    features::LinkRegisterPauthCapability,
};
use crate::system::identification_snapshot::Snapshot;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InstructionKey {
    A,
    B,
}
impl InstructionKey {
    const fn key(self) -> Key {
        match self {
            Self::A => Key::Ia,
            Self::B => Key::Ib,
        }
    }
}

/// Selects an architectural authentication operation, never a permission bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthenticationKind {
    Standalone,
    Return,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Error {
    WrongSnapshot,
    WrongAddressSpace,
    WrongVersion,
    Configuration(TwoModifierError),
    Authentication(AuthenticationError),
}

/// One context and its identification snapshot, held together. Not Clone or
/// Copy, with no key or state getters. The executing owner still resolves
/// enables and traps.
pub(crate) struct LinkRegisterContext<'run, 'profile> {
    capability: &'run LinkRegisterPauthCapability<'profile>,
    context: &'run Context,
}

impl<'run, 'profile> LinkRegisterContext<'run, 'profile> {
    pub(crate) fn new(
        snapshot: &Snapshot,
        address_space: u64,
        capability: &'run LinkRegisterPauthCapability<'profile>,
        context: &'run Context,
    ) -> Result<Self, Error> {
        if !snapshot.same_snapshot(capability.snapshot()) {
            return Err(Error::WrongSnapshot);
        }
        if address_space != context.address_space() {
            return Err(Error::WrongAddressSpace);
        }
        if context.version() != capability.version() {
            return Err(Error::WrongVersion);
        }
        Ok(Self {
            capability,
            context,
        })
    }

    pub(crate) fn snapshot(&self) -> &Snapshot {
        self.capability.snapshot()
    }

    pub(crate) fn sign(
        &self,
        key: InstructionKey,
        pointer: u64,
        modifier1: u64,
        modifier2: u64,
    ) -> Result<u64, Error> {
        self.context
            .sign_two_modifiers(key.key(), pointer, modifier1, modifier2)
            .map_err(Error::Configuration)
    }

    /// Single-modifier signing, for the older forms when PACM is zero.
    pub(crate) fn sign_single(
        &self,
        key: InstructionKey,
        pointer: u64,
        modifier: u64,
    ) -> Result<u64, Error> {
        self.context
            .sign(key.key(), pointer, modifier)
            .map_err(|_| Error::Configuration(TwoModifierError::KeyUnavailable { key: key.key() }))
    }

    pub(crate) fn authenticate_single(
        &self,
        key: InstructionKey,
        pointer: u64,
        modifier: u64,
        kind: AuthenticationKind,
    ) -> Result<AuthResult, Error> {
        self.context
            .authenticate_operation(
                key.key(),
                pointer,
                modifier,
                matches!(kind, AuthenticationKind::Return),
            )
            .map_err(Error::Authentication)
    }

    pub(crate) fn authenticate(
        &self,
        key: InstructionKey,
        pointer: u64,
        modifier1: u64,
        modifier2: u64,
        kind: AuthenticationKind,
    ) -> Result<AuthResult, Error> {
        self.context
            .authenticate_two_modifiers(
                key.key(),
                pointer,
                modifier1,
                modifier2,
                matches!(kind, AuthenticationKind::Return),
            )
            .map_err(Error::Configuration)?
            .map_err(Error::Authentication)
    }
}

#[cfg(test)]
mod tests;
