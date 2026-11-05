//! Read-only topology observations under the standalone ECAM assignment.
use super::*;
use stela_drivers::bus::pci::{
    Function, FunctionError, Identity, InventoryError, InventoryReleaseFailure,
    owned::ObservedConfig,
};

impl Source {
    /// Observe bridge and ARI topology without issuing a configuration writer.
    /// The bus owner keeps every mapping until acknowledged retirement.
    pub(crate) fn inventory(&self, window: &EcamWindow) -> Result<Vec<Identity>, Error> {
        Function::inventory_with(
            window,
            |address| {
                let (window, mapping) = self.config_mapping(address, Protection::ReadOnly)?;
                // SAFETY: the standalone source checked this bus and issued
                // the exact lease. It keeps the exclusive post-EBS bus owner.
                let config = match unsafe { ObservedConfig::attach(address, window, mapping) } {
                    Ok(config) => config,
                    Err((error, mut mapping)) => {
                        // SAFETY: no observation or view escaped the refused attach.
                        unsafe { mapping.retire() }.map_err(Error::Mapping)?;
                        return Err(Error::Config(error));
                    }
                };
                match Function::new(address, config) {
                    Ok(function) => Ok(Some(function)),
                    Err(mut refused) => {
                        refused.config.retire().map_err(Error::Mapping)?;
                        match refused.reason {
                            FunctionError::Absent => Ok(None),
                            FunctionError::ConfigurationRetry => Err(Error::NotReady(address)),
                            FunctionError::Access(error) => Err(Error::Config(error)),
                        }
                    }
                }
            },
            |mut function| {
                function
                    .config()
                    .retire()
                    .map_err(|error| InventoryReleaseFailure {
                        error: Error::Mapping(error),
                        function,
                    })
            },
        )
        .map_err(|failure| match failure.error {
            InventoryError::Open(error) | InventoryError::Release(error) => error,
            InventoryError::Configuration(error) => Error::Discovery(error),
        })
    }
}
