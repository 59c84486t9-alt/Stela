//! Cache/PTD quota association and exclusive native callback borrow.
use super::super::Prepared;
use super::*;
use crate::Result;
use stela_contracts::refuse;

impl EmptyResource {
    #[cfg(test)]
    pub(crate) fn service_test_components() -> (Prepared, Self) {
        tests::service_components()
    }
    /// Borrow this exact AP-facing bank for a native quota callback. This is
    /// not a clone of its words, a PMP startup or a service-completion token.
    pub fn quota_view(&mut self) -> QuotaView<'_> {
        QuotaView(self)
    }
    fn bind_quota_publisher(
        &mut self,
        local: crate::platform::apple::ptd::transport::notifications::LocalNotifications,
    ) -> Result<publisher::Binding> {
        if self.quota_claimed {
            return Err(refuse!(
                "actual cache native quota publisher is already admitted"
            ));
        }
        self.quota_claimed = true;
        Ok(publisher::Binding::new(self.quota_identity.clone(), local))
    }
}
impl Prepared {
    /// Bind exactly one native quota publisher to these component
    /// owners. It neither admits startup/IRQs nor completes a source command.
    pub fn bind_quota_publisher(
        &self,
        cache: &mut EmptyResource,
    ) -> Result<crate::platform::apple::pmp::native::cache::publisher::Binding> {
        if !Arc::ptr_eq(&self.ram, cache.registered_ram())
            || cache.binding().0.checked_add(cache.binding().1) != Some(self.descriptor.channels.0)
        {
            return Err(refuse!(
                "native quota publisher requires the same actual cache/DCS/PTD RAM and placement"
            ));
        }
        cache.bind_quota_publisher(self.local.clone())
    }
}
/// An exclusive callback borrow of the cache, including its current
/// lifecycle and shared quota words. The backing cannot be replaced while lent.
pub struct QuotaView<'a>(&'a mut EmptyResource);
impl publisher::Bank for QuotaView<'_> {
    fn identity(&self) -> &publisher::Identity {
        &self.0.quota_identity
    }
    fn validate(&self) -> Result<()> {
        self.0.locks.accessible()
    }
    fn read_quota(&mut self, group: u8) -> Result<u32> {
        if usize::from(group) >= 32 {
            return Err(refuse!("native quota group exceeds the actual bank"));
        }
        let offset = BROADCAST + QUOTAS + u64::from(group) * 4;
        self.0.checked(offset, Width::Word)?;
        self.0.read_cache(offset).map(|word| word as u32)
    }
    fn write_quota(&mut self, group: u8, value: u32, access: &mut Access<'_>) -> Result<()> {
        if usize::from(group) >= 32 {
            return Err(refuse!("native quota group exceeds the actual bank"));
        }
        self.0
            .write(
                BROADCAST + QUOTAS + u64::from(group) * 4,
                Width::Word,
                u64::from(value),
                access,
            )
            .map_err(|_| refuse!("native quota actual shared word programming refused"))
    }
}

#[cfg(test)]
mod tests;
