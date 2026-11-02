//! Ordered cross-field rules over the complete record; no parsing or mutation.
use super::*;

pub(super) fn system(options: &System) -> Result<(), Error> {
    restore(options)?;
    wifi(options)?;
    ipv4(options)?;
    install(options)?;
    boot_selection(options)?;
    dram(options)?;
    clock(options)?;
    Ok(())
}

fn restore(options: &System) -> Result<(), Error> {
    let restore_inputs = options.restore_source.is_some()
        || options.restore_manifest
        || options.restore_identity.is_some();
    if options.restore
        && (!options.bundle
            || options.preboot.is_some()
            || options.storage.is_none()
            || options.restore_source.is_none()
            || !options.restore_manifest
            || options.restore_identity.is_none()
            || options.survey)
    {
        return Err(Error::Constraint(Constraint::RestoreConfiguration));
    }
    if !options.restore && restore_inputs {
        return Err(Error::Constraint(Constraint::UnexpectedRestoreInputs));
    }
    Ok(())
}

fn wifi(options: &System) -> Result<(), Error> {
    if options.ssid.is_none() && (options.wifi_key.is_some() || options.wifi_country.is_some()) {
        return Err(Error::Constraint(Constraint::WifiDependency));
    }
    Ok(())
}

fn ipv4(options: &System) -> Result<(), Error> {
    if let Some(gateway) = options.ipv4_gateway
        && !options.ipv4.is_some_and(|ipv4| ipv4.neighbors(gateway))
    {
        return Err(Error::Constraint(Constraint::Ipv4Gateway));
    }
    Ok(())
}

fn install(options: &System) -> Result<(), Error> {
    if options.install_source.is_some() && options.install.is_none() {
        return Err(Error::Constraint(Constraint::InstallSourceDependency));
    }
    if options.install.is_some()
        && (!options.bundle
            || options.preboot.is_some()
            || options.storage.is_none()
            || options.nor.is_none()
            || options.restore
            || options.survey)
    {
        return Err(Error::Constraint(Constraint::InstallConfiguration));
    }
    if options.update_restore && options.install.is_none() {
        return Err(Error::Constraint(Constraint::UpdateDependency));
    }
    if options.development_restore && (options.install.is_none() || options.update_restore) {
        return Err(Error::Constraint(Constraint::DevelopmentRestore));
    }
    if options.verify_on_read && options.install.is_none() && !options.restore {
        return Err(Error::Constraint(Constraint::VerifyDependency));
    }
    if options.install.is_some() && !options.tss {
        return Err(Error::Constraint(Constraint::InstallTicket));
    }
    Ok(())
}

fn boot_selection(options: &System) -> Result<(), Error> {
    if options.preboot.is_none()
        && (options.boot_volume.is_some()
            || options.boot_command.is_some()
            || options.safe_boot
            || options.maintenance_write
            || options.upgrade
            || options.recovery.is_some())
    {
        return Err(Error::Constraint(Constraint::PrebootSelection));
    }
    if options.upgrade && (options.recovery.is_some() || options.safe_boot) {
        return Err(Error::Constraint(Constraint::UpgradeSelection));
    }
    if options.recovery.is_some() && options.safe_boot {
        return Err(Error::Constraint(Constraint::RecoverySafeMode));
    }
    Ok(())
}

fn dram(options: &System) -> Result<(), Error> {
    if !options.dram_base.is_multiple_of(LARGE) {
        return Err(Error::Constraint(Constraint::DramAlignment));
    }
    Ok(())
}

fn clock(options: &System) -> Result<(), Error> {
    if options.native_clock_check {
        if options.native_cores != Some(1) {
            return Err(Error::Constraint(Constraint::ClockCoreCount));
        }
        if options.native_mmio_check
            || options.native_memory_check
            || options.native_bootstrap_check
            || options.native_shared_check
            || options.native_rounds
            || options.audio_check.is_some()
            || options.network_check.is_some()
            || options.storage.is_some()
            || options.storage_ram.is_some()
            || options.preboot.is_some()
            || options.nor.is_some()
            || options.input
            || options.guest_network
            || options.ssid.is_some()
            || options.external_disks
            || !options.usb_storage.is_empty()
            || options.tss
            || options.install.is_some()
            || options.restore
        {
            return Err(Error::Constraint(Constraint::ClockExclusive));
        }
    }
    Ok(())
}
