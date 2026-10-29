// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2017 Intel Corporation
// Copyright (c) 2026 Stela contributors
//! Serialized firmware notification quiescence and fresh resume discovery.

use super::super::{Command, Controller, Error, Phase, Timer, Transport, Version, wire::NOTIFY};

impl<T: Transport, C: Timer> Controller<T, C> {
    /// Disable PPM notifications and wait for command acknowledgement
    /// before the platform stops EC/AML services. This must run in serialized
    /// process context, after callers stop submitting connector work.
    /// Snapshots are invalidated even on failure; failure keeps the fault and
    /// requires recovery while firmware services and mapping are still owned.
    pub fn suspend(&mut self) -> Result<(), Error> {
        let result = self
            .execute(Command::global(NOTIFY), &mut [], &[])
            .map(|_| ());
        self.initialized = false;
        self.capability = None;
        self.connectors.clear();
        self.ready = false;
        result
    }

    /// Re-read capabilities and every connector from firmware after a
    /// reset; no pre-suspend role/connection snapshot is republished as current.
    pub fn resume(&mut self) -> Result<(), Error> {
        super::super::validate_timer(&self.timer)?;
        self.ready = false;
        self.initialized = false;
        self.capability = None;
        self.connectors.clear();
        self.last_completion = None;
        // Firmware may have restarted while suspended. Refresh transport layout
        // and reject an unknown revision before publishing another command.
        let read = self.transport.read_version();
        let raw = self.io(Phase::Version, read)?;
        self.version = Version::new(raw).map_err(|error| self.poison(error))?;
        self.initialize()
    }
}
