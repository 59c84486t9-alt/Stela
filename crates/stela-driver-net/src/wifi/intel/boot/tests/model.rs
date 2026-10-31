// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2007-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
//! Serialized CSR/requester state shared by the boot fixtures.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Op {
    Read(u32),
    Write(u32, u32),
    Write8(u32, u8),
    Delay(u32),
}
#[derive(Clone)]
pub(super) struct Owner(pub(super) Arc<AtomicUsize>);
impl Drop for Owner {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}
#[derive(Clone)]
pub(super) struct Model {
    pub(super) state: Arc<Mutex<ModelState>>,
    pub(super) _owner: Owner,
}
pub(super) struct ModelState {
    pub(super) registers: BTreeMap<u32, u32>,
    pub(super) ops: Vec<Op>,
    pub(super) fail: Option<usize>,
    pub(super) fail_read: Option<u32>,
    pub(super) all_ff: bool,
    pub(super) stop_ack: bool,
    pub(super) sentinel: Option<(usize, u32)>,
}
impl Default for ModelState {
    fn default() -> Self {
        Self {
            registers: BTreeMap::from([(0x28, 0x340), (0x9c, 0x10a000), (0x24, 0x08000001)]),
            ops: Vec::new(),
            fail: None,
            fail_read: None,
            all_ff: false,
            stop_ack: true,
            sentinel: None,
        }
    }
}
impl Model {
    fn operation(
        &mut self,
        op: Op,
    ) -> Result<std::sync::MutexGuard<'_, ModelState>, power::AccessError> {
        let mut state = self.state.lock().unwrap();
        let index = state.ops.len();
        state.ops.push(op);
        if state.fail == Some(index) {
            return Err(power::AccessError::Unavailable);
        }
        Ok(state)
    }
}
impl Csr for Model {
    fn read32(&mut self, register: u32) -> Result<u32, power::AccessError> {
        let state = self.operation(Op::Read(register))?;
        if state.fail_read == Some(register) {
            return Err(power::AccessError::Unavailable);
        }
        if state.all_ff {
            return Ok(u32::MAX);
        }
        let value = if let Some((at, value)) = state.sentinel
            && at == state.ops.len() - 1
        {
            value
        } else {
            state.registers.get(&register).copied().unwrap_or(0)
        };
        Ok(
            if register == 0x20 && value & 0x200 != 0 && state.stop_ack {
                value | 0x100
            } else {
                value
            },
        )
    }
    fn write32(&mut self, register: u32, value: u32) -> Result<(), power::AccessError> {
        let mut state = self.operation(Op::Write(register, value))?;
        if register == 8 || register == 16 {
            let prior = state.registers.entry(register).or_default();
            *prior &= !value;
        } else {
            state.registers.insert(register, value);
        }
        Ok(())
    }
    fn delay_us(&mut self, microseconds: u32) -> Result<(), power::AccessError> {
        drop(self.operation(Op::Delay(microseconds))?);
        Ok(())
    }
}
// SAFETY: real owned synchronous CSR/requester model; no alternate accesses
// occur except explicit serialized device events through its shared state.
unsafe impl BootIo for Model {
    fn write8(&mut self, register: u32, value: u8) -> Result<(), power::AccessError> {
        let mut state = self.operation(Op::Write8(register, value))?;
        let word = state.registers.entry(register & !3).or_default();
        let shift = (register & 3) * 8;
        *word = (*word & !(0xff << shift)) | (u32::from(value) << shift);
        Ok(())
    }
}
