//! Actual source-selected controller views; no replacement register images.
//!
//! Original T8112 constructor1033000..10330e4 supplies four x2 tuples. Base
//!1005e94..1005eb4 copies their+38..+50 pointers into P1c8. Direct vtable
//!1043a90 and mapped1043600 share10081b4..1008258 flag operations. Member
//! reads are10080d4 or10066c8 respectively. Every MmioError is uncertain:
//! a register read may consume, and this adapter must not replay it.
use super::super::super::owner::Completion;
use super::{FlagsMethod, Operation, ResourceRequest, ResourceValue};
use crate::platform::apple::bus::{Access, MmioDevice, MmioError, Width};
use alloc::boxed::Box;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mapping {
    pub address: u64,
    pub bytes: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Placement {
    pub control: Mapping,
    pub member: Option<Mapping>,
    pub member_offset: u32,
    pub member_stride: u32,
}
impl Placement {
    /// Original controller classes, not PMGR domain IDs or invented counters.
    pub fn t8112(ordinal: usize, provider: u32) -> Result<Self, &'static str> {
        let address = match (ordinal, provider) {
            (4, 0) => 0x210ee0000,
            (5, 0) => 0x211ee0000,
            (5, 1) => 0x211ee8000,
            (5, 2) => 0x211ef0000,
            (7, 0) => {
                return Ok(Self {
                    control: Mapping {
                        address: 0x26b838000,
                        bytes: 0x8000,
                    },
                    member: Some(Mapping {
                        address: 0x23b2e0000,
                        bytes: 0x4000,
                    }),
                    member_offset: 0,
                    member_stride: 0x100,
                });
            }
            _ => return Err("T8112 auxiliary controller selector has no source-owned mapping"),
        };
        Ok(Self {
            control: Mapping {
                address,
                bytes: 0x8000,
            },
            member: None,
            member_offset: 0x4000,
            member_stride: 0x200,
        })
    }
}
struct Completed {
    request: ResourceRequest,
    operation: Operation,
    value: ResourceValue,
}
/// Own the actual device or an identity-preserving alias of the AP bus owner.
/// The caller must qualify those mapped views against the supplied placements;
/// numeric geometry by itself cannot turn a copied word bank into that owner.
/// This does not construct the hardware event producer or assume any reset word.
pub struct Controller {
    placement: Placement,
    provider: u32,
    control: Box<dyn MmioDevice>,
    member: Option<Box<dyn MmioDevice>>,
    completed: Option<Completed>,
    uncertain: Option<MmioError>,
}
impl Controller {
    pub fn t8112(
        ordinal: usize,
        provider: u32,
        control_mapping: Mapping,
        control: Box<dyn MmioDevice>,
        member_mapping: Option<Mapping>,
        member: Option<Box<dyn MmioDevice>>,
    ) -> Result<Self, &'static str> {
        let placement = Placement::t8112(ordinal, provider)?;
        if control_mapping != placement.control
            || member_mapping != placement.member
            || member.is_some() != placement.member.is_some()
        {
            return Err("auxiliary controller views differ from actual source placements");
        }
        Ok(Self {
            placement,
            provider,
            control,
            member,
            completed: None,
            uncertain: None,
        })
    }
    pub fn placement(&self) -> Placement {
        self.placement
    }
    pub fn uncertain_access(&self) -> Option<MmioError> {
        self.uncertain
    }
    pub fn call(
        &mut self,
        request: &ResourceRequest,
        operation: Operation,
        access: &mut Access<'_>,
    ) -> Completion<ResourceValue> {
        if self.uncertain.is_some() {
            return Completion::Refused(
                "auxiliary controller MMIO retirement is uncertain; replay refused",
            );
        }
        if let Some(done) = &self.completed {
            if done.request.same_operation(request) {
                return if done.operation == operation {
                    Completion::Retired {
                        value: done.value,
                        refusal: None,
                    }
                } else {
                    Completion::Refused("auxiliary controller retired operation changed")
                };
            }
            if !done.request.identity.same(&request.identity)
                || (request.sequence, request.step) <= (done.request.sequence, done.request.step)
            {
                return Completion::Refused("auxiliary controller caller is foreign or stale");
            }
        }
        let (provider, index, kind) = match operation {
            Operation::Flags70 { provider, member } => (provider, member, 0),
            Operation::Member28 { provider, member } => (provider, member, 1),
            Operation::Packed400 { provider } => (provider, 0, 2),
            Operation::Flags {
                provider, member, ..
            } => (provider, member, 3),
            _ => {
                return Completion::Refused(
                    "operation requires another actual auxiliary resource owner",
                );
            }
        };
        if provider != self.provider {
            return Completion::Refused(
                "auxiliary controller provider selector differs from its source binding",
            );
        }
        let offset = match kind {
            0 => index.checked_mul(0x200).and_then(|v| v.checked_add(0x1008)),
            1 => index
                .checked_mul(self.placement.member_stride)
                .and_then(|v| v.checked_add(self.placement.member_offset)),
            2 => Some(0x400),
            _ => {
                let base = match operation {
                    Operation::Flags {
                        method: FlagsMethod::Store58,
                        ..
                    } => 0x1008,
                    Operation::Flags {
                        method: FlagsMethod::Enable60,
                        ..
                    } => 0x1000,
                    Operation::Flags {
                        method: FlagsMethod::Disable68,
                        ..
                    } => 0x1004,
                    _ => unreachable!(),
                };
                index.checked_mul(0x200).and_then(|v| v.checked_add(base))
            }
        };
        let bytes = if kind == 1 {
            self.placement
                .member
                .unwrap_or(self.placement.control)
                .bytes
        } else {
            self.placement.control.bytes
        };
        let Some(offset) = offset.filter(|v| u64::from(*v) + 4 <= bytes) else {
            return Completion::Refused(
                "auxiliary controller operation exceeds its actual mapped aperture",
            );
        };
        let result = match operation {
            Operation::Flags { value, .. } => {
                let word = (u32::from(value & 1) << 24) | (u32::from((value >> 8) & 1) << 25);
                self.control
                    .write(u64::from(offset), Width::Word, u64::from(word), access)
                    .map(|()| ResourceValue::Complete)
            }
            _ => {
                let device = if kind == 1 {
                    match self.member.as_mut() {
                        Some(member) => &mut **member,
                        None => &mut *self.control,
                    }
                } else {
                    &mut *self.control
                };
                device
                    .read(u64::from(offset), Width::Word, access)
                    .map(|raw| {
                        let raw = raw as u32;
                        ResourceValue::Word(match kind {
                            0 => ((raw >> 24) & 1) | (((raw >> 25) & 1) << 8),
                            1 => (raw & 0x7fff) | ((raw >> 31) << 15),
                            _ => raw,
                        })
                    })
            }
        };
        match result {
            Ok(value) => {
                self.completed = Some(Completed {
                    request: request.clone(),
                    operation,
                    value,
                });
                Completion::Retired {
                    value,
                    refusal: None,
                }
            }
            Err(error) => {
                self.uncertain = Some(error);
                Completion::Refused(
                    "auxiliary controller MMIO retirement is uncertain; replay refused",
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::Identity;
    use super::*;
    use crate::platform::apple::{bus::Direction, interrupt::InterruptLatch};
    use alloc::{rc::Rc, vec, vec::Vec};
    use core::cell::RefCell;
    type AccessLog = Rc<RefCell<Vec<(u64, Option<u64>)>>>;
    #[derive(Clone)]
    struct Device(AccessLog, bool);
    impl MmioDevice for Device {
        fn name(&self) -> &'static str {
            "authored actual controller view"
        }
        fn read(
            &mut self,
            offset: u64,
            width: Width,
            _: &mut Access<'_>,
        ) -> Result<u64, MmioError> {
            self.0.borrow_mut().push((offset, None));
            if self.1 {
                return Err(MmioError::Unsupported {
                    device: self.name(),
                    offset,
                    width,
                    direction: Direction::Read,
                    reason: "authored read may have consumed",
                });
            }
            Ok(0x830a_1234)
        }
        fn write(
            &mut self,
            offset: u64,
            _: Width,
            value: u64,
            _: &mut Access<'_>,
        ) -> Result<(), MmioError> {
            self.0.borrow_mut().push((offset, Some(value)));
            Ok(())
        }
    }
    fn req(step: u64) -> ResourceRequest {
        ResourceRequest {
            identity: Identity::new(),
            sequence: 1,
            step,
        }
    }
    #[test]
    fn direct_flags_and_member_offsets_reach_the_same_owned_device_view() {
        let effects = Rc::new(RefCell::new(Vec::new()));
        let placement = Placement::t8112(5, 1).unwrap();
        let mut controller = Controller::t8112(
            5,
            1,
            placement.control,
            Box::new(Device(effects.clone(), false)),
            None,
            None,
        )
        .unwrap();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let r = req(0);
        assert_eq!(
            controller.call(
                &r,
                Operation::Flags70 {
                    provider: 1,
                    member: 2
                },
                &mut access
            ),
            Completion::Retired {
                value: ResourceValue::Word(0x101),
                refusal: None
            }
        );
        assert_eq!(
            controller.call(
                &r,
                Operation::Flags70 {
                    provider: 1,
                    member: 2
                },
                &mut access
            ),
            Completion::Retired {
                value: ResourceValue::Word(0x101),
                refusal: None
            }
        );
        let mut next = r.clone();
        next.step = 1;
        assert_eq!(
            controller.call(
                &next,
                Operation::Member28 {
                    provider: 1,
                    member: 2
                },
                &mut access
            ),
            Completion::Retired {
                value: ResourceValue::Word(0x9234),
                refusal: None
            }
        );
        next.step = 2;
        assert_eq!(
            controller.call(
                &next,
                Operation::Flags {
                    provider: 1,
                    member: 2,
                    method: FlagsMethod::Disable68,
                    value: 0x101
                },
                &mut access
            ),
            Completion::Retired {
                value: ResourceValue::Complete,
                refusal: None
            }
        );
        assert_eq!(
            *effects.borrow(),
            vec![(0x1408, None), (0x4400, None), (0x1404, Some(0x3000000))]
        );
    }
    #[test]
    fn mapped_member_uses_separate_real_mapping_and_uncertain_reads_cannot_replay() {
        let controls = Rc::new(RefCell::new(Vec::new()));
        let members = Rc::new(RefCell::new(Vec::new()));
        let p = Placement::t8112(7, 0).unwrap();
        let mut controller = Controller::t8112(
            7,
            0,
            p.control,
            Box::new(Device(controls.clone(), false)),
            p.member,
            Some(Box::new(Device(members.clone(), true))),
        )
        .unwrap();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let r = req(0);
        for _ in 0..2 {
            assert!(matches!(
                controller.call(
                    &r,
                    Operation::Member28 {
                        provider: 0,
                        member: 9
                    },
                    &mut access
                ),
                Completion::Refused(_)
            ));
        }
        assert_eq!(*members.borrow(), vec![(0x900, None)]);
        assert!(controls.borrow().is_empty());
        assert!(controller.uncertain_access().is_some());
        assert!(Placement::t8112(6, 0).is_err());
        assert!(Placement::t8112(5, 3).is_err());
    }
}
