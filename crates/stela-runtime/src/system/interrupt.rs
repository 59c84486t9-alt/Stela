//! GICv3 CPU-interface access planning, before interrupt-controller mutation.
//! AccessKind permission is resolved before producing a backend request. Every accepted access,
//! including configuration reads and writes, remains backend-owned: masks, banking, running
//! priority, pending/active transitions and interrupt delivery must not become plain storage.

use super::access::{
    AccessKind, Encoding, ExceptionLevel, Profile, Request, Resolution, SecurityState, Trap,
};

#[cfg(test)]
const SELECTOR_OP0_SHIFT: u32 = 14;
#[cfg(test)]
const SELECTOR_OP1_SHIFT: u32 = 11;
#[cfg(test)]
const SELECTOR_CRN_SHIFT: u32 = 7;
#[cfg(test)]
const SELECTOR_CRM_SHIFT: u32 = 3;
const ACTIVE_PRIORITY_INDEX_MASK: u16 = 0b11;
#[cfg(test)]
const MIN_GIC_PRIORITY_BITS: u8 = 5;
const MIN_PRIORITY_BITS_INDEX_ONE: u8 = 6;
const MIN_PRIORITY_BITS_INDEX_TWO_THREE: u8 = 7;
const ICC_PMR_EL1: u16 = selector(3, 0, 4, 6, 0);
const ICC_IAR0_EL1: u16 = selector(3, 0, 12, 8, 0);
const ICC_EOIR0_EL1: u16 = selector(3, 0, 12, 8, 1);
const ICC_HPPIR0_EL1: u16 = selector(3, 0, 12, 8, 2);
const ICC_BPR0_EL1: u16 = selector(3, 0, 12, 8, 3);
const ICC_AP0R0_EL1: u16 = selector(3, 0, 12, 8, 4);
const ICC_AP0R3_EL1: u16 = selector(3, 0, 12, 8, 7);
const ICC_AP1R0_EL1: u16 = selector(3, 0, 12, 9, 0);
const ICC_AP1R3_EL1: u16 = selector(3, 0, 12, 9, 3);
const ICC_NMIAR1_EL1: u16 = selector(3, 0, 12, 9, 5);
const ICC_DIR_EL1: u16 = selector(3, 0, 12, 11, 1);
const ICC_RPR_EL1: u16 = selector(3, 0, 12, 11, 3);
const ICC_SGI1R_EL1: u16 = selector(3, 0, 12, 11, 5);
const ICC_ASGI1R_EL1: u16 = selector(3, 0, 12, 11, 6);
const ICC_SGI0R_EL1: u16 = selector(3, 0, 12, 11, 7);
const ICC_IAR1_EL1: u16 = selector(3, 0, 12, 12, 0);
const ICC_EOIR1_EL1: u16 = selector(3, 0, 12, 12, 1);
const ICC_HPPIR1_EL1: u16 = selector(3, 0, 12, 12, 2);
const ICC_BPR1_EL1: u16 = selector(3, 0, 12, 12, 3);
const ICC_CTLR_EL1: u16 = selector(3, 0, 12, 12, 4);
const ICC_SRE_EL1: u16 = selector(3, 0, 12, 12, 5);
const ICC_IGRPEN0_EL1: u16 = selector(3, 0, 12, 12, 6);
const ICC_IGRPEN1_EL1: u16 = selector(3, 0, 12, 12, 7);

const ICC_APR_EL1: u16 = selector(3, 1, 12, 0, 0);
const ICC_CR0_EL1: u16 = selector(3, 1, 12, 0, 1);
const ICC_PCR_EL1: u16 = selector(3, 1, 12, 0, 2);
const ICC_PPI_HMR0_EL1: u16 = selector(3, 0, 12, 10, 0);
#[cfg(test)]
const ICC_IDR0_EL1: u16 = selector(3, 0, 12, 10, 2);
const ICC_HPPIR_EL1: u16 = selector(3, 0, 12, 10, 3);
const ICC_ICSR_EL1: u16 = selector(3, 0, 12, 10, 4);
const ICC_IAFFIDR_EL1: u16 = selector(3, 0, 12, 10, 5);
const ICC_PPI_ENABLER0_EL1: u16 = selector(3, 0, 12, 10, 6);
const ICC_PPI_ENABLER1_EL1: u16 = selector(3, 0, 12, 10, 7);
const ICC_PPI_CACTIVER0_EL1: u16 = selector(3, 0, 12, 13, 0);
const ICC_PPI_SPENDR1_EL1: u16 = selector(3, 0, 12, 13, 7);
const ICC_PPI_PRIORITYR0_EL1: u16 = selector(3, 0, 12, 14, 0);
const ICC_PPI_PRIORITYR15_EL1: u16 = selector(3, 0, 12, 15, 7);

const fn selector(op0: u8, op1: u8, crn: u8, crm: u8, op2: u8) -> u16 {
    Encoding::new(op0, op1, crn, crm, op2).selector()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Group {
    Group0,
    Group1,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SgiKind {
    Group0,
    Group1,
    OtherSecurityGroup1,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Interface {
    Physical,
    Virtual,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bank {
    Unbanked,
    Secure,
    NonSecure,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigurationRegister {
    PriorityMask,
    BinaryPoint(Group),
    ActivePriority(Group, u8),
    Control,
    SystemRegisterEnable,
    GroupEnable(Group),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    ReadConfiguration(ConfigurationRegister),
    WriteConfiguration(ConfigurationRegister, u64),
    Acknowledge(Group),
    AcknowledgeNmiGroup1,
    HighestPending(Group),
    RunningPriority,
    EndOfInterrupt(Group, u64),
    Deactivate(u64),
    GenerateSgi(SgiKind, u64),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendRequest {
    pub interface: Interface,
    pub bank: Bank,
    pub operation: Operation,
}

/// Inputs are effective architectural values, not raw cached host system registers.
/// `virtual_interface_profile` is opt-in and requires a real virtual GIC backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Context {
    pub profile: Profile,
    pub aa64: bool,
    pub gic_v3: bool,
    pub gic_v3_nmi: bool,
    pub gcie: bool,
    pub gcie_legacy: bool,
    pub priority_bits: u8,
    pub have_el2: bool,
    pub el3_sdd_undef_priority: bool,
    pub el3_sdd_undef: bool,
    pub scr_irq: bool,
    pub scr_fiq: bool,
    pub sre_el1: bool,
    pub effective_sre_el2_enable: bool,
    pub effective_sre_el3_enable: bool,
    pub ich_vctlr_v3: bool,
    pub ich_tall0: bool,
    pub ich_tall1: bool,
    pub ich_tc: bool,
    pub ich_tdir: bool,
    pub hcr_fmo: bool,
    pub hcr_imo: bool,
    pub fgt: bool,
    pub scr_fgt_enable: bool,
    pub fgt_igrpen_read: bool,
    pub fgt_igrpen_write: bool,
    pub sctlr_nmi: bool,
    pub virtual_interface_profile: bool,
}

#[cfg(test)]
impl Default for Context {
    fn default() -> Self {
        Self {
            profile: Profile {
                current_el: ExceptionLevel::El1,
                security: SecurityState::NonSecure,
                el2_enabled: false,
                el3_present: false,
            },
            aa64: true,
            gic_v3: true,
            gic_v3_nmi: false,
            gcie: false,
            gcie_legacy: false,
            priority_bits: MIN_GIC_PRIORITY_BITS,
            have_el2: false,
            el3_sdd_undef_priority: false,
            el3_sdd_undef: false,
            scr_irq: false,
            scr_fiq: false,
            sre_el1: true,
            effective_sre_el2_enable: true,
            effective_sre_el3_enable: true,
            ich_vctlr_v3: false,
            ich_tall0: false,
            ich_tall1: false,
            ich_tc: false,
            ich_tdir: false,
            hcr_fmo: false,
            hcr_imo: false,
            fgt: false,
            scr_fgt_enable: false,
            fgt_igrpen_read: false,
            fgt_igrpen_write: false,
            sctlr_nmi: false,
            virtual_interface_profile: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Route {
    Group(Group),
    Control,
    Deactivate,
    Sgi,
    SystemRegisterEnable,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Decoded {
    operation: Operation,
    route: Route,
    banked: bool,
}

fn configuration(register: ConfigurationRegister, access: AccessKind) -> Operation {
    match access {
        AccessKind::Read => Operation::ReadConfiguration(register),
        AccessKind::Write { value } => Operation::WriteConfiguration(register, value),
    }
}

fn decode(key: u16, access: AccessKind) -> Result<Decoded, Resolution<BackendRequest>> {
    use Group::{Group0, Group1};
    let (operation, route, banked) = match (key, access) {
        (ICC_IAR0_EL1, AccessKind::Read) => {
            (Operation::Acknowledge(Group0), Route::Group(Group0), false)
        }
        (ICC_IAR1_EL1, AccessKind::Read) => {
            (Operation::Acknowledge(Group1), Route::Group(Group1), false)
        }
        (ICC_NMIAR1_EL1, AccessKind::Read) => {
            (Operation::AcknowledgeNmiGroup1, Route::Group(Group1), false)
        }
        (ICC_HPPIR0_EL1, AccessKind::Read) => (
            Operation::HighestPending(Group0),
            Route::Group(Group0),
            false,
        ),
        (ICC_HPPIR1_EL1, AccessKind::Read) => (
            Operation::HighestPending(Group1),
            Route::Group(Group1),
            false,
        ),
        (ICC_EOIR0_EL1, AccessKind::Write { value }) => (
            Operation::EndOfInterrupt(Group0, value),
            Route::Group(Group0),
            false,
        ),
        (ICC_EOIR1_EL1, AccessKind::Write { value }) => (
            Operation::EndOfInterrupt(Group1, value),
            Route::Group(Group1),
            false,
        ),
        (ICC_DIR_EL1, AccessKind::Write { value }) => {
            (Operation::Deactivate(value), Route::Deactivate, false)
        }
        (ICC_SGI0R_EL1, AccessKind::Write { value }) => (
            Operation::GenerateSgi(SgiKind::Group0, value),
            Route::Sgi,
            false,
        ),
        (ICC_SGI1R_EL1, AccessKind::Write { value }) => (
            Operation::GenerateSgi(SgiKind::Group1, value),
            Route::Sgi,
            false,
        ),
        (ICC_ASGI1R_EL1, AccessKind::Write { value }) => (
            Operation::GenerateSgi(SgiKind::OtherSecurityGroup1, value),
            Route::Sgi,
            false,
        ),
        (ICC_RPR_EL1, AccessKind::Read) => (Operation::RunningPriority, Route::Control, false),
        (ICC_PMR_EL1, _) => (
            configuration(ConfigurationRegister::PriorityMask, access),
            Route::Control,
            false,
        ),
        (ICC_BPR0_EL1, _) => (
            configuration(ConfigurationRegister::BinaryPoint(Group0), access),
            Route::Group(Group0),
            false,
        ),
        (ICC_BPR1_EL1, _) => (
            configuration(ConfigurationRegister::BinaryPoint(Group1), access),
            Route::Group(Group1),
            true,
        ),
        (ICC_CTLR_EL1, _) => (
            configuration(ConfigurationRegister::Control, access),
            Route::Control,
            true,
        ),
        (ICC_SRE_EL1, _) => (
            configuration(ConfigurationRegister::SystemRegisterEnable, access),
            Route::SystemRegisterEnable,
            true,
        ),
        (ICC_IGRPEN0_EL1, _) => (
            configuration(ConfigurationRegister::GroupEnable(Group0), access),
            Route::Group(Group0),
            false,
        ),
        (ICC_IGRPEN1_EL1, _) => (
            configuration(ConfigurationRegister::GroupEnable(Group1), access),
            Route::Group(Group1),
            true,
        ),
        (ICC_AP0R0_EL1..=ICC_AP0R3_EL1, _) => (
            configuration(
                ConfigurationRegister::ActivePriority(
                    Group0,
                    (key & ACTIVE_PRIORITY_INDEX_MASK) as u8,
                ),
                access,
            ),
            Route::Group(Group0),
            false,
        ),
        (ICC_AP1R0_EL1..=ICC_AP1R3_EL1, _) => (
            configuration(
                ConfigurationRegister::ActivePriority(
                    Group1,
                    (key & ACTIVE_PRIORITY_INDEX_MASK) as u8,
                ),
                access,
            ),
            Route::Group(Group1),
            true,
        ),
        _ => return Err(Resolution::NotHandled),
    };
    Ok(Decoded {
        operation,
        route,
        banked,
    })
}

fn trap(target: ExceptionLevel) -> Resolution<BackendRequest> {
    Resolution::Trap(Trap::system_access(target))
}
fn el3_denied(context: &Context) -> Resolution<BackendRequest> {
    if context.el3_sdd_undef {
        Resolution::Undefined
    } else {
        trap(ExceptionLevel::El3)
    }
}
fn el3_routed(context: &Context, route: Route) -> bool {
    context.profile.el3_present
        && match route {
            Route::Group(Group::Group0) => context.scr_fiq,
            Route::Group(Group::Group1) => context.scr_irq,
            Route::Control | Route::Deactivate | Route::Sgi => context.scr_fiq && context.scr_irq,
            Route::SystemRegisterEnable => !context.effective_sre_el3_enable,
        }
}
fn is_group_enable(operation: Operation) -> bool {
    matches!(
        operation,
        Operation::ReadConfiguration(ConfigurationRegister::GroupEnable(_))
            | Operation::WriteConfiguration(ConfigurationRegister::GroupEnable(_), _)
    )
}
fn group_enable_fgt(context: &Context, operation: Operation, access: AccessKind) -> bool {
    is_group_enable(operation)
        && context.fgt
        && (!context.profile.el3_present || context.scr_fgt_enable)
        && match access {
            AccessKind::Read => context.fgt_igrpen_read,
            AccessKind::Write { .. } => context.fgt_igrpen_write,
        }
}

/// Plan an ICC access. ICV names have the same encoding: virtualization is selected by
/// HCR routing after all preceding permission checks, never by an alternative selector.
/// `NotHandled` is a family dispatch miss; the complete allocation table owns the
/// final architectural classification. No accepted request mutates controller state.
pub fn resolve(request: Request, context: &Context) -> Resolution<BackendRequest> {
    let encoding = request.encoding;
    let key = encoding.selector();
    let access = match request.kind {
        AccessKind::Read => AccessKind::Read,
        AccessKind::Write { .. } => AccessKind::Write {
            value: request.write_value().expect("write access"),
        },
    };
    let decoded = match decode(key, access) {
        Ok(value) => value,
        Err(Resolution::NotHandled) => return extended_access(key, access, context),
        Err(outcome) => return outcome,
    };
    let feature = match decoded.operation {
        Operation::AcknowledgeNmiGroup1 => context.gic_v3_nmi || context.gcie_legacy,
        Operation::ReadConfiguration(ConfigurationRegister::SystemRegisterEnable)
        | Operation::WriteConfiguration(ConfigurationRegister::SystemRegisterEnable, _) => {
            context.gic_v3 || (context.gcie && context.have_el2)
        }
        _ => context.gic_v3 || context.gcie_legacy,
    };
    if !context.aa64 || !feature {
        return Resolution::Undefined;
    }
    if let Operation::ReadConfiguration(ConfigurationRegister::ActivePriority(_, index))
    | Operation::WriteConfiguration(ConfigurationRegister::ActivePriority(_, index), _) =
        decoded.operation
        && ((index == 1 && context.priority_bits < MIN_PRIORITY_BITS_INDEX_ONE)
            || (index >= 2 && context.priority_bits < MIN_PRIORITY_BITS_INDEX_TWO_THREE))
    {
        return Resolution::Undefined;
    }
    if !matches!(
        context.profile.current_el,
        ExceptionLevel::El0 | ExceptionLevel::El1
    ) {
        return Resolution::Unsupported("GIC access planner supports EL0 and EL1 only");
    }
    if context.profile.current_el == ExceptionLevel::El1
        && context.el3_sdd_undef_priority
        && el3_routed(context, decoded.route)
    {
        return Resolution::Undefined;
    }
    if context.profile.current_el == ExceptionLevel::El0 {
        return Resolution::Undefined;
    }
    if matches!(decoded.operation, Operation::AcknowledgeNmiGroup1) && !context.sctlr_nmi {
        return Resolution::Undefined;
    }
    if decoded.route == Route::SystemRegisterEnable {
        if context.profile.el2_enabled && !context.effective_sre_el2_enable {
            return trap(ExceptionLevel::El2);
        }
        if el3_routed(context, decoded.route) {
            return el3_denied(context);
        }
        return backend(decoded, Interface::Physical, context);
    }
    let fine_grained_trap = group_enable_fgt(context, decoded.operation, access);
    let (coarse_trap, virtual_route) = match decoded.route {
        Route::Group(Group::Group0) => (context.ich_tall0, context.hcr_fmo),
        Route::Group(Group::Group1) => (context.ich_tall1, context.hcr_imo),
        Route::Control | Route::Sgi => (context.ich_tc, context.hcr_fmo || context.hcr_imo),
        Route::Deactivate => (
            context.ich_tdir || context.ich_tc,
            context.hcr_fmo || context.hcr_imo,
        ),
        Route::SystemRegisterEnable => unreachable!(),
    };
    if context.gcie_legacy
        && (!context.ich_vctlr_v3
            || !context.profile.el2_enabled
            || !(fine_grained_trap || coarse_trap || virtual_route))
    {
        return Resolution::Undefined;
    }
    if !context.sre_el1 {
        return trap(ExceptionLevel::El1);
    }
    if context.profile.el2_enabled {
        if fine_grained_trap || coarse_trap {
            return trap(ExceptionLevel::El2);
        }
        if virtual_route {
            if decoded.route == Route::Sgi {
                return trap(ExceptionLevel::El2);
            }
            if !context.virtual_interface_profile {
                return Resolution::Unsupported(
                    "virtual GIC interface requires an explicit backend profile",
                );
            }
            return backend(decoded, Interface::Virtual, context);
        }
    }
    if el3_routed(context, decoded.route) {
        return el3_denied(context);
    }
    backend(decoded, Interface::Physical, context)
}

fn backend(
    decoded: Decoded,
    interface: Interface,
    context: &Context,
) -> Resolution<BackendRequest> {
    let bank = if interface == Interface::Virtual || !decoded.banked || !context.profile.el3_present
    {
        Bank::Unbanked
    } else if context.profile.security != SecurityState::Secure {
        Bank::NonSecure
    } else {
        Bank::Secure
    };
    Resolution::BackendRequired(BackendRequest {
        interface,
        bank,
        operation: decoded.operation,
    })
}

// FEAT_GCIE introduces another interface and fine-grained trap bank. Recognize its
// allocated selectors without pretending the GICv3 rules implement those registers.
fn extended_access(key: u16, access: AccessKind, context: &Context) -> Resolution<BackendRequest> {
    let read_only = match key {
        ICC_PPI_HMR0_EL1..=ICC_HPPIR_EL1 | ICC_IAFFIDR_EL1 => true,
        ICC_APR_EL1
        | ICC_CR0_EL1
        | ICC_PCR_EL1
        | ICC_ICSR_EL1
        | ICC_PPI_ENABLER0_EL1..=ICC_PPI_ENABLER1_EL1
        | ICC_PPI_CACTIVER0_EL1..=ICC_PPI_SPENDR1_EL1
        | ICC_PPI_PRIORITYR0_EL1..=ICC_PPI_PRIORITYR15_EL1 => false,
        _ => return Resolution::NotHandled,
    };
    if read_only && matches!(access, AccessKind::Write { .. }) {
        return Resolution::NotHandled;
    }
    if !context.aa64 || !context.gcie || context.profile.current_el == ExceptionLevel::El0 {
        return Resolution::Undefined;
    }
    Resolution::Unsupported(
        "FEAT_GCIE extended register access rules require a separate interface profile",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(key: u16, access: AccessKind, rt: u8) -> Request {
        let encoding = Encoding::new(
            (key >> SELECTOR_OP0_SHIFT) as u8,
            ((key >> SELECTOR_OP1_SHIFT) & 0b111) as u8,
            ((key >> SELECTOR_CRN_SHIFT) & 0b1111) as u8,
            ((key >> SELECTOR_CRM_SHIFT) & 0b1111) as u8,
            (key & 0b111) as u8,
        );
        match access {
            AccessKind::Read => Request::read(encoding, rt),
            AccessKind::Write { value } => Request::write(encoding, rt, value),
        }
    }

    #[test]
    fn acknowledge_eoi_and_sgi_are_operations_not_register_storage() {
        let context = Context::default();
        for (key, access, operation) in [
            (
                ICC_IAR0_EL1,
                AccessKind::Read,
                Operation::Acknowledge(Group::Group0),
            ),
            (
                ICC_IAR1_EL1,
                AccessKind::Read,
                Operation::Acknowledge(Group::Group1),
            ),
            (
                ICC_HPPIR1_EL1,
                AccessKind::Read,
                Operation::HighestPending(Group::Group1),
            ),
            (
                ICC_EOIR0_EL1,
                AccessKind::Write { value: u64::MAX },
                Operation::EndOfInterrupt(Group::Group0, u64::MAX),
            ),
            (
                ICC_EOIR1_EL1,
                AccessKind::Write { value: u64::MAX },
                Operation::EndOfInterrupt(Group::Group1, u64::MAX),
            ),
            (
                ICC_DIR_EL1,
                AccessKind::Write { value: u64::MAX },
                Operation::Deactivate(u64::MAX),
            ),
            (
                ICC_SGI0R_EL1,
                AccessKind::Write { value: u64::MAX },
                Operation::GenerateSgi(SgiKind::Group0, u64::MAX),
            ),
            (
                ICC_SGI1R_EL1,
                AccessKind::Write { value: u64::MAX },
                Operation::GenerateSgi(SgiKind::Group1, u64::MAX),
            ),
            (
                ICC_ASGI1R_EL1,
                AccessKind::Write { value: u64::MAX },
                Operation::GenerateSgi(SgiKind::OtherSecurityGroup1, u64::MAX),
            ),
        ] {
            assert_eq!(
                resolve(request(key, access, 0), &context),
                Resolution::BackendRequired(BackendRequest {
                    interface: Interface::Physical,
                    bank: Bank::Unbanked,
                    operation
                })
            );
        }
    }

    #[test]
    fn xzr_read_keeps_acknowledge_effect_and_xzr_write_supplies_zero() {
        let context = Context::default();
        assert_eq!(
            resolve(request(ICC_IAR1_EL1, AccessKind::Read, 31), &context),
            Resolution::BackendRequired(BackendRequest {
                interface: Interface::Physical,
                bank: Bank::Unbanked,
                operation: Operation::Acknowledge(Group::Group1)
            })
        );
        assert_eq!(
            resolve(
                request(ICC_EOIR1_EL1, AccessKind::Write { value: u64::MAX }, 31),
                &context
            ),
            Resolution::BackendRequired(BackendRequest {
                interface: Interface::Physical,
                bank: Bank::Unbanked,
                operation: Operation::EndOfInterrupt(Group::Group1, 0)
            })
        );
    }

    #[test]
    fn wrong_direction_is_not_an_ordinary_register_access() {
        for key in [
            ICC_IAR0_EL1,
            ICC_IAR1_EL1,
            ICC_HPPIR0_EL1,
            ICC_HPPIR1_EL1,
            ICC_RPR_EL1,
            ICC_NMIAR1_EL1,
        ] {
            assert_eq!(
                resolve(
                    request(key, AccessKind::Write { value: 0 }, 0),
                    &Context::default()
                ),
                Resolution::NotHandled
            );
        }
        for key in [
            ICC_EOIR0_EL1,
            ICC_EOIR1_EL1,
            ICC_DIR_EL1,
            ICC_SGI0R_EL1,
            ICC_SGI1R_EL1,
            ICC_ASGI1R_EL1,
        ] {
            assert_eq!(
                resolve(request(key, AccessKind::Read, 0), &Context::default()),
                Resolution::NotHandled
            );
        }
        assert_eq!(
            resolve(
                request(selector(3, 0, 12, 9, 4), AccessKind::Read, 0),
                &Context::default()
            ),
            Resolution::NotHandled
        );
    }

    #[test]
    fn priority_register_index_boundaries_and_banked_routing() {
        for priority_bits in 5..=7 {
            for index in 0..4 {
                for key in [ICC_AP0R0_EL1 + index, ICC_AP1R0_EL1 + index] {
                    let context = Context {
                        priority_bits,
                        ..Context::default()
                    };
                    let expected_present =
                        index == 0 || (index == 1 && priority_bits >= 6) || priority_bits >= 7;
                    assert_eq!(
                        matches!(
                            resolve(request(key, AccessKind::Read, 0), &context),
                            Resolution::BackendRequired(_)
                        ),
                        expected_present
                    );
                }
            }
        }
        for security in [
            SecurityState::Secure,
            SecurityState::NonSecure,
            SecurityState::Realm,
        ] {
            let context = Context {
                profile: Profile {
                    el3_present: true,
                    security,
                    ..Context::default().profile
                },
                ..Context::default()
            };
            let bank = if security == SecurityState::Secure {
                Bank::Secure
            } else {
                Bank::NonSecure
            };
            assert_eq!(
                resolve(request(ICC_BPR1_EL1, AccessKind::Read, 0), &context),
                Resolution::BackendRequired(BackendRequest {
                    interface: Interface::Physical,
                    bank,
                    operation: Operation::ReadConfiguration(ConfigurationRegister::BinaryPoint(
                        Group::Group1
                    ))
                })
            );
        }
    }

    #[test]
    fn extended_gcie_registers_are_not_claimed_or_silently_stored() {
        for key in [
            ICC_PPI_HMR0_EL1,
            ICC_IDR0_EL1,
            ICC_HPPIR_EL1,
            ICC_IAFFIDR_EL1,
        ] {
            assert_eq!(
                resolve(
                    request(key, AccessKind::Write { value: 0 }, 0),
                    &Context::default()
                ),
                Resolution::NotHandled
            );
        }

        for key in [
            ICC_APR_EL1,
            ICC_CR0_EL1,
            ICC_PCR_EL1,
            ICC_PPI_HMR0_EL1,
            ICC_IDR0_EL1,
            ICC_PPI_PRIORITYR15_EL1,
        ] {
            assert_eq!(
                resolve(request(key, AccessKind::Read, 0), &Context::default()),
                Resolution::Undefined
            );
            let context = Context {
                gcie: true,
                ..Context::default()
            };
            assert!(matches!(
                resolve(request(key, AccessKind::Read, 0), &context),
                Resolution::Unsupported(_)
            ));
            let context = Context {
                profile: Profile {
                    current_el: ExceptionLevel::El0,
                    ..context.profile
                },
                ..context
            };
            assert_eq!(
                resolve(request(key, AccessKind::Read, 0), &context),
                Resolution::Undefined
            );
        }
    }
}
