//! Direct extended _CRS interrupt routes. As in pinned Linux
//! drivers/acpi/resource.c acpi_dev_get_irqresource, extended resources retain
//! their own electrical flags; ISA/MADT override policy is separate. Legacy
//! IRQ descriptors, producer/source indirection and edge routes are explicitly
//! unavailable until their full ownership/drain policy is supplied. Wake
//! capability remains descriptive metadata; this admits ordinary held-D0 IRQs
//! only and supplies no wake-enable or suspend/resume operation.
use stela_drivers::{
    bus::irq::{IrqError, LineRoute, Polarity, Trigger},
    platform::acpi::resources::{
        Descriptor, Polarity as AcpiPolarity, Resource, Trigger as AcpiTrigger,
    },
};

pub fn line(
    descriptors: &[Descriptor],
    ordinal: usize,
    pin_index: usize,
) -> Result<LineRoute, IrqError> {
    let descriptor = descriptors
        .iter()
        .find(|d| d.ordinal == ordinal)
        .ok_or(IrqError::Route)?;
    let Resource::Interrupt(interrupt) = &descriptor.resource else {
        return Err(IrqError::Route);
    };
    if descriptor.bytes.first() != Some(&0x89)
        || !interrupt.consumer
        || interrupt.source.is_some()
        || interrupt.trigger != AcpiTrigger::Level
    {
        return Err(IrqError::Unsupported);
    }
    let polarity = match interrupt.polarity {
        AcpiPolarity::High => Polarity::High,
        AcpiPolarity::Low => Polarity::Low,
        AcpiPolarity::Both => return Err(IrqError::Unsupported),
    };
    let gsi = *interrupt.pins.get(pin_index).ok_or(IrqError::Route)?;
    if interrupt.pins.iter().filter(|&&pin| pin == gsi).count() != 1 {
        return Err(IrqError::Route);
    }
    Ok(LineRoute {
        gsi,
        polarity,
        trigger: Trigger::Level,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use stela_drivers::platform::acpi::resources::{self, Interrupt};

    #[test]
    fn actual_extended_bytes_preserve_direct_crs_electrical_and_pin_index() {
        // Actual ACPI Extended IRQ encoding: consumer/shared/low/level, GSI33.
        let descriptors = resources::parse(&[0x89, 6, 0, 13, 1, 33, 0, 0, 0, 0x79, 0]).unwrap();
        assert_eq!(
            line(&descriptors, 0, 0),
            Ok(LineRoute {
                gsi: 33,
                polarity: Polarity::Low,
                trigger: Trigger::Level
            })
        );
        assert_eq!(line(&descriptors, 0, 1), Err(IrqError::Route));
        assert_eq!(line(&descriptors, 1, 0), Err(IrqError::Route));
        let wake_capable = resources::parse(&[0x89, 6, 0, 29, 1, 33, 0, 0, 0, 0x79, 0]).unwrap();
        assert_eq!(line(&wake_capable, 0, 0), line(&descriptors, 0, 0));
    }

    #[test]
    fn unsupported_route_requirements_never_turn_into_a_pin_grant() {
        let original = Descriptor {
            ordinal: 4,
            offset: 17,
            bytes: vec![0x89],
            resource: Resource::Interrupt(Interrupt {
                consumer: true,
                trigger: AcpiTrigger::Level,
                polarity: AcpiPolarity::High,
                shared: true,
                wake: false,
                pins: vec![22],
                source: None,
            }),
        };
        for case in 0..6 {
            let mut descriptor = original.clone();
            let Resource::Interrupt(irq) = &mut descriptor.resource else {
                unreachable!()
            };
            match case {
                0 => descriptor.bytes[0] = 0x23,
                1 => irq.consumer = false,
                2 => irq.trigger = AcpiTrigger::Edge,
                3 => irq.polarity = AcpiPolarity::Both,
                4 => {
                    irq.source = Some(resources::Source {
                        index: 0,
                        path: alloc::string::String::from("LINK"),
                    })
                }
                _ => irq.pins.push(22),
            }
            assert_eq!(
                line(&[descriptor], 4, 0),
                Err(if case == 5 {
                    IrqError::Route
                } else {
                    IrqError::Unsupported
                })
            );
        }
        assert_eq!(line(&[original], 4, 0).unwrap().gsi, 22);
    }
}
