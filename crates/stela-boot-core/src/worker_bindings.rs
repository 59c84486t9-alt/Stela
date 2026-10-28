//! Effect-free validation of the guest-PE/physical-worker bijection. These
//! records grant no execution authority; the real Hosts must still initialize
//! their publication owners against the retained capture and executor roster.
use stela_runtime::machine::engine::publication::WorkerBinding;

pub fn validate(
    cores: usize,
    boot_processor: usize,
    bindings: &[WorkerBinding],
) -> Result<(), &'static str> {
    if cores == 0 || boot_processor >= cores || bindings.len() != cores {
        return Err("canonical native assignment has an incomplete PE/worker roster");
    }
    for (index, binding) in bindings.iter().enumerate() {
        if binding.pe >= cores
            || binding.worker.0 >= cores
            || bindings[..index]
                .iter()
                .any(|earlier| earlier.pe == binding.pe || earlier.worker == binding.worker)
        {
            return Err("canonical native assignment is not a PE/worker bijection");
        }
        if (binding.pe == boot_processor) != (binding.worker.0 == 0) {
            return Err("canonical boot PE is not assigned to the actual BSP worker");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_runtime::machine::engine::publication::WorkerId;

    #[test]
    fn an_unordered_assignment_preserves_nonzero_boot_pe_and_physical_worker_ids() {
        let bindings = [
            WorkerBinding {
                pe: 3,
                worker: WorkerId(2),
            },
            WorkerBinding {
                pe: 0,
                worker: WorkerId(3),
            },
            WorkerBinding {
                pe: 2,
                worker: WorkerId(0),
            },
            WorkerBinding {
                pe: 1,
                worker: WorkerId(1),
            },
        ];
        assert_eq!(validate(4, 2, &bindings), Ok(()));
        assert!(validate(4, 0, &bindings).is_err());
        assert_eq!(
            validate(
                1,
                0,
                &[WorkerBinding {
                    pe: 0,
                    worker: WorkerId(0)
                }]
            ),
            Ok(())
        );
    }

    #[test]
    fn incomplete_duplicate_outside_and_wrong_bsp_assignments_refuse_before_adoption() {
        let good = [
            WorkerBinding {
                pe: 0,
                worker: WorkerId(1),
            },
            WorkerBinding {
                pe: 1,
                worker: WorkerId(0),
            },
        ];
        for (cores, boot) in [(0, 0), (1, 0), (2, 2), (3, 1)] {
            assert!(validate(cores, boot, &good).is_err());
        }
        assert!(validate(2, 1, &good[..1]).is_err());
        for bad in [
            [good[0], good[0]],
            [
                good[0],
                WorkerBinding {
                    pe: 1,
                    worker: WorkerId(1),
                },
            ],
            [
                good[0],
                WorkerBinding {
                    pe: 2,
                    worker: WorkerId(0),
                },
            ],
            [
                good[0],
                WorkerBinding {
                    pe: 1,
                    worker: WorkerId(2),
                },
            ],
        ] {
            assert!(validate(2, 1, &bad).is_err());
        }
    }
}
