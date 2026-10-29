//! Admission, flush barriers and partial effects across polling calls.
use super::*;

const BLOCKS: usize = 131;
const ADMISSIONS: usize = 64;

fn disk() -> RamDisk {
    let mut disk = RamDisk::new("poll", (BLOCKS + 2) as u64, 512);
    disk.identity.features.max_transfer = 512;
    disk.write(0, &vec![0xa5; (BLOCKS + 2) * 512]).unwrap();
    disk
}

fn request(disk: &impl BlockDevice, durable: bool) -> Submission {
    Submission::new(
        Request::Write {
            lba: 1,
            data: vec![0x3c; BLOCKS * 512],
            durable,
        },
        disk.identity(),
    )
    .unwrap()
}

fn check(disk: &mut RamDisk, changed: usize, last: u8) {
    let mut data = vec![0; (BLOCKS + 2) * 512];
    disk.read(0, &mut data).unwrap();
    assert!(data[..512].iter().all(|&byte| byte == 0xa5));
    assert!(
        data[512..(1 + changed) * 512]
            .iter()
            .all(|&byte| byte == 0x3c)
    );
    assert!(
        data[(1 + changed) * 512..(1 + BLOCKS) * 512]
            .iter()
            .all(|&byte| byte == 0xa5)
    );
    assert!(data[(1 + BLOCKS) * 512..].iter().all(|&byte| byte == last));
}

#[test]
fn synchronous_requests_yield_with_partial_effects_and_resume() {
    let mut disk = disk();
    let mut submission = request(&disk, false);
    assert_eq!(submission.poll(&mut disk), None);
    check(&mut disk, ADMISSIONS, 0xa5);
    // Another caller can make progress between polling calls.
    disk.write((BLOCKS + 1) as u64, &[0x7e; 512]).unwrap();
    assert_eq!(submission.poll(&mut disk), None);
    check(&mut disk, 2 * ADMISSIONS, 0x7e);
    assert_eq!(submission.poll(&mut disk), Some(Ok(None)));
    check(&mut disk, BLOCKS, 0x7e);
}

/// Commands complete before start returns, so room stays available. Results
/// remain owned by their tags until the caller takes them.
struct Eager {
    disk: RamDisk,
    given: Vec<Command>,
    done: BTreeMap<u32, Finished>,
    taken: usize,
    peak: usize,
    failure: Option<(u32, bool)>,
    depth: usize,
    ready: bool,
    direct_writes: usize,
}

impl Eager {
    fn new(failure: Option<(u32, bool)>) -> Self {
        let mut disk = disk();
        disk.identity.features.write_cache = true;
        disk.identity.features.fua = false;
        Self {
            disk,
            given: Vec::new(),
            done: BTreeMap::new(),
            taken: 0,
            peak: 0,
            failure,
            depth: 128,
            ready: true,
            direct_writes: 0,
        }
    }
}

impl BlockDevice for Eager {
    fn identity(&self) -> &Identity {
        self.disk.identity()
    }
    fn read(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        self.disk.read(lba, buffer)
    }
    fn write(&mut self, lba: u64, data: &[u8]) -> Result<(), BlockError> {
        self.direct_writes += 1;
        self.disk.write(lba, data)
    }
    fn depth(&self) -> usize {
        self.depth
    }
    fn room(&self) -> bool {
        true
    }
    fn start(&mut self, command: Command) -> Result<u32, BlockError> {
        let tag = self.given.len() as u32;
        self.given.push(command.clone());
        let result = if let Some((at, completion)) = self.failure
            && tag == at
        {
            let error = BlockError::Device { status: 17 };
            if !completion {
                return Err(error);
            }
            Err(error)
        } else if matches!(command, Command::Flush) {
            assert!(
                self.done.is_empty(),
                "flush before earlier results were drained"
            );
            Ok(None)
        } else {
            self.disk.execute(command)
        };
        assert!(self.done.insert(tag, result).is_none());
        self.peak = self.peak.max(self.done.len());
        Ok(tag)
    }
    fn finish(&mut self, tag: u32) -> Option<Finished> {
        if !self.ready {
            return None;
        }
        let result = self.done.remove(&tag)?;
        self.taken += 1;
        Some(result)
    }
}

#[test]
fn queued_results_drain_after_depth_shrinks_before_direct_execution() {
    let mut disk = Eager::new(None);
    disk.depth = 2;
    let mut submission = request(&disk, false);
    assert_eq!(submission.poll(&mut disk), None);
    assert_eq!(disk.given.len(), 2);
    disk.ready = false;
    for depth in [1, 0] {
        disk.depth = depth;
        assert_eq!(submission.poll(&mut disk), None);
        assert_eq!(disk.given.len(), 2);
        assert_eq!((disk.taken, disk.direct_writes), (0, 0));
    }
    disk.ready = true;
    assert_eq!(submission.poll(&mut disk), None);
    assert_eq!((disk.taken, disk.direct_writes), (2, ADMISSIONS));
    check(&mut disk.disk, 2 + ADMISSIONS, 0xa5);
    assert_eq!(submission.poll(&mut disk), None);
    assert_eq!(submission.poll(&mut disk), Some(Ok(None)));
    assert!(disk.done.is_empty());
    check(&mut disk.disk, BLOCKS, 0xa5);
}

#[test]
fn eager_requests_bound_admission_and_keep_flush_after_all_writes() {
    let mut disk = Eager::new(None);
    let mut submission = request(&disk, true);
    assert_eq!(submission.poll(&mut disk), None);
    assert_eq!(disk.given.len(), ADMISSIONS);
    check(&mut disk.disk, ADMISSIONS, 0xa5);
    let mut result = None;
    for _ in 0..8 {
        result = submission.poll(&mut disk);
        if result.is_some() {
            break;
        }
    }
    assert_eq!(result, Some(Ok(None)));
    assert_eq!(disk.peak, ADMISSIONS);
    assert_eq!(disk.taken, BLOCKS + 1);
    assert_eq!(disk.given.len(), BLOCKS + 1);
    assert!(matches!(disk.given.last(), Some(Command::Flush)));
    assert!(
        disk.given[..BLOCKS]
            .iter()
            .all(|command| matches!(command, Command::Write { fua: false, .. }))
    );
    assert!(disk.done.is_empty());
    check(&mut disk.disk, BLOCKS, 0xa5);
}

#[test]
fn failures_stop_admission_and_drain_owned_tags_without_flushing() {
    for completion in [false, true] {
        let mut disk = Eager::new(Some(((ADMISSIONS - 1) as u32, completion)));
        let mut submission = request(&disk, true);
        assert_eq!(submission.poll(&mut disk), None);
        assert_eq!(disk.given.len(), ADMISSIONS);
        assert_eq!(
            submission.poll(&mut disk),
            Some(Err(BlockError::Device { status: 17 }))
        );
        assert_eq!(disk.given.len(), ADMISSIONS);
        assert_eq!(disk.taken, ADMISSIONS - usize::from(!completion));
        assert!(disk.done.is_empty());
        assert!(
            !disk
                .given
                .iter()
                .any(|command| matches!(command, Command::Flush))
        );
        check(&mut disk.disk, ADMISSIONS - 1, 0xa5);
    }
}
