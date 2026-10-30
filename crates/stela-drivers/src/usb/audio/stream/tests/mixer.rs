// SPDX-License-Identifier: GPL-2.0-or-later
//! A descriptor-advertised hardware mixer composes with PCM/DMA ownership.
use super::*;

struct MixerDevice {
    transport: Model,
    gain: i16,
    writes: usize,
}
impl Control for MixerDevice {
    fn now_us(&self) -> u64 {
        self.transport.now_us()
    }
    fn relax(&mut self) {
        self.transport.relax();
    }
    fn control(&mut self, r: [u8; 8], out: &[u8]) -> Result<Vec<u8>, BlockError> {
        if r[5] != 6 {
            return self.transport.control(r, out);
        }
        assert_eq!((r[3], r[2], r[4]), (1, 1, 0));
        if r[0] == 0x21 {
            assert_eq!(r[1], 1);
            self.gain = i16::from_le_bytes(out.try_into().unwrap());
            self.writes += 1;
            return Ok(Vec::new());
        }
        assert_eq!(r[0], 0xa1);
        let data = if r[1] == 1 {
            self.gain.to_le_bytes().to_vec()
        } else {
            assert_eq!(r[1], 2);
            vec![1, 0, 0, 0xc0, 0, 0, 0, 1]
        };
        let n = usize::from(u16::from_le_bytes([r[6], r[7]]));
        Ok(data[..n.min(data.len())].to_vec())
    }
}
impl Transport for MixerDevice {
    // Independent in-memory device peer; it owns no native attachment.
    fn validate(&self) -> Result<(), BlockError> {
        Ok(())
    }
    type Ticket = u64;
    fn preflight(&mut self, e: &[Endpoint]) -> Result<(), BlockError> {
        self.transport.preflight(e)
    }
    fn configure(&mut self, o: Direction, e: &[Endpoint]) -> Result<(), BlockError> {
        self.transport.configure(o, e)
    }
    fn deconfigure(&mut self, o: Direction, e: &[Endpoint]) -> Result<(), BlockError> {
        self.transport.deconfigure(o, e)
    }
    fn submit(&mut self, e: &Endpoint, p: u64, n: usize) -> Result<u64, BlockError> {
        self.transport.submit(e, p, n)
    }
    fn completed(&mut self, t: &u64) -> Option<Result<Completion, BlockError>> {
        self.transport.completed(t)
    }
}
#[test]
fn descriptor_selected_mixer_controls_and_pcm_share_the_live_native_transport_owner() {
    let mut c = configuration();
    let header = c.windows(5).position(|d| d == [9, 0x24, 1, 0, 2]).unwrap();
    let speaker = c.windows(4).position(|d| d == [12, 0x24, 3, 3]).unwrap();
    c[speaker + 7] = 6;
    let at = c
        .windows(9)
        .position(|d| d == [9, 4, 1, 0, 0, 1, 2, 0x20, 0])
        .unwrap();
    c.splice(
        at..at,
        [16, 0x24, 4, 6, 2, 1, 4, 2, 3, 0, 0, 0, 0, 0x91, 0, 0],
    );
    let total = u16::from_le_bytes([c[header + 6], c[header + 7]]) + 16;
    c[header + 6..header + 8].copy_from_slice(&total.to_le_bytes());
    let total = c.len() as u16;
    c[2..4].copy_from_slice(&total.to_le_bytes());
    let all = interfaces(&c);
    let binding = Binding::parse(&all[0], &all, &c, 3).unwrap();
    assert_eq!(binding.graph.signal_cluster(6), Ok((2, 3)));
    let mut memory = vec![0u64; 256 * 1024];
    let base = memory.as_mut_ptr() as u64;
    // SAFETY: this exclusive backing outlives the PCM device and all tickets.
    let mut dma = unsafe { RegionAllocator::new(base..base + memory.len() as u64 * 8) };
    let transport = MixerDevice {
        transport: Model::new(),
        gain: 0,
        writes: 0,
    };
    let mut a = AudioDevice::new(transport, binding, &mut dma).unwrap();
    a.set_mixer_volume(6, 1, 1, -256).unwrap();
    assert_eq!(a.mixer_volume(6, 1, 1), Ok(-256));
    // Probing writes the minimum, one step and the saved value first.
    assert_eq!(a.transport.writes, 4);
    let pcm: Vec<u8> = (0..6144).map(|n| n as u8).collect();
    a.start_playback(0, 48000, &pcm, true).unwrap();
    a.start_capture(1, 48000).unwrap();
    for _ in 0..3 {
        a.poll().unwrap();
        if a.progress.playback_drained {
            break;
        }
    }
    assert_eq!(a.transport.transport.output, pcm);
    assert!(a.progress.capture_frames > 0);
    a.transport.transport.cancel_fail = true;
    let pending = a.transport.transport.pending.len();
    assert!(pending > 0);
    assert_eq!(a.stop_capture(), Err(Error::Poisoned));
    assert_eq!(a.transport.transport.pending.len(), pending);
    assert_eq!(a.set_mixer_volume(6, 1, 1, 0), Err(Error::Poisoned));
    a.transport.transport.cancel_fail = false;
    a.shutdown().unwrap();
    assert!(a.transport.transport.pending.is_empty());
}
