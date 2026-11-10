//! The case and result records `runner.c` reads and writes, and the
//! canonical one-line outcome both back ends are compared by.
use std::fmt::Write as _;

pub const WORDS: usize = 32;
pub const MEMORY: usize = 256;
pub const INPUT_BYTES: usize = 1184;
pub const OUTPUT_BYTES: usize = 1064;
const STATE_BYTES: usize = 784;

/// The architectural state a case starts or ends with.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct State {
    pub x: [u64; 31],
    pub nzcv: u64,
    pub fpcr: u64,
    pub fpsr: u64,
    pub v: [[u64; 2]; 32],
}

/// One case: A64 words that neither touch SP nor branch outside
/// themselves, the state they start from and a 256-byte buffer that the
/// registers in `memory_registers` point into, as offsets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Case {
    pub name: String,
    pub words: Vec<u32>,
    pub state: State,
    pub memory: [u8; MEMORY],
    pub memory_registers: u32,
}

impl Case {
    pub fn new(name: impl Into<String>, words: &[u32]) -> Self {
        Self {
            name: name.into(),
            words: words.to_vec(),
            state: State::default(),
            memory: [0; MEMORY],
            memory_registers: 0,
        }
    }

    pub fn x(mut self, register: usize, value: u64) -> Self {
        self.state.x[register] = value;
        self
    }

    pub fn v(mut self, register: usize, low: u64, high: u64) -> Self {
        self.state.v[register] = [low, high];
        self
    }

    pub fn fpcr(mut self, fpcr: u64) -> Self {
        self.state.fpcr = fpcr;
        self
    }

    pub fn nzcv(mut self, nzcv: u64) -> Self {
        self.state.nzcv = nzcv;
        self
    }

    /// `register` holds `offset` into the buffer, which holds `memory`.
    pub fn memory(mut self, register: usize, offset: u64, memory: &[u8]) -> Self {
        self.memory[..memory.len()].copy_from_slice(memory);
        self.memory_registers |= 1 << register;
        self.state.x[register] = offset;
        self
    }

    pub fn encode(&self) -> [u8; INPUT_BYTES] {
        assert!(self.words.len() <= WORDS, "{}", self.name);
        let mut bytes = [0; INPUT_BYTES];
        bytes[0..4].copy_from_slice(&(self.words.len() as u32).to_le_bytes());
        bytes[4..8].copy_from_slice(&self.memory_registers.to_le_bytes());
        for (index, word) in self.words.iter().enumerate() {
            bytes[8 + 4 * index..12 + 4 * index].copy_from_slice(&word.to_le_bytes());
        }
        encode_state(&self.state, &mut bytes[144..144 + STATE_BYTES]);
        bytes[928..].copy_from_slice(&self.memory);
        bytes
    }
}

fn encode_state(state: &State, bytes: &mut [u8]) {
    let mut put = |offset: usize, value: u64| {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    };
    for (index, value) in state.x.iter().enumerate() {
        put(8 * index, *value);
    }
    put(248, state.nzcv);
    put(256, state.fpcr);
    put(264, state.fpsr);
    for (index, [low, high]) in state.v.iter().enumerate() {
        put(272 + 16 * index, *low);
        put(280 + 16 * index, *high);
    }
}

fn decode_state(bytes: &[u8]) -> State {
    let get = |offset: usize| u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
    State {
        x: std::array::from_fn(|index| get(8 * index)),
        nzcv: get(248),
        fpcr: get(256),
        fpsr: get(264),
        v: std::array::from_fn(|index| [get(272 + 16 * index), get(280 + 16 * index)]),
    }
}

/// How a case ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ending {
    Completed {
        state: Box<State>,
        memory: Box<[u8; MEMORY]>,
    },
    /// A signal at the case's `index`th word: SIGILL for an UNDEFINED
    /// instruction or a trapped FP exception.
    Signal { name: &'static str, index: u64 },
    /// What the back end reported instead.
    Other(String),
}

/// A runner output record.
pub fn decode_output(bytes: &[u8]) -> Ending {
    assert_eq!(bytes.len(), OUTPUT_BYTES);
    let signal = i32::from_le_bytes(bytes[1040..1044].try_into().unwrap());
    let pc = u64::from_le_bytes(bytes[1056..1064].try_into().unwrap());
    if signal != 0 {
        return Ending::Signal {
            name: signal_name(signal),
            index: pc / 4,
        };
    }
    Ending::Completed {
        state: Box::new(decode_state(&bytes[..STATE_BYTES])),
        memory: Box::new(bytes[STATE_BYTES..STATE_BYTES + MEMORY].try_into().unwrap()),
    }
}

/// macOS signal numbers.
fn signal_name(signal: i32) -> &'static str {
    match signal {
        4 => "SIGILL",
        5 => "SIGTRAP",
        8 => "SIGFPE",
        10 => "SIGBUS",
        11 => "SIGSEGV",
        _ => "signal",
    }
}

/// The canonical outcome: each register and buffer range that changed, or
/// the signal, so that equal behaviour gives equal text on every back end.
pub fn outcome(case: &Case, ending: &Ending) -> String {
    let (state, memory) = match ending {
        Ending::Completed { state, memory } => (state, memory),
        Ending::Signal { name, index } => return format!("{name}@{index}"),
        Ending::Other(detail) => return format!("other:{}", detail.replace(['\t', '\n'], " ")),
    };
    let before = &case.state;
    let mut text = String::new();
    let mut field = |name: &str, value: String| {
        if !text.is_empty() {
            text.push(' ');
        }
        let _ = write!(text, "{name}={value}");
    };
    for (index, (old, new)) in before.x.iter().zip(&state.x).enumerate() {
        if old != new {
            field(&format!("x{index}"), format!("{new:#x}"));
        }
    }
    for (name, old, new) in [
        ("nzcv", before.nzcv, state.nzcv),
        ("fpcr", before.fpcr, state.fpcr),
        ("fpsr", before.fpsr, state.fpsr),
    ] {
        if old != new {
            field(name, format!("{new:#x}"));
        }
    }
    for (index, (old, new)) in before.v.iter().zip(&state.v).enumerate() {
        if old != new {
            field(&format!("v{index}"), format!("{:#x}:{:#x}", new[0], new[1]));
        }
    }
    let mut offset = 0;
    while offset < MEMORY {
        if case.memory[offset] == memory[offset] {
            offset += 1;
            continue;
        }
        let start = offset;
        while offset < MEMORY && case.memory[offset] != memory[offset] {
            offset += 1;
        }
        let bytes: String = memory[start..offset]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        field(&format!("m{start}"), bytes);
    }
    if text.is_empty() { "-".into() } else { text }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_case_encodes_at_the_runners_offsets() {
        let case = Case::new("probe", &[0xd503_201f])
            .x(30, 0x1234)
            .v(31, 5, 6)
            .fpcr(0x0040_0000)
            .memory(1, 8, &[0xaa]);
        let bytes = case.encode();
        assert_eq!(&bytes[0..4], &1u32.to_le_bytes());
        assert_eq!(&bytes[4..8], &2u32.to_le_bytes());
        assert_eq!(&bytes[144 + 240..144 + 248], &0x1234u64.to_le_bytes());
        assert_eq!(&bytes[144 + 256..144 + 264], &0x0040_0000u64.to_le_bytes());
        assert_eq!(
            &bytes[144 + 272 + 496..144 + 280 + 496],
            &5u64.to_le_bytes()
        );
        assert_eq!(bytes[928], 0xaa);
        assert_eq!(decode_state(&bytes[144..144 + STATE_BYTES]), case.state);
    }

    #[test]
    fn outcomes_name_only_what_changed() {
        let case = Case::new("probe", &[]).x(1, 1).memory(2, 0, &[1, 2, 3]);
        let mut state = case.state;
        state.x[1] = 0x10;
        state.fpsr = 2;
        let mut memory = case.memory;
        memory[1] = 9;
        memory[2] = 8;
        let ending = Ending::Completed {
            state: Box::new(state),
            memory: Box::new(memory),
        };
        assert_eq!(outcome(&case, &ending), "x1=0x10 fpsr=0x2 m1=0908");
        assert_eq!(
            outcome(
                &case,
                &Ending::Signal {
                    name: "SIGILL",
                    index: 2
                }
            ),
            "SIGILL@2"
        );
    }
}
