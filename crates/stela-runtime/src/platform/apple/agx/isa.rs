//! The AGX G14G (Apple G14, "AGX2") shader ISA: the instruction set the
//! userspace `AGXMetalG14G` driver compiles Metal shaders into at run time.
//!
//! The encodings come from Mesa's machine-readable description
//! `src/asahi/isa/AGX2.xml` (pinned `a2b6d5096ebee791427214cba47282788ef4e048`,
//! MIT), turned into static tables by `cargo xtask agx-isa`
//! ([`generated`], shaped by [`spec`]). [`decode`] matches words against the
//! tables and reads their operands; [`disasm`] prints them exactly as Mesa's
//! disassembler does and is checked against every vector of that tree's
//! `isa/test/cases.txt`. Nothing outside the description decodes: an
//! unmatched word, an unnamed bit, an operand no encoding case covers or an
//! enumeration value the description lacks refuses (docs/research/agx.md
//! §5.2, ISA-1 and ISA-2).

#[cfg(test)]
pub mod assemble;
pub mod decode;
pub mod disasm;
pub mod float;
pub mod generated;
pub mod spec;
