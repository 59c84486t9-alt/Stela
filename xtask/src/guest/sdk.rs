//! The kernel SDK the guest kexts compile against: xnu's headers from
//! `third_party/xnu`, plus what Apple's SDK build generates beside them.
//!
//! - `DriverKit/<Class>.h` for each `iokit/DriverKit/<Class>.iig`. In a kernel
//!   build iig keeps an interface's declarations outside its classes and
//!   turns each class it compiles into `<Class>_Methods` and
//!   `<Class>_KernelMethods`, which xnu's own class declarations expand.
//!   Of those methods only the `Dispatch` override is virtual, so it is the
//!   only one these headers declare: a kext never calls the rest, and every
//!   vtable keeps the kernel's layout.
//! - The Mach interface headers MIG generates, which `mach/mach_interface.h`
//!   includes for user-side RPC stubs a kext does not call: empty.
//! - `TargetConditionals.h`, which Libc supplies, for macOS on arm64.
//! - `string.h`, which the kernel SDK takes from xnu's `libsa`.
//! - `stela/gate.h`: the gate window's layout from [`window`].
use anyhow::{Context, Result, bail};
use std::{fmt::Write as _, fs, path::Path};
use stela_contracts::gate::window;

/// The MIG interfaces `mach/mach_interface.h` includes.
const MIG_INTERFACES: [&str; 16] = [
    "clock",
    "clock_priv",
    "clock_reply_server",
    "exc_server",
    "host_priv",
    "host_security",
    "mach_exc_server",
    "mach_host",
    "mach_port",
    "notify_server",
    "processor",
    "processor_set",
    "task",
    "thread_act",
    "vm_map",
    "upl",
];

const TARGET_CONDITIONALS: &str = "\
#ifndef __TARGETCONDITIONALS__
#define __TARGETCONDITIONALS__
#define TARGET_OS_MAC 1
#define TARGET_OS_OSX 1
#define TARGET_OS_IPHONE 0
#define TARGET_OS_IOS 0
#define TARGET_OS_WATCH 0
#define TARGET_OS_TV 0
#define TARGET_OS_BRIDGE 0
#define TARGET_OS_VISION 0
#define TARGET_OS_MACCATALYST 0
#define TARGET_OS_DRIVERKIT 0
#define TARGET_OS_SIMULATOR 0
#define TARGET_OS_EMBEDDED 0
#define TARGET_OS_EXCLAVECORE 0
#define TARGET_OS_EXCLAVEKIT 0
#define TARGET_CPU_ARM64 1
#define TARGET_CPU_X86_64 0
#define TARGET_RT_LITTLE_ENDIAN 1
#define TARGET_RT_64_BIT 1
#endif
";

/// Writes the generated headers for `xnu` into `include`.
pub fn generate(xnu: &Path, include: &Path) -> Result<()> {
    if include.exists() {
        fs::remove_dir_all(include)?;
    }
    let driverkit = include.join("DriverKit");
    fs::create_dir_all(&driverkit)?;
    let interfaces = xnu.join("iokit/DriverKit");
    for entry in fs::read_dir(&interfaces)
        .with_context(|| format!("{} (run `cargo xtask gpu fetch`)", interfaces.display()))?
    {
        let path = entry?.path();
        if path.extension().is_some_and(|extension| extension == "iig") {
            let source = fs::read_to_string(&path)?;
            let header = kernel_header(&source)
                .with_context(|| format!("cannot generate from {}", path.display()))?;
            let stem = path.file_stem().unwrap();
            fs::write(driverkit.join(stem).with_extension("h"), header)?;
        }
    }
    let mach = include.join("mach");
    fs::create_dir_all(&mach)?;
    for interface in MIG_INTERFACES {
        let header = format!(
            "/* The MIG interface `{interface}` has no kernel-side callers in a kext. */\n"
        );
        fs::write(mach.join(interface).with_extension("h"), header)?;
    }
    fs::write(include.join("TargetConditionals.h"), TARGET_CONDITIONALS)?;
    fs::copy(xnu.join("osfmk/libsa/string.h"), include.join("string.h"))?;
    let stela = include.join("stela");
    fs::create_dir_all(&stela)?;
    fs::write(stela.join("gate.h"), gate_header())?;
    Ok(())
}

/// The kernel header iig generates from an interface: its source with the
/// classes it compiles replaced by their method macros, and its `.iig`
/// includes by their headers.
pub fn kernel_header(source: &str) -> Result<String> {
    let mut header = String::new();
    let mut classes = Vec::new();
    let mut rest = source;
    while let Some(start) = class_definition(rest) {
        header.push_str(&rest[..start]);
        let (name, length) = class_extent(&rest[start..])?;
        classes.push(name);
        rest = &rest[start + length..];
    }
    header.push_str(rest);
    let mut header = header.replace(".iig>", ".h>");
    for class in classes {
        writeln!(
            header,
            "#define {class}_Methods public: \
             virtual kern_return_t Dispatch(const IORPC rpc) APPLE_KEXT_OVERRIDE; \
             static kern_return_t _Dispatch({class} * self, const IORPC rpc);\n\
             #define {class}_KernelMethods"
        )?;
    }
    Ok(header)
}

/// The offset of the next line-leading `class` that opens a body, skipping
/// forward declarations.
fn class_definition(source: &str) -> Option<usize> {
    let mut offset = 0;
    loop {
        let found = source[offset..].find("class ")? + offset;
        let at_line_start = found == 0 || source.as_bytes()[found - 1] == b'\n';
        let rest = &source[found..];
        let opens = rest.find('{');
        if at_line_start
            && opens.is_some_and(|opens| rest.find(';').is_none_or(|ends| opens < ends))
        {
            return Some(found);
        }
        offset = found + "class ".len();
    }
}

/// A class definition's name and length through its closing `};`, skipping
/// comments and literals while matching braces.
fn class_extent(definition: &str) -> Result<(String, usize)> {
    let opens = definition.find('{').unwrap();
    let head = &definition["class ".len()..opens];
    let head = head.split(':').next().unwrap();
    // Annotations precede the name; a parenthesized one takes arguments.
    let name = without_parentheses(head)
        .split_whitespace()
        .last()
        .context("a class without a name")?
        .to_owned();
    let bytes = definition.as_bytes();
    let (mut depth, mut index) = (0usize, opens);
    while index < bytes.len() {
        match bytes[index] {
            b'/' if bytes.get(index + 1) == Some(&b'/') => {
                index = definition[index..]
                    .find('\n')
                    .map_or(bytes.len(), |end| index + end);
            }
            b'/' if bytes.get(index + 1) == Some(&b'*') => {
                index = definition[index + 2..]
                    .find("*/")
                    .map_or(bytes.len(), |end| index + 2 + end + 1);
            }
            quote @ (b'"' | b'\'') => {
                index += 1;
                while index < bytes.len() && bytes[index] != quote {
                    index += usize::from(bytes[index] == b'\\') + 1;
                }
            }
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    let ends = definition[index..]
                        .find(';')
                        .context("a class body without its `;`")?;
                    return Ok((name, index + ends + 1));
                }
            }
            _ => {}
        }
        index += 1;
    }
    bail!("class {name} never closes")
}

fn without_parentheses(text: &str) -> String {
    let mut depth = 0usize;
    text.chars()
        .filter(|&character| {
            match character {
                '(' => depth += 1,
                ')' => depth -= 1,
                _ => return depth == 0,
            }
            false
        })
        .collect()
}

fn gate_header() -> String {
    let mut header = String::from(
        "/* The StelaGPU gate window's layout, from stela_contracts::gate::window. */\n\
         #pragma once\n",
    );
    for (name, value) in window::LAYOUT {
        writeln!(header, "#define STELA_GATE_{name} {value:#x}ULL").unwrap();
    }
    header
}

#[cfg(test)]
mod tests {
    use super::*;

    const INTERFACE: &str = r#"#include <DriverKit/OSAction.iig>
class OSAction;
class IIG_SERIALIZABLE OSData;
enum { kCount = 16 };
/* class Hidden { }; */
class KERNEL Widget : public OSObject
{
public:
    /* braces in comments: { */
    virtual kern_return_t Start(IOService * provider) LOCAL; // }
    char brace = '}';
};
class EXTENDS (Widget) WidgetPrivate
{
    void Local() LOCALONLY;
};
typedef int After;
"#;

    #[test]
    fn classes_become_their_method_macros() {
        let header = kernel_header(INTERFACE).unwrap();
        assert!(header.starts_with("#include <DriverKit/OSAction.h>\nclass OSAction;\n"));
        assert!(header.contains("class IIG_SERIALIZABLE OSData;\nenum { kCount = 16 };\n"));
        assert!(header.contains("/* class Hidden { }; */\n\n\ntypedef int After;\n"));
        assert!(!header.contains("Start("));
        assert!(header.contains(
            "#define Widget_Methods public: virtual kern_return_t Dispatch(const IORPC rpc) \
             APPLE_KEXT_OVERRIDE; static kern_return_t _Dispatch(Widget * self, const IORPC rpc);\n\
             #define Widget_KernelMethods\n"
        ));
        assert!(header.contains("#define WidgetPrivate_KernelMethods\n"));
    }

    #[test]
    fn an_unclosed_class_is_refused() {
        assert!(kernel_header("class KERNEL Widget : public OSObject\n{\n").is_err());
    }

    #[test]
    fn the_gate_header_names_every_register() {
        let header = gate_header();
        assert!(header.contains("#define STELA_GATE_PAGE 0x4000ULL\n"));
        assert!(header.contains("#define STELA_GATE_ACK 0x28ULL\n"));
    }
}
