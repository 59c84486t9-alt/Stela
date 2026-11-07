//! What the Mac's toolchain and SDK declare, and the tests that the suite
//! reaches every part of it within scope: the MSL standard library's
//! public functions, each named by some library a case compiles, and the
//! Metal framework's selectors and properties, each sent by the runner.
//!
//! `probe` copies the toolchain's `metal` headers into DIR/headers and the
//! SDK's Metal.framework headers into DIR/framework, and records each
//! header's functions in availability.json under `functions` and each
//! header's classes and protocols, with their selectors and properties,
//! under `api`. A function no corpus source or generated library names, or
//! a selector runner.m never sends, fails its test unless the tables below
//! leave it out, with the reason; a table entry that leaves nothing out
//! fails too.
//!
//! Selectors are matched by name, not by receiver: a selector two classes
//! declare counts as sent to both once the runner sends it to either.
use anyhow::{Context, Result};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

/// Each header's functions, by its path under the headers' root.
pub type Inventory = BTreeMap<String, BTreeSet<String>>;

/// Each framework header's classes and protocols, with their selectors
/// (`+` before a class method's) and properties (`.name`, then
/// `|getter` when it has its own).
pub type Api = BTreeMap<String, BTreeMap<String, BTreeSet<String>>>;

/// Headers whose every function lies outside the suite's scope.
#[cfg(test)]
const HEADERS_LEFT_OUT: [(&str, &str); 7] = [
    ("metal_raytracing", "ray tracing is not claimed"),
    (
        "metal_tensor",
        "tensors belong to the Metal4 family, left out",
    ),
    (
        "metal_cooperative_tensor",
        "tensors belong to the Metal4 family, left out",
    ),
    (
        "metal_packed_numeric",
        "the packed numeric formats tensors hold",
    ),
    ("metal_imageblocks", "imageblocks are left out"),
    (
        "extents.h",
        "the extents of tensors, which belong to the Metal4 family",
    ),
    (
        "units.h",
        "the execution scopes of tensor operations, which belong to the Metal4 family",
    ),
];

/// Functions outside the suite's scope, in headers that are otherwise in it.
#[cfg(test)]
const FUNCTIONS_LEFT_OUT: [(&str, &str); 31] = [
    ("sparse_color", "sparse textures are left out"),
    ("sparse_gather", "sparse textures are left out"),
    ("sparse_gather_compare", "sparse textures are left out"),
    ("sparse_read", "sparse textures are left out"),
    ("sparse_sample", "sparse textures are left out"),
    ("sparse_sample_compare", "sparse textures are left out"),
    ("set_imageblock_size", "imageblocks are left out"),
    (
        "rasterization_rate_map_decoder",
        "rasterization rate maps are left out",
    ),
    (
        "map_physical_to_screen_coordinates",
        "rasterization rate maps are left out",
    ),
    (
        "map_screen_to_physical_coordinates",
        "rasterization rate maps are left out",
    ),
    ("function_handle", "function handles exist for ray tracing"),
    (
        "is_null_function_handle",
        "function handles exist for ray tracing",
    ),
    (
        "atomic_min",
        "64-bit atomic min and max need Apple8, which is not claimed",
    ),
    (
        "atomic_max",
        "64-bit atomic min and max need Apple8, which is not claimed",
    ),
    (
        "atomic_min_explicit",
        "64-bit atomic min and max need Apple8, which is not claimed",
    ),
    (
        "atomic_max_explicit",
        "64-bit atomic min and max need Apple8, which is not claimed",
    ),
    (
        "interleave",
        "needs a GPU family the M1 Pro reference lacks and Stela does not claim",
    ),
    (
        "deinterleave",
        "needs a GPU family the M1 Pro reference lacks and Stela does not claim",
    ),
    (
        "yield_simdgroup",
        "needs GPU family 11, which the M1 Pro reference lacks and Stela does not claim",
    ),
    (
        "atomic_wait_simdgroup",
        "needs a GPU family the M1 Pro reference lacks and Stela does not claim",
    ),
    (
        "atomic_wait_explicit_simdgroup",
        "needs a GPU family the M1 Pro reference lacks and Stela does not claim",
    ),
    (
        "atomic_wait_value_simdgroup",
        "needs a GPU family the M1 Pro reference lacks and Stela does not claim",
    ),
    (
        "atomic_wait_value_explicit_simdgroup",
        "needs a GPU family the M1 Pro reference lacks and Stela does not claim",
    ),
    (
        "atomic_notify_one_simdgroup",
        "needs a GPU family the M1 Pro reference lacks and Stela does not claim",
    ),
    (
        "atomic_notify_all_simdgroup",
        "needs a GPU family the M1 Pro reference lacks and Stela does not claim",
    ),
    (
        "atomic_wait_with_predicate_explicit_simdgroup",
        "needs a GPU family the M1 Pro reference lacks and Stela does not claim",
    ),
    (
        "critical_section",
        "needs GPU family 11, which the M1 Pro reference lacks and Stela does not claim",
    ),
    ("sparse_block_read", "sparse textures are left out"),
    (
        "pack",
        "how the pixel types store their values, not a function a shader calls",
    ),
    (
        "unpack",
        "how the pixel types store their values, not a function a shader calls",
    ),
    (
        "decltype",
        "a keyword the header's declarations use, not a function",
    ),
];

fn identifier(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// The public functions a header declares: the name before the opening
/// parenthesis of each `METAL_FUNC` declaration (outside its return
/// type's template arguments), leaving out operators,
/// internal names (a leading underscore) and macros (no lower case).
pub fn functions(text: &str) -> BTreeSet<String> {
    let text: String = text
        .lines()
        .map(|line| line.split("//").next().unwrap_or_default())
        .collect::<Vec<_>>()
        .join("\n");
    let mut names = BTreeSet::new();
    for (at, _) in text.match_indices("METAL_FUNC") {
        let before = text[..at].chars().next_back();
        let rest = &text[at + "METAL_FUNC".len()..];
        if before.is_some_and(identifier) || rest.starts_with(identifier) {
            continue;
        }
        // The first parenthesis outside template arguments, which a
        // return type such as `enable_if_t<f(W, H), T>` may hold.
        let mut depth = 0usize;
        let Some(open) = rest.find(|c: char| {
            match c {
                '<' => depth += 1,
                '>' => depth = depth.saturating_sub(1),
                _ => {}
            }
            depth == 0 && matches!(c, '(' | ';' | '{')
        }) else {
            continue;
        };
        let declaration = &rest[..open];
        if !rest[open..].starts_with('(') || declaration.contains("operator") {
            continue;
        }
        let name = declaration
            .trim_end()
            .rsplit(|c: char| !identifier(c))
            .next()
            .unwrap_or_default();
        if !name.is_empty()
            && !name.starts_with('_')
            && !name.starts_with(|c: char| c.is_ascii_digit())
            && name.contains(|c: char| c.is_ascii_lowercase())
        {
            names.insert(name.to_string());
        }
    }
    names
}

/// The functions of every header under `root`.
pub fn inventory(root: &Path) -> Result<Inventory> {
    let mut out = Inventory::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(&dir).with_context(|| dir.display().to_string())? {
            let path = entry?.path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            let text = fs::read(&path).with_context(|| path.display().to_string())?;
            let names = functions(&String::from_utf8_lossy(&text));
            if !names.is_empty() {
                let key = path
                    .strip_prefix(root)?
                    .to_string_lossy()
                    .replace('\\', "/");
                out.insert(key, names);
            }
        }
    }
    Ok(out)
}

/// The text with comments dropped and string and character literals
/// emptied, so that neither reads as code.
fn code(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '/' if chars.peek() == Some(&'/') => {
                for c in chars.by_ref() {
                    if c == '\n' {
                        out.push('\n');
                        break;
                    }
                }
            }
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                let mut last = ' ';
                for c in chars.by_ref() {
                    if last == '*' && c == '/' {
                        break;
                    }
                    last = c;
                }
                out.push(' ');
            }
            '"' | '\'' => {
                let mut escaped = false;
                for d in chars.by_ref() {
                    if escaped {
                        escaped = false;
                    } else if d == '\\' {
                        escaped = true;
                    } else if d == c {
                        break;
                    }
                }
                out.push(c);
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

/// The text with every parenthesized group left out.
fn unparen(text: &str) -> String {
    let mut depth = 0usize;
    text.chars()
        .filter(|&c| match c {
            '(' => {
                depth += 1;
                false
            }
            ')' => {
                depth = depth.saturating_sub(1);
                false
            }
            _ => depth == 0,
        })
        .collect()
}

/// The prefixes of the availability and naming macros that trail
/// framework declarations.
const MACROS: [&[u8]; 3] = [b"API_", b"NS_", b"MTL_"];

/// Where the declaration's trailing availability and naming macros begin:
/// the first upper-case `API_`, `NS_` or `MTL_` word outside parentheses,
/// which must open a parenthesis of its own when `called`.
fn macros_at(d: &str, called: bool) -> usize {
    let bytes = d.as_bytes();
    let mut depth = 0usize;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => depth = depth.saturating_sub(1),
            _ if depth == 0
                && (i == 0 || !identifier(bytes[i - 1] as char))
                && MACROS.iter().any(|p| bytes[i..].starts_with(p)) =>
            {
                let end = bytes[i..]
                    .iter()
                    .position(|&b| !(b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_'))
                    .map_or(bytes.len(), |n| i + n);
                if !d[end..].starts_with(identifier)
                    && (!called || d[end..].trim_start().starts_with('('))
                {
                    return i;
                }
                i = end;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    d.len()
}

/// Whether a declaration says it is unavailable on macOS.
fn unavailable(d: &str) -> bool {
    d.contains("NS_UNAVAILABLE")
        || d.match_indices("API_UNAVAILABLE(").any(|(at, m)| {
            let args = &d[at + m.len()..];
            args[..args.find(')').unwrap_or(args.len())]
                .split(',')
                .any(|a| a.trim() == "macos")
        })
}

/// The selector a method declaration or definition head declares, from
/// its leading `-` or `+`: its keywords, or its one name.
fn selector(d: &str) -> Option<String> {
    let text = unparen(&d[..macros_at(d, true)]);
    let text = text.get(1..)?;
    let mut keywords = String::new();
    let mut rest = text;
    while let Some(at) = rest.find(identifier) {
        let tail = &rest[at..];
        let word = &tail[..tail.find(|c: char| !identifier(c)).unwrap_or(tail.len())];
        let after = tail[word.len()..].trim_start();
        if after.starts_with(':') {
            keywords.push_str(word);
            keywords.push(':');
        }
        rest = &tail[word.len()..];
    }
    if !keywords.is_empty() {
        return Some(keywords);
    }
    let word: String = text
        .trim_start()
        .chars()
        .take_while(|&c| identifier(c))
        .collect();
    (!word.is_empty() && !word.starts_with(|c: char| c.is_ascii_digit())).then_some(word)
}

/// The entry a property declaration declares: `.name`, then `|getter`
/// when it names one.
fn property(d: &str) -> Option<String> {
    let mut rest = d["@property".len()..].trim_start();
    let mut getter = None;
    if rest.starts_with('(') {
        let close = rest.find(')')?;
        getter = rest[1..close]
            .split(',')
            .find_map(|a| a.trim().strip_prefix("getter"))
            .and_then(|g| g.trim_start().strip_prefix('='))
            .map(|g| g.trim().to_string());
        rest = &rest[close + 1..];
    }
    let mut rest = rest[..macros_at(rest, false)].trim_end();
    if rest.ends_with(']') {
        rest = rest[..rest.rfind('[')?].trim_end();
    }
    let name = &rest[rest.trim_end_matches(identifier).len()..];
    if name.is_empty() || name.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    Some(match getter {
        Some(g) => format!(".{name}|{g}"),
        None => format!(".{name}"),
    })
}

/// The classes and protocols a framework header declares, each with its
/// selectors and properties available on macOS.
pub fn declarations(text: &str) -> BTreeMap<String, BTreeSet<String>> {
    let text = code(text);
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut at = 0;
    while let Some(found) = ["@interface", "@protocol"]
        .iter()
        .filter_map(|k| text[at..].find(k).map(|n| (at + n, k.len())))
        .min()
    {
        let (start, length) = found;
        let rest = &text[start + length..];
        let name: String = rest
            .trim_start()
            .chars()
            .take_while(|&c| identifier(c))
            .collect();
        let after = rest.trim_start()[name.len()..].trim_start();
        // A forward declaration, or `@protocol(Name)` in an expression.
        if name.is_empty() || after.starts_with([';', ',']) {
            at = start + length;
            continue;
        }
        let end = rest.find("@end").map_or(text.len(), |n| start + length + n);
        let body = &text[start + length..end];
        // The header line, which may hold superclasses and protocols.
        let body = &body[body.find('\n').unwrap_or(body.len())..];
        for d in body.split(';') {
            let d = d.split_whitespace().collect::<Vec<_>>().join(" ");
            let begin = d.find("@property").or_else(|| {
                d.char_indices().find_map(|(i, c)| {
                    ((c == '-' || c == '+') && d[i + 1..].trim_start().starts_with('('))
                        .then_some(i)
                })
            });
            let Some(begin) = begin else { continue };
            let d = &d[begin..];
            if unavailable(d) {
                continue;
            }
            let entry = if d.starts_with("@property") {
                property(d)
            } else {
                selector(d).map(|s| {
                    if d.starts_with('+') {
                        format!("+{s}")
                    } else {
                        s
                    }
                })
            };
            if let Some(entry) = entry {
                out.entry(name.clone()).or_default().insert(entry);
            }
        }
        at = end;
    }
    out
}

/// The declarations of every framework header under `root`.
pub fn framework(root: &Path) -> Result<Api> {
    let mut out = Api::new();
    for entry in fs::read_dir(root).with_context(|| root.display().to_string())? {
        let path = entry?.path();
        if path.extension().is_none_or(|e| e != "h") {
            continue;
        }
        let text = fs::read(&path).with_context(|| path.display().to_string())?;
        let classes = declarations(&String::from_utf8_lossy(&text));
        if !classes.is_empty() {
            out.insert(
                path.file_name().unwrap().to_string_lossy().to_string(),
                classes,
            );
        }
    }
    Ok(out)
}

/// What Objective-C source sends: the selectors of its message sends and
/// of the methods it defines, and every name it reads after a `.`.
#[cfg(test)]
pub fn sends(text: &str) -> (BTreeSet<String>, BTreeSet<String>) {
    /// An open bracket, parenthesis or brace: its kind, the keywords and
    /// names at its top level, and the ternaries open in it.
    struct Frame {
        open: char,
        keywords: Vec<String>,
        names: usize,
        last: String,
        ternaries: usize,
    }
    let text = code(text);
    let mut selectors = BTreeSet::new();
    let mut dotted = BTreeSet::new();
    // Method definitions, one per line beginning with `-` or `+`.
    for line in text.lines() {
        if line.starts_with("- (") || line.starts_with("+ (") {
            let head = &line[..line.find('{').unwrap_or(line.len())];
            selectors.extend(selector(head));
        }
    }
    let chars: Vec<char> = text.chars().collect();
    let mut frames: Vec<Frame> = Vec::new();
    let mut i = 0;
    let mut after_dot = false;
    while i < chars.len() {
        let c = chars[i];
        if identifier(c) {
            let start = i;
            while i < chars.len() && identifier(chars[i]) {
                i += 1;
            }
            if c.is_ascii_digit() {
                after_dot = false;
                continue;
            }
            let word: String = chars[start..i].iter().collect();
            if after_dot {
                dotted.insert(word.clone());
            }
            after_dot = false;
            let mut j = i;
            while j < chars.len() && chars[j].is_whitespace() {
                j += 1;
            }
            let keyword = chars.get(j) == Some(&':') && chars.get(j + 1) != Some(&':');
            if let Some(f) = frames.last_mut() {
                if keyword && f.ternaries > 0 {
                    f.ternaries -= 1;
                    i = j + 1;
                } else if f.open == '[' {
                    if keyword {
                        f.keywords.push(word);
                        i = j + 1;
                    } else if f.keywords.is_empty() {
                        f.names += 1;
                        f.last = word;
                    }
                }
            }
            continue;
        }
        after_dot = c == '.' || (after_dot && c.is_whitespace());
        match c {
            '[' | '(' | '{' => frames.push(Frame {
                open: c,
                keywords: vec![],
                names: 0,
                last: String::new(),
                ternaries: 0,
            }),
            ']' | ')' | '}' => {
                if let Some(f) = frames.pop() {
                    if f.open == '[' && c == ']' {
                        if !f.keywords.is_empty() {
                            selectors.insert(f.keywords.iter().map(|k| format!("{k}:")).collect());
                        } else if f.names >= 2 {
                            selectors.insert(f.last);
                        }
                    }
                    // A bracketed or parenthesized receiver.
                    if let Some(p) = frames.last_mut()
                        && p.open == '['
                        && p.keywords.is_empty()
                    {
                        p.names += 1;
                    }
                }
            }
            '?' => {
                if let Some(f) = frames.last_mut() {
                    f.ternaries += 1;
                }
            }
            ':' if chars.get(i + 1) == Some(&':') => i += 1,
            ':' => {
                if let Some(f) = frames.last_mut() {
                    f.ternaries = f.ternaries.saturating_sub(1);
                }
            }
            _ => {}
        }
        i += 1;
    }
    (selectors, dotted)
}

/// Framework headers whose every declaration lies outside the suite's
/// scope, by the start of their names.
#[cfg(test)]
const API_HEADERS_LEFT_OUT: [(&str, &str); 10] = [
    ("MTL4", "the Metal4 family is left out"),
    ("MTLAccelerationStructure", "ray tracing is not claimed"),
    ("MTLIntersectionFunctionTable", "ray tracing is not claimed"),
    (
        "MTLRasterizationRate",
        "rasterization rate maps are left out",
    ),
    ("MTLTensor", "tensors belong to the Metal4 family, left out"),
    (
        "MTLResourceState",
        "resource state encoders map sparse texture tiles, left out",
    ),
    (
        "MTLCapture",
        "GPU capture is a developer tool, not a path an application's work takes",
    ),
    (
        "MTLResourceViewPool",
        "view pools belong to the Metal4 family, left out",
    ),
    (
        "MTLTextureViewPool",
        "view pools belong to the Metal4 family, left out",
    ),
    (
        "MTLDeviceCertification",
        "certification notices are not GPU work",
    ),
];

/// Words that leave out every class or entry whose name holds them,
/// ignoring case, in headers that are otherwise in scope.
#[cfg(test)]
const API_WORDS_LEFT_OUT: [(&str, &str); 15] = [
    ("MTL4", "the Metal4 family is left out"),
    ("accelerationStructure", "ray tracing is not claimed"),
    ("intersectionFunction", "ray tracing is not claimed"),
    ("rayTracing", "ray tracing is not claimed"),
    (
        "withBinaryFunction",
        "binary functions belong to the Metal4 family, left out",
    ),
    (
        "counterHeap",
        "counter heaps belong to the Metal4 family, left out",
    ),
    (
        "colorAttachmentMap",
        "color attachment mapping belongs to the Metal4 family, left out",
    ),
    ("tensor", "tensors belong to the Metal4 family, left out"),
    ("sparse", "sparse resources are left out"),
    (
        "resourceState",
        "resource state encoders map sparse texture tiles, left out",
    ),
    ("rasterizationRate", "rasterization rate maps are left out"),
    (
        "remote",
        "views of resources on another device are left out",
    ),
    ("peer", "peer groups of linked GPUs are left out"),
    ("shaderValidation", "shader validation is a developer tool"),
    (
        "indexedSubscript",
        "subscripts send these, which the parser cannot tell from C indexing; the descriptors they reach are set and read",
    ),
];

/// Single entries left out, as `Class entry`.
#[cfg(test)]
const API_ENTRIES_LEFT_OUT: [(&str, &str); 25] = [
    (
        "MTLBlitCommandEncoder getTextureAccessCounters:region:mipLevel:slice:resetCounters:countersBuffer:countersBufferOffset:",
        "texture access counters count sparse texture use",
    ),
    (
        "MTLBlitCommandEncoder resetTextureAccessCounters:region:mipLevel:slice:",
        "texture access counters count sparse texture use",
    ),
    (
        "MTLTexture .firstMipmapInTail",
        "a mipmap tail is a sparse texture's",
    ),
    (
        "MTLTexture .tailSizeInBytes",
        "a mipmap tail is a sparse texture's",
    ),
    (
        "MTLDevice newArchiveWithURL:error:",
        "the Metal4 family is left out",
    ),
    (
        "MTLDevice newArgumentTableWithDescriptor:error:",
        "the Metal4 family is left out",
    ),
    (
        "MTLDevice newCommandAllocator",
        "the Metal4 family is left out",
    ),
    (
        "MTLDevice newCommandAllocatorWithDescriptor:error:",
        "the Metal4 family is left out",
    ),
    (
        "MTLDevice newCommandBuffer",
        "the Metal4 family is left out",
    ),
    (
        "MTLDevice newCompilerWithDescriptor:error:",
        "the Metal4 family is left out",
    ),
    (
        "MTLDevice newPipelineDataSetSerializerWithDescriptor:",
        "the Metal4 family is left out",
    ),
    (
        "MTLDevice newTextureViewPoolWithDescriptor:error:",
        "view pools belong to the Metal4 family, left out",
    ),
    (
        "MTLRenderPipelineState newRenderPipelineDescriptorForSpecialization",
        "the Metal4 family is left out",
    ),
    (
        "MTLDevice .registryID",
        "an identifier of this machine's device, the same on no other",
    ),
    (
        "MTLDevice .locationNumber",
        "an identifier of this machine's slot, the same on no other",
    ),
    (
        "MTLCommandQueue insertDebugCaptureBoundary",
        "GPU capture is a developer tool",
    ),
    (
        "MTLCommandBuffer .logs",
        "logs hold shader validation reports, a developer tool",
    ),
    (
        "MTLFunctionLog .debugLocation",
        "function logs hold shader validation reports, a developer tool",
    ),
    (
        "MTLFunctionLog .encoderLabel",
        "function logs hold shader validation reports, a developer tool",
    ),
    (
        "MTLFunctionLog .function",
        "function logs hold shader validation reports, a developer tool",
    ),
    (
        "MTLFunctionLogDebugLocation .URL",
        "function logs hold shader validation reports, a developer tool",
    ),
    (
        "MTLFunctionLogDebugLocation .column",
        "function logs hold shader validation reports, a developer tool",
    ),
    (
        "MTLFunctionLogDebugLocation .line",
        "function logs hold shader validation reports, a developer tool",
    ),
    (
        "MTLCommandBufferEncoderInfo .debugSignposts",
        "encoder infos describe GPU faults, which no case provokes",
    ),
    (
        "MTLCommandBufferEncoderInfo .errorState",
        "encoder infos describe GPU faults, which no case provokes",
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    fn availability() -> serde_json::Value {
        let path = super::super::assets().join("availability.json");
        serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap()
    }

    #[test]
    fn declarations_reads_headers() {
        let header = "\
            @protocol MTLThing;\n\
            @class MTLOther;\n\
            /* @interface MTLCommented\n@end */\n\
            API_AVAILABLE(macos(10.11))\n\
            @protocol MTLThing <NSObject>\n\
            @property (nonatomic, getter=isShared) BOOL shared API_AVAILABLE(macos(11.0));\n\
            @property (readonly) MTLSize sizes[4];\n\
            @property (copy) void (^handler)(int);\n\
            - (void)setBuffer:(nullable id <MTLBuffer>)buffer offset:(NSUInteger)offset\n\
                atIndex:(NSUInteger)index NS_SWIFT_NAME(setBuffer(_:offset:index:));\n\
            - (id <MTLThing>)newThing API_AVAILABLE(macos(13.0));\n\
            + (instancetype)thing;\n\
            - (void)gone API_UNAVAILABLE(macos, ios);\n\
            - (void)hidden NS_UNAVAILABLE;\n\
            @optional\n\
            - (void)wait:(void (^ NS_NOESCAPE)(int))block;\n\
            @end\n";
        let classes = declarations(header);
        let names: Vec<&String> = classes.keys().collect();
        assert_eq!(names, ["MTLThing"]);
        let entries: Vec<&str> = classes["MTLThing"].iter().map(String::as_str).collect();
        assert_eq!(
            entries,
            [
                "+thing",
                ".shared|isShared",
                ".sizes",
                "newThing",
                "setBuffer:offset:atIndex:",
                "wait:"
            ]
        );
    }

    #[test]
    fn sends_reads_messages() {
        let source = "\
            // [commented out:1]\n\
            - (id)newScratchBufferWithMinimumSize:(NSUInteger)size {\n\
            \tid x = [[MTLSharedEventListener alloc] init];\n\
            \t[e setBuffer:b offset:(flag ? 1 : 2) atIndex:k[0]];\n\
            \tNSLog(@\"[not sent:%d]\", 1);\n\
            \tfloat f = list[i].value * 1.5f;\n\
            \t[(id)thing commit];\n\
            \td.label = [e.device name];\n\
            }\n";
        let (sent, dotted) = sends(source);
        let sent: Vec<&str> = sent.iter().map(String::as_str).collect();
        assert_eq!(
            sent,
            [
                "alloc",
                "commit",
                "init",
                "name",
                "newScratchBufferWithMinimumSize:",
                "setBuffer:offset:atIndex:"
            ]
        );
        let dotted: Vec<&str> = dotted.iter().map(String::as_str).collect();
        assert_eq!(dotted, ["device", "label", "value"]);
    }

    /// Every framework selector and property in scope is sent or read by
    /// runner.m, and every entry left out is unsent.
    #[test]
    fn every_framework_entry_is_sent() {
        let api: Api = serde_json::from_value(availability()["api"].clone()).unwrap_or_default();
        assert!(
            !api.is_empty(),
            "availability.json records no framework inventory: run `cargo xtask gpu metal-suite probe`"
        );
        let runner = fs::read_to_string(super::super::assets().join("runner.m")).unwrap();
        let (sent, dotted) = sends(&runner);
        // A property is reached by its name, its getter or its setter; a
        // method of no arguments may be read as a property too.
        let reached = |entry: &str| match entry.strip_prefix('.') {
            Some(names) => {
                let mut names = names.split('|');
                let name = names.next().unwrap_or_default();
                let setter = format!("set{}{}:", name[..1].to_uppercase(), &name[1..]);
                sent.contains(&setter)
                    || std::iter::once(name)
                        .chain(names)
                        .any(|n| sent.contains(n) || dotted.contains(n))
            }
            None => {
                let s = entry.trim_start_matches('+');
                sent.contains(s) || (!s.contains(':') && dotted.contains(s))
            }
        };
        for (prefix, _) in API_HEADERS_LEFT_OUT {
            assert!(
                api.keys().any(|h| h.starts_with(prefix)),
                "{prefix} headers are left out but none exist"
            );
        }
        let mut unreached = vec![];
        let mut words = BTreeSet::new();
        let mut entries = BTreeSet::new();
        for (header, classes) in &api {
            if API_HEADERS_LEFT_OUT
                .iter()
                .any(|(p, _)| header.starts_with(p))
            {
                continue;
            }
            for (class, list) in classes {
                for entry in list.iter().filter(|e| !reached(e.as_str())) {
                    let named = format!("{class} {entry}");
                    let lower = named.to_lowercase();
                    if let Some((w, _)) = API_WORDS_LEFT_OUT
                        .iter()
                        .find(|(w, _)| lower.contains(&w.to_lowercase()))
                    {
                        words.insert(*w);
                    } else if let Some((e, _)) =
                        API_ENTRIES_LEFT_OUT.iter().find(|(e, _)| *e == named)
                    {
                        entries.insert(*e);
                    } else {
                        unreached.push(format!("{named} ({header})"));
                    }
                }
            }
        }
        assert!(
            unreached.is_empty(),
            "framework entries runner.m never sends:\n  {}",
            unreached.join("\n  ")
        );
        let stale: Vec<&str> = API_WORDS_LEFT_OUT
            .iter()
            .map(|(w, _)| *w)
            .filter(|w| !words.contains(w))
            .chain(
                API_ENTRIES_LEFT_OUT
                    .iter()
                    .map(|(e, _)| *e)
                    .filter(|e| !entries.contains(e)),
            )
            .collect();
        assert!(
            stale.is_empty(),
            "left out but leaving nothing out: {stale:?}"
        );
    }

    #[test]
    fn functions_reads_declarations() {
        let header = "\
            METAL_FUNC float abs(float x) { return x; }\n\
            template <typename T> METAL_FUNC enable_if_t<is_same<T, int>::value, T>\n\
            clamp(T x, T a, T b);\n\
            // METAL_FUNC float commented(float x);\n\
            METAL_FUNC bool operator==(int a, int b);\n\
            METAL_FUNC void __internal(int a);\n\
            METAL_FUNC void METAL_MACRO(int a);\n\
            METAL_FUNCTIONAL_TABLE float table(int a);\n\
              METAL_FUNC vec<T, 4> sample(sampler s, float2 coord) const thread\n\
            METAL_FUNC enable_if_t<_is_valid(W, H), block<T, W, H>>\n\
            block_read(sampler s, int2 coord) const thread;\n";
        let names: Vec<String> = functions(header).into_iter().collect();
        assert_eq!(names, ["abs", "block_read", "clamp", "sample"]);
    }

    /// Every word of every library the suite compiles.
    fn suite_words() -> BTreeSet<String> {
        let plan = super::super::full_plan().unwrap();
        let corpus = super::super::assets().join("corpus");
        let mut words = BTreeSet::new();
        let sources: BTreeSet<&String> = plan.libraries().values().map(|l| &l.source).collect();
        for source in sources {
            let text = plan.source_text(source, &corpus).unwrap();
            words.extend(
                text.split(|c: char| !identifier(c))
                    .filter(|w| !w.is_empty())
                    .map(str::to_string),
            );
        }
        words
    }

    #[test]
    fn every_library_function_has_a_case() {
        let inventory: Inventory =
            serde_json::from_value(availability()["functions"].clone()).unwrap_or_default();
        assert!(
            !inventory.is_empty(),
            "availability.json records no header inventory: run `cargo xtask gpu metal-suite probe`"
        );
        let headers: BTreeSet<&str> = HEADERS_LEFT_OUT.iter().map(|(h, _)| *h).collect();
        let left_out: BTreeSet<&str> = FUNCTIONS_LEFT_OUT.iter().map(|(f, _)| *f).collect();
        let stem = |header: &str| header.rsplit('/').next().unwrap_or(header).to_string();
        for header in &headers {
            assert!(
                inventory.keys().any(|h| stem(h) == *header),
                "{header} is left out but no longer exists"
            );
        }
        // Where each function is declared, outside the headers left out.
        let mut in_scope: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        let mut everywhere = BTreeSet::new();
        for (header, names) in &inventory {
            for name in names {
                everywhere.insert(name.as_str());
                if !headers.contains(stem(header).as_str()) {
                    in_scope
                        .entry(name.as_str())
                        .or_default()
                        .push(header.as_str());
                }
            }
        }
        let words = suite_words();
        let missing: Vec<String> = in_scope
            .iter()
            .filter(|(name, _)| !words.contains(**name) && !left_out.contains(**name))
            .map(|(name, headers)| format!("{name} ({})", headers.join(", ")))
            .collect();
        assert!(
            missing.is_empty(),
            "functions no case names:\n  {}",
            missing.join("\n  ")
        );
        let stale: Vec<&str> = left_out
            .iter()
            .filter(|f| !everywhere.contains(**f) || words.contains(**f))
            .copied()
            .collect();
        assert!(
            stale.is_empty(),
            "left out but absent from the headers, or named by a case: {stale:?}"
        );
    }
}
