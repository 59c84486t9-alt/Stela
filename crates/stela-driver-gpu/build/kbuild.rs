//! The object lists a driver's Kbuild makefiles compose, read with the subset
//! of GNU Make they use. Anything outside that subset is refused, even in an
//! inactive conditional, rather than guessed at.
//!
//! Accepted lines: comments; `include $(src)/<path>`; `ifdef CONFIG_<X>` and
//! `endif`; `ccflags-y += -I $(src)[/<path>]`; and `<name>-y` or
//! `<name>-$(CONFIG_<X>)` assigned with `:=` or `+=` from object paths and
//! `$(<name>-y)` references. A `:=` variable expands its references when
//! assigned, as Make's simply expanded variables do; a reference in a
//! recursively expanded variable is refused.
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

/// Bounds on what one driver's makefiles may hold.
const MAX_FILES: usize = 128;
const MAX_DEPTH: usize = 8;
const MAX_BYTES: usize = 1 << 20;

/// The `CONFIG_` symbols of a Kconfig header: `#define CONFIG_<X> <value>`.
pub struct Config(BTreeMap<String, String>);

impl Config {
    pub fn parse(header: &str) -> Result<Self, String> {
        let mut symbols = BTreeMap::new();
        for line in header.lines() {
            let Some(definition) = line.strip_prefix("#define ") else {
                continue;
            };
            let (name, value) = definition.split_once(' ').unwrap_or((definition, ""));
            if name.starts_with("CONFIG_")
                && symbols
                    .insert(name.to_owned(), value.trim().to_owned())
                    .is_some()
            {
                return Err(format!("{name} is defined twice"));
            }
        }
        Ok(Self(symbols))
    }

    /// Whether a `bool` or `tristate` symbol is `y`. A module (`m`) selection
    /// and a non-boolean value are refused: Stela builds no modules.
    fn enabled(&self, name: &str) -> Result<bool, String> {
        if self.0.contains_key(&format!("{name}_MODULE")) {
            return Err(format!("{name} selects a module"));
        }
        match self.0.get(name).map(String::as_str) {
            None => Ok(false),
            Some("1") => Ok(true),
            Some(value) => Err(format!("{name} is {value}, not a boolean")),
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Flavor {
    Simple,
    Recursive,
}

/// What a driver's makefiles define: its object lists and include paths.
#[derive(Default)]
pub struct Kbuild {
    variables: BTreeMap<String, (Flavor, Vec<String>)>,
    /// `ccflags-y` include directories, in order.
    pub includes: Vec<PathBuf>,
    /// Every makefile read, in order.
    pub files: Vec<PathBuf>,
}

impl Kbuild {
    /// Reads the makefile `Kbuild` in `source` and those it includes, which
    /// name paths relative to `source` as `$(src)`.
    pub fn read(source: &Path, config: &Config) -> Result<Self, String> {
        let mut kbuild = Self::default();
        kbuild.include(source, Path::new("Kbuild"), config, 0)?;
        Ok(kbuild)
    }

    /// The objects of `<name>-y`, as paths below the source directory.
    pub fn objects(&self, name: &str) -> Result<&[String], String> {
        self.variables
            .get(&format!("{name}-y"))
            .map(|(_, objects)| objects.as_slice())
            .ok_or_else(|| format!("Kbuild defines no {name}-y"))
    }

    fn include(
        &mut self,
        source: &Path,
        file: &Path,
        config: &Config,
        depth: usize,
    ) -> Result<(), String> {
        if depth > MAX_DEPTH || self.files.len() == MAX_FILES {
            return Err(format!("{} nests past Kbuild's bounds", file.display()));
        }
        let path = source.join(file);
        let text =
            fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        if text.len() > MAX_BYTES {
            return Err(format!("{} is too large", path.display()));
        }
        self.files.push(path.clone());
        let mut active = vec![true];
        for (number, line) in text.lines().enumerate() {
            let at = || format!("{}:{}", path.display(), number + 1);
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(symbol) = line.strip_prefix("ifdef ") {
                let enabled = config
                    .enabled(symbol.trim())
                    .map_err(|error| format!("{}: {error}", at()))?;
                active.push(active[active.len() - 1] && enabled);
                continue;
            }
            if line == "endif" {
                if active.len() == 1 {
                    return Err(format!("{}: endif without ifdef", at()));
                }
                active.pop();
                continue;
            }
            let statement = Statement::parse(line).map_err(|error| format!("{}: {error}", at()))?;
            if !active[active.len() - 1] {
                continue;
            }
            match statement {
                Statement::Include(relative) => {
                    self.include(source, Path::new(relative), config, depth + 1)?;
                }
                Statement::Includes(relative) => {
                    self.includes.push(source.join(relative));
                }
                Statement::Assign {
                    name,
                    condition,
                    simple,
                    words,
                } => {
                    if let Some(symbol) = condition
                        && !config
                            .enabled(symbol)
                            .map_err(|error| format!("{}: {error}", at()))?
                    {
                        continue;
                    }
                    self.assign(name, simple, &words)
                        .map_err(|error| format!("{}: {error}", at()))?;
                }
            }
        }
        if active.len() != 1 {
            return Err(format!("{}: ifdef without endif", path.display()));
        }
        Ok(())
    }

    fn assign(&mut self, name: &str, simple: bool, words: &[&str]) -> Result<(), String> {
        let key = format!("{name}-y");
        let flavor = match (simple, self.variables.get(&key)) {
            (true, _) => Flavor::Simple,
            (false, Some((flavor, _))) => *flavor,
            (false, None) => Flavor::Recursive,
        };
        let mut values = Vec::new();
        for word in words {
            if let Some(reference) = word
                .strip_prefix("$(")
                .and_then(|word| word.strip_suffix(')'))
            {
                if flavor == Flavor::Recursive {
                    return Err(format!("{key} refers to {reference} without :="));
                }
                let (_, referenced) = self
                    .variables
                    .get(reference)
                    .ok_or_else(|| format!("{key} refers to undefined {reference}"))?;
                values.extend(referenced.iter().cloned());
            } else if word.ends_with(".o") && !word.contains('$') && !word.contains("..") {
                values.push((*word).to_owned());
            } else {
                return Err(format!("{key} holds {word}, which is no object"));
            }
        }
        let entry = self.variables.entry(key).or_insert((flavor, Vec::new()));
        if simple {
            entry.1.clear();
        }
        entry.0 = flavor;
        entry.1.extend(values);
        Ok(())
    }
}

/// One line of the accepted subset.
enum Statement<'a> {
    Include(&'a str),
    Includes(&'a str),
    Assign {
        name: &'a str,
        condition: Option<&'a str>,
        simple: bool,
        words: Vec<&'a str>,
    },
}

impl<'a> Statement<'a> {
    fn parse(line: &'a str) -> Result<Self, String> {
        if let Some(path) = line.strip_prefix("include $(src)/") {
            return relative(path).map(Statement::Include);
        }
        if let Some(flag) = line.strip_prefix("ccflags-y += -I $(src)") {
            let path = flag.strip_prefix('/').unwrap_or(flag);
            return if flag.is_empty() || flag.starts_with('/') {
                Ok(Statement::Includes(if path.is_empty() {
                    "."
                } else {
                    relative(path)?
                }))
            } else {
                Err(format!("unsupported flag {line}"))
            };
        }
        let (target, simple, value) = if let Some((target, value)) = line.split_once(" := ") {
            (target, true, value)
        } else if let Some((target, value)) = line.split_once(" += ") {
            (target, false, value)
        } else {
            return Err(format!("unsupported statement {line}"));
        };
        let (name, selector) = target
            .rsplit_once('-')
            .ok_or_else(|| format!("unsupported target {target}"))?;
        let condition = match selector {
            "y" => None,
            selector => Some(
                selector
                    .strip_prefix("$(")
                    .and_then(|selector| selector.strip_suffix(')'))
                    .filter(|symbol| symbol.starts_with("CONFIG_"))
                    .ok_or_else(|| format!("unsupported selector {selector}"))?,
            ),
        };
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(format!("unsupported variable {name}"));
        }
        Ok(Statement::Assign {
            name,
            condition,
            simple,
            words: value.split_whitespace().collect(),
        })
    }
}

/// A path below `$(src)`.
fn relative(path: &str) -> Result<&str, String> {
    if path.is_empty()
        || path.starts_with('/')
        || path.split('/').any(|part| part == ".." || part.is_empty())
    {
        return Err(format!("{path} leaves the driver's tree"));
    }
    Ok(path)
}
