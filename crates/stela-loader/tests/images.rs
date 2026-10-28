//! Apple-linked fixture images load, bind and run through the loader.
//!
//! Each fixture is assembled and linked with the host's Apple toolchain, then
//! executed natively from an explicit entry ABI: X0 is an input and X30 a stop
//! address. Results are checked against each fixture's own arithmetic.
#![cfg(target_os = "macos")]

use anyhow::{Context, Result, ensure};
use object::{Object, ObjectSegment, ObjectSymbol};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use stela_compiler::{GuestAddress, GuestState};
use stela_loader::{
    dependency_graph::{DiscoveryOptions, discover},
    linked_images::{ImageInput, LinkedImages},
    mapped_image::{MappedImage, StackSpec},
};
use stela_runtime::blocks::ThreadState;

const SEED: u64 = 0x9e37_79b9_7f4a_7c15;
const INPUT: u64 = 0x0123_4567_89ab_cdef;
const STOP: u64 = 0xffff_0000;
const BLOCK_BUDGET: usize = 64;
const STACK_BYTES: u64 = 0x1_0000;
/// Tests share one process, so each loads its images in its own range.
const RANGE: u64 = 0x100_0000_0000;
const LIBRARY_STRIDE: u64 = 0x10_0000_0000;
const STACK_OFFSET: u64 = 0x80_0000_0000;
/// Each callee adds its own constant to the value it returns.
const CALLEE_ADDEND: u64 = 7;
const LIBRARY_ADDEND: u64 = 11;
const MIDDLE_ADDEND: u64 = 13;

/// Assembles and links fixtures in a private directory.
struct Toolchain {
    clang: PathBuf,
    linker: PathBuf,
    sdk: String,
    work: tempfile::TempDir,
}

fn xcrun(arguments: &[&str]) -> Result<String> {
    let output = Command::new("xcrun").args(arguments).output()?;
    ensure!(output.status.success(), "xcrun {arguments:?} failed");
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn run(command: &mut Command) -> Result<()> {
    let output = command.output()?;
    ensure!(
        output.status.success(),
        "{command:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

impl Toolchain {
    fn new() -> Result<Self> {
        Ok(Self {
            clang: xcrun(&["--find", "clang"])?.into(),
            linker: xcrun(&["--find", "ld"])?.into(),
            sdk: xcrun(&["--show-sdk-path"])?,
            work: tempfile::tempdir()?,
        })
    }

    fn path(&self, name: &str) -> PathBuf {
        self.work.path().join(name)
    }

    fn assemble(&self, fixture: &str) -> Result<PathBuf> {
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(fixture);
        let object = self.path(fixture).with_extension("o");
        run(Command::new(&self.clang)
            .args(["-target", "arm64-apple-macos14", "-c"])
            .arg(source)
            .arg("-o")
            .arg(&object))?;
        Ok(object)
    }

    /// Link `inputs` into `output` with `options`, against libSystem.
    fn link(&self, output: &Path, inputs: &[PathBuf], options: &[&str]) -> Result<Vec<u8>> {
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)?;
        }
        run(Command::new(&self.linker)
            .args([
                "-arch",
                "arm64",
                "-platform_version",
                "macos",
                "14.0",
                "14.0",
            ])
            .args(options)
            .arg("-o")
            .arg(output)
            .args(inputs)
            .args(["-syslibroot", &self.sdk, "-lSystem", "-no_adhoc_codesign"]))?;
        Ok(fs::read(output)?)
    }

    fn exports(&self, name: &str, symbols: &[&str]) -> Result<String> {
        let path = self.path(name);
        fs::write(&path, symbols.join("\n") + "\n")?;
        Ok(path.display().to_string())
    }
}

/// The linked address of `name`, slid from the image's preferred base.
fn symbol(image: &[u8], name: &str, slide: u64) -> Result<u64> {
    let file = object::File::parse(image)?;
    let address = file
        .symbols()
        .find(|symbol| symbol.name() == Ok(name))
        .with_context(|| format!("missing symbol {name}"))?
        .address();
    Ok(address.wrapping_add(slide))
}

/// The linked `__TEXT` address, from which a load base slides the image.
fn preferred_base(image: &[u8]) -> Result<u64> {
    let file = object::File::parse(image)?;
    let text = file
        .segments()
        .find(|segment| segment.name() == Ok(Some("__TEXT")))
        .context("missing __TEXT")?;
    Ok(text.address())
}

/// The first image base of test `index`; libraries and the stack follow it.
fn base(index: u64) -> u64 {
    (4 + index) * RANGE
}

fn stack(index: u64) -> StackSpec {
    StackSpec {
        base: base(index) + STACK_OFFSET,
        bytes: STACK_BYTES,
    }
}

fn entry_state(entry: u64, sp: u64) -> ThreadState {
    let mut registers = GuestState {
        sp,
        ..GuestState::default()
    };
    registers.x[0] = INPUT;
    registers.x[30] = STOP;
    ThreadState {
        registers,
        pc: GuestAddress(entry),
    }
}

fn quads(bytes: &[u8]) -> Vec<u64> {
    bytes
        .as_chunks::<8>()
        .0
        .iter()
        .map(|quad| u64::from_le_bytes(*quad))
        .collect()
}

fn input(data: Vec<u8>, load_base: u64) -> ImageInput {
    ImageInput {
        container_sha256: stela_formats::sha256(&data),
        data,
        slice_offset: 0,
        load_base: Some(load_base),
    }
}

#[test]
fn mapped_image_runs_from_its_own_data_and_zero_fill() -> Result<()> {
    let tools = Toolchain::new()?;
    let object = tools.assemble("mapped-image-arm64.S")?;
    let text = format!("{:#x}", base(0));
    let data = format!("{:#x}", base(0) + 0x4000);
    let options = [
        "-e",
        "_mapped_entry",
        "-segaddr",
        "__TEXT",
        &text,
        "-segaddr",
        "__DATA",
        &data,
        "-no_uuid",
    ];
    let image = tools.link(&tools.path("mapped"), &[object], &options)?;
    let mut mapped = MappedImage::load(&image, tools.path("cache"), Some(stack(0)), None)?;
    let sp = mapped.stack().context("stack")?.initial_sp;
    let mut thread = entry_state(mapped.mapped_entry(), sp);
    // SAFETY: the trusted fixture touches only its own mappings and stack.
    unsafe { mapped.run(&mut thread, Some(GuestAddress(STOP)), BLOCK_BUDGET)? };
    let result = INPUT.wrapping_add(SEED);
    assert_eq!(thread.pc, GuestAddress(STOP));
    assert_eq!(thread.registers.x[0], result + CALLEE_ADDEND);
    assert_eq!(thread.registers.x[1], SEED);
    assert_eq!(thread.registers.sp, sp);
    let output = symbol(&image, "_mapped_output", 0)?;
    assert_eq!(
        quads(&mapped.read_snapshot(output, 16)?),
        [result, result + CALLEE_ADDEND]
    );
    Ok(())
}

#[test]
fn chained_rebases_follow_the_load_base() -> Result<()> {
    let tools = Toolchain::new()?;
    let object = tools.assemble("chained-image-arm64.S")?;
    let image = tools.link(
        &tools.path("chained"),
        &[object],
        &["-e", "_chained_entry", "-no_uuid"],
    )?;
    for index in [1, 2] {
        let load_base = base(index);
        let slide = load_base.wrapping_sub(preferred_base(&image)?);
        let cache = tools.path(&format!("cache-{index}"));
        let mut mapped = MappedImage::load(&image, cache, Some(stack(index)), Some(load_base))?;
        let sp = mapped.stack().context("stack")?.initial_sp;
        let mut thread = entry_state(mapped.mapped_entry(), sp);
        // SAFETY: the trusted fixture touches only its own mappings and stack.
        unsafe { mapped.run(&mut thread, Some(GuestAddress(STOP)), BLOCK_BUDGET)? };
        let pointers = symbol(&image, "_chained_pointers", slide)?;
        let targets = ["_chained_seed", "_chained_output", "_chained_callee"]
            .map(|name| symbol(&image, name, slide));
        let targets: Vec<u64> = targets.into_iter().collect::<Result<_>>()?;
        assert_eq!(quads(&mapped.read_snapshot(pointers, 24)?), targets);
        let result = INPUT.wrapping_add(SEED);
        assert_eq!(thread.registers.x[0], result + CALLEE_ADDEND);
        assert_eq!(
            quads(&mapped.read_snapshot(targets[1], 16)?),
            [result, result + CALLEE_ADDEND]
        );
    }
    Ok(())
}

#[test]
fn bound_imports_call_into_the_companion_dylib() -> Result<()> {
    let tools = Toolchain::new()?;
    let main_object = tools.assemble("bound-image-arm64.S")?;
    let library_object = tools.assemble("bound-library-arm64.S")?;
    let exports = tools.exports("exports.txt", &["_bound_function", "_bound_seed"])?;
    let library_path = tools.path("libstela-fixture.dylib");
    let library = tools.link(
        &library_path,
        &[library_object],
        &[
            "-dylib",
            "-install_name",
            "@rpath/libstela-fixture.dylib",
            "-exported_symbols_list",
            &exports,
        ],
    )?;
    let main = tools.link(
        &tools.path("bound-main"),
        &[main_object, library_path],
        &["-e", "_bound_entry", "-no_uuid"],
    )?;
    let main_base = base(3);
    let library_base = main_base + LIBRARY_STRIDE;
    let library_slide = library_base.wrapping_sub(preferred_base(&library)?);
    let main_slide = main_base.wrapping_sub(preferred_base(&main)?);
    let inputs = vec![
        input(main.clone(), main_base),
        input(library.clone(), library_base),
    ];
    let mut images = LinkedImages::load(inputs, tools.path("cache"), stack(3))?;
    let mut thread = entry_state(images.entry(), images.stack().initial_sp);
    // SAFETY: the trusted fixtures touch only their own mappings and stack.
    unsafe { images.run(&mut thread, Some(GuestAddress(STOP)), BLOCK_BUDGET) }.context("run")?;
    let result = INPUT.wrapping_add(SEED);
    let returned = result + LIBRARY_ADDEND;
    assert_eq!(thread.registers.x[0], returned);
    let library_output = symbol(&library, "_library_output", library_slide)?;
    assert_eq!(
        quads(&images.read_snapshot(library_output, 16)?),
        [result, returned]
    );
    let main_output = symbol(&main, "_bound_output", main_slide)?;
    assert_eq!(quads(&images.read_snapshot(main_output, 8)?), [returned]);
    Ok(())
}

#[test]
fn rpath_dependencies_resolve_inside_the_guest_root() -> Result<()> {
    let tools = Toolchain::new()?;
    let guest = tools.path("guest");
    let main_path = guest.join("app/bin/main");
    let middle_path = guest.join("app/Frameworks/libmiddle-fixture.dylib");
    let leaf_path = guest.join("app/Frameworks/private/libleaf-fixture.dylib");
    let objects = [
        "bound-image-arm64.S",
        "dependency-middle-arm64.S",
        "dependency-leaf-arm64.S",
    ]
    .map(|fixture| tools.assemble(fixture));
    let [main_object, middle_object, leaf_object] = objects;
    let leaf_exports = tools.exports("leaf-exports.txt", &["_leaf_function"])?;
    let middle_exports =
        tools.exports("middle-exports.txt", &["_bound_function", "_bound_seed"])?;
    let leaf = tools.link(
        &leaf_path,
        &[leaf_object?],
        &[
            "-dylib",
            "-install_name",
            "@rpath/libleaf-fixture.dylib",
            "-exported_symbols_list",
            &leaf_exports,
        ],
    )?;
    tools.link(
        &middle_path,
        &[middle_object?, leaf_path],
        &[
            "-dylib",
            "-install_name",
            "@rpath/libmiddle-fixture.dylib",
            "-exported_symbols_list",
            &middle_exports,
            "-rpath",
            "@loader_path/private",
        ],
    )?;
    tools.link(
        &main_path,
        &[main_object?, middle_path],
        &[
            "-e",
            "_bound_entry",
            "-rpath",
            "@executable_path/../Frameworks",
            "-no_uuid",
        ],
    )?;
    let discovery = discover(
        &main_path,
        DiscoveryOptions {
            guest_root: guest,
            guest_path: Some("/app/bin/main".into()),
            architecture: Some("arm64".into()),
            image_base: Some(base(4)),
            library_base: base(4) + LIBRARY_STRIDE,
            library_stride: LIBRARY_STRIDE,
        },
    )?;
    // Only libSystem, absent from the guest root, stays unresolved.
    ensure!(
        discovery.inputs.len() == 3,
        "fixture images were not all discovered"
    );
    let leaf_index = discovery
        .inputs
        .iter()
        .position(|image| image.data == leaf)
        .context("leaf image was not discovered")?;
    let leaf_base = discovery.inputs[leaf_index]
        .load_base
        .context("leaf base")?;
    let leaf_slide = leaf_base.wrapping_sub(preferred_base(&leaf)?);
    let mut images = LinkedImages::load_discovered(
        discovery.inputs,
        tools.path("cache"),
        stack(4),
        &discovery.links,
    )?;
    let mut thread = entry_state(images.entry(), images.stack().initial_sp);
    // SAFETY: the trusted fixtures touch only their own mappings and stack.
    unsafe { images.run(&mut thread, Some(GuestAddress(STOP)), BLOCK_BUDGET) }.context("run")?;
    let result = INPUT.wrapping_add(SEED);
    let from_leaf = result + LIBRARY_ADDEND;
    assert_eq!(thread.registers.x[0], from_leaf + MIDDLE_ADDEND);
    let leaf_output = symbol(&leaf, "_leaf_output", leaf_slide)?;
    assert_eq!(
        quads(&images.read_snapshot(leaf_output, 16)?),
        [result, from_leaf]
    );
    Ok(())
}
