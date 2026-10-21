//! Host-device resources read from the selected boot volume before EBS. Unlike
//! a Vec/Arc in the loader heap, this fixed wire representation survives engine
//! relocation. Only immutable bytes in reserved LOADER_DATA pages cross it.
use crate::{firmware, handoff::Region, layout, output, paging::PAGE};
use alloc::{format, string::ToString, sync::Arc, vec::Vec};
use stela_drivers::firmware::{Catalog, Provider, Requirement, Target};
use stela_loader::host_firmware::{self as manifest, MAX_IMAGES, MAX_MANIFEST_BYTES, Manifest};
use uefi::{
    CString16,
    proto::media::file::{Directory, File as _, FileAttribute, FileInfo, FileMode, RegularFile},
};

/// At most 4096 siblings per path component; no unbounded directory scans or
/// variable-length firmware metadata allocations.
const MAX_DIRECTORY_ENTRIES: usize = 4096;
#[repr(align(8))]
struct InfoBuffer([u8; 1024]);

#[derive(Clone, Copy)]
#[repr(C)]
pub struct Resources {
    pub present: bool,
    pub manifest: Region,
    pub images: [Region; MAX_IMAGES],
    pub count: usize,
}
impl Resources {
    pub const fn absent() -> Self {
        Self {
            present: false,
            manifest: Region {
                physical: 0,
                bytes: 0,
            },
            images: [Region {
                physical: 0,
                bytes: 0,
            }; MAX_IMAGES],
            count: 0,
        }
    }

    /// # Safety
    /// Every region came from this module's reserved LOADER_DATA pages and is
    /// immutable for the boot. `map` must return a permanent mapped alias of the
    /// full range: identity while loading, shared-window physmap in the engine.
    /// No page is reclaimable by the guest/free-page allocator.
    unsafe fn catalog(
        &self,
        map: impl Fn(u64) -> u64,
        phase: Option<&'static str>,
    ) -> Result<Option<Arc<Catalog>>, &'static str> {
        if !self.present {
            return Ok(None);
        }
        if self.count > MAX_IMAGES
            || self.manifest.bytes as usize > MAX_MANIFEST_BYTES
            || self.manifest.bytes == 0
        {
            return Err("invalid host firmware wire handoff");
        }
        let view = |region: Region| -> Result<&'static [u8], &'static str> {
            let end = region
                .physical
                .checked_add(region.bytes)
                .ok_or("host firmware region overflow")?;
            if region.physical == 0
                || region.bytes == 0
                || map(end - 1) != map(region.physical) + region.bytes - 1
            {
                return Err("invalid host firmware mapped range");
            }
            // SAFETY: caller's reserved immutable pages and permanent alias.
            Ok(unsafe {
                core::slice::from_raw_parts(
                    map(region.physical) as *const u8,
                    region.bytes as usize,
                )
            })
        };
        let manifest_bytes = view(self.manifest)?;
        let parsed = Manifest::parse(manifest_bytes).map_err(report)?;
        if parsed.images.len() != self.count {
            return Err("host firmware wire count mismatch");
        }
        let mut bytes = Vec::with_capacity(self.count);
        for (image, region) in parsed.images.iter().zip(&self.images[..self.count]) {
            if region.bytes != image.length as u64 {
                return Err("host firmware wire length mismatch");
            }
            bytes.push(view(*region)?);
        }
        let catalog = Arc::new(parsed.catalog(&bytes).map_err(report)?);
        if let Some(phase) = phase {
            record(phase, manifest_bytes, &parsed, &catalog)?;
        }
        Ok(Some(catalog))
    }

    /// # Safety
    /// This loader still owns every immutable reserved page and its identity
    /// alias remains mapped for the resulting catalog's lifetime.
    /// The standalone caller runs before EBS, so this emits no phase receipt.
    pub unsafe fn identity_catalog(&self) -> Result<Option<Arc<Catalog>>, &'static str> {
        // SAFETY: caller supplied the permanent identity mapping contract.
        unsafe { self.catalog(|physical| physical, None) }
    }

    /// # Safety
    /// The loader supplied this validated wire handoff. Its LOADER_DATA pages
    /// are reserved, and the engine maps them in its permanent shared physmap.
    pub unsafe fn after_ebs(&self) -> Result<Option<Arc<Catalog>>, &'static str> {
        // SAFETY: the caller's validated loader handoff and permanent physmap.
        let catalog = unsafe { self.catalog(layout::physical, Some("after-ebs")) }?;
        if let Some(catalog) = &catalog {
            let (images, bytes) = catalog.inventory();
            output::arguments(format_args!(
                "HOST FIRMWARE phase=after-ebs images={images} bytes={bytes}\n"
            ));
        }
        Ok(catalog)
    }
}

/// JSON escaping makes literal quotes/backslashes in bounded identity labels
/// unambiguous. Records come from the actual validated catalog in this phase,
/// including an exact provider lookup for each manifest-selected requirement.
fn record(
    phase: &str,
    manifest_bytes: &[u8],
    manifest: &Manifest<'_>,
    catalog: &Catalog,
) -> Result<(), &'static str> {
    let (images, bytes) = catalog.inventory();
    let record = serde_json::json!({
        "kind": "manifest", "phase": phase, "images": images, "bytes": bytes,
        "sha256": stela_runtime::sha256(manifest_bytes),
    });
    output::arguments(format_args!("HOST FIRMWARE RECORD {record}\n"));
    for (index, expected) in manifest.images.iter().enumerate() {
        let image = catalog
            .load(Requirement {
                name: expected.name,
                target: Target {
                    driver: expected.target.driver,
                    hardware: expected.target.hardware,
                    revision: expected.target.revision,
                    board: expected.target.board,
                },
                minimum_bytes: expected.length,
            })
            .map_err(|_| "cannot record verified host firmware requirement")?;
        let target = image.target();
        let source = image.provenance();
        let digest: alloc::string::String = image
            .sha256()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let record = serde_json::json!({
            "kind": "resource", "phase": phase, "index": index,
            "name": image.name(), "bytes": image.bytes().len(), "sha256": digest,
            "target": {"driver": target.driver, "hardware": target.hardware,
                "revision": target.revision, "board": target.board},
            "provenance": {"source": source.source, "revision": source.revision,
                "member": source.member, "license": source.license},
        });
        output::arguments(format_args!("HOST FIRMWARE RECORD {record}\n"));
    }
    Ok(())
}

fn report(error: manifest::Error) -> &'static str {
    output::arguments(format_args!("HOST FIRMWARE refused: {error}\n"));
    "invalid host firmware resources"
}

/// Resolve each component by enumerating its actual directory once. UEFI/FAT
/// case-insensitive matching is accepted only when exactly one entry matches;
/// a second case alias is refused even on firmware with a case-sensitive driver.
fn open(root: &mut Directory, relative: &str) -> Result<Option<RegularFile>, &'static str> {
    let path = CString16::try_from("\\").map_err(|_| "invalid firmware root")?;
    let mut directory = root
        .open(&path, FileMode::Read, FileAttribute::empty())
        .map_err(|_| "cannot open host firmware root")?
        .into_directory()
        .ok_or("host firmware root is not a directory")?;
    let mut parts = relative.split('/').peekable();
    while let Some(part) = parts.next() {
        let mut found = None;
        let mut buffer = InfoBuffer([0; 1024]);
        let mut end = false;
        for index in 0..=MAX_DIRECTORY_ENTRIES {
            let Some(info) = directory
                .read_entry(&mut buffer.0)
                .map_err(|_| "cannot enumerate bounded host firmware path")?
            else {
                end = true;
                break;
            };
            if index == MAX_DIRECTORY_ENTRIES {
                return Err("host firmware directory has too many entries");
            }
            let name = info.file_name().to_string();
            if name.eq_ignore_ascii_case(part) {
                if found.is_some() {
                    return Err("ambiguous host firmware path case aliases");
                }
                found = Some(name);
            }
        }
        if !end {
            return Err("host firmware directory has too many entries");
        }
        let Some(name) = found else {
            return Ok(None);
        };
        let name =
            CString16::try_from(name.as_str()).map_err(|_| "host firmware path is not UCS-2")?;
        let handle = directory
            .open(&name, FileMode::Read, FileAttribute::empty())
            .map_err(|_| "cannot open present host firmware path")?;
        if parts.peek().is_none() {
            return handle
                .into_regular_file()
                .map(Some)
                .ok_or("host firmware file is a directory");
        }
        directory = handle
            .into_directory()
            .ok_or("host firmware parent is not a directory")?;
    }
    Err("empty host firmware path")
}

fn read_file(
    mut file: RegularFile,
    expected: Option<usize>,
    limit: usize,
) -> Result<Region, &'static str> {
    let mut info = InfoBuffer([0; 1024]);
    let size = file
        .get_info::<FileInfo>(&mut info.0)
        .map_err(|_| "cannot read bounded host firmware file metadata")?
        .file_size();
    let length = usize::try_from(size).map_err(|_| "host firmware file size overflow")?;
    if length == 0 || length > limit || expected.is_some_and(|n| n != length) {
        return Err("host firmware file length is outside its manifest/resource budget");
    }
    // Size and manifest-wide budgets are checked before this allocation.
    let physical = firmware::pages(length.div_ceil(PAGE))?;
    // SAFETY: fresh reserved LOADER_DATA pages, exclusively written here before
    // any immutable view is published. They are never freed or given to a guest.
    let buffer = unsafe { core::slice::from_raw_parts_mut(physical as *mut u8, length) };
    let mut done = 0;
    while done < length {
        let count = file
            .read(&mut buffer[done..])
            .map_err(|_| "cannot read host firmware file")?;
        if count == 0 {
            return Err("host firmware file truncated during read");
        }
        done += count;
    }
    let mut extra = [0];
    if file
        .read(&mut extra)
        .map_err(|_| "cannot finish host firmware file")?
        != 0
    {
        return Err("host firmware file grew during read");
    }
    Ok(Region {
        physical: physical as u64,
        bytes: size,
    })
}

/// Absence alone is optional. Any unreadable/malformed present manifest or
/// missing/corrupt resource is a boot refusal, with no alternate-volume search.
pub fn read(root: &mut Directory) -> Result<Resources, &'static str> {
    let Some(file) = open(root, manifest::MANIFEST_PATH)? else {
        output::arguments(format_args!("HOST FIRMWARE manifest=absent\n"));
        return Ok(Resources::absent());
    };
    let region = read_file(file, None, MAX_MANIFEST_BYTES)?;
    // SAFETY: read_file reserved these pages and completed all writes.
    let bytes =
        unsafe { core::slice::from_raw_parts(region.physical as *const u8, region.bytes as usize) };
    let parsed = Manifest::parse(bytes).map_err(report)?;
    let mut resources = Resources {
        present: true,
        manifest: region,
        count: parsed.images.len(),
        ..Resources::absent()
    };
    // Parse/identity checks and the total budget precede every image allocation.
    for (slot, image) in resources.images.iter_mut().zip(&parsed.images) {
        let path = format!("{}/{}", manifest::DIRECTORY, image.path);
        let file = open(root, &path)?.ok_or("host firmware manifest names a missing resource")?;
        *slot = read_file(file, Some(image.length), manifest::MAX_IMAGE_BYTES)?;
    }
    // SAFETY: only this loader owns these permanent pages; identity alias is
    // currently mapped by firmware. Drop metadata before engine relocation.
    let catalog = unsafe { resources.catalog(|physical| physical, Some("before-ebs")) }?
        .ok_or("missing host firmware catalog")?;
    let (images, total) = catalog.inventory();
    output::arguments(format_args!(
        "HOST FIRMWARE phase=before-ebs images={images} bytes={total}\n"
    ));
    Ok(resources)
}
