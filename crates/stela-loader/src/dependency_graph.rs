//! Read-only dependency discovery inside an explicitly supplied guest tree.
//! Missing images remain reported; no host dylib/shared-cache fallback occurs.
use super::{
    dependency_paths::{self, PathContext, RPath},
    linked_images::{DependencyLink, ImageInput},
    load_plan::{self, LoadPlan},
    mapped_image,
};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

const MAX_IMAGES: usize = 32;
const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_DEPENDENCIES: usize = 4096;

pub struct DiscoveryOptions {
    pub guest_root: PathBuf,
    pub guest_path: Option<String>,
    pub architecture: Option<String>,
    pub image_base: Option<u64>,
    pub library_base: u64,
    pub library_stride: u64,
}

#[derive(Debug, Serialize)]
pub struct DiscoveredImage {
    pub index: usize,
    pub guest_path: String,
    pub host_path: PathBuf,
    pub container_sha256: String,
    pub slice_offset: u64,
    pub load_base: u64,
    pub plan: LoadPlan,
    pub ancestor_chain: Vec<usize>,
}

#[derive(Default)]
struct DependencyTraversal {
    pending: Vec<(usize, Vec<usize>)>,
    processed: BTreeSet<usize>,
}
impl DependencyTraversal {
    fn new() -> Self {
        Self {
            pending: vec![(0, vec![])],
            ..Self::default()
        }
    }
    fn next(&mut self) -> Option<(usize, Vec<usize>)> {
        while let Some((index, ancestors)) = self.pending.pop() {
            if self.processed.insert(index) {
                return Some((index, ancestors));
            }
        }
        None
    }
    fn descend(&mut self, requester: usize, ancestors: &[usize], children: &[usize]) {
        let mut chain = vec![requester];
        chain.extend_from_slice(ancestors);
        self.pending
            .extend(children.iter().rev().map(|&child| (child, chain.clone())));
    }
}

#[derive(Debug, Serialize)]
pub struct PathAttempt {
    pub guest_path: String,
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct DependencyEdge {
    pub requester: usize,
    pub ordinal: usize,
    pub name: String,
    pub provider: Option<usize>,
    pub candidates: Vec<PathAttempt>,
}

#[derive(Debug, Serialize)]
pub struct DependencyGraph {
    pub guest_root: PathBuf,
    pub images: Vec<DiscoveredImage>,
    pub edges: Vec<DependencyEdge>,
    pub complete_dependency_graph: bool,
    pub unresolved_dependencies: usize,
}

pub struct Discovery {
    pub inputs: Vec<ImageInput>,
    pub links: Vec<DependencyLink>,
    pub graph: DependencyGraph,
}

fn inside(root: &Path, guest: &str) -> Result<PathBuf> {
    let path = root.join(
        guest
            .strip_prefix('/')
            .context("guest path is not absolute")?,
    );
    let canonical = path
        .canonicalize()
        .with_context(|| format!("guest file not available: {guest:?}"))?;
    ensure!(
        canonical.starts_with(root),
        "guest symlink escapes supplied filesystem root"
    );
    ensure!(
        canonical.is_file(),
        "guest path does not identify a regular file"
    );
    Ok(canonical)
}

fn read_input(
    path: &Path,
    architecture: Option<&str>,
    base: Option<u64>,
    library: bool,
) -> Result<(ImageInput, LoadPlan)> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_FILE_BYTES,
        "guest image exceeds discovery input limit"
    );
    let (slice_offset, slice) = super::select_slice(&bytes, path, architecture)?;
    let plan = if library {
        load_plan::plan_library(slice)?
    } else {
        load_plan::plan(slice)?
    };
    let load_base = base.unwrap_or(mapped_image::preferred_base(&plan)?);
    ensure!(
        (i128::from(load_base) - i128::from(mapped_image::preferred_base(&plan)?)) % 0x4000 == 0,
        "discovered image slide must be a multiple of 16 KiB"
    );
    Ok((
        ImageInput {
            data: slice.to_vec(),
            container_sha256: stela_core::sha256(&bytes),
            slice_offset,
            load_base: Some(load_base),
        },
        plan,
    ))
}

/// Load each image's immediate dependencies, then recursively process them in
/// command order. The first dependency-processing context supplies its runpath
/// ancestors, even when the file was loaded earlier as another node's sibling.
/// Canonical paths deduplicate symlink aliases/cycles.
/// Search uses only the guest tree and recorded owner-aware LC_RPATH chains.
/// Unsupported/missing candidates become explicit unresolved edges, never stubs.
pub fn discover(main: &Path, options: DiscoveryOptions) -> Result<Discovery> {
    let root = options
        .guest_root
        .canonicalize()
        .context("guest filesystem root is unavailable")?;
    ensure!(root.is_dir(), "guest filesystem root is not a directory");
    ensure!(
        options.library_stride > 0 && options.library_stride.is_multiple_of(0x4000),
        "library stride must be a positive 16 KiB multiple"
    );
    let main_path = main.canonicalize()?;
    ensure!(
        main_path.starts_with(&root),
        "main image is outside the supplied guest root"
    );
    let guest_path = if let Some(path) = options.guest_path {
        let guest = dependency_paths::normalize_guest_path(&path)?;
        ensure!(
            inside(&root, &guest)? == main_path,
            "guest main path does not identify the supplied main file"
        );
        guest
    } else {
        let relative = main_path
            .strip_prefix(&root)?
            .to_str()
            .context("non-UTF-8 guest main path")?;
        dependency_paths::normalize_guest_path(&format!("/{relative}"))?
    };
    let (input, plan) = read_input(
        &main_path,
        options.architecture.as_deref(),
        options.image_base,
        false,
    )?;
    let mut inputs = vec![input];
    let mut nodes = vec![DiscoveredImage {
        index: 0,
        guest_path: guest_path.clone(),
        host_path: main_path.clone(),
        container_sha256: inputs[0].container_sha256.clone(),
        slice_offset: inputs[0].slice_offset,
        load_base: inputs[0].load_base.context("missing main placement")?,
        plan,
        ancestor_chain: vec![],
    }];
    let mut identities = BTreeMap::from([(main_path, 0usize)]);
    let mut edges = Vec::new();
    let mut links = Vec::new();
    let mut traversal = DependencyTraversal::new();
    while let Some((requester, ancestors)) = traversal.next() {
        nodes[requester].ancestor_chain = ancestors.clone();
        let chain = std::iter::once(requester).chain(ancestors.iter().copied());
        let mut children = Vec::new();
        let mut rpaths = Vec::new();
        for index in chain {
            rpaths.extend(nodes[index].plan.rpaths.iter().map(|value| RPath {
                owner: nodes[index].guest_path.clone(),
                value: value.clone(),
            }));
        }
        let dependencies = nodes[requester].plan.dependencies.clone();
        for (position, dependency) in dependencies.into_iter().enumerate() {
            ensure!(
                edges.len() < MAX_DEPENDENCIES,
                "dependency graph exceeds edge limit"
            );
            let ordinal = position + 1;
            let mut edge = DependencyEdge {
                requester,
                ordinal,
                name: dependency.name.clone(),
                provider: None,
                candidates: vec![],
            };
            if dependency.command != object::macho::LC_LOAD_DYLIB {
                edge.candidates.push(PathAttempt {
                    guest_path: dependency.name,
                    reason: "unsupported nonordinary dependency command".into(),
                });
                edges.push(edge);
                continue;
            }
            let paths = dependency_paths::candidates(
                &dependency.name,
                &PathContext {
                    executable: &guest_path,
                    loader: &nodes[requester].guest_path,
                    rpaths: &rpaths,
                },
            );
            let paths = match paths {
                Ok(paths) => paths,
                Err(error) => {
                    edge.candidates.push(PathAttempt {
                        guest_path: dependency.name,
                        reason: format!("unsupported path expansion: {error:#}"),
                    });
                    edges.push(edge);
                    continue;
                }
            };
            if paths.is_empty() {
                edge.candidates.push(PathAttempt {
                    guest_path: dependency.name.clone(),
                    reason: "no declared LC_RPATH candidates".into(),
                });
            }
            for candidate in paths {
                let selected = (|| -> Result<usize> {
                    let path = inside(&root, &candidate)?;
                    if let Some(index) = identities.get(&path) {
                        ensure!(
                            *index != 0,
                            "ordinary dylib dependency resolves to the main executable"
                        );
                        return Ok(*index);
                    }
                    ensure!(
                        nodes.len() < MAX_IMAGES,
                        "dependency graph exceeds image limit"
                    );
                    let base = options
                        .library_base
                        .checked_add(
                            options
                                .library_stride
                                .checked_mul((nodes.len() - 1) as u64)
                                .context("library placement overflow")?,
                        )
                        .context("library placement overflow")?;
                    let (input, plan) =
                        read_input(&path, options.architecture.as_deref(), Some(base), true)?;
                    let index = nodes.len();
                    nodes.push(DiscoveredImage {
                        index,
                        guest_path: candidate.clone(),
                        host_path: path.clone(),
                        container_sha256: input.container_sha256.clone(),
                        slice_offset: input.slice_offset,
                        load_base: base,
                        plan,
                        ancestor_chain: vec![],
                    });
                    inputs.push(input);
                    identities.insert(path, index);
                    Ok(index)
                })();
                match selected {
                    Ok(provider) => {
                        edge.provider = Some(provider);
                        edge.candidates.push(PathAttempt {
                            guest_path: candidate,
                            reason: "selected guest image".into(),
                        });
                        links.push(DependencyLink {
                            requester,
                            ordinal,
                            provider,
                        });
                        break;
                    }
                    Err(error) => edge.candidates.push(PathAttempt {
                        guest_path: candidate,
                        reason: format!("{error:#}"),
                    }),
                }
            }
            if let Some(provider) = edge.provider {
                children.push(provider);
            }
            edges.push(edge);
        }
        traversal.descend(requester, &ancestors, &children);
    }
    let unresolved_dependencies = edges.iter().filter(|edge| edge.provider.is_none()).count();
    Ok(Discovery {
        inputs,
        links,
        graph: DependencyGraph {
            guest_root: root,
            images: nodes,
            edges,
            complete_dependency_graph: unresolved_dependencies == 0,
            unresolved_dependencies,
        },
    })
}

#[cfg(test)]
mod tests;
