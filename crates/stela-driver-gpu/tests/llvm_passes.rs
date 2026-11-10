//! Every LLVM pass pipeline the AIR compiler runs is one Stela's LLVM
//! (`src/compat/llvm/passes.cpp`) runs. Host builds of the compiler link a
//! full LLVM, where any pass name works, so only this check finds a name
//! `stela.efi` would refuse.

use std::fs;
use std::path::Path;

/// The string literal pipelines `source` passes to the pass C API.
fn pipelines(source: &str) -> Vec<String> {
    let mut found = vec![];
    for call in ["LLVMRunPasses(", "LLVMRunPassesOnFunction("] {
        for (at, _) in source.match_indices(call) {
            let rest = &source[at + call.len()..];
            let Some(open) = rest.find('"') else { continue };
            // The pipeline is the second argument, before any further comma.
            if rest[..open].matches(',').count() != 1 {
                continue;
            }
            let name = &rest[open + 1..];
            if let Some(close) = name.find('"') {
                found.push(name[..close].to_string());
            }
        }
    }
    found
}

#[test]
fn compiler_passes_exist_in_stelas_llvm() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let registry = fs::read_to_string(root.join("compat/llvm/passes.cpp")).unwrap();
    let mut checked = 0;
    for entry in fs::read_dir(root.join("compiler")).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "c") {
            continue;
        }
        let source = fs::read_to_string(&path).unwrap();
        for name in pipelines(&source) {
            assert!(
                registry.contains(&format!("pipeline == \"{name}\"")),
                "{} runs \"{name}\", which Stela's LLVM does not have",
                path.display()
            );
            checked += 1;
        }
    }
    assert!(checked >= 4, "found only {checked} pass pipelines");
}
