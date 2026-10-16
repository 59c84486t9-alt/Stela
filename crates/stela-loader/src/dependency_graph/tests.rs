use super::*;
#[test]
fn dependency_context_follows_immediate_load_then_recursive_descent() {
    fn visit(graph: &[&[usize]]) -> Vec<(usize, Vec<usize>)> {
        let mut traversal = DependencyTraversal::new();
        let mut result = Vec::new();
        while let Some((node, ancestors)) = traversal.next() {
            traversal.descend(node, &ancestors, graph[node]);
            result.push((node, ancestors));
        }
        result
    }
    assert_eq!(
        visit(&[&[1, 2], &[3], &[4], &[4], &[]]),
        vec![
            (0, vec![]),
            (1, vec![0]),
            (3, vec![1, 0]),
            (4, vec![3, 1, 0]),
            (2, vec![0])
        ]
    );
    // B is loaded as main's sibling before A recursively processes B;
    // B's dependencies inherit A's context, not its file-loading context.
    assert_eq!(
        visit(&[&[1, 2], &[2, 0], &[3], &[]]),
        vec![
            (0, vec![]),
            (1, vec![0]),
            (2, vec![1, 0]),
            (3, vec![2, 1, 0])
        ]
    );
}
#[test]
fn guest_tree_lookup_refuses_symlinks_outside_root_and_nonfiles() {
    let root = tempfile::tempdir().unwrap();
    let root_path = root.path().canonicalize().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("lib"), b"source").unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(outside.path().join("lib"), root.path().join("lib")).unwrap();
        assert!(inside(&root_path, "/lib").is_err());
    }
    assert!(inside(&root_path, "/missing").is_err());
    assert!(inside(&root_path, "/").is_err());
    std::fs::write(root.path().join("real"), b"source").unwrap();
    assert_eq!(
        inside(&root_path, "/real").unwrap(),
        root.path().join("real").canonicalize().unwrap()
    );
}
