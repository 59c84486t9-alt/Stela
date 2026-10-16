use super::*;

#[test]
fn groups_thousands() {
    assert_eq!(group(7), "7");
    assert_eq!(group(3201), "3,201");
    assert_eq!(group(1_234_567), "1,234,567");
}

#[test]
fn checklist_has_every_documented_form() -> Result<()> {
    let checklist = fs::read_to_string(root().join(CHECKLIST))?;
    assert_eq!(checklist_forms(&checklist)?.len(), 4332);
    Ok(())
}
