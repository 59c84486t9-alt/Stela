//! Partial evaluation of AARCHMRS accessor trees against the profile: every
//! condition the profile decides becomes `AST.Bool`, so only run-time
//! conditions remain. The profile has no EL3 and only Non-secure state, so
//! `EL2Enabled()` is TRUE and every Secure or EL3 test folds; without
//! FEAT_E2H0, `EffectiveHCR_EL2_E2H()` is '1'. The profile has no halting
//! debug, so `Halted()` and `HaltingAllowed()` are FALSE.
use super::expression::Profile;
use serde_json::{Value, json};

fn boolean(value: bool) -> Value {
    json!({"_type": "AST.Bool", "value": value})
}

pub fn as_bool(node: &Value) -> Option<bool> {
    (node["_type"] == "AST.Bool").then(|| node["value"].as_bool().unwrap_or(false))
}

fn identifier(node: &Value) -> Option<&str> {
    (node["_type"] == "AST.Identifier")
        .then(|| node["value"].as_str())
        .flatten()
}

fn level(node: &Value) -> Option<u8> {
    identifier(node)?.strip_prefix("EL")?.parse().ok()
}

fn is_current_el(node: &Value) -> bool {
    node["_type"] == "AST.DotAtom"
        && node["values"][0]["value"] == "PSTATE"
        && node["values"][1]["value"] == "EL"
}

pub fn fold(node: &Value, profile: &Profile) -> Value {
    let Some(kind) = node["_type"].as_str() else {
        return match node {
            Value::Array(list) => list.iter().map(|item| fold(item, profile)).collect(),
            other => other.clone(),
        };
    };
    match kind {
        "AST.Function" => function(node, profile),
        "AST.Identifier" => {
            let name = identifier(node).unwrap_or("");
            if profile.parameters.contains(name) && !profile.varying.contains(name) {
                boolean(profile.features.contains(name))
            } else {
                node.clone()
            }
        }
        "AST.UnaryOp" if node["op"] == "!" => {
            let inner = fold(&node["expr"], profile);
            match as_bool(&inner) {
                Some(value) => boolean(!value),
                None => json!({"_type": "AST.UnaryOp", "op": "!", "expr": inner}),
            }
        }
        "AST.BinaryOp" => binary(node, profile),
        _ => {
            let mut out = node.clone();
            if let Value::Object(map) = &mut out {
                for (key, value) in map.iter_mut() {
                    if key != "_type" {
                        *value = fold(value, profile);
                    }
                }
            }
            out
        }
    }
}

fn binary(node: &Value, profile: &Profile) -> Value {
    let op = node["op"].as_str().unwrap_or("");
    let left = fold(&node["left"], profile);
    let right = fold(&node["right"], profile);
    let (l, r) = (as_bool(&left), as_bool(&right));
    match op {
        "&&" => match (l, r) {
            (Some(false), _) | (_, Some(false)) => return boolean(false),
            (Some(true), _) => return right,
            (_, Some(true)) => return left,
            _ => {}
        },
        "||" => match (l, r) {
            (Some(true), _) | (_, Some(true)) => return boolean(true),
            (Some(false), _) => return right,
            (_, Some(false)) => return left,
            _ => {}
        },
        "==" | "!=" => {
            let equal = if is_current_el(&left) && level(&right).is_some_and(|el| el > 2) {
                Some(false)
            } else if let (Some(a), Some(b)) = (identifier(&left), identifier(&right)) {
                let constant = |name: &str| name.starts_with("SS_") || name.starts_with("EL");
                (constant(a) && constant(b)).then_some(a == b)
            } else if let (Some(a), Some(b)) = (l, r) {
                Some(a == b)
            } else if left["_type"] == "Values.Value" && right["_type"] == "Values.Value" {
                let bits = |node: &Value| node["value"].as_str().unwrap_or("").to_owned();
                let (a, b) = (bits(&left), bits(&right));
                (!a.contains('x') && !b.contains('x')).then(|| a == b)
            } else {
                None
            };
            if let Some(equal) = equal {
                return boolean(if op == "==" { equal } else { !equal });
            }
        }
        "IN" if left["_type"] == "Values.Value" => {
            let value = left["value"]
                .as_str()
                .unwrap_or("")
                .trim_matches('\'')
                .to_owned();
            if !value.contains('x') {
                let matches = |pattern: &str| {
                    let pattern = pattern.trim_matches('\'');
                    pattern.len() == value.len()
                        && pattern
                            .chars()
                            .zip(value.chars())
                            .all(|(p, v)| p == 'x' || p == v)
                };
                let any = right["values"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|pattern| matches(pattern["value"].as_str().unwrap_or("")));
                return boolean(any);
            }
        }
        _ => {}
    }
    json!({"_type": "AST.BinaryOp", "op": op, "left": left, "right": right})
}

fn function(node: &Value, profile: &Profile) -> Value {
    let name = node["name"].as_str().unwrap_or("");
    let arguments = &node["arguments"];
    let first = &arguments[0];
    let decided = match name {
        // A feature only some of the profile's CPUs have stays a run-time
        // question.
        "IsFeatureImplemented" => identifier(first)
            .filter(|feature| !profile.varying.contains(*feature))
            .map(|feature| profile.features.contains(feature)),
        "HaveEL" => level(first).map(|el| el <= profile.highest_el),
        "IsHighestEL" => level(first).map(|el| el == profile.highest_el),
        "ELUsingAArch32" => Some(false),
        "EL2Enabled" => Some(profile.highest_el >= 2),
        "EL3SDDUndef" | "EL3SDDUndefPriority" => Some(false),
        "Halted" | "HaltingAllowed" => Some(false),
        "IsCurrentSecurityState" => identifier(first).map(|state| state == "SS_NonSecure"),
        "ValidSecurityStateAtEL" => Some(true),
        "ImpDefBool" => first["value"]
            .as_str()
            .and_then(super::codegen::impdef_choice),
        _ => None,
    };
    if let Some(value) = decided {
        return boolean(value);
    }
    match name {
        "SecurityStateAtEL" => json!({"_type": "AST.Identifier", "value": "SS_NonSecure"}),
        "EffectiveHCR_EL2_E2H"
            if profile.features.contains("FEAT_VHE") && !profile.features.contains("FEAT_E2H0") =>
        {
            json!({"_type": "Values.Value", "value": "'1'"})
        }
        "EffectiveSCR_EL3_NS" => json!({"_type": "Values.Value", "value": "'1'"}),
        "EffectiveHCR_EL2_NVx" if !profile.features.contains("FEAT_NV") => {
            json!({"_type": "Values.Value", "value": "'000'"})
        }
        _ => {
            let mut out = node.clone();
            out["arguments"] = fold(arguments, profile);
            out
        }
    }
}

/// A folded permission tree: an ordered choice, the first true condition
/// winning, or a leaf statement list.
pub enum Tree {
    Choice(Vec<(Value, Tree)>),
    Leaf(Vec<Value>),
}

pub fn tree(access: &Value, profile: &Profile) -> Tree {
    if access["_type"] == "Accessors.Permission.SystemAccess" {
        return tree(&access["access"], profile);
    }
    if let Value::Array(list) = access {
        if list
            .iter()
            .all(|item| item["_type"] == "Accessors.Permission.SystemAccess")
        {
            let mut choices = Vec::new();
            for item in list {
                let condition = if item["condition"].is_null() {
                    boolean(true)
                } else {
                    fold(&item["condition"], profile)
                };
                if as_bool(&condition) == Some(false) {
                    continue;
                }
                let last = as_bool(&condition) == Some(true);
                choices.push((condition, tree(&item["access"], profile)));
                if last {
                    break;
                }
            }
            return Tree::Choice(choices);
        }
        return Tree::Leaf(list.iter().map(|item| fold(item, profile)).collect());
    }
    if access.is_null() {
        return Tree::Leaf(Vec::new());
    }
    Tree::Leaf(vec![fold(access, profile)])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recorded_implementation_defined_choices_fold() {
        let profile = Profile {
            parameters: Default::default(),
            features: Default::default(),
            highest_el: 2,
            varying: Default::default(),
        };
        let impdef = |text: &str| {
            json!({"_type": "AST.Function", "name": "ImpDefBool",
                   "arguments": [{"_type": "Types.String", "value": text}]})
        };
        let folded = fold(
            &impdef("Implementation can reset into AArch32 state"),
            &profile,
        );
        assert_eq!(as_bool(&folded), Some(false));
        let undecided = impdef("Something undecided");
        assert_eq!(fold(&undecided, &profile), undecided);
    }
}
