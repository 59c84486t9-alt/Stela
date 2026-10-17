//! AARCHMRS conditions (`AST.*` nodes) evaluated against a fixed feature
//! profile. As in the generated accessors ([`super::fold`]),
//! `EffectiveHCR_EL2_E2H()` is '1' with FEAT_VHE and without FEAT_E2H0.
//! Anything the profile does not decide, such as a run-time control
//! (`HCR_EL2.TGE`) or an ID field value, is `Dynamic`: the requirement exists
//! in some configuration of the profile.
use serde_json::Value;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Truth {
    True,
    False,
    Dynamic,
}

impl Truth {
    fn from_bool(value: bool) -> Self {
        if value { Self::True } else { Self::False }
    }

    fn not(self) -> Self {
        match self {
            Self::True => Self::False,
            Self::False => Self::True,
            Self::Dynamic => Self::Dynamic,
        }
    }

    fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::False, _) | (_, Self::False) => Self::False,
            (Self::True, Self::True) => Self::True,
            _ => Self::Dynamic,
        }
    }

    fn or(self, other: Self) -> Self {
        self.not().and(other.not()).not()
    }
}

/// The declared profile: implemented features and exception levels.
pub struct Profile {
    /// Every Boolean parameter of `Features.json`.
    pub parameters: BTreeSet<String>,
    pub features: BTreeSet<String>,
    /// The highest implemented EL.
    pub highest_el: u8,
}

enum Term {
    Truth(Truth),
    Level(u8),
    Integer(i64),
    /// A bit string without don't-care bits.
    Bits(String),
    Unknown,
}

impl Profile {
    pub fn truth(&self, node: &Value) -> Truth {
        match self.term(node) {
            Term::Truth(truth) => truth,
            _ => Truth::Dynamic,
        }
    }

    fn feature(&self, name: &str) -> Option<Truth> {
        self.parameters
            .contains(name)
            .then(|| Truth::from_bool(self.features.contains(name)))
    }

    fn term(&self, node: &Value) -> Term {
        match node["_type"].as_str().unwrap_or("") {
            "AST.Bool" => Term::Truth(Truth::from_bool(node["value"].as_bool().unwrap_or(false))),
            "AST.Integer" => node["value"].as_i64().map_or(Term::Unknown, Term::Integer),
            "AST.Identifier" => {
                let name = node["value"].as_str().unwrap_or("");
                if let Some(truth) = self.feature(name) {
                    Term::Truth(truth)
                } else if let Some(level) = name.strip_prefix("EL").and_then(|n| n.parse().ok()) {
                    Term::Level(level)
                } else {
                    Term::Unknown
                }
            }
            "AST.UnaryOp" if node["op"] == "!" => match self.term(&node["expr"]) {
                Term::Truth(truth) => Term::Truth(truth.not()),
                _ => Term::Unknown,
            },
            "AST.BinaryOp" => self.binary(node),
            "AST.Function" => self.function(node),
            "Values.Value" => {
                let bits = node["value"].as_str().unwrap_or("").trim_matches('\'');
                if !bits.is_empty() && bits.bytes().all(|b| b == b'0' || b == b'1') {
                    Term::Bits(bits.to_owned())
                } else {
                    Term::Unknown
                }
            }
            _ => Term::Unknown,
        }
    }

    fn binary(&self, node: &Value) -> Term {
        let op = node["op"].as_str().unwrap_or("");
        let (left, right) = (self.term(&node["left"]), self.term(&node["right"]));
        let truth = |term: &Term| match term {
            Term::Truth(truth) => *truth,
            _ => Truth::Dynamic,
        };
        let (l, r) = (truth(&left), truth(&right));
        Term::Truth(match op {
            "&&" => l.and(r),
            "||" => l.or(r),
            "==>" => l.not().or(r),
            "<=>" => l.and(r).or(l.not().and(r.not())),
            "==" | "!=" => {
                let equal = match (&left, &right) {
                    (Term::Level(a), Term::Level(b)) => Truth::from_bool(a == b),
                    (Term::Integer(a), Term::Integer(b)) => Truth::from_bool(a == b),
                    (Term::Bits(a), Term::Bits(b)) => Truth::from_bool(a == b),
                    (Term::Truth(a), Term::Truth(b))
                        if *a != Truth::Dynamic && *b != Truth::Dynamic =>
                    {
                        Truth::from_bool(a == b)
                    }
                    _ => Truth::Dynamic,
                };
                if op == "==" { equal } else { equal.not() }
            }
            _ => Truth::Dynamic,
        })
    }

    fn function(&self, node: &Value) -> Term {
        let argument = |index: usize| self.term(&node["arguments"][index]);
        match node["name"].as_str().unwrap_or("") {
            "IsFeatureImplemented" => match argument(0) {
                Term::Truth(truth) => Term::Truth(truth),
                _ => Term::Unknown,
            },
            "HaveEL" => match argument(0) {
                Term::Level(level) => Term::Truth(Truth::from_bool(level <= self.highest_el)),
                _ => Term::Unknown,
            },
            "IsHighestEL" => match argument(0) {
                Term::Level(level) => Term::Truth(Truth::from_bool(level == self.highest_el)),
                _ => Term::Unknown,
            },
            // The profile is AArch64-only.
            "ELUsingAArch32" => Term::Truth(Truth::False),
            // A recorded IMPLEMENTATION DEFINED choice.
            "ImpDefBool" => node["arguments"][0]["value"]
                .as_str()
                .and_then(super::codegen::impdef_choice)
                .map_or(Term::Unknown, |value| Term::Truth(Truth::from_bool(value))),
            // HCR_EL2.E2H is RES1 with VHE and without FEAT_E2H0.
            "EffectiveHCR_EL2_E2H"
                if self.features.contains("FEAT_VHE") && !self.features.contains("FEAT_E2H0") =>
            {
                Term::Bits("1".to_owned())
            }
            _ => Term::Unknown,
        }
    }
}

/// A condition as compact infix text for the matrix.
pub fn render(node: &Value) -> String {
    match node["_type"].as_str().unwrap_or("") {
        "AST.Bool" => node["value"].to_string(),
        "AST.Integer" => node["value"].to_string(),
        "AST.Identifier" => node["value"].as_str().unwrap_or("?").to_owned(),
        "AST.UnaryOp" => format!(
            "{}{}",
            node["op"].as_str().unwrap_or("?"),
            render(&node["expr"])
        ),
        "AST.BinaryOp" => format!(
            "({} {} {})",
            render(&node["left"]),
            node["op"].as_str().unwrap_or("?"),
            render(&node["right"])
        ),
        "AST.Function" => {
            let arguments: Vec<String> = node["arguments"]
                .as_array()
                .map(|arguments| arguments.iter().map(render).collect())
                .unwrap_or_default();
            format!(
                "{}({})",
                node["name"].as_str().unwrap_or("?"),
                arguments.join(", ")
            )
        }
        "Types.Field" => format!(
            "{}.{}",
            node["value"]["name"].as_str().unwrap_or("?"),
            node["value"]["field"].as_str().unwrap_or("?")
        ),
        "AST.Set" => {
            let values: Vec<String> = node["values"]
                .as_array()
                .map(|values| values.iter().map(render).collect())
                .unwrap_or_default();
            format!("{{{}}}", values.join(", "))
        }
        "Values.Value" => node["value"].as_str().unwrap_or("?").to_owned(),
        other => other.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn feature(name: &str) -> Value {
        json!({"_type": "AST.Function", "name": "IsFeatureImplemented",
               "arguments": [{"_type": "AST.Identifier", "value": name}]})
    }

    #[test]
    fn evaluates_features_levels_and_run_time_conditions() {
        let profile = Profile {
            parameters: ["FEAT_VHE", "FEAT_XS"].map(String::from).into(),
            features: ["FEAT_VHE"].map(String::from).into(),
            highest_el: 2,
        };
        assert_eq!(profile.truth(&feature("FEAT_VHE")), Truth::True);
        assert_eq!(profile.truth(&feature("FEAT_XS")), Truth::False);
        let have = |el: &str| {
            json!({"_type": "AST.Function", "name": "HaveEL",
                   "arguments": [{"_type": "AST.Identifier", "value": el}]})
        };
        assert_eq!(profile.truth(&have("EL2")), Truth::True);
        assert_eq!(profile.truth(&have("EL3")), Truth::False);
        let run_time = json!({"_type": "AST.Function", "name": "EffectiveHCR_EL2_TGE",
                              "arguments": []});
        // Without FEAT_E2H0, E2H is '1' as the generated accessors fold it.
        let e2h = json!({"_type": "AST.BinaryOp", "op": "==",
                         "left": {"_type": "AST.Function", "name": "EffectiveHCR_EL2_E2H",
                                  "arguments": []},
                         "right": {"_type": "Values.Value", "value": "'1'"}});
        assert_eq!(profile.truth(&e2h), Truth::True);
        // A recorded IMPLEMENTATION DEFINED choice decides; any other stays
        // a run-time question.
        let impdef = |text: &str| {
            json!({"_type": "AST.Function", "name": "ImpDefBool",
                   "arguments": [{"_type": "Types.String", "value": text}]})
        };
        assert_eq!(
            profile.truth(&impdef("Implementation can reset into AArch32 state")),
            Truth::False
        );
        assert_eq!(
            profile.truth(&impdef("Something undecided")),
            Truth::Dynamic
        );
        let and = |left: Value, right: Value| json!({"_type": "AST.BinaryOp", "op": "&&", "left": left, "right": right});
        assert_eq!(
            profile.truth(&and(feature("FEAT_VHE"), run_time.clone())),
            Truth::Dynamic
        );
        assert_eq!(
            profile.truth(&and(feature("FEAT_XS"), run_time)),
            Truth::False
        );
        assert_eq!(
            render(&and(feature("FEAT_VHE"), have("EL2"))),
            "(IsFeatureImplemented(FEAT_VHE) && HaveEL(EL2))"
        );
    }
}
