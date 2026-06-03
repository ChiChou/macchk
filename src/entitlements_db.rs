//! Security-relevant macOS/iOS entitlement rules.
//!
//! Rule data lives in `entitlements_db.rules` so adding or adjusting
//! entitlement semantics does not require editing Rust syntax. The Rust side
//! loads a small grouped text DSL and applies its value interpretation.

use std::collections::HashSet;
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Impact {
    Strengthens,
    Weakens,
    Info,
}

/// How an entitlement's plist value should be interpreted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValueRule {
    /// The key being present is enough; the value carries parameters.
    Exists,
    /// The entitlement is active only when its boolean value is true.
    BooleanTrue,
}

#[derive(Debug)]
pub struct EntitlementInfo {
    pub key: String,
    pub impact: Impact,
    pub value_rule: ValueRule,
    pub short_desc: String,
    pub category: String,
}

static ENTITLEMENTS: OnceLock<Vec<EntitlementInfo>> = OnceLock::new();

fn rules() -> &'static [EntitlementInfo] {
    ENTITLEMENTS
        .get_or_init(|| {
            parse_rules(include_str!("entitlements_db.rules"))
                .expect("embedded entitlement rule DSL must be valid")
        })
        .as_slice()
}

pub fn lookup(key: &str) -> Option<&'static EntitlementInfo> {
    rules().iter().find(|rule| rule.key == key)
}

pub fn classify(key: &str) -> Option<(Impact, &'static str, ValueRule)> {
    lookup(key).map(|info| (info.impact, info.short_desc.as_str(), info.value_rule))
}

fn parse_rules(input: &str) -> Result<Vec<EntitlementInfo>, String> {
    let mut current_section: Option<Section> = None;
    let mut rules = Vec::new();
    let mut seen_keys = HashSet::new();

    for (line_index, raw_line) in input.lines().enumerate() {
        let line_number = line_index + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if line.starts_with('[') || line.ends_with(']') {
            current_section = Some(parse_section(line_number, line)?);
            continue;
        }

        let section = current_section
            .as_ref()
            .ok_or_else(|| format!("line {line_number}: entry appears before any section"))?;
        let (key, short_desc) = line
            .split_once('=')
            .ok_or_else(|| format!("line {line_number}: expected `key = short description`"))?;
        let key = key.trim();
        let short_desc = short_desc.trim();
        if key.is_empty() {
            return Err(format!("line {line_number}: entitlement key is empty"));
        }
        if short_desc.is_empty() {
            return Err(format!("line {line_number}: short description is empty"));
        }
        if !seen_keys.insert(key.to_string()) {
            return Err(format!(
                "line {line_number}: duplicate entitlement key `{key}`"
            ));
        }

        rules.push(EntitlementInfo {
            key: key.to_string(),
            impact: section.impact,
            value_rule: section.value_rule,
            short_desc: short_desc.to_string(),
            category: section.category.clone(),
        });
    }

    Ok(rules)
}

#[derive(Debug)]
struct Section {
    category: String,
    impact: Impact,
    value_rule: ValueRule,
}

fn parse_section(line_number: usize, line: &str) -> Result<Section, String> {
    if !line.starts_with('[') || !line.ends_with(']') {
        return Err(format!(
            "line {line_number}: section must use `[category impact rule]`"
        ));
    }

    let inner = &line[1..line.len() - 1];
    let parts: Vec<_> = inner.split_whitespace().collect();
    if parts.len() != 3 {
        return Err(format!(
            "line {line_number}: section must contain category, impact, and rule"
        ));
    }

    Ok(Section {
        category: parts[0].to_string(),
        impact: parse_impact(line_number, parts[1])?,
        value_rule: parse_value_rule(line_number, parts[2])?,
    })
}

fn parse_impact(line_number: usize, value: &str) -> Result<Impact, String> {
    match value {
        "strengthens" => Ok(Impact::Strengthens),
        "weakens" => Ok(Impact::Weakens),
        "info" => Ok(Impact::Info),
        _ => Err(format!("line {line_number}: unknown impact `{value}`")),
    }
}

fn parse_value_rule(line_number: usize, value: &str) -> Result<ValueRule, String> {
    match value {
        "bool" | "boolean_true" => Ok(ValueRule::BooleanTrue),
        "exists" => Ok(ValueRule::Exists),
        _ => Err(format!("line {line_number}: unknown value rule `{value}`")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_embedded_rule_dsl() {
        assert!(rules().len() > 100);
    }

    #[test]
    fn boolean_entitlements_are_explicit() {
        let (_, _, rule) = classify("com.apple.security.app-sandbox").unwrap();
        assert_eq!(rule, ValueRule::BooleanTrue);
    }

    #[test]
    fn parses_grouped_rule_dsl() {
        let parsed = parse_rules(
            r#"
            [sandbox strengthens bool]
            com.apple.security.app-sandbox = App Sandbox enabled

            [sandbox_exception weakens exists]
            com.apple.security.temporary-exception.audio-unit-host = sandbox exception
            "#,
        )
        .unwrap();

        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].category, "sandbox");
        assert_eq!(parsed[0].impact, Impact::Strengthens);
        assert_eq!(parsed[0].value_rule, ValueRule::BooleanTrue);
        assert_eq!(parsed[1].category, "sandbox_exception");
        assert_eq!(parsed[1].impact, Impact::Weakens);
        assert_eq!(parsed[1].value_rule, ValueRule::Exists);
    }

    #[test]
    fn presence_entitlements_are_explicit() {
        let (_, _, rule) =
            classify("com.apple.security.temporary-exception.mach-lookup.global-name").unwrap();
        assert_eq!(rule, ValueRule::Exists);
    }

    #[test]
    fn boolean_capability_entitlements_are_explicit() {
        let (_, _, rule) = classify("com.apple.private.memorystatus").unwrap();
        assert_eq!(rule, ValueRule::BooleanTrue);
    }

    #[test]
    fn mixed_parameter_entitlements_remain_presence_based() {
        let (_, _, rule) = classify("com.apple.private.enable-coredump-on-panic").unwrap();
        assert_eq!(rule, ValueRule::Exists);
    }
}
