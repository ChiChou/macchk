use crate::codesign_parser::*;
use crate::detection::{AnalysisContext, Check};
use crate::types::*;

fn cs_flag_check(
    ctx: &AnalysisContext,
    id: CheckId,
    name: &'static str,
    polarity: Polarity,
    flag: u32,
    flag_name: &str,
) -> CheckResult {
    let cs = ctx.codesign_data();
    let (detected, evidence) = match cs {
        Some(info) => {
            let has = info.has_flag(flag);
            let ev = Evidence {
                strategy: "codesign_flag".into(),
                description: if has {
                    format!(
                        "{} ({:#x}) set in CS flags ({:#x})",
                        flag_name, flag, info.flags
                    )
                } else {
                    format!("{} not set in CS flags ({:#x})", flag_name, info.flags)
                },
                confidence: Confidence::Definitive,
                address: None,
                function_name: None,
            };
            (has, vec![ev])
        }
        None => (
            false,
            vec![Evidence {
                strategy: "codesign_flag".into(),
                description: "no code signature present".into(),
                confidence: Confidence::Definitive,
                address: None,
                function_name: None,
            }],
        ),
    };
    CheckResult {
        id,
        name: name.into(),
        category: Category::CodeSign,
        polarity,
        detected,
        evidence,
        stats: None,
    }
}

pub struct HardenedRuntimeCheck;
impl Check for HardenedRuntimeCheck {
    fn id(&self) -> CheckId {
        CheckId::HardenedRuntime
    }
    fn name(&self) -> &'static str {
        "Hardened Runtime"
    }
    fn min_level(&self) -> DetectionLevel {
        DetectionLevel::Quick
    }
    fn category(&self) -> Category {
        Category::CodeSign
    }
    fn polarity(&self) -> Polarity {
        Polarity::Positive
    }
    fn run(&self, ctx: &AnalysisContext) -> CheckResult {
        cs_flag_check(
            ctx,
            self.id(),
            self.name(),
            self.polarity(),
            CS_RUNTIME,
            "CS_RUNTIME",
        )
    }
}

pub struct CsRestrictCheck;
impl Check for CsRestrictCheck {
    fn id(&self) -> CheckId {
        CheckId::CsRestrict
    }
    fn name(&self) -> &'static str {
        "CS Restrict"
    }
    fn min_level(&self) -> DetectionLevel {
        DetectionLevel::Quick
    }
    fn category(&self) -> Category {
        Category::CodeSign
    }
    fn polarity(&self) -> Polarity {
        Polarity::Positive
    }
    fn run(&self, ctx: &AnalysisContext) -> CheckResult {
        cs_flag_check(
            ctx,
            self.id(),
            self.name(),
            self.polarity(),
            CS_RESTRICT,
            "CS_RESTRICT",
        )
    }
}

pub struct LibraryValidationCheck;
impl Check for LibraryValidationCheck {
    fn id(&self) -> CheckId {
        CheckId::LibraryValidation
    }
    fn name(&self) -> &'static str {
        "Library Validation"
    }
    fn min_level(&self) -> DetectionLevel {
        DetectionLevel::Quick
    }
    fn category(&self) -> Category {
        Category::CodeSign
    }
    fn polarity(&self) -> Polarity {
        Polarity::Positive
    }
    fn run(&self, ctx: &AnalysisContext) -> CheckResult {
        cs_flag_check(
            ctx,
            self.id(),
            self.name(),
            self.polarity(),
            CS_REQUIRE_LV,
            "CS_REQUIRE_LV",
        )
    }
}

pub struct CsHardKillCheck;
impl Check for CsHardKillCheck {
    fn id(&self) -> CheckId {
        CheckId::CsHardKill
    }
    fn name(&self) -> &'static str {
        "CS Hard+Kill"
    }
    fn min_level(&self) -> DetectionLevel {
        DetectionLevel::Quick
    }
    fn category(&self) -> Category {
        Category::CodeSign
    }
    fn polarity(&self) -> Polarity {
        Polarity::Positive
    }
    fn run(&self, ctx: &AnalysisContext) -> CheckResult {
        let cs = ctx.codesign_data();
        let (detected, evidence) = match cs {
            Some(info) => {
                let hard = info.has_flag(CS_HARD);
                let kill = info.has_flag(CS_KILL);
                let both = hard && kill;
                let desc = format!(
                    "CS_HARD={}, CS_KILL={} (flags={:#x})",
                    hard, kill, info.flags
                );
                (
                    both,
                    vec![Evidence {
                        strategy: "codesign_flag".into(),
                        description: desc,
                        confidence: Confidence::Definitive,
                        address: None,
                        function_name: None,
                    }],
                )
            }
            None => (
                false,
                vec![Evidence {
                    strategy: "codesign_flag".into(),
                    description: "no code signature present".into(),
                    confidence: Confidence::Definitive,
                    address: None,
                    function_name: None,
                }],
            ),
        };
        CheckResult {
            id: self.id(),
            name: self.name().into(),
            category: self.category(),
            polarity: self.polarity(),
            detected,
            evidence,
            stats: None,
        }
    }
}

pub struct SigningTypeCheck;
impl Check for SigningTypeCheck {
    fn id(&self) -> CheckId {
        CheckId::SigningType
    }
    fn name(&self) -> &'static str {
        "Signing Type"
    }
    fn min_level(&self) -> DetectionLevel {
        DetectionLevel::Quick
    }
    fn category(&self) -> Category {
        Category::CodeSign
    }
    fn polarity(&self) -> Polarity {
        Polarity::Info
    }
    fn run(&self, ctx: &AnalysisContext) -> CheckResult {
        let cs = ctx.codesign_data();
        let (signing_desc, _team) = match cs {
            Some(info) => {
                let desc = match &info.signing_type {
                    SigningType::Unsigned => "unsigned".to_string(),
                    SigningType::LinkerSigned => "linker-signed (unsigned equivalent)".to_string(),
                    SigningType::AdHoc => "ad-hoc signed".to_string(),
                    SigningType::DeveloperSigned => {
                        if let Some(ref tid) = info.team_id {
                            format!("developer-signed (team: {})", tid)
                        } else {
                            "developer-signed".to_string()
                        }
                    }
                    SigningType::PlatformBinary => {
                        format!("Apple platform binary (platform={})", info.platform)
                    }
                };
                (desc, info.team_id.clone())
            }
            None => ("unsigned (no LC_CODE_SIGNATURE)".to_string(), None),
        };
        CheckResult {
            id: self.id(),
            name: self.name().into(),
            category: self.category(),
            polarity: self.polarity(),
            detected: true, // Always has a value
            evidence: vec![Evidence {
                strategy: "signing_type".into(),
                description: signing_desc,
                confidence: Confidence::Definitive,
                address: None,
                function_name: None,
            }],
            stats: None,
        }
    }
}

/// CodeDirectory hash type mapping (from Apple Security CSCommon.h)
/// These values appear at offset 37 in the CS_CodeDirectory structure.
fn hash_type_name(ht: u8) -> &'static str {
    match ht {
        0 => "none",
        1 => "SHA-1",
        2 => "SHA-256",                // kSecCodeSignatureHashSHA256
        3 => "SHA-256 (truncated 20)", // kSecCodeSignatureHashSHA256Truncated (first 20 bytes of SHA-256)
        4 => "SHA-384",                // kSecCodeSignatureHashSHA384
        5 => "SHA-512",                // kSecCodeSignatureHashSHA512
        _ => "unknown",
    }
}

fn is_strong_hash(ht: u8) -> bool {
    matches!(ht, 2..=5) // SHA-256, SHA-256 (truncated), SHA-384, SHA-512
}

pub struct CodeSignHashTypeCheck;
impl Check for CodeSignHashTypeCheck {
    fn id(&self) -> CheckId {
        CheckId::CodeSignHashType
    }
    fn name(&self) -> &'static str {
        "CS Hash Type"
    }
    fn min_level(&self) -> DetectionLevel {
        DetectionLevel::Quick
    }
    fn category(&self) -> Category {
        Category::CodeSign
    }
    fn polarity(&self) -> Polarity {
        Polarity::Positive
    }
    fn run(&self, ctx: &AnalysisContext) -> CheckResult {
        let cs = ctx.codesign_data();
        let mut evidence = Vec::new();
        let mut has_strong = false;
        let mut has_weak = false;

        match cs {
            Some(info) => {
                for &ht in &info.hash_types {
                    let strong = is_strong_hash(ht);
                    if strong {
                        has_strong = true;
                    } else if ht == 1 {
                        has_weak = true;
                    }
                    evidence.push(Evidence {
                        strategy: "codedirectory_hash".into(),
                        description: format!(
                            "CodeDirectory hash: {} (type {}){}",
                            hash_type_name(ht),
                            ht,
                            if ht == 1 { " [WEAK]" } else { "" }
                        ),
                        confidence: Confidence::Definitive,
                        address: None,
                        function_name: None,
                    });
                }
                if has_weak && !has_strong {
                    evidence.push(Evidence {
                        strategy: "codedirectory_hash".into(),
                        description:
                            "no strong hash algorithm — SHA-1 only signatures are considered weak"
                                .into(),
                        confidence: Confidence::Definitive,
                        address: None,
                        function_name: None,
                    });
                }
            }
            None => {
                evidence.push(Evidence {
                    strategy: "codedirectory_hash".into(),
                    description: "no code signature present".into(),
                    confidence: Confidence::Definitive,
                    address: None,
                    function_name: None,
                });
            }
        }

        CheckResult {
            id: self.id(),
            name: self.name().into(),
            category: self.category(),
            polarity: self.polarity(),
            detected: has_strong,
            evidence,
            stats: None,
        }
    }
}

pub struct LaunchConstraintsCheck;
impl Check for LaunchConstraintsCheck {
    fn id(&self) -> CheckId {
        CheckId::LaunchConstraints
    }
    fn name(&self) -> &'static str {
        "Launch Constraints"
    }
    fn min_level(&self) -> DetectionLevel {
        DetectionLevel::Quick
    }
    fn category(&self) -> Category {
        Category::CodeSign
    }
    fn polarity(&self) -> Polarity {
        Polarity::Info
    }
    fn run(&self, ctx: &AnalysisContext) -> CheckResult {
        use crate::constraint_parser;

        let cs = ctx.codesign_data();
        let mut evidence = Vec::new();

        if let Some(info) = cs {
            let lc = &info.launch_constraints;
            let slots: &[(&str, &Option<Vec<u8>>)] = &[
                ("self", &lc.self_der),
                ("parent", &lc.parent_der),
                ("responsible", &lc.responsible_der),
                ("library", &lc.library_der),
            ];

            for &(label, der_opt) in slots {
                if let Some(der) = der_opt {
                    if let Some(decoded) = constraint_parser::decode_constraint(der) {
                        let details = decoded.describe();
                        if details.is_empty() {
                            evidence.push(Evidence {
                                strategy: "launch_constraint_blob".into(),
                                description: format!("[{}] present (no decodable facts)", label),
                                confidence: Confidence::High,
                                address: None,
                                function_name: None,
                            });
                        } else {
                            for line in details {
                                evidence.push(Evidence {
                                    strategy: "launch_constraint_blob".into(),
                                    description: format!("[{}] {}", label, line),
                                    confidence: Confidence::Definitive,
                                    address: None,
                                    function_name: None,
                                });
                            }
                        }
                    } else {
                        evidence.push(Evidence {
                            strategy: "launch_constraint_blob".into(),
                            description: format!(
                                "[{}] present ({} bytes, could not decode DER)",
                                label,
                                der.len()
                            ),
                            confidence: Confidence::Medium,
                            address: None,
                            function_name: None,
                        });
                    }
                }
            }
        }

        CheckResult {
            id: self.id(),
            name: self.name().into(),
            category: self.category(),
            polarity: self.polarity(),
            detected: !evidence.is_empty(),
            evidence,
            stats: None,
        }
    }
}

pub struct EntitlementsCheck;
impl Check for EntitlementsCheck {
    fn id(&self) -> CheckId {
        CheckId::Entitlements
    }
    fn name(&self) -> &'static str {
        "Entitlements"
    }
    fn min_level(&self) -> DetectionLevel {
        DetectionLevel::Quick
    }
    fn category(&self) -> Category {
        Category::Entitlements
    }
    fn polarity(&self) -> Polarity {
        Polarity::Info
    }
    fn run(&self, ctx: &AnalysisContext) -> CheckResult {
        use crate::entitlements_db::{self, Impact};

        let cs = ctx.codesign_data();
        let xml = cs.as_ref().and_then(|i| i.entitlements_xml.as_ref());
        let mut evidence = Vec::new();

        if let Some(xml_str) = xml {
            if let Ok(plist::Value::Dictionary(dict)) = plist::from_bytes(xml_str.as_bytes()) {
                let total = dict.len();
                let mut known_count = 0;

                // First pass: emit known security-relevant entitlements
                for key in dict.keys() {
                    if let Some((impact, desc)) = entitlements_db::classify(key) {
                        known_count += 1;
                        let tag = match impact {
                            Impact::Weakens => " [WEAKENS]",
                            Impact::Strengthens => " [STRENGTHENS]",
                            Impact::Info => "",
                        };
                        let val = format_plist_value(dict.get(key));
                        evidence.push(Evidence {
                            strategy: "entitlement".into(),
                            description: format!("{} = {} — {}{}", key, val, desc, tag),
                            confidence: Confidence::Definitive,
                            address: None,
                            function_name: None,
                        });
                    }
                }

                // Summary of remaining entitlements
                let other = total - known_count;
                if other > 0 {
                    evidence.push(Evidence {
                        strategy: "entitlement_summary".into(),
                        description: format!(
                            "({} total entitlements, {} not security-relevant)",
                            total, other
                        ),
                        confidence: Confidence::Definitive,
                        address: None,
                        function_name: None,
                    });
                }
            } else {
                evidence.push(Evidence {
                    strategy: "entitlement".into(),
                    description: "entitlements present but failed to parse plist".into(),
                    confidence: Confidence::Medium,
                    address: None,
                    function_name: None,
                });
            }
        }

        let detected = !evidence.is_empty();
        CheckResult {
            id: self.id(),
            name: self.name().into(),
            category: self.category(),
            polarity: self.polarity(),
            detected,
            evidence,
            stats: None,
        }
    }
}

fn format_plist_value(val: Option<&plist::Value>) -> String {
    val.map(|v| match v {
        plist::Value::Boolean(b) => b.to_string(),
        plist::Value::String(s) => s.clone(),
        plist::Value::Integer(i) => format!("{}", i),
        plist::Value::Array(a) => {
            let items: Vec<String> = a
                .iter()
                .take(3)
                .map(|item| match item {
                    plist::Value::String(s) => s.clone(),
                    other => format!("{:?}", other),
                })
                .collect();
            if a.len() > 3 {
                format!("[{}, ...+{}]", items.join(", "), a.len() - 3)
            } else {
                format!("[{}]", items.join(", "))
            }
        }
        _ => format!("{:?}", v),
    })
    .unwrap_or_default()
}
