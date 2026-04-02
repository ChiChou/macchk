use goblin::mach::load_command::CommandVariant;

use crate::detection::{AnalysisContext, Check};
use crate::types::*;

pub struct CodeSignatureCheck;
impl Check for CodeSignatureCheck {
    fn id(&self) -> CheckId {
        CheckId::CodeSignature
    }
    fn name(&self) -> &'static str {
        "Code Signature"
    }
    fn min_level(&self) -> DetectionLevel {
        DetectionLevel::Quick
    }
    fn category(&self) -> Category {
        Category::LoadCommands
    }
    fn polarity(&self) -> Polarity {
        Polarity::Positive
    }
    fn run(&self, ctx: &AnalysisContext) -> CheckResult {
        let mut detected = false;
        let mut evidence = Vec::new();
        for lc in &ctx.macho.load_commands {
            if let CommandVariant::CodeSignature(cs) = lc.command {
                detected = true;
                evidence.push(Evidence {
                    strategy: "load_command".into(),
                    description: format!(
                        "LC_CODE_SIGNATURE at offset {:#x}, size {:#x}",
                        cs.dataoff, cs.datasize
                    ),
                    confidence: Confidence::Definitive,
                    address: None,
                    function_name: None,
                });
                break;
            }
        }
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

pub struct EncryptionInfoCheck;
impl Check for EncryptionInfoCheck {
    fn id(&self) -> CheckId {
        CheckId::EncryptionInfo
    }
    fn name(&self) -> &'static str {
        "Encryption"
    }
    fn min_level(&self) -> DetectionLevel {
        DetectionLevel::Quick
    }
    fn category(&self) -> Category {
        Category::LoadCommands
    }
    fn polarity(&self) -> Polarity {
        Polarity::Info
    }
    fn run(&self, ctx: &AnalysisContext) -> CheckResult {
        let mut detected = false;
        let mut evidence = Vec::new();
        for lc in &ctx.macho.load_commands {
            match lc.command {
                CommandVariant::EncryptionInfo64(ei) => {
                    let encrypted = ei.cryptid != 0;
                    detected = encrypted;
                    evidence.push(Evidence {
                        strategy: "load_command".into(),
                        description: format!(
                            "LC_ENCRYPTION_INFO_64: cryptid={} ({})",
                            ei.cryptid,
                            if encrypted {
                                "encrypted"
                            } else {
                                "not encrypted"
                            }
                        ),
                        confidence: Confidence::Definitive,
                        address: None,
                        function_name: None,
                    });
                    break;
                }
                CommandVariant::EncryptionInfo32(ei) => {
                    let encrypted = ei.cryptid != 0;
                    detected = encrypted;
                    evidence.push(Evidence {
                        strategy: "load_command".into(),
                        description: format!(
                            "LC_ENCRYPTION_INFO: cryptid={} ({})",
                            ei.cryptid,
                            if encrypted {
                                "encrypted"
                            } else {
                                "not encrypted"
                            }
                        ),
                        confidence: Confidence::Definitive,
                        address: None,
                        function_name: None,
                    });
                    break;
                }
                _ => {}
            }
        }
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

pub struct ChainedFixupsCheck;
impl Check for ChainedFixupsCheck {
    fn id(&self) -> CheckId {
        CheckId::ChainedFixups
    }
    fn name(&self) -> &'static str {
        "Chained Fixups"
    }
    fn min_level(&self) -> DetectionLevel {
        DetectionLevel::Quick
    }
    fn category(&self) -> Category {
        Category::LoadCommands
    }
    fn polarity(&self) -> Polarity {
        Polarity::Positive
    }
    fn run(&self, ctx: &AnalysisContext) -> CheckResult {
        let mut has_chained = false;
        let mut evidence = Vec::new();
        for lc in &ctx.macho.load_commands {
            match lc.command {
                CommandVariant::DyldChainedFixups(_) => {
                    has_chained = true;
                    evidence.push(Evidence {
                        strategy: "load_command".into(),
                        description: "LC_DYLD_CHAINED_FIXUPS (modern format)".into(),
                        confidence: Confidence::High,
                        address: None,
                        function_name: None,
                    });
                }
                CommandVariant::DyldInfo(ref di) | CommandVariant::DyldInfoOnly(ref di) => {
                    if !has_chained {
                        let mut desc = "LC_DYLD_INFO_ONLY (legacy format)".to_string();
                        if di.lazy_bind_size > 0 {
                            desc.push_str(&format!(
                                ", lazy_bind_size={:#x} (writable PLT stubs)",
                                di.lazy_bind_size
                            ));
                        }
                        if di.weak_bind_size > 0 {
                            desc.push_str(&format!(
                                ", weak_bind_size={:#x} (overridable symbols)",
                                di.weak_bind_size
                            ));
                        }
                        evidence.push(Evidence {
                            strategy: "load_command".into(),
                            description: desc,
                            confidence: Confidence::High,
                            address: None,
                            function_name: None,
                        });
                    }
                }
                _ => {}
            }
        }
        CheckResult {
            id: self.id(),
            name: self.name().into(),
            category: self.category(),
            polarity: self.polarity(),
            detected: has_chained,
            evidence,
            stats: None,
        }
    }
}

pub struct RestrictSegmentCheck;
impl Check for RestrictSegmentCheck {
    fn id(&self) -> CheckId {
        CheckId::RestrictSegment
    }
    fn name(&self) -> &'static str {
        "__RESTRICT Segment"
    }
    fn min_level(&self) -> DetectionLevel {
        DetectionLevel::Quick
    }
    fn category(&self) -> Category {
        Category::LoadCommands
    }
    fn polarity(&self) -> Polarity {
        Polarity::Info
    }
    fn run(&self, ctx: &AnalysisContext) -> CheckResult {
        let mut detected = false;
        let mut evidence = Vec::new();
        for seg in &ctx.macho.segments {
            let name = seg.name().unwrap_or("");
            if name == "__RESTRICT" {
                detected = true;
                for (sec, _) in seg.sections().unwrap_or_default() {
                    let sname = sec.name().unwrap_or("");
                    if sname == "__restrict" {
                        evidence.push(Evidence {
                            strategy: "segment".into(),
                            description: "__RESTRICT/__restrict segment present".into(),
                            confidence: Confidence::Definitive,
                            address: None,
                            function_name: None,
                        });
                    }
                }
                if evidence.is_empty() {
                    evidence.push(Evidence {
                        strategy: "segment".into(),
                        description: "__RESTRICT segment present".into(),
                        confidence: Confidence::Definitive,
                        address: None,
                        function_name: None,
                    });
                }
                break;
            }
        }
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

pub struct RpathCheck;
impl Check for RpathCheck {
    fn id(&self) -> CheckId {
        CheckId::Rpath
    }
    fn name(&self) -> &'static str {
        "RPATH"
    }
    fn min_level(&self) -> DetectionLevel {
        DetectionLevel::Quick
    }
    fn category(&self) -> Category {
        Category::LoadCommands
    }
    fn polarity(&self) -> Polarity {
        Polarity::Info
    }
    fn run(&self, ctx: &AnalysisContext) -> CheckResult {
        let mut rpaths = Vec::new();
        for rp in &ctx.macho.rpaths {
            rpaths.push(format!("LC_RPATH: {}", rp));
        }
        let detected = !rpaths.is_empty();
        let evidence: Vec<Evidence> = rpaths
            .iter()
            .map(|desc| Evidence {
                strategy: "load_command".into(),
                description: desc.clone(),
                confidence: Confidence::Definitive,
                address: None,
                function_name: None,
            })
            .collect();
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

pub struct DyldEnvironmentCheck;
impl Check for DyldEnvironmentCheck {
    fn id(&self) -> CheckId {
        CheckId::DyldEnvironment
    }
    fn name(&self) -> &'static str {
        "LC_DYLD_ENVIRONMENT"
    }
    fn min_level(&self) -> DetectionLevel {
        DetectionLevel::Quick
    }
    fn category(&self) -> Category {
        Category::LoadCommands
    }
    fn polarity(&self) -> Polarity {
        Polarity::Info
    }
    fn run(&self, ctx: &AnalysisContext) -> CheckResult {
        let mut evidence = Vec::new();
        for lc in &ctx.macho.load_commands {
            if let CommandVariant::DyldEnvironment(ref de) = lc.command {
                let name_offset = de.name as usize;
                let lc_start = lc.offset;
                let lc_end = lc_start + lc.command.cmdsize();
                if lc_start + name_offset < ctx.raw_bytes.len() && lc_end <= ctx.raw_bytes.len() {
                    let str_start = lc_start + name_offset;
                    let str_end = ctx.raw_bytes[str_start..lc_end]
                        .iter()
                        .position(|&b| b == 0)
                        .map(|p| str_start + p)
                        .unwrap_or(lc_end);
                    let env_str = String::from_utf8_lossy(&ctx.raw_bytes[str_start..str_end]);
                    let warning = if env_str.starts_with("DYLD_INSERT_LIBRARIES") {
                        " [CRITICAL: library injection]"
                    } else if env_str.starts_with("DYLD_LIBRARY_PATH")
                        || env_str.starts_with("DYLD_FRAMEWORK_PATH")
                    {
                        " [library/framework path override]"
                    } else {
                        ""
                    };
                    evidence.push(Evidence {
                        strategy: "load_command".into(),
                        description: format!("LC_DYLD_ENVIRONMENT: {}{}", env_str, warning),
                        confidence: Confidence::Definitive,
                        address: None,
                        function_name: None,
                    });
                }
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
