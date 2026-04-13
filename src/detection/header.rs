use goblin::mach::header::MH_EXECUTE;

use crate::detection::{AnalysisContext, Check};
use crate::types::*;

// Mach-O header flag constants (from loader.h)
const MH_PIE: u32 = 0x200000;
const MH_NO_HEAP_EXECUTION: u32 = 0x1000000;
const MH_ALLOW_STACK_EXECUTION: u32 = 0x20000;
const MH_APP_EXTENSION_SAFE: u32 = 0x02000000;

fn flag_check(
    ctx: &AnalysisContext,
    id: CheckId,
    name: &'static str,
    polarity: Polarity,
    flag: u32,
    flag_name: &str,
) -> CheckResult {
    let flags = ctx.macho.header.flags;
    let detected = flags & flag != 0;
    let evidence = if detected {
        vec![Evidence {
            strategy: "header_flag".into(),
            description: format!("{} ({:#x}) set in MH flags ({:#x})", flag_name, flag, flags),
            confidence: Confidence::High,
            address: None,
            function_name: None,
        }]
    } else {
        vec![]
    };
    CheckResult {
        id,
        name: name.into(),
        category: Category::Header,
        polarity,
        detected,
        evidence,
        stats: None,
    }
}

fn skip_non_executable(id: CheckId, name: &'static str) -> CheckResult {
    CheckResult {
        id,
        name: name.into(),
        category: Category::Header,
        polarity: Polarity::Info,
        detected: false,
        evidence: vec![Evidence {
            strategy: "filetype_guard".into(),
            description: "not applicable (MH_EXECUTE only)".into(),
            confidence: Confidence::Definitive,
            address: None,
            function_name: None,
        }],
        stats: None,
    }
}

pub struct PieCheck;
impl Check for PieCheck {
    fn id(&self) -> CheckId {
        CheckId::Pie
    }
    fn name(&self) -> &'static str {
        "PIE (ASLR)"
    }
    fn min_level(&self) -> DetectionLevel {
        DetectionLevel::Quick
    }
    fn category(&self) -> Category {
        Category::Header
    }
    fn polarity(&self) -> Polarity {
        Polarity::Positive
    }
    fn run(&self, ctx: &AnalysisContext) -> CheckResult {
        if ctx.macho.header.filetype != MH_EXECUTE {
            return skip_non_executable(self.id(), self.name());
        }
        let mut result = flag_check(
            ctx,
            self.id(),
            self.name(),
            self.polarity(),
            MH_PIE,
            "MH_PIE",
        );
        if ctx.is_arm64() && result.detected {
            result.evidence.push(Evidence {
                strategy: "arch_note".into(),
                description: "mandatory on arm64 (kernel enforces PIE for all executables)".into(),
                confidence: Confidence::Definitive,
                address: None,
                function_name: None,
            });
        }
        result
    }
}

pub struct NoHeapExecCheck;
impl Check for NoHeapExecCheck {
    fn id(&self) -> CheckId {
        CheckId::NoHeapExec
    }
    fn name(&self) -> &'static str {
        "NX Heap"
    }
    fn min_level(&self) -> DetectionLevel {
        DetectionLevel::Quick
    }
    fn category(&self) -> Category {
        Category::Header
    }
    fn polarity(&self) -> Polarity {
        Polarity::Positive
    }
    fn run(&self, ctx: &AnalysisContext) -> CheckResult {
        if ctx.macho.header.filetype != MH_EXECUTE {
            return skip_non_executable(self.id(), self.name());
        }
        let mut result = flag_check(
            ctx,
            self.id(),
            self.name(),
            self.polarity(),
            MH_NO_HEAP_EXECUTION,
            "MH_NO_HEAP_EXECUTION",
        );
        if ctx.is_arm64() {
            result.evidence.push(Evidence {
                strategy: "arch_note".into(),
                description: "arm64 heaps are always non-executable regardless of this flag".into(),
                confidence: Confidence::Definitive,
                address: None,
                function_name: None,
            });
        }
        result
    }
}

pub struct AllowStackExecCheck;
impl Check for AllowStackExecCheck {
    fn id(&self) -> CheckId {
        CheckId::AllowStackExec
    }
    fn name(&self) -> &'static str {
        "Executable Stack"
    }
    fn min_level(&self) -> DetectionLevel {
        DetectionLevel::Quick
    }
    fn category(&self) -> Category {
        Category::Header
    }
    fn polarity(&self) -> Polarity {
        Polarity::Negative
    }
    fn run(&self, ctx: &AnalysisContext) -> CheckResult {
        if ctx.macho.header.filetype != MH_EXECUTE {
            return skip_non_executable(self.id(), self.name());
        }
        let mut result = flag_check(
            ctx,
            self.id(),
            self.name(),
            self.polarity(),
            MH_ALLOW_STACK_EXECUTION,
            "MH_ALLOW_STACK_EXECUTION",
        );
        if result.detected {
            result.evidence.push(Evidence {
                strategy: "arch_note".into(),
                description: "no effect on modern builds with code signing enforcement (CONFIG_ENFORCE_SIGNED_CODE)".into(),
                confidence: Confidence::Definitive,
                address: None,
                function_name: None,
            });
        }
        result
    }
}

pub struct AppExtensionSafeCheck;
impl Check for AppExtensionSafeCheck {
    fn id(&self) -> CheckId {
        CheckId::AppExtensionSafe
    }
    fn name(&self) -> &'static str {
        "App Extension Safe"
    }
    fn min_level(&self) -> DetectionLevel {
        DetectionLevel::Quick
    }
    fn category(&self) -> Category {
        Category::Header
    }
    fn polarity(&self) -> Polarity {
        Polarity::Info
    }
    fn run(&self, ctx: &AnalysisContext) -> CheckResult {
        flag_check(
            ctx,
            self.id(),
            self.name(),
            self.polarity(),
            MH_APP_EXTENSION_SAFE,
            "MH_APP_EXTENSION_SAFE",
        )
    }
}

pub struct CpuSubtypeCheck;
impl Check for CpuSubtypeCheck {
    fn id(&self) -> CheckId {
        CheckId::CpuSubtype
    }
    fn name(&self) -> &'static str {
        "CPU Subtype"
    }
    fn min_level(&self) -> DetectionLevel {
        DetectionLevel::Quick
    }
    fn category(&self) -> Category {
        Category::Header
    }
    fn polarity(&self) -> Polarity {
        Polarity::Info
    }
    fn run(&self, ctx: &AnalysisContext) -> CheckResult {
        use goblin::mach::constants::cputype::CPU_SUBTYPE_ARM64_E;
        let subtype = ctx.macho.header.cpusubtype();
        let is_arm64e = ctx.is_arm64() && subtype == CPU_SUBTYPE_ARM64_E;
        let desc = if is_arm64e {
            format!("arm64e (cpu_subtype={:#x})", subtype)
        } else if ctx.is_arm64() {
            format!("arm64 (cpu_subtype={:#x})", subtype)
        } else if ctx.is_x86_64() {
            format!("x86_64 (cpu_subtype={:#x})", subtype)
        } else {
            format!("cpu_subtype={:#x}", subtype)
        };
        CheckResult {
            id: self.id(),
            name: self.name().into(),
            category: self.category(),
            polarity: self.polarity(),
            detected: is_arm64e,
            evidence: vec![Evidence {
                strategy: "cpu_subtype".into(),
                description: desc,
                confidence: Confidence::Definitive,
                address: None,
                function_name: None,
            }],
            stats: None,
        }
    }
}
