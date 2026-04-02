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
        flag_check(
            ctx,
            self.id(),
            self.name(),
            self.polarity(),
            MH_PIE,
            "MH_PIE",
        )
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
        flag_check(
            ctx,
            self.id(),
            self.name(),
            self.polarity(),
            MH_NO_HEAP_EXECUTION,
            "MH_NO_HEAP_EXECUTION",
        )
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
        flag_check(
            ctx,
            self.id(),
            self.name(),
            self.polarity(),
            MH_ALLOW_STACK_EXECUTION,
            "MH_ALLOW_STACK_EXECUTION",
        )
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
