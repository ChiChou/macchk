use crate::detection::{AnalysisContext, Check};
use crate::types::*;

/// Match symbol names, handling Mach-O's leading underscore convention.
fn matches_any(name: &str, targets: &[&str]) -> bool {
    let stripped = name.strip_prefix('_').unwrap_or(name);
    for &target in targets {
        let target_stripped = target.strip_prefix('_').unwrap_or(target);
        if stripped == target_stripped {
            return true;
        }
    }
    false
}

/// Collect all visible symbol names (imports from both dyld_info and symbol table).
fn collect_symbol_names<'a>(ctx: &'a AnalysisContext) -> Vec<&'a str> {
    let mut names = Vec::new();
    // From imports
    if let Ok(imports) = ctx.macho.imports() {
        for imp in &imports {
            names.push(imp.name);
        }
    }
    // Also scan the full symbol table for undefined externals
    if let Some(ref syms) = ctx.macho.symbols {
        for (name, nlist) in syms.iter().flatten() {
            // N_EXT (0x01) && N_UNDF (type == 0) means imported symbol
            if nlist.n_type & 0x01 != 0 && nlist.n_type & 0x0e == 0 {
                names.push(name);
            }
        }
    }
    names
}

fn symbol_check(
    ctx: &AnalysisContext,
    id: CheckId,
    name: &'static str,
    polarity: Polarity,
    symbols: &[&str],
    strategy_name: &str,
) -> CheckResult {
    let mut found = Vec::new();
    let all_names = collect_symbol_names(ctx);
    for sym_name in &all_names {
        if matches_any(sym_name, symbols) && !found.iter().any(|f: &String| f == sym_name) {
            found.push(sym_name.to_string());
        }
    }
    let detected = !found.is_empty();
    let evidence: Vec<Evidence> = found
        .iter()
        .map(|s| Evidence {
            strategy: strategy_name.into(),
            description: format!("imported symbol: {}", s),
            confidence: Confidence::High,
            address: None,
            function_name: None,
        })
        .collect();
    CheckResult {
        id,
        name: name.into(),
        category: Category::Symbols,
        polarity,
        detected,
        evidence,
        stats: None,
    }
}

pub struct StackCanaryCheck;
impl Check for StackCanaryCheck {
    fn id(&self) -> CheckId {
        CheckId::StackCanary
    }
    fn name(&self) -> &'static str {
        "Stack Canary"
    }
    fn min_level(&self) -> DetectionLevel {
        DetectionLevel::Quick
    }
    fn category(&self) -> Category {
        Category::Symbols
    }
    fn polarity(&self) -> Polarity {
        Polarity::Positive
    }
    fn run(&self, ctx: &AnalysisContext) -> CheckResult {
        symbol_check(
            ctx,
            self.id(),
            self.name(),
            self.polarity(),
            &["___stack_chk_fail", "___stack_chk_guard"],
            "import_symbol",
        )
    }
}

/// Obj-C ARC runtime symbols.
const OBJC_ARC_SYMBOLS: &[&str] = &[
    "_objc_release",
    "_objc_retain",
    "_objc_autoreleasePoolPush",
];

/// Swift ARC runtime symbols.
const SWIFT_ARC_SYMBOLS: &[&str] = &[
    "_swift_retain",
    "_swift_release",
    "_swift_allocObject",
    "_swift_bridgeObjectRetain",
    "_swift_bridgeObjectRelease",
];

pub struct ArcCheck;
impl Check for ArcCheck {
    fn id(&self) -> CheckId {
        CheckId::Arc
    }
    fn name(&self) -> &'static str {
        "ARC"
    }
    fn min_level(&self) -> DetectionLevel {
        DetectionLevel::Quick
    }
    fn category(&self) -> Category {
        Category::Symbols
    }
    fn polarity(&self) -> Polarity {
        Polarity::Positive
    }
    fn run(&self, ctx: &AnalysisContext) -> CheckResult {
        let all_targets: Vec<&str> = OBJC_ARC_SYMBOLS
            .iter()
            .chain(SWIFT_ARC_SYMBOLS.iter())
            .copied()
            .collect();
        symbol_check(
            ctx,
            self.id(),
            self.name(),
            self.polarity(),
            &all_targets,
            "import_symbol",
        )
    }
}

pub struct SwiftRuntimeCheck;
impl Check for SwiftRuntimeCheck {
    fn id(&self) -> CheckId {
        CheckId::SwiftRuntime
    }
    fn name(&self) -> &'static str {
        "Swift Runtime"
    }
    fn min_level(&self) -> DetectionLevel {
        DetectionLevel::Quick
    }
    fn category(&self) -> Category {
        Category::Symbols
    }
    fn polarity(&self) -> Polarity {
        Polarity::Info
    }
    fn run(&self, ctx: &AnalysisContext) -> CheckResult {
        let mut found = Vec::new();
        for n in collect_symbol_names(ctx) {
            let stripped = n.strip_prefix('_').unwrap_or(n);
            if stripped.starts_with("$s") || stripped.starts_with("swift_") {
                found.push(n.to_string());
                if found.len() >= 3 {
                    break;
                }
            }
        }
        let detected = !found.is_empty();
        let evidence: Vec<Evidence> = found
            .iter()
            .map(|s| Evidence {
                strategy: "import_symbol".into(),
                description: format!("Swift import: {}", s),
                confidence: Confidence::High,
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

pub struct TypedAllocatorsCheck;
impl Check for TypedAllocatorsCheck {
    fn id(&self) -> CheckId {
        CheckId::TypedAllocators
    }
    fn name(&self) -> &'static str {
        "Typed Allocators"
    }
    fn min_level(&self) -> DetectionLevel {
        DetectionLevel::Quick
    }
    fn category(&self) -> Category {
        Category::Symbols
    }
    fn polarity(&self) -> Polarity {
        Polarity::Positive
    }
    fn run(&self, ctx: &AnalysisContext) -> CheckResult {
        // C typed allocators (-ftyped-memory-operations)
        let c_symbols: &[&str] = &[
            "_malloc_type_malloc",
            "_malloc_type_calloc",
            "_malloc_type_realloc",
            "_malloc_type_valloc",
            "_malloc_type_aligned_alloc",
        ];
        // C++ typed allocators (-ftyped-cxx-new-delete / -ftyped-cxx-delete)
        // Mangled typed operator new/delete with __type_descriptor_t parameter
        let cxx_symbols: &[&str] = &[
            "__ZnwmSt19__type_descriptor_t",
            "__ZnamSt19__type_descriptor_t",
            "__ZdlPvSt19__type_descriptor_t",
            "__ZdaPvSt19__type_descriptor_t",
        ];
        let all_symbols: Vec<&str> = c_symbols.iter().chain(cxx_symbols.iter()).copied().collect();
        symbol_check(
            ctx,
            self.id(),
            self.name(),
            self.polarity(),
            &all_symbols,
            "import_symbol",
        )
    }
}

/// Prefix-based symbol check: detects any imported symbol starting with the given prefix.
fn prefix_symbol_check(
    ctx: &AnalysisContext,
    id: CheckId,
    name: &'static str,
    polarity: Polarity,
    prefix: &str,
    strategy_name: &str,
    max_evidence: usize,
) -> CheckResult {
    let mut found = Vec::new();
    for n in collect_symbol_names(ctx) {
        let stripped = n.strip_prefix('_').unwrap_or(n);
        if stripped.starts_with(prefix)
            && !found.iter().any(|f: &String| f == n) {
                found.push(n.to_string());
                if found.len() >= max_evidence {
                    break;
                }
            }
    }
    let detected = !found.is_empty();
    let evidence: Vec<Evidence> = found
        .iter()
        .map(|s| Evidence {
            strategy: strategy_name.into(),
            description: format!("imported symbol: {}", s),
            confidence: Confidence::High,
            address: None,
            function_name: None,
        })
        .collect();
    CheckResult {
        id,
        name: name.into(),
        category: Category::Symbols,
        polarity,
        detected,
        evidence,
        stats: None,
    }
}

pub struct SanitizerAsanCheck;
impl Check for SanitizerAsanCheck {
    fn id(&self) -> CheckId {
        CheckId::SanitizerAsan
    }
    fn name(&self) -> &'static str {
        "AddressSanitizer"
    }
    fn min_level(&self) -> DetectionLevel {
        DetectionLevel::Quick
    }
    fn category(&self) -> Category {
        Category::Symbols
    }
    fn polarity(&self) -> Polarity {
        Polarity::Info
    }
    fn run(&self, ctx: &AnalysisContext) -> CheckResult {
        prefix_symbol_check(
            ctx,
            self.id(),
            self.name(),
            self.polarity(),
            "__asan_",
            "import_symbol",
            3,
        )
    }
}

pub struct SanitizerUbsanCheck;
impl Check for SanitizerUbsanCheck {
    fn id(&self) -> CheckId {
        CheckId::SanitizerUbsan
    }
    fn name(&self) -> &'static str {
        "UndefinedBehaviorSanitizer"
    }
    fn min_level(&self) -> DetectionLevel {
        DetectionLevel::Quick
    }
    fn category(&self) -> Category {
        Category::Symbols
    }
    fn polarity(&self) -> Polarity {
        Polarity::Info
    }
    fn run(&self, ctx: &AnalysisContext) -> CheckResult {
        prefix_symbol_check(
            ctx,
            self.id(),
            self.name(),
            self.polarity(),
            "__ubsan_",
            "import_symbol",
            3,
        )
    }
}

pub struct FortifySourceCheck;
impl Check for FortifySourceCheck {
    fn id(&self) -> CheckId {
        CheckId::FortifySource
    }
    fn name(&self) -> &'static str {
        "FORTIFY_SOURCE"
    }
    fn min_level(&self) -> DetectionLevel {
        DetectionLevel::Quick
    }
    fn category(&self) -> Category {
        Category::Symbols
    }
    fn polarity(&self) -> Polarity {
        Polarity::Positive
    }
    fn run(&self, ctx: &AnalysisContext) -> CheckResult {
        // FORTIFY_SOURCE _chk variants (as they appear in Mach-O symbol table with leading _)
        // Exclude ___stack_chk_* which is a canary, not FORTIFY.
        let fortify_suffixes = [
            "strcpy_chk",
            "strncpy_chk",
            "strcat_chk",
            "strncat_chk",
            "memcpy_chk",
            "memmove_chk",
            "memset_chk",
            "sprintf_chk",
            "snprintf_chk",
            "vsnprintf_chk",
            "vsprintf_chk",
            "fprintf_chk",
            "vfprintf_chk",
            "strlcpy_chk",
            "strlcat_chk",
        ];
        let mut found = Vec::new();
        for n in collect_symbol_names(ctx) {
            // Strip all leading underscores for matching
            let base = n.trim_start_matches('_');
            if fortify_suffixes.contains(&base)
                && !found.iter().any(|f: &String| f == n) {
                    found.push(n.to_string());
                }
        }
        let detected = !found.is_empty();
        let evidence: Vec<Evidence> = found
            .iter()
            .map(|s| Evidence {
                strategy: "import_symbol".into(),
                description: format!("fortified function: {}", s),
                confidence: Confidence::High,
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
