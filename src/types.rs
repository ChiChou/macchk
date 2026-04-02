use serde::Serialize;

/// User-selected analysis depth.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DetectionLevel {
    Quick,
    Standard,
    Full,
}

/// Grouping for output display.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Category {
    #[serde(rename = "header")]
    Header,
    #[serde(rename = "load_commands")]
    LoadCommands,
    #[serde(rename = "symbols")]
    Symbols,
    #[serde(rename = "codesign")]
    CodeSign,
    #[serde(rename = "sections")]
    Sections,
    #[serde(rename = "entitlements")]
    Entitlements,
    #[serde(rename = "instructions")]
    Instructions,
}

impl Category {
    pub fn label(&self) -> &'static str {
        match self {
            Category::Header => "Mach-O Header",
            Category::LoadCommands => "Load Commands",
            Category::Symbols => "Symbol Table",
            Category::CodeSign => "Code Signing",
            Category::Sections => "Sections & Segments",
            Category::Entitlements => "Entitlements",
            Category::Instructions => "Instruction Analysis",
        }
    }
}

/// Confidence in a detection result.
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Definitive,
    High,
    Medium,
}

/// Whether the feature being detected is positive or negative for security.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Polarity {
    /// Feature presence is good (e.g., PIE, hardened runtime).
    Positive,
    /// Feature presence is bad (e.g., executable stack, get-task-allow).
    Negative,
    /// Informational, not inherently good or bad.
    Info,
}

/// One piece of evidence for a security feature.
#[derive(Clone, Debug, Serialize)]
pub struct Evidence {
    pub strategy: String,
    pub description: String,
    pub confidence: Confidence,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_name: Option<String>,
}

/// Coverage statistics for Full mode.
#[derive(Clone, Debug, Default, Serialize)]
pub struct CoverageStats {
    pub functions_with_feature: u64,
    pub functions_scanned: u64,
    pub sites_found: u64,
}

/// Unique check identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckId {
    // Category A: Header
    Pie,
    NoHeapExec,
    AllowStackExec,
    AppExtensionSafe,
    CpuSubtype,
    // Category B: Load Commands
    CodeSignature,
    EncryptionInfo,
    ChainedFixups,
    RestrictSegment,
    Rpath,
    DyldEnvironment,
    // Category C: Symbols
    StackCanary,
    Arc,
    SwiftRuntime,
    TypedAllocators,
    FortifySource,
    SanitizerAsan,
    SanitizerUbsan,
    // Category D: Code Signing
    HardenedRuntime,
    CsRestrict,
    LibraryValidation,
    CsHardKill,
    SigningType,
    CodeSignHashType,
    LaunchConstraints,
    Entitlements,
    // Category E: Sections
    PacSections,
    DataConst,
    SegmentPermissions,
    PageZero,
    // Category F: Instructions
    PacInstructions,
    StackZeroInit,
    LibcppHardening,
    BoundsSafety,
    MteInstructions,
    StackCanaryInsn,
    JumpTableHardening,
}

/// Result for a single security check.
#[derive(Clone, Debug, Serialize)]
pub struct CheckResult {
    pub id: CheckId,
    pub name: String,
    pub category: Category,
    pub polarity: Polarity,
    pub detected: bool,
    pub evidence: Vec<Evidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats: Option<CoverageStats>,
}

/// Complete analysis result for one architecture slice.
#[derive(Clone, Debug, Serialize)]
pub struct SliceResult {
    pub arch: String,
    pub file_type: String,
    pub checks: Vec<CheckResult>,
}

/// Top-level result (may contain multiple slices for fat binaries).
#[derive(Clone, Debug, Serialize)]
pub struct AnalysisResult {
    pub path: String,
    pub slices: Vec<SliceResult>,
}
