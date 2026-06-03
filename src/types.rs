use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};

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

/// Security interpretation of a check result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Pass,
    Fail,
    Informational,
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
    TypedAllocatorsInsn,
    JumpTableHardening,
}

/// Result for a single security check.
#[derive(Clone, Debug)]
pub struct CheckResult {
    pub id: CheckId,
    pub name: String,
    pub category: Category,
    pub polarity: Polarity,
    pub detected: bool,
    pub evidence: Vec<Evidence>,
    pub stats: Option<CoverageStats>,
}

impl CheckResult {
    pub fn status(&self) -> CheckStatus {
        match (self.detected, self.polarity) {
            (true, Polarity::Positive) | (false, Polarity::Negative) => CheckStatus::Pass,
            (false, Polarity::Positive) | (true, Polarity::Negative) => CheckStatus::Fail,
            (_, Polarity::Info) => CheckStatus::Informational,
        }
    }
}

impl Serialize for CheckResult {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let field_count = if self.stats.is_some() { 8 } else { 7 };
        let mut state = serializer.serialize_struct("CheckResult", field_count)?;
        state.serialize_field("id", &self.id)?;
        state.serialize_field("name", &self.name)?;
        state.serialize_field("category", &self.category)?;
        state.serialize_field("polarity", &self.polarity)?;
        state.serialize_field("detected", &self.detected)?;
        state.serialize_field("status", &self.status())?;
        state.serialize_field("evidence", &self.evidence)?;
        if let Some(stats) = &self.stats {
            state.serialize_field("stats", stats)?;
        }
        state.end()
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn check_result(detected: bool, polarity: Polarity) -> CheckResult {
        CheckResult {
            id: CheckId::AllowStackExec,
            name: "Executable Stack".into(),
            category: Category::Header,
            polarity,
            detected,
            evidence: Vec::new(),
            stats: None,
        }
    }

    #[test]
    fn absent_negative_check_passes() {
        assert_eq!(
            check_result(false, Polarity::Negative).status(),
            CheckStatus::Pass
        );
    }

    #[test]
    fn present_negative_check_fails() {
        assert_eq!(
            check_result(true, Polarity::Negative).status(),
            CheckStatus::Fail
        );
    }

    #[test]
    fn serialized_absent_negative_check_reports_pass_status() {
        let value = serde_json::to_value(check_result(false, Polarity::Negative)).unwrap();

        assert_eq!(value["id"], "allow_stack_exec");
        assert_eq!(value["detected"], false);
        assert_eq!(value["status"], "pass");
        assert!(value.get("stats").is_none());
    }
}
