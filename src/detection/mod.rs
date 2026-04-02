pub mod codesign;
pub mod header;
pub mod instructions;
pub mod load_commands;
pub mod sections;
pub mod symbols;

use goblin::mach::load_command::CommandVariant;
use goblin::mach::MachO;
use std::cell::OnceCell;
use std::ops::Range;

use crate::codesign_parser::CodeSignInfo;
use crate::types::{Category, CheckId, CheckResult, DetectionLevel, Polarity};

/// Read-only context shared across all checks for one architecture slice.
pub struct AnalysisContext<'a> {
    pub level: DetectionLevel,
    pub macho: &'a MachO<'a>,
    pub raw_bytes: &'a [u8],
    pub little_endian: bool,
    /// File-offset range that is encrypted (cryptid != 0).
    /// When set, any code bytes within this range are ciphertext and must not
    /// be interpreted as instructions.
    pub encrypted_range: Option<Range<u64>>,
    codesign_data: OnceCell<Option<CodeSignInfo>>,
    function_boundaries: OnceCell<Vec<(u64, u64)>>,
}

impl<'a> AnalysisContext<'a> {
    pub fn new(level: DetectionLevel, macho: &'a MachO<'a>, raw_bytes: &'a [u8]) -> Self {
        let encrypted_range = Self::find_encrypted_range(macho);
        Self {
            level,
            macho,
            raw_bytes,
            little_endian: macho.little_endian,
            encrypted_range,
            codesign_data: OnceCell::new(),
            function_boundaries: OnceCell::new(),
        }
    }

    /// Extract the encrypted file-offset range from LC_ENCRYPTION_INFO{,_64}
    /// if cryptid != 0 (i.e. the binary is still encrypted / FairPlay DRM).
    fn find_encrypted_range(macho: &MachO) -> Option<Range<u64>> {
        for lc in &macho.load_commands {
            match lc.command {
                CommandVariant::EncryptionInfo64(ei) if ei.cryptid != 0 => {
                    return Some(ei.cryptoff as u64..ei.cryptoff as u64 + ei.cryptsize as u64);
                }
                CommandVariant::EncryptionInfo32(ei) if ei.cryptid != 0 => {
                    return Some(ei.cryptoff as u64..ei.cryptoff as u64 + ei.cryptsize as u64);
                }
                _ => {}
            }
        }
        None
    }

    /// Returns true if the given file-offset range overlaps the encrypted region.
    pub fn is_fileoff_encrypted(&self, offset: u64, size: u64) -> bool {
        if let Some(ref enc) = self.encrypted_range {
            let end = offset + size;
            offset < enc.end && end > enc.start
        } else {
            false
        }
    }

    pub fn codesign_data(&self) -> &Option<CodeSignInfo> {
        self.codesign_data.get_or_init(|| {
            crate::codesign_parser::parse_codesign(self.macho, self.raw_bytes)
                .ok()
                .flatten()
        })
    }

    pub fn function_boundaries(&self) -> &[(u64, u64)] {
        self.function_boundaries
            .get_or_init(|| instructions::compute_function_boundaries(self.macho, self.raw_bytes))
    }

    pub fn is_arm64(&self) -> bool {
        use goblin::mach::constants::cputype::CPU_TYPE_ARM64;
        self.macho.header.cputype() == CPU_TYPE_ARM64
    }

    pub fn is_arm64e(&self) -> bool {
        use goblin::mach::constants::cputype::{CPU_SUBTYPE_ARM64_E, CPU_TYPE_ARM64};
        self.macho.header.cputype() == CPU_TYPE_ARM64
            && self.macho.header.cpusubtype() == CPU_SUBTYPE_ARM64_E
    }

    pub fn is_x86_64(&self) -> bool {
        use goblin::mach::constants::cputype::CPU_TYPE_X86_64;
        self.macho.header.cputype() == CPU_TYPE_X86_64
    }
}

/// A security check. Each check targets a single feature/property.
pub trait Check {
    fn id(&self) -> CheckId;
    fn name(&self) -> &'static str;
    fn min_level(&self) -> DetectionLevel;
    fn category(&self) -> Category;
    fn polarity(&self) -> Polarity;
    fn run(&self, ctx: &AnalysisContext) -> CheckResult;
}

/// Run all applicable checks for the given context.
pub fn analyze_slice(ctx: &AnalysisContext) -> Vec<CheckResult> {
    let checks = all_checks();
    checks
        .iter()
        .filter(|c| c.min_level() <= ctx.level)
        .map(|c| c.run(ctx))
        .collect()
}

fn all_checks() -> Vec<Box<dyn Check>> {
    vec![
        // Category A: Header
        Box::new(header::PieCheck),
        Box::new(header::NoHeapExecCheck),
        Box::new(header::AllowStackExecCheck),
        Box::new(header::AppExtensionSafeCheck),
        Box::new(header::CpuSubtypeCheck),
        // Category B: Load Commands
        Box::new(load_commands::CodeSignatureCheck),
        Box::new(load_commands::EncryptionInfoCheck),
        Box::new(load_commands::ChainedFixupsCheck),
        Box::new(load_commands::RestrictSegmentCheck),
        Box::new(load_commands::RpathCheck),
        Box::new(load_commands::DyldEnvironmentCheck),
        // Category C: Symbols
        Box::new(symbols::StackCanaryCheck),
        Box::new(symbols::ArcCheck),
        Box::new(symbols::SwiftRuntimeCheck),
        Box::new(symbols::TypedAllocatorsCheck),
        Box::new(symbols::FortifySourceCheck),
        Box::new(symbols::SanitizerAsanCheck),
        Box::new(symbols::SanitizerUbsanCheck),
        // Category D: Code Signing
        Box::new(codesign::HardenedRuntimeCheck),
        Box::new(codesign::CsRestrictCheck),
        Box::new(codesign::LibraryValidationCheck),
        Box::new(codesign::CsHardKillCheck),
        Box::new(codesign::SigningTypeCheck),
        Box::new(codesign::CodeSignHashTypeCheck),
        Box::new(codesign::LaunchConstraintsCheck),
        Box::new(codesign::EntitlementsCheck),
        // Category E: Sections
        Box::new(sections::PacSectionsCheck),
        Box::new(sections::DataConstCheck),
        Box::new(sections::PageZeroCheck),
        // Category F: Instructions
        Box::new(instructions::PacInstructionsCheck),
        Box::new(instructions::StackZeroInitCheck),
        Box::new(instructions::LibcppHardeningCheck),
        Box::new(instructions::BoundsSafetyCheck),
        Box::new(instructions::MteInstructionsCheck),
        Box::new(instructions::StackCanaryInsnCheck),
        Box::new(instructions::JumpTableHardeningCheck),
    ]
}
