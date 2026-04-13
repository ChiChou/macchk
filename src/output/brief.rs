use crate::types::*;

pub fn print(result: &AnalysisResult) {
    for slice in &result.slices {
        let mut tags = Vec::new();

        for check in &slice.checks {
            if !check.detected { continue; }
            match check.id {
                CheckId::Pie => tags.push("PIE"),
                CheckId::NoHeapExec => tags.push("NX-Heap"),
                CheckId::AllowStackExec => tags.push("EXEC-STACK!"),
                CheckId::CodeSignature => tags.push("CodeSign"),
                CheckId::HardenedRuntime => tags.push("Hardened"),
                CheckId::StackCanary => tags.push("Canary"),
                CheckId::Arc => tags.push("ARC"),
                CheckId::FortifySource => tags.push("FORTIFY"),
                CheckId::TypedAllocators => tags.push("TypedAlloc"),
                CheckId::ChainedFixups => tags.push("ChainedFixups"),
                CheckId::RestrictSegment => tags.push("RESTRICT"),
                CheckId::DyldEnvironment => tags.push("DYLD_ENV!"),
                CheckId::CpuSubtype => tags.push("arm64e"),
                CheckId::PacSections => tags.push("PAC-Sec"),
                CheckId::PacInstructions => tags.push("PAC-Insn"),
                CheckId::StackZeroInit => tags.push("ZeroInit"),
                CheckId::LibcppHardening => tags.push("libc++"),
                CheckId::BoundsSafety => tags.push("BoundsSafe"),
                CheckId::MteInstructions => tags.push("MTE"),
                CheckId::DataConst => tags.push("__DATA_CONST"),
                CheckId::LibraryValidation => tags.push("LibVal"),
                CheckId::CsRestrict => tags.push("CS-Restrict"),
                CheckId::CsHardKill => tags.push("Hard+Kill"),
                CheckId::SwiftRuntime => tags.push("Swift"),
                CheckId::SanitizerAsan => tags.push("ASan!"),
                CheckId::SanitizerUbsan => tags.push("UBSan!"),
                CheckId::CodeSignHashType => tags.push("SHA256+"),
                CheckId::LaunchConstraints => tags.push("LWCR"),
                CheckId::StackCanaryInsn => tags.push("Canary-Insn"),
                CheckId::JumpTableHardening => tags.push("JT-Hard"),
                CheckId::SegmentPermissions => tags.push("RWX!"),
                _ => {}
            }
        }

        let tag_str = if tags.is_empty() {
            "none".to_string()
        } else {
            tags.join(" ")
        };
        println!("{}: {} | {}", result.path, tag_str, slice.arch);
    }
}
