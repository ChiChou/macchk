//! Integration tests for macchk detection checks.
//!
//! These tests use pre-compiled fixture binaries in tests/fixtures/bin/.
//! Run `make -C tests/fixtures` to build them before running tests.

use std::path::Path;

use macchk::binary::{analyze_binary, MappedBinary};
use macchk::types::{CheckId, DetectionLevel};

// Helpers

fn fixture(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/bin")
        .join(name)
}

fn check_detected(path: &Path, level: DetectionLevel, id: CheckId) -> bool {
    let mapped = MappedBinary::open(path).expect("failed to open fixture");
    let result = analyze_binary(path, &mapped.mmap, level, None).expect("analysis failed");
    result
        .slices
        .iter()
        .any(|s| s.checks.iter().any(|c| c.id == id && c.detected))
}

fn check_not_detected(path: &Path, level: DetectionLevel, id: CheckId) -> bool {
    let mapped = MappedBinary::open(path).expect("failed to open fixture");
    let result = analyze_binary(path, &mapped.mmap, level, None).expect("analysis failed");
    result
        .slices
        .iter()
        .all(|s| s.checks.iter().any(|c| c.id == id && !c.detected))
}

fn get_check_evidence(path: &Path, level: DetectionLevel, id: CheckId) -> Vec<String> {
    let mapped = MappedBinary::open(path).expect("failed to open fixture");
    let result = analyze_binary(path, &mapped.mmap, level, None).expect("analysis failed");
    result
        .slices
        .iter()
        .flat_map(|s| {
            s.checks
                .iter()
                .filter(|c| c.id == id)
                .flat_map(|c| c.evidence.iter().map(|e| e.description.clone()))
        })
        .collect()
}

// Exp 1: Stack zero-init

#[test]
fn zeroinit_detected_when_enabled() {
    let path = fixture("exp1_zeroinit");
    assert!(
        check_detected(&path, DetectionLevel::Standard, CheckId::StackZeroInit),
        "expected zero-init detection in exp1_zeroinit"
    );
}

#[test]
fn zeroinit_not_detected_in_baseline() {
    let path = fixture("exp1_baseline");
    assert!(
        check_not_detected(&path, DetectionLevel::Standard, CheckId::StackZeroInit),
        "expected no zero-init in exp1_baseline"
    );
}

// Exp 2: Pointer authentication (PAC)

#[test]
fn pac_detected_on_arm64e() {
    let path = fixture("exp2_arm64e");
    assert!(
        check_detected(&path, DetectionLevel::Standard, CheckId::PacInstructions),
        "expected PAC instructions in arm64e binary"
    );
}

#[test]
fn pac_sections_on_arm64e() {
    let path = fixture("exp2_arm64e");
    assert!(
        check_detected(&path, DetectionLevel::Quick, CheckId::PacSections),
        "expected PAC sections in arm64e binary"
    );
}

// Exp 3: C bounds safety

#[test]
fn bounds_safety_detected_when_enabled() {
    let path = fixture("exp3_bounds");
    assert!(
        check_detected(&path, DetectionLevel::Standard, CheckId::BoundsSafety),
        "expected bounds safety detection"
    );
}

#[test]
fn bounds_safety_not_detected_in_baseline() {
    let path = fixture("exp3_baseline");
    assert!(
        check_not_detected(&path, DetectionLevel::Standard, CheckId::BoundsSafety),
        "expected no bounds safety in baseline"
    );
}

// Exp 4: libc++ hardening

#[test]
fn libcpp_hardening_detected_when_enabled() {
    let path = fixture("exp4_hardened");
    assert!(
        check_detected(&path, DetectionLevel::Standard, CheckId::LibcppHardening),
        "expected libc++ hardening detection"
    );
}

#[test]
fn libcpp_hardening_not_detected_in_baseline() {
    let path = fixture("exp4_baseline");
    assert!(
        check_not_detected(&path, DetectionLevel::Standard, CheckId::LibcppHardening),
        "expected no libc++ hardening in baseline"
    );
}

// Exp 6: Typed allocators

#[test]
fn typed_allocators_detected_when_enabled() {
    let path = fixture("exp6_typed");
    assert!(
        check_detected(&path, DetectionLevel::Quick, CheckId::TypedAllocators),
        "expected typed allocators detection"
    );
}

#[test]
fn typed_allocators_not_detected_in_baseline() {
    let path = fixture("exp6_baseline");
    assert!(
        check_not_detected(&path, DetectionLevel::Quick, CheckId::TypedAllocators),
        "expected no typed allocators in baseline"
    );
}

// Exp 7: FORTIFY_SOURCE

#[test]
fn fortify_detected_when_enabled() {
    let path = fixture("exp7_fortify");
    assert!(
        check_detected(&path, DetectionLevel::Quick, CheckId::FortifySource),
        "expected FORTIFY detection"
    );
}

#[test]
fn fortify_not_detected_without_flag() {
    let path = fixture("exp7_no_fortify");
    assert!(
        check_not_detected(&path, DetectionLevel::Quick, CheckId::FortifySource),
        "expected no FORTIFY in no_fortify build"
    );
}

// Exp 8: Objective-C ARC

#[test]
fn arc_detected_when_enabled() {
    let path = fixture("exp8_arc");
    assert!(
        check_detected(&path, DetectionLevel::Quick, CheckId::Arc),
        "expected ARC detection"
    );
}

// Note: -fno-objc-arc still links Foundation which imports ARC runtime symbols.
// So ARC symbols are always present when Foundation is linked. This is expected.
#[test]
fn arc_detected_even_without_flag_due_to_framework() {
    let path = fixture("exp8_no_arc");
    assert!(
        check_detected(&path, DetectionLevel::Quick, CheckId::Arc),
        "ARC symbols come from Foundation framework even with -fno-objc-arc"
    );
}

// Exp 9: Swift runtime

#[test]
fn swift_runtime_detected() {
    let path = fixture("exp9_swift");
    assert!(
        check_detected(&path, DetectionLevel::Quick, CheckId::SwiftRuntime),
        "expected Swift runtime detection"
    );
}

// Exp 10: __RESTRICT segment

#[test]
fn restrict_detected_when_present() {
    let path = fixture("exp10_restrict");
    assert!(
        check_detected(&path, DetectionLevel::Quick, CheckId::RestrictSegment),
        "expected __RESTRICT detection"
    );
}

#[test]
fn restrict_not_detected_without_segment() {
    let path = fixture("exp10_no_restrict");
    assert!(
        check_not_detected(&path, DetectionLevel::Quick, CheckId::RestrictSegment),
        "expected no __RESTRICT in no_restrict build"
    );
}

// Exp 11: Stack canary (symbol-level)

#[test]
fn canary_symbol_detected_when_protected() {
    let path = fixture("exp11_canary");
    assert!(
        check_detected(&path, DetectionLevel::Quick, CheckId::StackCanary),
        "expected stack canary symbol detection"
    );
}

#[test]
fn canary_symbol_not_detected_without_protection() {
    let path = fixture("exp11_no_canary");
    assert!(
        check_not_detected(&path, DetectionLevel::Quick, CheckId::StackCanary),
        "expected no stack canary in no_canary build"
    );
}

// Exp 11: Stack canary (instruction-level)

#[test]
fn canary_insn_detected_arm64() {
    let path = fixture("exp11_canary");
    assert!(
        check_detected(&path, DetectionLevel::Standard, CheckId::StackCanaryInsn),
        "expected instruction-level canary in arm64"
    );
}

#[test]
fn canary_insn_not_detected_arm64_unprotected() {
    let path = fixture("exp11_no_canary");
    assert!(
        check_not_detected(&path, DetectionLevel::Standard, CheckId::StackCanaryInsn),
        "expected no instruction canary in unprotected arm64"
    );
}

#[test]
fn canary_insn_detected_x86() {
    let path = fixture("exp11_canary_x86");
    assert!(
        check_detected(&path, DetectionLevel::Standard, CheckId::StackCanaryInsn),
        "expected instruction-level canary in x86_64"
    );
}

#[test]
fn canary_insn_not_detected_x86_unprotected() {
    let path = fixture("exp11_no_canary_x86");
    assert!(
        check_not_detected(&path, DetectionLevel::Standard, CheckId::StackCanaryInsn),
        "expected no instruction canary in unprotected x86_64"
    );
}

#[test]
fn canary_insn_evidence_shows_pattern() {
    let path = fixture("exp11_canary");
    let evidence = get_check_evidence(&path, DetectionLevel::Standard, CheckId::StackCanaryInsn);
    let has_guard = evidence.iter().any(|e| e.contains("___stack_chk_guard"));
    assert!(
        has_guard,
        "expected evidence to mention ___stack_chk_guard, got: {:?}",
        evidence
    );
}

// Exp 14: Jump table hardening

#[test]
fn jump_table_hardening_detected() {
    let path = fixture("exp14_jt_hardened");
    assert!(
        check_detected(&path, DetectionLevel::Standard, CheckId::JumpTableHardening),
        "expected jump table hardening detection"
    );
}

#[test]
fn jump_table_hardening_not_detected_in_baseline() {
    let path = fixture("exp14_jt_normal");
    assert!(
        check_not_detected(&path, DetectionLevel::Standard, CheckId::JumpTableHardening),
        "expected no jump table hardening in baseline"
    );
}

// Exp 13: Sanitizers

#[test]
fn asan_detected_when_enabled() {
    let path = fixture("exp13_asan");
    assert!(
        check_detected(&path, DetectionLevel::Quick, CheckId::SanitizerAsan),
        "expected ASan detection"
    );
}

#[test]
fn asan_not_detected_without_sanitizer() {
    let path = fixture("exp13_no_sanitizer");
    assert!(
        check_not_detected(&path, DetectionLevel::Quick, CheckId::SanitizerAsan),
        "expected no ASan in baseline"
    );
}

#[test]
fn ubsan_detected_when_enabled() {
    let path = fixture("exp13_ubsan");
    assert!(
        check_detected(&path, DetectionLevel::Quick, CheckId::SanitizerUbsan),
        "expected UBSan detection"
    );
}

#[test]
fn ubsan_not_detected_without_sanitizer() {
    let path = fixture("exp13_no_sanitizer");
    assert!(
        check_not_detected(&path, DetectionLevel::Quick, CheckId::SanitizerUbsan),
        "expected no UBSan in baseline"
    );
}

// Exp 12: Hardened runtime + code signing

#[test]
fn hardened_runtime_detected() {
    let path = fixture("exp12_hardened");
    assert!(
        check_detected(&path, DetectionLevel::Quick, CheckId::HardenedRuntime),
        "expected hardened runtime detection"
    );
}

#[test]
fn hardened_runtime_not_detected_in_baseline() {
    let path = fixture("exp12_baseline");
    assert!(
        check_not_detected(&path, DetectionLevel::Quick, CheckId::HardenedRuntime),
        "expected no hardened runtime in baseline"
    );
}

#[test]
fn entitlements_detected_in_signed() {
    let path = fixture("exp12_hardened");
    assert!(
        check_detected(&path, DetectionLevel::Quick, CheckId::Entitlements),
        "expected entitlements in signed binary"
    );
}

#[test]
fn cs_hash_type_detected_in_signed() {
    let path = fixture("exp12_hardened");
    assert!(
        check_detected(&path, DetectionLevel::Quick, CheckId::CodeSignHashType),
        "expected CS hash type in signed binary"
    );
}

// Common checks: PIE, code signature, __PAGEZERO

#[test]
fn pie_detected_in_executables() {
    let path = fixture("exp1_baseline");
    assert!(
        check_detected(&path, DetectionLevel::Quick, CheckId::Pie),
        "expected PIE in standard executable"
    );
}

#[test]
fn code_signature_detected_in_signed() {
    let path = fixture("exp12_hardened");
    assert!(
        check_detected(&path, DetectionLevel::Quick, CheckId::CodeSignature),
        "expected code signature in signed binary"
    );
}

#[test]
fn pagezero_detected_in_executables() {
    let path = fixture("exp1_baseline");
    assert!(
        check_detected(&path, DetectionLevel::Quick, CheckId::PageZero),
        "expected __PAGEZERO in standard executable"
    );
}

// Full mode coverage stats

#[test]
fn full_mode_provides_coverage_stats() {
    let path = fixture("exp11_canary");
    let mapped = MappedBinary::open(&path).expect("failed to open fixture");
    let result =
        analyze_binary(&path, &mapped.mmap, DetectionLevel::Full, None).expect("analysis failed");
    for slice in &result.slices {
        let canary = slice
            .checks
            .iter()
            .find(|c| c.id == CheckId::StackCanaryInsn)
            .expect("StackCanaryInsn check missing");
        assert!(canary.detected, "expected canary detected in full mode");
        let stats = canary
            .stats
            .as_ref()
            .expect("expected coverage stats in full mode");
        assert!(
            stats.functions_scanned > 0,
            "expected scanned functions > 0"
        );
        assert!(
            stats.functions_with_feature > 0,
            "expected functions with canary > 0"
        );
    }
}

// x86_64 cross-architecture tests

#[test]
fn zeroinit_detected_x86() {
    let path = fixture("exp1_zeroinit_x86");
    assert!(
        check_detected(&path, DetectionLevel::Standard, CheckId::StackZeroInit),
        "expected zero-init in x86_64"
    );
}

#[test]
fn zeroinit_not_detected_x86_baseline() {
    let path = fixture("exp1_baseline_x86");
    assert!(
        check_not_detected(&path, DetectionLevel::Standard, CheckId::StackZeroInit),
        "expected no zero-init in x86_64 baseline"
    );
}

#[test]
fn bounds_safety_detected_x86() {
    let path = fixture("exp3_bounds_x86");
    assert!(
        check_detected(&path, DetectionLevel::Standard, CheckId::BoundsSafety),
        "expected bounds safety in x86_64"
    );
}

#[test]
fn libcpp_hardening_detected_x86() {
    let path = fixture("exp4_hardened_x86");
    assert!(
        check_detected(&path, DetectionLevel::Standard, CheckId::LibcppHardening),
        "expected libc++ hardening in x86_64"
    );
}
