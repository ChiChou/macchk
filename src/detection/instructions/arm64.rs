//! arm64 instruction detection via raw binary pattern matching.
//!
//! All arm64 instructions are fixed-width 4 bytes, little-endian aligned.
//! We express each detection target as (mask, value) pairs applied directly
//! to the instruction stream — no disassembly needed.

use crate::detection::instructions::{get_symbol_name, get_text_section};
use crate::detection::AnalysisContext;
use crate::types::*;

// ---------------------------------------------------------------------------
// Instruction encoding helpers
// ---------------------------------------------------------------------------

/// Extract the 16-bit immediate from a BRK instruction (bits [20:5]).
#[inline(always)]
fn brk_imm(word: u32) -> u16 {
    ((word >> 5) & 0xFFFF) as u16
}

/// Extract the condition code from a B.cond instruction (bits [3:0]).
#[inline(always)]
fn bcond_cc(word: u32) -> u8 {
    (word & 0xF) as u8
}

/// Extract the signed 19-bit offset from B.cond (bits [23:5]), in bytes.
#[inline(always)]
fn bcond_offset(word: u32) -> i64 {
    let imm19 = ((word >> 5) & 0x7FFFF) as i32;
    // Sign-extend from 19 bits
    let signed = if imm19 & 0x40000 != 0 {
        imm19 | !0x7FFFF_i32
    } else {
        imm19
    };
    (signed as i64) * 4
}

// ---------------------------------------------------------------------------
// Instruction matchers: (mask, value) pairs
// ---------------------------------------------------------------------------

// BRK #imm16: 0xD4200000 | (imm16 << 5)
const BRK_MASK: u32 = 0xFFE0001F;
const BRK_VALUE: u32 = 0xD4200000;

// B.cond: 0x54000000 | (imm19 << 5) | cond
const BCOND_MASK: u32 = 0xFF000010; // top byte + bit 4 (distinguishes B.cond from other branches)
const BCOND_VALUE: u32 = 0x54000000;

// Condition codes
const CC_EQ: u8 = 0x0;
const CC_HS: u8 = 0x2; // also CS
const CC_LO: u8 = 0x3; // also CC
const CC_HI: u8 = 0x8;

// CMP (SUBS with Rd=xzr): multiple forms
// CMP Xn, Xm, shift: SUBS XZR, Xn, Xm = 0xEB00001F mask 0xFF20001F
// CMP Xn, #imm12:     SUBS XZR, Xn, #imm = 0xF100001F mask 0xFF80001F
// CMP Wn, Wm:         SUBS WZR, Wn, Wm = 0x6B00001F mask 0xFF20001F
// CMP Wn, #imm12:     SUBS WZR, Wn, #imm = 0x7100001F mask 0xFF80001F
#[inline(always)]
fn is_cmp(w: u32) -> bool {
    // 64-bit register: SUBS Xd=XZR
    if w & 0xFF20001F == 0xEB00001F {
        return true;
    }
    // 64-bit immediate
    if w & 0xFF80001F == 0xF100001F {
        return true;
    }
    // 32-bit register
    if w & 0xFF20001F == 0x6B00001F {
        return true;
    }
    // 32-bit immediate
    if w & 0xFF80001F == 0x7100001F {
        return true;
    }
    false
}

// CCMP: Conditional Compare
// CCMP Xn, #imm5, #nzcv, cond: 0xFA400800 mask 0xFFE00C10 (64-bit imm)
// CCMP Xn, Xm, #nzcv, cond:    0xFA400000 mask 0xFFE00C10 (64-bit reg)
// CCMP Wn, ...:                 0x7A400800 / 0x7A400000 (32-bit variants)
#[inline(always)]
fn is_ccmp(w: u32) -> bool {
    if w & 0xFFE00C10 == 0xFA400800 {
        return true;
    }
    if w & 0xFFE00C10 == 0xFA400000 {
        return true;
    }
    if w & 0xFFE00C10 == 0x7A400800 {
        return true;
    }
    if w & 0xFFE00C10 == 0x7A400000 {
        return true;
    }
    false
}

#[inline(always)]
fn is_cmp_or_ccmp(w: u32) -> bool {
    is_cmp(w) || is_ccmp(w)
}

// --- PAC instruction encodings ---
const PACIBSP: u32 = 0xD503237F;
const PACIASP: u32 = 0xD503233F;
const RETAB: u32 = 0xD65F0FFF;
const RETAA: u32 = 0xD65F0BFF;
const AUTIASP: u32 = 0xD50323BF;
const AUTIBSP: u32 = 0xD50323FF;
// BRAAZ Xn:  0xD71F081F mask 0xFFFFFC1F (Rn in [9:5])
// BRAA Xn, Xm: 0xD71F0800 mask 0xFFFFF800 ... simplified
// BLRAAZ Xn: 0xD73F081F mask 0xFFFFFC1F
// BLRAA Xn, Xm: 0xD73F0800
const PAC_FIXED: &[u32] = &[PACIBSP, PACIASP, RETAB, RETAA, AUTIASP, AUTIBSP];

#[inline(always)]
fn is_pac_instruction(w: u32) -> bool {
    if PAC_FIXED.contains(&w) {
        return true;
    }
    // BRAAZ Xn
    if w & 0xFFFFFC1F == 0xD71F081F {
        return true;
    }
    // BRAA Xn, Xm
    if w & 0xFFFFF800 == 0xD71F0800 {
        return true;
    }
    // BLRAAZ Xn
    if w & 0xFFFFFC1F == 0xD73F081F {
        return true;
    }
    // BLRAA Xn, Xm
    if w & 0xFFFFF800 == 0xD73F0800 {
        return true;
    }
    false
}

fn pac_name(w: u32) -> &'static str {
    match w {
        PACIBSP => "pacibsp",
        PACIASP => "paciasp",
        RETAB => "retab",
        RETAA => "retaa",
        AUTIASP => "autiasp",
        AUTIBSP => "autibsp",
        _ if w & 0xFFFFFC1F == 0xD71F081F => "braaz",
        _ if w & 0xFFFFF800 == 0xD71F0800 => "braa",
        _ if w & 0xFFFFFC1F == 0xD73F081F => "blraaz",
        _ if w & 0xFFFFF800 == 0xD73F0800 => "blraa",
        _ => "pac?",
    }
}

// --- Zero-init patterns ---
// movi Vd.2D, #0: 0x6F00E400 mask 0xFFFFFFE0
const MOVI_2D_ZERO_MASK: u32 = 0xFFFFFFE0;
const MOVI_2D_ZERO_VAL: u32 = 0x6F00E400;

// STP with XZR: stp xzr, xzr, [base, #imm]
// STP (64-bit, signed offset): 0xA9000000 | (imm7 << 15) | (Rt2 << 10) | (Rn << 5) | Rt
// Rt=31 (xzr), Rt2=31 (xzr): bits [4:0]=11111, bits [14:10]=11111
// Mask for Rt=31 and Rt2=31: check bits [4:0] and [14:10]
#[inline(always)]
fn is_stp_xzr_xzr(w: u32) -> bool {
    let opc = w >> 30;
    let top = (w >> 22) & 0xFF;
    let rt = w & 0x1F;
    let rt2 = (w >> 10) & 0x1F;
    let rn = (w >> 5) & 0x1F;
    // 64-bit STP signed offset: opc=10, top=10100xxx
    // Pre-index: opc=10, top=10100xxx (bit 24 set differently)
    // We want base = sp (31) or fp/x29 (29)
    if rt != 31 || rt2 != 31 {
        return false;
    }
    if rn != 31 && rn != 29 {
        return false;
    } // sp or fp
      // STP 64-bit: top bits [31:22] = 10_101_0_0_xx (signed offset) or 10_101_0_1_xx (pre)
      // Simplified: opc=10 (bits [31:30]), V=0 (bit 26), L=0 (bit 22)
    if opc == 0b10 && (top & 0b11111000) == 0b10100000 && (w >> 22) & 1 == 0 {
        return true;
    }
    false
}

// STR Xzr/Wzr to stack: str xzr, [sp/fp, #imm] or str wzr, [sp/fp, #imm]
// STR (immediate, unsigned offset) 64-bit: 0xF9000000 mask 0xFFC00000
// STR (immediate, unsigned offset) 32-bit: 0xB9000000 mask 0xFFC00000
#[inline(always)]
fn is_str_zr_to_stack(w: u32) -> bool {
    let rt = w & 0x1F;
    let rn = (w >> 5) & 0x1F;
    if rt != 31 {
        return false;
    } // xzr/wzr
    if rn != 31 && rn != 29 {
        return false;
    } // sp or fp
      // STR 64-bit unsigned offset
    if w & 0xFFC00000 == 0xF9000000 {
        return true;
    }
    // STR 32-bit unsigned offset
    if w & 0xFFC00000 == 0xB9000000 {
        return true;
    }
    // STR 64-bit pre/post index (unscaled)
    if w & 0xFFE00000 == 0xF8000000 {
        return true;
    }
    // STR 32-bit pre/post index
    if w & 0xFFE00000 == 0xB8000000 {
        return true;
    }
    false
}

// STP Wzr, Wzr: 32-bit pair store with zero registers
#[inline(always)]
fn is_stp_wzr_wzr(w: u32) -> bool {
    let opc = w >> 30;
    let rt = w & 0x1F;
    let rt2 = (w >> 10) & 0x1F;
    let rn = (w >> 5) & 0x1F;
    if rt != 31 || rt2 != 31 {
        return false;
    }
    if rn != 31 && rn != 29 {
        return false;
    }
    // STP 32-bit: opc=00, top bits match load/store pair pattern, L=0
    if opc == 0b00 && (w >> 22) & 0xFF & 0b11111000 == 0b00101000 && (w >> 22) & 1 == 0 {
        return true;
    }
    false
}

// STP Qreg, Qreg to stack (stores from movi zero vector)
#[inline(always)]
fn is_stp_qreg_to_stack(w: u32) -> bool {
    let opc = w >> 30;
    let rn = (w >> 5) & 0x1F;
    if rn != 31 && rn != 29 {
        return false;
    }
    // STP 128-bit (SIMD): opc=10, V=1 (bit 26), L=0 (bit 22)
    // Encoding: 0xAD000000 for signed offset variant
    if opc == 0b10 && (w >> 26) & 1 == 1 && (w >> 22) & 1 == 0 {
        return true;
    }
    false
}

// Prologue instructions to skip past
#[inline(always)]
fn is_prologue_insn(w: u32) -> bool {
    // STP x29, x30, [sp, #off] — save frame pointer + link register
    // Check for STP with Rt=29 (fp) and Rt2=30 (lr), Rn=31 (sp)
    let rt = w & 0x1F;
    let rn = (w >> 5) & 0x1F;
    let rt2 = (w >> 10) & 0x1F;
    if rt == 29 && rt2 == 30 && rn == 31 && (w >> 22) & 0xFF & 0b11111000 == 0b10100000 {
        return true;
    }
    // SUB sp, sp, #imm (stack frame allocation)
    // SUB (immediate) 64-bit: 0xD1000000 mask 0xFF800000
    if w & 0xFF80001F == 0xD100001F {
        return true;
    } // Rd=sp
    if w & 0xFF800000 == 0xD1000000 && (w & 0x1F) == 31 {
        return true;
    }
    // ADD x29, sp, #imm (set frame pointer)
    if w & 0xFF800000 == 0x91000000 && (w & 0x1F) == 29 && ((w >> 5) & 0x1F) == 31 {
        return true;
    }
    // PACIBSP / PACIASP
    if w == PACIBSP || w == PACIASP {
        return true;
    }
    false
}

// RET, B, BL, BRK — terminators
#[inline(always)]
fn is_terminator(w: u32) -> bool {
    w == 0xD65F03C0 // RET
        || w & 0xFC000000 == 0x14000000 // B imm
        || w & 0xFC000000 == 0x94000000 // BL imm
        || w & BRK_MASK == BRK_VALUE // BRK
}

// --- MTE instruction encodings (from previous implementation) ---

fn is_mte_instruction(word: u32) -> Option<&'static str> {
    if word & 0xFFE0FC00 == 0x9AC01000 {
        return Some("irg");
    }
    if word & 0xFFE0FC00 == 0x9AC01400 {
        return Some("gmi");
    }
    if word & 0xFFC0C000 == 0x91800000 {
        return Some("addg");
    }
    if word & 0xFFC0C000 == 0xD1800000 {
        return Some("subg");
    }
    // STG (all addressing modes: offset=0b10, post=0b01, pre=0b11)
    if word & 0xFFE00C00 == 0xD9200800 {
        return Some("stg");
    }
    if word & 0xFFE00C00 == 0xD9200400 {
        return Some("stg");
    }
    if word & 0xFFE00C00 == 0xD9200C00 {
        return Some("stg");
    }
    // STZG
    if word & 0xFFE00C00 == 0xD9600800 {
        return Some("stzg");
    }
    if word & 0xFFE00C00 == 0xD9600400 {
        return Some("stzg");
    }
    if word & 0xFFE00C00 == 0xD9600C00 {
        return Some("stzg");
    }
    // ST2G
    if word & 0xFFE00C00 == 0xD9A00800 {
        return Some("st2g");
    }
    if word & 0xFFE00C00 == 0xD9A00400 {
        return Some("st2g");
    }
    if word & 0xFFE00C00 == 0xD9A00C00 {
        return Some("st2g");
    }
    // STZ2G
    if word & 0xFFE00C00 == 0xD9E00800 {
        return Some("stz2g");
    }
    if word & 0xFFE00C00 == 0xD9E00400 {
        return Some("stz2g");
    }
    if word & 0xFFE00C00 == 0xD9E00C00 {
        return Some("stz2g");
    }
    // LDG
    if word & 0xFFE00C00 == 0xD9600000 {
        return Some("ldg");
    }
    // STGP
    if word & 0xFFC00000 == 0x69000000 {
        return Some("stgp");
    }
    if word & 0xFFC00000 == 0x68800000 {
        return Some("stgp");
    }
    if word & 0xFFC00000 == 0x69800000 {
        return Some("stgp");
    }
    // SUBP / SUBPS
    if word & 0xFFE0FC00 == 0x9AC00000 {
        return Some("subp");
    }
    if word & 0xFFE0FC00 == 0xBAC00000 {
        return Some("subps");
    }
    None
}

// ---------------------------------------------------------------------------
// Scan helpers — operate on raw u32 word arrays
// ---------------------------------------------------------------------------

/// Convert text section bytes to aligned u32 words.
fn to_words(data: &[u8]) -> Vec<u32> {
    data.chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect()
}

/// Scan the entire text section for a specific BRK immediate.
/// Returns byte offsets relative to text_data where BRK is found.
/// This is the SIMD-friendly fast path — the compiler can auto-vectorize
/// the comparison loop since it's a simple scan over u32 values.
fn find_brk_sites(words: &[u32], brk_imm_val: u16) -> Vec<usize> {
    words
        .iter()
        .enumerate()
        .filter(|(_, &w)| w & BRK_MASK == BRK_VALUE && brk_imm(w) == brk_imm_val)
        .map(|(i, _)| i)
        .collect()
}

// ---------------------------------------------------------------------------
// Detection functions
// ---------------------------------------------------------------------------

pub fn detect_pac_instructions(
    ctx: &AnalysisContext,
    id: CheckId,
    name: &'static str,
    polarity: Polarity,
) -> CheckResult {
    let (text_data, text_base) = match get_text_section(ctx) {
        Some(v) => v,
        None => return empty_result(id, name, polarity),
    };
    let words = to_words(&text_data);
    let bounds = ctx.function_boundaries();
    let is_full = ctx.level == DetectionLevel::Full;
    let mut evidence = Vec::new();
    let mut stats = CoverageStats::default();

    for &(fstart, fend) in bounds {
        let w_start = ((fstart - text_base) / 4) as usize;
        let w_end = ((fend - text_base) / 4) as usize;
        if w_end > words.len() {
            continue;
        }
        stats.functions_scanned += 1;

        let mut found = false;
        for i in w_start..w_end {
            if is_pac_instruction(words[i]) {
                found = true;
                if evidence.is_empty() || is_full {
                    let addr = text_base + (i as u64) * 4;
                    let fname = get_symbol_name(ctx.macho, fstart);
                    evidence.push(Evidence {
                        strategy: "binary_pattern".into(),
                        description: format!("{} in {}", pac_name(words[i]), fname),
                        confidence: Confidence::Definitive,
                        address: Some(addr),
                        function_name: Some(fname),
                    });
                }
                break;
            }
        }
        if found {
            stats.functions_with_feature += 1;
            stats.sites_found += 1;
        }
        if !is_full && !evidence.is_empty() {
            break;
        }
    }

    CheckResult {
        id,
        name: name.into(),
        category: Category::Instructions,
        polarity,
        detected: !evidence.is_empty(),
        evidence,
        stats: if is_full { Some(stats) } else { None },
    }
}

pub fn detect_zeroinit(
    ctx: &AnalysisContext,
    id: CheckId,
    name: &'static str,
    polarity: Polarity,
) -> CheckResult {
    let (text_data, text_base) = match get_text_section(ctx) {
        Some(v) => v,
        None => return empty_result(id, name, polarity),
    };
    let words = to_words(&text_data);
    let bounds = ctx.function_boundaries();
    let is_full = ctx.level == DetectionLevel::Full;
    let mut evidence = Vec::new();
    let mut stats = CoverageStats::default();

    for &(fstart, fend) in bounds {
        let w_start = ((fstart - text_base) / 4) as usize;
        let w_end = ((fend - text_base) / 4) as usize;
        if w_end > words.len() {
            continue;
        }
        stats.functions_scanned += 1;

        // Find prologue end (first 8 instructions)
        let prologue_end = {
            let mut pe = w_start;
            for i in w_start..std::cmp::min(w_start + 8, w_end) {
                if is_prologue_insn(words[i]) {
                    pe = i + 1;
                }
            }
            pe
        };

        let mut found = false;
        let scan_end = std::cmp::min(prologue_end + 12, w_end);

        for i in w_start..scan_end {
            let w = words[i];

            // Pattern 1: movi Vd.2D, #0 followed by stp Qd,Qd,[sp/fp]
            if w & MOVI_2D_ZERO_MASK == MOVI_2D_ZERO_VAL {
                // Check for subsequent stp qN to stack
                for j in (i + 1)..std::cmp::min(i + 12, w_end) {
                    if is_stp_qreg_to_stack(words[j]) {
                        found = true;
                        break;
                    }
                    if is_terminator(words[j]) {
                        break;
                    }
                }
            }

            // Pattern 2: stp xzr, xzr, [sp/fp, #imm] (16 bytes zeroed)
            if !found && is_stp_xzr_xzr(w) {
                // Only near prologue to avoid false positives from memset-like code
                if i <= prologue_end + 8 {
                    found = true;
                }
            }

            // Pattern 3: str xzr/wzr, [sp/fp, #imm] (4/8 bytes zeroed)
            // Only count if there are multiple consecutive stores to stack
            if !found && is_str_zr_to_stack(w) && i <= prologue_end + 8 {
                // Need at least 2 consecutive zero stores to be confident
                if i + 1 < w_end
                    && (is_str_zr_to_stack(words[i + 1]) || is_stp_xzr_xzr(words[i + 1]))
                {
                    found = true;
                }
            }

            // Pattern 4: stp wzr, wzr, [sp/fp] (8 bytes zeroed)
            if !found && is_stp_wzr_wzr(w) && i <= prologue_end + 8 {
                found = true;
            }

            if found {
                break;
            }
        }

        if found {
            stats.functions_with_feature += 1;
            stats.sites_found += 1;
            if evidence.is_empty() || is_full {
                let fname = get_symbol_name(ctx.macho, fstart);
                evidence.push(Evidence {
                    strategy: "binary_pattern".into(),
                    description: format!("zero-init pattern near prologue in {}", fname),
                    confidence: Confidence::High,
                    address: Some(fstart),
                    function_name: Some(fname),
                });
            }
        }
        if !is_full && !evidence.is_empty() {
            break;
        }
    }

    CheckResult {
        id,
        name: name.into(),
        category: Category::Instructions,
        polarity,
        detected: !evidence.is_empty(),
        evidence,
        stats: if is_full { Some(stats) } else { None },
    }
}

/// Detect libc++ hardening: cmp + b.{hs,hi,eq} -> brk #0x1
pub fn detect_libcpp_hardening(
    ctx: &AnalysisContext,
    id: CheckId,
    name: &'static str,
    polarity: Polarity,
) -> CheckResult {
    detect_brk_pattern(
        ctx,
        id,
        name,
        polarity,
        0x1,
        &[CC_HS, CC_HI, CC_EQ],
        "brk #0x1",
    )
}

/// Detect C bounds safety: cmp + b.{lo,hi} -> brk #0x5519
pub fn detect_bounds_safety(
    ctx: &AnalysisContext,
    id: CheckId,
    name: &'static str,
    polarity: Polarity,
) -> CheckResult {
    detect_brk_pattern(
        ctx,
        id,
        name,
        polarity,
        0x5519,
        &[CC_LO, CC_HI],
        "brk #0x5519",
    )
}

/// Generic detector for: cmp/ccmp + b.{conds} -> brk #imm patterns.
fn detect_brk_pattern(
    ctx: &AnalysisContext,
    id: CheckId,
    name: &'static str,
    polarity: Polarity,
    brk_imm_val: u16,
    allowed_conds: &[u8],
    brk_desc: &str,
) -> CheckResult {
    let (text_data, text_base) = match get_text_section(ctx) {
        Some(v) => v,
        None => return empty_result(id, name, polarity),
    };
    let words = to_words(&text_data);
    let is_full = ctx.level == DetectionLevel::Full;

    // Fast path: scan entire section for brk sites first
    let brk_indices = find_brk_sites(&words, brk_imm_val);
    if brk_indices.is_empty() {
        // No brk with this immediate anywhere — skip function-level scan
        return if is_full {
            let bounds = ctx.function_boundaries();
            CheckResult {
                id,
                name: name.into(),
                category: Category::Instructions,
                polarity,
                detected: false,
                evidence: vec![],
                stats: Some(CoverageStats {
                    functions_scanned: bounds.len() as u64,
                    ..Default::default()
                }),
            }
        } else {
            empty_result(id, name, polarity)
        };
    }

    // Build a set of brk word indices for O(1) lookup
    let brk_set: std::collections::HashSet<usize> = brk_indices.into_iter().collect();

    let bounds = ctx.function_boundaries();
    let mut evidence = Vec::new();
    let mut stats = CoverageStats::default();

    for &(fstart, fend) in bounds {
        let w_start = ((fstart - text_base) / 4) as usize;
        let w_end = ((fend - text_base) / 4) as usize;
        if w_end > words.len() {
            continue;
        }
        stats.functions_scanned += 1;

        let mut func_found = false;

        for i in w_start..w_end {
            let w = words[i];
            // Is this a B.cond?
            if w & BCOND_MASK != BCOND_VALUE {
                continue;
            }

            let cc = bcond_cc(w);
            if !allowed_conds.contains(&cc) {
                continue;
            }

            // Compute branch target word index
            let offset = bcond_offset(w);
            let target_addr = (text_base + (i as u64) * 4).wrapping_add(offset as u64);
            let target_idx = ((target_addr - text_base) / 4) as usize;

            // Does it branch to one of our brk sites?
            if !brk_set.contains(&target_idx) {
                continue;
            }

            // Check for preceding cmp/ccmp within 3 instructions
            let has_cmp = (1..=3u32).any(|back| {
                let j = i.wrapping_sub(back as usize);
                j >= w_start && is_cmp_or_ccmp(words[j])
            });
            if !has_cmp {
                continue;
            }

            func_found = true;
            stats.sites_found += 1;

            if evidence.is_empty() || is_full {
                let cc_name = match cc {
                    CC_EQ => "eq",
                    CC_HS => "hs",
                    CC_LO => "lo",
                    CC_HI => "hi",
                    _ => "??",
                };
                let addr = text_base + (i as u64) * 4;
                let fname = get_symbol_name(ctx.macho, fstart);
                evidence.push(Evidence {
                    strategy: "binary_pattern".into(),
                    description: format!(
                        "cmp + b.{} -> {} in {} @ {:#x}",
                        cc_name, brk_desc, fname, addr
                    ),
                    confidence: Confidence::High,
                    address: Some(addr),
                    function_name: Some(fname),
                });
            }
            if !is_full {
                break;
            }
        }
        if func_found {
            stats.functions_with_feature += 1;
        }
        if !is_full && !evidence.is_empty() {
            break;
        }
    }

    CheckResult {
        id,
        name: name.into(),
        category: Category::Instructions,
        polarity,
        detected: !evidence.is_empty(),
        evidence,
        stats: if is_full { Some(stats) } else { None },
    }
}

pub fn detect_mte(
    ctx: &AnalysisContext,
    id: CheckId,
    name: &'static str,
    polarity: Polarity,
) -> CheckResult {
    let (text_data, text_base) = match get_text_section(ctx) {
        Some(v) => v,
        None => return empty_result(id, name, polarity),
    };
    let words = to_words(&text_data);
    let bounds = ctx.function_boundaries();
    let is_full = ctx.level == DetectionLevel::Full;
    let mut evidence = Vec::new();
    let mut stats = CoverageStats::default();

    for &(fstart, fend) in bounds {
        let w_start = ((fstart - text_base) / 4) as usize;
        let w_end = ((fend - text_base) / 4) as usize;
        if w_end > words.len() {
            continue;
        }
        stats.functions_scanned += 1;

        let mut found = false;
        for i in w_start..w_end {
            if let Some(mte_name) = is_mte_instruction(words[i]) {
                found = true;
                if evidence.is_empty() || is_full {
                    let addr = text_base + (i as u64) * 4;
                    let fname = get_symbol_name(ctx.macho, fstart);
                    evidence.push(Evidence {
                        strategy: "binary_pattern".into(),
                        description: format!(
                            "{} ({:#010x}) in {} @ {:#x}",
                            mte_name, words[i], fname, addr
                        ),
                        confidence: Confidence::Definitive,
                        address: Some(addr),
                        function_name: Some(fname),
                    });
                }
                break;
            }
        }
        if found {
            stats.functions_with_feature += 1;
            stats.sites_found += 1;
        }
        if !is_full && !evidence.is_empty() {
            break;
        }
    }

    CheckResult {
        id,
        name: name.into(),
        category: Category::Instructions,
        polarity,
        detected: !evidence.is_empty(),
        evidence,
        stats: if is_full { Some(stats) } else { None },
    }
}

// --- Stack canary detection ---
// BL imm26: 0x94000000 | (imm26 & 0x3FFFFFF)
const BL_MASK: u32 = 0xFC000000;
const BL_VALUE: u32 = 0x94000000;

// ADRP Xd, #page: 1_immlo(2)_10000_immhi(19)_Rd(5)
const ADRP_MASK: u32 = 0x9F000000;
const ADRP_VALUE: u32 = 0x90000000;

// LDR Xt, [Xn, #imm12]: 1_1_11_1_0_01_01_imm12(12)_Rn(5)_Rt(5)
// 64-bit unsigned offset: 0xF9400000 mask 0xFFC00000
const LDR64_UOFF_MASK: u32 = 0xFFC00000;
const LDR64_UOFF_VALUE: u32 = 0xF9400000;

/// Compute the page address from an ADRP instruction.
#[inline(always)]
fn adrp_target(word: u32, pc: u64) -> u64 {
    let immlo = ((word >> 29) & 0x3) as i64;
    let immhi = ((word >> 5) & 0x7FFFF) as i64;
    let imm = (immhi << 2) | immlo;
    // Sign-extend from 21 bits
    let signed = if imm & 0x100000 != 0 {
        imm | !0x1FFFFF_i64
    } else {
        imm
    };
    (pc & !0xFFF).wrapping_add((signed << 12) as u64)
}

/// Extract the scaled 12-bit unsigned offset from a 64-bit LDR.
#[inline(always)]
fn ldr64_offset(word: u32) -> u64 {
    let imm12 = ((word >> 10) & 0xFFF) as u64;
    imm12 * 8 // scale by 8 for 64-bit LDR
}

/// Extract Rd (destination register) from an instruction (bits [4:0]).
#[inline(always)]
fn rd(word: u32) -> u32 {
    word & 0x1F
}

/// Extract Rn (base register) from an instruction (bits [9:5]).
#[inline(always)]
fn rn(word: u32) -> u32 {
    (word >> 5) & 0x1F
}

/// Extract the signed 26-bit offset from BL, in bytes.
#[inline(always)]
fn bl_target(word: u32, pc: u64) -> u64 {
    let imm26 = (word & 0x03FFFFFF) as i32;
    let signed = if imm26 & 0x02000000 != 0 {
        imm26 | !0x03FFFFFF_i32
    } else {
        imm26
    };
    pc.wrapping_add((signed as i64 * 4) as u64)
}

/// Detailed stack canary detection for arm64/arm64e.
///
/// Detects the full pattern:
///   Prologue: adrp Xn, guard@PAGE → ldr Xn, [Xn, guard@PAGEOFF] → ldr Xn, [Xn] → str Xn, [sp/fp]
///   Epilogue: ldr Xn, [sp/fp] → adrp Xm, guard@PAGE → ldr Xm, [Xm, guard@PAGEOFF] → ldr Xm, [Xm] → cmp → b.ne → bl __stack_chk_fail
pub fn detect_stack_canary(
    ctx: &AnalysisContext,
    id: CheckId,
    name: &'static str,
    polarity: Polarity,
) -> CheckResult {
    use crate::detection::instructions::{find_got_for_symbol, find_stub_for_symbol};

    let (text_data, text_base) = match get_text_section(ctx) {
        Some(v) => v,
        None => return empty_result(id, name, polarity),
    };

    let chk_fail_addr =
        find_stub_for_symbol(ctx.macho, ctx.raw_bytes, "___stack_chk_fail");
    let chk_guard_got =
        find_got_for_symbol(ctx.macho, ctx.raw_bytes, "___stack_chk_guard");

    // Need at least one of them to detect canaries
    if chk_fail_addr.is_none() && chk_guard_got.is_none() {
        return empty_result(id, name, polarity);
    }

    let words = to_words(&text_data);
    let bounds = ctx.function_boundaries();
    let is_full = ctx.level == DetectionLevel::Full;
    let mut evidence = Vec::new();
    let mut stats = CoverageStats::default();

    for &(fstart, fend) in bounds {
        let w_start = ((fstart - text_base) / 4) as usize;
        let w_end = ((fend - text_base) / 4) as usize;
        if w_end > words.len() {
            continue;
        }
        stats.functions_scanned += 1;

        let mut has_guard_load = false;
        let mut has_guard_check = false;
        let mut has_chk_fail = false;

        for i in w_start..w_end {
            let w = words[i];

            // Detect ADRP+LDR that computes ___stack_chk_guard GOT address
            if let Some(guard_addr) = chk_guard_got {
                if w & ADRP_MASK == ADRP_VALUE {
                    let pc = text_base + (i as u64) * 4;
                    let page = adrp_target(w, pc);
                    let adrp_rd = rd(w);
                    // Check next instruction for LDR Xd, [Xn, #off] where
                    // Xn == ADRP's Rd and page + offset == guard GOT address
                    if i + 1 < w_end {
                        let next = words[i + 1];
                        if next & LDR64_UOFF_MASK == LDR64_UOFF_VALUE
                            && rn(next) == adrp_rd
                        {
                            let addr = page + ldr64_offset(next);
                            if addr == guard_addr {
                                has_guard_load = true;
                            }
                        }
                    }
                }

                // Detect CMP after guard load (epilogue check)
                if has_guard_load && is_cmp(w) {
                    has_guard_check = true;
                }
            }

            // Detect B.NE (branch to fail path)
            // Not strictly required but confirms the pattern

            // Detect BL ___stack_chk_fail
            if let Some(fail_addr) = chk_fail_addr {
                if w & BL_MASK == BL_VALUE {
                    let pc = text_base + (i as u64) * 4;
                    if bl_target(w, pc) == fail_addr {
                        has_chk_fail = true;
                    }
                }
            }
        }

        // A function has a canary if we see the guard load + either check or fail call
        let found = has_guard_load && (has_guard_check || has_chk_fail);

        if found {
            stats.functions_with_feature += 1;
            stats.sites_found += 1;
            if evidence.is_empty() || is_full {
                let fname = get_symbol_name(ctx.macho, fstart);
                let mut parts = Vec::new();
                if has_guard_load {
                    parts.push("load ___stack_chk_guard");
                }
                if has_guard_check {
                    parts.push("cmp");
                }
                if has_chk_fail {
                    parts.push("bl ___stack_chk_fail");
                }
                evidence.push(Evidence {
                    strategy: "binary_pattern".into(),
                    description: format!("{} in {}", parts.join(" → "), fname),
                    confidence: Confidence::Definitive,
                    address: Some(fstart),
                    function_name: Some(fname),
                });
            }
        }
        if !is_full && !evidence.is_empty() {
            break;
        }
    }

    CheckResult {
        id,
        name: name.into(),
        category: Category::Instructions,
        polarity,
        detected: !evidence.is_empty(),
        evidence,
        stats: if is_full { Some(stats) } else { None },
    }
}

// --- Jump table hardening ---
// csel x16, x16, xzr, ls — index clamping for Spectre v1 mitigation
const CSEL_X16_XZR_LS: u32 = 0x9A9F9210;
// br x16 — indirect branch through hardened jump table
const BR_X16: u32 = 0xD61F0200;

/// Detect jump table hardening (Spectre v1 mitigation).
///
/// The hardened pattern uses `csel x16, x16, xzr, ls` to clamp the jump table
/// index, preventing speculative out-of-bounds reads. This is followed by
/// `ldrsw x16, [x17, x16, lsl #2]` and `br x16`.
///
/// On arm64, this requires `-faarch64-jump-table-hardening`.
pub fn detect_jump_table_hardening(
    ctx: &AnalysisContext,
    id: CheckId,
    name: &'static str,
    polarity: Polarity,
) -> CheckResult {
    let (text_data, text_base) = match get_text_section(ctx) {
        Some(v) => v,
        None => return empty_result(id, name, polarity),
    };
    let words = to_words(&text_data);
    let bounds = ctx.function_boundaries();
    let is_full = ctx.level == DetectionLevel::Full;
    let mut evidence = Vec::new();
    let mut stats = CoverageStats::default();

    for &(fstart, fend) in bounds {
        let w_start = ((fstart - text_base) / 4) as usize;
        let w_end = ((fend - text_base) / 4) as usize;
        if w_end > words.len() {
            continue;
        }
        stats.functions_scanned += 1;

        let mut found = false;
        for i in w_start..w_end {
            if words[i] != CSEL_X16_XZR_LS {
                continue;
            }
            // Verify br x16 follows within 8 instructions
            let look_end = std::cmp::min(i + 8, w_end);
            for j in (i + 1)..look_end {
                if words[j] == BR_X16 {
                    found = true;
                    if evidence.is_empty() || is_full {
                        let addr = text_base + (i as u64) * 4;
                        let fname = get_symbol_name(ctx.macho, fstart);
                        evidence.push(Evidence {
                            strategy: "binary_pattern".into(),
                            description: format!(
                                "csel x16, x16, xzr, ls + br x16 in {}",
                                fname
                            ),
                            confidence: Confidence::Definitive,
                            address: Some(addr),
                            function_name: Some(fname),
                        });
                    }
                    break;
                }
            }
            if found {
                break;
            }
        }
        if found {
            stats.functions_with_feature += 1;
            stats.sites_found += 1;
        }
        if !is_full && !evidence.is_empty() {
            break;
        }
    }

    CheckResult {
        id,
        name: name.into(),
        category: Category::Instructions,
        polarity,
        detected: !evidence.is_empty(),
        evidence,
        stats: if is_full { Some(stats) } else { None },
    }
}

fn empty_result(id: CheckId, name: &'static str, polarity: Polarity) -> CheckResult {
    CheckResult {
        id,
        name: name.into(),
        category: Category::Instructions,
        polarity,
        detected: false,
        evidence: vec![],
        stats: None,
    }
}
