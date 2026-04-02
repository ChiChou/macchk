use capstone::arch::x86::X86Insn;
use capstone::prelude::*;
use std::collections::HashSet;

use crate::detection::instructions::{get_symbol_name, get_text_section};
use crate::detection::AnalysisContext;
use crate::types::*;

fn make_engine() -> Result<Capstone, capstone::Error> {
    Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .detail(true)
        .build()
}

// --- Stack Zero-Init ---

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
    let cs = match make_engine() {
        Ok(v) => v,
        Err(_) => return empty_result(id, name, polarity),
    };
    let bounds = ctx.function_boundaries();
    let is_full = ctx.level == DetectionLevel::Full;
    let mut evidence = Vec::new();
    let mut stats = CoverageStats::default();

    for &(fstart, fend) in bounds {
        let off = (fstart - text_base) as usize;
        let sz = (fend - fstart) as usize;
        if off + sz > text_data.len() {
            continue;
        }

        let insns = match cs.disasm_all(&text_data[off..off + sz], fstart) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let insn_vec: Vec<_> = insns.as_ref().iter().collect();
        stats.functions_scanned += 1;

        let prologue_end = find_prologue_end_x86(&insn_vec);
        let mut found = false;

        for (i, insn) in insn_vec.iter().enumerate() {
            if i as isize - prologue_end as isize > 8 {
                break;
            }
            let mn = insn.mnemonic().unwrap_or("");
            // xorps xmmN, xmmN or pxor xmmN, xmmN (self-xor to zero)
            if !["xorps", "xorpd", "pxor", "vxorps", "vxorpd", "vpxor"].contains(&mn) {
                continue;
            }
            let op = insn.op_str().unwrap_or("");
            let parts: Vec<&str> = op.split(", ").collect();
            if parts.len() != 2 || parts[0] != parts[1] {
                continue;
            }
            if !parts[0].starts_with("xmm") {
                continue;
            }

            // Look for movaps/movups [rbp/rsp-off], xmmN stores
            let mut has_store = false;
            for j in (i + 1)..std::cmp::min(i + 16, insn_vec.len()) {
                let smn = insn_vec[j].mnemonic().unwrap_or("");
                let sop = insn_vec[j].op_str().unwrap_or("");
                if ["movaps", "movups"].contains(&smn)
                    && (sop.contains("[rbp") || sop.contains("[rsp"))
                {
                    has_store = true;
                    break;
                }
                if ["ret", "jmp", "call", "ud2"].contains(&smn) {
                    break;
                }
            }
            if has_store {
                found = true;
                if evidence.is_empty() || is_full {
                    let fname = get_symbol_name(ctx.macho, fstart);
                    evidence.push(Evidence {
                        strategy: "instruction_scan".into(),
                        description: format!("xorps+movaps zero-init pattern in {}", fname),
                        confidence: Confidence::High,
                        address: Some(insn.address()),
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

// --- libc++ Hardening ---

pub fn detect_libcpp_hardening(
    ctx: &AnalysisContext,
    id: CheckId,
    name: &'static str,
    polarity: Polarity,
) -> CheckResult {
    let (text_data, text_base) = match get_text_section(ctx) {
        Some(v) => v,
        None => return empty_result(id, name, polarity),
    };
    let cs = match make_engine() {
        Ok(v) => v,
        Err(_) => return empty_result(id, name, polarity),
    };
    let bounds = ctx.function_boundaries();
    let is_full = ctx.level == DetectionLevel::Full;
    let mut evidence = Vec::new();
    let mut stats = CoverageStats::default();

    for &(fstart, fend) in bounds {
        let off = (fstart - text_base) as usize;
        let sz = (fend - fstart) as usize;
        if off + sz > text_data.len() {
            continue;
        }

        let insns = match cs.disasm_all(&text_data[off..off + sz], fstart) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let insn_vec: Vec<_> = insns.as_ref().iter().collect();
        stats.functions_scanned += 1;

        // Find ud2 addresses
        let ud2_addrs: HashSet<u64> = insn_vec
            .iter()
            .filter(|i| {
                let insn_id = X86Insn::from(i.id().0 as u32);
                insn_id == X86Insn::X86_INS_UD2
            })
            .map(|i| i.address())
            .collect();

        if ud2_addrs.is_empty() {
            continue;
        }

        let mut func_found = false;
        for (i, insn) in insn_vec.iter().enumerate() {
            let mn = insn.mnemonic().unwrap_or("");
            if !["jae", "ja", "je"].contains(&mn) {
                continue;
            }

            let op = insn.op_str().unwrap_or("");
            let target = parse_x86_branch_target(op);
            if !ud2_addrs.contains(&target) {
                continue;
            }

            let has_cmp = (1..=3).any(|back| {
                if i >= back {
                    let pmn = insn_vec[i - back].mnemonic().unwrap_or("");
                    ["cmp", "test"].contains(&pmn)
                } else {
                    false
                }
            });
            if !has_cmp {
                continue;
            }

            func_found = true;
            stats.sites_found += 1;

            if evidence.is_empty() || is_full {
                let fname = get_symbol_name(ctx.macho, fstart);
                evidence.push(Evidence {
                    strategy: "instruction_scan".into(),
                    description: format!(
                        "cmp + {} -> ud2 pattern in {} @ {:#x}",
                        mn,
                        fname,
                        insn.address()
                    ),
                    confidence: Confidence::High,
                    address: Some(insn.address()),
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

// --- C Bounds Safety ---

pub fn detect_bounds_safety(
    ctx: &AnalysisContext,
    id: CheckId,
    name: &'static str,
    polarity: Polarity,
) -> CheckResult {
    let (text_data, text_base) = match get_text_section(ctx) {
        Some(v) => v,
        None => return empty_result(id, name, polarity),
    };
    let cs = match make_engine() {
        Ok(v) => v,
        Err(_) => return empty_result(id, name, polarity),
    };
    let bounds = ctx.function_boundaries();
    let is_full = ctx.level == DetectionLevel::Full;
    let mut evidence = Vec::new();
    let mut stats = CoverageStats::default();

    for &(fstart, fend) in bounds {
        let off = (fstart - text_base) as usize;
        let sz = (fend - fstart) as usize;
        if off + sz > text_data.len() {
            continue;
        }

        let insns = match cs.disasm_all(&text_data[off..off + sz], fstart) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let insn_vec: Vec<_> = insns.as_ref().iter().collect();
        stats.functions_scanned += 1;

        // Find ud1 addresses (bounds safety uses ud1, not ud2)
        let ud1_addrs: HashSet<u64> = insn_vec
            .iter()
            .filter(|i| {
                let insn_id = X86Insn::from(i.id().0 as u32);
                insn_id == X86Insn::X86_INS_UD1
            })
            .map(|i| i.address())
            .collect();

        if ud1_addrs.is_empty() {
            continue;
        }

        let mut func_found = false;
        for (i, insn) in insn_vec.iter().enumerate() {
            let mn = insn.mnemonic().unwrap_or("");
            if !["jb", "ja"].contains(&mn) {
                continue;
            }

            let op = insn.op_str().unwrap_or("");
            let target = parse_x86_branch_target(op);
            if !ud1_addrs.contains(&target) {
                continue;
            }

            let has_cmp = (1..=3).any(|back| {
                if i >= back {
                    let pmn = insn_vec[i - back].mnemonic().unwrap_or("");
                    ["cmp", "test"].contains(&pmn)
                } else {
                    false
                }
            });
            if !has_cmp {
                continue;
            }

            func_found = true;
            stats.sites_found += 1;

            if evidence.is_empty() || is_full {
                let fname = get_symbol_name(ctx.macho, fstart);
                evidence.push(Evidence {
                    strategy: "instruction_scan".into(),
                    description: format!(
                        "cmp + {} -> ud1 pattern in {} @ {:#x}",
                        mn,
                        fname,
                        insn.address()
                    ),
                    confidence: Confidence::High,
                    address: Some(insn.address()),
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

// --- Stack Canary ---

/// Detailed stack canary detection for x86_64.
///
/// Detects the full pattern:
///   Prologue: mov rax, [rip+off] (load GOT ptr to guard) → mov rax, [rax] → mov [rbp-off], rax
///   Epilogue: mov rax, [rip+off] (reload guard) → mov rax, [rax] → cmp → jne → call __stack_chk_fail
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
    let cs = match make_engine() {
        Ok(v) => v,
        Err(_) => return empty_result(id, name, polarity),
    };

    let chk_fail_addr = find_stub_for_symbol(ctx.macho, ctx.raw_bytes, "___stack_chk_fail");
    let chk_guard_got = find_got_for_symbol(ctx.macho, ctx.raw_bytes, "___stack_chk_guard");

    if chk_fail_addr.is_none() && chk_guard_got.is_none() {
        return empty_result(id, name, polarity);
    }

    let bounds = ctx.function_boundaries();
    let is_full = ctx.level == DetectionLevel::Full;
    let mut evidence = Vec::new();
    let mut stats = CoverageStats::default();

    for &(fstart, fend) in bounds {
        let off = (fstart - text_base) as usize;
        let sz = (fend - fstart) as usize;
        if off + sz > text_data.len() {
            continue;
        }

        let insns = match cs.disasm_all(&text_data[off..off + sz], fstart) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let insn_vec: Vec<_> = insns.as_ref().iter().collect();
        stats.functions_scanned += 1;

        let mut has_guard_load = false;
        let mut has_guard_check = false;
        let mut has_chk_fail = false;

        for insn in insn_vec.iter() {
            let insn_id = X86Insn::from(insn.id().0 as u32);
            let op = insn.op_str().unwrap_or("");

            // Detect MOV reg, [RIP+off] that loads ___stack_chk_guard GOT pointer
            if let Some(guard_addr) = chk_guard_got {
                if insn_id == X86Insn::X86_INS_MOV && op.contains("rip") {
                    // capstone shows: "rax, qword ptr [rip + 0x...]"
                    // The RIP-relative address resolves to insn.address() + insn.len() + disp
                    // But we can check if the resolved address matches guard GOT
                    // by looking at the raw displacement in the operand
                    if let Some(target) = extract_rip_relative_target(insn) {
                        if target == guard_addr {
                            has_guard_load = true;
                        }
                    }
                }
            }

            // Detect CMP after guard load
            if has_guard_load {
                if insn_id == X86Insn::X86_INS_CMP {
                    has_guard_check = true;
                }
            }

            // Detect CALL ___stack_chk_fail
            if let Some(fail_addr) = chk_fail_addr {
                if insn_id == X86Insn::X86_INS_CALL {
                    let target = parse_x86_branch_target(op);
                    if target == fail_addr {
                        has_chk_fail = true;
                    }
                }
            }
        }

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
                    parts.push("call ___stack_chk_fail");
                }
                evidence.push(Evidence {
                    strategy: "instruction_scan".into(),
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

/// Extract the target address from a RIP-relative memory operand.
/// For `mov rax, qword ptr [rip + disp]`, the effective address is
/// instruction_address + instruction_length + displacement.
fn extract_rip_relative_target(insn: &capstone::Insn) -> Option<u64> {
    let bytes = insn.bytes();
    // x86_64 RIP-relative MOV: look for the 32-bit displacement
    // Common encoding: REX.W + 0x8B + ModR/M(00,reg,101) + disp32
    // ModR/M byte with mod=00, rm=101 indicates RIP-relative
    for (j, &b) in bytes.iter().enumerate() {
        if b == 0x8B && j + 5 <= bytes.len() {
            let modrm = bytes[j + 1];
            if modrm & 0xC7 == 0x05 {
                // mod=00, rm=101 (RIP-relative)
                let disp = i32::from_le_bytes([
                    bytes[j + 2],
                    bytes[j + 3],
                    bytes[j + 4],
                    bytes[j + 5],
                ]);
                let next_ip = insn.address() + insn.len() as u64;
                return Some(next_ip.wrapping_add(disp as i64 as u64));
            }
        }
    }
    None
}

// --- Helpers ---

fn find_prologue_end_x86(insns: &[&capstone::Insn]) -> usize {
    let mut end = 0;
    for (i, insn) in insns.iter().enumerate().take(8) {
        let mn = insn.mnemonic().unwrap_or("");
        let op = insn.op_str().unwrap_or("");
        if mn == "push" && op == "rbp" {
            end = i + 1;
        } else if mn == "mov" && op == "rbp, rsp" {
            end = i + 1;
        } else if mn == "sub" && op.starts_with("rsp,") {
            end = i + 1;
        }
    }
    end
}

fn parse_x86_branch_target(op_str: &str) -> u64 {
    let s = op_str.trim();
    if let Some(hex) = s.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).unwrap_or(0)
    } else {
        s.parse::<u64>().unwrap_or(0)
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
