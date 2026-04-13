pub mod arm64;
#[cfg(feature = "x86_64")]
pub mod x86_64;

use std::collections::HashMap;

use goblin::mach::load_command::CommandVariant;
use goblin::mach::MachO;

use crate::detection::{AnalysisContext, Check};
use crate::types::*;

/// Decode a ULEB128 value from a byte slice. Returns (value, bytes_consumed).
fn read_uleb128(data: &[u8]) -> (u64, usize) {
    let mut result: u64 = 0;
    let mut shift = 0;
    for (i, &byte) in data.iter().enumerate() {
        result |= ((byte & 0x7F) as u64) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return (result, i + 1);
        }
        if shift >= 64 {
            break;
        }
    }
    (result, 0) // malformed
}

/// Get __text section data and base address, skipping any encrypted regions.
///
/// When the binary has `cryptid != 0`, the encrypted file-offset range
/// (from LC_ENCRYPTION_INFO) contains ciphertext.  We convert the section's
/// file offset to determine overlap and either:
///   - return `None` if the section is fully encrypted, or
///   - trim the returned data to only include the unencrypted portion.
pub fn get_text_section<'a>(ctx: &'a AnalysisContext<'a>) -> Option<(Vec<u8>, u64)> {
    let macho = ctx.macho;
    for seg in &macho.segments {
        if let Ok(sections) = seg.sections() {
            for (sec, data) in sections {
                if sec.name().unwrap_or("") != "__text" {
                    continue;
                }

                // If the binary isn't encrypted, return the full section.
                let enc = match ctx.encrypted_range {
                    Some(ref r) => r,
                    None => return Some((data.to_vec(), sec.addr)),
                };

                let sec_file_start = sec.offset as u64;
                let sec_file_end = sec_file_start + sec.size;

                // No overlap with encrypted range — return as-is.
                if sec_file_end <= enc.start || sec_file_start >= enc.end {
                    return Some((data.to_vec(), sec.addr));
                }

                // Fully encrypted — skip instruction scanning entirely.
                if sec_file_start >= enc.start && sec_file_end <= enc.end {
                    return None;
                }

                // Partial overlap: return only the unencrypted tail/head.
                // In practice the encrypted range usually covers the entire
                // __TEXT segment, but handle partial for correctness.
                if sec_file_start < enc.start {
                    // Unencrypted prefix before the encrypted region.
                    let usable = (enc.start - sec_file_start) as usize;
                    return Some((data[..usable].to_vec(), sec.addr));
                } else {
                    // Unencrypted suffix after the encrypted region.
                    let skip = (enc.end - sec_file_start) as usize;
                    if skip < data.len() {
                        let new_base = sec.addr + skip as u64;
                        return Some((data[skip..].to_vec(), new_base));
                    }
                    return None;
                }
            }
        }
    }
    None
}

/// Compute function boundaries from LC_FUNCTION_STARTS + symbol table.
pub fn compute_function_boundaries(macho: &MachO, raw_bytes: &[u8]) -> Vec<(u64, u64)> {
    let (text_start, text_end) = match get_text_range(macho) {
        Some(v) => v,
        None => return vec![],
    };

    let mut starts = std::collections::BTreeSet::new();

    // From LC_FUNCTION_STARTS — decode ULEB128-encoded delta offsets
    for lc in &macho.load_commands {
        if let CommandVariant::FunctionStarts(ref fs) = lc.command {
            let data_off = fs.dataoff as usize;
            let data_sz = fs.datasize as usize;
            {
                let raw = raw_bytes;
                if data_off + data_sz <= raw.len() {
                    let func_data = &raw[data_off..data_off + data_sz];
                    let mut addr = text_start; // Function starts are relative to __TEXT segment
                    let mut pos = 0;
                    while pos < func_data.len() {
                        let (delta, bytes_read) = read_uleb128(&func_data[pos..]);
                        if bytes_read == 0 || delta == 0 {
                            break;
                        }
                        pos += bytes_read;
                        addr += delta;
                        if addr >= text_start && addr < text_end {
                            starts.insert(addr);
                        }
                    }
                }
            }
        }
    }

    // From symbol table
    if let Some(ref syms) = macho.symbols {
        for (_name, nlist) in syms.iter().flatten() {
            let addr = nlist.n_value;
            if addr >= text_start && addr < text_end && nlist.n_type & 0x0e != 0 {
                starts.insert(addr);
            }
        }
    }

    // Also try exports
    if let Ok(exports) = macho.exports() {
        for export in &exports {
            let addr = export.offset;
            if addr >= text_start && addr < text_end {
                starts.insert(addr);
            }
        }
    }

    if starts.is_empty() {
        return vec![(text_start, text_end)];
    }

    let sorted: Vec<u64> = starts.into_iter().collect();
    sorted
        .windows(2)
        .map(|w| (w[0], w[1]))
        .chain(std::iter::once((*sorted.last().unwrap(), text_end)))
        .collect()
}

fn get_text_range(macho: &MachO) -> Option<(u64, u64)> {
    for seg in &macho.segments {
        if let Ok(sections) = seg.sections() {
            for (sec, _) in &sections {
                if sec.name().unwrap_or("") == "__text" {
                    return Some((sec.addr, sec.addr + sec.size));
                }
            }
        }
    }
    None
}

fn get_symbol_name(macho: &MachO, addr: u64) -> String {
    if let Some(ref syms) = macho.symbols {
        for (name, nlist) in syms.iter().flatten() {
            if nlist.n_value == addr {
                return name.to_string();
            }
        }
    }
    format!("sub_{:x}", addr)
}

// Check implementations that delegate to arch-specific modules

pub struct PacInstructionsCheck;
impl Check for PacInstructionsCheck {
    fn id(&self) -> CheckId {
        CheckId::PacInstructions
    }
    fn name(&self) -> &'static str {
        "PAC Instructions"
    }
    fn min_level(&self) -> DetectionLevel {
        DetectionLevel::Standard
    }
    fn category(&self) -> Category {
        Category::Instructions
    }
    fn polarity(&self) -> Polarity {
        Polarity::Positive
    }
    fn run(&self, ctx: &AnalysisContext) -> CheckResult {
        if !ctx.is_arm64e() {
            return not_applicable(self.id(), self.name(), "arm64e only");
        }
        arm64::detect_pac_instructions(ctx, self.id(), self.name(), self.polarity())
    }
}

pub struct StackZeroInitCheck;
impl Check for StackZeroInitCheck {
    fn id(&self) -> CheckId {
        CheckId::StackZeroInit
    }
    fn name(&self) -> &'static str {
        "Stack Zero-Init"
    }
    fn min_level(&self) -> DetectionLevel {
        DetectionLevel::Standard
    }
    fn category(&self) -> Category {
        Category::Instructions
    }
    fn polarity(&self) -> Polarity {
        Polarity::Positive
    }
    fn run(&self, ctx: &AnalysisContext) -> CheckResult {
        if ctx.is_arm64() {
            arm64::detect_zeroinit(ctx, self.id(), self.name(), self.polarity())
        } else if cfg!(feature = "x86_64") && ctx.is_x86_64() {
            #[cfg(feature = "x86_64")]
            return x86_64::detect_zeroinit(ctx, self.id(), self.name(), self.polarity());
            #[cfg(not(feature = "x86_64"))]
            unreachable!()
        } else {
            not_applicable(self.id(), self.name(), "unsupported arch")
        }
    }
}

pub struct LibcppHardeningCheck;
impl Check for LibcppHardeningCheck {
    fn id(&self) -> CheckId {
        CheckId::LibcppHardening
    }
    fn name(&self) -> &'static str {
        "libc++ Hardening"
    }
    fn min_level(&self) -> DetectionLevel {
        DetectionLevel::Standard
    }
    fn category(&self) -> Category {
        Category::Instructions
    }
    fn polarity(&self) -> Polarity {
        Polarity::Positive
    }
    fn run(&self, ctx: &AnalysisContext) -> CheckResult {
        if ctx.is_arm64() {
            arm64::detect_libcpp_hardening(ctx, self.id(), self.name(), self.polarity())
        } else if cfg!(feature = "x86_64") && ctx.is_x86_64() {
            #[cfg(feature = "x86_64")]
            return x86_64::detect_libcpp_hardening(ctx, self.id(), self.name(), self.polarity());
            #[cfg(not(feature = "x86_64"))]
            unreachable!()
        } else {
            not_applicable(self.id(), self.name(), "unsupported arch")
        }
    }
}

pub struct BoundsSafetyCheck;
impl Check for BoundsSafetyCheck {
    fn id(&self) -> CheckId {
        CheckId::BoundsSafety
    }
    fn name(&self) -> &'static str {
        "C Bounds Safety"
    }
    fn min_level(&self) -> DetectionLevel {
        DetectionLevel::Standard
    }
    fn category(&self) -> Category {
        Category::Instructions
    }
    fn polarity(&self) -> Polarity {
        Polarity::Positive
    }
    fn run(&self, ctx: &AnalysisContext) -> CheckResult {
        if ctx.is_arm64() {
            arm64::detect_bounds_safety(ctx, self.id(), self.name(), self.polarity())
        } else if cfg!(feature = "x86_64") && ctx.is_x86_64() {
            #[cfg(feature = "x86_64")]
            return x86_64::detect_bounds_safety(ctx, self.id(), self.name(), self.polarity());
            #[cfg(not(feature = "x86_64"))]
            unreachable!()
        } else {
            not_applicable(self.id(), self.name(), "unsupported arch")
        }
    }
}

pub struct MteInstructionsCheck;
impl Check for MteInstructionsCheck {
    fn id(&self) -> CheckId {
        CheckId::MteInstructions
    }
    fn name(&self) -> &'static str {
        "MTE Instructions"
    }
    fn min_level(&self) -> DetectionLevel {
        DetectionLevel::Standard
    }
    fn category(&self) -> Category {
        Category::Instructions
    }
    fn polarity(&self) -> Polarity {
        Polarity::Positive
    }
    fn run(&self, ctx: &AnalysisContext) -> CheckResult {
        if !ctx.is_arm64e() {
            return not_applicable(self.id(), self.name(), "arm64e only");
        }
        arm64::detect_mte(ctx, self.id(), self.name(), self.polarity())
    }
}

/// Info about a section parsed from raw load commands, including reserved fields.
struct RawSectionInfo {
    addr: u64,
    size: u64,
    reserved1: u32, // indirect sym table index
    reserved2: u32, // stub size (for S_SYMBOL_STUBS)
}

// Section types from mach-o/loader.h
const S_NON_LAZY_SYMBOL_POINTERS: u8 = 0x06;
const S_SYMBOL_STUBS: u8 = 0x08;

/// Find a section by type from raw load commands.
/// Goblin's generalized Section doesn't expose reserved1/reserved2,
/// so we parse the raw section header from the load command data.
///
/// Matches both `__stubs`/`__auth_stubs` (type 0x08) and
/// `__got`/`__la_symbol_ptr` (type 0x06).
fn find_section_by_type(macho: &MachO, raw_bytes: &[u8], section_type: u8) -> Option<RawSectionInfo> {
    let is64 = macho.header.magic == 0xFEEDFACF || macho.header.magic == 0xCFFAEDFE;

    for lc in &macho.load_commands {
        let cmd = match lc.command {
            CommandVariant::Segment64(_) if is64 => true,
            CommandVariant::Segment32(_) if !is64 => true,
            _ => continue,
        };
        if !cmd {
            continue;
        }

        let lc_data = &raw_bytes[lc.offset..lc.offset + lc.command.cmdsize()];
        let (header_size, sec_size) = if is64 { (72, 80) } else { (56, 68) };
        if lc_data.len() < header_size {
            continue;
        }

        let nsects_off = if is64 { 64 } else { 48 };
        let nsects = u32::from_le_bytes([
            lc_data[nsects_off],
            lc_data[nsects_off + 1],
            lc_data[nsects_off + 2],
            lc_data[nsects_off + 3],
        ]) as usize;

        for i in 0..nsects {
            let sec_off = header_size + i * sec_size;
            if sec_off + sec_size > lc_data.len() {
                break;
            }
            let sec_data = &lc_data[sec_off..sec_off + sec_size];

            let flags_off = if is64 { 64 } else { 52 };
            let flags = u32::from_le_bytes([
                sec_data[flags_off],
                sec_data[flags_off + 1],
                sec_data[flags_off + 2],
                sec_data[flags_off + 3],
            ]);

            if flags & 0xFF != section_type as u32 {
                continue;
            }

            let (addr, size) = if is64 {
                (
                    u64::from_le_bytes(sec_data[32..40].try_into().ok()?),
                    u64::from_le_bytes(sec_data[40..48].try_into().ok()?),
                )
            } else {
                (
                    u32::from_le_bytes(sec_data[32..36].try_into().ok()?) as u64,
                    u32::from_le_bytes(sec_data[36..40].try_into().ok()?) as u64,
                )
            };

            let r1_off = if is64 { 68 } else { 56 };
            let reserved1 = u32::from_le_bytes([
                sec_data[r1_off],
                sec_data[r1_off + 1],
                sec_data[r1_off + 2],
                sec_data[r1_off + 3],
            ]);
            let reserved2 = u32::from_le_bytes([
                sec_data[r1_off + 4],
                sec_data[r1_off + 5],
                sec_data[r1_off + 6],
                sec_data[r1_off + 7],
            ]);

            return Some(RawSectionInfo {
                addr,
                size,
                reserved1,
                reserved2,
            });
        }
    }
    None
}

/// Resolve indirect-symbol-table-backed section entries to symbol names.
/// Works for both `__stubs`/`__auth_stubs` (S_SYMBOL_STUBS) and
/// `__got`/`__la_symbol_ptr` (S_NON_LAZY_SYMBOL_POINTERS).
fn resolve_indirect_section(
    macho: &MachO,
    raw_bytes: &[u8],
    section: &RawSectionInfo,
    entry_size: u64,
) -> HashMap<u64, String> {
    let mut result = HashMap::new();

    let (indsym_off, indsym_count) = macho
        .load_commands
        .iter()
        .find_map(|lc| {
            if let CommandVariant::Dysymtab(ref ds) = lc.command {
                Some((ds.indirectsymoff as usize, ds.nindirectsyms as usize))
            } else {
                None
            }
        })
        .unwrap_or((0, 0));

    if indsym_off == 0 || indsym_count == 0 || entry_size == 0 {
        return result;
    }

    let sym_names: Vec<String> = macho
        .symbols
        .as_ref()
        .map(|syms| {
            syms.iter()
                .map(|s| s.map(|(name, _)| name.to_string()).unwrap_or_default())
                .collect()
        })
        .unwrap_or_default();

    let num_entries = section.size / entry_size;
    for i in 0..num_entries as usize {
        let idx_pos = section.reserved1 as usize + i;
        if idx_pos >= indsym_count {
            break;
        }

        let file_off = indsym_off + idx_pos * 4;
        if file_off + 4 > raw_bytes.len() {
            break;
        }
        let sym_idx = u32::from_le_bytes([
            raw_bytes[file_off],
            raw_bytes[file_off + 1],
            raw_bytes[file_off + 2],
            raw_bytes[file_off + 3],
        ]) as usize;

        // Skip INDIRECT_SYMBOL_LOCAL (0x80000000) and INDIRECT_SYMBOL_ABS (0x40000000)
        if sym_idx >= 0x40000000 {
            continue;
        }
        if sym_idx < sym_names.len() {
            let addr = section.addr + (i as u64) * entry_size;
            result.insert(addr, sym_names[sym_idx].clone());
        }
    }

    result
}

/// Find the stub address for a given symbol name.
pub fn find_stub_for_symbol(macho: &MachO, raw_bytes: &[u8], target: &str) -> Option<u64> {
    let stubs = find_section_by_type(macho, raw_bytes, S_SYMBOL_STUBS)?;
    let stub_size = stubs.reserved2 as u64;
    if stub_size == 0 {
        return None;
    }
    let map = resolve_indirect_section(macho, raw_bytes, &stubs, stub_size);
    map.into_iter()
        .find(|(_, name)| name == target)
        .map(|(addr, _)| addr)
}

/// Find all sections matching a given type.
fn find_all_sections_by_type(macho: &MachO, raw_bytes: &[u8], section_type: u8) -> Vec<RawSectionInfo> {
    let is64 = macho.header.magic == 0xFEEDFACF || macho.header.magic == 0xCFFAEDFE;
    let mut result = Vec::new();

    for lc in &macho.load_commands {
        let cmd = match lc.command {
            CommandVariant::Segment64(_) if is64 => true,
            CommandVariant::Segment32(_) if !is64 => true,
            _ => continue,
        };
        if !cmd {
            continue;
        }

        let lc_data = match raw_bytes.get(lc.offset..lc.offset + lc.command.cmdsize()) {
            Some(d) => d,
            None => continue,
        };
        let (header_size, sec_size) = if is64 { (72, 80) } else { (56, 68) };
        if lc_data.len() < header_size {
            continue;
        }

        let nsects_off = if is64 { 64 } else { 48 };
        let nsects = u32::from_le_bytes([
            lc_data[nsects_off],
            lc_data[nsects_off + 1],
            lc_data[nsects_off + 2],
            lc_data[nsects_off + 3],
        ]) as usize;

        for i in 0..nsects {
            let sec_off = header_size + i * sec_size;
            if sec_off + sec_size > lc_data.len() {
                break;
            }
            let sec_data = &lc_data[sec_off..sec_off + sec_size];

            let flags_off = if is64 { 64 } else { 52 };
            let flags = u32::from_le_bytes([
                sec_data[flags_off],
                sec_data[flags_off + 1],
                sec_data[flags_off + 2],
                sec_data[flags_off + 3],
            ]);

            if flags & 0xFF != section_type as u32 {
                continue;
            }

            let (addr, size) = if is64 {
                let a = u64::from_le_bytes(sec_data[32..40].try_into().unwrap_or_default());
                let s = u64::from_le_bytes(sec_data[40..48].try_into().unwrap_or_default());
                (a, s)
            } else {
                let a = u32::from_le_bytes(sec_data[32..36].try_into().unwrap_or_default()) as u64;
                let s = u32::from_le_bytes(sec_data[36..40].try_into().unwrap_or_default()) as u64;
                (a, s)
            };

            let r1_off = if is64 { 68 } else { 56 };
            let reserved1 = u32::from_le_bytes([
                sec_data[r1_off],
                sec_data[r1_off + 1],
                sec_data[r1_off + 2],
                sec_data[r1_off + 3],
            ]);
            let reserved2 = u32::from_le_bytes([
                sec_data[r1_off + 4],
                sec_data[r1_off + 5],
                sec_data[r1_off + 6],
                sec_data[r1_off + 7],
            ]);

            result.push(RawSectionInfo {
                addr,
                size,
                reserved1,
                reserved2,
            });
        }
    }
    result
}

/// Find the GOT entry address for a given symbol name.
/// Searches all S_NON_LAZY_SYMBOL_POINTERS sections (__got and __auth_got).
pub fn find_got_for_symbol(macho: &MachO, raw_bytes: &[u8], target: &str) -> Option<u64> {
    let is64 = macho.header.magic == 0xFEEDFACF || macho.header.magic == 0xCFFAEDFE;
    let ptr_size: u64 = if is64 { 8 } else { 4 };
    let sections = find_all_sections_by_type(macho, raw_bytes, S_NON_LAZY_SYMBOL_POINTERS);
    for sec in &sections {
        let map = resolve_indirect_section(macho, raw_bytes, sec, ptr_size);
        if let Some((addr, _)) = map.into_iter().find(|(_, name)| name == target) {
            return Some(addr);
        }
    }
    None
}

pub struct JumpTableHardeningCheck;
impl Check for JumpTableHardeningCheck {
    fn id(&self) -> CheckId {
        CheckId::JumpTableHardening
    }
    fn name(&self) -> &'static str {
        "Jump Table Hardening"
    }
    fn min_level(&self) -> DetectionLevel {
        DetectionLevel::Standard
    }
    fn category(&self) -> Category {
        Category::Instructions
    }
    fn polarity(&self) -> Polarity {
        Polarity::Positive
    }
    fn run(&self, ctx: &AnalysisContext) -> CheckResult {
        if ctx.is_arm64() {
            arm64::detect_jump_table_hardening(ctx, self.id(), self.name(), self.polarity())
        } else {
            not_applicable(self.id(), self.name(), "arm64 only")
        }
    }
}

pub struct StackCanaryInsnCheck;
impl Check for StackCanaryInsnCheck {
    fn id(&self) -> CheckId {
        CheckId::StackCanaryInsn
    }
    fn name(&self) -> &'static str {
        "Stack Canary (insn)"
    }
    fn min_level(&self) -> DetectionLevel {
        DetectionLevel::Standard
    }
    fn category(&self) -> Category {
        Category::Instructions
    }
    fn polarity(&self) -> Polarity {
        Polarity::Positive
    }
    fn run(&self, ctx: &AnalysisContext) -> CheckResult {
        if ctx.is_arm64() {
            arm64::detect_stack_canary(ctx, self.id(), self.name(), self.polarity())
        } else if cfg!(feature = "x86_64") && ctx.is_x86_64() {
            #[cfg(feature = "x86_64")]
            return x86_64::detect_stack_canary(ctx, self.id(), self.name(), self.polarity());
            #[cfg(not(feature = "x86_64"))]
            unreachable!()
        } else {
            not_applicable(self.id(), self.name(), "unsupported arch")
        }
    }
}

fn not_applicable(id: CheckId, name: &'static str, reason: &str) -> CheckResult {
    CheckResult {
        id,
        name: name.into(),
        category: Category::Instructions,
        polarity: Polarity::Info,
        detected: false,
        evidence: vec![Evidence {
            strategy: "skip".into(),
            description: format!("skipped: {}", reason),
            confidence: Confidence::Definitive,
            address: None,
            function_name: None,
        }],
        stats: None,
    }
}
