# Architecture

## Overview

macchk performs static security analysis on Mach-O binaries. It extracts security metadata from six sources:

1. **Mach-O header** — flags and CPU subtype
2. **Load commands** — LC_CODE_SIGNATURE, LC_ENCRYPTION_INFO, LC_DYLD_CHAINED_FIXUPS, etc.
3. **Symbol table** — imported symbols indicating compiler features
4. **Code signature** — SuperBlob parsing for CS flags and entitlements
5. **Sections/segments** — names and permissions
6. **Instructions** — binary pattern matching for compiler-inserted security patterns

## Detection Levels

```
Quick     [A][B][C][D][E]         Headers, load commands, symbols, codesign, sections
Standard  [A][B][C][D][E][F*]     + instruction scan (first match, early return)
Full      [A][B][C][D][E][F**]    + instruction scan (all functions, coverage stats)
```

## Binary Format Support

- **Fat/universal binaries** — each architecture slice analyzed independently
- **Thin binaries** — single architecture analysis
- **Endianness** — big-endian Mach-O rejected (PPC legacy, not supported)
- **File types** — executables, dylibs, bundles, objects, kexts

## arm64 Instruction Detection

All arm64 detectors use raw binary pattern matching — no disassembly library needed.

**How it works:** arm64 instructions are fixed-width 4 bytes, little-endian, 4-byte aligned. Each detection target is expressed as `(mask, value)` pairs:

```
if instruction_word & MASK == VALUE { matched }
```

**Performance characteristics:**
- `to_words()` converts `&[u8]` to `&[u32]` once per slice
- `find_brk_sites()` does a linear scan that the compiler auto-vectorizes
- For brk-based patterns, we sweep the entire section first, then only verify near hits
- Function boundaries from LC_FUNCTION_STARTS (ULEB128 decoded) + symbol table

## x86_64 Instruction Detection

Uses capstone for x86_64 because instructions are variable-length (1-15 bytes). Pattern matching is not reliable without full decoding.

## Code Signature Parsing

Manual parsing of the SuperBlob structure (no external library):

```
LC_CODE_SIGNATURE → raw file offset
  → CS_SuperBlob (magic 0xfade0cc0, big-endian)
    → CS_BlobIndex array
      → Slot 0: CS_CodeDirectory → flags, hashType, platform, version, team_id
      → Slot 5: Entitlements → XML plist (magic 0xfade7171)
      → Slot 8-11: Launch/Library Constraints → DER-encoded (magic 0xfade8181)
      → Slot 0x10000: CMS signature → presence determines signing type
      → Slot 0x1000+: Alternative CodeDirectories (different hash algorithms)
```

All integers in the SuperBlob are big-endian (parsed with `scroll::BE`).

## Check Registration

Each check implements the `Check` trait:

```rust
pub trait Check {
    fn id(&self) -> CheckId;
    fn name(&self) -> &'static str;
    fn min_level(&self) -> DetectionLevel;
    fn category(&self) -> Category;
    fn polarity(&self) -> Polarity;
    fn run(&self, ctx: &AnalysisContext) -> CheckResult;
}
```

Checks are registered in `all_checks()` and filtered by `min_level <= user_level` at runtime. The `AnalysisContext` provides lazy-initialized shared state (codesign data, function boundaries).
