# Instruction-Level Checks

Requires Standard or Full detection level. arm64 uses raw binary pattern matching (no disassembly library needed). x86_64 uses capstone for variable-length instruction decoding.

## Detection Levels

| Level | Behavior | Use Case |
|-------|----------|----------|
| **Standard** | First match per feature, early return | Quick security assessment |
| **Full** | Scan all functions, produce coverage stats | Audit reports |

## PAC Instructions (arm64 only)

- **Build setting:** `ENABLE_POINTER_AUTHENTICATION`
- **Patterns:** `pacibsp` (`0xD503237F`), `paciasp` (`0xD503233F`), `retab` (`0xD65F0FFF`), `retaa` (`0xD65F0BFF`), `braaz`, `blraaz`, `braa`, `blraa`, `autiasp`, `autibsp`
- **Impact:** Positive — function prologues/returns are PAC-protected
- **Multi-strategy:** Also detected via CPU subtype (Quick) and section names (Quick)
- **Encoding:** All are fixed 32-bit encodings, matched as `(mask, value)` pairs

## Stack Zero-Init

- **Build setting:** `CLANG_ENABLE_STACK_ZERO_INIT`
- **Compiler flag:** `-ftrivial-auto-var-init=zero`
- **arm64 patterns (varies by buffer size):**
  - `movi Vd.2D, #0` + `stp Qd, Qd, [sp/fp]` — large buffers (32+ bytes, NEON)
  - `stp xzr, xzr, [sp/fp, #imm]` — medium (16 bytes)
  - `str xzr, [sp/fp, #imm]` / `str wzr, [sp/fp, #imm]` — small (4-8 bytes)
  - `stp wzr, wzr, [sp/fp, #imm]` — 8 bytes
- **x86_64 patterns:** `xorps xmmN, xmmN` + `movaps/movups [rsp/rbp], xmmN`
- **False positive risk:** Explicit `= {0}` initializers produce identical code. Mitigated by proximity-to-prologue heuristic.

## libc++ Hardening

- **Build setting:** `CLANG_CXX_STANDARD_LIBRARY_HARDENING` (Xcode), with defaults influenced by `ENABLE_CPLUSPLUS_BOUNDS_SAFE_BUFFERS` and `ENABLE_ENHANCED_SECURITY`
- **Compiler flag:** `-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_FAST`
- **arm64 pattern:** `cmp` + `b.{hs,hi,eq}` → `brk #0x1` (`0xD4200020`)
- **x86_64 pattern:** `cmp/test` + `jae/ja/je` → `ud2`
- **Notes:** The trap immediate `#0x1` is a libc++ convention. Fast mode is intended for production. Extensive and Debug modes add more checks but with higher performance overhead.

## C Bounds Safety

- **Build setting:** `ENABLE_C_BOUNDS_SAFETY`
- **Compiler flag:** `-fbounds-safety`
- **arm64 pattern:** `cmp/ccmp` + `b.{lo,hi}` → `brk #0x5519` (`0xD42AA320`)
- **x86_64 pattern:** `cmp/test` + `jb/ja` → `ud1`
- **Notes:** `#0x5519` is the bounds-safety-specific trap code chosen by clang. Per-access bounds checking using `__counted_by` annotations.

## MTE Instructions (arm64 only)

- **Instructions:** `irg`, `addg`, `subg`, `gmi`, `stg`, `stzg`, `st2g`, `stz2g`, `stgp`, `ldg`
- **Detection:** Raw binary pattern matching with full encoding masks (capstone may not recognize MTE on all hosts)
- **Notes:** Presence indicates the binary was compiled with `-march=armv8.5-a+memtag`. Requires hardware MTE support (Apple Silicon M-series with `com.apple.security.hardened-process.checked-allocations` entitlement).

## Jump Table Hardening (arm64 only) — experimental

- **Compiler flag:** `-faarch64-jump-table-hardening`
- **arm64 pattern:** `csel x16, x16, xzr, ls` (`0x9A9F9210`) followed by `br x16` (`0xD61F0200`)
- **Impact:** Positive — Spectre v1 mitigation for indirect branches via jump tables
- **Notes:** The hardened pattern clamps the jump table index using `csel` before the indirect branch, preventing speculative out-of-bounds reads. This detection is experimental — the heuristic matches a specific instruction sequence that may change across compiler versions or produce false positives in unrelated code that happens to use x16/x17 for conditional dispatch.

## Stack Canary (instruction-level)

- **arm64 detection:** Resolves `___stack_chk_guard` GOT address via indirect symbol table, then detects `ADRP+LDR` pairs computing that address, followed by `CMP` and `BL ___stack_chk_fail` (stub resolved from `__stubs`/`__auth_stubs`)
- **x86_64 detection:** Resolves `___stack_chk_guard` GOT address, detects `MOV reg, [RIP+disp]` loading the GOT pointer, followed by `CMP` and `CALL ___stack_chk_fail`
- **Impact:** Positive — per-function canary verification
- **Evidence:** Reports the detected chain, e.g. `load ___stack_chk_guard → cmp → bl ___stack_chk_fail`
- **Notes:** Complements the symbol-level check (Quick) with actual instruction verification (Standard). In Full mode, reports coverage: how many functions have canaries out of total scanned. Some functions show partial chains (e.g. `load → cmp` without the `bl`) when the fail call is in a shared trampoline outside the function boundary.
