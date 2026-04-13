# macchk

![AI Slop: YES](badge.svg)

Static security analysis for Mach-O binaries. Like [checksec](https://github.com/slimm609/checksec.sh), but for macOS/iOS.

Inspects executables, dylibs, and universal binaries for compiler hardening, code signing, entitlements, and instruction-level security features.

## Install

```
cargo install --path .
```

For x86_64 instruction analysis (requires Capstone):

```
cargo install --path . --features x86_64
```

x86_64 binaries are still recognized and checked at the header/symbol/codesign level without this feature. The feature flag only controls instruction-level pattern scanning (stack zero-init, libc++ hardening, bounds safety, stack canary patterns) which depends on the Capstone disassembly library.

## Usage

```
macchk /sbin/launchd
macchk --brief /usr/libexec/*
macchk --json /usr/bin/log
macchk -l full /sbin/launchd        # instruction-level coverage stats
macchk --arch arm64e /sbin/launchd   # single arch from universal binary
```

### Brief mode

```
$ macchk --brief /sbin/launchd /usr/libexec/amfid /usr/libexec/xpcproxy
/sbin/launchd: PIE arm64e CodeSign ChainedFixups Canary ARC Swift TypedAlloc FORTIFY SHA256+ LWCR PAC-Sec __DATA_CONST PAC-Insn ZeroInit BoundsSafe Canary-Insn | arm64e
/usr/libexec/amfid: PIE arm64e CodeSign ChainedFixups RESTRICT Canary ARC Swift TypedAlloc SHA256+ PAC-Sec __DATA_CONST PAC-Insn ZeroInit libc++ Canary-Insn | arm64e
/usr/libexec/xpcproxy: PIE arm64e CodeSign ChainedFixups Canary TypedAlloc Hardened SHA256+ LWCR PAC-Sec __DATA_CONST PAC-Insn ZeroInit Canary-Insn | arm64e
```

## Checks

### Detection Levels

| Level | Flag | What it does |
|-------|------|-------------|
| Quick | `-l quick` | Header flags, symbols, code signing |
| Standard | `-l standard` | + instruction pattern scanning (default) |
| Full | `-l full` | + per-function coverage statistics |

> **Note**: Instruction-level checks (PAC instructions, stack canary patterns, etc.) are based on pattern matching and may produce false positives or negatives.

### What it checks

**Mach-O Header**: PIE/ASLR, NX Heap, Executable Stack, App Extension Safe, CPU Subtype (arm64e)

**Load Commands**: Code Signature, Encryption, Chained Fixups, `__RESTRICT` segment, RPATH, `LC_DYLD_ENVIRONMENT`

**Symbol Table**: Stack Canary, Automatic Reference Counting (ARC), Swift Runtime, Typed Allocators, FORTIFY_SOURCE, AddressSanitizer, UBSan

**Code Signing**: Hardened Runtime, CS_RESTRICT, Library Validation, CS_HARD+KILL, Signing Type, CodeDirectory Hash Type (flags SHA-1 as weak), Launch Constraints (DER-decoded), Entitlements (classified as strengthens/weakens/info)

**Sections**: PAC markers, `__DATA_CONST`, `__PAGEZERO`, Segment Permissions

**Instructions**: PAC instructions, Stack Zero-Init (`-ftrivial-auto-var-init=zero`), libc++ Hardening, C Bounds Safety (`-fbounds-safety`), MTE instructions, Stack Canary patterns (resolves `___stack_chk_guard` GOT + `___stack_chk_fail` stub), Jump Table Hardening

## Output Formats

- **Table** (default): colored, grouped by category
- **Brief** (`--brief`): one-liner per architecture slice
- **JSON** (`--json`): machine-readable

## Building Test Fixtures

```
cd tests/fixtures
make
```

Then run the test suite:

```
cargo test
```

## License

MIT
