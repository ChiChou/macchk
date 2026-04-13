# Code Signing Checks

Extracted by parsing the `LC_CODE_SIGNATURE` SuperBlob (magic `0xfade0cc0`) from raw binary data. The CodeDirectory blob contains flags and metadata; the entitlements blob contains an XML plist.

## Hardened Runtime (CS_RUNTIME)

- **Flag:** `0x10000` in CodeDirectory flags
- **Impact:** Positive — enforces JIT/dyld restrictions, requires entitlements for exceptions
- **Notes:** With hardened runtime, the process cannot: map writable+executable memory, use DYLD_* env vars, or load unsigned dylibs — unless it has specific exception entitlements.

## CS Restrict (CS_RESTRICT)

- **Flag:** `0x800` in CodeDirectory flags
- **Impact:** Positive — dyld doesn't load unsigned/ad-hoc dylibs
- **Notes:** Runtime enforcement complement to __RESTRICT segment. Prevents dylib injection via env vars.

## Library Validation (CS_REQUIRE_LV)

- **Flag:** `0x2000` in CodeDirectory flags
- **Impact:** Positive — only loads dylibs signed by same team or Apple
- **Notes:** Prevents loading of third-party unsigned or differently-signed code.

## CS Hard + Kill

- **Flags:** `CS_HARD` (`0x100`) + `CS_KILL` (`0x200`)
- **Impact:** Positive — invalid pages kill the process (no fallback to unsigned)
- **Notes:** CS_HARD means no mapping of invalid pages. CS_KILL means kernel sends SIGKILL if signature becomes invalid at runtime.

## Signing Type

Classification based on CodeDirectory and CMS signature:

| Type | Description | Security Level |
|------|-------------|---------------|
| **Unsigned** | No LC_CODE_SIGNATURE | Lowest |
| **Linker-signed** | CS_LINKER_SIGNED flag, no real signature | Equivalent to unsigned |
| **Ad-hoc** | CodeDirectory but no CMS blob | Local/developer only |
| **Developer-signed** | CMS blob + team ID | Standard distribution |
| **Platform binary** | platform byte != 0 | Apple system binary |

## CodeDirectory Hash Type

- **Field:** `hashType` at offset 37 in CodeDirectory
- **Impact:** Positive — strong hash algorithms detected
- **Values:** 0=none, 1=SHA-1 (weak), 2=SHA-256, 3=SHA-256 (truncated 20 bytes), 4=SHA-384, 5=SHA-512
- **Notes:** Collects hash types from all CodeDirectories (primary + alternatives at slot 0x1000+). SHA-1-only signatures are flagged as weak. Modern binaries typically use SHA-256.

## Launch Constraints

- **Slots:** 8 (self), 9 (parent), 10 (responsible), 11 (library) in SuperBlob
- **Magic:** `0xfade8181`
- **Impact:** Info
- **Notes:** DER-encoded constraint dictionaries using Apple's CoreEntitlements format. Decoded to show constraint facts: `validation-category`, `signing-identifier`, `is-init-proc`, `developer-mode`, `$or`/`$and` operators, etc. Most Apple system binaries use trust cache constraints (kernel-side, not in the binary); only some embed constraints directly in the code signature.

## Entitlements

Extracted from CSSLOT_ENTITLEMENTS (slot 5, magic `0xfade7171`) as XML plist. Each entitlement is classified using the entitlements database. See [entitlements.md](../entitlements.md) for the full reference.
