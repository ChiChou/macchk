# Load Command Checks

Extracted by iterating `macho.load_commands`. Quick-level, no disassembly needed.

## Code Signature (LC_CODE_SIGNATURE)

- **Impact:** Positive — binary has embedded code signature
- **Detection:** Presence of `LC_CODE_SIGNATURE` load command
- **Notes:** We only check the presence but do not perform validation.

## Encryption (LC_ENCRYPTION_INFO_64)

- **Impact:** Informational — indicates FairPlay DRM or similar encryption
- **Detection:** `cryptid != 0` in the encryption info command
- **Notes:** Common for iOS App Store binaries. `cryptid == 0` means the segment is not currently encrypted.

## Chained Fixups (LC_DYLD_CHAINED_FIXUPS)

- **Impact:** Positive — modern pointer fixup format, enables PAC on fixups
- **Detection:** Presence of `LC_DYLD_CHAINED_FIXUPS` vs legacy `LC_DYLD_INFO_ONLY`
- **Notes:** Legacy format uses `lazy_bind_size > 0` which means writable PLT stubs at runtime — weaker than chained fixups where all pointers are resolved at load time. `weak_bind_size > 0` indicates overridable symbol bindings.

## __RESTRICT Segment

- **Impact:** Positive — blocks DYLD_* environment variable processing
- **Detection:** Segment named `__RESTRICT` with section `__restrict`
- **Notes:** When present, dyld ignores `DYLD_INSERT_LIBRARIES`, `DYLD_LIBRARY_PATH`, etc. This is a legacy mechanism; modern binaries use Hardened Runtime (`CS_RUNTIME`) or Library Validation (`CS_REQUIRE_LV`) instead.

## RPATH (LC_RPATH)

- **Impact:** Informational — specifies runtime library search paths
- **Detection:** Count of `LC_RPATH` load commands
- **Notes:** RPATHs can be a library hijacking vector if they point to writable directories.

## LC_DYLD_ENVIRONMENT

- **Impact:** Informational — embeds DYLD_* environment variables in the binary
- **Detection:** Presence of `LC_DYLD_ENVIRONMENT` load commands, with variable name extraction
- **Notes:** Can override library/framework search paths at the binary level. `DYLD_INSERT_LIBRARIES` cannot be injected this way (dyld rejects it). Disabled for binaries with `__RESTRICT` segment.
