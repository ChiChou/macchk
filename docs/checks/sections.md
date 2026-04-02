# Section & Segment Checks

Extracted by iterating `macho.segments` and their sections. Quick-level.

## PAC Sections

- **Sections:** `__auth_stubs`, `__auth_got`, `__auth_ptr`
- **Impact:** Positive — binary uses pointer authentication for dynamic linking
- **Notes:** `__auth_stubs` replaces `__stubs` on arm64e. `__auth_got` replaces `__got`. Each pointer in these sections is PAC-signed.

## __DATA_CONST (RELRO Equivalent)

- **Segment:** `__DATA_CONST`
- **Impact:** Positive — data made read-only after dyld fixups
- **Notes:** The macOS equivalent of ELF RELRO. Contains GOT entries, ObjC metadata, and other pointers that are written once by dyld then made read-only. Prevents GOT overwrite attacks.

## __PAGEZERO

- **Segment:** `__PAGEZERO` (vmaddr=0, vmsize typically 0x100000000 on 64-bit)
- **Impact:** Positive — maps low memory as non-accessible, catching NULL dereferences
- **Notes:** Missing or zero-sized `__PAGEZERO` makes NULL dereference bugs exploitable. Dylibs and kexts legitimately lack this segment.

## Segment Permissions

- **Check:** rwx segments (initprot & 7 == 7)
- **Impact:** Negative if rwx found — violates W^X principle
- **Notes:** Reports all segment permissions for audit. Any segment with simultaneous write+execute is a security concern.
