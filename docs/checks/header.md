# Mach-O Header Checks

Extracted from `macho.header.flags` and `cpu_subtype`. These are the cheapest checks — single bitfield reads.

## PIE (ASLR)

- **Flag:** `MH_PIE` (`0x200000`)
- **Impact:** Positive — enables Address Space Layout Randomization
- **Detection:** `header.flags & MH_PIE != 0`
- **Notes:** All modern macOS/iOS executables should have this. Dylibs are always position-independent.

## NX Heap

- **Flag:** `MH_NO_HEAP_EXECUTION` (`0x1000000`)
- **Impact:** Positive — prevents execution of heap-allocated memory
- **Detection:** `header.flags & MH_NO_HEAP_EXECUTION != 0`
- **Notes:** Primarily enforced on i386. On arm64, heap is non-executable by default regardless of this flag.

## Executable Stack

- **Flag:** `MH_ALLOW_STACK_EXECUTION` (`0x20000`)
- **Impact:** Negative — allows stack pages to be executable
- **Detection:** `header.flags & MH_ALLOW_STACK_EXECUTION != 0`
- **Notes:** Should never be set in modern binaries. Enables classic stack buffer overflow exploitation.

## App Extension Safe

- **Flag:** `MH_APP_EXTENSION_SAFE` (`0x02000000`)
- **Impact:** Informational — indicates the binary is safe for App Extensions
- **Detection:** `header.flags & MH_APP_EXTENSION_SAFE != 0`

## CPU Subtype (arm64e)

- **Constant:** `CPU_SUBTYPE_ARM64_E` (`0x2`)
- **Impact:** Informational — arm64e enables pointer authentication at the ISA level
- **Detection:** `cpu_type == ARM64 && cpusubtype == 2`
- **Notes:** arm64e implies PAC hardware support. The binary was compiled with `-arch arm64e`.
