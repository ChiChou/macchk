# Symbol Table Checks

Extracted from imported symbols (nlist entries with N_EXT && N_UNDF). Quick-level.

> **Note:** Symbol-based checks rely on the binary actually importing the relevant runtime functions. Stub binaries or binaries with minimal code may not import these symbols even when compiled with the corresponding security flags, since the compiler only emits them when the code requires it.

## Stack Canary

- **Symbols:** `___stack_chk_fail`, `___stack_chk_guard`
- **Impact:** Positive — compiler inserts stack canary checks (`-fstack-protector`)
- **Notes:** Presence of the import means at least one function has a canary. Does not guarantee all functions are protected. Use `-fstack-protector-all` for full coverage.

## ARC

- **Obj-C symbols:** `_objc_release`, `_objc_retain`, `_objc_autoreleasePoolPush`
- **Swift symbols:** `_swift_retain`, `_swift_release`, `_swift_allocObject`, `_swift_bridgeObjectRetain`, `_swift_bridgeObjectRelease`
- **Impact:** Positive — Automatic Reference Counting prevents use-after-free
- **Notes:** Detects both Obj-C and Swift ARC runtime usage.

## Swift Runtime

- **Symbols:** Prefixed with `_$s` (Swift mangling) or `_swift_`
- **Impact:** Informational — binary uses Swift runtime
- **Notes:** Swift provides memory safety by default (bounds checking, no dangling pointers).

## Typed Allocators

- **Symbols:** `_malloc_type_malloc`, `_malloc_type_calloc`, `_malloc_type_realloc`, `_malloc_type_valloc`, `_malloc_type_aligned_alloc`
- **Impact:** Positive — type-isolated allocation prevents type confusion exploitation
- **Build settings:** `CLANG_ENABLE_C_TYPED_ALLOCATOR_SUPPORT`, `CLANG_ENABLE_CPLUSPLUS_TYPED_ALLOCATOR_SUPPORT`
- **Compiler flag:** `-ftyped-memory-operations-experimental` (enables `__has_feature(typed_memory_operations)`)
- **Notes:** Each allocation site gets a 64-bit type hash. Memory for different types is isolated.

## AddressSanitizer

- **Symbols:** prefixed with `__asan_` (e.g. `___asan_init`, `___asan_report_load4`)
- **Impact:** Informational — binary is instrumented with ASan
- **Notes:** ASan is a debug/test tool for detecting memory errors (use-after-free, buffer overflow). Not typically shipped in production binaries due to performance overhead.

## UndefinedBehaviorSanitizer

- **Symbols:** prefixed with `__ubsan_` (e.g. `___ubsan_handle_add_overflow`)
- **Impact:** Informational — binary is instrumented with UBSan
- **Notes:** UBSan detects undefined behavior at runtime (integer overflow, null pointer dereference, etc.). Not typically shipped in production binaries.

## FORTIFY_SOURCE

- **Symbols:** `___strcpy_chk`, `___memcpy_chk`, `___snprintf_chk`, etc.
- **Impact:** Positive — buffer overflow detection in standard library functions
- **Compiler flag:** `-D_FORTIFY_SOURCE=2` or `-D_FORTIFY_SOURCE=3`
- **Notes:** Level 2 (standard) only protects buffers with constant sizes known at compile-time. Level 3 (modern) uses dynamic object size tracking to protect buffers whose sizes are determined at runtime. Only effective when optimization (`-O1` or higher) is enabled. May not appear if the compiler inlines the checks.
