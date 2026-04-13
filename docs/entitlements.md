# Entitlements Reference

Comprehensive database of security-relevant macOS/iOS entitlements. Sources: XNU kernel source (`kern_exec.c`, `mach_loader.c`, `cs_blobs.h`, `task.c`, `ipc_tt.c`), Apple Developer Documentation, and AMFI decompilation.

## Enhanced Security / Hardened Process

| Entitlement | Impact | Description |
|-------------|--------|-------------|
| `com.apple.security.hardened-process` | STRENGTHENS | Enables enhanced security / hardened process mode |
| `com.apple.developer.hardened-process` | STRENGTHENS | Developer variant of hardened process |
| `com.apple.security.hardened-process.hardened-heap` | STRENGTHENS | Type-aware memory allocations (requires `CLANG_ENABLE_C_TYPED_ALLOCATOR_SUPPORT` and `CLANG_ENABLE_CPLUSPLUS_TYPED_ALLOCATOR_SUPPORT` build settings) |
| `com.apple.security.hardened-process.dyld-ro` | STRENGTHENS | Read-only dyld memory (prevents runtime tampering) |
| `com.apple.security.hardened-process.checked-allocations` | STRENGTHENS | Hardware memory tagging (MTE) for allocations |
| `com.apple.security.hardened-process.platform-restrictions` | STRENGTHENS | Deprecated integer variant of platform restrictions (default: 2) |
| `com.apple.security.hardened-process.platform-restrictions-string` | STRENGTHENS | Platform restrictions — limits IPC and port access |
| `com.apple.security.hardened-process.enhanced-security-version` | STRENGTHENS | Enhanced security version for progressive hardening |
| `com.apple.security.hardened-process.enhanced-security-version-string` | STRENGTHENS | Deprecated string variant of above |

### Platform Restrictions

When `com.apple.security.hardened-process.platform-restrictions-string` (or its deprecated integer predecessor `platform-restrictions`, default: 2) is enabled, the kernel enforces runtime checks on Mach IPC and VM operations. Potentially insecure usage crashes the process with `EXC_GUARD` / `GUARD_TYPE_MACH_PORT`. The exception message identifies the violation:

| Exception Message | Meaning |
|---|---|
| `REQUIRE_REPLY_PORT_SEMANTICS` | Mach message reply port can be diverted — use XPC instead of raw Mach IPC traps |
| `KOBJECT_REPLY_PORT_SEMANTICS` | Kernel message reply port can be intercepted — use libSystem or kernel MIG interfaces |
| `OOL_PORT_ARRAY` | Insecure descriptor layout (OOL port arrays) in MIG/Mach IPC — use XPC or avoid port arrays |
| `THREAD_SET_STATE` | Insecure `thread_set_state` call — attacker could hijack control flow |
| `SET_EXCEPTION_BEHAVIOR` | Exception port uses insecure behavior (e.g. `EXCEPTION_DEFAULT`) that leaks task/thread ports — use `EXCEPTION_IDENTITY_PROTECTED` or `EXCEPTION_STATE` |
| `ILLEGAL_MOVE` | Send right to task/thread control port moved to another process — removes this escalation path |

These restrictions push adoption of higher-level IPC (XPC) over raw Mach traps, which are difficult to use securely.

### Hardware Memory Tagging (Checked Allocations)

These entitlements control ARM MTE (Memory Tagging Extension) for heap allocations. None are in open-source XNU — they are enforced by the allocator (libmalloc) and kernel memory subsystem.

| Entitlement | Impact | Description |
|-------------|--------|-------------|
| `com.apple.security.hardened-process.checked-allocations` | STRENGTHENS | Enables tagging of pointers and memory allocations with hardware MTE |
| `com.apple.security.hardened-process.checked-allocations.soft-mode` | STRENGTHENS | Soft mode — produces simulated crash reports on tag mismatches instead of terminating |
| `com.apple.security.hardened-process.checked-allocations.enable-pure-data` | STRENGTHENS | Also tags memory regions that contain only data (no pointers) |
| `com.apple.security.hardened-process.checked-allocations.no-tagged-receive` | STRENGTHENS | Prevents receiving tagged memory from other processes via IPC |

## Code Signing Exceptions

These entitlements weaken the hardened runtime by granting specific exceptions:

| Entitlement | Impact | Description |
|-------------|--------|-------------|
| `com.apple.security.cs.disable-library-validation` | WEAKENS | Disables library validation, allows unsigned dylibs |
| `com.apple.security.cs.allow-jit` | WEAKENS | Allows JIT code generation (MAP_JIT) |
| `com.apple.security.cs.single-jit` | WEAKENS | Allows single JIT code region |
| `com.apple.security.cs.allow-unsigned-executable-memory` | WEAKENS | Allows unsigned executable memory pages |
| `com.apple.security.cs.allow-dyld-environment-variables` | WEAKENS | Allows DYLD_* env vars (library injection vector) |
| `com.apple.security.cs.disable-executable-page-protection` | WEAKENS | Disables W^X executable page protection |
| `com.apple.security.cs.debugger` | INFO | Can act as debugger for other processes |
| `dynamic-codesigning` | WEAKENS | Allows dynamic code signing (JIT, self-modifying code) |

## Debugging & Task Control

| Entitlement | Impact | Description |
|-------------|--------|-------------|
| `com.apple.security.get-task-allow` | WEAKENS | Allows task_for_pid — process is debuggable. **Must be removed for production.** |
| `task_for_pid-allow` | INFO | Can call task_for_pid on other processes |
| `internal.com.apple.system-task-ports.control` | INFO | Internal control port access (Apple Internal only) |
| `com.apple.security.get-movable-control-port` | INFO | Can obtain movable control port for tasks |
| `com.apple.private.cs.debugger` | INFO | Can map pages with invalid code signatures in debugged processes |
| `com.apple.private.thread-set-state` | INFO | Can modify thread register state |
| `com.apple.private.set-exception-port` | INFO | Can set exception ports on tasks/threads |
| `com.apple.private.amfi.can-set-exception-ports` | INFO | Can set exception ports on tasks/threads, bypassing AMFI restrictions |
| `com.apple.private.host-exception-port-override` | INFO | Can override host exception port |
| `com.apple.private.delegate-signals` | INFO | Can delegate signals between processes |

## Library Validation

| Entitlement | Impact | Description |
|-------------|--------|-------------|
| `com.apple.private.security.clear-library-validation` | WEAKENS | Clears library validation via CS_OPS_CLEAR_LV |
| `com.apple.private.cs.automator-plugins` | WEAKENS | Permits loading untrusted automator plugins |
| `com.apple.private.amfi.can-allow-non-platform` | INFO | Can toggle system-wide allow-only-platform-code policy via AMFI sysctl |

## Sandbox

| Entitlement | Impact | Description |
|-------------|--------|-------------|
| `com.apple.security.app-sandbox` | STRENGTHENS | App Sandbox (restricts filesystem/network/IPC) |
| `com.apple.private.security.no-sandbox` | WEAKENS | Disables sandbox (DEBUG/DEVELOPMENT kernels only) |

### Temporary Exceptions

Sandbox temporary exceptions punch holes in an otherwise sandboxed app. These indicate the app needs broader access than the sandbox normally allows and should be reviewed for necessity.

| Entitlement | Impact | Description |
|-------------|--------|-------------|
| `com.apple.security.temporary-exception.apple-events` | WEAKENS | Send Apple events to other apps |
| `com.apple.security.temporary-exception.audio-unit-host` | WEAKENS | Host non-sandbox-safe audio components |
| `com.apple.security.temporary-exception.mach-lookup.global-name` | WEAKENS | Lookup global Mach services |
| `com.apple.security.temporary-exception.mach-register.global-name` | WEAKENS | Register global Mach services |
| `com.apple.security.temporary-exception.files.home-relative-path.read-only` | WEAKENS | Read files in home directory |
| `com.apple.security.temporary-exception.files.home-relative-path.read-write` | WEAKENS | Read/write files in home directory |
| `com.apple.security.temporary-exception.files.absolute-path.read-only` | WEAKENS | Read files at absolute paths |
| `com.apple.security.temporary-exception.files.absolute-path.read-write` | WEAKENS | Read/write files at absolute paths |
| `com.apple.security.temporary-exception.iokit-user-client-class` | WEAKENS | Access additional IOUserClient subclasses |
| `com.apple.security.temporary-exception.shared-preference.read-only` | WEAKENS | Read shared preference domains |
| `com.apple.security.temporary-exception.shared-preference.read-write` | WEAKENS | Read/write shared preference domains |

## Pointer Authentication (PAC)

| Entitlement | Impact | Description |
|-------------|--------|-------------|
| `com.apple.private.pac.exception` | STRENGTHENS | Enables all PAC exception hardening (fatal PAC faults) |
| `com.apple.private.skip.pac.exception` | WEAKENS | Allows non-fatal PAC exceptions (weakens PAC enforcement) |
| `com.apple.pac.shared_region_id` | STRENGTHENS | Per-group JOP key diversification. See detailed explanation below. |

### How `com.apple.pac.shared_region_id` works

The kernel isolates PAC keys (specifically the A-keys for JOP protection) and shared cache mappings for security-sensitive processes. The mapping from a `shared_region_id` string to a random 64-bit JOP key (`srp_jop_key`) is managed in `osfmk/vm/vm_shared_region_pager.c`. 

When a process starts, `bsd/kern/kern_exec.c` determines which shared region group it belongs to, in priority order:

1. **WebContent entitlement** (`BrowserWebContentEntitlementMask`) → ID = `"C-"` — browser sandbox processes
2. **Inherited** from parent task (fork/posix_spawn)
3. **Team ID** → ID = `"T-<teamid>"` (if `vm_shared_region_per_team_id` sysctl is enabled)
4. **This entitlement** → ID = `"E-<entitlement_value>"` (if `vm_shared_region_by_entitlement` sysctl is enabled)
5. **Default** → ID = `""` — all processes without classification share one global key

Each unique ID gets a distinct random key via `generate_jop_key()`. The dyld shared cache pages are mapped and re-signed with this key when loaded into the process's address space. This ensures that a PAC-signed pointer (JOP gadget) from one group is invalid in another, effectively sandboxing the PAC environment against cross-process code reuse attacks.

**Security effect:** Two processes with the entitlement `com.apple.pac.shared_region_id=foo` would share A keys and shared regions with each other, but not with other system processes. This is a critical mitigation against cross-process code reuse attacks in sandboxed architectures. Its presence indicates Apple considers the process security-critical enough to warrant isolated pointer signing.

## Exception Handling

| Entitlement | Impact | Description |
|-------------|--------|-------------|
| `com.apple.security.fatal-exceptions` | STRENGTHENS | Makes specified exception types fatal (SIGKILL) |
| `com.apple.security.only-one-exception-port` | STRENGTHENS | Restricts to single exception port per task |

## Trust Cache

| Entitlement | Impact | Description |
|-------------|--------|-------------|
| `com.apple.private.unload-trust-cache` | INFO | Can unload trust caches |
| `com.apple.private.pmap.load-trust-cache` | INFO | Can load trust caches into pmap |

## Diagnostics & Coredump

| Entitlement | Impact | Description |
|-------------|--------|-------------|
| `com.apple.private.enable-coredump-on-panic` | INFO | Triggers userspace coredump on kernel panic |
| `com.apple.private.custom-coredump-location` | INFO | Custom coredump file path |
| `com.apple.private.coredump-encryption-key` | INFO | Provides coredump encryption capability |

## Kernel & System Access

| Entitlement | Impact | Description |
|-------------|--------|-------------|
| `com.apple.private.ktrace-allow` | INFO | Can perform kernel tracing |
| `com.apple.private.stackshot` | INFO | Can capture kernel stackshots |
| `com.apple.private.read-environment-variables` | INFO | Can read other processes' environment variables via sysctl |
| `com.apple.private.task_policy` | INFO | Can modify task policy settings |
| `com.apple.private.spawn-subsystem-root` | INFO | Can spawn with subsystem root capabilities |
