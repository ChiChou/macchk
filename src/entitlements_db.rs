//! Comprehensive database of security-relevant macOS/iOS entitlements.
//!
//! Classification:
//!   STRENGTHENS — entitlement enables additional security protections on this process
//!   WEAKENS     — entitlement disables or bypasses a security protection on this process
//!   INFO        — grants a capability; does not change the process's security posture
//!
//! Each entry is verified against XNU or dyld source where possible.
//! Entries marked "AMFI-enforced" are processed by Apple Mobile File Integrity
//! (closed source kext) — the entitlement string appears in test plists and
//! man pages but not in XNU/dyld enforcement code.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Impact {
    Strengthens,
    Weakens,
    Info,
}

pub struct EntitlementInfo {
    pub key: &'static str,
    pub impact: Impact,
    pub short_desc: &'static str,
    pub category: &'static str,
}

pub fn lookup(key: &str) -> Option<&'static EntitlementInfo> {
    ENTITLEMENTS.iter().find(|e| e.key == key)
}

pub fn classify(key: &str) -> Option<(Impact, &'static str)> {
    lookup(key).map(|info| (info.impact, info.short_desc))
}

pub static ENTITLEMENTS: &[EntitlementInfo] = &[

    // ═══════════════════════════════════════════════════════════════════
    // STRENGTHENS — enables additional protections on this process
    // ═══════════════════════════════════════════════════════════════════

    // ── Enhanced Security ──────────────────────────────────────────────

    EntitlementInfo {
        key: "com.apple.security.hardened-process",
        impact: Impact::Strengthens,
        short_desc: "enables hardened process mode",
        category: "enhanced_security",
    },
    EntitlementInfo {
        key: "com.apple.developer.hardened-process",
        impact: Impact::Strengthens,
        short_desc: "enables hardened process mode (developer variant)",
        category: "enhanced_security",
    },
    EntitlementInfo {
        key: "com.apple.security.hardened-process.hardened-heap",
        impact: Impact::Strengthens,
        short_desc: "type-aware hardened heap allocator with integrity checks",
        category: "enhanced_security",
    },
    EntitlementInfo {
        key: "com.apple.developer.hardened-process.hardened-heap",
        impact: Impact::Strengthens,
        short_desc: "type-aware hardened heap allocator (developer variant)",
        category: "enhanced_security",
    },
    EntitlementInfo {
        key: "com.apple.security.hardened-process.dyld-ro",
        impact: Impact::Strengthens,
        // TPRO marks dyld internal state as read-only after initialization.
        short_desc: "read-only dyld memory via TPRO, prevents runtime tampering",
        category: "enhanced_security",
    },
    EntitlementInfo {
        key: "com.apple.security.hardened-process.platform-restrictions",
        impact: Impact::Strengthens,
        // Integer value; opts into IPC restrictions. Auto-set for hardened browsers.
        short_desc: "platform restrictions on IPC and port access",
        category: "enhanced_security",
    },
    EntitlementInfo {
        key: "com.apple.security.hardened-process.enhanced-security-version",
        impact: Impact::Strengthens,
        // Integer stored in 3 bits via task_set_hardened_process_version().
        short_desc: "enhanced security version for progressive hardening",
        category: "enhanced_security",
    },

    // ── Checked Allocations (MTE / Hardware Memory Tagging) ────────────

    EntitlementInfo {
        key: "com.apple.security.hardened-process.checked-allocations",
        impact: Impact::Strengthens,
        short_desc: "enables hardware memory tagging (MTE) for heap allocations",
        category: "enhanced_security",
    },
    EntitlementInfo {
        key: "com.apple.security.hardened-process.checked-allocations.soft-mode",
        impact: Impact::Strengthens,
        // Produces simulated crash reports on tag mismatches instead of terminating.
        short_desc: "MTE soft mode — simulated crashes on tag mismatches instead of terminating",
        category: "enhanced_security",
    },
    EntitlementInfo {
        key: "com.apple.security.hardened-process.checked-allocations.enable-pure-data",
        impact: Impact::Strengthens,
        short_desc: "extends MTE tagging to memory containing only data (no pointers)",
        category: "enhanced_security",
    },
    EntitlementInfo {
        key: "com.apple.security.hardened-process.checked-allocations.no-tagged-receive",
        impact: Impact::Strengthens,
        short_desc: "prevents receiving tagged memory from other processes via IPC",
        category: "enhanced_security",
    },

    // ── Containment ─────────────────────────────────────────────────────

    EntitlementInfo {
        key: "com.apple.security.hardened-process.containment.ipc",
        impact: Impact::Strengthens,
        // Undocumented. Found on system binaries. Naming pattern suggests
        // IPC containment — restricts the process's IPC surface.
        short_desc: "IPC containment, undocumented, details unknown",
        category: "enhanced_security",
    },

    // ── Deprecated enhanced security variants ──────────────────────────

    EntitlementInfo {
        key: "com.apple.security.hardened-process.enhanced-security-version-string",
        impact: Impact::Strengthens,
        short_desc: "enhanced security version (deprecated string variant)",
        category: "enhanced_security",
    },
    EntitlementInfo {
        key: "com.apple.security.hardened-process.platform-restrictions-string",
        impact: Impact::Strengthens,
        short_desc: "platform restrictions (deprecated string variant)",
        category: "enhanced_security",
    },

    // ── Sandbox ────────────────────────────────────────────────────────

    EntitlementInfo {
        key: "com.apple.security.app-sandbox",
        impact: Impact::Strengthens,
        short_desc: "App Sandbox enabled — restricts filesystem, network, and IPC",
        category: "sandbox",
    },

    // ── PAC ────────────────────────────────────────────────────────────

    EntitlementInfo {
        key: "com.apple.private.pac.exception",
        impact: Impact::Strengthens,
        // Enables fatal PAC exceptions + signed user state enforcement.
        short_desc: "enforces fatal PAC exceptions and signed user state",
        category: "pac",
    },
    EntitlementInfo {
        key: "com.apple.pac.shared_region_id",
        impact: Impact::Strengthens,
        // Each unique ID gets a random JOP key. PAC-signed shared cache
        // pointers from one group are invalid in another, defeating
        // cross-process JOP gadget reuse (e.g. Safari WebContent vs UI).
        short_desc: "per-group JOP key diversification — isolates PAC-signed shared cache pointers between processes",
        category: "pac",
    },

    // ── Exception Handling ─────────────────────────────────────────────

    EntitlementInfo {
        key: "com.apple.security.fatal-exceptions",
        impact: Impact::Strengthens,
        // String value (e.g. "jit") makes specified exception types deliver SIGKILL.
        short_desc: "makes specified exceptions fatal (SIGKILL instead of SIGSEGV)",
        category: "exceptions",
    },
    EntitlementInfo {
        key: "com.apple.security.only-one-exception-port",
        impact: Impact::Strengthens,
        // Disallows set_exception_ports unless being debugged.
        short_desc: "restricts to single exception port per task",
        category: "exceptions",
    },

    // ═══════════════════════════════════════════════════════════════════
    // WEAKENS — disables or bypasses a security protection on this process
    // ═══════════════════════════════════════════════════════════════════

    // ── Code Signing Exceptions ────────────────────────────────────────

    EntitlementInfo {
        key: "com.apple.security.cs.disable-library-validation",
        impact: Impact::Weakens,
        short_desc: "disables library validation — allows loading unsigned dylibs",
        category: "cs_exception",
    },
    EntitlementInfo {
        key: "com.apple.security.cs.allow-jit",
        impact: Impact::Weakens,
        short_desc: "allows MAP_JIT for JIT compilation",
        category: "cs_exception",
    },
    EntitlementInfo {
        key: "com.apple.security.cs.single-jit",
        impact: Impact::Weakens,
        short_desc: "allows single JIT code region",
        category: "cs_exception",
    },
    EntitlementInfo {
        key: "com.apple.security.cs.allow-unsigned-executable-memory",
        impact: Impact::Weakens,
        short_desc: "allows unsigned W+X memory pages",
        category: "cs_exception",
    },
    EntitlementInfo {
        key: "com.apple.security.cs.allow-dyld-environment-variables",
        impact: Impact::Weakens,
        // AMFI translates to AMFI_DYLD_OUTPUT_ALLOW_PATH_VARS for dyld.
        short_desc: "allows DYLD_* environment variables — library path injection vector",
        category: "cs_exception",
    },
    EntitlementInfo {
        key: "com.apple.security.cs.allow-relative-library-loads",
        impact: Impact::Weakens,
        // Allows @loader_path/@executable_path-relative dylib loads without
        // requiring the dylib to be in a standard location or signed by the
        // same team. Enables dylib proxying / hijacking via relative paths.
        short_desc: "allows relative @loader_path/@executable_path dylib loads — dylib hijack vector",
        category: "cs_exception",
    },
    EntitlementInfo {
        key: "com.apple.security.cs.disable-executable-page-protection",
        impact: Impact::Weakens,
        short_desc: "disables W^X page protection",
        category: "cs_exception",
    },
    EntitlementInfo {
        key: "com.apple.security.cs.jit-write-allowlist",
        impact: Impact::Weakens,
        // Enables JIT callback allowlists via pthread_jit_write_with_callback_np().
        // Replaces pthread_jit_write_protect_np() which becomes uncallable.
        // More restrictive than allow-jit: only allowlisted callbacks can write to JIT memory.
        short_desc: "enables JIT callback allowlists via pthread_jit_write_with_callback_np",
        category: "cs_exception",
    },
    EntitlementInfo {
        key: "com.apple.security.cs.jit-write-allowlist-freeze-late",
        impact: Impact::Weakens,
        // Allows dynamic library callbacks to be added to JIT allowlists at
        // runtime before freezing with pthread_jit_write_freeze_callbacks_np().
        short_desc: "allows late-freezing of JIT callback allowlists for dynamic libraries",
        category: "cs_exception",
    },
    EntitlementInfo {
        key: "dynamic-codesigning",
        impact: Impact::Weakens,
        short_desc: "allows dynamic code signing at runtime",
        category: "cs_exception",
    },

    // ── Debugging (weakens THIS process) ───────────────────────────────

    EntitlementInfo {
        key: "com.apple.security.get-task-allow",
        impact: Impact::Weakens,
        // Sets CS_GET_TASK_ALLOW flag; makes this process debuggable.
        short_desc: "makes process debuggable via task_for_pid",
        category: "debugging",
    },
    EntitlementInfo {
        key: "get-task-allow",
        impact: Impact::Weakens,
        // Short form of com.apple.security.get-task-allow, same effect.
        short_desc: "makes process debuggable via task_for_pid",
        category: "debugging",
    },

    // ── Library Validation ─────────────────────────────────────────────

    EntitlementInfo {
        key: "com.apple.private.security.clear-library-validation",
        impact: Impact::Weakens,
        short_desc: "clears library validation at runtime via CS_OPS_CLEAR_LV",
        category: "library_validation",
    },
    EntitlementInfo {
        key: "com.apple.private.cs.automator-plugins",
        impact: Impact::Weakens,
        short_desc: "disables library validation for automator plugin hosting",
        category: "library_validation",
    },
    EntitlementInfo {
        key: "com.apple.private.amfi.can-allow-non-platform",
        impact: Impact::Info,
        // Grants ability to write the amfi.allow-only-platform-code sysctl.
        // Requires root. Changes system-wide policy, does not weaken the holder.
        short_desc: "can toggle system-wide allow-only-platform-code policy via AMFI sysctl",
        category: "amfi",
    },
    EntitlementInfo {
        key: "com.apple.private.cs.debugger",
        impact: Impact::Weakens,
        // Allows mapping pages with invalid code signatures in this process.
        short_desc: "allows mapping pages with invalid code signatures",
        category: "debugging",
    },
    EntitlementInfo {
        key: "com.apple.private.skip.pac.exception",
        impact: Impact::Weakens,
        short_desc: "allows non-fatal PAC exceptions on non-FPAC hardware",
        category: "pac",
    },
    EntitlementInfo {
        key: "com.apple.private.security.no-sandbox",
        impact: Impact::Weakens,
        // Only effective on DEBUG/DEVELOPMENT kernels.
        short_desc: "disables sandbox (DEBUG/DEVELOPMENT kernels only)",
        category: "sandbox",
    },

    // ── Sandbox Temporary Exceptions ──────────────────────────────────

    EntitlementInfo {
        key: "com.apple.security.temporary-exception.apple-events",
        impact: Impact::Weakens,
        short_desc: "sandbox exception: send Apple events to other apps",
        category: "sandbox_exception",
    },
    EntitlementInfo {
        key: "com.apple.security.temporary-exception.audio-unit-host",
        impact: Impact::Weakens,
        short_desc: "sandbox exception: host non-sandbox-safe audio components",
        category: "sandbox_exception",
    },
    EntitlementInfo {
        key: "com.apple.security.temporary-exception.mach-lookup.global-name",
        impact: Impact::Weakens,
        short_desc: "sandbox exception: lookup global Mach services",
        category: "sandbox_exception",
    },
    EntitlementInfo {
        key: "com.apple.security.temporary-exception.mach-register.global-name",
        impact: Impact::Weakens,
        short_desc: "sandbox exception: register global Mach services",
        category: "sandbox_exception",
    },
    EntitlementInfo {
        key: "com.apple.security.temporary-exception.files.home-relative-path.read-only",
        impact: Impact::Weakens,
        short_desc: "sandbox exception: read files in home directory",
        category: "sandbox_exception",
    },
    EntitlementInfo {
        key: "com.apple.security.temporary-exception.files.home-relative-path.read-write",
        impact: Impact::Weakens,
        short_desc: "sandbox exception: read/write files in home directory",
        category: "sandbox_exception",
    },
    EntitlementInfo {
        key: "com.apple.security.temporary-exception.files.absolute-path.read-only",
        impact: Impact::Weakens,
        short_desc: "sandbox exception: read files at absolute paths",
        category: "sandbox_exception",
    },
    EntitlementInfo {
        key: "com.apple.security.temporary-exception.files.absolute-path.read-write",
        impact: Impact::Weakens,
        short_desc: "sandbox exception: read/write files at absolute paths",
        category: "sandbox_exception",
    },
    EntitlementInfo {
        key: "com.apple.security.temporary-exception.iokit-user-client-class",
        impact: Impact::Weakens,
        short_desc: "sandbox exception: access additional IOUserClient subclasses",
        category: "sandbox_exception",
    },
    EntitlementInfo {
        key: "com.apple.security.temporary-exception.shared-preference.read-only",
        impact: Impact::Weakens,
        short_desc: "sandbox exception: read shared preference domains",
        category: "sandbox_exception",
    },
    EntitlementInfo {
        key: "com.apple.security.temporary-exception.shared-preference.read-write",
        impact: Impact::Weakens,
        short_desc: "sandbox exception: read/write shared preference domains",
        category: "sandbox_exception",
    },

    // ═══════════════════════════════════════════════════════════════════
    // INFO — grants capabilities; doesn't change this process's security
    // ═══════════════════════════════════════════════════════════════════

    EntitlementInfo {
        key: "com.apple.security.cs.debugger",
        impact: Impact::Info,
        short_desc: "can act as debugger for other processes",
        category: "debugging",
    },
    EntitlementInfo {
        key: "task_for_pid-allow",
        impact: Impact::Info,
        short_desc: "can call task_for_pid on other processes",
        category: "debugging",
    },
    EntitlementInfo {
        key: "com.apple.private.set-exception-port",
        impact: Impact::Info,
        short_desc: "can set exception ports on tasks/threads",
        category: "debugging",
    },
    EntitlementInfo {
        key: "com.apple.system-task-ports.token.control",
        impact: Impact::Info,
        short_desc: "can obtain control port tokens for system tasks",
        category: "debugging",
    },
    EntitlementInfo {
        key: "com.apple.private.thread-set-state",
        impact: Impact::Info,
        short_desc: "can modify thread register state",
        category: "debugging",
    },
    EntitlementInfo {
        key: "com.apple.private.delegate-signals",
        impact: Impact::Info,
        short_desc: "can delegate signals between processes",
        category: "debugging",
    },
    EntitlementInfo {
        key: "com.apple.private.settime",
        impact: Impact::Info,
        // Bypasses root + MAC check for settimeofday/ntp_adjtime.
        short_desc: "can set system time via settimeofday/ntp_adjtime",
        category: "kernel",
    },
    EntitlementInfo {
        key: "com.apple.private.ktrace-allow",
        impact: Impact::Info,
        short_desc: "can perform kernel tracing",
        category: "kernel",
    },
    EntitlementInfo {
        key: "com.apple.private.stackshot",
        impact: Impact::Info,
        short_desc: "can capture kernel stackshots",
        category: "kernel",
    },
    EntitlementInfo {
        key: "com.apple.private.read-environment-variables",
        impact: Impact::Info,
        short_desc: "can read other processes' environment variables via sysctl",
        category: "kernel",
    },
    EntitlementInfo {
        key: "com.apple.private.spawn-subsystem-root",
        impact: Impact::Info,
        short_desc: "can spawn with subsystem root capabilities",
        category: "kernel",
    },
    EntitlementInfo {
        key: "com.apple.private.iokit.system-nvram-allow",
        impact: Impact::Info,
        short_desc: "can access system NVRAM",
        category: "kernel",
    },
    EntitlementInfo {
        key: "com.apple.private.unload-trust-cache",
        impact: Impact::Info,
        short_desc: "can unload trust caches",
        category: "trust_cache",
    },
    EntitlementInfo {
        key: "com.apple.private.pmap.load-trust-cache",
        impact: Impact::Info,
        short_desc: "can load trust caches into pmap",
        category: "trust_cache",
    },
    EntitlementInfo {
        key: "com.apple.private.enable-coredump-on-panic",
        impact: Impact::Info,
        short_desc: "triggers userspace coredump on kernel panic",
        category: "diagnostics",
    },
    EntitlementInfo {
        key: "com.apple.private.custom-coredump-location",
        impact: Impact::Info,
        short_desc: "custom coredump file path",
        category: "diagnostics",
    },
    EntitlementInfo {
        key: "com.apple.private.coredump-encryption-key",
        impact: Impact::Info,
        short_desc: "coredump encryption capability",
        category: "diagnostics",
    },
    EntitlementInfo {
        key: "com.apple.developer.kernel.extended-virtual-addressing",
        impact: Impact::Info,
        short_desc: "extended virtual address space",
        category: "memory",
    },
    EntitlementInfo {
        key: "com.apple.developer.kernel.increased-memory-limit",
        impact: Impact::Info,
        short_desc: "increased memory footprint limit",
        category: "memory",
    },
    EntitlementInfo {
        key: "com.apple.private.persona-mgmt",
        impact: Impact::Info,
        short_desc: "can manage personas",
        category: "process_control",
    },
    EntitlementInfo {
        key: "com.apple.private.memorystatus",
        impact: Impact::Info,
        short_desc: "privileged memorystatus/jetsam operations",
        category: "memory",
    },
    EntitlementInfo {
        key: "com.apple.private.vfs.open-by-id",
        impact: Impact::Info,
        short_desc: "can open files by inode ID",
        category: "filesystem",
    },

    // ── Code Signing (allow-in-chroot) ────────────────────────────────

    EntitlementInfo {
        key: "com.apple.security.cs.allow-in-chroot",
        impact: Impact::Weakens,
        // Checked in _cred_label_update_execve. Without this, code signed
        // binaries are blocked from executing inside a chroot.
        short_desc: "allows code-signed binary execution inside a chroot environment",
        category: "cs_exception",
    },

    // ── OOP-JIT ───────────────────────────────────────────────────────

    EntitlementInfo {
        key: "com.apple.private.oop-jit.runner",
        impact: Impact::Weakens,
        // Marks this process as an OOP-JIT runner — it may receive and map
        // unsigned JIT code pages produced by a paired loader process.
        // Checked during library validation; non-platform binaries are rejected.
        short_desc: "OOP-JIT runner — may map unsigned JIT code from a paired loader",
        category: "cs_exception",
    },
    EntitlementInfo {
        key: "com.apple.private.oop-jit.loader",
        impact: Impact::Weakens,
        // String value names the OOP-JIT type this process can load.
        // _validateOOPJit verifies the loader's entitlement matches the
        // code directory's linkage type before allowing the JIT signature.
        short_desc: "OOP-JIT loader — may load OOP-JIT signed code into runner processes",
        category: "cs_exception",
    },

    // ── Core Dump Policy ──────────────────────────────────────────────

    EntitlementInfo {
        key: "com.apple.security.allow-coredump",
        impact: Impact::Weakens,
        // Checked in core_dump_policy. Allows core dumps even when SIP
        // restricts them (csr_check(CSR_ALLOW_UNRESTRICTED_DTRACE)).
        short_desc: "allows core dumps when SIP is enabled",
        category: "diagnostics",
    },

    // ── Developer JIT variant ─────────────────────────────────────────

    EntitlementInfo {
        key: "com.apple.developer.cs.allow-jit",
        impact: Impact::Weakens,
        // Developer-prefixed variant of allow-jit. Validated in profile
        // validation and vnode signature checks alongside the security variant.
        short_desc: "allows MAP_JIT for JIT compilation (developer variant)",
        category: "cs_exception",
    },

    // ── AMFI Exception Ports ──────────────────────────────────────────

    EntitlementInfo {
        key: "com.apple.private.amfi.can-set-exception-ports",
        impact: Impact::Weakens,
        // Checked in amfi_exc_action_label_populate. Allows a process to
        // set exception ports on tasks/threads, bypassing AMFI restrictions.
        short_desc: "allows setting exception ports, bypassing AMFI exception port policy",
        category: "debugging",
    },

    // ── AMFI Version Restriction ──────────────────────────────────────

    EntitlementInfo {
        key: "com.apple.private.amfi.version-restriction",
        impact: Impact::Strengthens,
        // Integer value. Platform binaries without a sufficiently high version
        // are rejected by allowedWithVersionRestriction(). Ensures only
        // binaries built for the current OS version can run.
        short_desc: "enforces minimum version restriction on platform binaries",
        category: "amfi",
    },

    // ── AMFI Management ───────────────────────────────────────────────

    EntitlementInfo {
        key: "com.apple.private.amfi.can-set-denylist",
        impact: Impact::Info,
        // AppleMobileFileIntegrityUserClient::setDenylist
        short_desc: "can set AMFI code signing denylist",
        category: "amfi",
    },
    EntitlementInfo {
        key: "com.apple.private.amfi.can-load-cdhash",
        impact: Impact::Info,
        // AppleMobileFileIntegrityUserClient::loadCompilationServiceCodeDirectoryHash
        short_desc: "can load code directory hashes into AMFI",
        category: "amfi",
    },
    EntitlementInfo {
        key: "com.apple.private.amfi.set-permissive",
        impact: Impact::Info,
        // AppleMobileFileIntegrityUserClient::setPermissiveTCMode
        short_desc: "can set AMFI trust cache to permissive mode",
        category: "amfi",
    },
    EntitlementInfo {
        key: "com.apple.private.amfi.developer-mode-control",
        impact: Impact::Info,
        // Used by turnOnDeveloperMode, turnOffDeveloperMode,
        // armSecurityBootMode, isDeveloperModeWritable.
        short_desc: "can control developer mode (enable, disable, query)",
        category: "amfi",
    },
    EntitlementInfo {
        key: "com.apple.private.amfi.garbage-collect-profiles",
        impact: Impact::Info,
        // AppleMobileFileIntegrityUserClient::garbageCollectXNUProfiles
        short_desc: "can trigger garbage collection of XNU provisioning profiles",
        category: "amfi",
    },
    EntitlementInfo {
        key: "com.apple.private.amfi.can-check-trust-cache",
        impact: Impact::Info,
        short_desc: "can query trust cache entries",
        category: "amfi",
    },
    EntitlementInfo {
        key: "com.apple.private.amfi.can-execute-cdhash",
        impact: Impact::Info,
        // Checked in library validation and vnode signature verification.
        short_desc: "can validate and execute code by cdhash",
        category: "amfi",
    },

    // ── System Task Ports (full set) ──────────────────────────────────

    EntitlementInfo {
        key: "com.apple.system-task-ports",
        impact: Impact::Info,
        // Grants full (control-level) task port access on other processes.
        // Checked in macos_task_policy and checkDebuggerStatus.
        short_desc: "full task port access (control) on other processes",
        category: "debugging",
    },
    EntitlementInfo {
        key: "com.apple.system-task-ports.control",
        impact: Impact::Info,
        // Grants control port access on other processes.
        short_desc: "can obtain control port on other processes",
        category: "debugging",
    },
    EntitlementInfo {
        key: "com.apple.system-task-ports.inspect",
        impact: Impact::Info,
        // Grants inspect port access on other processes.
        short_desc: "can obtain inspect port on other processes",
        category: "debugging",
    },
    EntitlementInfo {
        key: "com.apple.system-task-ports.read",
        impact: Impact::Info,
        // Grants read port access on other processes.
        short_desc: "can obtain read port on other processes",
        category: "debugging",
    },
    EntitlementInfo {
        key: "com.apple.system-task-ports.safe",
        impact: Impact::Info,
        // Full task port access with additional safety restrictions.
        short_desc: "full task port access with safety restrictions",
        category: "debugging",
    },
    EntitlementInfo {
        key: "com.apple.system-task-ports.control.safe",
        impact: Impact::Info,
        // Control port access with additional safety restrictions.
        short_desc: "control port access with safety restrictions",
        category: "debugging",
    },
    EntitlementInfo {
        key: "com.apple.system-task-ports.inspect.safe",
        impact: Impact::Info,
        short_desc: "inspect port access with safety restrictions",
        category: "debugging",
    },
    EntitlementInfo {
        key: "com.apple.system-task-ports.read.safe",
        impact: Impact::Info,
        short_desc: "read port access with safety restrictions",
        category: "debugging",
    },
    EntitlementInfo {
        key: "internal.com.apple.system-task-ports.control",
        impact: Impact::Info,
        // Internal-only variant. Checked in macos_task_policy on
        // Apple Internal builds alongside the public entitlements.
        short_desc: "internal control port access (Apple Internal only)",
        category: "debugging",
    },
    EntitlementInfo {
        key: "com.apple.system-task-ports.token.corpse",
        impact: Impact::Info,
        // Checked in _task_id_token_get_task. Allows getting task ID
        // tokens for corpse tasks without further restrictions.
        short_desc: "can obtain task ID tokens for corpse tasks",
        category: "debugging",
    },
    EntitlementInfo {
        key: "com.apple.system-task-ports.token.inspect",
        impact: Impact::Info,
        // Grants inspect-level access via task ID tokens.
        short_desc: "can obtain task ID tokens for inspection",
        category: "debugging",
    },
    EntitlementInfo {
        key: "com.apple.system-task-ports.token.read",
        impact: Impact::Info,
        // Grants read-level access via task ID tokens.
        short_desc: "can obtain task ID tokens for reading",
        category: "debugging",
    },

    // ── Debugger Variants ─────────────────────────────────────────────

    EntitlementInfo {
        key: "com.apple.private.cs.debugger.safe",
        impact: Impact::Info,
        // Like com.apple.private.cs.debugger but with safety restrictions.
        // Checked in checkDebuggerStatus and macos_task_policy.
        short_desc: "can act as debugger with safety restrictions",
        category: "debugging",
    },
    EntitlementInfo {
        key: "com.apple.security.cs.debugger.root",
        impact: Impact::Info,
        // Root-level debugger. Also granted implicitly to platform binaries
        // like plockstat and dtrace. Checked in macos_task_policy.
        short_desc: "root-level debugger — elevated task port access",
        category: "debugging",
    },
    EntitlementInfo {
        key: "com.apple.security.cs.debugger.read.root",
        impact: Impact::Info,
        // Read-only root-level debugger access.
        short_desc: "read-only root-level debugger — read task port access",
        category: "debugging",
    },

    // ── Code Signing Operations ───────────────────────────────────────

    EntitlementInfo {
        key: "com.apple.private.allow-cs-signing",
        impact: Impact::Info,
        // Checked in _policy_syscall. Allows code signing operations
        // through the AMFI policy syscall interface.
        short_desc: "can perform code signing operations via AMFI policy syscall",
        category: "code_signing",
    },
    EntitlementInfo {
        key: "com.apple.private.allow-cs-signing.internal",
        impact: Impact::Info,
        // Internal variant for Apple Internal builds.
        short_desc: "can perform internal code signing operations",
        category: "code_signing",
    },
    EntitlementInfo {
        key: "com.apple.private.playgrounds-local-signing-allowed",
        impact: Impact::Info,
        // Checked in _policy_syscall for Swift Playgrounds code signing.
        short_desc: "Swift Playgrounds local code signing allowed",
        category: "code_signing",
    },
    EntitlementInfo {
        key: "com.apple.private.enable-swift-playgrounds-validation",
        impact: Impact::Info,
        // Checked in _policy_syscall for Swift Playgrounds validation.
        short_desc: "enables Swift Playgrounds code validation",
        category: "code_signing",
    },
    EntitlementInfo {
        key: "com.apple.private.codesignkit.signer-source-host",
        impact: Impact::Info,
        short_desc: "can act as CodeSignKit signer source host",
        category: "code_signing",
    },

    // ── SIP / Rootless ────────────────────────────────────────────────

    EntitlementInfo {
        key: "com.apple.private.allow-bless",
        impact: Impact::Info,
        // Checked in hook_vnode_check_setextattr. Allows setting
        // com.apple.root.installed xattr (blessing volumes).
        short_desc: "can bless volumes via com.apple.root.installed xattr",
        category: "rootless",
    },
    EntitlementInfo {
        key: "com.apple.rootless.install",
        impact: Impact::Info,
        // SIP: allows installing into SIP-protected paths.
        short_desc: "can install into SIP-protected paths",
        category: "rootless",
    },
    EntitlementInfo {
        key: "com.apple.rootless.install.heritable",
        impact: Impact::Info,
        // Heritable variant — child processes inherit the capability.
        // Checked in postValidation for platform binary restrictions.
        short_desc: "can install into SIP-protected paths (heritable)",
        category: "rootless",
    },
    EntitlementInfo {
        key: "com.apple.rootless.internal-installer-equivalent",
        impact: Impact::Info,
        // Grants installer-equivalent SIP bypass on Apple Internal builds.
        short_desc: "SIP installer-equivalent (Apple Internal)",
        category: "rootless",
    },
    EntitlementInfo {
        key: "com.apple.rootless.restricted-nvram-variables.heritable",
        impact: Impact::Info,
        short_desc: "can access restricted NVRAM variables (heritable)",
        category: "rootless",
    },
    EntitlementInfo {
        key: "com.apple.rootless.datavault.controller",
        impact: Impact::Info,
        short_desc: "SIP data vault controller",
        category: "rootless",
    },
    EntitlementInfo {
        key: "com.apple.rootless.datavault.controller.internal",
        impact: Impact::Info,
        short_desc: "SIP data vault controller (Apple Internal)",
        category: "rootless",
    },
    EntitlementInfo {
        key: "com.apple.rootless.storage.cvms",
        impact: Impact::Info,
        short_desc: "SIP-exempt access to CVMS storage",
        category: "rootless",
    },
    EntitlementInfo {
        key: "com.apple.private.security.install",
        impact: Impact::Info,
        // Private variant of rootless.install.
        short_desc: "can install into protected paths (private variant)",
        category: "rootless",
    },
    EntitlementInfo {
        key: "com.apple.private.security.install.heritable",
        impact: Impact::Info,
        short_desc: "can install into protected paths (private, heritable)",
        category: "rootless",
    },
    EntitlementInfo {
        key: "com.apple.private.security.restricted-nvram-variables.heritable",
        impact: Impact::Info,
        short_desc: "can access restricted NVRAM variables (private, heritable)",
        category: "rootless",
    },
    EntitlementInfo {
        key: "com.apple.private.security.datavault.controller",
        impact: Impact::Info,
        short_desc: "data vault controller (private variant)",
        category: "rootless",
    },
    EntitlementInfo {
        key: "com.apple.private.security.internal-installer-equivalent",
        impact: Impact::Info,
        short_desc: "installer-equivalent SIP bypass (private variant)",
        category: "rootless",
    },
    EntitlementInfo {
        key: "com.apple.private.security.datavault.controller.internal",
        impact: Impact::Info,
        short_desc: "internal data vault controller (private variant)",
        category: "rootless",
    },

    // ── Security Container / Storage ──────────────────────────────────

    EntitlementInfo {
        key: "com.apple.private.security.container-manager",
        impact: Impact::Info,
        short_desc: "can manage security containers",
        category: "sandbox",
    },
    EntitlementInfo {
        key: "com.apple.private.security.no-container",
        impact: Impact::Weakens,
        short_desc: "runs without a security container",
        category: "sandbox",
    },
    EntitlementInfo {
        key: "com.apple.private.security.disk-device-access",
        impact: Impact::Info,
        short_desc: "direct disk device access",
        category: "filesystem",
    },
    EntitlementInfo {
        key: "com.apple.private.security.storage-exempt.heritable",
        impact: Impact::Weakens,
        short_desc: "exempt from storage restrictions (heritable)",
        category: "sandbox",
    },
    EntitlementInfo {
        key: "com.apple.private.security.storage.AppBundles",
        impact: Impact::Info,
        short_desc: "access to app bundle storage",
        category: "filesystem",
    },
    EntitlementInfo {
        key: "com.apple.private.security.storage.DiagnosticReports.read-write",
        impact: Impact::Info,
        short_desc: "read-write access to DiagnosticReports storage",
        category: "filesystem",
    },
    EntitlementInfo {
        key: "com.apple.private.security.storage.Messages",
        impact: Impact::Info,
        short_desc: "access to Messages storage",
        category: "filesystem",
    },
    EntitlementInfo {
        key: "com.apple.private.security.storage.Photos",
        impact: Impact::Info,
        short_desc: "access to Photos storage",
        category: "filesystem",
    },
    EntitlementInfo {
        key: "com.apple.private.security.storage.trustd-private",
        impact: Impact::Info,
        short_desc: "access to trustd private storage",
        category: "filesystem",
    },

    // ── TCC (Transparency, Consent, and Control) ──────────────────────

    EntitlementInfo {
        key: "com.apple.private.tcc.allow",
        impact: Impact::Info,
        // Array of TCC service strings. Grants access to protected resources
        // (microphone, camera, contacts, etc.) without user consent prompts.
        // Checked extensively in postValidation with identity-specific restrictions.
        short_desc: "grants access to TCC-protected resources without consent",
        category: "tcc",
    },
    EntitlementInfo {
        key: "com.apple.private.tcc.allow.overridable",
        impact: Impact::Info,
        short_desc: "TCC access that can be overridden by user",
        category: "tcc",
    },
    EntitlementInfo {
        key: "com.apple.private.tcc.manager",
        impact: Impact::Info,
        // Can manage TCC database entries.
        short_desc: "can manage TCC database entries",
        category: "tcc",
    },
    EntitlementInfo {
        key: "com.apple.private.tcc.manager.set-responsible",
        impact: Impact::Info,
        // Can set the responsible process for TCC purposes.
        short_desc: "can set responsible process for TCC attribution",
        category: "tcc",
    },

    // ── Web Browser Engine ────────────────────────────────────────────

    EntitlementInfo {
        key: "com.apple.developer.web-browser-engine.webcontent",
        impact: Impact::Info,
        // Checked in _vnode_check_signature for alternative browser engine
        // web content processes. Required for non-WebKit browser engines.
        short_desc: "web content process for alternative browser engine",
        category: "browser",
    },

    // ── Developer: System Extensions & Security ───────────────────────

    EntitlementInfo {
        key: "com.apple.developer.system-extension",
        impact: Impact::Info,
        short_desc: "can install and manage system extensions",
        category: "developer",
    },
    EntitlementInfo {
        key: "com.apple.developer.endpoint-security",
        impact: Impact::Info,
        short_desc: "can use Endpoint Security framework",
        category: "developer",
    },
    EntitlementInfo {
        key: "com.apple.developer.networking.networkextension",
        impact: Impact::Info,
        short_desc: "can use NetworkExtension framework",
        category: "developer",
    },
    EntitlementInfo {
        key: "com.apple.developer.driverkit",
        impact: Impact::Info,
        short_desc: "can develop DriverKit drivers",
        category: "developer",
    },

    // ── App Protection / Groups ───────────────────────────────────────

    EntitlementInfo {
        key: "com.apple.security.application-groups",
        impact: Impact::Info,
        // Array of group identifiers for shared containers.
        short_desc: "application group container access",
        category: "sandbox",
    },
    EntitlementInfo {
        key: "com.apple.security.app-protection",
        impact: Impact::Strengthens,
        short_desc: "enables app protection",
        category: "enhanced_security",
    },

    // ── Miscellaneous ─────────────────────────────────────────────────

    EntitlementInfo {
        key: "com.apple.private.host-exception-port-override",
        impact: Impact::Info,
        short_desc: "can override host exception port",
        category: "debugging",
    },
    EntitlementInfo {
        key: "com.apple.private.kernel.system-override",
        impact: Impact::Info,
        short_desc: "kernel system override capabilities",
        category: "kernel",
    },
    EntitlementInfo {
        key: "com.apple.private.talagent.signature_update",
        impact: Impact::Info,
        // Required for com.apple.talagent platform binary. Without it,
        // the binary is rejected during postValidation.
        short_desc: "TAL agent signature update capability",
        category: "code_signing",
    },
    EntitlementInfo {
        key: "com.apple.private.xpc.role-account",
        impact: Impact::Info,
        // Restricted for certain platform binaries in postValidation.
        short_desc: "XPC role account capability",
        category: "process_control",
    },
    EntitlementInfo {
        key: "com.apple.private.signing-identifier",
        impact: Impact::Info,
        short_desc: "custom signing identifier override",
        category: "code_signing",
    },
    EntitlementInfo {
        key: "com.apple.security.get-movable-control-port",
        impact: Impact::Info,
        short_desc: "can obtain movable control port for tasks",
        category: "debugging",
    },
    EntitlementInfo {
        key: "com.apple.developer.swift-playgrounds-app.development-build",
        impact: Impact::Weakens,
        // Treated like get-task-allow for OOP-JIT previews —
        // allows OOP-JIT runner code loading.
        short_desc: "Swift Playgrounds development build — allows OOP-JIT previews",
        category: "cs_exception",
    },
    EntitlementInfo {
        key: "com.apple.private.vfs.snapshot",
        impact: Impact::Info,
        short_desc: "can create and manage filesystem snapshots",
        category: "filesystem",
    },
];
