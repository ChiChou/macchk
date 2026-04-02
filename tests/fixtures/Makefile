CC      := clang
CXX     := clang++
CFLAGS  := -O1
CXXFLAGS := -O1 -std=c++20

SIM_SDK := $(shell xcrun --sdk iphonesimulator --show-sdk-path)
X86_TARGET := -arch x86_64 -isysroot $(SIM_SDK) -target x86_64-apple-ios18.0-simulator

SRCDIR := src
BINDIR := bin

# ── Targets ──────────────────────────────────────────────────────────────

ARM64_BINS := \
	$(BINDIR)/exp1_baseline       $(BINDIR)/exp1_zeroinit \
	$(BINDIR)/exp2_arm64          $(BINDIR)/exp2_arm64e \
	$(BINDIR)/exp3_baseline       $(BINDIR)/exp3_bounds \
	$(BINDIR)/exp4_baseline       $(BINDIR)/exp4_hardened \
	$(BINDIR)/exp6_baseline       $(BINDIR)/exp6_typed \
	$(BINDIR)/exp_mte             $(BINDIR)/exp_mte_stack_baseline \
	$(BINDIR)/exp_mte_stack \
	$(BINDIR)/exp7_fortify        $(BINDIR)/exp7_no_fortify \
	$(BINDIR)/exp8_arc            $(BINDIR)/exp8_no_arc \
	$(BINDIR)/exp9_swift \
	$(BINDIR)/exp10_restrict      $(BINDIR)/exp10_no_restrict \
	$(BINDIR)/exp11_canary        $(BINDIR)/exp11_no_canary \
	$(BINDIR)/exp12_hardened      $(BINDIR)/exp12_baseline \
	$(BINDIR)/exp13_asan          $(BINDIR)/exp13_ubsan \
	$(BINDIR)/exp13_no_sanitizer \
	$(BINDIR)/exp14_jt_hardened   $(BINDIR)/exp14_jt_normal

X86_BINS := \
	$(BINDIR)/exp1_baseline_x86   $(BINDIR)/exp1_zeroinit_x86 \
	$(BINDIR)/exp3_baseline_x86   $(BINDIR)/exp3_bounds_x86 \
	$(BINDIR)/exp4_baseline_x86   $(BINDIR)/exp4_hardened_x86 \
	$(BINDIR)/exp11_canary_x86    $(BINDIR)/exp11_no_canary_x86

ALL_BINS := $(ARM64_BINS) $(X86_BINS)

.PHONY: all arm64 x86_64 clean

all: arm64 x86_64

arm64: $(ARM64_BINS)

x86_64: $(X86_BINS)

# ── Exp 1: Stack zero-init ───────────────────────────────────────────────

$(BINDIR)/exp1_baseline: $(SRCDIR)/exp1_stack_zero.c | $(BINDIR)
	$(CC) $(CFLAGS) -arch arm64 -o $@ $<

$(BINDIR)/exp1_zeroinit: $(SRCDIR)/exp1_stack_zero.c | $(BINDIR)
	$(CC) $(CFLAGS) -arch arm64 -ftrivial-auto-var-init=zero -o $@ $<

$(BINDIR)/exp1_baseline_x86: $(SRCDIR)/exp1_stack_zero.c | $(BINDIR)
	$(CC) $(CFLAGS) $(X86_TARGET) -o $@ $<

$(BINDIR)/exp1_zeroinit_x86: $(SRCDIR)/exp1_stack_zero.c | $(BINDIR)
	$(CC) $(CFLAGS) $(X86_TARGET) -ftrivial-auto-var-init=zero -o $@ $<

# ── Exp 2: Pointer authentication ────────────────────────────────────────

$(BINDIR)/exp2_arm64: $(SRCDIR)/exp2_ptrauth.c | $(BINDIR)
	$(CC) $(CFLAGS) -arch arm64 -o $@ $<

$(BINDIR)/exp2_arm64e: $(SRCDIR)/exp2_ptrauth.c | $(BINDIR)
	$(CC) $(CFLAGS) -arch arm64e -o $@ $<

# ── Exp 3: C bounds safety ───────────────────────────────────────────────

$(BINDIR)/exp3_baseline: $(SRCDIR)/exp3_bounds_safety.c | $(BINDIR)
	$(CC) $(CFLAGS) -arch arm64 -o $@ $<

$(BINDIR)/exp3_bounds: $(SRCDIR)/exp3_bounds_safety.c | $(BINDIR)
	$(CC) $(CFLAGS) -arch arm64 -fbounds-safety -o $@ $<

$(BINDIR)/exp3_baseline_x86: $(SRCDIR)/exp3_bounds_safety.c | $(BINDIR)
	$(CC) $(CFLAGS) $(X86_TARGET) -o $@ $<

$(BINDIR)/exp3_bounds_x86: $(SRCDIR)/exp3_bounds_safety.c | $(BINDIR)
	$(CC) $(CFLAGS) $(X86_TARGET) -fbounds-safety -o $@ $<

# ── Exp 4: C++ libc++ hardening ──────────────────────────────────────────

$(BINDIR)/exp4_baseline: $(SRCDIR)/exp4_cpp_bounds.cpp | $(BINDIR)
	$(CXX) $(CXXFLAGS) -arch arm64 -o $@ $<

$(BINDIR)/exp4_hardened: $(SRCDIR)/exp4_cpp_bounds.cpp | $(BINDIR)
	$(CXX) $(CXXFLAGS) -arch arm64 \
		-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_FAST -o $@ $<

$(BINDIR)/exp4_baseline_x86: $(SRCDIR)/exp4_cpp_bounds.cpp | $(BINDIR)
	$(CXX) $(CXXFLAGS) $(X86_TARGET) -o $@ $<

$(BINDIR)/exp4_hardened_x86: $(SRCDIR)/exp4_cpp_bounds.cpp | $(BINDIR)
	$(CXX) $(CXXFLAGS) $(X86_TARGET) \
		-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_FAST -o $@ $<

# ── Exp 6: Typed allocators ──────────────────────────────────────────────

$(BINDIR)/exp6_baseline: $(SRCDIR)/exp6_typed_alloc.c | $(BINDIR)
	$(CC) $(CFLAGS) -arch arm64 -o $@ $<

$(BINDIR)/exp6_typed: $(SRCDIR)/exp6_typed_alloc.c | $(BINDIR)
	$(CC) $(CFLAGS) -arch arm64 -ftyped-memory-operations-experimental -o $@ $<

# ── Exp 7: FORTIFY_SOURCE ────────────────────────────────────────────────

$(BINDIR)/exp7_fortify: $(SRCDIR)/exp7_fortify.c | $(BINDIR)
	$(CC) -O0 -arch arm64 -D_FORTIFY_SOURCE=2 -o $@ $<

$(BINDIR)/exp7_no_fortify: $(SRCDIR)/exp7_fortify.c | $(BINDIR)
	$(CC) $(CFLAGS) -arch arm64 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -o $@ $<

# ── Exp 8: Objective-C ARC ──────────────────────────────────────────────

$(BINDIR)/exp8_arc: $(SRCDIR)/exp8_objc_arc.m | $(BINDIR)
	$(CC) $(CFLAGS) -arch arm64 -fobjc-arc -framework Foundation -o $@ $<

$(BINDIR)/exp8_no_arc: $(SRCDIR)/exp8_objc_arc.m | $(BINDIR)
	$(CC) $(CFLAGS) -arch arm64 -fno-objc-arc -framework Foundation -o $@ $<

# ── Exp 9: Swift ────────────────────────────────────────────────────────

$(BINDIR)/exp9_swift: $(SRCDIR)/exp9_swift.swift | $(BINDIR)
	swiftc -O -o $@ $<

# ── Exp 10: __RESTRICT ──────────────────────────────────────────────────

$(BINDIR)/exp10_restrict: $(SRCDIR)/exp10_restrict.c | $(BINDIR)
	$(CC) $(CFLAGS) -arch arm64 -Wl,-sectcreate,__RESTRICT,__restrict,/dev/null -o $@ $<

$(BINDIR)/exp10_no_restrict: $(SRCDIR)/exp10_restrict.c | $(BINDIR)
	$(CC) $(CFLAGS) -arch arm64 -o $@ $<

# ── Exp 11: Stack canary ────────────────────────────────────────────────

$(BINDIR)/exp11_canary: $(SRCDIR)/exp11_canary.c | $(BINDIR)
	$(CC) $(CFLAGS) -arch arm64 -fstack-protector-all -o $@ $<

$(BINDIR)/exp11_no_canary: $(SRCDIR)/exp11_canary.c | $(BINDIR)
	$(CC) $(CFLAGS) -arch arm64 -fno-stack-protector -o $@ $<

$(BINDIR)/exp11_canary_x86: $(SRCDIR)/exp11_canary.c | $(BINDIR)
	$(CC) $(CFLAGS) $(X86_TARGET) -fstack-protector-all -o $@ $<

$(BINDIR)/exp11_no_canary_x86: $(SRCDIR)/exp11_canary.c | $(BINDIR)
	$(CC) $(CFLAGS) $(X86_TARGET) -fno-stack-protector -o $@ $<

# ── Exp 12: Hardened runtime + entitlements ─────────────────────────────

$(BINDIR)/exp12_hardened: $(SRCDIR)/exp12_hardened_runtime.c $(SRCDIR)/exp12_entitlements.plist | $(BINDIR)
	$(CC) $(CFLAGS) -arch arm64 -o $@ $<
	codesign -s - --options runtime --entitlements $(SRCDIR)/exp12_entitlements.plist $@

$(BINDIR)/exp12_baseline: $(SRCDIR)/exp12_hardened_runtime.c | $(BINDIR)
	$(CC) $(CFLAGS) -arch arm64 -o $@ $<

# ── Exp 14: Jump table hardening ────────────────────────────────────────
# Compile as .o since extern functions are undefined (no main needed)
# Use -Wl,-undefined,dynamic_lookup to link without resolving symbols

$(BINDIR)/exp14_jt_hardened: $(SRCDIR)/exp14_jump_table.c | $(BINDIR)
	$(CC) -O2 -arch arm64 -faarch64-jump-table-hardening \
		-Wl,-undefined,dynamic_lookup -Wl,-e,_dispatch -o $@ $<

$(BINDIR)/exp14_jt_normal: $(SRCDIR)/exp14_jump_table.c | $(BINDIR)
	$(CC) -O2 -arch arm64 \
		-Wl,-undefined,dynamic_lookup -Wl,-e,_dispatch -o $@ $<

# ── Exp 13: Sanitizers ──────────────────────────────────────────────────

$(BINDIR)/exp13_asan: $(SRCDIR)/exp13_sanitizers.c | $(BINDIR)
	$(CC) $(CFLAGS) -arch arm64 -fsanitize=address -o $@ $<

$(BINDIR)/exp13_ubsan: $(SRCDIR)/exp13_sanitizers.c | $(BINDIR)
	$(CC) $(CFLAGS) -arch arm64 -fsanitize=undefined -o $@ $<

$(BINDIR)/exp13_no_sanitizer: $(SRCDIR)/exp13_sanitizers.c | $(BINDIR)
	$(CC) $(CFLAGS) -arch arm64 -o $@ $<

# ── MTE: intrinsics ──────────────────────────────────────────────────────

$(BINDIR)/exp_mte: $(SRCDIR)/exp_mte_intrinsics.c | $(BINDIR)
	$(CC) $(CFLAGS) -arch arm64 -march=armv8.5-a+memtag -o $@ $<

$(BINDIR)/exp_mte_stack_baseline: $(SRCDIR)/exp_mte_stack.c | $(BINDIR)
	$(CC) $(CFLAGS) -arch arm64 -o $@ $<

$(BINDIR)/exp_mte_stack: $(SRCDIR)/exp_mte_stack.c | $(BINDIR)
	$(CC) $(CFLAGS) -arch arm64 -march=armv8.5-a+memtag \
		-fsanitize=memtag-stack -o $@ $<

# ── Directory creation ───────────────────────────────────────────────────

$(BINDIR):
	mkdir -p $(BINDIR)

# ── Clean ─────────────────────────────────────────────────────────────────

clean:
	rm -f $(ALL_BINS)
