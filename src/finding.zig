const std = @import("std");

pub const TOOL_NAME = "Snap-Oracle";
pub const TOOL_VERSION = "0.3.0-arm64";
pub const HELP_BASE_URI = "https://github.com/Elephantpanda6/snap-oracle/blob/main/docs/ARM64_ARCHITECTURE_AND_LAPTOPS.md";

pub const Severity = enum(u8) {
    info = 0,
    low = 1,
    medium = 2,
    high = 3,
    critical = 4,

    pub fn toString(self: Severity) []const u8 {
        return switch (self) {
            .info => "info",
            .low => "low",
            .medium => "medium",
            .high => "high",
            .critical => "critical",
        };
    }

    pub fn badge(self: Severity) []const u8 {
        return switch (self) {
            .info => "INFO",
            .low => "LOW ",
            .medium => "MED ",
            .high => "HIGH",
            .critical => "CRIT",
        };
    }

    pub fn toSarifLevel(self: Severity) []const u8 {
        return switch (self) {
            .critical, .high => "error",
            .medium => "warning",
            .low, .info => "note",
        };
    }

    /// CVSS-like string expected by GitHub Code Scanning `properties."security-severity"`.
    pub fn toSecuritySeverityScore(self: Severity) []const u8 {
        return switch (self) {
            .critical => "9.5",
            .high => "7.8",
            .medium => "5.3",
            .low => "3.1",
            .info => "0.5",
        };
    }

    pub fn fromString(s: []const u8) ?Severity {
        if (eqlIgnoreCase(s, "info")) return .info;
        if (eqlIgnoreCase(s, "low")) return .low;
        if (eqlIgnoreCase(s, "medium") or eqlIgnoreCase(s, "med")) return .medium;
        if (eqlIgnoreCase(s, "high")) return .high;
        if (eqlIgnoreCase(s, "critical") or eqlIgnoreCase(s, "crit")) return .critical;
        return null;
    }
};

pub const Confidence = enum(u8) {
    low = 0,
    medium = 1,
    high = 2,

    pub fn toString(self: Confidence) []const u8 {
        return switch (self) {
            .low => "low",
            .medium => "medium",
            .high => "high",
        };
    }
};

pub const RuleMeta = struct {
    id: []const u8,
    title: []const u8,
    category: []const u8,
    default_severity: Severity,
    cwe: ?u16,
    help_uri: []const u8,
    remediation: []const u8,
};

pub const RULE_CATALOG = [_]RuleMeta{
    // AArch64 control-flow integrity / ISA hardening
    .{
        .id = "SO-PAC-001",
        .title = "Low or missing ARMv8.3-A PAC return-address signing coverage",
        .category = "hardening",
        .default_severity = .medium,
        .cwe = 121,
        .help_uri = HELP_BASE_URI,
        .remediation = "Compile with -mbranch-protection=standard (Clang/GCC) or /guard:cf /Qspectre (MSVC ARM64).",
    },
    .{
        .id = "SO-BTI-001",
        .title = "Missing ARMv8.5-A BTI indirect-branch landing pads",
        .category = "hardening",
        .default_severity = .medium,
        .cwe = 119,
        .help_uri = HELP_BASE_URI,
        .remediation = "Enable Branch Target Identification (-mbranch-protection=bti+pac-ret) and verify ELF .note.gnu.property.",
    },

    // Dependency & mixed-arch ABI compatibility
    .{
        .id = "SO-DEP-001",
        .title = "Architecture-incompatible binary in dependency load chain",
        .category = "deps",
        .default_severity = .critical,
        .cwe = 758,
        .help_uri = HELP_BASE_URI,
        .remediation = "Rebuild the imported library for native AArch64 (or ARM64EC/ARM64X on Windows) matching the parent binary.",
    },
    .{
        .id = "SO-DEP-002",
        .title = "ARM64EC / native ARM64 ABI boundary transition",
        .category = "deps",
        .default_severity = .medium,
        .cwe = 758,
        .help_uri = HELP_BASE_URI,
        .remediation = "Verify thunk/ARM64X pure-forwarder exports so plugins load without emulation penalties.",
    },
    .{
        .id = "SO-DEP-003",
        .title = "Unresolved non-system dynamic library dependency",
        .category = "deps",
        .default_severity = .medium,
        .cwe = 427,
        .help_uri = HELP_BASE_URI,
        .remediation = "Bundle the missing DLL/.so/.dylib beside the binary or pass --root <dir> containing staged artifacts.",
    },
    .{
        .id = "SO-DEP-004",
        .title = "Ordinal-only PE import fragile across OS/SDK updates",
        .category = "deps",
        .default_severity = .low,
        .cwe = 477,
        .help_uri = HELP_BASE_URI,
        .remediation = "Prefer named imports over ordinal-only bindings in export definition files.",
    },

    // Page size readiness (4K / 16K / 64K)
    .{
        .id = "SO-PAGE-001",
        .title = "Segment or section alignment below target kernel page size",
        .category = "pagesize",
        .default_severity = .high,
        .cwe = 119,
        .help_uri = HELP_BASE_URI,
        .remediation = "Relink with -Wl,-z,max-page-size=16384 (or 65536) on ELF, or /ALIGN:16384 on Windows PE.",
    },
    .{
        .id = "SO-PAGE-002",
        .title = "ELF PT_LOAD virtual/file offset congruence violation",
        .category = "pagesize",
        .default_severity = .critical,
        .cwe = 119,
        .help_uri = HELP_BASE_URI,
        .remediation = "Rebuild with LLD/Gold -z common-page-size=16384 -z max-page-size=16384 so (p_vaddr % P) == (p_offset % P).",
    },
    .{
        .id = "SO-PAGE-003",
        .title = "Adjacent W+X segments share a target virtual memory page",
        .category = "pagesize",
        .default_severity = .high,
        .cwe = 693,
        .help_uri = HELP_BASE_URI,
        .remediation = "Separate writable and executable segments onto distinct target page boundaries (-z separate-code).",
    },
    .{
        .id = "SO-PAGE-004",
        .title = "Hardcoded 4KB (0x1000 / 0xFFF) page-size assumption in machine code",
        .category = "pagesize",
        .default_severity = .medium,
        .cwe = 190,
        .help_uri = HELP_BASE_URI,
        .remediation = "Query runtime page size via sysconf(_SC_PAGESIZE) / GetSystemInfo instead of hardcoding 4096.",
    },

    // Binary hardening & supply-chain posture
    .{
        .id = "SO-HARDEN-001",
        .title = "ASLR / PIE relocation hardening disabled",
        .category = "hardening",
        .default_severity = .high,
        .cwe = 119,
        .help_uri = HELP_BASE_URI,
        .remediation = "Link with /DYNAMICBASE /HIGHENTROPYVA (PE) or -fPIE -pie / -fPIC -shared (ELF/Mach-O).",
    },
    .{
        .id = "SO-HARDEN-002",
        .title = "NX / non-executable stack or W^X protection missing",
        .category = "hardening",
        .default_severity = .critical,
        .cwe = 693,
        .help_uri = HELP_BASE_URI,
        .remediation = "Enable /NXCOMPAT (PE) or -Wl,-z,noexecstack (ELF) and remove combined W+X segment flags.",
    },
    .{
        .id = "SO-HARDEN-003",
        .title = "Control Flow Guard (CFG) or Full RELRO not enabled",
        .category = "hardening",
        .default_severity = .high,
        .cwe = 693,
        .help_uri = HELP_BASE_URI,
        .remediation = "Build with /guard:cf (Windows ARM64) or -Wl,-z,relro,-z,now (Linux AArch64).",
    },
    .{
        .id = "SO-HARDEN-004",
        .title = "Stack smash protector (__stack_chk_fail) not detected",
        .category = "hardening",
        .default_severity = .medium,
        .cwe = 121,
        .help_uri = HELP_BASE_URI,
        .remediation = "Compile with -fstack-protector-strong (Clang/GCC) or /GS (MSVC).",
    },
    .{
        .id = "SO-HARDEN-005",
        .title = "Mach-O code signature or hardened runtime (CS_RUNTIME) missing",
        .category = "hardening",
        .default_severity = .high,
        .cwe = 345,
        .help_uri = HELP_BASE_URI,
        .remediation = "Sign Apple Silicon binaries with codesign --options runtime.",
    },
    .{
        .id = "SO-HARDEN-006",
        .title = "ARMv8.5-A Memory Tagging Extension (MTE) metadata absent",
        .category = "hardening",
        .default_severity = .info,
        .cwe = 119,
        .help_uri = HELP_BASE_URI,
        .remediation = "Consider -fsanitize=memtag for Android/Linux ARMv9 targets supporting MTE.",
    },
    .{
        .id = "SO-HARDEN-007",
        .title = "Text relocations (DT_TEXTREL) require writable code pages",
        .category = "hardening",
        .default_severity = .high,
        .cwe = 693,
        .help_uri = HELP_BASE_URI,
        .remediation = "Recompile all object files with -fPIC to eliminate text relocations.",
    },

    // Defensive crash triage classifications
    .{
        .id = "SO-CRASH-001",
        .title = "Controlled or wild write access violation",
        .category = "triage",
        .default_severity = .critical,
        .cwe = 787,
        .help_uri = HELP_BASE_URI,
        .remediation = "Audit bounds validation before store instructions at the faulting RVA.",
    },
    .{
        .id = "SO-CRASH-002",
        .title = "Wild control-flow transfer or PC corruption",
        .category = "triage",
        .default_severity = .critical,
        .cwe = 119,
        .help_uri = HELP_BASE_URI,
        .remediation = "Validate indirect call targets, vtables, and enable PAC/BTI + CFG.",
    },
    .{
        .id = "SO-CRASH-003",
        .title = "ARM64 PAC authentication failure or BTI violation",
        .category = "triage",
        .default_severity = .critical,
        .cwe = 119,
        .help_uri = HELP_BASE_URI,
        .remediation = "PAC/BTI caught control-flow corruption; trace stack corruption preceding RET/BLRAA/BR.",
    },
    .{
        .id = "SO-CRASH-004",
        .title = "Out-of-bounds read access violation",
        .category = "triage",
        .default_severity = .high,
        .cwe = 125,
        .help_uri = HELP_BASE_URI,
        .remediation = "Add slice/length bounds checks before memory load at the faulting RVA.",
    },
    .{
        .id = "SO-CRASH-005",
        .title = "Stack exhaustion / stack overflow",
        .category = "triage",
        .default_severity = .medium,
        .cwe = 674,
        .help_uri = HELP_BASE_URI,
        .remediation = "Bound recursion depth and large stack buffers on untrusted input paths.",
    },
    .{
        .id = "SO-CRASH-006",
        .title = "Null-pointer dereference or near-null offset",
        .category = "triage",
        .default_severity = .low,
        .cwe = 476,
        .help_uri = HELP_BASE_URI,
        .remediation = "Check pointer validity before dereferencing optional or parsed structures.",
    },
    .{
        .id = "SO-CRASH-007",
        .title = "Assertion trap, divide-by-zero, or illegal instruction",
        .category = "triage",
        .default_severity = .medium,
        .cwe = 617,
        .help_uri = HELP_BASE_URI,
        .remediation = "Replace fatal traps or unchecked divisors on external input with explicit error returns.",
    },

    // Performance & ARM64 vectorization migration advisor
    .{
        .id = "SO-PERF-001",
        .title = "Scalar floating-point loop without NEON/SVE vectorization",
        .category = "perf",
        .default_severity = .medium,
        .cwe = null,
        .help_uri = HELP_BASE_URI,
        .remediation = "Enable auto-vectorization (-O3 -ffast-math where safe) or rewrite hot loops with NEON/SVE intrinsics.",
    },
    .{
        .id = "SO-PERF-002",
        .title = "High-contention LL/SC atomics (LDXR/STXR) instead of ARMv8.1 LSE",
        .category = "perf",
        .default_severity = .medium,
        .cwe = null,
        .help_uri = HELP_BASE_URI,
        .remediation = "Compile with -march=armv8.1-a or -moutline-atomics to utilize LSE atomics (LDADD/CASAL).",
    },
    .{
        .id = "SO-PERF-003",
        .title = "Compute/ML kernel lacks DotProd (SDOT/UDOT) or I8MM/BF16 acceleration",
        .category = "perf",
        .default_severity = .medium,
        .cwe = null,
        .help_uri = HELP_BASE_URI,
        .remediation = "Target +dotprod / +i8mm / +bf16 on Snapdragon X, Apple Silicon, NVIDIA N1X, and Graviton3+.",
    },
    .{
        .id = "SO-PERF-004",
        .title = "Non-native x64 or ARM64EC emulated path incurring translation overhead",
        .category = "perf",
        .default_severity = .high,
        .cwe = null,
        .help_uri = HELP_BASE_URI,
        .remediation = "Port hot modules from x64/Prism/Rosetta2 to native AArch64.",
    },
    .{
        .id = "SO-PERF-005",
        .title = "x64 SSE/AVX/AVX-512 SIMD paths requiring NEON/SVE2 translation",
        .category = "perf",
        .default_severity = .high,
        .cwe = null,
        .help_uri = HELP_BASE_URI,
        .remediation = "Replace x86 VEX/EVEX hot kernels with native NEON or vector-length-agnostic SVE2.",
    },

    // Source & binary x64->ARM64 porting hazard scanner
    .{
        .id = "SO-PORT-001",
        .title = "Direct x86 SSE/AVX/AVX-512 compiler intrinsics in source",
        .category = "porting",
        .default_severity = .high,
        .cwe = 758,
        .help_uri = HELP_BASE_URI,
        .remediation = "Guard with #if defined(__aarch64__) || defined(_M_ARM64) and provide NEON/SIMDe implementations.",
    },
    .{
        .id = "SO-PORT-002",
        .title = "x86-specific CPU/TSC intrinsics (__rdtsc, __cpuid, _BitScan)",
        .category = "porting",
        .default_severity = .high,
        .cwe = 758,
        .help_uri = HELP_BASE_URI,
        .remediation = "Use CNTVCT_EL0 / std::chrono on ARM64 and getauxval/IsProcessorFeaturePresent instead of CPUID.",
    },
    .{
        .id = "SO-PORT-003",
        .title = "Inline x86 assembly block will fail AArch64 compilation",
        .category = "porting",
        .default_severity = .critical,
        .cwe = 758,
        .help_uri = HELP_BASE_URI,
        .remediation = "Replace inline x86 asm with C11/C++11 atomics, compiler builtins, or AArch64 equivalents.",
    },
    .{
        .id = "SO-PORT-004",
        .title = "Asymmetric x86 preprocessor guard lacks ARM64 branch",
        .category = "porting",
        .default_severity = .medium,
        .cwe = 758,
        .help_uri = HELP_BASE_URI,
        .remediation = "Add explicit #elif defined(__aarch64__) || defined(_M_ARM64) handling.",
    },
    .{
        .id = "SO-PORT-005",
        .title = "Weak-memory hazard: volatile synchronization unsafe on ARM64",
        .category = "porting",
        .default_severity = .high,
        .cwe = 362,
        .help_uri = HELP_BASE_URI,
        .remediation = "ARM64 has weak memory ordering unlike x64 TSO; replace volatile sync with atomic acquire/release.",
    },
    .{
        .id = "SO-PORT-006",
        .title = "Plain char signedness comparison hazard (unsigned on Linux AArch64)",
        .category = "porting",
        .default_severity = .medium,
        .cwe = 195,
        .help_uri = HELP_BASE_URI,
        .remediation = "Use explicit signed char / int8_t instead of assuming plain char is signed.",
    },
    .{
        .id = "SO-PORT-007",
        .title = "long double precision divergence across x64 (80-bit) and ARM64 (64/128-bit)",
        .category = "porting",
        .default_severity = .low,
        .cwe = 681,
        .help_uri = HELP_BASE_URI,
        .remediation = "Use double or explicit fixed-precision types where cross-platform determinism matters.",
    },
    .{
        .id = "SO-PORT-008",
        .title = "Binary synchronization hazard (x64 LOCK/MFENCE or unbarriered LL/SC)",
        .category = "porting",
        .default_severity = .medium,
        .cwe = 362,
        .help_uri = HELP_BASE_URI,
        .remediation = "Verify acquire/release (LDAR/STLR) or DMB ISH placement in lock-free routines.",
    },

    // SBOM / provenance
    .{
        .id = "SO-SBOM-001",
        .title = "Reproducible build identifier or debug provenance missing",
        .category = "sbom",
        .default_severity = .info,
        .cwe = null,
        .help_uri = HELP_BASE_URI,
        .remediation = "Link with --build-id=sha256 (ELF) or embed CodeView/RSDS debug metadata (PE).",
    },
    .{
        .id = "SO-SBOM-002",
        .title = "Third-party component detected inside binary artifact",
        .category = "sbom",
        .default_severity = .info,
        .cwe = null,
        .help_uri = HELP_BASE_URI,
        .remediation = "Track detected embedded libraries and versions in CycloneDX/SPDX SBOM feeds.",
    },
};

pub fn findRule(id: []const u8) ?RuleMeta {
    for (RULE_CATALOG) |r| {
        if (std.mem.eql(u8, r.id, id)) return r;
    }
    return null;
}

pub const Finding = struct {
    rule_id: []const u8,
    severity: Severity,
    confidence: Confidence = .high,
    title: []const u8,
    detail: []const u8,
    artifact: []const u8,
    rva: ?u32 = null,
    file_offset: ?u32 = null,
    line: ?u32 = null,
    func_name: ?[]const u8 = null,
    remediation: []const u8,
    cwe: ?u16 = null,
    fingerprint: u64 = 0,
};

pub const AddOptions = struct {
    rule_id: []const u8,
    severity: ?Severity = null,
    confidence: Confidence = .high,
    title: ?[]const u8 = null,
    detail: []const u8,
    artifact: []const u8,
    rva: ?u32 = null,
    file_offset: ?u32 = null,
    line: ?u32 = null,
    func_name: ?[]const u8 = null,
    remediation: ?[]const u8 = null,
    cwe: ?u16 = null,
};

pub const FindingSet = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    items: std.ArrayList(Finding) = .empty,

    pub fn init(backing_allocator: std.mem.Allocator) FindingSet {
        return .{
            .allocator = backing_allocator,
            .arena = std.heap.ArenaAllocator.init(backing_allocator),
            .items = .empty,
        };
    }

    pub fn deinit(self: *FindingSet) void {
        self.items.deinit(self.allocator);
        self.arena.deinit();
    }

    pub fn add(self: *FindingSet, opts: AddOptions) !void {
        const aa = self.arena.allocator();
        const meta = findRule(opts.rule_id);
        const sev = opts.severity orelse (if (meta) |m| m.default_severity else Severity.medium);
        const title_src = opts.title orelse (if (meta) |m| m.title else opts.rule_id);
        const rem_src = opts.remediation orelse (if (meta) |m| m.remediation else "Review finding details and apply standard ARM64 remediation.");
        const cwe_val = opts.cwe orelse (if (meta) |m| m.cwe else null);

        const rule_duped = try aa.dupe(u8, opts.rule_id);
        const title_duped = try aa.dupe(u8, title_src);
        const detail_duped = try aa.dupe(u8, opts.detail);
        const artifact_duped = try aa.dupe(u8, opts.artifact);
        const rem_duped = try aa.dupe(u8, rem_src);
        const fn_duped: ?[]const u8 = if (opts.func_name) |fn_name| try aa.dupe(u8, fn_name) else null;

        const loc: u64 = if (opts.rva) |r|
            @as(u64, r)
        else if (opts.line) |l|
            @as(u64, l)
        else
            @as(u64, opts.file_offset orelse 0);
        const fp = computeFingerprint(rule_duped, artifact_duped, fn_duped orelse "", loc, detail_duped);

        try self.items.append(self.allocator, .{
            .rule_id = rule_duped,
            .severity = sev,
            .confidence = opts.confidence,
            .title = title_duped,
            .detail = detail_duped,
            .artifact = artifact_duped,
            .rva = opts.rva,
            .file_offset = opts.file_offset,
            .line = opts.line,
            .func_name = fn_duped,
            .remediation = rem_duped,
            .cwe = cwe_val,
            .fingerprint = fp,
        });
    }

    pub fn countBySeverity(self: *const FindingSet, sev: Severity) usize {
        var n: usize = 0;
        for (self.items.items) |f| {
            if (f.severity == sev) n += 1;
        }
        return n;
    }

    pub fn countAtOrAbove(self: *const FindingSet, min_sev: Severity) usize {
        var n: usize = 0;
        const thresh = @intFromEnum(min_sev);
        for (self.items.items) |f| {
            if (@intFromEnum(f.severity) >= thresh) n += 1;
        }
        return n;
    }

    pub fn maxSeverity(self: *const FindingSet) ?Severity {
        var best: ?Severity = null;
        for (self.items.items) |f| {
            if (best == null or @intFromEnum(f.severity) > @intFromEnum(best.?)) {
                best = f.severity;
            }
        }
        return best;
    }

    pub fn exitCode(self: *const FindingSet, threshold: Severity) u8 {
        return if (self.countAtOrAbove(threshold) > 0) 1 else 0;
    }
};

pub fn basename(path: []const u8) []const u8 {
    var i: usize = path.len;
    while (i > 0) {
        i -= 1;
        if (path[i] == '/' or path[i] == '\\') {
            return path[i + 1 ..];
        }
    }
    return path;
}

pub fn computeFingerprint(rule_id: []const u8, artifact: []const u8, func_name: []const u8, loc: u64, detail: []const u8) u64 {
    var h = std.hash.Fnv1a_64.init();
    h.update(rule_id);
    h.update("|");
    h.update(basename(artifact));
    h.update("|");
    h.update(func_name);
    if (func_name.len == 0) {
        var buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &buf, loc, .little);
        h.update(&buf);
        if (loc == 0) {
            h.update("|");
            h.update(detail);
        }
    }
    return h.final();
}

pub fn sha256Hex(bytes: []const u8) [64]u8 {
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    const hex = "0123456789abcdef";
    var out: [64]u8 = undefined;
    for (digest, 0..) |b, i| {
        out[i * 2] = hex[b >> 4];
        out[i * 2 + 1] = hex[b & 0xF];
    }
    return out;
}

pub fn appendJsonEscaped(list: *std.ArrayList(u8), allocator: std.mem.Allocator, s: []const u8) !void {
    try list.append(allocator, '"');
    var i: usize = 0;
    while (i < s.len) {
        const c = s[i];
        switch (c) {
            '"' => {
                try list.appendSlice(allocator, "\\\"");
                i += 1;
            },
            '\\' => {
                try list.appendSlice(allocator, "\\\\");
                i += 1;
            },
            '\x08' => {
                try list.appendSlice(allocator, "\\b");
                i += 1;
            },
            '\x0C' => {
                try list.appendSlice(allocator, "\\f");
                i += 1;
            },
            '\n' => {
                try list.appendSlice(allocator, "\\n");
                i += 1;
            },
            '\r' => {
                try list.appendSlice(allocator, "\\r");
                i += 1;
            },
            '\t' => {
                try list.appendSlice(allocator, "\\t");
                i += 1;
            },
            else => {
                if (c < 0x20 or c == 0x7F) {
                    var buf: [6]u8 = undefined;
                    const esc = try std.fmt.bufPrint(&buf, "\\u{x:0>4}", .{c});
                    try list.appendSlice(allocator, esc);
                    i += 1;
                } else if (c >= 0x80) {
                    if (std.unicode.utf8ByteSequenceLength(c)) |seq_len| {
                        if (i + seq_len <= s.len) {
                            if (std.unicode.utf8Decode(s[i .. i + seq_len])) |_| {
                                try list.appendSlice(allocator, s[i .. i + seq_len]);
                                i += seq_len;
                                continue;
                            } else |_| {}
                        }
                    } else |_| {}
                    try list.appendSlice(allocator, "\\uFFFD");
                    i += 1;
                } else {
                    try list.append(allocator, c);
                    i += 1;
                }
            },
        }
    }
    try list.append(allocator, '"');
}

pub fn appendXmlEscaped(list: *std.ArrayList(u8), allocator: std.mem.Allocator, s: []const u8) !void {
    for (s) |c| {
        switch (c) {
            '&' => try list.appendSlice(allocator, "&amp;"),
            '<' => try list.appendSlice(allocator, "&lt;"),
            '>' => try list.appendSlice(allocator, "&gt;"),
            '"' => try list.appendSlice(allocator, "&quot;"),
            '\'' => try list.appendSlice(allocator, "&apos;"),
            else => {
                if (c < 0x20 and c != '\n' and c != '\r' and c != '\t') {
                    try list.append(allocator, ' ');
                } else {
                    try list.append(allocator, c);
                }
            },
        }
    }
}

pub fn appendHtmlEscaped(list: *std.ArrayList(u8), allocator: std.mem.Allocator, s: []const u8) !void {
    try appendXmlEscaped(list, allocator, s);
}

pub fn writeOutputFile(io: std.Io, path: []const u8, data: []const u8) !void {
    if (std.Io.Dir.path.dirname(path)) |parent| {
        if (parent.len > 0) {
            std.Io.Dir.cwd().createDirPath(io, parent) catch {};
        }
    }
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = data });
}

pub fn writeStdout(io: std.Io, data: []const u8) void {
    std.Io.File.stdout().writeStreamingAll(io, data) catch {
        std.debug.print("{s}", .{data});
    };
}

pub fn eqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (std.ascii.toLower(ca) != std.ascii.toLower(cb)) return false;
    }
    return true;
}

pub fn indexOfIgnoreCase(haystack: []const u8, needle: []const u8) ?usize {
    if (needle.len == 0) return 0;
    if (haystack.len < needle.len) return null;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (eqlIgnoreCase(haystack[i .. i + needle.len], needle)) return i;
    }
    return null;
}

pub fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    return indexOfIgnoreCase(haystack, needle) != null;
}
