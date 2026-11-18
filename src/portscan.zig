const std = @import("std");
const binary = @import("binary.zig");
const cfg = @import("cfg.zig");
const arm64_isa = @import("arm64_isa.zig");
const finding = @import("finding.zig");
const report = @import("report.zig");

pub const PortScanSummary = struct {
    files_scanned: usize = 0,
    binaries_scanned: usize = 0,
    lines_scanned: usize = 0,
};

fn isSupportedSourceExt(name: []const u8) bool {
    const exts = [_][]const u8{ ".c", ".h", ".cc", ".cpp", ".hpp", ".cxx", ".rs", ".zig" };
    for (exts) |e| {
        if (name.len > e.len and finding.eqlIgnoreCase(name[name.len - e.len ..], e)) return true;
    }
    return false;
}

fn isIgnoredDirName(name: []const u8) bool {
    const skipped = [_][]const u8{ ".git", ".zig-cache", "zig-cache", "zig-out", "node_modules", "target", "build" };
    for (skipped) |s| {
        if (std.mem.eql(u8, name, s)) return true;
    }
    return false;
}

fn isBinaryMagic(bytes: []const u8) bool {
    if (bytes.len >= 4 and std.mem.eql(u8, bytes[0..4], "\x7fELF")) return true;
    if (bytes.len >= 2 and bytes[0] == 'M' and bytes[1] == 'Z') return true;
    if (bytes.len >= 4) {
        const le = std.mem.readInt(u32, bytes[0..4], .little);
        const be = std.mem.readInt(u32, bytes[0..4], .big);
        if (le == 0xFEED_FACF or be == 0xCAFE_BABE) return true;
    }
    return false;
}

fn stripLineComment(line: []const u8, is_zig_file: bool, in_block_comment: *bool, scratch: *[2048]u8) []const u8 {
    const raw_trimmed = std.mem.trim(u8, line, " \t\r");
    if (is_zig_file and std.mem.startsWith(u8, raw_trimmed, "\\\\")) {
        return "";
    }
    const keep_strings = std.mem.startsWith(u8, raw_trimmed, "#include") or
        std.mem.indexOf(u8, raw_trimmed, "__asm") != null or
        std.mem.indexOf(u8, raw_trimmed, "asm volatile") != null;

    var out_len: usize = 0;
    var i: usize = 0;
    var in_str = false;
    var str_quote: u8 = '"';

    while (i < line.len and out_len < scratch.len) {
        if (in_block_comment.*) {
            if (i + 1 < line.len and line[i] == '*' and line[i + 1] == '/') {
                in_block_comment.* = false;
                i += 2;
                scratch[out_len] = ' ';
                out_len += 1;
            } else {
                i += 1;
            }
            continue;
        }

        const c = line[i];
        if (!in_str) {
            if (i + 1 < line.len and c == '/' and line[i + 1] == '/') {
                break;
            }
            if (i + 1 < line.len and c == '/' and line[i + 1] == '*') {
                in_block_comment.* = true;
                i += 2;
                scratch[out_len] = ' ';
                out_len += 1;
                continue;
            }
            if (c == '"' or c == '\'') {
                in_str = true;
                str_quote = c;
                scratch[out_len] = c;
                out_len += 1;
                i += 1;
                continue;
            }
            scratch[out_len] = c;
            out_len += 1;
            i += 1;
        } else {
            if (c == '\\' and i + 1 < line.len) {
                if (keep_strings) {
                    scratch[out_len] = c;
                    out_len += 1;
                }
                i += 2;
                continue;
            }
            if (c == str_quote) {
                in_str = false;
                scratch[out_len] = c;
            } else {
                scratch[out_len] = if (keep_strings) c else ' ';
            }
            out_len += 1;
            i += 1;
        }
    }
    return scratch[0..out_len];
}

pub fn scanSourceText(
    allocator: std.mem.Allocator,
    file_path: []const u8,
    source: []const u8,
    out_fs: *finding.FindingSet,
) !usize {
    const is_zig = file_path.len > 4 and finding.eqlIgnoreCase(file_path[file_path.len - 4 ..], ".zig");
    const file_mentions_arm64 = std.mem.indexOf(u8, source, "__aarch64__") != null or
        std.mem.indexOf(u8, source, "_M_ARM64") != null or
        std.mem.indexOf(u8, source, "aarch64") != null;
    const file_has_atomics = std.mem.indexOf(u8, source, "std::atomic") != null or
        std.mem.indexOf(u8, source, "__atomic_") != null or
        std.mem.indexOf(u8, source, "atomic_load") != null or
        std.mem.indexOf(u8, source, "MemoryBarrier") != null or
        std.mem.indexOf(u8, source, "dmb ") != null;

    var in_block_comment = false;
    var scratch: [2048]u8 = undefined;
    var lines = std.mem.splitScalar(u8, source, '\n');
    var line_no: usize = 0;

    // Limit repetitive hits per rule inside one file to keep enterprise reports actionable
    var simd_hits: usize = 0;
    var x86_guard_emitted = false;
    var volatile_emitted = false;

    while (lines.next()) |raw_line| {
        line_no += 1;
        const clean = stripLineComment(raw_line, is_zig, &in_block_comment, &scratch);
        const trimmed = std.mem.trim(u8, clean, " \t\r");
        if (trimmed.len == 0) continue;

        // 1. x86 SIMD intrinsics & headers
        if (simd_hits < 3 and (std.mem.indexOf(u8, trimmed, "_mm_") != null or
            std.mem.indexOf(u8, trimmed, "_mm256_") != null or
            std.mem.indexOf(u8, trimmed, "_mm512_") != null or
            std.mem.indexOf(u8, trimmed, "<immintrin.h>") != null or
            std.mem.indexOf(u8, trimmed, "<emmintrin.h>") != null or
            std.mem.indexOf(u8, trimmed, "<xmmintrin.h>") != null or
            std.mem.indexOf(u8, trimmed, "__m128") != null or
            std.mem.indexOf(u8, trimmed, "__m256") != null))
        {
            simd_hits += 1;
            const detail = try std.fmt.allocPrint(allocator, "{s}:{d}: x86 SIMD intrinsic/header usage: '{s}'", .{
                finding.basename(file_path),
                line_no,
                trimmed[0..@min(trimmed.len, 96)],
            });
            defer allocator.free(detail);
            try out_fs.add(.{
                .rule_id = "SO-PORT-001",
                .artifact = file_path,
                .file_offset = @intCast(line_no),
                .detail = detail,
            });
        }

        // 2. x86 CPU/TSC intrinsics
        if (std.mem.indexOf(u8, trimmed, "__rdtsc") != null or
            std.mem.indexOf(u8, trimmed, "__cpuid") != null or
            std.mem.indexOf(u8, trimmed, "_xgetbv") != null or
            std.mem.indexOf(u8, trimmed, "_BitScanForward") != null or
            std.mem.indexOf(u8, trimmed, "_BitScanReverse") != null)
        {
            const detail = try std.fmt.allocPrint(allocator, "{s}:{d}: x86 CPU/TSC intrinsic: '{s}'", .{
                finding.basename(file_path),
                line_no,
                trimmed[0..@min(trimmed.len, 96)],
            });
            defer allocator.free(detail);
            try out_fs.add(.{
                .rule_id = "SO-PORT-002",
                .artifact = file_path,
                .file_offset = @intCast(line_no),
                .detail = detail,
            });
        }

        // 3. Inline x86 assembly
        if ((std.mem.indexOf(u8, trimmed, "__asm__") != null or
            std.mem.indexOf(u8, trimmed, "__asm") != null or
            std.mem.indexOf(u8, trimmed, "asm volatile") != null) and
            (std.mem.indexOf(u8, trimmed, "%rax") != null or
                std.mem.indexOf(u8, trimmed, "%eax") != null or
                std.mem.indexOf(u8, trimmed, "cmpxchg") != null or
                std.mem.indexOf(u8, trimmed, "mfence") != null or
                std.mem.indexOf(u8, trimmed, "pause") != null or
                std.mem.indexOf(u8, trimmed, "lock ") != null or
                std.mem.indexOf(u8, trimmed, "rdtsc") != null or
                std.mem.indexOf(u8, trimmed, "cpuid") != null))
        {
            const detail = try std.fmt.allocPrint(allocator, "{s}:{d}: inline x86 assembly instruction block", .{
                finding.basename(file_path),
                line_no,
            });
            defer allocator.free(detail);
            try out_fs.add(.{
                .rule_id = "SO-PORT-003",
                .artifact = file_path,
                .file_offset = @intCast(line_no),
                .detail = detail,
            });
        }

        // 4. Asymmetric x86 arch macro guard without ARM64 fallback in file
        if (!x86_guard_emitted and !file_mentions_arm64 and
            std.mem.startsWith(u8, trimmed, "#if") and
            (std.mem.indexOf(u8, trimmed, "_M_X64") != null or
                std.mem.indexOf(u8, trimmed, "__x86_64__") != null or
                std.mem.indexOf(u8, trimmed, "_M_IX86") != null or
                std.mem.indexOf(u8, trimmed, "__i386__") != null))
        {
            x86_guard_emitted = true;
            const detail = try std.fmt.allocPrint(allocator, "{s}:{d}: x86 preprocessor guard '{s}' has no matching _M_ARM64/__aarch64__ branch in file", .{
                finding.basename(file_path),
                line_no,
                trimmed[0..@min(trimmed.len, 80)],
            });
            defer allocator.free(detail);
            try out_fs.add(.{
                .rule_id = "SO-PORT-004",
                .artifact = file_path,
                .file_offset = @intCast(line_no),
                .detail = detail,
            });
        }

        // 5. Weak-memory volatile synchronization hazard
        if (!volatile_emitted and !file_has_atomics and
            std.mem.indexOf(u8, trimmed, "volatile ") != null and
            (std.mem.indexOf(u8, trimmed, "flag") != null or
                std.mem.indexOf(u8, trimmed, "ready") != null or
                std.mem.indexOf(u8, trimmed, "lock") != null or
                std.mem.indexOf(u8, trimmed, "spin") != null or
                std.mem.indexOf(u8, trimmed, "done") != null))
        {
            volatile_emitted = true;
            const detail = try std.fmt.allocPrint(allocator, "{s}:{d}: 'volatile' synchronization variable may break under ARM64 weak memory ordering", .{
                finding.basename(file_path),
                line_no,
            });
            defer allocator.free(detail);
            try out_fs.add(.{
                .rule_id = "SO-PORT-005",
                .confidence = .medium,
                .artifact = file_path,
                .file_offset = @intCast(line_no),
                .detail = detail,
            });
        }

        // 6. Plain char signedness hazard
        if (std.mem.indexOf(u8, trimmed, "char ") != null and
            std.mem.indexOf(u8, trimmed, "signed char") == null and
            (std.mem.indexOf(u8, trimmed, "< 0") != null or std.mem.indexOf(u8, trimmed, "== -1") != null))
        {
            const detail = try std.fmt.allocPrint(allocator, "{s}:{d}: plain 'char' compared against negative value (< 0 or == -1); unsigned on Linux AArch64", .{
                finding.basename(file_path),
                line_no,
            });
            defer allocator.free(detail);
            try out_fs.add(.{
                .rule_id = "SO-PORT-006",
                .confidence = .medium,
                .artifact = file_path,
                .file_offset = @intCast(line_no),
                .detail = detail,
            });
        }

        // 7. long double precision assumption
        if (std.mem.indexOf(u8, trimmed, "long double") != null) {
            const detail = try std.fmt.allocPrint(allocator, "{s}:{d}: 'long double' differs across x64 (80-bit), Windows ARM64 (64-bit), and Linux AArch64 (128-bit)", .{
                finding.basename(file_path),
                line_no,
            });
            defer allocator.free(detail);
            try out_fs.add(.{
                .rule_id = "SO-PORT-007",
                .confidence = .low,
                .artifact = file_path,
                .file_offset = @intCast(line_no),
                .detail = detail,
            });
        }
    }

    return line_no;
}

pub fn scanBinaryPortability(
    allocator: std.mem.Allocator,
    path: []const u8,
    bytes: []const u8,
    out_fs: *finding.FindingSet,
) !void {
    var img = try binary.parseBinary(allocator, bytes);
    defer img.deinit();

    const text = img.findCodeSection() orelse return;
    if (@as(u64, text.raw_offset) + text.raw_size > bytes.len or text.raw_size == 0) return;
    const code = bytes[text.raw_offset .. text.raw_offset + text.raw_size];

    if (img.isArm64()) {
        var ll_sc: usize = 0;
        var barriers: usize = 0;
        var rcpc_lse: usize = 0;
        var off: usize = 0;
        while (off + 4 <= code.len) : (off += 4) {
            const insn = std.mem.readInt(u32, code[off..][0..4], .little);
            switch (arm64_isa.decode(insn).class) {
                .ldxr, .stxr => ll_sc += 1,
                .barrier => barriers += 1,
                .lse_atomic, .rcpc_atomic => rcpc_lse += 1,
                else => {},
            }
        }
        if (ll_sc >= 6 and barriers == 0 and rcpc_lse == 0) {
            const detail = try std.fmt.allocPrint(allocator, "AArch64 binary contains {d} LL/SC ops with 0 DMB barriers or LDAR/STLR acquire-release pairs", .{ll_sc});
            defer allocator.free(detail);
            try out_fs.add(.{
                .rule_id = "SO-PORT-008",
                .confidence = .medium,
                .artifact = path,
                .detail = detail,
            });
        }
    } else if (img.machine == .amd64) {
        var lock_ops: usize = 0;
        var tsc_cpuid_ops: usize = 0;
        var off: usize = 0;
        const limit = @min(code.len, 2 * 1024 * 1024);
        while (off < limit) {
            const insn = cfg.decodeX64Insn(code[off..]) orelse {
                off += 1;
                continue;
            };
            const raw = code[off .. off + insn.len];
            if (raw.len >= 1 and raw[0] == 0xF0) lock_ops += 1;
            if (raw.len >= 2 and raw[0] == 0x0F and (raw[1] == 0x31 or raw[1] == 0xA2)) tsc_cpuid_ops += 1;
            off += insn.len;
        }
        if (lock_ops > 0 or tsc_cpuid_ops > 0) {
            const detail = try std.fmt.allocPrint(allocator, "x86_64 binary uses {d} LOCK-prefixed ops and {d} RDTSC/CPUID insns requiring weak-memory audit during ARM64 port", .{
                lock_ops,
                tsc_cpuid_ops,
            });
            defer allocator.free(detail);
            try out_fs.add(.{
                .rule_id = "SO-PORT-008",
                .confidence = .high,
                .artifact = path,
                .detail = detail,
            });
        }
    }
}

fn scanDirRecursive(
    io: std.Io,
    allocator: std.mem.Allocator,
    dir_path: []const u8,
    depth: usize,
    summary: *PortScanSummary,
    out_fs: *finding.FindingSet,
) !void {
    if (depth > 8 or summary.files_scanned > 2000) return;

    var dir = std.Io.Dir.cwd().openDir(io, dir_path, .{ .iterate = true }) catch return;
    defer dir.close(io);

    var it = dir.iterate();
    while (it.next(io) catch null) |entry| {
        if (summary.files_scanned > 2000) break;
        const child = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ dir_path, entry.name });
        defer allocator.free(child);

        if (entry.kind == .directory) {
            if (!isIgnoredDirName(entry.name)) {
                try scanDirRecursive(io, allocator, child, depth + 1, summary, out_fs);
            }
        } else if (entry.kind == .file and isSupportedSourceExt(entry.name)) {
            const src = std.Io.Dir.cwd().readFileAlloc(io, child, allocator, .limited(8 * 1024 * 1024)) catch continue;
            defer allocator.free(src);
            summary.files_scanned += 1;
            summary.lines_scanned += try scanSourceText(allocator, child, src, out_fs);
        }
    }
}

pub fn runPortscanCommand(io: std.Io, allocator: std.mem.Allocator, args: []const []const u8) !u8 {
    if (args.len == 0) {
        std.debug.print("Usage: snap-oracle portscan <source_dir|source_file|binary> [--format text|json|sarif|junit|gha] [--out <file>] [--fail-on <sev>]\n", .{});
        return 2;
    }

    var target: ?[]const u8 = null;
    var fmt: report.ReportFormat = .text;
    var out_path: ?[]const u8 = null;
    var fail_on: finding.Severity = .high;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--format") and i + 1 < args.len) {
            i += 1;
            fmt = report.ReportFormat.fromString(args[i]) orelse .text;
        } else if (std.mem.eql(u8, a, "--out") and i + 1 < args.len) {
            i += 1;
            out_path = args[i];
        } else if (std.mem.eql(u8, a, "--fail-on") and i + 1 < args.len) {
            i += 1;
            fail_on = finding.Severity.fromString(args[i]) orelse .high;
        } else if (target == null and a.len > 0 and a[0] != '-') {
            target = a;
        }
    }

    const path = target orelse {
        std.debug.print("Usage: snap-oracle portscan <source_dir|source_file|binary>\n", .{});
        return 2;
    };

    var fs = finding.FindingSet.init(allocator);
    defer fs.deinit();

    var summary = PortScanSummary{};
    var bin_bytes: ?[]u8 = null;
    defer if (bin_bytes) |b| allocator.free(b);

    // Check if path opens cleanly as a directory first; otherwise read as a file (source or binary)
    if (std.Io.Dir.cwd().openDir(io, path, .{ .iterate = true })) |d| {
        var dir = d;
        dir.close(io);
        try scanDirRecursive(io, allocator, path, 0, &summary, &fs);
    } else |_| {
        const raw = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(64 * 1024 * 1024));
        if (isBinaryMagic(raw)) {
            bin_bytes = raw;
            summary.binaries_scanned = 1;
            try scanBinaryPortability(allocator, path, raw, &fs);
        } else {
            defer allocator.free(raw);
            summary.files_scanned = 1;
            summary.lines_scanned = try scanSourceText(allocator, path, raw, &fs);
        }
    }

    if (fmt == .text) {
        std.debug.print(
            \\=== x64 -> ARM64 Porting Hazard Scanner: {s} ===
            \\Source Files Scanned: {d} ({d} lines) | Binaries Scanned: {d}
            \\
        , .{ path, summary.files_scanned, summary.lines_scanned, summary.binaries_scanned });
    }

    try report.emitOrPrint(io, allocator, &fs, fmt, out_path, bin_bytes);
    return fs.exitCode(fail_on);
}
