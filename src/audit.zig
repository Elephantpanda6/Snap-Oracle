const std = @import("std");
const binary = @import("binary.zig");
const macho = @import("macho_arm64.zig");
const pe = @import("pe.zig");
const cfg = @import("cfg.zig");
const arm64_isa = @import("arm64_isa.zig");
const finding = @import("finding.zig");
const report_mod = @import("report.zig");
const hardening = @import("hardening.zig");

pub const FuzzCandidate = struct {
    name: []u8,
    rva: u32,
    bb_count: usize,
    branch_count: usize,
    score: usize,
};

pub const AuditReport = struct {
    format: binary.BinaryFormat,
    machine: pe.Machine,
    is_arm64: bool,
    is_arm64ec: bool,
    image_base: u64,
    size_of_image: u32,
    min_segment_align: u32,
    function_count: usize,
    export_count: usize,
    basic_block_count: usize,
    total_insns: usize,
    bti_count: usize,
    pac_count: usize,
    xpac_count: usize,
    ldxr_stxr_count: usize,
    exclusive_zone_count: usize,
    lse_atomic_count: usize,
    rcpc_atomic_count: usize,
    neon_count: usize,
    sve_count: usize,
    sme_count: usize,
    fp_scalar_count: usize,
    mov_wide_count: usize,
    cmp_imm_count: usize,
    brk_udf_count: usize,
    writable_data_bytes: usize,
    has_pac_metadata: bool,
    has_bti_metadata: bool,
    compat_snapdragon_x1: bool,
    compat_snapdragon_x2_n1x: bool,
    compat_apple_macos: bool,
    compat_linux_4k: bool,
    compat_asahi_16k: bool,
    top_candidates: []FuzzCandidate,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *AuditReport) void {
        for (self.top_candidates) |c| {
            self.allocator.free(c.name);
        }
        self.allocator.free(self.top_candidates);
    }
};

/// Analyze any PE32+, ELF64, or 64-bit Mach-O binary for ARM64 instruction features,
/// PAC/BTI hardening, exclusive monitor hazards, ARM laptop ISA compatibility, and fuzzable exports.
pub fn analyzeArm64Binary(allocator: std.mem.Allocator, raw_bytes: []const u8) !AuditReport {
    const bytes = macho.unwrapFatSlice(raw_bytes);
    var img = try binary.parseBinary(allocator, bytes);
    defer img.deinit();

    const wsecs = try img.writableDataSections(allocator);
    defer allocator.free(wsecs);
    var writable_bytes: usize = 0;
    for (wsecs) |s| writable_bytes += s.virtual_size;

    var report = AuditReport{
        .format = img.format,
        .machine = img.machine,
        .is_arm64 = img.isArm64(),
        .is_arm64ec = img.is_arm64ec,
        .image_base = img.image_base,
        .size_of_image = img.size_of_image,
        .min_segment_align = img.min_segment_align,
        .function_count = img.functions.len,
        .export_count = img.exports.len,
        .basic_block_count = 0,
        .total_insns = 0,
        .bti_count = 0,
        .pac_count = 0,
        .xpac_count = 0,
        .ldxr_stxr_count = 0,
        .exclusive_zone_count = 0,
        .lse_atomic_count = 0,
        .rcpc_atomic_count = 0,
        .neon_count = 0,
        .sve_count = 0,
        .sme_count = 0,
        .fp_scalar_count = 0,
        .mov_wide_count = 0,
        .cmp_imm_count = 0,
        .brk_udf_count = 0,
        .writable_data_bytes = writable_bytes,
        .has_pac_metadata = img.has_pac,
        .has_bti_metadata = img.has_bti,
        .compat_snapdragon_x1 = false,
        .compat_snapdragon_x2_n1x = false,
        .compat_apple_macos = false,
        .compat_linux_4k = false,
        .compat_asahi_16k = false,
        .top_candidates = &.{},
        .allocator = allocator,
    };

    var cand_list = std.ArrayList(FuzzCandidate).empty;
    errdefer {
        for (cand_list.items) |c| allocator.free(c.name);
        cand_list.deinit(allocator);
    }

    if (img.findCodeSection()) |text_sec| {
        const raw_off: usize = text_sec.raw_offset;
        if (raw_off < bytes.len and text_sec.raw_size > 0) {
            const avail = @min(@as(usize, text_sec.raw_size), bytes.len - raw_off);
            const span: u32 = if (text_sec.virtual_size == 0) text_sec.raw_size else @min(text_sec.virtual_size, text_sec.raw_size);
            const code_len = @min(avail, @as(usize, span));
            const code = bytes[raw_off .. raw_off + code_len];
            const text_begin = text_sec.virtual_address;
            const text_end = text_begin +| @as(u32, @intCast(code_len));

            if (img.isArm64()) {
                const zones = try arm64_isa.findExclusiveZones(allocator, code, text_begin);
                defer allocator.free(zones);
                report.exclusive_zone_count = zones.len;

                var off: usize = 0;
                while (off + 4 <= code.len) : (off += 4) {
                    const insn = std.mem.readInt(u32, code[off..][0..4], .little);
                    const d = arm64_isa.decode(insn);
                    report.total_insns += 1;
                    switch (d.class) {
                        .bti => report.bti_count += 1,
                        .pac_sign, .pac_auth, .retaa, .retab, .braa, .blraa => report.pac_count += 1,
                        .xpac => report.xpac_count += 1,
                        .ldxr, .stxr => report.ldxr_stxr_count += 1,
                        .lse_atomic => report.lse_atomic_count += 1,
                        .rcpc_atomic => report.rcpc_atomic_count += 1,
                        .neon_simd => report.neon_count += 1,
                        .sve => report.sve_count += 1,
                        .sme => report.sme_count += 1,
                        .fp_scalar => report.fp_scalar_count += 1,
                        .mov_wide => report.mov_wide_count += 1,
                        .cmp_imm => report.cmp_imm_count += 1,
                        .brk, .udf, .hlt => report.brk_udf_count += 1,
                        else => {},
                    }
                }
            }

            const bbs = cfg.decodeAllTextBasicBlocks(allocator, bytes) catch &[_]cfg.BasicBlock{};
            defer if (bbs.len > 0) allocator.free(bbs);
            report.basic_block_count = bbs.len;

            // Score exported functions by basic-block density inside their function span.
            const max_cands = @min(img.exports.len, 64);
            for (img.exports[0..max_cands]) |exp| {
                if (exp.is_forwarded or exp.rva < text_begin or exp.rva >= text_end) continue;
                var fn_end = @min(exp.rva +| 4096, text_end);
                for (img.functions) |f| {
                    if (exp.rva >= f.begin_rva and exp.rva < f.end_rva) {
                        fn_end = @min(f.end_rva, text_end);
                        break;
                    }
                }
                const f_bbs = switch (img.machine) {
                    .arm64, .arm64ec => try cfg.decodeArm64BasicBlocksEx(allocator, code, text_begin, exp.rva, fn_end, true),
                    .amd64 => try cfg.decodeX64BasicBlocksFull(allocator, code, text_begin, exp.rva, fn_end),
                    else => continue,
                };
                defer allocator.free(f_bbs);

                var branch_cnt: usize = 0;
                if (img.isArm64()) {
                    const start_off = @as(usize, exp.rva - text_begin);
                    const end_off = @min(code.len, @as(usize, fn_end - text_begin));
                    var p = start_off;
                    while (p + 4 <= end_off) : (p += 4) {
                        const d = arm64_isa.decode(std.mem.readInt(u32, code[p..][0..4], .little));
                        if (d.target_delta != null or d.class == .cmp_imm) branch_cnt += 1;
                    }
                }
                const score = f_bbs.len * 10 + branch_cnt * 3;
                const dup_name = try allocator.dupe(u8, exp.name);
                errdefer allocator.free(dup_name);
                try cand_list.append(allocator, .{
                    .name = dup_name,
                    .rva = exp.rva,
                    .bb_count = f_bbs.len,
                    .branch_count = branch_cnt,
                    .score = score,
                });
            }
        }
    }

    // Sort candidates descending by score and keep top 8
    std.mem.sort(FuzzCandidate, cand_list.items, {}, struct {
        fn lessThan(_: void, a: FuzzCandidate, b: FuzzCandidate) bool {
            return a.score > b.score;
        }
    }.lessThan);
    if (cand_list.items.len > 8) {
        for (cand_list.items[8..]) |c| allocator.free(c.name);
        cand_list.shrinkRetainingCapacity(8);
    }
    report.top_candidates = try cand_list.toOwnedSlice(allocator);

    // Compute ARM64 laptop/OS compatibility matrix
    if (img.format == .pe32plus and img.isArm64()) {
        report.compat_snapdragon_x1 = (report.sve_count == 0 and report.sme_count == 0);
        report.compat_snapdragon_x2_n1x = true;
    } else if (img.format == .elf64 and img.isArm64()) {
        report.compat_linux_4k = true;
        report.compat_asahi_16k = (img.min_segment_align >= 16384);
    } else if (img.format == .macho64 and img.isArm64()) {
        report.compat_apple_macos = true;
    }

    return report;
}

pub fn runAuditCommand(io: std.Io, allocator: std.mem.Allocator, path: []const u8) !void {
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(256 * 1024 * 1024));
    defer allocator.free(bytes);

    var r = try analyzeArm64Binary(allocator, bytes);
    defer r.deinit();

    std.debug.print(
        \\Snap-Oracle ARM64 Binary Readiness & Hardening Audit
        \\  File:              {s}
        \\  Format / Machine:  {s} / {s} (0x{x:0>4})
        \\  ImageBase / Size:  0x{x} / {d} bytes (min_align={d}B)
        \\  Functions / BBs:   {d} funcs / {d} basic blocks
        \\  Writable State:    {d} bytes (snapshot-restorable .data/.bss)
        \\
    , .{
        path,
        @tagName(r.format),
        @tagName(r.machine),
        @intFromEnum(r.machine),
        r.image_base,
        r.size_of_image,
        r.min_segment_align,
        r.function_count,
        r.basic_block_count,
        r.writable_data_bytes,
    });

    if (r.is_arm64) {
        std.debug.print(
            \\  AArch64 ISA Telemetry ({d} instructions decoded):
            \\    Hardening:       PAC={d} XPAC={d} BTI={d} (metadata: pac={any}, bti={any})
            \\    Atomics:         LSE={d} RCPC={d} LL/SC(LDXR/STXR)={d} (protected_zones={d})
            \\    Vector/Math:     NEON={d} FP={d} SVE={d} SME={d}
            \\    Magic/Compare:   MOVZ/MOVK/MOVN={d} CMP_IMM={d} BRK/UDF/HLT={d}
            \\  ARM64 Laptop Compatibility Matrix:
            \\    Snapdragon X1 (Elite/Plus, ARMv8.7): {any}
            \\    Snapdragon X2 / NVIDIA N1X (ARMv9):  {any}
            \\    Apple M1-M4 macOS (16KB Mach-O):     {any}
            \\    Linux ARM64 4KB (Ubuntu/Kompanio):   {any}
            \\    Asahi Linux 16KB (Apple M1-M4):      {any}
            \\
        , .{
            r.total_insns,
            r.pac_count,
            r.xpac_count,
            r.bti_count,
            r.has_pac_metadata,
            r.has_bti_metadata,
            r.lse_atomic_count,
            r.rcpc_atomic_count,
            r.ldxr_stxr_count,
            r.exclusive_zone_count,
            r.neon_count,
            r.fp_scalar_count,
            r.sve_count,
            r.sme_count,
            r.mov_wide_count,
            r.cmp_imm_count,
            r.brk_udf_count,
            r.compat_snapdragon_x1,
            r.compat_snapdragon_x2_n1x,
            r.compat_apple_macos,
            r.compat_linux_4k,
            r.compat_asahi_16k,
        });
    } else {
        std.debug.print("  Note: Non-ARM64 binary ({s}); ARM64 ISA audit skipped. Use `fuzz` or cross-compile target to `aarch64-windows-gnu` for full ARM64 telemetry.\n", .{@tagName(r.machine)});
    }

    if (r.top_candidates.len > 0) {
        std.debug.print("  Top Fuzzable Exports ({d}):\n", .{r.top_candidates.len});
        for (r.top_candidates) |c| {
            std.debug.print("    - {s:<24} rva=0x{x:0>6} bbs={d:<4} branches={d:<4} score={d}\n", .{
                c.name, c.rva, c.bb_count, c.branch_count, c.score,
            });
        }
    }
}

pub fn runAuditCommandEx(io: std.Io, allocator: std.mem.Allocator, args: []const []const u8) !u8 {
    if (args.len == 0) {
        std.debug.print("Usage: snap-oracle audit <binary> [--format text|json|sarif|junit|gha] [--out <file>] [--fail-on <sev>]\n", .{});
        return 2;
    }

    var bin_path: ?[]const u8 = null;
    var fmt: report_mod.ReportFormat = .text;
    var out_path: ?[]const u8 = null;
    var fail_on: finding.Severity = .high;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--format") and i + 1 < args.len) {
            i += 1;
            fmt = report_mod.ReportFormat.fromString(args[i]) orelse .text;
        } else if (std.mem.eql(u8, a, "--out") and i + 1 < args.len) {
            i += 1;
            out_path = args[i];
        } else if (std.mem.eql(u8, a, "--fail-on") and i + 1 < args.len) {
            i += 1;
            fail_on = finding.Severity.fromString(args[i]) orelse .high;
        } else if (bin_path == null and a.len > 0 and a[0] != '-') {
            bin_path = a;
        }
    }

    const path = bin_path orelse {
        std.debug.print("Usage: snap-oracle audit <binary> [--format text|json|sarif|junit|gha] [--out <file>]\n", .{});
        return 2;
    };

    if (fmt == .text and out_path == null) {
        try runAuditCommand(io, allocator, path);
        return 0;
    }

    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(256 * 1024 * 1024));
    defer allocator.free(bytes);

    var fs = finding.FindingSet.init(allocator);
    defer fs.deinit();
    _ = try hardening.auditHardening(allocator, path, bytes, .baseline, &fs);
    try report_mod.emitOrPrint(io, allocator, &fs, fmt, out_path, bytes);
    return fs.exitCode(fail_on);
}

test "audit analyzes ARM64 PE32+ image and flags BTI, PAC, LSE, CMP" {
    var raw: [1024]u8 = @splat(0);
    raw[0] = 'M';
    raw[1] = 'Z';
    std.mem.writeInt(u32, raw[0x3C..][0..4], 0x80, .little);
    @memcpy(raw[0x80..0x84], "PE\x00\x00");
    std.mem.writeInt(u16, raw[0x84..][0..2], 0xAA64, .little);
    std.mem.writeInt(u16, raw[0x86..][0..2], 1, .little);
    std.mem.writeInt(u16, raw[0x94..][0..2], 240, .little);
    std.mem.writeInt(u16, raw[0x98..][0..2], 0x020B, .little);
    std.mem.writeInt(u32, raw[0x98 + 56 ..][0..4], 0x2000, .little);
    std.mem.writeInt(u32, raw[0x98 + 108 ..][0..4], 16, .little);

    // .text at 0x188
    @memcpy(raw[0x188 .. 0x188 + 5], ".text");
    std.mem.writeInt(u32, raw[0x188 + 8 ..][0..4], 20, .little);
    std.mem.writeInt(u32, raw[0x188 + 12 ..][0..4], 0x1000, .little);
    std.mem.writeInt(u32, raw[0x188 + 16 ..][0..4], 20, .little);
    std.mem.writeInt(u32, raw[0x188 + 20 ..][0..4], 0x200, .little);
    std.mem.writeInt(u32, raw[0x188 + 36 ..][0..4], pe.IMAGE_SCN_MEM_READ | pe.IMAGE_SCN_MEM_EXECUTE, .little);

    // 5 ARM64 instructions at 0x200: bti c, paciasp, ldaddal, cmp imm, retaa
    const insns = [_]u32{ 0xD503_245F, 0xD503_233F, 0xB8E0_0041, 0x7101_083F, 0xD65F_0BFF };
    for (insns, 0..) |w, idx| {
        std.mem.writeInt(u32, raw[0x200 + idx * 4 ..][0..4], w, .little);
    }

    var rep = try analyzeArm64Binary(std.testing.allocator, &raw);
    defer rep.deinit();

    try std.testing.expect(rep.is_arm64);
    try std.testing.expectEqual(@as(usize, 5), rep.total_insns);
    try std.testing.expectEqual(@as(usize, 1), rep.bti_count);
    try std.testing.expectEqual(@as(usize, 2), rep.pac_count);
    try std.testing.expectEqual(@as(usize, 1), rep.lse_atomic_count);
    try std.testing.expectEqual(@as(usize, 1), rep.cmp_imm_count);
    try std.testing.expect(rep.compat_snapdragon_x1);
    try std.testing.expect(rep.compat_snapdragon_x2_n1x);
}
