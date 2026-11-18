const std = @import("std");
const binary = @import("binary.zig");
const pe = @import("pe.zig");
const arm64_isa = @import("arm64_isa.zig");
const finding = @import("finding.zig");
const report = @import("report.zig");

pub const SegmentInfo = struct {
    name: []const u8,
    vaddr: u64,
    offset: u64,
    memsz: u64,
    filesz: u64,
    p_align: u64,
    writable: bool,
    executable: bool,
};

pub const PageVerdict = enum {
    pass,
    warn,
    fail,

    pub fn toString(self: PageVerdict) []const u8 {
        return switch (self) {
            .pass => "PASS",
            .warn => "WARN",
            .fail => "FAIL",
        };
    }
};

pub const TargetResult = struct {
    page_size: u32,
    verdict: PageVerdict,
    alignment_failures: usize,
    congruence_failures: usize,
    wx_overlaps: usize,
};

pub const PageSizeReport = struct {
    format: binary.BinaryFormat,
    machine: pe.Machine,
    pe_section_align: u32,
    pe_file_align: u32,
    hardcoded_4k_hits: usize,
    first_4k_rva: ?u32,
    targets: [3]TargetResult,
};

fn alignDown(val: u64, p: u64) u64 {
    return val & ~(p - 1);
}

fn alignUp(val: u64, p: u64) u64 {
    return (val +| (p - 1)) & ~(p - 1);
}

fn extractSegments(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    img: *const binary.BinaryImage,
) !struct { segs: []SegmentInfo, pe_sec_align: u32, pe_file_align: u32 } {
    var list = std.ArrayList(SegmentInfo).empty;
    errdefer list.deinit(allocator);
    var pe_sec_align: u32 = 4096;
    var pe_file_align: u32 = 512;

    switch (img.format) {
        .elf64 => {
            if (bytes.len >= 64) {
                const e_phoff = std.mem.readInt(u64, bytes[32..40], .little);
                const e_phentsize = std.mem.readInt(u16, bytes[54..56], .little);
                const e_phnum = @min(std.mem.readInt(u16, bytes[56..58], .little), 256);
                var i: u16 = 0;
                while (i < e_phnum) : (i += 1) {
                    const off = e_phoff + @as(u64, i) * e_phentsize;
                    if (off + 56 > bytes.len or e_phentsize < 56) break;
                    const ph = bytes[@intCast(off)..];
                    const p_type = std.mem.readInt(u32, ph[0..4], .little);
                    if (p_type != 1) continue; // PT_LOAD
                    const p_flags = std.mem.readInt(u32, ph[4..8], .little);
                    const p_offset = std.mem.readInt(u64, ph[8..16], .little);
                    const p_vaddr = std.mem.readInt(u64, ph[16..24], .little);
                    const p_filesz = std.mem.readInt(u64, ph[32..40], .little);
                    const p_memsz = std.mem.readInt(u64, ph[40..48], .little);
                    const p_align = std.mem.readInt(u64, ph[48..56], .little);
                    try list.append(allocator, .{
                        .name = "PT_LOAD",
                        .vaddr = p_vaddr,
                        .offset = p_offset,
                        .memsz = p_memsz,
                        .filesz = p_filesz,
                        .p_align = if (p_align == 0) 1 else p_align,
                        .writable = (p_flags & 2) != 0,
                        .executable = (p_flags & 1) != 0,
                    });
                }
            }
        },
        .macho64 => {
            if (bytes.len >= 32 and std.mem.readInt(u32, bytes[0..4], .little) == 0xFEED_FACF) {
                const ncmds = @min(std.mem.readInt(u32, bytes[16..20], .little), 4096);
                var off: usize = 32;
                var i: u32 = 0;
                while (i < ncmds) : (i += 1) {
                    if (off + 8 > bytes.len) break;
                    const cmd = std.mem.readInt(u32, bytes[off..][0..4], .little);
                    const cmdsize = std.mem.readInt(u32, bytes[off + 4 ..][0..4], .little);
                    if (cmdsize < 8 or off + cmdsize > bytes.len) break;
                    if (cmd == 0x19 and cmdsize >= 72) { // LC_SEGMENT_64
                        const segname_raw = bytes[off + 8 .. off + 24];
                        const z = std.mem.indexOfScalar(u8, segname_raw, 0) orelse 16;
                        const vmaddr = std.mem.readInt(u64, bytes[off + 24 ..][0..8], .little);
                        const vmsize = std.mem.readInt(u64, bytes[off + 32 ..][0..8], .little);
                        const fileoff = std.mem.readInt(u64, bytes[off + 40 ..][0..8], .little);
                        const filesize = std.mem.readInt(u64, bytes[off + 48 ..][0..8], .little);
                        const initprot = std.mem.readInt(u32, bytes[off + 60 ..][0..4], .little);
                        // Skip __PAGEZERO guard segment
                        if (!(initprot == 0 and fileoff == 0 and vmaddr == 0)) {
                            const eff_align: u64 = if ((vmaddr % 16384) == 0 and (fileoff % 16384) == 0) 16384 else 4096;
                            try list.append(allocator, .{
                                .name = segname_raw[0..z],
                                .vaddr = vmaddr,
                                .offset = fileoff,
                                .memsz = vmsize,
                                .filesz = filesize,
                                .p_align = eff_align,
                                .writable = (initprot & 2) != 0,
                                .executable = (initprot & 4) != 0,
                            });
                        }
                    }
                    off += cmdsize;
                }
            }
        },
        .pe32plus => {
            if (bytes.len >= 0x40) {
                const e_lfanew = std.mem.readInt(u32, bytes[0x3C..][0..4], .little);
                const opt_off = @as(u64, e_lfanew) + 24;
                if (opt_off + 40 <= bytes.len) {
                    pe_sec_align = std.mem.readInt(u32, bytes[@intCast(opt_off + 32)..][0..4], .little);
                    pe_file_align = std.mem.readInt(u32, bytes[@intCast(opt_off + 36)..][0..4], .little);
                }
            }
            for (img.sections) |sec| {
                try list.append(allocator, .{
                    .name = sec.nameSlice(),
                    .vaddr = sec.virtual_address,
                    .offset = sec.raw_offset,
                    .memsz = sec.virtual_size,
                    .filesz = sec.raw_size,
                    .p_align = pe_sec_align,
                    .writable = (sec.characteristics & pe.IMAGE_SCN_MEM_WRITE) != 0,
                    .executable = (sec.characteristics & pe.IMAGE_SCN_MEM_EXECUTE) != 0,
                });
            }
        },
    }

    // Sort segments by virtual address for adjacent overlap analysis
    const owned = try list.toOwnedSlice(allocator);
    std.mem.sort(SegmentInfo, owned, {}, struct {
        fn lessThan(_: void, a: SegmentInfo, b: SegmentInfo) bool {
            return a.vaddr < b.vaddr;
        }
    }.lessThan);

    return .{ .segs = owned, .pe_sec_align = pe_sec_align, .pe_file_align = pe_file_align };
}

pub fn auditPageSize(
    allocator: std.mem.Allocator,
    artifact_path: []const u8,
    bytes: []const u8,
    out_fs: *finding.FindingSet,
) !PageSizeReport {
    var img = try binary.parseBinary(allocator, bytes);
    defer img.deinit();

    const seg_info = try extractSegments(allocator, bytes, &img);
    defer allocator.free(seg_info.segs);

    // Scan AArch64 executable sections for hardcoded 4K (0x1000 / 0xFFF) assumptions
    var hits_4k: usize = 0;
    var first_4k_rva: ?u32 = null;
    if (img.isArm64()) {
        for (img.sections) |sec| {
            if ((sec.characteristics & pe.IMAGE_SCN_MEM_EXECUTE) == 0) continue;
            if (@as(u64, sec.raw_offset) + sec.raw_size > bytes.len) continue;
            const code = bytes[sec.raw_offset .. sec.raw_offset + sec.raw_size];
            var off: usize = 0;
            while (off + 4 <= code.len) : (off += 4) {
                const insn = std.mem.readInt(u32, code[off..][0..4], .little);
                if (arm64_isa.isHardcoded4kPageImm(insn)) {
                    hits_4k += 1;
                    if (first_4k_rva == null) {
                        first_4k_rva = sec.virtual_address +| @as(u32, @intCast(off));
                    }
                }
            }
        }
    }

    if (hits_4k > 0) {
        const detail = try std.fmt.allocPrint(allocator, "{d} AArch64 instruction(s) reference 0x1000/0xFFF constants (first at 0x{x}); audit before 16K/64K deployment", .{
            hits_4k,
            first_4k_rva orelse 0,
        });
        defer allocator.free(detail);
        try out_fs.add(.{
            .rule_id = "SO-PAGE-004",
            .confidence = .medium,
            .artifact = artifact_path,
            .rva = first_4k_rva,
            .detail = detail,
        });
    }

    const targets_p = [_]u32{ 4096, 16384, 65536 };
    var target_results: [3]TargetResult = undefined;

    for (targets_p, 0..) |p_u32, tidx| {
        const p: u64 = p_u32;
        var align_fails: usize = 0;
        var cong_fails: usize = 0;
        var wx_overlaps: usize = 0;

        for (seg_info.segs, 0..) |seg, sidx| {
            if (seg.p_align < p) {
                align_fails += 1;
                if (p_u32 == 16384) {
                    const detail = try std.fmt.allocPrint(allocator, "{s} segment #{d} alignment {d} < {d} bytes (unsafe for 16K kernels: Apple Silicon / Android 15+)", .{
                        finding.basename(artifact_path),
                        sidx,
                        seg.p_align,
                        p_u32,
                    });
                    defer allocator.free(detail);
                    try out_fs.add(.{
                        .rule_id = "SO-PAGE-001",
                        .severity = if (img.format == .pe32plus) .low else .high,
                        .artifact = artifact_path,
                        .rva = @truncate(seg.vaddr),
                        .detail = detail,
                    });
                }
            }

            if (img.format != .pe32plus and seg.memsz > 0) {
                if ((seg.vaddr % p) != (seg.offset % p)) {
                    cong_fails += 1;
                    if (p_u32 == 16384) {
                        const detail = try std.fmt.allocPrint(allocator, "{s} segment {s} violates (vaddr 0x{x} % {d}) == (offset 0x{x} % {d})", .{
                            finding.basename(artifact_path),
                            seg.name,
                            seg.vaddr,
                            p_u32,
                            seg.offset,
                            p_u32,
                        });
                        defer allocator.free(detail);
                        try out_fs.add(.{
                            .rule_id = "SO-PAGE-002",
                            .artifact = artifact_path,
                            .rva = @truncate(seg.vaddr),
                            .detail = detail,
                        });
                    }
                }
            }

            if (sidx + 1 < seg_info.segs.len) {
                const next = seg_info.segs[sidx + 1];
                if ((seg.executable and next.writable) or (seg.writable and next.executable)) {
                    const prev_end = alignUp(seg.vaddr +| seg.memsz, p);
                    const next_start = alignDown(next.vaddr, p);
                    if (next_start < prev_end) {
                        wx_overlaps += 1;
                        if (p_u32 == 16384) {
                            const detail = try std.fmt.allocPrint(allocator, "W/X segments {s} and {s} share a {d}-byte virtual page boundary", .{
                                seg.name,
                                next.name,
                                p_u32,
                            });
                            defer allocator.free(detail);
                            try out_fs.add(.{
                                .rule_id = "SO-PAGE-003",
                                .artifact = artifact_path,
                                .rva = @truncate(next.vaddr),
                                .detail = detail,
                            });
                        }
                    }
                }
            }
        }

        const verdict: PageVerdict = if (cong_fails > 0 or align_fails > 0 or wx_overlaps > 0)
            .fail
        else if (p_u32 > 4096 and hits_4k > 0)
            .warn
        else
            .pass;

        target_results[tidx] = .{
            .page_size = p_u32,
            .verdict = verdict,
            .alignment_failures = align_fails,
            .congruence_failures = cong_fails,
            .wx_overlaps = wx_overlaps,
        };
    }

    return .{
        .format = img.format,
        .machine = img.machine,
        .pe_section_align = seg_info.pe_sec_align,
        .pe_file_align = seg_info.pe_file_align,
        .hardcoded_4k_hits = hits_4k,
        .first_4k_rva = first_4k_rva,
        .targets = target_results,
    };
}

pub fn runPagesizeCommand(io: std.Io, allocator: std.mem.Allocator, args: []const []const u8) !u8 {
    if (args.len == 0) {
        std.debug.print("Usage: snap-oracle pagesize <binary> [--fix-hints] [--format text|json|sarif|junit|gha] [--out <file>] [--fail-on <sev>]\n", .{});
        return 2;
    }

    var bin_path: ?[]const u8 = null;
    var fix_hints = false;
    var fmt: report.ReportFormat = .text;
    var out_path: ?[]const u8 = null;
    var fail_on: finding.Severity = .high;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--fix-hints")) {
            fix_hints = true;
        } else if (std.mem.eql(u8, a, "--format") and i + 1 < args.len) {
            i += 1;
            fmt = report.ReportFormat.fromString(args[i]) orelse .text;
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
        std.debug.print("Usage: snap-oracle pagesize <binary> [--fix-hints]\n", .{});
        return 2;
    };

    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(128 * 1024 * 1024));
    defer allocator.free(bytes);

    var fs = finding.FindingSet.init(allocator);
    defer fs.deinit();

    const res = try auditPageSize(allocator, path, bytes, &fs);

    if (fmt == .text) {
        std.debug.print(
            \\=== ARM64 Kernel Page-Size Readiness: {s} ({s}/{s}) ===
            \\Code 0x1000/0xFFF constants: {d}
            \\Page Size | Verdict | Align Fails | Congruence Fails | W^X Page Overlaps
            \\----------+---------+-------------+------------------+------------------
            \\
        , .{ finding.basename(path), @tagName(res.format), @tagName(res.machine), res.hardcoded_4k_hits });

        for (res.targets) |t| {
            std.debug.print(" {d:<7}  | {s:<7} | {d:<11} | {d:<16} | {d}\n", .{
                t.page_size,
                t.verdict.toString(),
                t.alignment_failures,
                t.congruence_failures,
                t.wx_overlaps,
            });
        }

        if (fix_hints) {
            std.debug.print(
                \\
                \\Toolchain Remediation Hints:
                \\  * Android NDK / Linux ELF (16K): -Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384 -Wl,-z,separate-code
                \\  * RHEL / Graviton 64K ELF:       -Wl,-z,max-page-size=65536 -Wl,-z,separate-code
                \\  * Windows PE (MSVC/LLD):         /ALIGN:16384 (for native 16K experiments; default 4K on Windows)
                \\  * Zig Build System:              exe.link_z_max_page_size = 16384
                \\
            , .{});
        }
        std.debug.print("\n", .{});
    }

    try report.emitOrPrint(io, allocator, &fs, fmt, out_path, bytes);
    return fs.exitCode(fail_on);
}
