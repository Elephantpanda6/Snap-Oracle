const std = @import("std");
const binary = @import("binary.zig");
const pe = @import("pe.zig");
const arm64_isa = @import("arm64_isa.zig");
const finding = @import("finding.zig");
const report = @import("report.zig");

pub const AuditLevel = enum {
    baseline,
    strict,
};

pub const HardeningSummary = struct {
    format: binary.BinaryFormat,
    machine: pe.Machine,
    aslr_pie: bool = false,
    high_entropy_va: bool = false,
    nx_stack: bool = true,
    no_wx_segments: bool = true,
    cfg_or_full_relro: bool = false,
    stack_canary: bool = false,
    fortify_source: bool = false,
    pac_note_or_abi: bool = false,
    bti_note: bool = false,
    mte_tagged: bool = false,
    codesign_present: bool = false,
    hardened_runtime: bool = false,
    total_functions: usize = 0,
    pac_prologue_funcs: usize = 0,
    bti_prologue_funcs: usize = 0,
    score: u32 = 0,

    pub fn pacCoveragePct(self: HardeningSummary) u32 {
        if (self.total_functions == 0) return 0;
        return @intCast((self.pac_prologue_funcs * 100) / self.total_functions);
    }

    pub fn btiCoveragePct(self: HardeningSummary) u32 {
        if (self.total_functions == 0) return 0;
        return @intCast((self.bti_prologue_funcs * 100) / self.total_functions);
    }
};

pub fn auditHardening(
    allocator: std.mem.Allocator,
    path: []const u8,
    bytes: []const u8,
    level: AuditLevel,
    out_fs: *finding.FindingSet,
) !HardeningSummary {
    var img = try binary.parseBinary(allocator, bytes);
    defer img.deinit();

    var sum = HardeningSummary{
        .format = img.format,
        .machine = img.machine,
        .pac_note_or_abi = img.has_pac,
        .bti_note = img.has_bti,
        .total_functions = img.functions.len,
    };

    // Measure actual AArch64 PAC & BTI prologue coverage across recovered functions
    if (img.isArm64()) {
        for (img.functions) |f| {
            const off = img.rvaToOffset(f.begin_rva) orelse continue;
            var has_pac = false;
            var has_bti = false;
            var step: usize = 0;
            while (step < 2 and off + step * 4 + 4 <= bytes.len) : (step += 1) {
                const insn = std.mem.readInt(u32, bytes[off + step * 4 ..][0..4], .little);
                const cls = arm64_isa.decode(insn).class;
                if (cls == .pac_sign) has_pac = true;
                if (cls == .bti) has_bti = true;
            }
            if (has_pac) sum.pac_prologue_funcs += 1;
            if (has_bti) sum.bti_prologue_funcs += 1;
        }
    }

    // Symbol/string heuristics common to stack canary & fortify checks
    if (std.mem.indexOf(u8, bytes, "__stack_chk_fail") != null or std.mem.indexOf(u8, bytes, "__security_check_cookie") != null) {
        sum.stack_canary = true;
    }
    if (std.mem.indexOf(u8, bytes, "__memcpy_chk") != null or std.mem.indexOf(u8, bytes, "__snprintf_chk") != null or std.mem.indexOf(u8, bytes, "__strcpy_chk") != null) {
        sum.fortify_source = true;
    }

    switch (img.format) {
        .pe32plus => try auditPeHardening(allocator, path, bytes, &img, &sum, out_fs),
        .elf64 => try auditElfHardening(allocator, path, bytes, &img, &sum, out_fs),
        .macho64 => try auditMachoHardening(allocator, path, bytes, &img, &sum, out_fs),
    }

    if (img.isArm64()) {
        const pac_thresh: u32 = if (level == .strict) 50 else 5;
        if (!sum.pac_note_or_abi and sum.pacCoveragePct() < pac_thresh and sum.total_functions >= 8) {
            const detail = try std.fmt.allocPrint(allocator, "PAC return-address signing coverage is {d}% ({d}/{d} functions) and PAC ABI/note metadata is absent", .{
                sum.pacCoveragePct(),
                sum.pac_prologue_funcs,
                sum.total_functions,
            });
            defer allocator.free(detail);
            try out_fs.add(.{
                .rule_id = "SO-PAC-001",
                .severity = if (level == .strict) .high else .medium,
                .artifact = path,
                .detail = detail,
            });
        }

        if (!sum.bti_note and sum.btiCoveragePct() < pac_thresh and sum.total_functions >= 8 and img.format != .pe32plus) {
            const detail = try std.fmt.allocPrint(allocator, "BTI indirect-branch landing-pad coverage is {d}% ({d}/{d} functions) and BTI note is absent", .{
                sum.btiCoveragePct(),
                sum.bti_prologue_funcs,
                sum.total_functions,
            });
            defer allocator.free(detail);
            try out_fs.add(.{
                .rule_id = "SO-BTI-001",
                .severity = if (level == .strict) .high else .medium,
                .artifact = path,
                .detail = detail,
            });
        }
    }

    if (!sum.stack_canary) {
        try out_fs.add(.{
            .rule_id = "SO-HARDEN-004",
            .severity = if (level == .strict) .medium else .low,
            .artifact = path,
            .detail = "Neither __stack_chk_fail nor MSVC __security_check_cookie security cookie helper was observed",
        });
    }

    // Compute clean 0..100 compliance score
    var pts: u32 = 0;
    if (sum.aslr_pie) pts += 20;
    if (sum.nx_stack) pts += 20;
    if (sum.no_wx_segments) pts += 15;
    if (sum.cfg_or_full_relro) pts += 20;
    if (sum.stack_canary) pts += 10;
    if (sum.pac_note_or_abi or sum.pacCoveragePct() >= 25) pts += 10;
    if (sum.bti_note or sum.codesign_present or sum.fortify_source) pts += 5;
    sum.score = @min(pts, 100);

    return sum;
}

fn auditPeHardening(
    allocator: std.mem.Allocator,
    path: []const u8,
    bytes: []const u8,
    img: *const binary.BinaryImage,
    sum: *HardeningSummary,
    out_fs: *finding.FindingSet,
) !void {
    if (bytes.len < 0x40) return;
    const e_lfanew = std.mem.readInt(u32, bytes[0x3C..][0..4], .little);
    const opt_off = @as(u64, e_lfanew) + 24;
    if (opt_off + 72 > bytes.len) return;
    const opt = bytes[@intCast(opt_off)..];
    const dll_chars = std.mem.readInt(u16, opt[70..72], .little);

    sum.aslr_pie = (dll_chars & 0x0040) != 0; // DYNAMIC_BASE
    sum.high_entropy_va = (dll_chars & 0x0020) != 0;
    sum.nx_stack = (dll_chars & 0x0100) != 0; // NX_COMPAT
    sum.cfg_or_full_relro = (dll_chars & 0x4000) != 0; // GUARD_CF

    if (!sum.aslr_pie) {
        try out_fs.add(.{
            .rule_id = "SO-HARDEN-001",
            .artifact = path,
            .detail = "PE DllCharacteristics lacks IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE (0x0040)",
        });
    }
    if (!sum.nx_stack) {
        try out_fs.add(.{
            .rule_id = "SO-HARDEN-002",
            .artifact = path,
            .detail = "PE DllCharacteristics lacks IMAGE_DLLCHARACTERISTICS_NX_COMPAT (0x0100)",
        });
    }
    if (!sum.cfg_or_full_relro) {
        try out_fs.add(.{
            .rule_id = "SO-HARDEN-003",
            .artifact = path,
            .detail = "PE Control Flow Guard (IMAGE_DLLCHARACTERISTICS_GUARD_CF) is disabled",
        });
    }

    for (img.sections) |sec| {
        if ((sec.characteristics & pe.IMAGE_SCN_MEM_WRITE) != 0 and (sec.characteristics & pe.IMAGE_SCN_MEM_EXECUTE) != 0) {
            sum.no_wx_segments = false;
            const detail = try std.fmt.allocPrint(allocator, "PE section '{s}' is simultaneously WRITABLE and EXECUTABLE (W^X violation)", .{sec.nameSlice()});
            defer allocator.free(detail);
            try out_fs.add(.{
                .rule_id = "SO-HARDEN-002",
                .artifact = path,
                .rva = sec.virtual_address,
                .detail = detail,
            });
        }
    }
}

fn auditElfHardening(
    allocator: std.mem.Allocator,
    path: []const u8,
    bytes: []const u8,
    img: *const binary.BinaryImage,
    sum: *HardeningSummary,
    out_fs: *finding.FindingSet,
) !void {
    if (bytes.len < 64) return;
    const e_type = std.mem.readInt(u16, bytes[16..18], .little);
    sum.aslr_pie = (e_type == 3); // ET_DYN

    if (!sum.aslr_pie) {
        try out_fs.add(.{
            .rule_id = "SO-HARDEN-001",
            .artifact = path,
            .detail = "ELF e_type is ET_EXEC (non-PIE); binary cannot benefit from full ASLR",
        });
    }

    const e_phoff = std.mem.readInt(u64, bytes[32..40], .little);
    const e_phentsize = std.mem.readInt(u16, bytes[54..56], .little);
    const e_phnum = @min(std.mem.readInt(u16, bytes[56..58], .little), 256);

    var has_gnu_stack = false;
    var has_relro = false;
    var has_bind_now = false;
    var has_textrel = false;
    var dyn_off: usize = 0;
    var dyn_sz: usize = 0;

    var i: u16 = 0;
    while (i < e_phnum) : (i += 1) {
        const off = e_phoff + @as(u64, i) * e_phentsize;
        if (off + 56 > bytes.len or e_phentsize < 56) break;
        const ph = bytes[@intCast(off)..];
        const p_type = std.mem.readInt(u32, ph[0..4], .little);
        const p_flags = std.mem.readInt(u32, ph[4..8], .little);
        const p_offset = std.mem.readInt(u64, ph[8..16], .little);
        const p_vaddr = std.mem.readInt(u64, ph[16..24], .little);
        const p_filesz = std.mem.readInt(u64, ph[32..40], .little);

        if (p_type == 1 and (p_flags & 3) == 3) { // PT_LOAD with W+X
            sum.no_wx_segments = false;
            const detail = try std.fmt.allocPrint(allocator, "ELF PT_LOAD segment #{d} (vaddr 0x{x}) is both WRITABLE and EXECUTABLE", .{ i, p_vaddr });
            defer allocator.free(detail);
            try out_fs.add(.{
                .rule_id = "SO-HARDEN-002",
                .artifact = path,
                .detail = detail,
            });
        } else if (p_type == 0x6474_E551) { // PT_GNU_STACK
            has_gnu_stack = true;
            if ((p_flags & 1) != 0) {
                sum.nx_stack = false;
                try out_fs.add(.{
                    .rule_id = "SO-HARDEN-002",
                    .artifact = path,
                    .detail = "ELF PT_GNU_STACK allows executable stack (PF_X set)",
                });
            }
        } else if (p_type == 0x6474_E552) { // PT_GNU_RELRO
            has_relro = true;
        } else if (p_type == 2 and p_offset + p_filesz <= bytes.len) {
            dyn_off = @intCast(p_offset);
            dyn_sz = @intCast(p_filesz);
        }
    }

    if (dyn_off > 0 and dyn_sz >= 16) {
        const max_ents = @min(dyn_sz / 16, 4096);
        var idx: usize = 0;
        while (idx < max_ents) : (idx += 1) {
            const off = dyn_off + idx * 16;
            const tag = std.mem.readInt(i64, bytes[off..][0..8], .little);
            const val = std.mem.readInt(u64, bytes[off + 8 ..][0..8], .little);
            if (tag == 0) break;
            if (tag == 24) has_bind_now = true; // DT_BIND_NOW
            if (tag == 30 and (val & 0x8) != 0) has_bind_now = true; // DF_BIND_NOW
            if (tag == 30 and (val & 0x4) != 0) has_textrel = true; // DF_TEXTREL
            if (tag == 22) has_textrel = true; // DT_TEXTREL
            if (tag == 0x6FFF_FFFB and (val & 0x1) != 0) has_bind_now = true; // DF_1_NOW
            if (tag == 0x7000_0009) sum.mte_tagged = true; // DT_AARCH64_MEMTAG_MODE
        }
    }

    sum.cfg_or_full_relro = has_relro and has_bind_now;
    if (!has_relro or !has_bind_now) {
        const kind = if (!has_relro) "No RELRO" else "Partial RELRO (missing BIND_NOW)";
        const detail = try std.fmt.allocPrint(allocator, "ELF GOT hardening incomplete: {s}", .{kind});
        defer allocator.free(detail);
        try out_fs.add(.{
            .rule_id = "SO-HARDEN-003",
            .artifact = path,
            .detail = detail,
        });
    }
    if (has_textrel) {
        try out_fs.add(.{
            .rule_id = "SO-HARDEN-007",
            .artifact = path,
            .detail = "ELF contains DT_TEXTREL / DF_TEXTREL forcing writable executable pages at load time",
        });
    }
    if (img.isArm64() and !sum.mte_tagged) {
        try out_fs.add(.{
            .rule_id = "SO-HARDEN-006",
            .artifact = path,
            .detail = "ELF does not carry ARMv9 MTE dynamic tag (DT_AARCH64_MEMTAG_MODE)",
        });
    }
}

fn auditMachoHardening(
    allocator: std.mem.Allocator,
    path: []const u8,
    bytes: []const u8,
    img: *const binary.BinaryImage,
    sum: *HardeningSummary,
    out_fs: *finding.FindingSet,
) !void {
    if (bytes.len < 32 or std.mem.readInt(u32, bytes[0..4], .little) != 0xFEED_FACF) return;
    const cpusubtype = std.mem.readInt(u32, bytes[8..12], .little);
    const flags = std.mem.readInt(u32, bytes[24..28], .little);

    sum.aslr_pie = (flags & 0x0020_0000) != 0; // MH_PIE
    sum.cfg_or_full_relro = sum.aslr_pie; // dyld chained fixups / two-level namespace
    if ((cpusubtype & 0xFF) == 2) sum.pac_note_or_abi = true; // arm64e

    if (!sum.aslr_pie) {
        try out_fs.add(.{
            .rule_id = "SO-HARDEN-001",
            .artifact = path,
            .detail = "Mach-O header lacks MH_PIE (0x00200000)",
        });
    }
    if ((flags & 0x0002_0000) != 0) { // MH_ALLOW_STACK_EXECUTION
        sum.nx_stack = false;
        try out_fs.add(.{
            .rule_id = "SO-HARDEN-002",
            .artifact = path,
            .detail = "Mach-O sets MH_ALLOW_STACK_EXECUTION (executable stack)",
        });
    }

    const ncmds = @min(std.mem.readInt(u32, bytes[16..20], .little), 4096);
    var off: usize = 32;
    var i: u32 = 0;
    while (i < ncmds) : (i += 1) {
        if (off + 8 > bytes.len) break;
        const cmd = std.mem.readInt(u32, bytes[off..][0..4], .little);
        const cmdsize = std.mem.readInt(u32, bytes[off + 4 ..][0..4], .little);
        if (cmdsize < 8 or off + cmdsize > bytes.len) break;

        if (cmd == 0x19 and cmdsize >= 72) { // LC_SEGMENT_64
            const initprot = std.mem.readInt(u32, bytes[off + 60 ..][0..4], .little);
            if ((initprot & 6) == 6) {
                sum.no_wx_segments = false;
                try out_fs.add(.{
                    .rule_id = "SO-HARDEN-002",
                    .artifact = path,
                    .detail = "Mach-O LC_SEGMENT_64 sets both VM_PROT_WRITE and VM_PROT_EXECUTE",
                });
            }
        } else if (cmd == 0x1D and cmdsize >= 16) { // LC_CODE_SIGNATURE
            sum.codesign_present = true;
            const dataoff = std.mem.readInt(u32, bytes[off + 8 ..][0..4], .little);
            const datasize = std.mem.readInt(u32, bytes[off + 12 ..][0..4], .little);
            if (@as(u64, dataoff) + datasize <= bytes.len and datasize >= 12) {
                const sb = bytes[dataoff .. dataoff + datasize];
                if (std.mem.readInt(u32, sb[0..4], .big) == 0xFADE_0CC0) {
                    const cnt = @min(std.mem.readInt(u32, sb[8..12], .big), 32);
                    var bi: u32 = 0;
                    while (bi < cnt) : (bi += 1) {
                        const idx_off = 12 + @as(usize, bi) * 8;
                        if (idx_off + 8 > sb.len) break;
                        const blob_off = std.mem.readInt(u32, sb[idx_off + 4 ..][0..4], .big);
                        if (blob_off + 16 <= sb.len and std.mem.readInt(u32, sb[blob_off..][0..4], .big) == 0xFADE_0C02) {
                            const cs_flags = std.mem.readInt(u32, sb[blob_off + 12 ..][0..4], .big);
                            if ((cs_flags & 0x10000) != 0) sum.hardened_runtime = true; // CS_RUNTIME
                        }
                    }
                }
            }
        }
        off += cmdsize;
    }

    if (!sum.codesign_present or !sum.hardened_runtime) {
        const msg = if (!sum.codesign_present)
            "Mach-O binary lacks LC_CODE_SIGNATURE code signature"
        else
            "Mach-O code signature lacks Hardened Runtime flag (CS_RUNTIME 0x10000)";
        const d = try allocator.dupe(u8, msg);
        defer allocator.free(d);
        try out_fs.add(.{
            .rule_id = "SO-HARDEN-005",
            .artifact = path,
            .detail = d,
        });
    }
    _ = img;
}

pub fn runHardenCommand(io: std.Io, allocator: std.mem.Allocator, args: []const []const u8) !u8 {
    if (args.len == 0) {
        std.debug.print("Usage: snap-oracle harden <binary> [--level baseline|strict] [--format text|json|sarif|junit|gha] [--out <file>] [--fail-on <sev>]\n", .{});
        return 2;
    }

    var bin_path: ?[]const u8 = null;
    var level: AuditLevel = .baseline;
    var fmt: report.ReportFormat = .text;
    var out_path: ?[]const u8 = null;
    var fail_on: finding.Severity = .high;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--level") and i + 1 < args.len) {
            i += 1;
            if (finding.eqlIgnoreCase(args[i], "strict")) level = .strict;
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
        std.debug.print("Usage: snap-oracle harden <binary> [--level baseline|strict]\n", .{});
        return 2;
    };

    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(128 * 1024 * 1024));
    defer allocator.free(bytes);

    var fs = finding.FindingSet.init(allocator);
    defer fs.deinit();

    const sum = try auditHardening(allocator, path, bytes, level, &fs);

    if (fmt == .text) {
        std.debug.print(
            \\=== AArch64 Binary Hardening & Compliance Audit: {s} ===
            \\Format: {s} ({s}) | Score: {d}/100 | Level: {s}
            \\ASLR/PIE: {any} | NX/W^X: {any}/{any} | CFG/Full-RELRO: {any} | Canary: {any}
            \\PAC Note/ABI: {any} ({d}% prologues) | BTI Note: {any} ({d}% prologues) | MTE: {any}
            \\
        , .{
            finding.basename(path),
            @tagName(sum.format),
            @tagName(sum.machine),
            sum.score,
            @tagName(level),
            sum.aslr_pie,
            sum.nx_stack,
            sum.no_wx_segments,
            sum.cfg_or_full_relro,
            sum.stack_canary,
            sum.pac_note_or_abi,
            sum.pacCoveragePct(),
            sum.bti_note,
            sum.btiCoveragePct(),
            sum.mte_tagged,
        });
    }

    try report.emitOrPrint(io, allocator, &fs, fmt, out_path, bytes);
    return fs.exitCode(fail_on);
}
