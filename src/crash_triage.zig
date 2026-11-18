const std = @import("std");
const binary = @import("binary.zig");
const arm64_isa = @import("arm64_isa.zig");
const symbols = @import("symbols.zig");
const veh = @import("veh.zig");
const runner = @import("runner.zig");
const l1 = @import("l1_engine.zig");
const dll_snapshot = @import("dll_snapshot.zig");
const finding = @import("finding.zig");
const report = @import("report.zig");

pub const CrashClass = enum {
    null_deref,
    stack_overflow,
    heap_oob_read,
    heap_oob_write,
    wild_write,
    wild_exec,
    pc_corrupt,
    div_zero,
    illegal_insn,
    bti_violation,
    pac_auth_fail,
    assert_trap,
    unknown,

    pub fn toString(self: CrashClass) []const u8 {
        return @tagName(self);
    }
};

pub const TriageVerdict = struct {
    class: CrashClass,
    rule_id: []const u8,
    severity: finding.Severity,
    cwe: u16,
    faulting_symbol: []const u8,
    faulting_offset: u32,
    input_tainted_addr: bool,
    faulting_insn_class: []const u8,
    reason: []const u8,
};

fn isFaultAddrInputTainted(fault_addr: usize, input: []const u8) bool {
    if (fault_addr < 0x10000) return false;
    if (input.len >= 8) {
        var needle8: [8]u8 = undefined;
        std.mem.writeInt(u64, &needle8, @intCast(fault_addr), .little);
        if (std.mem.indexOf(u8, input, &needle8) != null) return true;
    }
    if (input.len >= 4) {
        var needle4: [4]u8 = undefined;
        const low32: u32 = @truncate(fault_addr);
        if (low32 >= 0x10000) {
            std.mem.writeInt(u32, &needle4, low32, .little);
            if (std.mem.indexOf(u8, input, &needle4) != null) return true;
        }
    }
    return false;
}

pub fn classifyCrash(
    res: veh.RunResult,
    input: []const u8,
    img: ?*const binary.BinaryImage,
    symtab: ?*const symbols.SymbolTable,
    raw_bytes: ?[]const u8,
) TriageVerdict {
    var sym_name: []const u8 = "<unknown>";
    var sym_off: u32 = res.fault_rva;
    if (symtab) |st| {
        const rs = st.resolve(res.fault_rva);
        sym_name = rs.name;
        sym_off = rs.offset;
    }

    var insn_cls: []const u8 = "n/a";
    var is_pac_auth_insn = false;
    if (img) |image| {
        if (image.isArm64() and raw_bytes != null and res.fault_rva != 0) {
            if (image.rvaToOffset(res.fault_rva)) |off| {
                const bytes = raw_bytes.?;
                if (off + 4 <= bytes.len) {
                    const insn = std.mem.readInt(u32, bytes[off..][0..4], .little);
                    const d = arm64_isa.decode(insn);
                    insn_cls = @tagName(d.class);
                    if (d.class == .retaa or d.class == .braa or d.class == .blraa or d.class == .pac_auth) {
                        is_pac_auth_insn = true;
                    }
                }
            }
        }
    }

    const tainted = isFaultAddrInputTainted(res.fault_addr, input);
    const addr_val: u64 = @intCast(res.fault_addr);
    const top16: u16 = @truncate(addr_val >> 48);
    const non_canonical_pac = (res.fault_addr >= 0x10000) and (top16 != 0 and top16 != 0xFFFF);

    switch (res.exception_code) {
        0xC000_00FD => return .{
            .class = .stack_overflow,
            .rule_id = "SO-CRASH-005",
            .severity = .medium,
            .cwe = 674,
            .faulting_symbol = sym_name,
            .faulting_offset = sym_off,
            .input_tainted_addr = false,
            .faulting_insn_class = insn_cls,
            .reason = "Stack guard page exhausted (recursion or oversized stack buffer)",
        },
        0xC000_0094, 0xC000_008E => return .{
            .class = .div_zero,
            .rule_id = "SO-CRASH-007",
            .severity = .medium,
            .cwe = 369,
            .faulting_symbol = sym_name,
            .faulting_offset = sym_off,
            .input_tainted_addr = false,
            .faulting_insn_class = insn_cls,
            .reason = "Divide-by-zero exception on runtime execution path",
        },
        0xC000_001D => return .{
            .class = if (is_pac_auth_insn) .bti_violation else .illegal_insn,
            .rule_id = if (is_pac_auth_insn) "SO-CRASH-003" else "SO-CRASH-007",
            .severity = if (is_pac_auth_insn) .critical else .high,
            .cwe = 119,
            .faulting_symbol = sym_name,
            .faulting_offset = sym_off,
            .input_tainted_addr = false,
            .faulting_insn_class = insn_cls,
            .reason = if (is_pac_auth_insn) "Illegal/BTI control-flow exception at protected call/branch" else "Illegal instruction exception (possible jump into data)",
        },
        0x8000_0003 => return .{
            .class = .assert_trap,
            .rule_id = "SO-CRASH-007",
            .severity = .medium,
            .cwe = 617,
            .faulting_symbol = sym_name,
            .faulting_offset = sym_off,
            .input_tainted_addr = false,
            .faulting_insn_class = insn_cls,
            .reason = "Explicit debug/assertion trap (BRK #0xF000 or INT3) reached",
        },
        0x8000_0002 => return .{
            .class = .heap_oob_read,
            .rule_id = "SO-CRASH-004",
            .severity = .medium,
            .cwe = 125,
            .faulting_symbol = sym_name,
            .faulting_offset = sym_off,
            .input_tainted_addr = tainted,
            .faulting_insn_class = insn_cls,
            .reason = "ARM64 datatype misalignment fault (unaligned strict-access or LDXR/STXR)",
        },
        0xC000_0005, 0xC000_0006 => {
            if (non_canonical_pac or is_pac_auth_insn) {
                return .{
                    .class = .pac_auth_fail,
                    .rule_id = "SO-CRASH-003",
                    .severity = .critical,
                    .cwe = 119,
                    .faulting_symbol = sym_name,
                    .faulting_offset = sym_off,
                    .input_tainted_addr = tainted,
                    .faulting_insn_class = insn_cls,
                    .reason = "Non-canonical top pointer bits indicate poisoned PAC return/function pointer",
                };
            }
            if (res.access_type == 8 or res.fault_rva == 0) {
                return .{
                    .class = if (res.fault_rva == 0) .pc_corrupt else .wild_exec,
                    .rule_id = "SO-CRASH-002",
                    .severity = .critical,
                    .cwe = 119,
                    .faulting_symbol = sym_name,
                    .faulting_offset = sym_off,
                    .input_tainted_addr = tainted,
                    .faulting_insn_class = insn_cls,
                    .reason = "Control-flow hijacked outside valid module bounds or DEP execution fault",
                };
            }
            if (res.fault_addr > 0 and res.fault_addr < 0x10000) {
                return .{
                    .class = .null_deref,
                    .rule_id = "SO-CRASH-006",
                    .severity = .low,
                    .cwe = 476,
                    .faulting_symbol = sym_name,
                    .faulting_offset = sym_off,
                    .input_tainted_addr = false,
                    .faulting_insn_class = insn_cls,
                    .reason = "Null or near-null struct offset dereference (< 64KB guard page)",
                };
            }
            if (res.access_type == 2) {
                return .{
                    .class = if (tainted) .wild_write else .heap_oob_write,
                    .rule_id = "SO-CRASH-001",
                    .severity = .critical,
                    .cwe = 787,
                    .faulting_symbol = sym_name,
                    .faulting_offset = sym_off,
                    .input_tainted_addr = tainted,
                    .faulting_insn_class = insn_cls,
                    .reason = if (tainted) "Write AV with input-controlled fault address (critical memory corruption)" else "Out-of-bounds memory write access violation",
                };
            }
            return .{
                .class = .heap_oob_read,
                .rule_id = "SO-CRASH-004",
                .severity = if (tainted) .high else .medium,
                .cwe = 125,
                .faulting_symbol = sym_name,
                .faulting_offset = sym_off,
                .input_tainted_addr = tainted,
                .faulting_insn_class = insn_cls,
                .reason = if (tainted) "Memory read AV at input-derived address" else "Out-of-bounds memory read access violation",
            };
        },
        else => return .{
            .class = .unknown,
            .rule_id = "SO-CRASH-007",
            .severity = .medium,
            .cwe = 119,
            .faulting_symbol = sym_name,
            .faulting_offset = sym_off,
            .input_tainted_addr = tainted,
            .faulting_insn_class = insn_cls,
            .reason = "Unhandled runtime exception during target execution",
        },
    }
}

pub fn runTriageCommand(io: std.Io, allocator: std.mem.Allocator, args: []const []const u8) !u8 {
    var target_path: ?[]const u8 = null;
    var entry_name: []const u8 = "fuzz_entry";
    var input_path: ?[]const u8 = null;
    var crash_dir: ?[]const u8 = null;
    var fmt: report.ReportFormat = .text;
    var out_path: ?[]const u8 = null;
    var fail_on: finding.Severity = .high;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--target") and i + 1 < args.len) {
            i += 1;
            target_path = args[i];
        } else if (std.mem.eql(u8, a, "--entry") and i + 1 < args.len) {
            i += 1;
            entry_name = args[i];
        } else if (std.mem.eql(u8, a, "--input") and i + 1 < args.len) {
            i += 1;
            input_path = args[i];
        } else if (std.mem.eql(u8, a, "--crash-dir") and i + 1 < args.len) {
            i += 1;
            crash_dir = args[i];
        } else if (std.mem.eql(u8, a, "--format") and i + 1 < args.len) {
            i += 1;
            fmt = report.ReportFormat.fromString(args[i]) orelse .text;
        } else if (std.mem.eql(u8, a, "--out") and i + 1 < args.len) {
            i += 1;
            out_path = args[i];
        } else if (std.mem.eql(u8, a, "--fail-on") and i + 1 < args.len) {
            i += 1;
            fail_on = finding.Severity.fromString(args[i]) orelse .high;
        }
    }

    const dll_path = target_path orelse {
        std.debug.print("Usage: snap-oracle triage --target <dll/so> [--entry fn] (--input <file> | --crash-dir <dir>) [--format text|json|sarif] [--out <file>]\n", .{});
        return 2;
    };

    const image_bytes = try std.Io.Dir.cwd().readFileAlloc(io, dll_path, allocator, .limited(256 * 1024 * 1024));
    defer allocator.free(image_bytes);
    var img = try binary.parseBinary(allocator, image_bytes);
    defer img.deinit();
    var symtab = try symbols.SymbolTable.build(allocator, &img, image_bytes, true);
    defer symtab.deinit();

    var loaded = try runner.LoadedTarget.load(allocator, dll_path, entry_name);
    defer loaded.unload();

    var guard = veh.Guard.init();
    defer guard.deinit();
    veh.setTargetModuleBounds(loaded.base_addr, img.size_of_image);
    defer veh.setTargetModuleBounds(0, 0);

    var arena = try l1.SnapshotArena.init(allocator, 64 * 1024);
    defer arena.deinit();
    arena.takeSnapshot();

    var mod_snap = try dll_snapshot.ModuleDataSnapshot.init(allocator, loaded.base_addr, &img);
    defer mod_snap.deinit();

    var fs = finding.FindingSet.init(allocator);
    defer fs.deinit();

    var paths = std.ArrayList([]u8).empty;
    defer {
        for (paths.items) |p| allocator.free(p);
        paths.deinit(allocator);
    }

    if (input_path) |ip| {
        try paths.append(allocator, try allocator.dupe(u8, ip));
    }
    if (crash_dir) |cd| {
        var dir = try std.Io.Dir.cwd().openDir(io, cd, .{ .iterate = true });
        defer dir.close(io);
        var it = dir.iterate();
        while (it.next(io) catch null) |ent| {
            if (ent.kind != .file) continue;
            try paths.append(allocator, try std.fmt.allocPrint(allocator, "{s}/{s}", .{ cd, ent.name }));
        }
    }
    if (paths.items.len == 0) {
        std.debug.print("[triage] specify --input <file> or --crash-dir <dir>\n", .{});
        return 2;
    }

    for (paths.items) |p| {
        const in_bytes = std.Io.Dir.cwd().readFileAlloc(io, p, allocator, .limited(64 * 1024)) catch continue;
        defer allocator.free(in_bytes);

        @memcpy(arena.live_ptr[0..in_bytes.len], in_bytes);
        const res = veh.runProtected(loaded.entry, arena.live_ptr, in_bytes.len);
        _ = arena.restoreDirtyPages() catch 0;
        _ = mod_snap.restore();

        if (!res.crashed) {
            if (fmt == .text) {
                std.debug.print("[triage] {s} -> NO CRASH (returned {d})\n", .{ p, res.ret_val });
            }
            continue;
        }

        const v = classifyCrash(res, in_bytes, &img, &symtab, image_bytes);
        const sym_label = try std.fmt.allocPrint(allocator, "{s}+0x{x}", .{ v.faulting_symbol, v.faulting_offset });
        defer allocator.free(sym_label);

        const detail = try std.fmt.allocPrint(
            allocator,
            "class={s} exc=0x{x:0>8} fault_addr=0x{x} taint={any} insn={s} input={s}: {s}",
            .{ v.class.toString(), res.exception_code, res.fault_addr, v.input_tainted_addr, v.faulting_insn_class, finding.basename(p), v.reason },
        );
        defer allocator.free(detail);

        try fs.add(.{
            .rule_id = v.rule_id,
            .severity = v.severity,
            .artifact = dll_path,
            .rva = res.fault_rva,
            .func_name = sym_label,
            .cwe = v.cwe,
            .detail = detail,
        });
    }

    try report.emitOrPrint(io, allocator, &fs, fmt, out_path, image_bytes);
    return fs.exitCode(fail_on);
}
