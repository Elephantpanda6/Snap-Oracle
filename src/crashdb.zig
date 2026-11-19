const std = @import("std");
const finding = @import("finding.zig");
const report = @import("report.zig");

pub const DbRecord = struct {
    fingerprint: []const u8,
    rule_id: []const u8,
    severity: []const u8,
    artifact: []const u8,
    title: []const u8,
    count: u32 = 1,
    status: []const u8 = "new",
    crc32: u32 = 0,
};

pub const BaselineDoc = struct {
    schema_version: []const u8 = "1.0",
    fingerprints: []const []const u8 = &.{},
};

pub fn computeRecordCrc(rec: DbRecord) u32 {
    var h = std.hash.Crc32.init();
    h.update(rec.fingerprint);
    h.update("|");
    h.update(rec.rule_id);
    h.update("|");
    h.update(rec.severity);
    h.update("|");
    h.update(rec.artifact);
    h.update("|");
    h.update(rec.title);
    h.update("|");
    h.update(rec.status);
    h.update("|");
    var count_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &count_buf, rec.count, .little);
    h.update(&count_buf);
    return h.final();
}

fn writeFileAtomic(io: std.Io, allocator: std.mem.Allocator, dest_path: []const u8, data: []const u8) !void {
    if (std.Io.Dir.path.dirname(dest_path)) |parent| {
        if (parent.len > 0) std.Io.Dir.cwd().createDirPath(io, parent) catch {};
    }
    const tmp_path = try std.fmt.allocPrint(allocator, "{s}.tmp", .{dest_path});
    defer allocator.free(tmp_path);

    const cwd = std.Io.Dir.cwd();
    try cwd.writeFile(io, .{ .sub_path = tmp_path, .data = data });
    cwd.rename(tmp_path, cwd, dest_path, io) catch {
        cwd.writeFile(io, .{ .sub_path = dest_path, .data = data }) catch |err| {
            cwd.deleteFile(io, tmp_path) catch {};
            return err;
        };
        cwd.deleteFile(io, tmp_path) catch {};
    };
}

fn appendDupedDbRecord(
    allocator: std.mem.Allocator,
    list: *std.ArrayList(DbRecord),
    fp: []const u8,
    rule_id: []const u8,
    severity: []const u8,
    artifact: []const u8,
    title: []const u8,
    count: u32,
    status: []const u8,
    crc32: u32,
) !void {
    const f_fp = try allocator.dupe(u8, fp);
    errdefer allocator.free(f_fp);
    const f_rule = try allocator.dupe(u8, rule_id);
    errdefer allocator.free(f_rule);
    const f_sev = try allocator.dupe(u8, severity);
    errdefer allocator.free(f_sev);
    const f_art = try allocator.dupe(u8, artifact);
    errdefer allocator.free(f_art);
    const f_title = try allocator.dupe(u8, title);
    errdefer allocator.free(f_title);
    const f_status = try allocator.dupe(u8, status);
    errdefer allocator.free(f_status);

    try list.append(allocator, .{
        .fingerprint = f_fp,
        .rule_id = f_rule,
        .severity = f_sev,
        .artifact = f_art,
        .title = f_title,
        .count = count,
        .status = f_status,
        .crc32 = crc32,
    });
}

pub fn loadDbRecords(
    io: std.Io,
    allocator: std.mem.Allocator,
    db_file: []const u8,
    verify_crc: bool,
) !std.ArrayList(DbRecord) {
    var arena_list = std.ArrayList(DbRecord).empty;
    errdefer {
        for (arena_list.items) |r| {
            allocator.free(r.fingerprint);
            allocator.free(r.rule_id);
            allocator.free(r.severity);
            allocator.free(r.artifact);
            allocator.free(r.title);
            allocator.free(r.status);
        }
        arena_list.deinit(allocator);
    }

    const raw = std.Io.Dir.cwd().readFileAlloc(io, db_file, allocator, .limited(32 * 1024 * 1024)) catch return arena_list;
    defer allocator.free(raw);

    var lines = std.mem.splitScalar(u8, raw, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0) continue;
        const parsed = std.json.parseFromSlice(DbRecord, allocator, trimmed, .{ .ignore_unknown_fields = true }) catch continue;
        defer parsed.deinit();
        const v = parsed.value;
        if (verify_crc and computeRecordCrc(v) != v.crc32) {
            // Skip corrupted / torn line safely (including crc32 == 0)
            continue;
        }
        try appendDupedDbRecord(
            allocator,
            &arena_list,
            v.fingerprint,
            v.rule_id,
            v.severity,
            v.artifact,
            v.title,
            v.count,
            v.status,
            v.crc32,
        );
    }
    return arena_list;
}

pub fn freeDbRecords(allocator: std.mem.Allocator, list: *std.ArrayList(DbRecord)) void {
    for (list.items) |r| {
        allocator.free(r.fingerprint);
        allocator.free(r.rule_id);
        allocator.free(r.severity);
        allocator.free(r.artifact);
        allocator.free(r.title);
        allocator.free(r.status);
    }
    list.deinit(allocator);
}

fn saveDbRecords(io: std.Io, allocator: std.mem.Allocator, db_file: []const u8, records: []const DbRecord) !void {
    var out = std.ArrayList(u8).empty;
    defer out.deinit(allocator);

    for (records) |r| {
        const crc = computeRecordCrc(r);
        try out.appendSlice(allocator, "{\"fingerprint\":");
        try finding.appendJsonEscaped(&out, allocator, r.fingerprint);
        try out.appendSlice(allocator, ",\"rule_id\":");
        try finding.appendJsonEscaped(&out, allocator, r.rule_id);
        try out.appendSlice(allocator, ",\"severity\":");
        try finding.appendJsonEscaped(&out, allocator, r.severity);
        try out.appendSlice(allocator, ",\"artifact\":");
        try finding.appendJsonEscaped(&out, allocator, r.artifact);
        try out.appendSlice(allocator, ",\"title\":");
        try finding.appendJsonEscaped(&out, allocator, r.title);
        try out.appendSlice(allocator, ",\"status\":");
        try finding.appendJsonEscaped(&out, allocator, r.status);
        const tail = try std.fmt.allocPrint(allocator, ",\"count\":{d},\"crc32\":{d}}}\n", .{ r.count, crc });
        defer allocator.free(tail);
        try out.appendSlice(allocator, tail);
    }
    try writeFileAtomic(io, allocator, db_file, out.items);
}

pub fn filterFindingsAgainstBaseline(
    allocator: std.mem.Allocator,
    current: *const finding.FindingSet,
    baseline_json: []const u8,
    out_new: *finding.FindingSet,
) !usize {
    const parsed = try std.json.parseFromSlice(BaselineDoc, allocator, baseline_json, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();

    var key_arena = std.heap.ArenaAllocator.init(allocator);
    defer key_arena.deinit();
    const ka = key_arena.allocator();

    var seen = std.StringHashMap(void).init(allocator);
    defer seen.deinit();
    for (parsed.value.fingerprints) |fp| {
        const low = try ka.alloc(u8, fp.len);
        for (fp, 0..) |c, idx| low[idx] = std.ascii.toLower(c);
        try seen.put(low, {});
    }

    var suppressed: usize = 0;
    for (current.items.items) |f| {
        var fp_buf: [16]u8 = undefined;
        const fp_hex = try std.fmt.bufPrint(&fp_buf, "{x:0>16}", .{f.fingerprint});
        if (seen.contains(fp_hex)) {
            suppressed += 1;
            continue;
        }
        try out_new.add(.{
            .rule_id = f.rule_id,
            .severity = f.severity,
            .confidence = f.confidence,
            .title = f.title,
            .detail = f.detail,
            .artifact = f.artifact,
            .rva = f.rva,
            .file_offset = f.file_offset,
            .line = f.line,
            .func_name = f.func_name,
            .remediation = f.remediation,
            .cwe = f.cwe,
        });
    }
    return suppressed;
}

pub fn createBaselineJson(allocator: std.mem.Allocator, fs: *const finding.FindingSet) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, "{\n  \"schema_version\": \"1.0\",\n  \"fingerprints\": [\n");
    for (fs.items.items, 0..) |f, i| {
        if (i > 0) try out.appendSlice(allocator, ",\n");
        var fp_buf: [16]u8 = undefined;
        const fp_hex = try std.fmt.bufPrint(&fp_buf, "{x:0>16}", .{f.fingerprint});
        try out.appendSlice(allocator, "    ");
        try finding.appendJsonEscaped(&out, allocator, fp_hex);
    }
    try out.appendSlice(allocator, "\n  ]\n}\n");
    return out.toOwnedSlice(allocator);
}

pub fn runCrashDbCommand(io: std.Io, allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len == 0) {
        std.debug.print("Usage: snap-oracle crashdb <init|add|list|stats> [--db <path>] [--report <findings.json>]\n", .{});
        return;
    }

    const sub = args[0];
    var db_path: []const u8 = ".snapdb/records.jsonl";
    var report_path: ?[]const u8 = null;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--db") and i + 1 < args.len) {
            i += 1;
            db_path = args[i];
        } else if (std.mem.eql(u8, args[i], "--report") and i + 1 < args.len) {
            i += 1;
            report_path = args[i];
        }
    }

    if (std.mem.eql(u8, sub, "init")) {
        try writeFileAtomic(io, allocator, db_path, "");
        std.debug.print("[crashdb] initialized store at {s}\n", .{db_path});
        return;
    }

    var records = try loadDbRecords(io, allocator, db_path, true);
    defer freeDbRecords(allocator, &records);

    if (std.mem.eql(u8, sub, "add")) {
        const rp = report_path orelse {
            std.debug.print("[crashdb add] missing --report <findings.json>\n", .{});
            return;
        };
        const raw = try std.Io.Dir.cwd().readFileAlloc(io, rp, allocator, .limited(64 * 1024 * 1024));
        defer allocator.free(raw);
        var fs = finding.FindingSet.init(allocator);
        defer fs.deinit();
        try report.parseJsonReportIntoFindingSet(allocator, raw, &fs);

        var added: usize = 0;
        var updated: usize = 0;
        for (fs.items.items) |f| {
            var fp_buf: [16]u8 = undefined;
            const fp_hex = try std.fmt.bufPrint(&fp_buf, "{x:0>16}", .{f.fingerprint});
            var found = false;
            for (records.items) |*rec| {
                if (finding.eqlIgnoreCase(rec.fingerprint, fp_hex)) {
                    rec.count += 1;
                    updated += 1;
                    found = true;
                    break;
                }
            }
            if (!found) {
                try appendDupedDbRecord(
                    allocator,
                    &records,
                    fp_hex,
                    f.rule_id,
                    f.severity.toString(),
                    finding.basename(f.artifact),
                    f.title,
                    1,
                    "new",
                    0,
                );
                added += 1;
            }
        }
        try saveDbRecords(io, allocator, db_path, records.items);
        std.debug.print("[crashdb add] added={d} updated={d} total={d} ({s})\n", .{ added, updated, records.items.len, db_path });
        return;
    }

    if (std.mem.eql(u8, sub, "list")) {
        std.debug.print("=== Snap-Oracle Crash/Finding DB ({s}, {d} records) ===\n", .{ db_path, records.items.len });
        for (records.items) |r| {
            std.debug.print("  {s} [{s:<8}] {s:<14} seen={d:<3} status={s:<7} {s}\n", .{
                r.fingerprint,
                r.severity,
                r.rule_id,
                r.count,
                r.status,
                r.title,
            });
        }
        return;
    }

    if (std.mem.eql(u8, sub, "stats")) {
        var total_seen: u64 = 0;
        for (records.items) |r| total_seen += r.count;
        std.debug.print("[crashdb stats] unique_buckets={d} cumulative_observations={d} store={s}\n", .{
            records.items.len,
            total_seen,
            db_path,
        });
        return;
    }

    std.debug.print("Usage: snap-oracle crashdb <init|add|list|stats> [--db <path>] [--report <file>]\n", .{});
}

pub fn runBaselineCommand(io: std.Io, allocator: std.mem.Allocator, args: []const []const u8) !u8 {
    if (args.len == 0) {
        std.debug.print("Usage: snap-oracle baseline <create|diff> --report <findings.json> [--baseline <base.json>] [--out <file>] [--format text|json|sarif] [--fail-on <sev>]\n", .{});
        return 2;
    }

    const sub = args[0];
    var report_path: ?[]const u8 = null;
    var base_path: ?[]const u8 = null;
    var out_path: ?[]const u8 = null;
    var fmt: report.ReportFormat = .text;
    var fail_on: finding.Severity = .high;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--report") and i + 1 < args.len) {
            i += 1;
            report_path = args[i];
        } else if (std.mem.eql(u8, a, "--baseline") and i + 1 < args.len) {
            i += 1;
            base_path = args[i];
        } else if (std.mem.eql(u8, a, "--out") and i + 1 < args.len) {
            i += 1;
            out_path = args[i];
        } else if (std.mem.eql(u8, a, "--format") and i + 1 < args.len) {
            i += 1;
            fmt = report.ReportFormat.fromString(args[i]) orelse .text;
        } else if (std.mem.eql(u8, a, "--fail-on") and i + 1 < args.len) {
            i += 1;
            fail_on = finding.Severity.fromString(args[i]) orelse .high;
        }
    }

    const rp = report_path orelse {
        std.debug.print("[baseline] missing --report <findings.json>\n", .{});
        return 2;
    };
    const raw = try std.Io.Dir.cwd().readFileAlloc(io, rp, allocator, .limited(64 * 1024 * 1024));
    defer allocator.free(raw);

    var cur_fs = finding.FindingSet.init(allocator);
    defer cur_fs.deinit();
    try report.parseJsonReportIntoFindingSet(allocator, raw, &cur_fs);

    if (std.mem.eql(u8, sub, "create")) {
        const base_json = try createBaselineJson(allocator, &cur_fs);
        defer allocator.free(base_json);
        if (out_path) |op| {
            try writeFileAtomic(io, allocator, op, base_json);
            std.debug.print("[baseline] created baseline ({d} fingerprints) -> {s}\n", .{ cur_fs.items.items.len, op });
        } else {
            finding.writeStdout(io, base_json);
        }
        return 0;
    }

    if (std.mem.eql(u8, sub, "diff")) {
        const bp = base_path orelse {
            std.debug.print("[baseline diff] missing --baseline <base.json>\n", .{});
            return 2;
        };
        const base_raw = try std.Io.Dir.cwd().readFileAlloc(io, bp, allocator, .limited(16 * 1024 * 1024));
        defer allocator.free(base_raw);

        var new_fs = finding.FindingSet.init(allocator);
        defer new_fs.deinit();
        const suppressed = try filterFindingsAgainstBaseline(allocator, &cur_fs, base_raw, &new_fs);
        if (fmt == .text) {
            std.debug.print("[baseline diff] total={d} suppressed={d} new={d}\n", .{
                cur_fs.items.items.len,
                suppressed,
                new_fs.items.items.len,
            });
        }
        try report.emitOrPrint(io, allocator, &new_fs, fmt, out_path, null);
        return new_fs.exitCode(fail_on);
    }

    std.debug.print("Usage: snap-oracle baseline <create|diff> ...\n", .{});
    return 2;
}
