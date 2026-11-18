const std = @import("std");
const finding = @import("finding.zig");

pub const ReportFormat = enum {
    text,
    json,
    sarif,
    junit,
    gha,

    pub fn fromString(s: []const u8) ?ReportFormat {
        if (finding.eqlIgnoreCase(s, "text")) return .text;
        if (finding.eqlIgnoreCase(s, "json")) return .json;
        if (finding.eqlIgnoreCase(s, "sarif")) return .sarif;
        if (finding.eqlIgnoreCase(s, "junit") or finding.eqlIgnoreCase(s, "xml")) return .junit;
        if (finding.eqlIgnoreCase(s, "gha") or finding.eqlIgnoreCase(s, "github")) return .gha;
        return null;
    }
};

pub const JsonFindingDto = struct {
    rule_id: []const u8,
    severity: []const u8,
    confidence: []const u8 = "high",
    title: []const u8,
    detail: []const u8,
    artifact: []const u8 = "",
    rva: ?u32 = null,
    file_offset: ?u32 = null,
    func_name: ?[]const u8 = null,
    remediation: []const u8 = "",
    cwe: ?u16 = null,
    fingerprint: []const u8 = "",
};

pub const JsonReportDto = struct {
    schema_version: []const u8 = "1.0",
    tool: []const u8 = finding.TOOL_NAME,
    version: []const u8 = finding.TOOL_VERSION,
    artifact_sha256: ?[]const u8 = null,
    findings: []const JsonFindingDto = &.{},
};

pub fn parseJsonReportIntoFindingSet(
    allocator: std.mem.Allocator,
    json_bytes: []const u8,
    out_fs: *finding.FindingSet,
) !void {
    const parsed = try std.json.parseFromSlice(JsonReportDto, allocator, json_bytes, .{
        .ignore_unknown_fields = true,
    });
    defer parsed.deinit();

    for (parsed.value.findings) |item| {
        const sev = finding.Severity.fromString(item.severity) orelse .medium;
        const conf: finding.Confidence = if (finding.eqlIgnoreCase(item.confidence, "low"))
            .low
        else if (finding.eqlIgnoreCase(item.confidence, "medium"))
            .medium
        else
            .high;

        try out_fs.add(.{
            .rule_id = item.rule_id,
            .severity = sev,
            .confidence = conf,
            .title = item.title,
            .detail = item.detail,
            .artifact = item.artifact,
            .rva = item.rva,
            .file_offset = item.file_offset,
            .func_name = item.func_name,
            .remediation = item.remediation,
            .cwe = item.cwe,
        });
    }
}

pub fn renderFindingSet(
    allocator: std.mem.Allocator,
    fs: *const finding.FindingSet,
    fmt: ReportFormat,
    artifact_bytes: ?[]const u8,
) ![]u8 {
    return switch (fmt) {
        .text => renderText(allocator, fs),
        .json => renderJson(allocator, fs, artifact_bytes),
        .sarif => renderSarif(allocator, fs, artifact_bytes),
        .junit => renderJunit(allocator, fs),
        .gha => renderGha(allocator, fs),
    };
}

pub fn emitOrPrint(
    io: std.Io,
    allocator: std.mem.Allocator,
    fs: *const finding.FindingSet,
    fmt: ReportFormat,
    out_path: ?[]const u8,
    artifact_bytes: ?[]const u8,
) !void {
    const rendered = try renderFindingSet(allocator, fs, fmt, artifact_bytes);
    defer allocator.free(rendered);

    if (out_path) |path| {
        try finding.writeOutputFile(io, path, rendered);
        if (fmt != .text) {
            std.debug.print("[report] wrote {s} ({d} findings, fmt={s})\n", .{ path, fs.items.items.len, @tagName(fmt) });
        }
    } else {
        finding.writeStdout(io, rendered);
    }
}

fn appendFmt(list: *std.ArrayList(u8), allocator: std.mem.Allocator, comptime fmt_str: []const u8, args: anytype) !void {
    const s = try std.fmt.allocPrint(allocator, fmt_str, args);
    defer allocator.free(s);
    try list.appendSlice(allocator, s);
}

fn renderText(allocator: std.mem.Allocator, fs: *const finding.FindingSet) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);

    try appendFmt(&out, allocator, "=== {s} Findings Report ({d} total | CRIT={d} HIGH={d} MED={d} LOW={d} INFO={d}) ===\n", .{
        finding.TOOL_NAME,
        fs.items.items.len,
        fs.countBySeverity(.critical),
        fs.countBySeverity(.high),
        fs.countBySeverity(.medium),
        fs.countBySeverity(.low),
        fs.countBySeverity(.info),
    });

    if (fs.items.items.len == 0) {
        try out.appendSlice(allocator, "Status: CLEAN (no findings recorded)\n");
        return out.toOwnedSlice(allocator);
    }

    for (fs.items.items, 1..) |f, idx| {
        try appendFmt(&out, allocator, "[{d}] [{s}] {s}: {s}\n", .{
            idx,
            f.severity.badge(),
            f.rule_id,
            f.title,
        });
        try appendFmt(&out, allocator, "    Artifact : {s}", .{f.artifact});
        if (f.func_name) |fn_name| {
            try appendFmt(&out, allocator, " | Symbol: {s}", .{fn_name});
        }
        if (f.rva) |rva| {
            try appendFmt(&out, allocator, " | RVA: 0x{x}", .{rva});
        }
        if (f.cwe) |cwe| {
            try appendFmt(&out, allocator, " | CWE-{d}", .{cwe});
        }
        try appendFmt(&out, allocator, " | FP: {x:0>16}\n", .{f.fingerprint});
        try appendFmt(&out, allocator, "    Detail   : {s}\n", .{f.detail});
        try appendFmt(&out, allocator, "    Fix      : {s}\n", .{f.remediation});
    }

    return out.toOwnedSlice(allocator);
}

fn renderJson(allocator: std.mem.Allocator, fs: *const finding.FindingSet, artifact_bytes: ?[]const u8) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);

    try out.appendSlice(allocator, "{\n  \"schema_version\": \"1.0\",\n  \"tool\": ");
    try finding.appendJsonEscaped(&out, allocator, finding.TOOL_NAME);
    try out.appendSlice(allocator, ",\n  \"version\": ");
    try finding.appendJsonEscaped(&out, allocator, finding.TOOL_VERSION);
    try out.appendSlice(allocator, ",\n  \"artifact_sha256\": ");
    if (artifact_bytes) |bytes| {
        const hex = finding.sha256Hex(bytes);
        try finding.appendJsonEscaped(&out, allocator, &hex);
    } else {
        try out.appendSlice(allocator, "null");
    }

    try appendFmt(&out, allocator,
        ",\n  \"summary\": {{\"total\": {d}, \"critical\": {d}, \"high\": {d}, \"medium\": {d}, \"low\": {d}, \"info\": {d}}},\n  \"findings\": [\n",
        .{
            fs.items.items.len,
            fs.countBySeverity(.critical),
            fs.countBySeverity(.high),
            fs.countBySeverity(.medium),
            fs.countBySeverity(.low),
            fs.countBySeverity(.info),
        },
    );

    for (fs.items.items, 0..) |f, i| {
        if (i > 0) try out.appendSlice(allocator, ",\n");
        try out.appendSlice(allocator, "    {\n      \"rule_id\": ");
        try finding.appendJsonEscaped(&out, allocator, f.rule_id);
        try out.appendSlice(allocator, ",\n      \"severity\": ");
        try finding.appendJsonEscaped(&out, allocator, f.severity.toString());
        try out.appendSlice(allocator, ",\n      \"confidence\": ");
        try finding.appendJsonEscaped(&out, allocator, f.confidence.toString());
        try out.appendSlice(allocator, ",\n      \"title\": ");
        try finding.appendJsonEscaped(&out, allocator, f.title);
        try out.appendSlice(allocator, ",\n      \"detail\": ");
        try finding.appendJsonEscaped(&out, allocator, f.detail);
        try out.appendSlice(allocator, ",\n      \"artifact\": ");
        try finding.appendJsonEscaped(&out, allocator, f.artifact);
        try out.appendSlice(allocator, ",\n      \"rva\": ");
        if (f.rva) |r| {
            try appendFmt(&out, allocator, "{d}", .{r});
        } else {
            try out.appendSlice(allocator, "null");
        }
        try out.appendSlice(allocator, ",\n      \"file_offset\": ");
        if (f.file_offset) |fo| {
            try appendFmt(&out, allocator, "{d}", .{fo});
        } else {
            try out.appendSlice(allocator, "null");
        }
        try out.appendSlice(allocator, ",\n      \"func_name\": ");
        if (f.func_name) |fn_name| {
            try finding.appendJsonEscaped(&out, allocator, fn_name);
        } else {
            try out.appendSlice(allocator, "null");
        }
        try out.appendSlice(allocator, ",\n      \"remediation\": ");
        try finding.appendJsonEscaped(&out, allocator, f.remediation);
        try out.appendSlice(allocator, ",\n      \"cwe\": ");
        if (f.cwe) |c| {
            try appendFmt(&out, allocator, "{d}", .{c});
        } else {
            try out.appendSlice(allocator, "null");
        }
        var fp_buf: [16]u8 = undefined;
        const fp_hex = try std.fmt.bufPrint(&fp_buf, "{x:0>16}", .{f.fingerprint});
        try out.appendSlice(allocator, ",\n      \"fingerprint\": ");
        try finding.appendJsonEscaped(&out, allocator, fp_hex);
        try out.appendSlice(allocator, "\n    }");
    }
    try out.appendSlice(allocator, "\n  ]\n}\n");
    return out.toOwnedSlice(allocator);
}

fn renderSarif(allocator: std.mem.Allocator, fs: *const finding.FindingSet, artifact_bytes: ?[]const u8) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);

    // Collect unique rule IDs referenced in this finding set
    var seen_rules = std.StringHashMap(finding.Finding).init(allocator);
    defer seen_rules.deinit();
    var rule_order = std.ArrayList([]const u8).empty;
    defer rule_order.deinit(allocator);

    var seen_artifacts = std.StringHashMap(void).init(allocator);
    defer seen_artifacts.deinit();
    var artifact_order = std.ArrayList([]const u8).empty;
    defer artifact_order.deinit(allocator);

    for (fs.items.items) |f| {
        if (!seen_rules.contains(f.rule_id)) {
            try seen_rules.put(f.rule_id, f);
            try rule_order.append(allocator, f.rule_id);
        }
        if (f.artifact.len > 0 and !seen_artifacts.contains(f.artifact)) {
            try seen_artifacts.put(f.artifact, {});
            try artifact_order.append(allocator, f.artifact);
        }
    }

    try out.appendSlice(allocator,
        "{\n  \"$schema\": \"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json\",\n  \"version\": \"2.1.0\",\n  \"runs\": [\n    {\n      \"tool\": {\n        \"driver\": {\n          \"name\": "
    );
    try finding.appendJsonEscaped(&out, allocator, finding.TOOL_NAME);
    try out.appendSlice(allocator, ",\n          \"version\": ");
    try finding.appendJsonEscaped(&out, allocator, finding.TOOL_VERSION);
    try out.appendSlice(allocator, ",\n          \"informationUri\": ");
    try finding.appendJsonEscaped(&out, allocator, "https://github.com/Elephantpanda6/snap-oracle");
    try out.appendSlice(allocator, ",\n          \"rules\": [\n");

    for (rule_order.items, 0..) |rid, idx| {
        if (idx > 0) try out.appendSlice(allocator, ",\n");
        const meta = finding.findRule(rid);
        const sample = seen_rules.get(rid).?;
        const title = if (meta) |m| m.title else sample.title;
        const help_uri = if (meta) |m| m.help_uri else finding.HELP_BASE_URI;
        const default_sev = if (meta) |m| m.default_severity else sample.severity;

        try out.appendSlice(allocator, "            {\n              \"id\": ");
        try finding.appendJsonEscaped(&out, allocator, rid);
        try out.appendSlice(allocator, ",\n              \"shortDescription\": { \"text\": ");
        try finding.appendJsonEscaped(&out, allocator, title);
        try out.appendSlice(allocator, " },\n              \"fullDescription\": { \"text\": ");
        try finding.appendJsonEscaped(&out, allocator, sample.remediation);
        try out.appendSlice(allocator, " },\n              \"helpUri\": ");
        try finding.appendJsonEscaped(&out, allocator, help_uri);
        try out.appendSlice(allocator, ",\n              \"defaultConfiguration\": { \"level\": ");
        try finding.appendJsonEscaped(&out, allocator, default_sev.toSarifLevel());
        try out.appendSlice(allocator, " },\n              \"properties\": { \"security-severity\": ");
        try finding.appendJsonEscaped(&out, allocator, default_sev.toSecuritySeverityScore());
        try out.appendSlice(allocator, " }\n            }");
    }

    try out.appendSlice(allocator, "\n          ]\n        }\n      },\n      \"artifacts\": [\n");
    for (artifact_order.items, 0..) |art, idx| {
        if (idx > 0) try out.appendSlice(allocator, ",\n");
        try out.appendSlice(allocator, "        {\n          \"location\": { \"uri\": ");
        try finding.appendJsonEscaped(&out, allocator, finding.basename(art));
        try out.appendSlice(allocator, " }");
        if (idx == 0) {
            if (artifact_bytes) |bytes| {
                const hex = finding.sha256Hex(bytes);
                try out.appendSlice(allocator, ",\n          \"hashes\": { \"sha-256\": ");
                try finding.appendJsonEscaped(&out, allocator, &hex);
                try out.appendSlice(allocator, " }");
            }
        }
        try out.appendSlice(allocator, "\n        }");
    }

    try out.appendSlice(allocator, "\n      ],\n      \"results\": [\n");
    for (fs.items.items, 0..) |f, idx| {
        if (idx > 0) try out.appendSlice(allocator, ",\n");
        try out.appendSlice(allocator, "        {\n          \"ruleId\": ");
        try finding.appendJsonEscaped(&out, allocator, f.rule_id);
        try out.appendSlice(allocator, ",\n          \"level\": ");
        try finding.appendJsonEscaped(&out, allocator, f.severity.toSarifLevel());
        try out.appendSlice(allocator, ",\n          \"message\": { \"text\": ");
        const msg = if (f.rva) |r|
            try std.fmt.allocPrint(allocator, "{s} (RVA 0x{x}). Remediation: {s}", .{ f.detail, r, f.remediation })
        else
            try std.fmt.allocPrint(allocator, "{s}. Remediation: {s}", .{ f.detail, f.remediation });
        defer allocator.free(msg);
        try finding.appendJsonEscaped(&out, allocator, msg);
        try out.appendSlice(allocator, " },\n          \"locations\": [{\n            \"physicalLocation\": {\n              \"artifactLocation\": { \"uri\": ");
        try finding.appendJsonEscaped(&out, allocator, finding.basename(f.artifact));
        try out.appendSlice(allocator, " },\n              \"region\": { \"byteOffset\": ");
        try appendFmt(&out, allocator, "{d}", .{f.file_offset orelse (f.rva orelse 0)});
        try out.appendSlice(allocator, " }\n            }\n          }],\n          \"partialFingerprints\": { \"primaryLocationLineHash\": ");
        var fp_buf: [16]u8 = undefined;
        const fp_hex = try std.fmt.bufPrint(&fp_buf, "{x:0>16}", .{f.fingerprint});
        try finding.appendJsonEscaped(&out, allocator, fp_hex);
        try out.appendSlice(allocator, " },\n          \"properties\": {\n            \"severity\": ");
        try finding.appendJsonEscaped(&out, allocator, f.severity.toString());
        try out.appendSlice(allocator, ",\n            \"confidence\": ");
        try finding.appendJsonEscaped(&out, allocator, f.confidence.toString());
        try out.appendSlice(allocator, ",\n            \"security-severity\": ");
        try finding.appendJsonEscaped(&out, allocator, f.severity.toSecuritySeverityScore());
        if (f.cwe) |c| {
            try appendFmt(&out, allocator, ",\n            \"cwe\": \"CWE-{d}\"", .{c});
        }
        try out.appendSlice(allocator, "\n          }\n        }");
    }
    try out.appendSlice(allocator, "\n      ]\n    }\n  ]\n}\n");
    return out.toOwnedSlice(allocator);
}

fn renderJunit(allocator: std.mem.Allocator, fs: *const finding.FindingSet) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);

    const failures = fs.countAtOrAbove(.medium);
    const total = if (fs.items.items.len == 0) @as(usize, 1) else fs.items.items.len;

    try appendFmt(&out, allocator,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuites tests=\"{d}\" failures=\"{d}\">\n  <testsuite name=\"{s}\" tests=\"{d}\" failures=\"{d}\">\n",
        .{ total, failures, finding.TOOL_NAME, total, failures },
    );

    if (fs.items.items.len == 0) {
        try out.appendSlice(allocator, "    <testcase classname=\"snap-oracle.audit\" name=\"baseline-clean\"/>\n");
    } else {
        for (fs.items.items) |f| {
            try out.appendSlice(allocator, "    <testcase classname=\"");
            try finding.appendXmlEscaped(&out, allocator, finding.basename(f.artifact));
            try out.appendSlice(allocator, "\" name=\"");
            try finding.appendXmlEscaped(&out, allocator, f.rule_id);
            if (f.func_name) |fn_name| {
                try out.appendSlice(allocator, "::");
                try finding.appendXmlEscaped(&out, allocator, fn_name);
            }
            try out.appendSlice(allocator, "\">\n");
            if (@intFromEnum(f.severity) >= @intFromEnum(finding.Severity.medium)) {
                try out.appendSlice(allocator, "      <failure type=\"");
                try finding.appendXmlEscaped(&out, allocator, f.severity.toString());
                try out.appendSlice(allocator, "\" message=\"");
                try finding.appendXmlEscaped(&out, allocator, f.title);
                try out.appendSlice(allocator, "\">");
                try finding.appendXmlEscaped(&out, allocator, f.detail);
                try out.appendSlice(allocator, "\nRemediation: ");
                try finding.appendXmlEscaped(&out, allocator, f.remediation);
                try out.appendSlice(allocator, "</failure>\n");
            }
            try out.appendSlice(allocator, "    </testcase>\n");
        }
    }

    try out.appendSlice(allocator, "  </testsuite>\n</testsuites>\n");
    return out.toOwnedSlice(allocator);
}

fn renderGha(allocator: std.mem.Allocator, fs: *const finding.FindingSet) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);

    for (fs.items.items) |f| {
        const level: []const u8 = switch (f.severity) {
            .critical, .high => "error",
            .medium => "warning",
            .low, .info => "notice",
        };
        try appendFmt(&out, allocator, "::{s} file={s},title={s} ({s})::{s} — Fix: {s}\n", .{
            level,
            finding.basename(f.artifact),
            f.rule_id,
            f.severity.toString(),
            f.detail,
            f.remediation,
        });
    }
    return out.toOwnedSlice(allocator);
}

pub fn runReportCommand(io: std.Io, allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len == 0) {
        std.debug.print("Usage: snap-oracle report convert <input.json> [--format sarif|json|junit|gha|text] [--out <file>]\n", .{});
        return;
    }

    var in_path: ?[]const u8 = null;
    var fmt: ReportFormat = .sarif;
    var out_path: ?[]const u8 = null;

    var i: usize = 0;
    if (std.mem.eql(u8, args[0], "convert")) i = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--format") and i + 1 < args.len) {
            i += 1;
            fmt = ReportFormat.fromString(args[i]) orelse return error.InvalidFormat;
        } else if (std.mem.eql(u8, a, "--out") and i + 1 < args.len) {
            i += 1;
            out_path = args[i];
        } else if (a.len > 0 and a[0] != '-') {
            in_path = a;
        }
    }

    const src_path = in_path orelse {
        std.debug.print("Usage: snap-oracle report convert <input.json> [--format sarif|json|junit|gha|text] [--out <file>]\n", .{});
        return;
    };

    const raw = try std.Io.Dir.cwd().readFileAlloc(io, src_path, allocator, .limited(64 * 1024 * 1024));
    defer allocator.free(raw);

    var fs = finding.FindingSet.init(allocator);
    defer fs.deinit();
    try parseJsonReportIntoFindingSet(allocator, raw, &fs);
    try emitOrPrint(io, allocator, &fs, fmt, out_path, null);
}
