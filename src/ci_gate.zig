const std = @import("std");
const finding = @import("finding.zig");
const report = @import("report.zig");
const crashdb = @import("crashdb.zig");
const license = @import("license.zig");

pub const CiProvider = enum {
    github,
    gitlab,
    azdo,
    jenkins,

    pub fn fromString(s: []const u8) ?CiProvider {
        if (finding.eqlIgnoreCase(s, "github") or finding.eqlIgnoreCase(s, "gha")) return .github;
        if (finding.eqlIgnoreCase(s, "gitlab")) return .gitlab;
        if (finding.eqlIgnoreCase(s, "azdo") or finding.eqlIgnoreCase(s, "azure")) return .azdo;
        if (finding.eqlIgnoreCase(s, "jenkins")) return .jenkins;
        return null;
    }
};

pub const Waiver = struct {
    rule_id: []const u8,
    artifact: []const u8 = "",
    expires: []const u8 = "2099-12-31",
    reason: []const u8 = "",
};

pub const WaiverDoc = struct {
    fail_on: ?[]const u8 = null,
    max_new: ?usize = null,
    waivers: []const Waiver = &.{},
};

pub fn renderPipelineTemplate(provider: CiProvider) []const u8 {
    return switch (provider) {
        .github =>
        \\name: Snap-Oracle ARM64 Security Gate
        \\on: [push, pull_request]
        \\jobs:
        \\  arm64-gate:
        \\    strategy:
        \\      matrix:
        \\        os: [ubuntu-24.04-arm, windows-11-arm, macos-14]
        \\    runs-on: ${{ matrix.os }}
        \\    steps:
        \\      - uses: actions/checkout@v4
        \\      - uses: mlugg/setup-zig@v2
        \\        with:
        \\          version: 0.17.1
        \\      - run: zig build test
        \\      - run: zig build -Doptimize=ReleaseFast
        \\      - name: Hardening & Page-Size Gate
        \\        shell: bash
        \\        run: |
        \\          TARGET="$(ls ./zig-out/bin/test_target.dll ./zig-out/lib/libtest_target.* 2>/dev/null | head -n 1)"
        \\          ./zig-out/bin/snap-oracle harden "$TARGET" --format sarif --out harden.sarif --fail-on high
        \\          ./zig-out/bin/snap-oracle pagesize "$TARGET" --targets 16k,64k --fix-hints
        \\          ./zig-out/bin/snap-oracle deps "$TARGET" --recursive
        \\          ./zig-out/bin/snap-oracle sbom "$TARGET" --format cyclonedx --out bom.cdx.json
        \\      - name: Time-boxed Snapshot Fuzzing
        \\        shell: bash
        \\        run: |
        \\          TARGET="$(ls ./zig-out/bin/test_target.dll ./zig-out/lib/libtest_target.* 2>/dev/null | head -n 1)"
        \\          ./zig-out/bin/snap-oracle fuzz --target "$TARGET" --max-execs 250000 --duration 60
        \\      - uses: github/codeql-action/upload-sarif@v3
        \\        if: always()
        \\        with:
        \\          sarif_file: harden.sarif
        \\
        ,
        .gitlab =>
        \\stages:
        \\  - arm64_audit
        \\  - arm64_fuzz
        \\
        \\arm64_static_gate:
        \\  stage: arm64_audit
        \\  tags: [arm64]
        \\  script:
        \\    - zig build -Doptimize=ReleaseFast
        \\    - ./zig-out/bin/snap-oracle harden ./zig-out/lib/test_target.so --format json --out findings.json
        \\    - ./zig-out/bin/snap-oracle pagesize ./zig-out/lib/test_target.so --fail-on high
        \\    - ./zig-out/bin/snap-oracle sbom ./zig-out/lib/test_target.so --format spdx --out bom.spdx.json
        \\    - ./zig-out/bin/snap-oracle ci gate --report findings.json --fail-on high
        \\  artifacts:
        \\    paths: [findings.json, bom.spdx.json]
        \\
        ,
        .azdo =>
        \\trigger:
        \\  - main
        \\pool:
        \\  vmImage: 'ubuntu-24.04-arm'
        \\steps:
        \\  - script: |
        \\      zig build -Doptimize=ReleaseFast
        \\      ./zig-out/bin/snap-oracle harden ./zig-out/lib/test_target.so --format sarif --out $(Build.ArtifactStagingDirectory)/snap-oracle.sarif --fail-on high
        \\      ./zig-out/bin/snap-oracle deps ./zig-out/lib/test_target.so --recursive --fail-on critical
        \\    displayName: 'Snap-Oracle ARM64 Security Gate'
        \\
        ,
        .jenkins =>
        \\pipeline {
        \\  agent { label 'arm64' }
        \\  stages {
        \\    stage('Build & Audit') {
        \\      steps {
        \\        sh 'zig build -Doptimize=ReleaseFast'
        \\        sh './zig-out/bin/snap-oracle harden ./zig-out/lib/test_target.so --format junit --out snap-oracle-junit.xml --fail-on high'
        \\        sh './zig-out/bin/snap-oracle sbom ./zig-out/lib/test_target.so --format cyclonedx --out bom.cdx.json'
        \\      }
        \\    }
        \\  }
        \\  post {
        \\    always { junit 'snap-oracle-junit.xml' }
        \\  }
        \\}
        \\
        ,
    };
}

pub fn evaluateGate(
    allocator: std.mem.Allocator,
    raw_report_json: []const u8,
    baseline_json: ?[]const u8,
    waivers_json: ?[]const u8,
    cli_fail_on: finding.Severity,
    today_ymd: u32,
    out_active: *finding.FindingSet,
) !struct {
    passed: bool,
    total: usize,
    suppressed_baseline: usize,
    waived: usize,
    expired_waivers: usize,
    remaining_failing: usize,
} {
    var cur_fs = finding.FindingSet.init(allocator);
    defer cur_fs.deinit();
    try report.parseJsonReportIntoFindingSet(allocator, raw_report_json, &cur_fs);

    var after_base = finding.FindingSet.init(allocator);
    defer after_base.deinit();
    var suppressed_base: usize = 0;
    if (baseline_json) |bj| {
        suppressed_base = try crashdb.filterFindingsAgainstBaseline(allocator, &cur_fs, bj, &after_base);
    } else {
        for (cur_fs.items.items) |f| {
            try after_base.add(.{
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
    }

    var effective_fail_on = cli_fail_on;
    var max_new_cap: ?usize = null;
    var parsed_waivers: ?std.json.Parsed(WaiverDoc) = null;
    defer if (parsed_waivers) |pw| pw.deinit();

    var expired_waivers: usize = 0;
    if (waivers_json) |wj| {
        parsed_waivers = try std.json.parseFromSlice(WaiverDoc, allocator, wj, .{ .ignore_unknown_fields = true });
        if (parsed_waivers.?.value.fail_on) |fo| {
            effective_fail_on = finding.Severity.fromString(fo) orelse cli_fail_on;
        }
        max_new_cap = parsed_waivers.?.value.max_new;
        for (parsed_waivers.?.value.waivers) |w| {
            const exp_opt = license.parseYmd(w.expires);
            if (exp_opt == null or (today_ymd > 0 and exp_opt.? < today_ymd)) {
                expired_waivers += 1;
            }
        }
    }

    var waived_cnt: usize = 0;
    for (after_base.items.items) |f| {
        var is_waived = false;
        if (parsed_waivers) |pw| {
            for (pw.value.waivers) |w| {
                if (!std.mem.eql(u8, w.rule_id, f.rule_id)) continue;
                if (w.artifact.len > 0 and !std.mem.eql(u8, finding.basename(w.artifact), finding.basename(f.artifact))) continue;
                const exp = license.parseYmd(w.expires) orelse continue; // Fail closed on malformed expiry!
                if (today_ymd > 0 and exp < today_ymd) continue; // Waiver expired!
                is_waived = true;
                break;
            }
        }
        if (is_waived) {
            waived_cnt += 1;
            continue;
        }
        try out_active.add(.{
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

    const sev_hits = out_active.countAtOrAbove(effective_fail_on);
    const exceeds_cap = if (max_new_cap) |cap| out_active.items.items.len > cap else false;
    const passed = (sev_hits == 0 and !exceeds_cap);

    return .{
        .passed = passed,
        .total = cur_fs.items.items.len,
        .suppressed_baseline = suppressed_base,
        .waived = waived_cnt,
        .expired_waivers = expired_waivers,
        .remaining_failing = sev_hits,
    };
}

pub fn currentUtcYmd(io: std.Io) u32 {
    const ts = std.Io.Timestamp.now(io, .real);
    const secs_i64 = ts.toSeconds();
    const secs: u64 = if (secs_i64 > 0) @intCast(secs_i64) else 0;
    const epoch_secs = std.time.epoch.EpochSeconds{ .secs = secs };
    const year_day = epoch_secs.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const y: u32 = year_day.year;
    const m: u32 = month_day.month.numeric();
    const d: u32 = @as(u32, month_day.day_index) + 1;
    return y * 10000 + m * 100 + d;
}

pub fn runCiCommand(io: std.Io, allocator: std.mem.Allocator, args: []const []const u8) !u8 {
    if (args.len == 0) {
        std.debug.print("Usage: snap-oracle ci <init|gate> ...\n", .{});
        return 2;
    }

    const sub = args[0];
    if (std.mem.eql(u8, sub, "init")) {
        var provider: CiProvider = .github;
        var out_path: ?[]const u8 = null;
        var i: usize = 1;
        while (i < args.len) : (i += 1) {
            if (std.mem.eql(u8, args[i], "--provider") and i + 1 < args.len) {
                i += 1;
                provider = CiProvider.fromString(args[i]) orelse .github;
            } else if (std.mem.eql(u8, args[i], "--out") and i + 1 < args.len) {
                i += 1;
                out_path = args[i];
            }
        }
        const tpl = renderPipelineTemplate(provider);
        if (out_path) |op| {
            try finding.writeOutputFile(io, op, tpl);
            std.debug.print("[ci init] wrote {s} ARM64 pipeline template -> {s}\n", .{ @tagName(provider), op });
        } else {
            finding.writeStdout(io, tpl);
        }
        return 0;
    }

    if (std.mem.eql(u8, sub, "gate")) {
        var report_path: ?[]const u8 = null;
        var base_path: ?[]const u8 = null;
        var policy_path: ?[]const u8 = null;
        var fail_on: finding.Severity = .high;
        var today_ymd: u32 = currentUtcYmd(io);
        var fmt: report.ReportFormat = .text;
        var out_path: ?[]const u8 = null;

        var i: usize = 1;
        while (i < args.len) : (i += 1) {
            const a = args[i];
            if (std.mem.eql(u8, a, "--report") and i + 1 < args.len) {
                i += 1;
                report_path = args[i];
            } else if (std.mem.eql(u8, a, "--baseline") and i + 1 < args.len) {
                i += 1;
                base_path = args[i];
            } else if ((std.mem.eql(u8, a, "--policy") or std.mem.eql(u8, a, "--waivers")) and i + 1 < args.len) {
                i += 1;
                policy_path = args[i];
            } else if (std.mem.eql(u8, a, "--fail-on") and i + 1 < args.len) {
                i += 1;
                fail_on = finding.Severity.fromString(args[i]) orelse .high;
            } else if (std.mem.eql(u8, a, "--today") and i + 1 < args.len) {
                i += 1;
                today_ymd = license.parseYmd(args[i]) orelse {
                    std.debug.print("[ci gate] invalid --today date '{s}' (expected YYYY-MM-DD or YYYYMMDD)\n", .{args[i]});
                    return 2;
                };
            } else if (std.mem.eql(u8, a, "--format") and i + 1 < args.len) {
                i += 1;
                fmt = report.ReportFormat.fromString(args[i]) orelse .text;
            } else if (std.mem.eql(u8, a, "--out") and i + 1 < args.len) {
                i += 1;
                out_path = args[i];
            }
        }

        const rp = report_path orelse {
            std.debug.print("Usage: snap-oracle ci gate --report <findings.json> [--baseline <base.json>] [--policy <waivers.json>] [--fail-on high]\n", .{});
            return 2;
        };

        const raw_rep = try std.Io.Dir.cwd().readFileAlloc(io, rp, allocator, .limited(64 * 1024 * 1024));
        defer allocator.free(raw_rep);

        const base_raw: ?[]u8 = if (base_path) |bp|
            try std.Io.Dir.cwd().readFileAlloc(io, bp, allocator, .limited(16 * 1024 * 1024))
        else
            null;
        defer if (base_raw) |br| allocator.free(br);

        const pol_raw: ?[]u8 = if (policy_path) |pp|
            try std.Io.Dir.cwd().readFileAlloc(io, pp, allocator, .limited(4 * 1024 * 1024))
        else
            null;
        defer if (pol_raw) |pr| allocator.free(pr);

        var active = finding.FindingSet.init(allocator);
        defer active.deinit();
        const ev = try evaluateGate(allocator, raw_rep, base_raw, pol_raw, fail_on, today_ymd, &active);

        if (fmt == .text) {
            std.debug.print(
                "[ci gate] status={s} | total={d} baseline_suppressed={d} waived={d} expired_waivers={d} failing={d}\n",
                .{
                    if (ev.passed) "PASS" else "FAIL",
                    ev.total,
                    ev.suppressed_baseline,
                    ev.waived,
                    ev.expired_waivers,
                    ev.remaining_failing,
                },
            );
        }
        try report.emitOrPrint(io, allocator, &active, fmt, out_path, null);
        return if (ev.passed) 0 else 1;
    }

    std.debug.print("Usage: snap-oracle ci <init|gate> ...\n", .{});
    return 2;
}
