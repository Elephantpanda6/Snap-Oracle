const std = @import("std");
const binary = @import("binary.zig");
const cfg = @import("cfg.zig");
const runner = @import("runner.zig");
const audit = @import("audit.zig");
const arm_laptops = @import("arm_laptops.zig");
const worker = @import("worker.zig");
const pool = @import("pool.zig");
const finding = @import("finding.zig");
const report = @import("report.zig");
const symbols = @import("symbols.zig");
const license = @import("license.zig");
const imports = @import("imports.zig");
const pagesize = @import("pagesize.zig");
const hardening = @import("hardening.zig");
const sbom = @import("sbom.zig");
const perfadvisor = @import("perfadvisor.zig");
const portscan = @import("portscan.zig");
const crash_triage = @import("crash_triage.zig");
const harnessgen = @import("harnessgen.zig");
const cmin = @import("cmin.zig");
const covreport = @import("covreport.zig");
const bench = @import("bench.zig");
const crashdb = @import("crashdb.zig");
const ci_gate = @import("ci_gate.zig");

fn getFlag(args: []const []const u8, name: []const u8) ?[]const u8 {
    var i: usize = 0;
    while (i + 1 < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], name)) return args[i + 1];
    }
    return null;
}

fn hasFlag(args: []const []const u8, name: []const u8) bool {
    for (args) |a| {
        if (std.mem.eql(u8, a, name)) return true;
    }
    return false;
}

fn printUsage() void {
    std.debug.print(
        \\{s} {s} (ARM64-First Cross-OS Security Gate, Auditor & Snapshot Fuzzer)
        \\Authorized Defensive & QA Testing Use Only. See LICENSE for Commercial Terms.
        \\
        \\Core Discovery & Hardware:
        \\  snap-oracle inspect     <binary>                      Parse PE32+/ELF64/Mach-O headers & BBs
        \\  snap-oracle audit       <binary> [--format ...]       ARM64 readiness, PAC/BTI/LSE, SARIF/JSON
        \\  snap-oracle sym         <binary> [rva_hex...]         Resolve symbols, demangle C++ & DWARF files
        \\  snap-oracle hwinfo                                    Probe live host ARM64 ISA/page-size/profile
        \\  snap-oracle profiles                                  List supported ARM64 laptop/server profiles
        \\
        \\Enterprise ARM64 Compliance & Porting:
        \\  snap-oracle deps        <binary> [--root dir]         PE/ARM64EC/ELF/Mach-O ABI dependency graph
        \\  snap-oracle pagesize    <binary> [--fix-hints]        4K/16K/64K kernel page-size readiness audit
        \\  snap-oracle harden      <binary> [--level strict]     PAC/BTI/CFG/RELRO/PIE/Codesign/MTE audit
        \\  snap-oracle sbom        <binary> [--format cyclonedx|spdx|text]  SBOM & build provenance
        \\  snap-oracle perf-advise <binary> [--profile id]       Scalar FP loops, LL/SC vs LSE, DotProd/AVX
        \\  snap-oracle portscan    <dir|src|bin> [--format ...]  x64->ARM64 C/C++/Rust/Zig & binary scanner
        \\
        \\Fuzzing, Coverage & Crash Triage:
        \\  snap-oracle fuzz        --target <bin> [--iters N] [--max-execs N] [--duration sec] [--jobs N]
        \\  snap-oracle diff        [--a <bin1> --b <bin2>] [--entry <fn>] [--iters N]
        \\  snap-oracle replay      --target <bin> --input <file> [--minimize]
        \\  snap-oracle triage      --target <bin> (--input <file> | --crash-dir <dir>) [--format sarif|json]
        \\  snap-oracle cmin        --target <bin> --corpus <in> --out <out> [--tmin]
        \\  snap-oracle cov         --target <bin> [--corpus <dir>] --format html|json|lcov|drcov --out <file>
        \\  snap-oracle gen         <harness|repro> --target <bin> [--input <crash>] --lang c|zig|rust|py
        \\  snap-oracle bench       [--suite all|decode|cfg|mutate|snapshot|exec] [--json out]
        \\  snap-oracle worker      --target <bin> [--entry <fn>] [--bti-safe]
        \\
        \\DevSecOps CI/CD & Licensing:
        \\  snap-oracle report      convert <in.json> --format sarif|junit|gha|json|text
        \\  snap-oracle crashdb     <init|add|list|stats> [--db path] [--report json]
        \\  snap-oracle baseline    <create|diff> --report <json> [--baseline base.json]
        \\  snap-oracle ci          <init|gate> [--provider github|gitlab|azdo|jenkins]
        \\  snap-oracle license     <status|terms|verify <file>|keygen-demo>
        \\
    , .{ finding.TOOL_NAME, finding.TOOL_VERSION });
}

fn cmdInspect(io: std.Io, allocator: std.mem.Allocator, path: []const u8) !void {
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(128 * 1024 * 1024));
    defer allocator.free(bytes);

    var img = try binary.parseBinary(allocator, bytes);
    defer img.deinit();

    std.debug.print("File:       {s}\n", .{path});
    std.debug.print("Format:     {s}\n", .{@tagName(img.format)});
    std.debug.print("Machine:    {s} (0x{x:0>4})\n", .{ @tagName(img.machine), @intFromEnum(img.machine) });
    std.debug.print("ImageBase:  0x{x}\n", .{img.image_base});
    std.debug.print("ImageSize:  {d} bytes (min_align={d})\n", .{ img.size_of_image, img.min_segment_align });
    std.debug.print("EntryRVA:   0x{x}\n", .{img.entry_rva});
    std.debug.print("Sections:   {d}\n", .{img.sections.len});
    std.debug.print("Functions:  {d}\n", .{img.functions.len});
    std.debug.print("Exports:    {d}\n", .{img.exports.len});

    if (img.findCodeSection()) |text_sec| {
        if (text_sec.raw_offset < bytes.len and text_sec.raw_size > 0) {
            const avail = @min(@as(usize, text_sec.raw_size), bytes.len - text_sec.raw_offset);
            const code = bytes[text_sec.raw_offset .. text_sec.raw_offset + avail];
            var total_bb: usize = 0;
            const sample_fns = @min(img.functions.len, 64);
            for (img.functions[0..sample_fns]) |f| {
                if (f.begin_rva < text_sec.virtual_address or f.end_rva > text_sec.virtual_address + text_sec.raw_size) continue;
                const bbs = switch (img.machine) {
                    .arm64, .arm64ec => try cfg.decodeArm64BasicBlocksEx(allocator, code, text_sec.virtual_address, f.begin_rva, f.end_rva, true),
                    .amd64 => try cfg.decodeX64BasicBlocksFull(allocator, code, text_sec.virtual_address, f.begin_rva, f.end_rva),
                    else => continue,
                };
                defer allocator.free(bbs);
                total_bb += bbs.len;
            }
            std.debug.print("Decoded BBs (first {d} funcs): {d}\n", .{ sample_fns, total_bb });
        }
    }
}

pub fn main(init: std.process.Init) !u8 {
    const allocator = std.heap.c_allocator;

    var args_list = std.ArrayList([]const u8).empty;
    defer args_list.deinit(allocator);
    var it = try init.minimal.args.iterateAllocator(allocator);
    defer it.deinit();
    while (it.next()) |arg| {
        try args_list.append(allocator, arg);
    }
    const args = args_list.items;

    if (args.len < 2) {
        printUsage();
        return 0;
    }

    const sub = args[1];
    const rest = args[2..];

    if (std.mem.eql(u8, sub, "help") or std.mem.eql(u8, sub, "--help") or std.mem.eql(u8, sub, "-h")) {
        printUsage();
        return 0;
    } else if (std.mem.eql(u8, sub, "inspect") and rest.len >= 1) {
        try cmdInspect(init.io, allocator, rest[0]);
        return 0;
    } else if (std.mem.eql(u8, sub, "audit")) {
        return try audit.runAuditCommandEx(init.io, allocator, rest);
    } else if (std.mem.eql(u8, sub, "hwinfo")) {
        arm_laptops.printHostInfo();
        return 0;
    } else if (std.mem.eql(u8, sub, "profiles")) {
        arm_laptops.printAllProfiles();
        return 0;
    } else if (std.mem.eql(u8, sub, "deps")) {
        return try imports.runDepsCommand(init.io, allocator, rest);
    } else if (std.mem.eql(u8, sub, "pagesize")) {
        return try pagesize.runPagesizeCommand(init.io, allocator, rest);
    } else if (std.mem.eql(u8, sub, "harden")) {
        return try hardening.runHardenCommand(init.io, allocator, rest);
    } else if (std.mem.eql(u8, sub, "sbom")) {
        try sbom.runSbomCommand(init.io, allocator, rest);
        return 0;
    } else if (std.mem.eql(u8, sub, "perf-advise")) {
        return try perfadvisor.runPerfAdviseCommand(init.io, allocator, rest);
    } else if (std.mem.eql(u8, sub, "portscan")) {
        return try portscan.runPortscanCommand(init.io, allocator, rest);
    } else if (std.mem.eql(u8, sub, "triage")) {
        return try crash_triage.runTriageCommand(init.io, allocator, rest);
    } else if (std.mem.eql(u8, sub, "gen")) {
        try harnessgen.runGenCommand(init.io, allocator, rest);
        return 0;
    } else if (std.mem.eql(u8, sub, "cmin")) {
        try cmin.runCminCommand(init.io, allocator, rest);
        return 0;
    } else if (std.mem.eql(u8, sub, "cov")) {
        try covreport.runCovCommand(init.io, allocator, rest);
        return 0;
    } else if (std.mem.eql(u8, sub, "bench")) {
        return try bench.runBenchCommand(init.io, allocator, rest);
    } else if (std.mem.eql(u8, sub, "crashdb")) {
        try crashdb.runCrashDbCommand(init.io, allocator, rest);
        return 0;
    } else if (std.mem.eql(u8, sub, "baseline")) {
        return try crashdb.runBaselineCommand(init.io, allocator, rest);
    } else if (std.mem.eql(u8, sub, "ci")) {
        return try ci_gate.runCiCommand(init.io, allocator, rest);
    } else if (std.mem.eql(u8, sub, "sym")) {
        try symbols.runSymCommand(init.io, allocator, rest);
        return 0;
    } else if (std.mem.eql(u8, sub, "report")) {
        try report.runReportCommand(init.io, allocator, rest);
        return 0;
    } else if (std.mem.eql(u8, sub, "license")) {
        return try license.runLicenseCommand(init.io, allocator, rest);
    } else if (std.mem.eql(u8, sub, "fuzz")) {
        const target = getFlag(rest, "--target") orelse {
            printUsage();
            return 2;
        };
        const entry = getFlag(rest, "--entry") orelse "fuzz_entry";
        const iters_str = getFlag(rest, "--iters") orelse "1000";
        const iters = std.fmt.parseInt(usize, iters_str, 10) catch 1000;
        const max_execs_str = getFlag(rest, "--max-execs") orelse "0";
        const max_execs = std.fmt.parseInt(u64, max_execs_str, 10) catch 0;
        const dur_str = getFlag(rest, "--duration") orelse "0";
        const max_seconds = std.fmt.parseInt(u64, dur_str, 10) catch 0;
        const corpus_dir = getFlag(rest, "--corpus");
        const dict_path = getFlag(rest, "--dict");
        const max_in_str = getFlag(rest, "--max-input") orelse "4096";
        const max_input = std.fmt.parseInt(usize, max_in_str, 10) catch 4096;
        const seed_opt: ?u64 = if (getFlag(rest, "--seed")) |s|
            std.fmt.parseInt(u64, s, 0) catch null
        else
            null;
        const jobs_str = getFlag(rest, "--jobs") orelse "1";
        const jobs = std.fmt.parseInt(usize, jobs_str, 10) catch 1;
        const laptop_profile = getFlag(rest, "--laptop");
        const bti_safe = hasFlag(rest, "--bti-safe");

        if (jobs > 1) {
            try pool.runPoolFuzz(
                init.io,
                allocator,
                args[0],
                target,
                entry,
                if (max_execs > 0) @intCast(max_execs) else iters,
                jobs,
                corpus_dir,
                dict_path,
                max_input,
                laptop_profile,
                bti_safe,
            );
        } else {
            try runner.runFuzzEx(init.io, allocator, .{
                .target_path = target,
                .entry_name = entry,
                .iters = iters,
                .max_execs = max_execs,
                .max_seconds = max_seconds,
                .corpus_dir = corpus_dir,
                .dict_path = dict_path,
                .max_input = max_input,
                .seed = seed_opt,
                .laptop_profile = laptop_profile,
                .bti_safe = bti_safe,
            });
        }
        return 0;
    } else if (std.mem.eql(u8, sub, "diff")) {
        const bin_a = getFlag(rest, "--a") orelse getFlag(rest, "--x64") orelse {
            printUsage();
            return 2;
        };
        const bin_b = getFlag(rest, "--b") orelse getFlag(rest, "--arm64") orelse {
            printUsage();
            return 2;
        };
        const entry = getFlag(rest, "--entry") orelse "fuzz_entry";
        const iters_str = getFlag(rest, "--iters") orelse "1000";
        const iters = std.fmt.parseInt(usize, iters_str, 10) catch 1000;
        try runner.runDiff(init.io, allocator, bin_a, bin_b, entry, iters);
        return 0;
    } else if (std.mem.eql(u8, sub, "replay")) {
        const target = getFlag(rest, "--target") orelse {
            printUsage();
            return 2;
        };
        const entry = getFlag(rest, "--entry") orelse "fuzz_entry";
        const input = getFlag(rest, "--input") orelse {
            printUsage();
            return 2;
        };
        const minimize = hasFlag(rest, "--minimize");
        try runner.runReplay(init.io, allocator, target, entry, input, minimize);
        return 0;
    } else if (std.mem.eql(u8, sub, "worker")) {
        const target = getFlag(rest, "--target") orelse {
            printUsage();
            return 2;
        };
        const entry = getFlag(rest, "--entry") orelse "fuzz_entry";
        const bti_safe = hasFlag(rest, "--bti-safe");
        try worker.runWorkerStdio(init.io, allocator, target, entry, bti_safe);
        return 0;
    } else {
        printUsage();
        return 2;
    }
}
