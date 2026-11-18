const std = @import("std");
const builtin = @import("builtin");
const arm64_isa = @import("arm64_isa.zig");
const arm_laptops = @import("arm_laptops.zig");
const cfg = @import("cfg.zig");
const mutator = @import("mutator.zig");
const l1 = @import("l1_engine.zig");
const runner = @import("runner.zig");
const veh = @import("veh.zig");
const binary = @import("binary.zig");
const finding = @import("finding.zig");

pub const SuiteKind = enum {
    decode,
    cfg,
    mutate,
    snapshot,
    exec,
    all,

    pub fn fromString(s: []const u8) ?SuiteKind {
        if (finding.eqlIgnoreCase(s, "decode")) return .decode;
        if (finding.eqlIgnoreCase(s, "cfg")) return .cfg;
        if (finding.eqlIgnoreCase(s, "mutate")) return .mutate;
        if (finding.eqlIgnoreCase(s, "snapshot")) return .snapshot;
        if (finding.eqlIgnoreCase(s, "exec")) return .exec;
        if (finding.eqlIgnoreCase(s, "all")) return .all;
        return null;
    }
};

pub const BenchMetric = struct {
    name: []const u8,
    ops_per_iter: u64,
    unit_label: []const u8,
    median_ns: u64,
    p95_ns: u64,
    mad_ns: u64,
    throughput_per_sec: u64,
};

fn computeStats(samples_ns: *[15]u64) struct { median: u64, p95: u64, mad: u64 } {
    var sorted = samples_ns.*;
    std.mem.sort(u64, &sorted, {}, std.sort.asc(u64));
    const median = sorted[7];
    const p95 = sorted[14];

    var devs: [15]u64 = undefined;
    for (sorted, 0..) |s, i| {
        devs[i] = if (s >= median) s - median else median - s;
    }
    std.mem.sort(u64, &devs, {}, std.sort.asc(u64));
    return .{
        .median = @max(median, 1),
        .p95 = @max(p95, 1),
        .mad = devs[7],
    };
}

fn throughput(ops: u64, ns: u64) u64 {
    if (ns == 0) return 0;
    return @intCast((@as(u128, ops) * 1_000_000_000) / ns);
}

fn benchDecode(io: std.Io, allocator: std.mem.Allocator) !BenchMetric {
    const N_INSNS: usize = 100_000;
    const words = try allocator.alloc(u32, N_INSNS);
    defer allocator.free(words);
    var rng = mutator.Rng.init(0x9E37_79B9_7F4A_7C15);
    const seed_insns = [_]u32{
        0xD503_233F, // paciasp
        0x5400_0040, // b.eq
        0xB8E0_0041, // ldaddal
        0x4E80_9400, // sdot
        0x1E20_0800, // fp scalar
        0xD65F_03C0, // ret
    };
    for (words, 0..) |*w, i| {
        w.* = if ((i & 3) == 0) seed_insns[i % seed_insns.len] else @truncate(rng.next());
    }

    var sink: u64 = 0;
    var samples: [15]u64 = undefined;
    for (0..17) |iter| {
        const t0 = std.Io.Timestamp.now(io, .awake);
        var acc: u64 = 0;
        for (words) |w| {
            const d = arm64_isa.decode(w);
            const ce = arm64_isa.classifyComputeExt(w);
            acc +%= @intFromEnum(d.class) +% @intFromEnum(ce);
        }
        std.mem.doNotOptimizeAway(&acc);
        sink +%= acc;
        const t1 = std.Io.Timestamp.now(io, .awake);
        if (iter >= 2) {
            samples[iter - 2] = @intCast(@max(t1.nanoseconds - t0.nanoseconds, 1));
        }
    }
    std.mem.doNotOptimizeAway(&sink);
    const st = computeStats(&samples);
    return .{
        .name = "arm64_decode",
        .ops_per_iter = N_INSNS,
        .unit_label = "insns/s",
        .median_ns = st.median,
        .p95_ns = st.p95,
        .mad_ns = st.mad,
        .throughput_per_sec = throughput(N_INSNS, st.median),
    };
}

fn benchCfg(io: std.Io, allocator: std.mem.Allocator) !BenchMetric {
    // 64 synthetic basic blocks stitched into one 1024-byte AArch64 routine
    var code: [256]u32 = @splat(0xD503_201F);
    var k: usize = 0;
    while (k + 4 < 252) : (k += 4) {
        code[k] = 0xD503_245F; // bti c
        code[k + 1] = 0x5400_0040; // b.eq +8
        code[k + 2] = 0x1E20_0800; // fadd s0, s0, s0
    }
    code[255] = 0xD65F_03C0; // ret
    const code_bytes = std.mem.sliceAsBytes(&code);

    const N_RUNS: u64 = 500;
    var sink: u64 = 0;
    var samples: [15]u64 = undefined;
    for (0..17) |iter| {
        const t0 = std.Io.Timestamp.now(io, .awake);
        for (0..N_RUNS) |_| {
            const bbs = try cfg.decodeArm64BasicBlocksEx(allocator, code_bytes, 0x1000, 0x1000, 0x1000 + 1024, true);
            sink +%= bbs.len;
            allocator.free(bbs);
        }
        const t1 = std.Io.Timestamp.now(io, .awake);
        if (iter >= 2) {
            samples[iter - 2] = @intCast(@max(t1.nanoseconds - t0.nanoseconds, 1));
        }
    }
    std.mem.doNotOptimizeAway(&sink);
    const st = computeStats(&samples);
    return .{
        .name = "cfg_recovery",
        .ops_per_iter = N_RUNS,
        .unit_label = "cfgs/s",
        .median_ns = st.median,
        .p95_ns = st.p95,
        .mad_ns = st.mad,
        .throughput_per_sec = throughput(N_RUNS, st.median),
    };
}

fn benchMutate(io: std.Io, allocator: std.mem.Allocator) !BenchMetric {
    const N_MUTS: usize = 50_000;
    const BUF_LEN: usize = 1024;
    const buf = try allocator.alloc(u8, BUF_LEN);
    defer allocator.free(buf);
    @memset(buf, 0x41);

    var rng = mutator.Rng.init(0x1234_5678_9ABC_DEF0);
    var dict = mutator.Dictionary.init();
    _ = dict.add("GGUF");
    _ = dict.add("STAT");

    var sink: usize = 0;
    var samples: [15]u64 = undefined;
    for (0..17) |iter| {
        const t0 = std.Io.Timestamp.now(io, .awake);
        var cur_len: usize = 64;
        for (0..N_MUTS) |_| {
            cur_len = mutator.mutateWithDict(&rng, buf, cur_len, BUF_LEN, &dict);
            if (cur_len < 8) {
                @memcpy(buf[0..16], "GGUF_BENCH_SEED!");
                cur_len = 16;
            }
            sink +%= cur_len;
        }
        const t1 = std.Io.Timestamp.now(io, .awake);
        if (iter >= 2) {
            samples[iter - 2] = @intCast(@max(t1.nanoseconds - t0.nanoseconds, 1));
        }
    }
    std.mem.doNotOptimizeAway(&sink);
    const st = computeStats(&samples);
    return .{
        .name = "havoc_mutate",
        .ops_per_iter = N_MUTS,
        .unit_label = "muts/s",
        .median_ns = st.median,
        .p95_ns = st.p95,
        .mad_ns = st.mad,
        .throughput_per_sec = throughput(N_MUTS, st.median),
    };
}

fn benchSnapshot(io: std.Io, allocator: std.mem.Allocator) !BenchMetric {
    var arena = try l1.SnapshotArena.init(allocator, 64 * 1024);
    defer arena.deinit();
    arena.takeSnapshot();

    const N_RESETS: usize = 10_000;
    var sink: usize = 0;
    var samples: [15]u64 = undefined;
    for (0..17) |iter| {
        const t0 = std.Io.Timestamp.now(io, .awake);
        for (0..N_RESETS) |k| {
            // Dirty 2 pages per execution
            arena.live_ptr[0] = @truncate(k);
            arena.live_ptr[4096] = @truncate(k >> 8);
            sink +%= try arena.restoreDirtyPages();
        }
        const t1 = std.Io.Timestamp.now(io, .awake);
        if (iter >= 2) {
            samples[iter - 2] = @intCast(@max(t1.nanoseconds - t0.nanoseconds, 1));
        }
    }
    std.mem.doNotOptimizeAway(&sink);
    const st = computeStats(&samples);
    return .{
        .name = "l1_snapshot_2pg",
        .ops_per_iter = N_RESETS,
        .unit_label = "resets/s",
        .median_ns = st.median,
        .p95_ns = st.p95,
        .mad_ns = st.mad,
        .throughput_per_sec = throughput(N_RESETS, st.median),
    };
}

fn benchExec(io: std.Io, allocator: std.mem.Allocator, target_path: []const u8, entry_name: []const u8) !BenchMetric {
    const img_bytes = try std.Io.Dir.cwd().readFileAlloc(io, target_path, allocator, .limited(64 * 1024 * 1024));
    defer allocator.free(img_bytes);
    var img = try binary.parseBinary(allocator, img_bytes);
    defer img.deinit();

    var loaded = try runner.LoadedTarget.load(allocator, target_path, entry_name);
    defer loaded.unload();
    var guard = veh.Guard.init();
    defer guard.deinit();

    var arena = try l1.SnapshotArena.init(allocator, 64 * 1024);
    defer arena.deinit();
    @memcpy(arena.live_ptr[0..8], "BENCH_IN");
    arena.takeSnapshot();

    const N_EXECS: usize = 20_000;
    var sink: u64 = 0;
    var samples: [15]u64 = undefined;
    for (0..17) |iter| {
        const t0 = std.Io.Timestamp.now(io, .awake);
        for (0..N_EXECS) |_| {
            const r = veh.runProtected(loaded.entry, arena.live_ptr, 8);
            sink +%= r.ret_val;
            _ = arena.restoreDirtyPages() catch 0;
        }
        const t1 = std.Io.Timestamp.now(io, .awake);
        if (iter >= 2) {
            samples[iter - 2] = @intCast(@max(t1.nanoseconds - t0.nanoseconds, 1));
        }
    }
    std.mem.doNotOptimizeAway(&sink);
    const st = computeStats(&samples);
    return .{
        .name = "live_exec",
        .ops_per_iter = N_EXECS,
        .unit_label = "exec/s",
        .median_ns = st.median,
        .p95_ns = st.p95,
        .mad_ns = st.mad,
        .throughput_per_sec = throughput(N_EXECS, st.median),
    };
}

const JsonBenchMetric = struct {
    name: []const u8,
    median_ns: u64,
    mad_ns: u64,
    throughput_per_sec: u64,
};

const JsonBenchDoc = struct {
    metrics: []const JsonBenchMetric = &.{},
};

pub fn runBenchCommand(io: std.Io, allocator: std.mem.Allocator, args: []const []const u8) !u8 {
    var suite: SuiteKind = .all;
    var target_path: ?[]const u8 = null;
    var entry_name: []const u8 = "fuzz_entry";
    var out_json: ?[]const u8 = null;
    var compare_path: ?[]const u8 = null;
    var max_regress_pct: u64 = 15;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--suite") and i + 1 < args.len) {
            i += 1;
            suite = SuiteKind.fromString(args[i]) orelse .all;
        } else if (std.mem.eql(u8, a, "--target") and i + 1 < args.len) {
            i += 1;
            target_path = args[i];
        } else if (std.mem.eql(u8, a, "--entry") and i + 1 < args.len) {
            i += 1;
            entry_name = args[i];
        } else if (std.mem.eql(u8, a, "--json") and i + 1 < args.len) {
            i += 1;
            out_json = args[i];
        } else if (std.mem.eql(u8, a, "--compare") and i + 1 < args.len) {
            i += 1;
            compare_path = args[i];
        } else if (std.mem.eql(u8, a, "--max-regress") and i + 1 < args.len) {
            i += 1;
            const raw_p = std.mem.trimEnd(u8, args[i], "%");
            max_regress_pct = std.fmt.parseInt(u64, raw_p, 10) catch 15;
        }
    }

    var metrics = std.ArrayList(BenchMetric).empty;
    defer metrics.deinit(allocator);

    if (suite == .all or suite == .decode) try metrics.append(allocator, try benchDecode(io, allocator));
    if (suite == .all or suite == .cfg) try metrics.append(allocator, try benchCfg(io, allocator));
    if (suite == .all or suite == .mutate) try metrics.append(allocator, try benchMutate(io, allocator));
    if (suite == .all or suite == .snapshot) try metrics.append(allocator, try benchSnapshot(io, allocator));
    if (suite == .exec or (suite == .all and target_path != null)) {
        if (target_path) |tp| {
            try metrics.append(allocator, try benchExec(io, allocator, tp, entry_name));
        }
    }

    const caps = arm_laptops.probeHostCapabilities();
    const is_debug = (builtin.mode == .debug);
    std.debug.print(
        \\=== Snap-Oracle ARM64 Hardware Benchmark Suite ===
        \\Host Arch: {s} | OS: {s} | Page Size: {d}B | Build Mode: {s}{s}
        \\Metric            | Median ms | p95 ms   | MAD ms  | Throughput
        \\------------------+-----------+----------+---------+-------------------
        \\
    , .{
        @tagName(builtin.cpu.arch),
        @tagName(builtin.os.tag),
        caps.page_size,
        @tagName(builtin.mode),
        if (is_debug) " (Debug: non-comparative)" else "",
    });

    for (metrics.items) |m| {
        const med_ms = @as(f64, @floatFromInt(m.median_ns)) / 1_000_000.0;
        const p95_ms = @as(f64, @floatFromInt(m.p95_ns)) / 1_000_000.0;
        const mad_ms = @as(f64, @floatFromInt(m.mad_ns)) / 1_000_000.0;
        std.debug.print("{s:<17} | {d:>8.3}  | {d:>7.3}  | {d:>6.3}  | {d} {s}\n", .{
            m.name,
            med_ms,
            p95_ms,
            mad_ms,
            m.throughput_per_sec,
            m.unit_label,
        });
    }

    if (out_json) |jp| {
        var json = std.ArrayList(u8).empty;
        defer json.deinit(allocator);
        const hdr = try std.fmt.allocPrint(allocator,
            "{{\n  \"arch\": \"{s}\",\n  \"os\": \"{s}\",\n  \"page_size\": {d},\n  \"build_mode\": \"{s}\",\n  \"invalid_for_comparison\": {any},\n  \"metrics\": [\n",
            .{ @tagName(builtin.cpu.arch), @tagName(builtin.os.tag), caps.page_size, @tagName(builtin.mode), is_debug },
        );
        defer allocator.free(hdr);
        try json.appendSlice(allocator, hdr);
        for (metrics.items, 0..) |m, idx| {
            if (idx > 0) try json.appendSlice(allocator, ",\n");
            const row = try std.fmt.allocPrint(allocator,
                "    {{ \"name\": \"{s}\", \"ops_per_iter\": {d}, \"unit\": \"{s}\", \"median_ns\": {d}, \"p95_ns\": {d}, \"mad_ns\": {d}, \"throughput_per_sec\": {d} }}",
                .{ m.name, m.ops_per_iter, m.unit_label, m.median_ns, m.p95_ns, m.mad_ns, m.throughput_per_sec },
            );
            defer allocator.free(row);
            try json.appendSlice(allocator, row);
        }
        try json.appendSlice(allocator, "\n  ]\n}\n");
        try finding.writeOutputFile(io, jp, json.items);
        std.debug.print("[bench] wrote JSON metrics -> {s}\n", .{jp});
    }

    if (compare_path) |cp| {
        const base_raw = try std.Io.Dir.cwd().readFileAlloc(io, cp, allocator, .limited(4 * 1024 * 1024));
        defer allocator.free(base_raw);
        const parsed = try std.json.parseFromSlice(JsonBenchDoc, allocator, base_raw, .{ .ignore_unknown_fields = true });
        defer parsed.deinit();

        var regressed = false;
        for (metrics.items) |cur| {
            for (parsed.value.metrics) |base| {
                if (!std.mem.eql(u8, cur.name, base.name)) continue;
                const thresh = (base.median_ns * (100 + max_regress_pct)) / 100;
                const noise_floor = @max(base.mad_ns, 1) * 3;
                if (cur.median_ns > thresh and (cur.median_ns - base.median_ns) > noise_floor) {
                    regressed = true;
                    std.debug.print("[bench] REGRESSION on {s}: new={d}ns vs base={d}ns (+>{d}%)\n", .{
                        cur.name,
                        cur.median_ns,
                        base.median_ns,
                        max_regress_pct,
                    });
                }
            }
        }
        if (regressed) return 1;
        std.debug.print("[bench] baseline comparison PASSED (within {d}% tolerance)\n", .{max_regress_pct});
    }

    return 0;
}
