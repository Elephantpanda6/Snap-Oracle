const std = @import("std");
const arch = @import("arch.zig");
const l1 = @import("l1_engine.zig");
const mutator = @import("mutator.zig");
const veh = @import("veh.zig");
const pe = @import("pe.zig");
const cfg = @import("cfg.zig");
const coverage = @import("coverage.zig");
const corpus = @import("corpus.zig");
const minimizer = @import("minimizer.zig");

const HMODULE = *anyopaque;
extern "kernel32" fn LoadLibraryA(lpLibFileName: [*:0]const u8) callconv(.winapi) ?HMODULE;
extern "kernel32" fn GetProcAddress(hModule: HMODULE, lpProcName: [*:0]const u8) callconv(.winapi) ?*anyopaque;
extern "kernel32" fn FreeLibrary(hLibModule: HMODULE) callconv(.winapi) i32;

pub const LoadedTarget = struct {
    module: HMODULE,
    entry: veh.TargetFn,

    pub fn load(allocator: std.mem.Allocator, dll_path: []const u8, entry_name: []const u8) !LoadedTarget {
        const path_z = try allocator.allocSentinel(u8, dll_path.len, 0);
        defer allocator.free(path_z);
        @memcpy(path_z, dll_path);
        const mod = LoadLibraryA(path_z.ptr) orelse return error.LoadLibraryFailed;
        errdefer _ = FreeLibrary(mod);

        const entry_z = try allocator.allocSentinel(u8, entry_name.len, 0);
        defer allocator.free(entry_z);
        @memcpy(entry_z, entry_name);
        const proc = GetProcAddress(mod, entry_z.ptr) orelse return error.EntryNotFound;

        return .{
            .module = mod,
            .entry = @ptrCast(@alignCast(proc)),
        };
    }

    pub fn unload(self: *LoadedTarget) void {
        _ = FreeLibrary(self.module);
    }
};

extern "kernel32" fn GetTickCount64() callconv(.winapi) u64;
extern "kernel32" fn QueryPerformanceCounter(lpPerformanceCount: *i64) callconv(.winapi) i32;

fn prngSeed(salt: u64) u64 {
    var qpc: i64 = 0;
    if (QueryPerformanceCounter(&qpc) != 0) {
        return @as(u64, @bitCast(qpc)) ^ GetTickCount64() ^ salt;
    }
    return GetTickCount64() ^ salt;
}

pub fn runFuzz(
    io: std.Io,
    allocator: std.mem.Allocator,
    target_path: []const u8,
    entry_name: []const u8,
    iters: usize,
    corpus_dir: ?[]const u8,
) !void {
    // Static analysis of the on-disk image: machine type + basic-block RVAs.
    const image_bytes = try std.Io.Dir.cwd().readFileAlloc(io, target_path, allocator, .limited(256 * 1024 * 1024));
    defer allocator.free(image_bytes);
    var img = try pe.parsePe(allocator, image_bytes);
    defer img.deinit();
    const blocks = try cfg.decodeAllTextBasicBlocks(allocator, image_bytes);
    defer allocator.free(blocks);

    var target = try LoadedTarget.load(allocator, target_path, entry_name);
    defer target.unload();

    var guard = veh.Guard.init();
    defer guard.deinit();

    var bitmap = l1.CoverageBitmap{};
    var bp_table = try coverage.BreakpointTable.init(allocator, @intFromPtr(target.module), img.machine, blocks, &bitmap);
    // Deferred after `target.unload()` so they run BEFORE the module is unloaded.
    defer veh.setBreakpointTable(null);
    defer bp_table.deinit();
    veh.setBreakpointTable(&bp_table);

    var arena = try l1.SnapshotArena.init(allocator, 64 * 1024);
    defer arena.deinit();
    const max_input: usize = 1024;
    @memset(arena.live_ptr[0..max_input], 0x41);
    arena.takeSnapshot();

    var rng = mutator.Rng.init(prngSeed(0x517cc1b727220a95));

    var corp = corpus.Corpus.init(allocator);
    defer corp.deinit();
    var loaded: usize = 0;
    if (corpus_dir) |dir| loaded = corp.loadDir(io, dir) catch 0;
    try corp.ensureNonEmpty();

    var seen_crashes = std.AutoHashMap(u64, void).init(allocator);
    defer seen_crashes.deinit();

    var total_dirty_pages: usize = 0;
    var total_crashes: usize = 0;
    var unique_crashes: usize = 0;

    std.debug.print(
        "[fuzz] image={s} machine={s} blocks={d} armed={d} seeds={d}\n",
        .{ target_path, @tagName(img.machine), blocks.len, bp_table.totalCount(), corp.count() },
    );

    const t0 = GetTickCount64();

    var i: usize = 0;
    while (i < iters) : (i += 1) {
        // Fresh input: pick a corpus entry, optionally pad it (the havoc mutator can only grow
        // inside the slice it is handed), then mutate in place.
        const seed = corp.pickNext(&rng);
        const n = @min(seed.len, max_input);
        const pad = @min(rng.below(9), max_input - n);
        @memcpy(arena.live_ptr[0..n], seed[0..n]);
        for (0..pad) |k| arena.live_ptr[n + k] = if (n > 0) seed[k % n] else 0x41;
        const total = n + pad;
        const mlen = mutator.mutateHavoc(&rng, arena.live_ptr[0..total], total);

        const prev_hits = bp_table.hitCount();
        const res = veh.runProtected(target.entry, arena.live_ptr, mlen);

        if (res.crashed) {
            total_crashes += 1;
            const frames = [_]u32{@truncate(res.exception_addr)};
            const h = mutator.hashCrash(res.exception_code, &frames);
            const gop = try seen_crashes.getOrPut(h);
            if (!gop.found_existing) {
                unique_crashes += 1;
                var name_buf: [64]u8 = undefined;
                const fname = try std.fmt.bufPrint(&name_buf, "crash_{x:0>16}.bin", .{h});
                std.Io.Dir.cwd().writeFile(io, .{ .sub_path = fname, .data = arena.live_ptr[0..mlen] }) catch {};
                std.debug.print("[fuzz] NEW CRASH #{d} code=0x{x:0>8} addr=0x{x} len={d} -> {s}\n", .{ unique_crashes, res.exception_code, res.exception_addr, mlen, fname });
            }
        }

        // Coverage feedback: any block hit for the first time promotes the input to the corpus.
        const new_hits = bp_table.hitCount() - prev_hits;
        if (new_hits > 0) {
            if (try corp.addSeed(arena.live_ptr[0..mlen], new_hits)) {
                if (corpus_dir) |dir| saveSeed(io, allocator, dir, arena.live_ptr[0..mlen]);
            }
        }
        total_dirty_pages += arena.restoreDirtyPages();
    }

    const t1 = GetTickCount64();
    const elapsed_ms: u64 = @max(t1 -% t0, 1);
    const exec_per_sec: u64 = @intCast((@as(u128, iters) * 1000) / elapsed_ms);
    std.debug.print(
        "[fuzz] target={s} entry={s} iters={d} elapsed_ms={d} exec_per_sec={d} edges={d}/{d} corpus={d} (loaded={d}) crashes={d} (unique={d}) dirty_pages_reset={d}\n",
        .{
            target_path,                entry_name,       iters,         elapsed_ms,
            exec_per_sec,               bp_table.hitCount(), bp_table.totalCount(), corp.count(),
            loaded,                     total_crashes,    unique_crashes, total_dirty_pages,
        },
    );
}

fn saveSeed(io: std.Io, allocator: std.mem.Allocator, dir: []const u8, data: []const u8) void {
    var name_buf: [64]u8 = undefined;
    const name = std.fmt.bufPrint(&name_buf, "seed_{x:0>16}.bin", .{std.hash.Wyhash.hash(0, data)}) catch return;
    const path = std.fs.path.join(allocator, &.{ dir, name }) catch return;
    defer allocator.free(path);
    std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = data }) catch {};
}
pub fn runDiff(
    allocator: std.mem.Allocator,
    x64_path: []const u8,
    arm64_path: []const u8,
    entry_name: []const u8,
    iters: usize,
) !void {
    var t_a = try LoadedTarget.load(allocator, x64_path, entry_name);
    defer t_a.unload();

    var t_b_opt: ?LoadedTarget = LoadedTarget.load(allocator, arm64_path, entry_name) catch null;
    defer if (t_b_opt) |*tb| tb.unload();

    if (t_b_opt == null) {
        std.debug.print(
            "[diff] loaded {s} natively; {s} cannot be loaded on this host arch (cross-arch emulation/ARM64 host required for live diff)\n",
            .{ x64_path, arm64_path },
        );
        return;
    }
    const t_b = t_b_opt.?;

    var guard = veh.Guard.init();
    defer guard.deinit();

    var rng = mutator.Rng.init(prngSeed(0x9e3779b97f4a7c15));
    var buf: [256]u8 = @splat(0x41);
    var divergences: usize = 0;

    var i: usize = 0;
    while (i < iters) : (i += 1) {
        const mlen = mutator.mutateHavoc(&rng, &buf, buf.len);
        const r_a = veh.runProtected(t_a.entry, &buf, mlen);
        const r_b = veh.runProtected(t_b.entry, &buf, mlen);
        if (r_a.crashed != r_b.crashed or r_a.ret_val != r_b.ret_val or r_a.exception_code != r_b.exception_code) {
            divergences += 1;
        }
    }

    std.debug.print(
        "[diff] a={s} b={s} entry={s} iters={d} divergences={d}\n",
        .{ x64_path, arm64_path, entry_name, iters, divergences },
    );
}

pub fn runReplay(
    io: std.Io,
    allocator: std.mem.Allocator,
    target_path: []const u8,
    entry_name: []const u8,
    input_path: []const u8,
    minimize: bool,
) !void {
    const data = try std.Io.Dir.cwd().readFileAlloc(io, input_path, allocator, .limited(16 * 1024 * 1024));
    defer allocator.free(data);

    var target = try LoadedTarget.load(allocator, target_path, entry_name);
    defer target.unload();

    var guard = veh.Guard.init();
    defer guard.deinit();

    const res = veh.runProtected(target.entry, data.ptr, data.len);
    if (res.crashed) {
        std.debug.print(
            "[replay] CRASH caught: code=0x{x:0>8} addr=0x{x} len={d}\n",
            .{ res.exception_code, res.exception_addr, data.len },
        );
        if (minimize) {
            const small = try minimizer.minimizeCrash(allocator, target.entry, data, res.exception_code);
            defer allocator.free(small);
            const out_path = try std.fmt.allocPrint(allocator, "{s}.min", .{input_path});
            defer allocator.free(out_path);
            try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = out_path, .data = small });
            std.debug.print("[replay] minimized {d} -> {d} bytes ({s})\n", .{ data.len, small.len, out_path });
        }
    } else {
        std.debug.print(
            "[replay] OK: ret=0x{x} len={d}\n",
            .{ res.ret_val, data.len },
        );
    }
}
