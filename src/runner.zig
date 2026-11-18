const std = @import("std");
const builtin = @import("builtin");
const arch = @import("arch.zig");
const l1 = @import("l1_engine.zig");
const mutator = @import("mutator.zig");
const veh = @import("veh.zig");
const binary = @import("binary.zig");
const cfg = @import("cfg.zig");
const coverage = @import("coverage.zig");
const corpus = @import("corpus.zig");
const minimizer = @import("minimizer.zig");
const dict_extract = @import("dict_extract.zig");
const dll_snapshot = @import("dll_snapshot.zig");
const arm_laptops = @import("arm_laptops.zig");

const HMODULE = *anyopaque;

const WinDyn = if (builtin.os.tag == .windows) struct {
    extern "kernel32" fn LoadLibraryA(lpLibFileName: [*:0]const u8) callconv(.winapi) ?HMODULE;
    extern "kernel32" fn GetProcAddress(hModule: HMODULE, lpProcName: [*:0]const u8) callconv(.winapi) ?*anyopaque;
    extern "kernel32" fn FreeLibrary(hLibModule: HMODULE) callconv(.winapi) i32;
    extern "kernel32" fn GetTickCount64() callconv(.winapi) u64;
    extern "kernel32" fn QueryPerformanceCounter(lpPerformanceCount: *i64) callconv(.winapi) i32;
} else struct {};

pub const LoadedTarget = struct {
    module: HMODULE,
    entry: veh.TargetFn,

    pub fn load(allocator: std.mem.Allocator, dll_path: []const u8, entry_name: []const u8) !LoadedTarget {
        const path_z = try allocator.allocSentinel(u8, dll_path.len, 0);
        defer allocator.free(path_z);
        @memcpy(path_z, dll_path);

        const entry_z = try allocator.allocSentinel(u8, entry_name.len, 0);
        defer allocator.free(entry_z);
        @memcpy(entry_z, entry_name);

        if (builtin.os.tag == .windows) {
            const mod = WinDyn.LoadLibraryA(path_z.ptr) orelse return error.LoadLibraryFailed;
            errdefer _ = WinDyn.FreeLibrary(mod);
            const proc = WinDyn.GetProcAddress(mod, entry_z.ptr) orelse return error.EntryNotFound;
            return .{
                .module = mod,
                .entry = @ptrCast(@alignCast(proc)),
            };
        } else {
            const mod = std.c.dlopen(path_z.ptr, .{ .NOW = true }) orelse return error.LoadLibraryFailed;
            errdefer _ = std.c.dlclose(mod);
            const proc = std.c.dlsym(mod, entry_z.ptr) orelse return error.EntryNotFound;
            return .{
                .module = mod,
                .entry = @ptrCast(@alignCast(proc)),
            };
        }
    }

    pub fn unload(self: *LoadedTarget) void {
        if (builtin.os.tag == .windows) {
            _ = WinDyn.FreeLibrary(self.module);
        } else {
            _ = std.c.dlclose(self.module);
        }
    }
};

fn prngSeed(io: std.Io, salt: u64) u64 {
    if (builtin.os.tag == .windows) {
        var qpc: i64 = 0;
        if (WinDyn.QueryPerformanceCounter(&qpc) != 0) {
            return @as(u64, @bitCast(qpc)) ^ WinDyn.GetTickCount64() ^ salt;
        }
        return WinDyn.GetTickCount64() ^ salt;
    } else {
        const ts = std.Io.Timestamp.now(io, .awake);
        const raw: u64 = @truncate(@as(u96, @bitCast(ts.nanoseconds)));
        return raw ^ arch.readCycleCounter() ^ salt;
    }
}

pub const FuzzOptions = struct {
    target_path: []const u8,
    entry_name: []const u8 = "fuzz_entry",
    iters: usize = 1000,
    corpus_dir: ?[]const u8 = null,
    dict_path: ?[]const u8 = null,
    max_input: usize = 4096,
    seed: ?u64 = null,
    laptop_profile: ?[]const u8 = null,
    bti_safe: bool = false,
};

fn loadCustomDict(io: std.Io, allocator: std.mem.Allocator, dict_path: []const u8, dict: *mutator.Dictionary) void {
    const raw = std.Io.Dir.cwd().readFileAlloc(io, dict_path, allocator, .limited(256 * 1024)) catch return;
    defer allocator.free(raw);
    var it = std.mem.tokenizeAny(u8, raw, "\r\n");
    while (it.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\"");
        if (trimmed.len >= 2) _ = dict.add(trimmed);
    }
}

pub fn runFuzz(
    io: std.Io,
    allocator: std.mem.Allocator,
    target_path: []const u8,
    entry_name: []const u8,
    iters: usize,
    corpus_dir: ?[]const u8,
) !void {
    return runFuzzEx(io, allocator, .{
        .target_path = target_path,
        .entry_name = entry_name,
        .iters = iters,
        .corpus_dir = corpus_dir,
    });
}

pub fn runFuzzEx(io: std.Io, allocator: std.mem.Allocator, opts: FuzzOptions) !void {
    const image_bytes = try std.Io.Dir.cwd().readFileAlloc(io, opts.target_path, allocator, .limited(256 * 1024 * 1024));
    defer allocator.free(image_bytes);
    var img = try binary.parseBinary(allocator, image_bytes);
    defer img.deinit();

    const blocks = try cfg.decodeAllTextBasicBlocksEx(allocator, image_bytes, opts.bti_safe);
    defer allocator.free(blocks);

    var dict = mutator.Dictionary.init();
    const extracted_tokens = dict_extract.extractFromBinary(allocator, image_bytes, &dict) catch 0;
    if (opts.dict_path) |dp| loadCustomDict(io, allocator, dp, &dict);

    var arena_bytes: usize = 64 * 1024;
    if (opts.laptop_profile) |lp| {
        if (arm_laptops.findProfile(lp)) |prof| {
            _ = arm_laptops.applyProfileAffinity(prof);
            arena_bytes = @as(usize, prof.recommended_arena_kb) * 1024;
        }
    }
    const max_input = @max(@min(opts.max_input, arena_bytes), 64);

    var target = try LoadedTarget.load(allocator, opts.target_path, opts.entry_name);
    defer target.unload();

    var guard = veh.Guard.init();
    defer guard.deinit();

    veh.setTargetModuleBounds(@intFromPtr(target.module), img.size_of_image);
    defer veh.setTargetModuleBounds(0, 0);

    var bitmap = l1.CoverageBitmap{};
    var bp_table = try coverage.BreakpointTable.init(allocator, @intFromPtr(target.module), img.machine, blocks, &bitmap);
    defer bp_table.deinit();
    veh.setBreakpointTable(&bp_table);

    var arena = try l1.SnapshotArena.init(allocator, arena_bytes);
    defer arena.deinit();
    @memset(arena.live_ptr[0..max_input], 0x41);
    arena.takeSnapshot();

    var mod_snap = try dll_snapshot.ModuleDataSnapshot.init(allocator, @intFromPtr(target.module), &img);
    defer mod_snap.deinit();

    var rng = mutator.Rng.init(opts.seed orelse prngSeed(io, 0x517cc1b727220a95));

    var corp = corpus.Corpus.init(allocator);
    defer corp.deinit();
    corp.max_seed_bytes = max_input;
    var loaded: usize = 0;
    if (opts.corpus_dir) |dir| loaded = corp.loadDir(io, dir) catch 0;
    try corp.ensureNonEmpty();

    var seen_crashes = std.AutoHashMap(u64, void).init(allocator);
    defer seen_crashes.deinit();

    var total_dirty_pages: usize = 0;
    var total_crashes: usize = 0;
    var unique_crashes: usize = 0;

    std.debug.print(
        "[fuzz] image={s} fmt={s} machine={s} blocks={d} armed={d} dict={d} (auto={d}) data_snap={d}B seeds={d}\n",
        .{
            opts.target_path,
            @tagName(img.format),
            @tagName(img.machine),
            blocks.len,
            bp_table.totalCount(),
            dict.count,
            extracted_tokens,
            mod_snap.totalBytes(),
            corp.count(),
        },
    );

    const t0 = std.Io.Timestamp.now(io, .awake);

    var i: usize = 0;
    while (i < opts.iters) : (i += 1) {
        const seed = corp.pickWeighted(&rng);
        const n = @min(seed.len, max_input);
        const pad = @min(rng.below(9), max_input - n);
        @memcpy(arena.live_ptr[0..n], seed[0..n]);
        for (0..pad) |k| arena.live_ptr[n + k] = if (n > 0) seed[k % n] else 0x41;
        const total = n + pad;
        const mlen = mutator.mutateWithDict(&rng, arena.live_ptr[0..max_input], total, max_input, &dict);

        const prev_hits = bp_table.hitCount();
        const res = veh.runProtected(target.entry, arena.live_ptr, mlen);

        if (res.crashed) {
            total_crashes += 1;
            const frames = [_]u32{res.fault_rva};
            const h = mutator.hashCrash(res.exception_code, &frames);
            const gop = try seen_crashes.getOrPut(h);
            if (!gop.found_existing) {
                unique_crashes += 1;
                var name_buf: [64]u8 = undefined;
                const fname = try std.fmt.bufPrint(&name_buf, "crash_{x:0>16}.bin", .{h});
                std.Io.Dir.cwd().writeFile(io, .{ .sub_path = fname, .data = arena.live_ptr[0..mlen] }) catch {};
                std.debug.print(
                    "[fuzz] NEW CRASH #{d} code=0x{x:0>8} rva=0x{x} addr=0x{x} len={d} -> {s}\n",
                    .{ unique_crashes, res.exception_code, res.fault_rva, res.exception_addr, mlen, fname },
                );
            }
        }

        const new_hits = bp_table.hitCount() - prev_hits;
        if (new_hits > 0) {
            if (try corp.addSeed(arena.live_ptr[0..mlen], new_hits)) {
                if (opts.corpus_dir) |dir| saveSeed(io, allocator, dir, arena.live_ptr[0..mlen]);
            }
        }
        total_dirty_pages += arena.restoreDirtyPages() catch 0;
        total_dirty_pages += mod_snap.restore();
    }

    const t1 = std.Io.Timestamp.now(io, .awake);
    const elapsed_ms: u64 = @intCast(@max(@divFloor(t1.nanoseconds - t0.nanoseconds, 1_000_000), 1));
    const exec_per_sec: u64 = @intCast((@as(u128, opts.iters) * 1000) / elapsed_ms);
    std.debug.print(
        "[fuzz] target={s} entry={s} iters={d} elapsed_ms={d} exec_per_sec={d} edges={d}/{d} corpus={d} (loaded={d}) crashes={d} (unique={d}) dirty_pages_reset={d}\n",
        .{
            opts.target_path,
            opts.entry_name,
            opts.iters,
            elapsed_ms,
            exec_per_sec,
            bp_table.hitCount(),
            bp_table.totalCount(),
            corp.count(),
            loaded,
            total_crashes,
            unique_crashes,
            total_dirty_pages,
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

const ReplayResetCtx = struct {
    arena: *l1.SnapshotArena,
    mod_snap: *dll_snapshot.ModuleDataSnapshot,
};

fn replayResetCallback(raw_ctx: ?*anyopaque) void {
    const ctx: *ReplayResetCtx = @ptrCast(@alignCast(raw_ctx orelse return));
    _ = ctx.arena.restoreDirtyPages() catch 0;
    _ = ctx.mod_snap.restore();
}

pub fn runDiff(
    io: std.Io,
    allocator: std.mem.Allocator,
    path_a: []const u8,
    path_b: []const u8,
    entry_name: []const u8,
    iters: usize,
) !void {
    const bytes_a = try std.Io.Dir.cwd().readFileAlloc(io, path_a, allocator, .limited(256 * 1024 * 1024));
    defer allocator.free(bytes_a);
    var bin_a = try binary.parseBinary(allocator, bytes_a);
    defer bin_a.deinit();

    const bytes_b = try std.Io.Dir.cwd().readFileAlloc(io, path_b, allocator, .limited(256 * 1024 * 1024));
    defer allocator.free(bytes_b);
    var bin_b = try binary.parseBinary(allocator, bytes_b);
    defer bin_b.deinit();

    var t_a_opt: ?LoadedTarget = LoadedTarget.load(allocator, path_a, entry_name) catch null;
    defer if (t_a_opt) |*ta| ta.unload();
    var t_b_opt: ?LoadedTarget = LoadedTarget.load(allocator, path_b, entry_name) catch null;
    defer if (t_b_opt) |*tb| tb.unload();

    if (t_a_opt == null or t_b_opt == null) {
        std.debug.print(
            "[diff] a={s} ({s}) b={s} ({s}): one or both binaries target a foreign OS/arch; use `snap-oracle worker` over stdio/SSH for cross-device live ARM64 vs x64 diff.\n",
            .{ path_a, @tagName(bin_a.machine), path_b, @tagName(bin_b.machine) },
        );
        return;
    }

    const t_a = t_a_opt.?;
    const t_b = t_b_opt.?;

    var guard = veh.Guard.init();
    defer guard.deinit();

    var arena = try l1.SnapshotArena.init(allocator, 64 * 1024);
    defer arena.deinit();
    arena.takeSnapshot();

    var snap_a = try dll_snapshot.ModuleDataSnapshot.init(allocator, @intFromPtr(t_a.module), &bin_a);
    defer snap_a.deinit();
    var snap_b = try dll_snapshot.ModuleDataSnapshot.init(allocator, @intFromPtr(t_b.module), &bin_b);
    defer snap_b.deinit();

    var dict = mutator.Dictionary.init();
    _ = dict_extract.extractFromBinary(allocator, bytes_a, &dict) catch 0;
    _ = dict_extract.extractFromBinary(allocator, bytes_b, &dict) catch 0;

    var rng = mutator.Rng.init(prngSeed(io, 0x9e3779b97f4a7c15));
    var input_seed: [256]u8 = @splat(0x41);
    var divergences: usize = 0;

    var i: usize = 0;
    while (i < iters) : (i += 1) {
        @memcpy(arena.live_ptr[0..input_seed.len], &input_seed);
        const mlen = mutator.mutateWithDict(&rng, arena.live_ptr[0..256], 64, 256, &dict);

        veh.setTargetModuleBounds(@intFromPtr(t_a.module), bin_a.size_of_image);
        const r_a = veh.runProtected(t_a.entry, arena.live_ptr, mlen);
        _ = arena.restoreDirtyPages() catch 0;
        _ = snap_a.restore();

        @memcpy(arena.live_ptr[0..mlen], arena.live_ptr[0..mlen]);
        veh.setTargetModuleBounds(@intFromPtr(t_b.module), bin_b.size_of_image);
        const r_b = veh.runProtected(t_b.entry, arena.live_ptr, mlen);
        _ = arena.restoreDirtyPages() catch 0;
        _ = snap_b.restore();

        if (r_a.crashed != r_b.crashed or r_a.ret_val != r_b.ret_val or r_a.exception_code != r_b.exception_code) {
            divergences += 1;
            if (divergences <= 5) {
                std.debug.print(
                    "[diff] DIVERGENCE #{d}: iter={d} a(crash={any},ret=0x{x}) b(crash={any},ret=0x{x})\n",
                    .{ divergences, i, r_a.crashed, r_a.ret_val, r_b.crashed, r_b.ret_val },
                );
            }
        }
    }
    veh.setTargetModuleBounds(0, 0);

    std.debug.print(
        "[diff] a={s} b={s} entry={s} iters={d} divergences={d}\n",
        .{ path_a, path_b, entry_name, iters, divergences },
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

    const image_bytes = try std.Io.Dir.cwd().readFileAlloc(io, target_path, allocator, .limited(256 * 1024 * 1024));
    defer allocator.free(image_bytes);
    var img = try binary.parseBinary(allocator, image_bytes);
    defer img.deinit();

    var target = try LoadedTarget.load(allocator, target_path, entry_name);
    defer target.unload();

    var guard = veh.Guard.init();
    defer guard.deinit();

    veh.setTargetModuleBounds(@intFromPtr(target.module), img.size_of_image);
    defer veh.setTargetModuleBounds(0, 0);

    var arena = try l1.SnapshotArena.init(allocator, @max(64 * 1024, data.len));
    defer arena.deinit();
    arena.takeSnapshot();

    var mod_snap = try dll_snapshot.ModuleDataSnapshot.init(allocator, @intFromPtr(target.module), &img);
    defer mod_snap.deinit();

    @memcpy(arena.live_ptr[0..data.len], data);
    const res = veh.runProtected(target.entry, arena.live_ptr, data.len);
    _ = arena.restoreDirtyPages() catch 0;
    _ = mod_snap.restore();

    if (res.crashed) {
        std.debug.print(
            "[replay] CRASH caught: code=0x{x:0>8} rva=0x{x} addr=0x{x} len={d}\n",
            .{ res.exception_code, res.fault_rva, res.exception_addr, data.len },
        );
        if (minimize) {
            var rctx = ReplayResetCtx{ .arena = &arena, .mod_snap = &mod_snap };
            const small = try minimizer.minimizeCrashIsolated(
                allocator,
                target.entry,
                data,
                res.exception_code,
                replayResetCallback,
                &rctx,
            );
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
