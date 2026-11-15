const std = @import("std");
const arch = @import("arch.zig");
const l1 = @import("l1_engine.zig");
const mutator = @import("mutator.zig");
const veh = @import("veh.zig");

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

pub fn runFuzz(
    io: std.Io,
    allocator: std.mem.Allocator,
    target_path: []const u8,
    entry_name: []const u8,
    iters: usize,
) !void {
    var target = try LoadedTarget.load(allocator, target_path, entry_name);
    defer target.unload();

    var guard = veh.Guard.init();
    defer guard.deinit();

    var arena = try l1.SnapshotArena.init(allocator, 64 * 1024);
    defer arena.deinit();
    const max_input: usize = 256;
    @memset(arena.live_ptr[0..max_input], 0x41);
    arena.takeSnapshot();

    var rng = mutator.Rng.init(arch.readCycleCounter() ^ 0x517cc1b727220a95);
    var seen_crashes = std.AutoHashMap(u64, void).init(allocator);
    defer seen_crashes.deinit();

    var total_dirty_pages: usize = 0;
    var total_crashes: usize = 0;
    var unique_crashes: usize = 0;

    const t0 = arch.readCycleCounter();

    var i: usize = 0;
    while (i < iters) : (i += 1) {
        const mlen = mutator.mutateHavoc(&rng, arena.live_ptr[0..max_input], max_input);

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
            }
        }
        total_dirty_pages += arena.restoreDirtyPages();
    }

    const t1 = arch.readCycleCounter();
    std.debug.print(
        "[fuzz] target={s} entry={s} iters={d} crashes={d} (unique={d}) dirty_pages_reset={d} cycles={d}\n",
        .{ target_path, entry_name, iters, total_crashes, unique_crashes, total_dirty_pages, t1 -% t0 },
    );
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

    var rng = mutator.Rng.init(arch.readCycleCounter() ^ 0x9e3779b97f4a7c15);
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
    } else {
        std.debug.print(
            "[replay] OK: ret=0x{x} len={d}\n",
            .{ res.ret_val, data.len },
        );
    }
}
