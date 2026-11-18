const std = @import("std");
const binary = @import("binary.zig");
const cfg = @import("cfg.zig");
const coverage = @import("coverage.zig");
const l1 = @import("l1_engine.zig");
const dll_snapshot = @import("dll_snapshot.zig");
const runner = @import("runner.zig");
const veh = @import("veh.zig");
const finding = @import("finding.zig");

pub const SeedTrace = struct {
    name: []const u8,
    bytes: []const u8,
    crashed: bool,
    hit_blocks: []const usize,
};

pub const CminStats = struct {
    seeds_in: usize = 0,
    seeds_out: usize = 0,
    crashes_skipped: usize = 0,
    bytes_in: usize = 0,
    bytes_out: usize = 0,
    blocks_covered: usize = 0,
    total_blocks: usize = 0,
};

/// Pure greedy weighted set cover over observed basic-block indices.
/// Picks the seed maximizing `(newly_covered_blocks * 1024) / (seed_len + 16)` each round.
pub fn selectMinimalSeeds(
    allocator: std.mem.Allocator,
    num_blocks: usize,
    traces: []const SeedTrace,
) ![]usize {
    var selected = std.ArrayList(usize).empty;
    errdefer selected.deinit(allocator);

    if (num_blocks == 0 or traces.len == 0) return selected.toOwnedSlice(allocator);

    const covered = try allocator.alloc(bool, num_blocks);
    defer allocator.free(covered);
    @memset(covered, false);

    const used = try allocator.alloc(bool, traces.len);
    defer allocator.free(used);
    @memset(used, false);

    while (true) {
        var best_idx: ?usize = null;
        var best_gain: usize = 0;
        var best_score: u64 = 0;

        for (traces, 0..) |tr, idx| {
            if (used[idx] or tr.crashed) continue;
            var gain: usize = 0;
            for (tr.hit_blocks) |b| {
                if (b < num_blocks and !covered[b]) gain += 1;
            }
            if (gain == 0) continue;

            const denom: u64 = @as(u64, tr.bytes.len) + 16;
            const score: u64 = (@as(u64, gain) * 1_000_000) / denom;
            if (best_idx == null or score > best_score or (score == best_score and gain > best_gain)) {
                best_idx = idx;
                best_gain = gain;
                best_score = score;
            }
        }

        const win_idx = best_idx orelse break;
        used[win_idx] = true;
        try selected.append(allocator, win_idx);
        for (traces[win_idx].hit_blocks) |b| {
            if (b < num_blocks) covered[b] = true;
        }
    }

    return selected.toOwnedSlice(allocator);
}

fn measureSeedTrace(
    allocator: std.mem.Allocator,
    entry: veh.TargetFn,
    base_addr: usize,
    machine: @import("pe.zig").Machine,
    blocks: []const cfg.BasicBlock,
    arena: *l1.SnapshotArena,
    mod_snap: *dll_snapshot.ModuleDataSnapshot,
    data: []const u8,
) !struct { crashed: bool, hit_blocks: []usize } {
    const armed = try allocator.alloc(bool, blocks.len);
    defer allocator.free(armed);

    var bitmap = l1.CoverageBitmap{};
    var bp_table = try coverage.BreakpointTable.init(allocator, base_addr, machine, blocks, &bitmap);
    defer bp_table.deinit();

    for (blocks, 0..) |bb, bi| {
        const addr = base_addr + @as(usize, bb.rva);
        armed[bi] = bp_table.orig_bytes.contains(addr);
    }

    veh.setBreakpointTable(&bp_table);
    @memcpy(arena.live_ptr[0..data.len], data);
    const res = veh.runProtected(entry, arena.live_ptr, data.len);
    _ = arena.restoreDirtyPages() catch 0;
    _ = mod_snap.restore();

    var hits = std.ArrayList(usize).empty;
    errdefer hits.deinit(allocator);
    for (blocks, 0..) |bb, bi| {
        if (!armed[bi]) continue;
        const addr = base_addr + @as(usize, bb.rva);
        if (!bp_table.orig_bytes.contains(addr)) {
            try hits.append(allocator, bi);
        }
    }

    return .{
        .crashed = res.crashed,
        .hit_blocks = try hits.toOwnedSlice(allocator),
    };
}

fn containsAllBlocks(haystack: []const usize, required: []const usize) bool {
    for (required) |r| {
        if (std.mem.indexOfScalar(usize, haystack, r) == null) return false;
    }
    return true;
}

fn ddminSeed(
    allocator: std.mem.Allocator,
    entry: veh.TargetFn,
    base_addr: usize,
    machine: @import("pe.zig").Machine,
    blocks: []const cfg.BasicBlock,
    arena: *l1.SnapshotArena,
    mod_snap: *dll_snapshot.ModuleDataSnapshot,
    orig_data: []const u8,
    req_hits: []const usize,
) ![]u8 {
    var cur = try allocator.dupe(u8, orig_data);
    errdefer allocator.free(cur);

    var chunk_sz: usize = @max(cur.len / 2, 1);
    while (chunk_sz >= 1 and cur.len > 1) {
        var offset: usize = 0;
        var reduced = false;
        while (offset < cur.len and cur.len > 1) {
            const end = @min(offset + chunk_sz, cur.len);
            const new_len = cur.len - (end - offset);
            if (new_len == 0) {
                offset = end;
                continue;
            }
            const cand = try allocator.alloc(u8, new_len);
            @memcpy(cand[0..offset], cur[0..offset]);
            @memcpy(cand[offset..new_len], cur[end..cur.len]);

            const probe = try measureSeedTrace(allocator, entry, base_addr, machine, blocks, arena, mod_snap, cand);
            defer allocator.free(probe.hit_blocks);

            if (!probe.crashed and containsAllBlocks(probe.hit_blocks, req_hits)) {
                allocator.free(cur);
                cur = cand;
                reduced = true;
            } else {
                allocator.free(cand);
                offset += chunk_sz;
            }
        }
        if (!reduced) chunk_sz /= 2;
    }
    return cur;
}

pub fn runCminCommand(io: std.Io, allocator: std.mem.Allocator, args: []const []const u8) !void {
    var target_path: ?[]const u8 = null;
    var entry_name: []const u8 = "fuzz_entry";
    var in_dir: ?[]const u8 = null;
    var out_dir: ?[]const u8 = null;
    var do_tmin = false;
    var bti_safe = false;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--target") and i + 1 < args.len) {
            i += 1;
            target_path = args[i];
        } else if (std.mem.eql(u8, a, "--entry") and i + 1 < args.len) {
            i += 1;
            entry_name = args[i];
        } else if ((std.mem.eql(u8, a, "--corpus") or std.mem.eql(u8, a, "--in")) and i + 1 < args.len) {
            i += 1;
            in_dir = args[i];
        } else if (std.mem.eql(u8, a, "--out") and i + 1 < args.len) {
            i += 1;
            out_dir = args[i];
        } else if (std.mem.eql(u8, a, "--tmin")) {
            do_tmin = true;
        } else if (std.mem.eql(u8, a, "--bti-safe")) {
            bti_safe = true;
        }
    }

    const dll_path = target_path orelse {
        std.debug.print("Usage: snap-oracle cmin --target <dll/so> [--entry fn] --corpus <in_dir> --out <out_dir> [--tmin]\n", .{});
        return;
    };
    const corp_in = in_dir orelse {
        std.debug.print("[cmin] missing --corpus <in_dir>\n", .{});
        return;
    };
    const corp_out = out_dir orelse {
        std.debug.print("[cmin] missing --out <out_dir>\n", .{});
        return;
    };

    const image_bytes = try std.Io.Dir.cwd().readFileAlloc(io, dll_path, allocator, .limited(256 * 1024 * 1024));
    defer allocator.free(image_bytes);
    var img = try binary.parseBinary(allocator, image_bytes);
    defer img.deinit();

    const blocks = try cfg.decodeAllTextBasicBlocksEx(allocator, image_bytes, bti_safe);
    defer allocator.free(blocks);

    var target = try runner.LoadedTarget.load(allocator, dll_path, entry_name);
    defer target.unload();

    var guard = veh.Guard.init();
    defer guard.deinit();
    veh.setTargetModuleBounds(target.base_addr, img.size_of_image);
    defer veh.setTargetModuleBounds(0, 0);

    var arena = try l1.SnapshotArena.init(allocator, 64 * 1024);
    defer arena.deinit();
    arena.takeSnapshot();

    var mod_snap = try dll_snapshot.ModuleDataSnapshot.init(allocator, target.base_addr, &img);
    defer mod_snap.deinit();

    var dir = try std.Io.Dir.cwd().openDir(io, corp_in, .{ .iterate = true });
    defer dir.close(io);

    var names = std.ArrayList([]u8).empty;
    var payloads = std.ArrayList([]u8).empty;
    var traces = std.ArrayList(SeedTrace).empty;
    defer {
        for (names.items) |n| allocator.free(n);
        names.deinit(allocator);
        for (payloads.items) |p| allocator.free(p);
        payloads.deinit(allocator);
        for (traces.items) |t| allocator.free(t.hit_blocks);
        traces.deinit(allocator);
    }

    var stats = CminStats{ .total_blocks = blocks.len };
    var it = dir.iterate();
    while (it.next(io) catch null) |ent| {
        if (ent.kind != .file) continue;
        const data = dir.readFileAlloc(io, ent.name, allocator, .limited(64 * 1024)) catch continue;
        stats.seeds_in += 1;
        stats.bytes_in += data.len;
        const measured = try measureSeedTrace(allocator, target.entry, target.base_addr, img.machine, blocks, &arena, &mod_snap, data);
        if (measured.crashed) stats.crashes_skipped += 1;

        try names.append(allocator, try allocator.dupe(u8, ent.name));
        try payloads.append(allocator, data);
        try traces.append(allocator, .{
            .name = names.items[names.items.len - 1],
            .bytes = data,
            .crashed = measured.crashed,
            .hit_blocks = measured.hit_blocks,
        });
    }

    const picked = try selectMinimalSeeds(allocator, blocks.len, traces.items);
    defer allocator.free(picked);

    try std.Io.Dir.cwd().createDirPath(io, corp_out);

    var covered_union = std.AutoHashMap(usize, void).init(allocator);
    defer covered_union.deinit();

    for (picked) |sidx| {
        const tr = traces.items[sidx];
        for (tr.hit_blocks) |b| try covered_union.put(b, {});

        var final_bytes: []u8 = undefined;
        var owned_min = false;
        if (do_tmin and tr.bytes.len > 1) {
            final_bytes = try ddminSeed(allocator, target.entry, target.base_addr, img.machine, blocks, &arena, &mod_snap, tr.bytes, tr.hit_blocks);
            owned_min = true;
        } else {
            final_bytes = @constCast(tr.bytes);
        }
        defer if (owned_min) allocator.free(final_bytes);

        const h = std.hash.Wyhash.hash(0, final_bytes);
        const out_file = try std.fmt.allocPrint(allocator, "{s}/seed_{x:0>16}.bin", .{ corp_out, h });
        defer allocator.free(out_file);
        try finding.writeOutputFile(io, out_file, final_bytes);
        stats.seeds_out += 1;
        stats.bytes_out += final_bytes.len;
    }
    stats.blocks_covered = covered_union.count();

    std.debug.print(
        "[cmin] distilled corpus: seeds {d} -> {d} ({d}B -> {d}B) | covered {d}/{d} basic blocks | crashes skipped={d}\n",
        .{ stats.seeds_in, stats.seeds_out, stats.bytes_in, stats.bytes_out, stats.blocks_covered, stats.total_blocks, stats.crashes_skipped },
    );
}
