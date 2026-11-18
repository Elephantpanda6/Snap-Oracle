const std = @import("std");
const arm_laptops = @import("arm_laptops.zig");

/// Shared-nothing multi-core fuzzing coordinator: spawns `jobs` independent worker processes
/// sharing a corpus directory, optionally pins P-core affinity on heterogeneous ARM64 laptops,
/// and summarizes combined throughput and unique discoveries.
pub fn runPoolFuzz(
    io: std.Io,
    allocator: std.mem.Allocator,
    exe_path: []const u8,
    target_path: []const u8,
    entry_name: []const u8,
    total_iters: usize,
    jobs: usize,
    corpus_dir: ?[]const u8,
    dict_path: ?[]const u8,
    max_input: usize,
    laptop_profile: ?[]const u8,
    bti_safe: bool,
) !void {
    const worker_count = @max(jobs, 1);
    const effective_corpus = corpus_dir orelse ".snap_pool_corpus";
    std.Io.Dir.cwd().createDirPath(io, effective_corpus) catch {};

    if (laptop_profile) |lp| {
        if (arm_laptops.findProfile(lp)) |prof| {
            _ = arm_laptops.applyProfileAffinity(prof);
            std.debug.print("[pool] laptop_profile={s} workers={d} p_core_mask=0x{x}\n", .{
                prof.id, worker_count, prof.p_core_affinity_mask,
            });
        }
    }

    const per_worker = (total_iters + worker_count - 1) / worker_count;
    const iters_str = try std.fmt.allocPrint(allocator, "{d}", .{per_worker});
    defer allocator.free(iters_str);
    const max_in_str = try std.fmt.allocPrint(allocator, "{d}", .{max_input});
    defer allocator.free(max_in_str);

    const children = try allocator.alloc(std.process.Child, worker_count);
    defer allocator.free(children);
    const seed_strs = try allocator.alloc([]u8, worker_count);
    @memset(seed_strs, &.{});
    defer {
        for (seed_strs) |s| {
            if (s.len > 0) allocator.free(s);
        }
        allocator.free(seed_strs);
    }

    const t0 = std.Io.Timestamp.now(io, .awake);

    var spawned: usize = 0;
    errdefer {
        for (children[0..spawned]) |*ch| ch.kill(io);
    }

    for (0..worker_count) |idx| {
        seed_strs[idx] = try std.fmt.allocPrint(allocator, "{d}", .{@as(u64, 0x9E37_79B9_7F4A_7C15) +% (@as(u64, idx) *% 0xBF58_476D_1CE4_E5B9)});
        var argv_buf: [24][]const u8 = undefined;
        var argc: usize = 0;
        argv_buf[argc] = exe_path;
        argc += 1;
        argv_buf[argc] = "fuzz";
        argc += 1;
        argv_buf[argc] = "--target";
        argc += 1;
        argv_buf[argc] = target_path;
        argc += 1;
        argv_buf[argc] = "--entry";
        argc += 1;
        argv_buf[argc] = entry_name;
        argc += 1;
        argv_buf[argc] = "--iters";
        argc += 1;
        argv_buf[argc] = iters_str;
        argc += 1;
        argv_buf[argc] = "--corpus";
        argc += 1;
        argv_buf[argc] = effective_corpus;
        argc += 1;
        argv_buf[argc] = "--max-input";
        argc += 1;
        argv_buf[argc] = max_in_str;
        argc += 1;
        argv_buf[argc] = "--seed";
        argc += 1;
        argv_buf[argc] = seed_strs[idx];
        argc += 1;
        if (dict_path) |dp| {
            argv_buf[argc] = "--dict";
            argc += 1;
            argv_buf[argc] = dp;
            argc += 1;
        }
        if (laptop_profile) |lp| {
            argv_buf[argc] = "--laptop";
            argc += 1;
            argv_buf[argc] = lp;
            argc += 1;
        }
        if (bti_safe) {
            argv_buf[argc] = "--bti-safe";
            argc += 1;
        }

        children[idx] = try std.process.spawn(io, .{
            .argv = argv_buf[0..argc],
            .stdin = .ignore,
            .stdout = .inherit,
            .stderr = .inherit,
        });
        spawned += 1;
    }

    var failed: usize = 0;
    for (children[0..spawned]) |*ch| {
        const term = try ch.wait(io);
        if (!term.success()) failed += 1;
    }

    const t1 = std.Io.Timestamp.now(io, .awake);
    const elapsed_ms: u64 = @intCast(@max(@divFloor(t1.nanoseconds - t0.nanoseconds, 1_000_000), 1));
    const total_ran = per_worker * worker_count;
    const agg_exec_sec: u64 = @intCast((@as(u128, total_ran) * 1000) / elapsed_ms);

    var seed_files: usize = 0;
    if (std.Io.Dir.cwd().openDir(io, effective_corpus, .{ .iterate = true })) |dir_const| {
        var dir = dir_const;
        defer dir.close(io);
        var it = dir.iterate();
        while (it.next(io) catch null) |e| {
            if (e.kind == .file) seed_files += 1;
        }
    } else |_| {}

    std.debug.print(
        "[pool] jobs={d} failed={d} total_iters={d} elapsed_ms={d} combined_exec_per_sec={d} corpus_files={d}\n",
        .{ worker_count, failed, total_ran, elapsed_ms, agg_exec_sec, seed_files },
    );
}
