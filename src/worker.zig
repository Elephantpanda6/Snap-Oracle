const std = @import("std");
const builtin = @import("builtin");
const binary = @import("binary.zig");
const cfg = @import("cfg.zig");
const l1 = @import("l1_engine.zig");
const dll_snapshot = @import("dll_snapshot.zig");
const veh = @import("veh.zig");
const coverage = @import("coverage.zig");
const diff_protocol = @import("diff_protocol.zig");
const runner = @import("runner.zig");

/// Persistent out-of-process worker serving framed `diff_protocol` execution requests over
/// `stdin`/`stdout`. Used for cross-arch (`x64` vs `ARM64` via SSH/WSL/QEMU) and isolated
/// multi-process differential testing.
pub fn runWorkerStdio(
    io: std.Io,
    allocator: std.mem.Allocator,
    target_path: []const u8,
    entry_name: []const u8,
    bti_safe: bool,
) !void {
    const image_bytes = try std.Io.Dir.cwd().readFileAlloc(io, target_path, allocator, .limited(256 * 1024 * 1024));
    defer allocator.free(image_bytes);
    var img = try binary.parseBinary(allocator, image_bytes);
    defer img.deinit();
    const blocks = try cfg.decodeAllTextBasicBlocksEx(allocator, image_bytes, bti_safe);
    defer allocator.free(blocks);

    var target = try runner.LoadedTarget.load(allocator, target_path, entry_name);
    defer target.unload();

    var guard = veh.Guard.init();
    defer guard.deinit();

    veh.setTargetModuleBounds(target.base_addr, img.size_of_image);
    defer veh.setTargetModuleBounds(0, 0);

    var bitmap = l1.CoverageBitmap{};
    var bp_table = try coverage.BreakpointTable.init(allocator, target.base_addr, img.machine, blocks, &bitmap);
    defer bp_table.deinit();
    veh.setBreakpointTable(&bp_table);

    var arena = try l1.SnapshotArena.init(allocator, 64 * 1024);
    defer arena.deinit();
    arena.takeSnapshot();

    var mod_snap = try dll_snapshot.ModuleDataSnapshot.init(allocator, target.base_addr, &img);
    defer mod_snap.deinit();

    const stdin_f = std.Io.File.stdin();
    const stdout_f = std.Io.File.stdout();

    const hello_tag = @tagName(builtin.cpu.arch) ++ "-" ++ @tagName(builtin.os.tag);
    try diff_protocol.writeFrame(stdout_f, io, .hello, hello_tag);

    while (true) {
        const frame = diff_protocol.readFrameAlloc(stdin_f, io, allocator) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        defer allocator.free(frame.payload);

        switch (frame.header.msg_type) {
            .quit => break,
            .hello => try diff_protocol.writeFrame(stdout_f, io, .hello, hello_tag),
            .reset_req => {
                _ = arena.restoreDirtyPages() catch 0;
                _ = mod_snap.restore();
                try diff_protocol.writeFrame(stdout_f, io, .reset_resp, &.{});
            },
            .run_req => {
                const len = @min(frame.payload.len, arena.maxCapacity());
                if (len > 0) {
                    @memcpy(arena.live_ptr[0..len], frame.payload[0..len]);
                }
                bitmap.resetTrace();
                const prev_hits = bp_table.hitCount();
                const res = veh.runProtected(target.entry, arena.live_ptr, len);
                const new_edges: u32 = @intCast(bp_table.hitCount() - prev_hits);

                _ = arena.restoreDirtyPages() catch 0;
                _ = mod_snap.restore();

                const enc = diff_protocol.encodeRunResp(.{
                    .crashed = res.crashed,
                    .exception_code = res.exception_code,
                    .fault_rva = res.fault_rva,
                    .ret_val = res.ret_val,
                    .new_edges = new_edges,
                });
                try diff_protocol.writeFrame(stdout_f, io, .run_resp, &enc);
            },
            else => {},
        }
    }
}
