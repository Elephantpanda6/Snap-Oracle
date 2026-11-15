const std = @import("std");
const cfg = @import("cfg.zig");
const mutator = @import("mutator.zig");
const l1 = @import("l1_engine.zig");
const veh = @import("veh.zig");

test "arm64 basic-block decoder" {
    const alloc = std.testing.allocator;
    // NOP; B.EQ +8; NOP; RET
    const code = [_]u8{
        0x1F, 0x20, 0x03, 0xD5, // 0x1000: nop
        0x40, 0x00, 0x00, 0x54, // 0x1004: b.eq +8 -> 0x100C
        0x1F, 0x20, 0x03, 0xD5, // 0x1008: nop
        0xC0, 0x03, 0x5F, 0xD6, // 0x100C: ret
    };
    const bbs = try cfg.decodeArm64BasicBlocks(alloc, &code, 0x1000, 0x1000, 0x1010);
    defer alloc.free(bbs);
    try std.testing.expectEqual(@as(usize, 3), bbs.len);
}

test "x64 basic-block decoder" {
    const alloc = std.testing.allocator;
    // nop; je +2; nop; nop; ret
    const code = [_]u8{ 0x90, 0x74, 0x02, 0x90, 0x90, 0xC3 };
    const bbs = try cfg.decodeX64BasicBlocks(alloc, &code, 0x1000, 0x1000, 0x1006);
    defer alloc.free(bbs);
    try std.testing.expectEqual(@as(usize, 2), bbs.len);
}

test "mutator & coverage bitmap" {
    var rng = mutator.Rng.init(42);
    var buf = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const new_len = mutator.mutateHavoc(&rng, &buf, buf.len);
    try std.testing.expect(new_len > 0 and new_len <= buf.len);

    var bm = l1.CoverageBitmap{};
    try std.testing.expect(bm.recordEdge(0x140001000));
    try std.testing.expectEqual(@as(usize, 1), bm.unique_edges);
}

test "windows MEM_WRITE_WATCH dirty-page reset" {
    const alloc = std.testing.allocator;
    var arena = try l1.SnapshotArena.init(alloc, 16 * 1024);
    defer arena.deinit();

    arena.live_ptr[0] = 0xAA;
    arena.takeSnapshot();

    arena.live_ptr[0] = 0x55;
    arena.live_ptr[4096] = 0x77;
    const restored = arena.restoreDirtyPages();
    try std.testing.expectEqual(@as(usize, 2), restored);
    try std.testing.expectEqual(@as(u8, 0xAA), arena.live_ptr[0]);
    try std.testing.expectEqual(@as(u8, 0x00), arena.live_ptr[4096]);
}

fn testTargetFn(ptr: [*]const u8, len: usize) callconv(.c) u64 {
    if (len >= 4 and ptr[0] == 'B' and ptr[1] == 'O' and ptr[2] == 'O' and ptr[3] == 'M') {
        const bad: *volatile u8 = @ptrFromInt(0xDEAD);
        bad.* = 1;
    }
    return @as(u64, len);
}

test "VEH protected execution & crash recovery" {
    var guard = veh.Guard.init();
    defer guard.deinit();

    const ok_input = "SAFE";
    const ok_res = veh.runProtected(testTargetFn, ok_input.ptr, ok_input.len);
    try std.testing.expect(!ok_res.crashed);
    try std.testing.expectEqual(@as(u64, 4), ok_res.ret_val);

    const boom_input = "BOOM";
    const crash_res = veh.runProtected(testTargetFn, boom_input.ptr, boom_input.len);
    try std.testing.expect(crash_res.crashed);
    try std.testing.expectEqual(@as(u32, 0xC0000005), crash_res.exception_code);
}
