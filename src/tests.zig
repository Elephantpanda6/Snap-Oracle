const std = @import("std");
const builtin = @import("builtin");
const cfg = @import("cfg.zig");
const mutator = @import("mutator.zig");
const l1 = @import("l1_engine.zig");
const veh = @import("veh.zig");
const coverage = @import("coverage.zig");
const corpus = @import("corpus.zig");
const minimizer = @import("minimizer.zig");

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

const MEM_COMMIT_TEST: u32 = 0x1000;
const MEM_RESERVE_TEST: u32 = 0x2000;
const MEM_RELEASE_TEST: u32 = 0x8000;
const PAGE_EXECUTE_READWRITE_TEST: u32 = 0x40;

extern "kernel32" fn VirtualAlloc(?*anyopaque, usize, u32, u32) callconv(.winapi) ?*anyopaque;
extern "kernel32" fn VirtualFree(*anyopaque, usize, u32) callconv(.winapi) c_int;

test "end-to-end decodeX64BasicBlocksFull + BreakpointTable + VEH one-shot coverage" {
    if (builtin.cpu.arch != .x86_64 or builtin.os.tag != .windows) return error.SkipZigTest;

    const mem: [*]u8 = @ptrCast(VirtualAlloc(null, 4096, MEM_RESERVE_TEST | MEM_COMMIT_TEST, PAGE_EXECUTE_READWRITE_TEST) orelse return error.SkipZigTest);
    defer _ = VirtualFree(mem, 0, MEM_RELEASE_TEST);

    // Win64 ABI (rcx=ptr, rdx=len):
    // 0x00: 48 83 FA 04        cmp rdx, 4
    // 0x04: 72 06              jb +6 (-> 0x0C)
    // 0x06: B8 01 00 00 00     mov eax, 1
    // 0x0B: C3                 ret
    // 0x0C: 31 C0              xor eax, eax
    // 0x0E: C3                 ret
    const code = [_]u8{
        0x48, 0x83, 0xFA, 0x04,
        0x72, 0x06,
        0xB8, 0x01, 0x00, 0x00, 0x00,
        0xC3,
        0x31, 0xC0,
        0xC3,
    };
    @memcpy(mem[0..code.len], &code);

    const blocks = try cfg.decodeX64BasicBlocksFull(std.testing.allocator, mem[0..code.len], 0, 0, code.len);
    defer std.testing.allocator.free(blocks);
    try std.testing.expectEqual(@as(usize, 3), blocks.len);

    var bitmap = l1.CoverageBitmap{};
    var table = try coverage.BreakpointTable.init(std.testing.allocator, @intFromPtr(mem), .amd64, blocks, &bitmap);
    defer table.deinit();
    try std.testing.expectEqual(@as(usize, 3), table.totalCount());

    var guard = veh.Guard.init();
    defer guard.deinit();
    veh.setBreakpointTable(&table);
    defer veh.setBreakpointTable(null);

    const f: veh.TargetFn = @ptrCast(mem);
    const long_in = "ABCD";
    const res1 = veh.runProtected(f, long_in.ptr, long_in.len);
    try std.testing.expect(!res1.crashed);
    try std.testing.expectEqual(@as(u64, 1), res1.ret_val);
    try std.testing.expectEqual(@as(usize, 2), table.hitCount());
    try std.testing.expectEqual(@as(usize, 2), bitmap.unique_edges);

    // One-shot: re-running same path must not add hits.
    const res2 = veh.runProtected(f, long_in.ptr, long_in.len);
    try std.testing.expect(!res2.crashed);
    try std.testing.expectEqual(@as(u64, 1), res2.ret_val);
    try std.testing.expectEqual(@as(usize, 2), table.hitCount());

    // Taking the jb branch hits the 3rd block.
    const short_in = "A";
    const res3 = veh.runProtected(f, short_in.ptr, short_in.len);
    try std.testing.expect(!res3.crashed);
    try std.testing.expectEqual(@as(u64, 0), res3.ret_val);
    try std.testing.expectEqual(@as(usize, 3), table.hitCount());
    try std.testing.expectEqual(@as(usize, 3), bitmap.unique_edges);
}

test "end-to-end Corpus deduplication and biased selection" {
    var c = corpus.Corpus.init(std.testing.allocator);
    defer c.deinit();

    try c.ensureNonEmpty();
    try std.testing.expectEqual(@as(usize, 1), c.count());

    try std.testing.expect(try c.addSeed("seed_a", 1));
    try std.testing.expect(!try c.addSeed("seed_a", 2));
    try std.testing.expect(try c.addSeed("seed_b", 3));
    try std.testing.expectEqual(@as(usize, 3), c.count());

    var rng = mutator.Rng.init(0xCAFEBABEDEADBEEF);
    var latest_hits: usize = 0;
    for (0..1000) |_| {
        if (std.mem.eql(u8, c.pickNext(&rng), "seed_b")) {
            latest_hits += 1;
        }
    }
    try std.testing.expect(latest_hits >= 650);
}

fn paddedCrashTarget(ptr: [*]const u8, len: usize) callconv(.c) u64 {
    if (len < 4) return 0;
    if (std.mem.indexOf(u8, ptr[0..len], "BOOM") != null) {
        const bad: *volatile u8 = @ptrFromInt(0xDEAD);
        bad.* = 1;
    }
    return @as(u64, len);
}

test "end-to-end minimizeCrash shrinks padded trigger to BOOM" {
    var guard = veh.Guard.init();
    defer guard.deinit();

    const padded = "XXXX_BOOM_YYYY";
    const out = try minimizer.minimizeCrash(std.testing.allocator, paddedCrashTarget, padded, 0xC0000005);
    defer std.testing.allocator.free(out);
    try std.testing.expectEqualStrings("BOOM", out);
}
