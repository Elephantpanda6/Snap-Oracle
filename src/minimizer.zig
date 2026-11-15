const std = @import("std");
const veh = @import("veh.zig");

pub fn minimizeCrash(
    allocator: std.mem.Allocator,
    func: veh.TargetFn,
    orig: []const u8,
    expected_code: u32,
) ![]u8 {
    var buf = try allocator.dupe(u8, orig);
    errdefer allocator.free(buf);

    const initial = veh.runProtected(func, buf.ptr, buf.len);
    if (!initial.crashed or initial.exception_code != expected_code) {
        return buf;
    }

    var len = buf.len;
    const cand = try allocator.alloc(u8, orig.len);
    defer allocator.free(cand);

    // Phase 1: binary chunk removal (halves, quarters, ..., down to chunk size 2).
    var chunk: usize = len / 2;
    while (chunk >= 2) : (chunk /= 2) {
        var i: usize = 0;
        while (i + chunk <= len) {
            const cand_len = len - chunk;
            if (i > 0) {
                @memcpy(cand[0..i], buf[0..i]);
            }
            const tail_len = len - (i + chunk);
            if (tail_len > 0) {
                @memcpy(cand[i .. i + tail_len], buf[i + chunk .. len]);
            }

            const res = veh.runProtected(func, cand.ptr, cand_len);
            if (res.crashed and res.exception_code == expected_code) {
                @memcpy(buf[0..cand_len], cand[0..cand_len]);
                len = cand_len;
            } else {
                i += chunk;
            }
        }
    }

    // Phase 2: single-byte removal pass left-to-right until a full pass makes no progress.
    while (len > 0) {
        var progress = false;
        var i: usize = 0;
        while (i < len) {
            const cand_len = len - 1;
            if (i > 0) {
                @memcpy(cand[0..i], buf[0..i]);
            }
            const tail_len = len - i - 1;
            if (tail_len > 0) {
                @memcpy(cand[i .. i + tail_len], buf[i + 1 .. len]);
            }

            const res = veh.runProtected(func, cand.ptr, cand_len);
            if (res.crashed and res.exception_code == expected_code) {
                @memcpy(buf[0..cand_len], cand[0..cand_len]);
                len = cand_len;
                progress = true;
            } else {
                i += 1;
            }
        }
        if (!progress) break;
    }

    const result = try allocator.dupe(u8, buf[0..len]);
    allocator.free(buf);
    return result;
}

fn crashOnBoom(data: [*]const u8, len: usize) callconv(.c) u64 {
    if (len < 4) return 0;
    const slice = data[0..len];
    if (std.mem.indexOf(u8, slice, "BOOM") != null) {
        const bad: *volatile u8 = @ptrFromInt(0xDEAD);
        bad.* = 1;
    }
    return @as(u64, len);
}

test "minimizeCrash reduces AAAA_BOOM_ZZZZ to BOOM" {
    var guard = veh.Guard.init();
    defer guard.deinit();

    const alloc = std.testing.allocator;
    const orig = "AAAA_BOOM_ZZZZ";
    const minimized = try minimizeCrash(alloc, crashOnBoom, orig, 0xC0000005);
    defer alloc.free(minimized);

    try std.testing.expectEqualStrings("BOOM", minimized);
}

test "minimizeCrash returns copy of orig when it does not crash with expected_code" {
    var guard = veh.Guard.init();
    defer guard.deinit();

    const alloc = std.testing.allocator;
    const safe = "AAAA_SAFE_ZZZZ";
    const kept_safe = try minimizeCrash(alloc, crashOnBoom, safe, 0xC0000005);
    defer alloc.free(kept_safe);
    try std.testing.expectEqualStrings(safe, kept_safe);

    const wrong_code_kept = try minimizeCrash(alloc, crashOnBoom, "AAAA_BOOM_ZZZZ", 0xC0000094);
    defer alloc.free(wrong_code_kept);
    try std.testing.expectEqualStrings("AAAA_BOOM_ZZZZ", wrong_code_kept);
}
