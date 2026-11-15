const std = @import("std");

export fn fuzz_entry(ptr: [*]const u8, len: usize) callconv(.c) u64 {
    if (len >= 4 and ptr[0] == 'B' and ptr[1] == 'O' and ptr[2] == 'O' and ptr[3] == 'M') {
        const bad: *volatile u8 = @ptrFromInt(0xDEAD);
        bad.* = 1;
    }

    var h: u64 = 0xcbf29ce484222325;
    for (ptr[0..len]) |b| {
        h ^= b;
        h *%= 0x100000001b3;
    }
    return h;
}

fn crashNow() noreturn {
    const bad: *volatile u8 = @ptrFromInt(0xDEAD);
    bad.* = 1;
    unreachable;
}

/// Stage 5: innermost record body. Only reached through magic -> version -> type 3 -> nested
/// header -> sub-length agreement; the fault hides behind two further byte-level checks.
noinline fn parseNested(p: []const u8) u64 {
    // nested header: 'Q', flags, inner_len
    if (p.len < 3) return 0x30;
    if (p[0] != 'Q') return 0x31;
    const flags = p[1];
    const inner_len: usize = p[2];
    if (inner_len != p.len - 3) return 0x32; // sub-length must match exactly
    const body = p[3..];
    if (flags & 0x80 == 0) return 0x33;
    if (body.len >= 2 and body[0] == 0xDE) {
        if (body[1] == 0xAD) crashNow(); // deepest branch: controlled fault
        return 0x34;
    }
    return 0x35;
}

/// Stage 4: TLV list (type 1). Tags 1..3 are accepted, others skipped.
noinline fn parseTlv(p: []const u8) u64 {
    var i: usize = 0;
    var acc: u64 = 0;
    var records: u64 = 0;
    while (i + 2 <= p.len) {
        const tag = p[i];
        const l: usize = p[i + 1];
        i += 2;
        if (i + l > p.len) return 0x40; // truncated record
        const v = p[i .. i + l];
        i += l;
        records += 1;
        switch (tag) {
            1 => {
                if (l == 4) acc +%= std.mem.readInt(u32, v[0..4], .little) else acc +%= 1;
            },
            2 => {
                if (l > 0 and v[0] == 0xFF) acc ^= 0xFF00 else acc ^= 0x00FF;
            },
            3 => acc +%= l,
            else => {},
        }
        if (records > 16) return 0x41;
    }
    return acc ^ records;
}

/// Stage 4': checksum record (type 2).
noinline fn parseChecksum(p: []const u8) u64 {
    if (p.len < 2) return 0x50;
    var sum: u8 = 0;
    for (p[0 .. p.len - 1]) |b| sum +%= b;
    if (sum != p[p.len - 1]) return 0x51;
    return 0x52;
}

/// Multi-stage binary packet parser used to demonstrate coverage-guided fuzzing.
///   offset 0: 'S'   offset 1: 'N'   offset 2: version (1..3)   offset 3: type (1..3)
///   offset 4: payload length   offset 5..: payload
export fn parse_packet(ptr: [*]const u8, len: usize) callconv(.c) u64 {
    const d = ptr[0..len];
    if (len < 6) return 0x01; // stage 1: header length
    if (d[0] != 'S') return 0x02; // stage 2: magic byte 0
    if (d[1] != 'N') return 0x03; // magic byte 1
    const version = d[2];
    if (version == 0 or version > 3) return 0x04; // stage 3: version
    const kind = d[3];
    const plen: usize = d[4];
    if (plen != len - 5) return 0x05; // payload length must agree
    const payload = d[5..];
    switch (kind) { // stage 4: type dispatch
        1 => return parseTlv(payload),
        2 => return parseChecksum(payload),
        3 => {
            if (version < 2) return 0x06; // nested records need v2+
            return parseNested(payload); // stage 5
        },
        else => return 0x07,
    }
}
test "parse_packet stages are progressively reachable; deepest branch faults" {
    const veh = @import("veh.zig");
    var guard = veh.Guard.init();
    defer guard.deinit();

    const short = [_]u8{ 'S', 'N' };
    try std.testing.expectEqual(@as(u64, 0x01), parse_packet(&short, short.len));
    const bad_magic = [_]u8{ 'X', 'N', 1, 1, 0, 0 };
    try std.testing.expectEqual(@as(u64, 0x02), parse_packet(&bad_magic, bad_magic.len));
    const bad_magic2 = [_]u8{ 'S', 'X', 1, 1, 1, 0 };
    try std.testing.expectEqual(@as(u64, 0x03), parse_packet(&bad_magic2, bad_magic2.len));
    const bad_ver = [_]u8{ 'S', 'N', 9, 1, 1, 0 };
    try std.testing.expectEqual(@as(u64, 0x04), parse_packet(&bad_ver, bad_ver.len));
    const bad_len = [_]u8{ 'S', 'N', 1, 1, 7, 0 };
    try std.testing.expectEqual(@as(u64, 0x05), parse_packet(&bad_len, bad_len.len));
    const tlv = [_]u8{ 'S', 'N', 1, 1, 3, 3, 1, 0xAA };
    try std.testing.expect(parse_packet(&tlv, tlv.len) != 0x05);
    const cks_bad = [_]u8{ 'S', 'N', 1, 2, 2, 6, 5 };
    try std.testing.expectEqual(@as(u64, 0x51), parse_packet(&cks_bad, cks_bad.len));
    const cks_ok = [_]u8{ 'S', 'N', 1, 2, 2, 5, 5 };
    try std.testing.expectEqual(@as(u64, 0x52), parse_packet(&cks_ok, cks_ok.len));
    const nested_old = [_]u8{ 'S', 'N', 1, 3, 1, 0 };
    try std.testing.expectEqual(@as(u64, 0x06), parse_packet(&nested_old, nested_old.len));
    const nested_noflag = [_]u8{ 'S', 'N', 2, 3, 5, 'Q', 0, 2, 0xDE, 0xAD };
    try std.testing.expectEqual(@as(u64, 0x33), parse_packet(&nested_noflag, nested_noflag.len));

    const boom = [_]u8{ 'S', 'N', 2, 3, 5, 'Q', 0x80, 2, 0xDE, 0xAD };
    const r = veh.runProtected(parse_packet, &boom, boom.len);
    try std.testing.expect(r.crashed);
    try std.testing.expectEqual(@as(u32, 0xC0000005), r.exception_code);
}