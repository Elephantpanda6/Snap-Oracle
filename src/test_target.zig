const std = @import("std");

/// Stateful `.data` section counter exported to deterministically verify `ModuleDataSnapshot` resets.
var g_stateful_hits: u32 = 0;

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

/// Stateful parser that crashes ONLY when `g_stateful_hits` starts at `0` (so `g_stateful_hits == 1`).
/// Without `.data` snapshot restoration after each iteration, the second execution has `g_stateful_hits > 1`
/// and fails to reproduce or minimize.
export fn stateful_counter(ptr: [*]const u8, len: usize) callconv(.c) u64 {
    g_stateful_hits +%= 1;
    if (g_stateful_hits != 1) return @as(u64, g_stateful_hits) | 0x8000;
    if (len >= 4 and ptr[0] == 'S' and ptr[1] == 'T' and ptr[2] == 'A' and ptr[3] == 'T') {
        crashNow();
    }
    return @as(u64, len);
}

/// ARM64 ABI, NEON vector reduction, and floating-point/sign-extension differential probe target.
export fn arm64_abi_probe(ptr: [*]const u8, len: usize) callconv(.c) u64 {
    if (len < 16) return 0x10;
    const vec: @Vector(16, u8) = ptr[0..16].*;
    const xor_sum = @reduce(.Xor, vec);
    const signed_first: i8 = @bitCast(ptr[0]);
    var acc: u64 = @as(u64, xor_sum);
    if (signed_first < 0) acc ^= 0x55AA;

    const flt: f64 = @as(f64, @floatFromInt(@as(u32, ptr[4]) *% 17)) / 3.0;
    const sat: u32 = @intFromFloat(@max(0.0, flt));
    acc +%= sat;

    if (ptr[0] == 'A' and ptr[1] == '6' and ptr[2] == '4' and ptr[3] == '!' and xor_sum == 0xAA) {
        crashNow();
    }
    return acc;
}

/// Local ARM64 AI laptop GGUF model header parser (magic `GGUF`, version 2..3, tensor overflow check).
export fn gguf_header_parse(ptr: [*]const u8, len: usize) callconv(.c) u64 {
    if (len < 24) return 0x60;
    const d = ptr[0..len];
    if (d[0] != 'G' or d[1] != 'G' or d[2] != 'U' or d[3] != 'F') return 0x61;
    const version = std.mem.readInt(u32, d[4..8], .little);
    if (version < 2 or version > 3) return 0x62;
    const tensor_count = std.mem.readInt(u64, d[8..16], .little);
    const kv_count = std.mem.readInt(u64, d[16..24], .little);
    if (tensor_count == 0 or kv_count > 1_000_000) return 0x63;
    if (len >= 26 and d[24] == 0xFF and d[25] == 0xFE and tensor_count > 0x00FF_FFFF) {
        crashNow();
    }
    return tensor_count ^ (kv_count << 1);
}

/// Stage 5: innermost record body. Only reached through magic -> version -> type 3 -> nested
/// header -> sub-length agreement; the fault hides behind two further byte-level checks.
noinline fn parseNested(p: []const u8) u64 {
    if (p.len < 3) return 0x30;
    if (p[0] != 'Q') return 0x31;
    const flags = p[1];
    const inner_len: usize = p[2];
    if (inner_len != p.len - 3) return 0x32;
    const body = p[3..];
    if (flags & 0x80 == 0) return 0x33;
    if (body.len >= 2 and body[0] == 0xDE) {
        if (body[1] == 0xAD) crashNow();
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
        if (i + l > p.len) return 0x40;
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
export fn parse_packet(ptr: [*]const u8, len: usize) callconv(.c) u64 {
    const d = ptr[0..len];
    if (len < 6) return 0x01;
    if (d[0] != 'S') return 0x02;
    if (d[1] != 'N') return 0x03;
    const version = d[2];
    if (version == 0 or version > 3) return 0x04;
    const kind = d[3];
    const plen: usize = d[4];
    if (plen != len - 5) return 0x05;
    const payload = d[5..];
    switch (kind) {
        1 => return parseTlv(payload),
        2 => return parseChecksum(payload),
        3 => {
            if (version < 2) return 0x06;
            return parseNested(payload);
        },
        else => return 0x07,
    }
}

test "parse_packet, stateful_counter, and gguf_header_parse work as expected" {
    const veh = @import("veh.zig");
    var guard = veh.Guard.init();
    defer guard.deinit();

    const short = [_]u8{ 'S', 'N' };
    try std.testing.expectEqual(@as(u64, 0x01), parse_packet(&short, short.len));
    const tlv = [_]u8{ 'S', 'N', 1, 1, 3, 3, 1, 0xAA };
    try std.testing.expect(parse_packet(&tlv, tlv.len) != 0x05);
    const cks_ok = [_]u8{ 'S', 'N', 1, 2, 2, 5, 5 };
    try std.testing.expectEqual(@as(u64, 0x52), parse_packet(&cks_ok, cks_ok.len));

    const boom = [_]u8{ 'S', 'N', 2, 3, 5, 'Q', 0x80, 2, 0xDE, 0xAD };
    const r = veh.runProtected(parse_packet, &boom, boom.len);
    try std.testing.expect(r.crashed);
    try std.testing.expectEqual(@as(u32, 0xC0000005), r.exception_code);

    g_stateful_hits = 0;
    const stat = "STAT";
    const r_stat = veh.runProtected(stateful_counter, stat.ptr, stat.len);
    try std.testing.expect(r_stat.crashed);
    const r_stat2 = veh.runProtected(stateful_counter, stat.ptr, stat.len);
    try std.testing.expect(!r_stat2.crashed); // second run skips fault unless .data is snapshot-restored
    g_stateful_hits = 0;

    var gguf: [26]u8 = @splat(0);
    @memcpy(gguf[0..4], "GGUF");
    std.mem.writeInt(u32, gguf[4..8], 3, .little);
    std.mem.writeInt(u64, gguf[8..16], 0x0100_0000, .little);
    std.mem.writeInt(u64, gguf[16..24], 4, .little);
    gguf[24] = 0xFF;
    gguf[25] = 0xFE;
    const r_gguf = veh.runProtected(gguf_header_parse, &gguf, gguf.len);
    try std.testing.expect(r_gguf.crashed);
}
