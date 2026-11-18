const std = @import("std");

pub const MAGIC: u32 = 0x534E_4150; // "SNAP"
pub const HEADER_SIZE: usize = 12;
pub const RUN_RESP_SIZE: usize = 24;
pub const MAX_PAYLOAD_LEN: usize = 4 * 1024 * 1024;

pub const MsgType = enum(u8) {
    hello = 1,
    run_req = 2,
    run_resp = 3,
    reset_req = 4,
    reset_resp = 5,
    quit = 6,
};

pub const Header = struct {
    magic: u32 = MAGIC,
    msg_type: MsgType,
    flags: u8 = 0,
    reserved: u16 = 0,
    payload_len: u32 = 0,
};

pub const RunResp = struct {
    crashed: bool,
    exception_code: u32,
    fault_rva: u32,
    ret_val: u64,
    new_edges: u32,
};

pub fn encodeHeader(hdr: Header) [HEADER_SIZE]u8 {
    var out: [HEADER_SIZE]u8 = undefined;
    std.mem.writeInt(u32, out[0..4], hdr.magic, .little);
    out[4] = @intFromEnum(hdr.msg_type);
    out[5] = hdr.flags;
    std.mem.writeInt(u16, out[6..8], hdr.reserved, .little);
    std.mem.writeInt(u32, out[8..12], hdr.payload_len, .little);
    return out;
}

pub fn decodeHeader(buf: *const [HEADER_SIZE]u8) !Header {
    const magic = std.mem.readInt(u32, buf[0..4], .little);
    if (magic != MAGIC) return error.BadFrameMagic;
    const msg_raw = buf[4];
    const msg_type: MsgType = switch (msg_raw) {
        1 => .hello,
        2 => .run_req,
        3 => .run_resp,
        4 => .reset_req,
        5 => .reset_resp,
        6 => .quit,
        else => return error.InvalidMsgType,
    };
    const payload_len = std.mem.readInt(u32, buf[8..12], .little);
    if (payload_len > MAX_PAYLOAD_LEN) return error.PayloadTooLarge;
    return .{
        .magic = magic,
        .msg_type = msg_type,
        .flags = buf[5],
        .reserved = std.mem.readInt(u16, buf[6..8], .little),
        .payload_len = payload_len,
    };
}

pub fn encodeRunResp(r: RunResp) [RUN_RESP_SIZE]u8 {
    var out: [RUN_RESP_SIZE]u8 = @splat(0);
    out[0] = if (r.crashed) 1 else 0;
    std.mem.writeInt(u32, out[4..8], r.exception_code, .little);
    std.mem.writeInt(u32, out[8..12], r.fault_rva, .little);
    std.mem.writeInt(u64, out[12..20], r.ret_val, .little);
    std.mem.writeInt(u32, out[20..24], r.new_edges, .little);
    return out;
}

pub fn decodeRunResp(buf: []const u8) !RunResp {
    if (buf.len < RUN_RESP_SIZE) return error.TruncatedRunResp;
    return .{
        .crashed = buf[0] != 0,
        .exception_code = std.mem.readInt(u32, buf[4..8], .little),
        .fault_rva = std.mem.readInt(u32, buf[8..12], .little),
        .ret_val = std.mem.readInt(u64, buf[12..20], .little),
        .new_edges = std.mem.readInt(u32, buf[20..24], .little),
    };
}

pub fn readExact(file: std.Io.File, io: std.Io, buf: []u8) !void {
    var total: usize = 0;
    while (total < buf.len) {
        const bufs = [_][]u8{buf[total..]};
        const n = try file.readStreaming(io, &bufs);
        if (n == 0) return error.EndOfStream;
        total += n;
    }
}

pub fn writeFrame(file: std.Io.File, io: std.Io, msg_type: MsgType, payload: []const u8) !void {
    if (payload.len > MAX_PAYLOAD_LEN) return error.PayloadTooLarge;
    const hdr = encodeHeader(.{
        .msg_type = msg_type,
        .payload_len = @intCast(payload.len),
    });
    try file.writeStreamingAll(io, &hdr);
    if (payload.len > 0) {
        try file.writeStreamingAll(io, payload);
    }
}

pub const Frame = struct {
    header: Header,
    payload: []u8,
};

pub fn readFrameAlloc(file: std.Io.File, io: std.Io, allocator: std.mem.Allocator) !Frame {
    var hdr_buf: [HEADER_SIZE]u8 = undefined;
    try readExact(file, io, &hdr_buf);
    const hdr = try decodeHeader(&hdr_buf);
    const payload = try allocator.alloc(u8, hdr.payload_len);
    errdefer allocator.free(payload);
    if (hdr.payload_len > 0) {
        try readExact(file, io, payload);
    }
    return .{ .header = hdr, .payload = payload };
}

test "diff_protocol header and RunResp round-trip and malformed guard" {
    const hdr_bytes = encodeHeader(.{ .msg_type = .run_req, .flags = 3, .payload_len = 128 });
    const hdr = try decodeHeader(&hdr_bytes);
    try std.testing.expectEqual(MsgType.run_req, hdr.msg_type);
    try std.testing.expectEqual(@as(u8, 3), hdr.flags);
    try std.testing.expectEqual(@as(u32, 128), hdr.payload_len);

    var bad_magic = hdr_bytes;
    bad_magic[0] = 0xFF;
    try std.testing.expectError(error.BadFrameMagic, decodeHeader(&bad_magic));

    const resp = RunResp{
        .crashed = true,
        .exception_code = 0xC0000005,
        .fault_rva = 0x1040,
        .ret_val = 0xDEAD_BEEF,
        .new_edges = 7,
    };
    const enc = encodeRunResp(resp);
    const dec = try decodeRunResp(&enc);
    try std.testing.expectEqual(resp.crashed, dec.crashed);
    try std.testing.expectEqual(resp.exception_code, dec.exception_code);
    try std.testing.expectEqual(resp.fault_rva, dec.fault_rva);
    try std.testing.expectEqual(resp.ret_val, dec.ret_val);
    try std.testing.expectEqual(resp.new_edges, dec.new_edges);
}
