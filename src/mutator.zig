const std = @import("std");

pub const Rng = struct {
    s: [4]u64,

    pub fn init(seed: u64) Rng {
        var z = seed;
        var s: [4]u64 = undefined;
        for (&s) |*slot| {
            z +%= 0x9e3779b97f4a7c15;
            var x = z;
            x = (x ^ (x >> 30)) *% 0xbf58476d1ce4e5b9;
            x = (x ^ (x >> 27)) *% 0x94d049bb133111eb;
            slot.* = x ^ (x >> 31);
        }
        return .{ .s = s };
    }

    pub inline fn next(self: *Rng) u64 {
        const res = std.math.rotl(u64, self.s[1] *% 5, 7) *% 9;
        const t = self.s[1] << 17;
        self.s[2] ^= self.s[0];
        self.s[3] ^= self.s[1];
        self.s[1] ^= self.s[2];
        self.s[0] ^= self.s[3];
        self.s[2] ^= t;
        self.s[3] = std.math.rotl(u64, self.s[3], 45);
        return res;
    }

    pub inline fn below(self: *Rng, bound: usize) usize {
        if (bound <= 1) return 0;
        return @intCast(self.next() % @as(u64, bound));
    }
};

const INTERESTING_U8 = [_]u8{ 0x00, 0x01, 0x7F, 0x80, 0xFF };

pub const MAX_DICT_TOKENS: usize = 128;
pub const MAX_TOKEN_LEN: usize = 32;

pub const DictToken = struct {
    bytes: [MAX_TOKEN_LEN]u8 = @splat(0),
    len: u8 = 0,
};

pub const Dictionary = struct {
    tokens: [MAX_DICT_TOKENS]DictToken = undefined,
    count: usize = 0,

    pub fn init() Dictionary {
        return .{};
    }

    /// Add a 2..32 byte constant token to the dictionary, ignoring empty/oversized or duplicate entries.
    pub fn add(self: *Dictionary, tok: []const u8) bool {
        if (tok.len < 2 or tok.len > MAX_TOKEN_LEN) return false;
        if (self.count >= MAX_DICT_TOKENS) return false;
        for (self.tokens[0..self.count]) |existing| {
            const s = existing.bytes[0..existing.len];
            if (std.mem.eql(u8, s, tok)) return false;
        }
        var entry = DictToken{ .len = @intCast(tok.len) };
        @memcpy(entry.bytes[0..tok.len], tok);
        self.tokens[self.count] = entry;
        self.count += 1;
        return true;
    }

    pub fn sliceAt(self: *const Dictionary, idx: usize) []const u8 {
        const t = &self.tokens[idx];
        return t.bytes[0..t.len];
    }
};

pub fn mutateHavoc(rng: *Rng, buf: []u8, max_len: usize) usize {
    return mutateHavocLen(rng, buf, buf.len, max_len);
}

pub fn mutateHavocLen(rng: *Rng, buf: []u8, cur_len: usize, max_len: usize) usize {
    const cap = @min(buf.len, max_len);
    if (cap == 0 or cur_len == 0) return 0;
    var len = @min(cur_len, cap);
    const ops = 1 + rng.below(6);

    for (0..ops) |_| {
        if (len == 0) break;
        switch (rng.below(5)) {
            0 => {
                // Bit flip
                const idx = rng.below(len);
                const bit: u3 = @intCast(rng.below(8));
                buf[idx] ^= (@as(u8, 1) << bit);
            },
            1 => {
                // Byte replace with random or interesting boundary
                const idx = rng.below(len);
                if (rng.below(2) == 0) {
                    buf[idx] = INTERESTING_U8[rng.below(INTERESTING_U8.len)];
                } else {
                    buf[idx] = @truncate(rng.next());
                }
            },
            2 => {
                // Arithmetic +/- delta
                const idx = rng.below(len);
                const delta: u8 = @intCast(1 + rng.below(16));
                if (rng.below(2) == 0) {
                    buf[idx] +%= delta;
                } else {
                    buf[idx] -%= delta;
                }
            },
            3 => {
                // Shrink
                if (len > 4) len -= 1 + rng.below(@min(len - 1, 8));
            },
            4 => {
                // Grow / duplicate byte
                if (len < cap) {
                    const idx = rng.below(len);
                    buf[len] = buf[idx];
                    len += 1;
                }
            },
            else => {},
        }
    }
    return len;
}

/// Dictionary-guided havoc mutator: runs byte havoc, then periodically splices or overwrites
/// an extracted magic token (e.g. `.rdata` string or ARM64 `MOVZ`/`CMP` immediate).
pub fn mutateWithDict(rng: *Rng, buf: []u8, cur_len: usize, max_len: usize, dict: *const Dictionary) usize {
    const cap = @min(buf.len, max_len);
    if (cap == 0) return 0;
    const bounded_cur = @min(@max(cur_len, 1), cap);
    var len = mutateHavocLen(rng, buf[0..cap], bounded_cur, cap);
    if (dict.count == 0) return len;

    if (rng.below(100) < 45) {
        const tok = dict.sliceAt(rng.below(dict.count));
        if (tok.len <= cap) {
            if (len < tok.len) {
                @memcpy(buf[0..tok.len], tok);
                len = tok.len;
            } else if (rng.below(2) == 0 and len + tok.len <= cap) {
                @memcpy(buf[len .. len + tok.len], tok);
                len += tok.len;
            } else {
                const max_pos = len - tok.len + 1;
                const pos = rng.below(max_pos);
                @memcpy(buf[pos .. pos + tok.len], tok);
            }
        }
    }
    return len;
}

pub fn hashCrash(fault_rva: u32, frames: []const u32) u64 {
    var h: u64 = 0xcbf29ce484222325;
    h = (h ^ fault_rva) *% 0x100000001b3;
    for (frames[0..@min(frames.len, 3)]) |f| {
        h = (h ^ f) *% 0x100000001b3;
    }
    return h;
}

test "dictionary add, deduplication, and mutateWithDict" {
    var dict = Dictionary.init();
    try std.testing.expect(!dict.add("A")); // too short
    try std.testing.expect(dict.add("GGUF"));
    try std.testing.expect(!dict.add("GGUF")); // duplicate
    try std.testing.expect(dict.add("BOOM"));
    try std.testing.expectEqual(@as(usize, 2), dict.count);
    try std.testing.expectEqualStrings("GGUF", dict.sliceAt(0));

    var rng = Rng.init(0x1234_5678_9ABC_DEF0);
    var buf: [32]u8 = @splat(0x41);
    var saw_token = false;
    for (0..64) |_| {
        const n = mutateWithDict(&rng, &buf, 16, buf.len, &dict);
        if (n >= 4 and (std.mem.indexOf(u8, buf[0..n], "GGUF") != null or std.mem.indexOf(u8, buf[0..n], "BOOM") != null)) {
            saw_token = true;
            break;
        }
    }
    try std.testing.expect(saw_token);
}
