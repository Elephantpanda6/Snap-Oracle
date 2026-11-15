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

pub fn mutateHavoc(rng: *Rng, buf: []u8, max_len: usize) usize {
    if (buf.len == 0 or max_len == 0) return 0;
    var len = @min(buf.len, max_len);
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
                if (len < max_len) {
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

pub fn hashCrash(fault_rva: u32, frames: []const u32) u64 {
    var h: u64 = 0xcbf29ce484222325;
    h = (h ^ fault_rva) *% 0x100000001b3;
    for (frames[0..@min(frames.len, 3)]) |f| {
        h = (h ^ f) *% 0x100000001b3;
    }
    return h;
}
