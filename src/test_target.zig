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
