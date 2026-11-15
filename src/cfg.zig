const std = @import("std");
const pe = @import("pe.zig");

pub const BasicBlock = struct {
    rva: u32,
    func_rva: u32,
};

fn signExtend(val: u32, bits: u5) i64 {
    const shift: u6 = @intCast(64 - @as(u7, bits));
    return @as(i64, @bitCast(@as(u64, val) << shift)) >> shift;
}

/// Decode AArch64 32-bit fixed-width branches inside a `.pdata` function range
/// to discover basic-block entry RVAs without source or DWARF symbols.
pub fn decodeArm64BasicBlocks(
    allocator: std.mem.Allocator,
    code: []const u8,
    base_rva: u32,
    func_begin_rva: u32,
    func_end_rva: u32,
) ![]BasicBlock {
    var seen = std.AutoHashMap(u32, void).init(allocator);
    defer seen.deinit();

    var blocks = std.ArrayList(BasicBlock).empty;
    errdefer blocks.deinit(allocator);

    if (func_end_rva <= func_begin_rva) return blocks.toOwnedSlice(allocator);
    try seen.put(func_begin_rva, {});
    try blocks.append(allocator, .{ .rva = func_begin_rva, .func_rva = func_begin_rva });

    var rva = func_begin_rva;
    while (rva + 4 <= func_end_rva) : (rva += 4) {
        const off = @as(usize, rva - base_rva);
        if (off + 4 > code.len) break;
        const insn = std.mem.readInt(u32, code[off..][0..4], .little);

        var target_delta: ?i64 = null;
        var falls_through = true;

        // B / BL: 0x14000000 / 0x94000000 (imm26)
        if ((insn & 0x7C00_0000) == 0x1400_0000) {
            const imm26 = insn & 0x03FF_FFFF;
            target_delta = signExtend(imm26, 26) * 4;
            falls_through = (insn & 0x8000_0000) != 0; // BL falls through; B does not
        } else if ((insn & 0xFF00_0010) == 0x5400_0000) {
            // B.cond: imm19 << 5
            const imm19 = (insn >> 5) & 0x7FFFF;
            target_delta = signExtend(imm19, 19) * 4;
        } else if ((insn & 0x7E00_0000) == 0x3400_0000) {
            // CBZ / CBNZ: imm19 << 5
            const imm19 = (insn >> 5) & 0x7FFFF;
            target_delta = signExtend(imm19, 19) * 4;
        } else if ((insn & 0x7E00_0000) == 0x3600_0000) {
            // TBZ / TBNZ: imm14 << 5
            const imm14 = (insn >> 5) & 0x3FFF;
            target_delta = signExtend(imm14, 14) * 4;
        } else if ((insn & 0xFFFF_FC1F) == 0xD65F_0000) {
            // RET
            falls_through = false;
        }

        if (target_delta) |delta| {
            const t_i64 = @as(i64, rva) + delta;
            if (t_i64 >= @as(i64, func_begin_rva) and t_i64 < @as(i64, func_end_rva)) {
                const t_rva: u32 = @intCast(t_i64);
                if (!seen.contains(t_rva)) {
                    try seen.put(t_rva, {});
                    try blocks.append(allocator, .{ .rva = t_rva, .func_rva = func_begin_rva });
                }
            }
            if (falls_through and rva + 4 < func_end_rva and !seen.contains(rva + 4)) {
                try seen.put(rva + 4, {});
                try blocks.append(allocator, .{ .rva = rva + 4, .func_rva = func_begin_rva });
            }
        }
    }

    return blocks.toOwnedSlice(allocator);
}

/// Lightweight x86_64 branch scanner for basic-block entrypoints inside `.pdata`.
pub fn decodeX64BasicBlocks(
    allocator: std.mem.Allocator,
    code: []const u8,
    base_rva: u32,
    func_begin_rva: u32,
    func_end_rva: u32,
) ![]BasicBlock {
    var seen = std.AutoHashMap(u32, void).init(allocator);
    defer seen.deinit();

    var blocks = std.ArrayList(BasicBlock).empty;
    errdefer blocks.deinit(allocator);

    if (func_end_rva <= func_begin_rva) return blocks.toOwnedSlice(allocator);
    try seen.put(func_begin_rva, {});
    try blocks.append(allocator, .{ .rva = func_begin_rva, .func_rva = func_begin_rva });

    var rva = func_begin_rva;
    while (rva < func_end_rva) : (rva += 1) {
        const off = @as(usize, rva - base_rva);
        if (off >= code.len) break;
        const b = code[off];

        // Short Jcc (0x70..0x7F) or JMP rel8 (0xEB)
        if ((b >= 0x70 and b <= 0x7F) or b == 0xEB) {
            if (off + 2 <= code.len) {
                const rel8: i8 = @bitCast(code[off + 1]);
                const t_i64 = @as(i64, rva) + 2 + @as(i64, rel8);
                if (t_i64 >= @as(i64, func_begin_rva) and t_i64 < @as(i64, func_end_rva)) {
                    const t_rva: u32 = @intCast(t_i64);
                    if (!seen.contains(t_rva)) {
                        try seen.put(t_rva, {});
                        try blocks.append(allocator, .{ .rva = t_rva, .func_rva = func_begin_rva });
                    }
                }
            }
        } else if (b == 0x0F and off + 6 <= code.len) {
            const b2 = code[off + 1];
            if (b2 >= 0x80 and b2 <= 0x8F) {
                const rel32 = std.mem.readInt(i32, code[off + 2 ..][0..4], .little);
                const t_i64 = @as(i64, rva) + 6 + @as(i64, rel32);
                if (t_i64 >= @as(i64, func_begin_rva) and t_i64 < @as(i64, func_end_rva)) {
                    const t_rva: u32 = @intCast(t_i64);
                    if (!seen.contains(t_rva)) {
                        try seen.put(t_rva, {});
                        try blocks.append(allocator, .{ .rva = t_rva, .func_rva = func_begin_rva });
                    }
                }
            }
        }
    }

    return blocks.toOwnedSlice(allocator);
}
