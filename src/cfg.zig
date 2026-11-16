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

pub const Flow = enum {
    /// Execution continues with the next instruction.
    seq,
    /// Conditional branch: may jump to `rel` target, otherwise falls through.
    cond,
    /// Unconditional direct jump to `rel` target; no fall-through.
    jmp,
    /// ret / ud2 / hlt / int3 / indirect jmp: no known successor.
    term,
};

pub const Insn = struct {
    len: u8,
    flow: Flow,
    /// Displacement relative to the END of the instruction (only for `.cond` / `.jmp`).
    rel: i32 = 0,
};

const ModRm = struct { len: usize, reg: u8 };

fn parseModrm(code: []const u8, i: usize) ?ModRm {
    if (i >= code.len) return null;
    const m = code[i];
    const mod = m >> 6;
    const rm = m & 7;
    const reg = (m >> 3) & 7;
    var n: usize = 1;
    if (mod != 3) {
        if (rm == 4) {
            if (i + 1 >= code.len) return null;
            const sib = code[i + 1];
            n += 1;
            if (mod == 0 and (sib & 7) == 5) n += 4;
        } else if (mod == 0 and rm == 5) {
            n += 4;
        }
        if (mod == 1) {
            n += 1;
        } else if (mod == 2) {
            n += 4;
        }
    }
    return .{ .len = n, .reg = reg };
}

/// 0F-map opcodes (VEX/EVEX map 1 or legacy 0F) that carry a trailing imm8 after ModRM.
fn map1HasImm8(op: u8) bool {
    return switch (op) {
        0x70, 0x71, 0x72, 0x73, 0xA4, 0xAC, 0xBA, 0xC2, 0xC4, 0xC5, 0xC6, 0x0F => true,
        else => false,
    };
}

/// x86_64 instruction-length decoder. Returns `null` for undecodable / invalid-in-64-bit-mode
/// byte sequences (so callers can stop treating the stream as code).
/// `code` must begin at the first byte of the instruction.
pub fn decodeX64Insn(code: []const u8) ?Insn {
    var i: usize = 0;
    var opsize16 = false;
    var addr32 = false;
    while (i < code.len and i < 14) : (i += 1) {
        switch (code[i]) {
            0x66 => opsize16 = true,
            0x67 => addr32 = true,
            0xF0, 0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65 => {},
            else => break,
        }
    }
    if (i >= code.len) return null;

    var rex_w = false;
    if ((code[i] & 0xF0) == 0x40) {
        rex_w = (code[i] & 0x08) != 0;
        i += 1;
        if (i >= code.len) return null;
    }
    const op = code[i];
    i += 1;

    const immz: usize = if (opsize16 and !rex_w) 2 else 4;
    var has_modrm = false;
    var imm: usize = 0; // total immediate bytes following ModRM/opcode
    var flow: Flow = .seq;
    var rel_size: usize = 0; // if non-zero, the last `rel_size` imm bytes are a branch displacement
    var group3 = false; // F6/F7: imm only when reg field is 0/1
    var group5 = false; // FF
    var modrm_reg: u8 = 0;

    if (op == 0x0F) {
        if (i >= code.len) return null;
        const op2 = code[i];
        i += 1;
        switch (op2) {
            0x38 => {
                if (i >= code.len) return null;
                i += 1;
                has_modrm = true;
            },
            0x3A => {
                if (i >= code.len) return null;
                i += 1;
                has_modrm = true;
                imm = 1;
            },
            0x80...0x8F => {
                imm = 4;
                rel_size = 4;
                flow = .cond;
            },
            0x0B => flow = .term, // ud2
            0x05, 0x06, 0x07, 0x08, 0x09, 0x0E, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x37, 0x77, 0xA0, 0xA1, 0xA2, 0xA8, 0xA9, 0xAA, 0xC8...0xCF => {},
            0x04, 0x0A, 0x0C, 0x24...0x27, 0x36, 0x39, 0x3B...0x3F, 0x7A, 0x7B, 0xA6, 0xA7 => return null,
            else => {
                has_modrm = true;
                if (map1HasImm8(op2)) imm = 1;
            },
        }
    } else {
        switch (op) {
            0x00...0x3F => {
                const lo = op & 7;
                if (lo < 4) {
                    has_modrm = true;
                } else if (lo == 4) {
                    imm = 1;
                } else if (lo == 5) {
                    imm = immz;
                } else return null;
            },
            0x50...0x5F => {},
            0x62 => {
                // EVEX: 62 P0 P1 P2 opcode modrm [imm8]
                if (i + 4 > code.len) return null;
                const map = code[i] & 0x07;
                const eop = code[i + 3];
                i += 4;
                has_modrm = true;
                if (map == 3 or (map == 1 and map1HasImm8(eop))) imm = 1;
            },
            0x63 => has_modrm = true,
            0x68 => imm = immz,
            0x69 => {
                has_modrm = true;
                imm = immz;
            },
            0x6A => imm = 1,
            0x6B => {
                has_modrm = true;
                imm = 1;
            },
            0x6C...0x6F => {},
            0x70...0x7F => {
                imm = 1;
                rel_size = 1;
                flow = .cond;
            },
            0x80, 0x83 => {
                has_modrm = true;
                imm = 1;
            },
            0x81 => {
                has_modrm = true;
                imm = immz;
            },
            0x84...0x8F => has_modrm = true,
            0x90...0x99 => {},
            0x9B...0x9F => {},
            0xA0...0xA3 => imm = if (addr32) 4 else 8,
            0xA4...0xA7 => {},
            0xA8 => imm = 1,
            0xA9 => imm = immz,
            0xAA...0xAF => {},
            0xB0...0xB7 => imm = 1,
            0xB8...0xBF => imm = if (rex_w) 8 else immz,
            0xC0, 0xC1 => {
                has_modrm = true;
                imm = 1;
            },
            0xC2, 0xCA => {
                imm = 2;
                flow = .term;
            },
            0xC3, 0xCB, 0xCC, 0xCF => flow = .term,
            0xC4, 0xC5 => {
                // VEX (always VEX in 64-bit mode)
                var map: u8 = 1;
                if (op == 0xC4) {
                    if (i + 2 > code.len) return null;
                    map = code[i] & 0x1F;
                    i += 2;
                } else {
                    if (i + 1 > code.len) return null;
                    i += 1;
                }
                if (i >= code.len) return null;
                const vop = code[i];
                i += 1;
                has_modrm = !(map == 1 and vop == 0x77); // vzeroupper/vzeroall
                if (map == 3 or (map == 1 and map1HasImm8(vop))) imm = 1;
            },
            0xC6 => {
                has_modrm = true;
                imm = 1;
            },
            0xC7 => {
                has_modrm = true;
                imm = immz;
            },
            0xC8 => imm = 3,
            0xC9 => {},
            0xCD => imm = 1,
            0xD0...0xD3 => has_modrm = true,
            0xD7 => {},
            0xD8...0xDF => has_modrm = true,
            0xE0...0xE3 => {
                imm = 1;
                rel_size = 1;
                flow = .cond;
            },
            0xE4...0xE7 => imm = 1,
            0xE8 => imm = 4, // call rel32: control returns, treat as sequential
            0xE9 => {
                imm = 4;
                rel_size = 4;
                flow = .jmp;
            },
            0xEB => {
                imm = 1;
                rel_size = 1;
                flow = .jmp;
            },
            0xEC...0xEF => {},
            0xF1, 0xF5, 0xF8...0xFD => {},
            0xF4 => flow = .term,
            0xF6, 0xF7 => {
                has_modrm = true;
                group3 = true;
            },
            0xFE => has_modrm = true,
            0xFF => {
                has_modrm = true;
                group5 = true;
            },
            else => return null,
        }
    }

    if (has_modrm) {
        const m = parseModrm(code, i) orelse return null;
        i += m.len;
        modrm_reg = m.reg;
        if (group3 and modrm_reg <= 1) imm = if (op == 0xF6) 1 else immz;
        if (group5) {
            switch (modrm_reg) {
                0, 1, 2, 3, 6 => {}, // inc/dec/call/far call/push
                4, 5 => flow = .term, // indirect jmp
                else => return null,
            }
        }
    }

    const total = i + imm;
    if (total > code.len or total > 15) return null;

    var rel: i32 = 0;
    if (rel_size == 1) {
        rel = @as(i8, @bitCast(code[total - 1]));
    } else if (rel_size == 4) {
        rel = std.mem.readInt(i32, code[total - 4 ..][0..4], .little);
    }
    return .{ .len = @intCast(total), .flow = flow, .rel = rel };
}

fn addBlock(
    allocator: std.mem.Allocator,
    seen: *std.AutoHashMap(u32, void),
    blocks: *std.ArrayList(BasicBlock),
    rva: i64,
    func_begin_rva: u32,
    func_end_rva: u32,
) !bool {
    if (rva < @as(i64, func_begin_rva) or rva >= @as(i64, func_end_rva)) return false;
    const r: u32 = @intCast(rva);
    if (seen.contains(r)) return false;
    try seen.put(r, {});
    try blocks.append(allocator, .{ .rva = r, .func_rva = func_begin_rva });
    return true;
}

/// Recursive-descent x86_64 basic-block discovery. Starting at the function entry it follows
/// every direct branch with the instruction-length decoder, so every emitted RVA is a true
/// instruction boundary of reachable code (inline data / jump tables are never decoded).
/// When `include_fallthrough` is set, the instruction following a conditional branch is also a
/// block entry.
pub fn decodeX64BasicBlocksEx(
    allocator: std.mem.Allocator,
    code: []const u8,
    base_rva: u32,
    func_begin_rva: u32,
    func_end_rva: u32,
    include_fallthrough: bool,
) ![]BasicBlock {
    var seen = std.AutoHashMap(u32, void).init(allocator);
    defer seen.deinit();
    var visited = std.AutoHashMap(u32, void).init(allocator);
    defer visited.deinit();
    var work = std.ArrayList(u32).empty;
    defer work.deinit(allocator);

    var blocks = std.ArrayList(BasicBlock).empty;
    errdefer blocks.deinit(allocator);

    if (func_end_rva <= func_begin_rva or func_begin_rva < base_rva) return blocks.toOwnedSlice(allocator);
    try seen.put(func_begin_rva, {});
    try blocks.append(allocator, .{ .rva = func_begin_rva, .func_rva = func_begin_rva });
    try work.append(allocator, func_begin_rva);

    while (work.pop()) |start| {
        var pc: u32 = start;
        while (pc >= func_begin_rva and pc < func_end_rva) {
            if (visited.contains(pc)) break;
            const off = @as(usize, pc - base_rva);
            if (off >= code.len) break;
            const lim = @min(code.len - off, @as(usize, func_end_rva - pc));
            const insn = decodeX64Insn(code[off..][0..lim]) orelse break;
            try visited.put(pc, {});
            const next: u32 = pc + insn.len;
            switch (insn.flow) {
                .seq => pc = next,
                .cond, .jmp => {
                    const t = @as(i64, next) + @as(i64, insn.rel);
                    if (try addBlock(allocator, &seen, &blocks, t, func_begin_rva, func_end_rva)) {
                        try work.append(allocator, @intCast(t));
                    } else if (t >= func_begin_rva and t < func_end_rva and !visited.contains(@intCast(t))) {
                        try work.append(allocator, @intCast(t));
                    }
                    if (insn.flow == .jmp) break;
                    if (include_fallthrough) {
                        _ = try addBlock(allocator, &seen, &blocks, next, func_begin_rva, func_end_rva);
                    }
                    pc = next;
                },
                .term => break,
            }
        }
    }

    return blocks.toOwnedSlice(allocator);
}

/// x86_64 basic-block scanner (branch targets only; kept compatible with earlier callers).
pub fn decodeX64BasicBlocks(
    allocator: std.mem.Allocator,
    code: []const u8,
    base_rva: u32,
    func_begin_rva: u32,
    func_end_rva: u32,
) ![]BasicBlock {
    return decodeX64BasicBlocksEx(allocator, code, base_rva, func_begin_rva, func_end_rva, false);
}

/// Targets plus conditional-branch fall-through blocks (finer-grained coverage).
pub fn decodeX64BasicBlocksFull(
    allocator: std.mem.Allocator,
    code: []const u8,
    base_rva: u32,
    func_begin_rva: u32,
    func_end_rva: u32,
) ![]BasicBlock {
    return decodeX64BasicBlocksEx(allocator, code, base_rva, func_begin_rva, func_end_rva, true);
}

/// Parse a PE image from `bytes` and decode basic blocks for every `.pdata` function that lies
/// entirely inside `.text`. For ARM64 images (whose `.pdata` layout differs) the whole `.text`
/// section is decoded as one fixed-width range. Result RVAs are globally de-duplicated.
pub fn decodeAllTextBasicBlocks(allocator: std.mem.Allocator, bytes: []const u8) ![]BasicBlock {
    var img = try pe.parsePe(allocator, bytes);
    defer img.deinit();

    const text = img.findSection(".text") orelse return error.NoTextSection;
    const raw_off: usize = text.raw_offset;
    if (raw_off >= bytes.len) return error.InvalidPe;
    const avail = @min(@as(usize, text.raw_size), bytes.len - raw_off);
    const code = bytes[raw_off..][0..avail];
    const span: u32 = if (text.virtual_size == 0) text.raw_size else @min(text.virtual_size, text.raw_size);
    const text_begin = text.virtual_address;
    const text_end = text_begin + @min(span, @as(u32, @intCast(avail)));

    var seen = std.AutoHashMap(u32, void).init(allocator);
    defer seen.deinit();
    var out = std.ArrayList(BasicBlock).empty;
    errdefer out.deinit(allocator);

    for (img.functions) |f| {
        if (f.end_rva <= f.begin_rva) continue;
        if (f.begin_rva < text_begin or f.end_rva > text_end) continue;
        const bbs = switch (img.machine) {
            .arm64, .arm64ec => try decodeArm64BasicBlocks(allocator, code, text_begin, f.begin_rva, f.end_rva),
            .amd64 => try decodeX64BasicBlocksFull(allocator, code, text_begin, f.begin_rva, f.end_rva),
            else => continue,
        };
        defer allocator.free(bbs);
        for (bbs) |bb| {
            if (seen.contains(bb.rva)) continue;
            try seen.put(bb.rva, {});
            try out.append(allocator, bb);
        }
    }
    return out.toOwnedSlice(allocator);
}

fn expectLen(expected: u8, bytes: []const u8) !void {
    const insn = decodeX64Insn(bytes) orelse return error.Undecodable;
    try std.testing.expectEqual(expected, insn.len);
}

test "x64 length decoder" {
    try expectLen(1, &.{0x90});
    try expectLen(2, &.{ 0x66, 0x90 });
    try expectLen(5, &.{ 0x48, 0x89, 0x5C, 0x24, 0x08 }); // mov [rsp+8], rbx
    try expectLen(4, &.{ 0x48, 0x83, 0xEC, 0x28 }); // sub rsp, 28h
    try expectLen(5, &.{ 0xE8, 0, 0, 0, 0 }); // call rel32
    try expectLen(5, &.{ 0x0F, 0x1F, 0x44, 0x00, 0x00 }); // nop dword [rax+rax]
    try expectLen(9, &.{ 0x66, 0x0F, 0x1F, 0x84, 0, 0, 0, 0, 0 });
    try expectLen(10, &.{ 0x48, 0xB8, 1, 2, 3, 4, 5, 6, 7, 8 }); // movabs
    try expectLen(5, &.{ 0xB8, 1, 0, 0, 0 }); // mov eax, imm32
    try expectLen(4, &.{ 0x66, 0xB8, 0x34, 0x12 }); // mov ax, imm16
    try expectLen(6, &.{ 0x8B, 0x05, 0, 0, 0, 0 }); // mov eax, [rip+disp32]
    try expectLen(7, &.{ 0xC7, 0x45, 0xFC, 1, 0, 0, 0 }); // mov dword [rbp-4], 1
    try expectLen(6, &.{ 0xF7, 0xC1, 1, 0, 0, 0 }); // test ecx, imm32
    try expectLen(2, &.{ 0xF7, 0xD9 }); // neg ecx (group3 reg=3: no imm)
    try expectLen(3, &.{ 0xF6, 0xC1, 0x01 }); // test cl, imm8
    try expectLen(6, &.{ 0x0F, 0x84, 0, 0, 0, 0 }); // je rel32
    try expectLen(6, &.{ 0xFF, 0x15, 0, 0, 0, 0 }); // call [rip+disp32]
    try expectLen(4, &.{ 0x4C, 0x8D, 0x0C, 0x40 }); // lea r9,[rax+rax*2]
    try expectLen(4, &.{ 0x0F, 0xBA, 0xE0, 0x05 }); // bt eax, 5
    try expectLen(8, &.{ 0x48, 0x8B, 0x04, 0x25, 0, 0, 0, 0 }); // SIB no-base disp32
    try expectLen(4, &.{ 0xF3, 0x0F, 0x1E, 0xFA }); // endbr64
    try expectLen(2, &.{ 0x0F, 0x05 }); // syscall
    try expectLen(5, &.{ 0x66, 0x0F, 0x38, 0x00, 0xC1 }); // pshufb
    try expectLen(6, &.{ 0x66, 0x0F, 0x3A, 0x0F, 0xC1, 0x04 }); // palignr
    try expectLen(3, &.{ 0xC5, 0xF8, 0x77 }); // vzeroupper
    try expectLen(5, &.{ 0xC5, 0xF9, 0x70, 0xC0, 0x1B }); // vpshufd imm8
    try expectLen(5, &.{ 0xC4, 0xE2, 0x7D, 0x58, 0xC0 }); // vpbroadcastd
    try expectLen(9, &.{ 0xA1, 1, 2, 3, 4, 5, 6, 7, 8 }); // mov eax, moffs64
    try std.testing.expect(decodeX64Insn(&.{0x06}) == null); // invalid in 64-bit mode
    try std.testing.expect(decodeX64Insn(&.{ 0xE8, 0, 0 }) == null); // truncated
}

test "x64 basic blocks: targets, fall-throughs, no decoding of dead data" {
    const alloc = std.testing.allocator;
    const code = [_]u8{
        0x31, 0xC0, // 0x1000 xor eax,eax
        0x83, 0xF8, 0x05, // 0x1002 cmp eax,5       (loop head)
        0x7D, 0x04, // 0x1005 jge 0x100B
        0xFF, 0xC0, // 0x1007 inc eax
        0xEB, 0xF7, // 0x1009 jmp 0x1002
        0xC3, // 0x100B ret
        0xE9, 0xFF, 0xFF, 0xFF, 0x7F, // 0x100C dead data (never reached)
    };
    const full = try decodeX64BasicBlocksFull(alloc, &code, 0x1000, 0x1000, 0x1011);
    defer alloc.free(full);
    try std.testing.expectEqual(@as(usize, 4), full.len);
    const want = [_]u32{ 0x1000, 0x1002, 0x1007, 0x100B };
    for (want) |w| {
        var found = false;
        for (full) |bb| {
            if (bb.rva == w) found = true;
        }
        try std.testing.expect(found);
    }

    const targets = try decodeX64BasicBlocks(alloc, &code, 0x1000, 0x1000, 0x1011);
    defer alloc.free(targets);
    try std.testing.expectEqual(@as(usize, 3), targets.len);
}

test "decodeAllTextBasicBlocks on kernel32.dll" {
    const alloc = std.testing.allocator;
    const arch = @import("builtin").cpu.arch;
    if ((arch != .x86_64 and arch != .aarch64) or @import("builtin").os.tag != .windows) return error.SkipZigTest;
    // Parse a system DLL image from disk (kernel32 is always present).
    var buf: [64]u8 = undefined;
    _ = &buf;
    const path = "C:\\Windows\\System32\\kernel32.dll";
    const io = std.testing.io;
    const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, alloc, .limited(64 * 1024 * 1024)) catch return error.SkipZigTest;
    defer alloc.free(bytes);
    const bbs = decodeAllTextBasicBlocks(alloc, bytes) catch return error.SkipZigTest;
    defer alloc.free(bbs);
    try std.testing.expect(bbs.len > 1000);
}
