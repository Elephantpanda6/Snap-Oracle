const std = @import("std");
const pe = @import("pe.zig");
const macho = @import("macho_arm64.zig");
const arm64_isa = @import("arm64_isa.zig");
const binary = @import("binary.zig");

pub const BasicBlock = struct {
    rva: u32,
    func_rva: u32,
};

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

/// Recursive-descent AArch64 basic-block analyzer.
/// Starting from `func_begin_rva`, follows reachable branch targets (`B`, `B.cond`, `CBZ`, `CBNZ`,
/// `TBZ`, `TBNZ`) and conditional fall-throughs, terminates on `B`/`RET`/`RETAA`/`RETAB`/`BR`/`BRAA`/`HLT`/`UDF`,
/// avoids misdecoding literal pools, and protects exclusive monitor (`LDXR`..`STXR`) critical sections.
/// When `skip_landing_pads` is true, entry/target blocks starting with `BTI` or `PACIASP`/`PACIBSP`
/// advance the armed breakpoint RVA by +4 bytes to preserve indirect-branch landing-pad invariants.
pub fn decodeArm64BasicBlocksEx(
    allocator: std.mem.Allocator,
    code: []const u8,
    base_rva: u32,
    func_begin_rva: u32,
    func_end_rva: u32,
    skip_landing_pads: bool,
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
    const func_off = @as(usize, func_begin_rva - base_rva);
    if (func_off >= code.len) return blocks.toOwnedSlice(allocator);
    const func_avail = @min(code.len - func_off, @as(usize, func_end_rva - func_begin_rva));

    const excl_zones = try arm64_isa.findExclusiveZones(allocator, code[func_off .. func_off + func_avail], func_begin_rva);
    defer allocator.free(excl_zones);

    const recordSafeBlock = struct {
        fn emit(
            alloc: std.mem.Allocator,
            seen_map: *std.AutoHashMap(u32, void),
            out_blocks: *std.ArrayList(BasicBlock),
            bytes: []const u8,
            b_rva: u32,
            f_begin: u32,
            f_end: u32,
            zones: []const arm64_isa.ExclusiveZone,
            bti_skip: bool,
            raw_rva: i64,
        ) !void {
            if (raw_rva < @as(i64, f_begin) or raw_rva >= @as(i64, f_end)) return;
            var rva: u32 = @intCast(raw_rva);
            if (bti_skip and rva + 4 < f_end and rva >= b_rva) {
                const off = @as(usize, rva - b_rva);
                if (off + 4 <= bytes.len) {
                    const insn = std.mem.readInt(u32, bytes[off..][0..4], .little);
                    if (arm64_isa.isLandingPadOrPrologue(insn)) {
                        rva += 4;
                    }
                }
            }
            if (arm64_isa.isRvaInExclusiveZone(zones, rva)) return;
            _ = try addBlock(alloc, seen_map, out_blocks, @intCast(rva), f_begin, f_end);
        }
    }.emit;

    try recordSafeBlock(allocator, &seen, &blocks, code, base_rva, func_begin_rva, func_end_rva, excl_zones, skip_landing_pads, func_begin_rva);
    try work.append(allocator, func_begin_rva);

    while (work.pop()) |start| {
        var pc: u32 = start;
        while (pc >= func_begin_rva and pc + 4 <= func_end_rva) {
            if (visited.contains(pc)) break;
            const off = @as(usize, pc - base_rva);
            if (off + 4 > code.len) break;
            try visited.put(pc, {});

            const insn = std.mem.readInt(u32, code[off..][0..4], .little);
            const d = arm64_isa.decode(insn);
            const next = pc + 4;

            if (d.target_delta) |delta| {
                const t = @as(i64, pc) + delta;
                if (d.class != .bl) {
                    try recordSafeBlock(allocator, &seen, &blocks, code, base_rva, func_begin_rva, func_end_rva, excl_zones, skip_landing_pads, t);
                    if (t >= @as(i64, func_begin_rva) and t < @as(i64, func_end_rva)) {
                        const t_u32: u32 = @intCast(t);
                        if (!visited.contains(t_u32)) {
                            try work.append(allocator, t_u32);
                        }
                    }
                }
                if (!d.falls_through or d.is_terminator) break;
                if (d.class != .bl) {
                    try recordSafeBlock(allocator, &seen, &blocks, code, base_rva, func_begin_rva, func_end_rva, excl_zones, skip_landing_pads, next);
                }
                pc = next;
                continue;
            }

            if (d.is_terminator or !d.falls_through) break;
            pc = next;
        }
    }

    return blocks.toOwnedSlice(allocator);
}

/// Default AArch64 basic-block decoder (recursive descent, exclusive-monitor safe).
pub fn decodeArm64BasicBlocks(
    allocator: std.mem.Allocator,
    code: []const u8,
    base_rva: u32,
    func_begin_rva: u32,
    func_end_rva: u32,
) ![]BasicBlock {
    return decodeArm64BasicBlocksEx(allocator, code, base_rva, func_begin_rva, func_end_rva, false);
}

/// BTI- and PAC-safe AArch64 basic-block decoder (`--bti-safe` mode).
pub fn decodeArm64BasicBlocksBtiSafe(
    allocator: std.mem.Allocator,
    code: []const u8,
    base_rva: u32,
    func_begin_rva: u32,
    func_end_rva: u32,
) ![]BasicBlock {
    return decodeArm64BasicBlocksEx(allocator, code, base_rva, func_begin_rva, func_end_rva, true);
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
    var imm: usize = 0;
    var flow: Flow = .seq;
    var rel_size: usize = 0;
    var group3 = false;
    var group5 = false;
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
            0x0B => flow = .term,
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
                if (i + 4 > code.len) return null;
                const map = code[i] & 0x03;
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
                has_modrm = !(map == 1 and vop == 0x77);
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
            0xE8 => imm = 4,
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
                0, 1, 2, 3, 6 => {},
                4, 5 => flow = .term,
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

/// Recursive-descent x86_64 basic-block discovery.
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

pub fn decodeX64BasicBlocks(
    allocator: std.mem.Allocator,
    code: []const u8,
    base_rva: u32,
    func_begin_rva: u32,
    func_end_rva: u32,
) ![]BasicBlock {
    return decodeX64BasicBlocksEx(allocator, code, base_rva, func_begin_rva, func_end_rva, false);
}

pub fn decodeX64BasicBlocksFull(
    allocator: std.mem.Allocator,
    code: []const u8,
    base_rva: u32,
    func_begin_rva: u32,
    func_end_rva: u32,
) ![]BasicBlock {
    return decodeX64BasicBlocksEx(allocator, code, base_rva, func_begin_rva, func_end_rva, true);
}

/// Parse a PE32+, ELF64, or Mach-O 64 image and decode basic blocks via recursive descent
/// for every recovered function (`.pdata`, `.symtab`/`.dynsym`, or `LC_FUNCTION_STARTS`).
pub fn decodeAllTextBasicBlocksEx(
    allocator: std.mem.Allocator,
    raw_bytes: []const u8,
    bti_safe: bool,
) ![]BasicBlock {
    const bytes = macho.unwrapFatSlice(raw_bytes);
    var img = try binary.parseBinary(allocator, bytes);
    defer img.deinit();

    const text = img.findCodeSection() orelse return error.NoTextSection;
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

    // Fallback to exported symbols or full text span if a stripped ELF/Mach-O has no function table.
    var fallback_fns: [1]pe.RuntimeFunction = undefined;
    const fn_slice: []const pe.RuntimeFunction = if (img.functions.len > 0)
        img.functions
    else blk: {
        fallback_fns[0] = .{ .begin_rva = text_begin, .end_rva = text_end, .unwind_rva = 0 };
        break :blk &fallback_fns;
    };

    for (fn_slice) |f| {
        if (f.end_rva <= f.begin_rva) continue;
        if (f.begin_rva < text_begin or f.end_rva > text_end) continue;
        const bbs = switch (img.machine) {
            .arm64, .arm64ec => try decodeArm64BasicBlocksEx(allocator, code, text_begin, f.begin_rva, f.end_rva, bti_safe),
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

pub fn decodeAllTextBasicBlocks(allocator: std.mem.Allocator, bytes: []const u8) ![]BasicBlock {
    return decodeAllTextBasicBlocksEx(allocator, bytes, false);
}

fn expectLen(expected: u8, bytes: []const u8) !void {
    const insn = decodeX64Insn(bytes) orelse return error.Undecodable;
    try std.testing.expectEqual(expected, insn.len);
}

test "arm64 recursive-descent skips dead literal pool after ret and protects exclusive zones" {
    const alloc = std.testing.allocator;
    // 0x1000: bti c        (D503245F)
    // 0x1004: cbz w0, +8   -> 0x100C (34000040)
    // 0x1008: ret          (D65F03C0)
    // 0x100C: ldxr w1,[x0] (885F7C01)
    // 0x1010: stxr w2,w1,[x0] (88027C01)
    // 0x1014: ret          (D65F03C0)
    // 0x1018: literal pool fake B instruction (0x14000001) - must NOT be decoded!
    const code = [_]u8{
        0x5F, 0x24, 0x03, 0xD5, // 0x1000: bti c
        0x40, 0x00, 0x00, 0x34, // 0x1004: cbz w0, +8 -> 0x100C
        0xC0, 0x03, 0x5F, 0xD6, // 0x1008: ret
        0x01, 0x7C, 0x5F, 0x88, // 0x100C: ldxr
        0x01, 0x7C, 0x02, 0x88, // 0x1010: stxr
        0xC0, 0x03, 0x5F, 0xD6, // 0x1014: ret
        0x01, 0x00, 0x00, 0x14, // 0x1018: dead literal
    };

    const bbs = try decodeArm64BasicBlocksEx(alloc, &code, 0x1000, 0x1000, 0x101C, true);
    defer alloc.free(bbs);
    // Entry 0x1000 steps over BTI -> 0x1004, fallthrough -> 0x1008, cbz target -> 0x100C; dead 0x1018 ignored.
    try std.testing.expectEqual(@as(usize, 3), bbs.len);
    try std.testing.expectEqual(@as(u32, 0x1004), bbs[0].rva);
    try std.testing.expectEqual(@as(u32, 0x100C), bbs[1].rva);
    try std.testing.expectEqual(@as(u32, 0x1008), bbs[2].rva);
}

test "x64 length decoder" {
    try expectLen(1, &.{0x90});
    try expectLen(2, &.{ 0x66, 0x90 });
    try expectLen(5, &.{ 0x48, 0x89, 0x5C, 0x24, 0x08 });
    try expectLen(4, &.{ 0x48, 0x83, 0xEC, 0x28 });
    try expectLen(5, &.{ 0xE8, 0, 0, 0, 0 });
    try expectLen(5, &.{ 0x0F, 0x1F, 0x44, 0x00, 0x00 });
    try expectLen(9, &.{ 0x66, 0x0F, 0x1F, 0x84, 0, 0, 0, 0, 0 });
    try expectLen(10, &.{ 0x48, 0xB8, 1, 2, 3, 4, 5, 6, 7, 8 });
    try expectLen(5, &.{ 0xB8, 1, 0, 0, 0 });
    try expectLen(4, &.{ 0x66, 0xB8, 0x34, 0x12 });
    try expectLen(6, &.{ 0x8B, 0x05, 0, 0, 0, 0 });
    try expectLen(7, &.{ 0xC7, 0x45, 0xFC, 1, 0, 0, 0 });
    try expectLen(6, &.{ 0xF7, 0xC1, 1, 0, 0, 0 });
    try expectLen(2, &.{ 0xF7, 0xD9 });
    try expectLen(3, &.{ 0xF6, 0xC1, 0x01 });
    try expectLen(6, &.{ 0x0F, 0x84, 0, 0, 0, 0 });
    try expectLen(6, &.{ 0xFF, 0x15, 0, 0, 0, 0 });
    try expectLen(4, &.{ 0x4C, 0x8D, 0x0C, 0x40 });
    try expectLen(4, &.{ 0x0F, 0xBA, 0xE0, 0x05 });
    try expectLen(8, &.{ 0x48, 0x8B, 0x04, 0x25, 0, 0, 0, 0 });
    try expectLen(4, &.{ 0xF3, 0x0F, 0x1E, 0xFA });
    try expectLen(2, &.{ 0x0F, 0x05 });
    try expectLen(5, &.{ 0x66, 0x0F, 0x38, 0x00, 0xC1 });
    try expectLen(6, &.{ 0x66, 0x0F, 0x3A, 0x0F, 0xC1, 0x04 });
    try expectLen(3, &.{ 0xC5, 0xF8, 0x77 });
    try expectLen(5, &.{ 0xC5, 0xF9, 0x70, 0xC0, 0x1B });
    try expectLen(5, &.{ 0xC4, 0xE2, 0x7D, 0x58, 0xC0 });
    try expectLen(9, &.{ 0xA1, 1, 2, 3, 4, 5, 6, 7, 8 });
    try std.testing.expect(decodeX64Insn(&.{0x06}) == null);
    try std.testing.expect(decodeX64Insn(&.{ 0xE8, 0, 0 }) == null);
}

test "x64 basic blocks: targets, fall-throughs, no decoding of dead data" {
    const alloc = std.testing.allocator;
    const code = [_]u8{
        0x31, 0xC0,
        0x83, 0xF8, 0x05,
        0x7D, 0x04,
        0xFF, 0xC0,
        0xEB, 0xF7,
        0xC3,
        0xE9, 0xFF, 0xFF, 0xFF, 0x7F,
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
    const path = "C:\\Windows\\System32\\kernel32.dll";
    const io = std.testing.io;
    const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, alloc, .limited(64 * 1024 * 1024)) catch return error.SkipZigTest;
    defer alloc.free(bytes);
    const bbs = decodeAllTextBasicBlocks(alloc, bytes) catch return error.SkipZigTest;
    defer alloc.free(bbs);
    try std.testing.expect(bbs.len > 1000);
}
