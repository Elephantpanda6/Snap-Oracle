const std = @import("std");

pub const InsnClass = enum {
    nop,
    b,
    bl,
    b_cond,
    cbz,
    cbnz,
    tbz,
    tbnz,
    ret,
    retaa,
    retab,
    br,
    blr,
    braa,
    blraa,
    eret,
    bti,
    pac_sign,
    pac_auth,
    xpac,
    brk,
    hlt,
    svc,
    udf,
    ldxr,
    stxr,
    clrex,
    lse_atomic,
    rcpc_atomic,
    barrier,
    mov_wide,
    cmp_imm,
    add_sub_imm,
    adr,
    adrp,
    ldr_lit,
    neon_simd,
    sve,
    sme,
    fp_scalar,
    other,
};

pub const DecodedArm64 = struct {
    raw: u32,
    class: InsnClass,
    target_delta: ?i64 = null,
    falls_through: bool = true,
    is_terminator: bool = false,
    rd: u5 = 0,
    rn: u5 = 0,
    imm: u64 = 0,
    shift: u6 = 0,
    cond: u4 = 0,
};

pub const ExclusiveZone = struct {
    start_rva: u32,
    end_rva: u32,
};

pub fn signExtend(val: u32, bits: u5) i64 {
    const shift: u6 = @intCast(64 - @as(u7, bits));
    return @as(i64, @bitCast(@as(u64, val) << shift)) >> shift;
}

/// Decode a single 32-bit little-endian A64 instruction word for CFG recovery, hardening audit,
/// exclusive-monitor hazard avoidance, and immediate constant extraction.
pub fn decode(insn: u32) DecodedArm64 {
    if (insn == 0xD503_201F) {
        return .{ .raw = insn, .class = .nop };
    }

    // BTI hints: `0xD503241F` (`bti`), `0xD503245F` (`bti c`), `0xD503249F` (`bti j`), `0xD50324DF` (`bti jc`)
    if ((insn & 0xFFFF_FF3F) == 0xD503_241F and (insn & 0x0000_00C0) != 0) {
        return .{ .raw = insn, .class = .bti };
    }

    // Pointer Authentication prologue/epilogue hint & general instructions
    switch (insn) {
        0xD503_233F, // paciasp
        0xD503_237F, // pacibsp
        0xD503_211F, // pacia1716
        0xD503_215F, // pacib1716
        0xD503_219F, // paciaz
        0xD503_21DF, // pacibz
        => return .{ .raw = insn, .class = .pac_sign },

        0xD503_23BF, // autiasp
        0xD503_23FF, // autibsp
        0xD503_213F, // autia1716
        0xD503_217F, // autib1716
        0xD503_21BF, // autiaz
        0xD503_21FF, // autibz
        => return .{ .raw = insn, .class = .pac_auth },

        0xD65F_0BFF => return .{ .raw = insn, .class = .retaa, .falls_through = false, .is_terminator = true },
        0xD65F_0FFF => return .{ .raw = insn, .class = .retab, .falls_through = false, .is_terminator = true },
        0xD69F_03E0 => return .{ .raw = insn, .class = .eret, .falls_through = false, .is_terminator = true },
        else => {},
    }

    // XPACI / XPACD / XPACLRI
    if ((insn & 0xFFFF_FBFF) == 0xDAC1_43E0 or insn == 0xD503_20FF) {
        return .{ .raw = insn, .class = .xpac, .rd = @truncate(insn & 0x1F) };
    }

    // Non-hint PAC instructions (PACIA/PACIB/AUTIA/AUTIB)
    if ((insn & 0xFFFF_F000) == 0xDAC1_0000) {
        const op2 = (insn >> 10) & 0x7;
        return .{
            .raw = insn,
            .class = if (op2 <= 3) .pac_sign else .pac_auth,
            .rd = @truncate(insn & 0x1F),
            .rn = @truncate((insn >> 5) & 0x1F),
        };
    }

    // Unconditional branch to register / RET / BR / BLR / authenticated variants
    if ((insn & 0xFFFF_FC1F) == 0xD65F_0000) {
        return .{ .raw = insn, .class = .ret, .rn = @truncate((insn >> 5) & 0x1F), .falls_through = false, .is_terminator = true };
    }
    if ((insn & 0xFFFF_FC1F) == 0xD61F_0000) {
        return .{ .raw = insn, .class = .br, .rn = @truncate((insn >> 5) & 0x1F), .falls_through = false, .is_terminator = true };
    }
    if ((insn & 0xFFFF_FC1F) == 0xD63F_0000) {
        return .{ .raw = insn, .class = .blr, .rn = @truncate((insn >> 5) & 0x1F), .falls_through = true };
    }
    if ((insn & 0xFEFF_F800) == 0xD71F_0000 or (insn & 0xFFFF_F81F) == 0xD61F_081F) {
        return .{ .raw = insn, .class = .braa, .rn = @truncate((insn >> 5) & 0x1F), .falls_through = false, .is_terminator = true };
    }
    if ((insn & 0xFEFF_F800) == 0xD73F_0000 or (insn & 0xFFFF_F81F) == 0xD63F_081F) {
        return .{ .raw = insn, .class = .blraa, .rn = @truncate((insn >> 5) & 0x1F), .falls_through = true };
    }

    // Exception generation & permanent undefined (UDF)
    if ((insn & 0xFFE0_001F) == 0xD420_0000) {
        return .{ .raw = insn, .class = .brk, .imm = (insn >> 5) & 0xFFFF, .falls_through = false, .is_terminator = true };
    }
    if ((insn & 0xFFE0_001F) == 0xD440_0000) {
        return .{ .raw = insn, .class = .hlt, .imm = (insn >> 5) & 0xFFFF, .falls_through = false, .is_terminator = true };
    }
    if ((insn & 0xFFE0_001F) == 0xD400_0001) {
        return .{ .raw = insn, .class = .svc, .imm = (insn >> 5) & 0xFFFF };
    }
    if ((insn & 0xFFFF_0000) == 0x0000_0000) {
        return .{ .raw = insn, .class = .udf, .imm = insn & 0xFFFF, .falls_through = false, .is_terminator = true };
    }

    // Direct unconditional & call branches: B (imm26) / BL (imm26)
    if ((insn & 0xFC00_0000) == 0x1400_0000) {
        const imm26 = insn & 0x03FF_FFFF;
        return .{
            .raw = insn,
            .class = .b,
            .target_delta = signExtend(imm26, 26) * 4,
            .falls_through = false,
            .is_terminator = true,
        };
    }
    if ((insn & 0xFC00_0000) == 0x9400_0000) {
        const imm26 = insn & 0x03FF_FFFF;
        return .{
            .raw = insn,
            .class = .bl,
            .target_delta = signExtend(imm26, 26) * 4,
            .falls_through = true,
        };
    }

    // Conditional branch B.cond (imm19)
    if ((insn & 0xFF00_0010) == 0x5400_0000) {
        const imm19 = (insn >> 5) & 0x7FFFF;
        return .{
            .raw = insn,
            .class = .b_cond,
            .target_delta = signExtend(imm19, 19) * 4,
            .cond = @truncate(insn & 0xF),
        };
    }

    // CBZ / CBNZ (imm19)
    if ((insn & 0x7E00_0000) == 0x3400_0000) {
        const imm19 = (insn >> 5) & 0x7FFFF;
        const is_nz = (insn & 0x0100_0000) != 0;
        return .{
            .raw = insn,
            .class = if (is_nz) .cbnz else .cbz,
            .target_delta = signExtend(imm19, 19) * 4,
            .rd = @truncate(insn & 0x1F),
        };
    }

    // TBZ / TBNZ (imm14)
    if ((insn & 0x7E00_0000) == 0x3600_0000) {
        const imm14 = (insn >> 5) & 0x3FFF;
        const is_nz = (insn & 0x0100_0000) != 0;
        return .{
            .raw = insn,
            .class = if (is_nz) .tbnz else .tbz,
            .target_delta = signExtend(imm14, 14) * 4,
            .rd = @truncate(insn & 0x1F),
        };
    }

    // Barriers & CLREX
    if ((insn & 0xFFFF_F0FF) == 0xD503_305F) {
        return .{ .raw = insn, .class = .clrex };
    }
    if ((insn & 0xFFFF_F01F) == 0xD503_301F) {
        const crm = (insn >> 8) & 0xF;
        const op2 = (insn >> 5) & 0x7;
        if (op2 == 4 or op2 == 5 or op2 == 6) {
            return .{ .raw = insn, .class = .barrier, .imm = crm };
        }
    }

    // Load/Store Exclusive monitor (LDXR/LDAXR/LDXP/STXR/STLXR/STXP) - must never trap between LDXR..STXR
    // Load/store exclusive group has op0=x0, op1=0, op2=0, bit24=0 (`(insn & 0x3F00_0000) == 0x0800_0000`)
    if ((insn & 0x3F00_0000) == 0x0800_0000) {
        const is_lse_cas = (insn & 0x00A0_0000) == 0x00A0_0000;
        if (is_lse_cas) {
            return .{ .raw = insn, .class = .lse_atomic, .rd = @truncate(insn & 0x1F) };
        }
        const is_load = (insn & 0x0040_0000) != 0;
        return .{
            .raw = insn,
            .class = if (is_load) .ldxr else .stxr,
            .rd = @truncate(insn & 0x1F),
            .rn = @truncate((insn >> 5) & 0x1F),
        };
    }

    // LSE atomics (LDADD/LDCLR/LDEOR/LDSET/SWP/LDMAX/LDMIN/CASP): op0=x11, op1=1, bit21=1, bits[11:10]=00
    if ((insn & 0x3B20_0C00) == 0x3820_0000) {
        return .{ .raw = insn, .class = .lse_atomic, .rd = @truncate(insn & 0x1F) };
    }

    // RCPC load-acquire (LDAPUR / LDAPR): `(insn & 0x3FA0_0C00) == 0x1900_0000` or `0x38BF_C000`
    if ((insn & 0x3FE0_FC00) == 0x38BF_C000 or (insn & 0x3FA0_0C00) == 0x1940_0000) {
        return .{ .raw = insn, .class = .rcpc_atomic, .rd = @truncate(insn & 0x1F) };
    }

    // Move wide immediate: MOVN (opc=00), MOVZ (opc=10), MOVK (opc=11)
    if ((insn & 0x1F80_0000) == 0x1280_0000) {
        const opc = (insn >> 29) & 0x3;
        if (opc != 1) {
            const hw: u6 = @intCast(((insn >> 21) & 0x3) * 16);
            return .{
                .raw = insn,
                .class = .mov_wide,
                .rd = @truncate(insn & 0x1F),
                .imm = (insn >> 5) & 0xFFFF,
                .shift = hw,
            };
        }
    }

    // CMP (immediate) = SUBS Wzr/Xzr, Rn, #imm12{, LSL #12}
    if ((insn & 0x7F80_001F) == 0x7100_001F) {
        const sh: u6 = if (((insn >> 22) & 1) != 0) 12 else 0;
        const imm12: u64 = (insn >> 10) & 0xFFF;
        return .{
            .raw = insn,
            .class = .cmp_imm,
            .rn = @truncate((insn >> 5) & 0x1F),
            .imm = imm12 << sh,
            .shift = sh,
        };
    }

    // ADD/SUB immediate (non-zr)
    if ((insn & 0x1F00_0000) == 0x1100_0000) {
        const sh: u6 = if (((insn >> 22) & 1) != 0) 12 else 0;
        const imm12: u64 = (insn >> 10) & 0xFFF;
        return .{
            .raw = insn,
            .class = .add_sub_imm,
            .rd = @truncate(insn & 0x1F),
            .rn = @truncate((insn >> 5) & 0x1F),
            .imm = imm12 << sh,
            .shift = sh,
        };
    }

    // ADR / ADRP
    if ((insn & 0x1F00_0000) == 0x1000_0000) {
        return .{
            .raw = insn,
            .class = if ((insn & 0x8000_0000) != 0) .adrp else .adr,
            .rd = @truncate(insn & 0x1F),
        };
    }

    // PC-relative literal load
    if ((insn & 0x3B00_0000) == 0x1800_0000) {
        return .{ .raw = insn, .class = .ldr_lit, .rd = @truncate(insn & 0x1F) };
    }

    // SVE (`op0` bits [28:25] == 0010 -> `0x0400_0000`)
    if ((insn & 0x1E00_0000) == 0x0400_0000) {
        return .{ .raw = insn, .class = .sve };
    }

    // SME (`op0` bits [31:25] == 1000000 / 1100000 family: 0x8000_0000 .. outer product)
    if ((insn & 0xDF00_0000) == 0x8000_0000 or (insn & 0xFFE0_0000) == 0xC080_0000) {
        return .{ .raw = insn, .class = .sme };
    }

    // Advanced SIMD (NEON) & Scalar FP (`op0` bits [27:25] == 111 -> `0x0E00_0000` / `0x1E00_0000`)
    if ((insn & 0x1E00_0000) == 0x0E00_0000) {
        return .{ .raw = insn, .class = .neon_simd };
    }
    if ((insn & 0x5F00_0000) == 0x1E00_0000) {
        return .{ .raw = insn, .class = .fp_scalar };
    }

    return .{ .raw = insn, .class = .other };
}

/// Returns true if an instruction is an indirect-branch landing pad (`BTI`) or PAC prologue sign
/// (`PACIASP` / `PACIBSP`) that a coverage trap should step over when `--bti-safe` is enabled.
pub fn isLandingPadOrPrologue(insn: u32) bool {
    const d = decode(insn);
    return d.class == .bti or d.class == .pac_sign;
}

/// Locate `[ldxr .. stxr/clrex]` exclusive monitor windows so one-shot breakpoints never trigger
/// an exception inside an LL/SC loop (which clears the CPU exclusive monitor and creates livelock).
pub fn findExclusiveZones(allocator: std.mem.Allocator, code: []const u8, base_rva: u32) ![]ExclusiveZone {
    var zones = std.ArrayList(ExclusiveZone).empty;
    errdefer zones.deinit(allocator);

    var off: usize = 0;
    while (off + 4 <= code.len) : (off += 4) {
        const insn = std.mem.readInt(u32, code[off..][0..4], .little);
        if (decode(insn).class == .ldxr) {
            const start_rva = base_rva + @as(u32, @intCast(off));
            var end_rva: u32 = start_rva + 4;
            // Scan up to 16 instructions forward for matching STXR/STLXR or CLREX.
            var k: usize = off + 4;
            const limit = @min(code.len, off + 64);
            while (k + 4 <= limit) : (k += 4) {
                const next_insn = std.mem.readInt(u32, code[k..][0..4], .little);
                const cls = decode(next_insn).class;
                if (cls == .stxr or cls == .clrex) {
                    end_rva = base_rva + @as(u32, @intCast(k)) + 4;
                    break;
                }
            }
            if (end_rva > start_rva + 4) {
                try zones.append(allocator, .{ .start_rva = start_rva, .end_rva = end_rva });
                off = @as(usize, end_rva - base_rva) - 4;
            }
        }
    }

    return zones.toOwnedSlice(allocator);
}

/// Returns true if `rva` lies strictly inside an exclusive-monitor `[ldxr+4, stxr_end)` window
/// where trapping would invalidate the exclusive monitor.
pub fn isRvaInExclusiveZone(zones: []const ExclusiveZone, rva: u32) bool {
    for (zones) |z| {
        if (rva > z.start_rva and rva < z.end_rva) return true;
    }
    return false;
}

test "arm64_isa decodes branches, BTI, PAC, LSE, NEON, MOVZ/CMP" {
    try std.testing.expectEqual(InsnClass.nop, decode(0xD503_201F).class);
    try std.testing.expectEqual(InsnClass.bti, decode(0xD503_245F).class); // bti c
    try std.testing.expectEqual(InsnClass.pac_sign, decode(0xD503_233F).class); // paciasp
    try std.testing.expectEqual(InsnClass.pac_auth, decode(0xD503_23BF).class); // autiasp
    try std.testing.expectEqual(InsnClass.ret, decode(0xD65F_03C0).class);
    try std.testing.expectEqual(InsnClass.retaa, decode(0xD65F_0BFF).class);
    try std.testing.expectEqual(InsnClass.br, decode(0xD61F_0100).class); // br x8

    const beq = decode(0x5400_0040); // b.eq +8
    try std.testing.expectEqual(InsnClass.b_cond, beq.class);
    try std.testing.expectEqual(@as(?i64, 8), beq.target_delta);

    const b_back = decode(0x17FF_FFFF); // b -4
    try std.testing.expectEqual(InsnClass.b, b_back.class);
    try std.testing.expectEqual(@as(?i64, -4), b_back.target_delta);
    try std.testing.expect(!b_back.falls_through);

    // cmp w1, #0x42 -> 0x7101083F (imm12=0x42)
    const cmp = decode(0x7101_083F);
    try std.testing.expectEqual(InsnClass.cmp_imm, cmp.class);
    try std.testing.expectEqual(@as(u64, 0x42), cmp.imm);

    // movz w0, #0x4E53 -> 0x5289CA60
    const movz = decode(0x5289_CA60);
    try std.testing.expectEqual(InsnClass.mov_wide, movz.class);
    try std.testing.expectEqual(@as(u5, 0), movz.rd);
    try std.testing.expectEqual(@as(u64, 0x4E53), movz.imm);

    // LSE LDADDAL w0, w1, [x2] -> 0xB8E00041
    try std.testing.expectEqual(InsnClass.lse_atomic, decode(0xB8E0_0041).class);
}

test "arm64_isa detects exclusive LDXR..STXR monitor zones" {
    const code = [_]u8{
        0x1F, 0x20, 0x03, 0xD5, // 0x1000: nop
        0x00, 0x7C, 0x5F, 0x88, // 0x1004: ldxr w0, [x0] (0x885F7C00)
        0x00, 0x04, 0x00, 0x11, // 0x1008: add w0, w0, #1
        0x20, 0x7C, 0x01, 0x88, // 0x100C: stxr w1, w0, [x1] (0x88017C20)
        0xC0, 0x03, 0x5F, 0xD6, // 0x1010: ret
    };
    const zones = try findExclusiveZones(std.testing.allocator, &code, 0x1000);
    defer std.testing.allocator.free(zones);
    try std.testing.expectEqual(@as(usize, 1), zones.len);
    try std.testing.expectEqual(@as(u32, 0x1004), zones[0].start_rva);
    try std.testing.expectEqual(@as(u32, 0x1010), zones[0].end_rva);
    try std.testing.expect(!isRvaInExclusiveZone(zones, 0x1004));
    try std.testing.expect(isRvaInExclusiveZone(zones, 0x1008));
    try std.testing.expect(isRvaInExclusiveZone(zones, 0x100C));
    try std.testing.expect(!isRvaInExclusiveZone(zones, 0x1010));
}
