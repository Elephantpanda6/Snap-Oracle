const std = @import("std");
const mutator = @import("mutator.zig");
const binary = @import("binary.zig");
const pe = @import("pe.zig");
const arm64_isa = @import("arm64_isa.zig");

fn isPrintableAscii(b: u8) bool {
    return b >= 0x20 and b <= 0x7E;
}

/// Scan read-only data sections (`.rdata`, `.rodata`, `__cstring`, `__const`) for ASCII magic
/// tokens of length `2..16`.
pub fn extractFromReadOnlyData(slice: []const u8, dict: *mutator.Dictionary) usize {
    var added: usize = 0;
    var i: usize = 0;
    while (i < slice.len) {
        if (!isPrintableAscii(slice[i])) {
            i += 1;
            continue;
        }
        var j = i;
        while (j < slice.len and isPrintableAscii(slice[j]) and (j - i) < 16) : (j += 1) {}
        const len = j - i;
        if (len >= 2 and len <= 16) {
            if (dict.add(slice[i..j])) added += 1;
        }
        i = if (j < slice.len and isPrintableAscii(slice[j])) j else j + 1;
    }
    return added;
}

fn addIntToken(dict: *mutator.Dictionary, val: u64, byte_len: usize) usize {
    if (byte_len < 2 or byte_len > 8) return 0;
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, val, .little);
    return if (dict.add(buf[0..byte_len])) 1 else 0;
}

fn allPrintableAscii(b: []const u8) bool {
    for (b) |c| {
        if (c < 0x21 or c > 0x7E) return false;
    }
    return true;
}

/// Extract 4-byte ASCII magic immediates from x86_64 instructions (`cmp`/`mov` imm32).
pub fn extractX64Immediates(code: []const u8, dict: *mutator.Dictionary) usize {
    const cfg = @import("cfg.zig");
    var added: usize = 0;
    var off: usize = 0;
    while (off < code.len) {
        const insn = cfg.decodeX64Insn(code[off..]) orelse {
            off += 1;
            continue;
        };
        if (insn.len >= 5 and off + insn.len <= code.len) {
            const tail4 = code[off + insn.len - 4 .. off + insn.len];
            if (allPrintableAscii(tail4)) {
                if (dict.add(tail4)) added += 1;
            }
        }
        off += @max(insn.len, 1);
    }
    return added;
}

/// Extract magic integers directly from ARM64 instruction streams (`MOVZ`/`MOVK` chains and `CMP` immediates).
/// Because ARM64 compilers frequently synthesize 2-byte/4-byte magic values like `"SN"`, `"BOOM"`, or `"GGUF"`
/// in registers with `MOVZ`+`MOVK` instead of `.rdata` pools, scanning A64 instructions recovers tokens
/// that pure `.rdata` scraping misses.
pub fn extractArm64Immediates(code: []const u8, dict: *mutator.Dictionary) usize {
    var added: usize = 0;
    var reg_vals: [32]u64 = @splat(0);
    var reg_valid: [32]bool = @splat(false);

    var off: usize = 0;
    while (off + 4 <= code.len) : (off += 4) {
        const insn = std.mem.readInt(u32, code[off..][0..4], .little);
        const d = arm64_isa.decode(insn);
        switch (d.class) {
            .mov_wide => {
                const opc = (insn >> 29) & 0x3;
                if (opc == 2) {
                    // MOVZ: clears other lanes and sets 16-bit lane at `shift`.
                    const v = d.imm << d.shift;
                    reg_vals[d.rd] = v;
                    reg_valid[d.rd] = true;
                    if (d.imm > 0xFF and d.shift == 0) {
                        added += addIntToken(dict, d.imm, 2);
                    }
                } else if (opc == 3 and reg_valid[d.rd]) {
                    // MOVK: merges 16-bit lane into active register value (handles both lo->hi and hi->lo order).
                    const mask = ~(@as(u64, 0xFFFF) << d.shift);
                    const v = (reg_vals[d.rd] & mask) | (d.imm << d.shift);
                    reg_vals[d.rd] = v;
                    if ((d.shift == 16 or d.shift == 0) and v > 0xFFFF and v <= std.math.maxInt(u32)) {
                        added += addIntToken(dict, v, 4);
                    } else if (d.shift == 48) {
                        added += addIntToken(dict, v, 8);
                    }
                } else {
                    reg_valid[d.rd] = false;
                }
            },
            .cmp_imm => {
                if (d.imm >= 0x100 and d.imm <= 0xFFFF) {
                    added += addIntToken(dict, d.imm, 2);
                }
            },
            .bl, .b, .ret, .retaa, .retab => {
                @memset(&reg_valid, false);
            },
            else => {},
        }
    }
    return added;
}

/// Extract fuzzing dictionary tokens from a PE32+, ELF64, or Mach-O binary (`bytes`).
pub fn extractFromBinary(allocator: std.mem.Allocator, bytes: []const u8, dict: *mutator.Dictionary) !usize {
    var img = try binary.parseBinary(allocator, bytes);
    defer img.deinit();

    var added: usize = 0;

    // 1. Read-only data sections (.rdata, .rodata, __cstring, __const)
    for (img.sections) |sec| {
        const name = sec.nameSlice();
        const is_ro = std.mem.eql(u8, name, ".rdata") or
            std.mem.eql(u8, name, ".rodata") or
            std.mem.eql(u8, name, "__cstrin") or
            std.mem.eql(u8, name, "__const") or
            ((sec.characteristics & pe.IMAGE_SCN_MEM_WRITE) == 0 and
                (sec.characteristics & pe.IMAGE_SCN_MEM_EXECUTE) == 0 and
                (sec.characteristics & pe.IMAGE_SCN_MEM_READ) != 0);
        if (!is_ro or sec.raw_offset >= bytes.len or sec.raw_size == 0) continue;
        const avail = @min(@as(usize, sec.raw_size), bytes.len - sec.raw_offset);
        added += extractFromReadOnlyData(bytes[sec.raw_offset .. sec.raw_offset + avail], dict);
    }

    // 2. Immediate constant recovery from executable code section (ARM64-first, plus x64 fallback)
    if (img.findCodeSection()) |text| {
        if (text.raw_offset < bytes.len and text.raw_size > 0) {
            const avail = @min(@as(usize, text.raw_size), bytes.len - text.raw_offset);
            const code = bytes[text.raw_offset .. text.raw_offset + avail];
            if (img.isArm64()) {
                added += extractArm64Immediates(code, dict);
            } else if (img.machine == .amd64) {
                added += extractX64Immediates(code, dict);
            }
        }
    }

    return added;
}

test "dict_extract recovers ASCII tokens and ARM64 MOVZ+MOVK 32-bit magic" {
    var dict = mutator.Dictionary.init();
    const rdata = "\x00\x00BOOM\x00\x00\x00GGUF\x00";
    const c1 = extractFromReadOnlyData(rdata, &dict);
    try std.testing.expectEqual(@as(usize, 2), c1);
    try std.testing.expectEqualStrings("BOOM", dict.sliceAt(0));
    try std.testing.expectEqualStrings("GGUF", dict.sliceAt(1));

    // ARM64: movz w1, #0x4E53 ("SN"); movk w1, #0x4241, lsl #16 ("AB") -> "SNAB"
    const arm_code = [_]u8{
        0x61, 0xCA, 0x89, 0x52, // movz w1, #0x4e53
        0x21, 0x48, 0xA8, 0x72, // movk w1, #0x4241, lsl #16
    };
    const c2 = extractArm64Immediates(&arm_code, &dict);
    try std.testing.expect(c2 >= 2);
    var found_sn = false;
    var found_snab = false;
    for (0..dict.count) |idx| {
        const s = dict.sliceAt(idx);
        if (std.mem.eql(u8, s, "SN")) found_sn = true;
        if (std.mem.eql(u8, s, "SNAB")) found_snab = true;
    }
    try std.testing.expect(found_sn);
    try std.testing.expect(found_snab);
}
