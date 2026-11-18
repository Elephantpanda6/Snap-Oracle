const std = @import("std");
const pe = @import("pe.zig");

const MH_MAGIC_64: u32 = 0xFEED_FACF;
const CPU_TYPE_ARM64: u32 = 0x0100_000C;
const CPU_TYPE_X86_64: u32 = 0x0100_0007;
const CPU_SUBTYPE_ARM64E: u32 = 2;

const LC_SYMTAB: u32 = 0x02;
const LC_SEGMENT_64: u32 = 0x19;
const LC_FUNCTION_STARTS: u32 = 0x26;

pub const MachoImage = struct {
    machine: pe.Machine,
    image_base: u64,
    entry_rva: u32,
    size_of_image: u32,
    has_pac: bool,
    sections: []pe.Section,
    functions: []pe.RuntimeFunction,
    exports: []pe.ExportSymbol,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *MachoImage) void {
        for (self.exports) |exp| {
            self.allocator.free(exp.name);
        }
        self.allocator.free(self.sections);
        self.allocator.free(self.functions);
        self.allocator.free(self.exports);
    }
};

fn readU32(b: []const u8, off: usize) !u32 {
    if (off + 4 > b.len) return error.UnexpectedEof;
    return std.mem.readInt(u32, b[off..][0..4], .little);
}

fn readU64(b: []const u8, off: usize) !u64 {
    if (off + 8 > b.len) return error.UnexpectedEof;
    return std.mem.readInt(u64, b[off..][0..8], .little);
}

fn readUleb128(b: []const u8, pos: *usize) ?u64 {
    var result: u64 = 0;
    var shift: u6 = 0;
    while (pos.* < b.len) {
        const byte = b[pos.*];
        pos.* += 1;
        result |= @as(u64, byte & 0x7F) << shift;
        if ((byte & 0x80) == 0) return result;
        if (shift >= 57) return null;
        shift += 7;
    }
    return null;
}

pub fn parseMachO(allocator: std.mem.Allocator, bytes: []const u8) !MachoImage {
    if (bytes.len < 32) return error.InvalidMachO;
    const magic = try readU32(bytes, 0);
    if (magic != MH_MAGIC_64) return error.InvalidMachO;

    const cputype = try readU32(bytes, 4);
    const cpusubtype = try readU32(bytes, 8);
    const ncmds = try readU32(bytes, 16);
    const sizeofcmds = try readU32(bytes, 20);
    if (32 + @as(usize, sizeofcmds) > bytes.len) return error.InvalidMachO;

    const machine: pe.Machine = switch (cputype) {
        CPU_TYPE_ARM64 => .arm64,
        CPU_TYPE_X86_64 => .amd64,
        else => @enumFromInt(@as(u16, @truncate(cputype))),
    };
    const has_pac = (cputype == CPU_TYPE_ARM64) and ((cpusubtype & 0xFF) == CPU_SUBTYPE_ARM64E);

    var sec_list = std.ArrayList(pe.Section).empty;
    errdefer sec_list.deinit(allocator);
    var fn_list = std.ArrayList(pe.RuntimeFunction).empty;
    errdefer fn_list.deinit(allocator);
    var exp_list = std.ArrayList(pe.ExportSymbol).empty;
    errdefer {
        for (exp_list.items) |e| allocator.free(e.name);
        exp_list.deinit(allocator);
    }

    var text_base_vm: u64 = 0;
    var max_vm: u64 = 0;
    var text_end_rva: u32 = 0;
    var fn_starts_off: u32 = 0;
    var fn_starts_sz: u32 = 0;

    var cmd_off: usize = 32;
    for (0..ncmds) |_| {
        if (cmd_off + 8 > bytes.len) break;
        const cmd = try readU32(bytes, cmd_off);
        const cmdsize = try readU32(bytes, cmd_off + 4);
        if (cmdsize < 8 or cmd_off + cmdsize > bytes.len) break;

        if (cmd == LC_SEGMENT_64 and cmdsize >= 72) {
            const segname = bytes[cmd_off + 8 .. cmd_off + 24];
            const vmaddr = try readU64(bytes, cmd_off + 24);
            const vmsz = try readU64(bytes, cmd_off + 32);
            const initprot = try readU32(bytes, cmd_off + 60);
            const nsects = try readU32(bytes, cmd_off + 64);

            if (std.mem.startsWith(u8, segname, "__TEXT")) {
                text_base_vm = vmaddr;
            }
            if (!std.mem.startsWith(u8, segname, "__PAGEZERO")) {
                max_vm = @max(max_vm, vmaddr +| vmsz);
            }

            var sec_off = cmd_off + 72;
            for (0..nsects) |_| {
                if (sec_off + 80 > cmd_off + cmdsize) break;
                var name8: [8]u8 = @splat(0);
                const sectname = bytes[sec_off .. sec_off + 16];
                const nlen = std.mem.indexOfScalar(u8, sectname, 0) orelse 16;
                const copy_len = @min(nlen, 8);
                @memcpy(name8[0..copy_len], sectname[0..copy_len]);

                const addr = try readU64(bytes, sec_off + 32);
                const size = try readU64(bytes, sec_off + 40);
                const offset = try readU32(bytes, sec_off + 48);
                const flags = try readU32(bytes, sec_off + 64);

                var chars: u32 = pe.IMAGE_SCN_MEM_READ;
                if ((initprot & 2) != 0 and !std.mem.startsWith(u8, segname, "__TEXT") and !std.mem.startsWith(u8, sectname, "__const")) {
                    chars |= pe.IMAGE_SCN_MEM_WRITE;
                }
                if ((flags & 0x8000_0000) != 0 or std.mem.startsWith(u8, sectname, "__text")) {
                    chars |= pe.IMAGE_SCN_MEM_EXECUTE;
                }

                const rva: u32 = if (addr >= text_base_vm)
                    @intCast(@min(addr - text_base_vm, std.math.maxInt(u32)))
                else
                    @truncate(addr);
                const sz32: u32 = @intCast(@min(size, std.math.maxInt(u32)));
                if (std.mem.startsWith(u8, sectname, "__text")) {
                    text_end_rva = rva +| sz32;
                }
                try sec_list.append(allocator, .{
                    .name = name8,
                    .virtual_size = sz32,
                    .virtual_address = rva,
                    .raw_size = if (offset > 0) sz32 else 0,
                    .raw_offset = offset,
                    .characteristics = chars,
                });
                sec_off += 80;
            }
        } else if (cmd == LC_FUNCTION_STARTS and cmdsize >= 16) {
            fn_starts_off = try readU32(bytes, cmd_off + 8);
            fn_starts_sz = try readU32(bytes, cmd_off + 12);
        } else if (cmd == LC_SYMTAB and cmdsize >= 24) {
            const symoff = try readU32(bytes, cmd_off + 8);
            const nsyms = try readU32(bytes, cmd_off + 12);
            const stroff = try readU32(bytes, cmd_off + 16);
            const strsize = try readU32(bytes, cmd_off + 20);
            if (@as(usize, stroff) +| strsize <= bytes.len and @as(usize, symoff) +| @as(usize, nsyms) *| 16 <= bytes.len) {
                for (0..nsyms) |si| {
                    const nl = @as(usize, symoff) + si * 16;
                    const strx = try readU32(bytes, nl);
                    const n_type = bytes[nl + 4];
                    const n_value = try readU64(bytes, nl + 8);
                    // External defined symbol (N_EXT=0x01, N_SECT=0x0E)
                    if ((n_type & 0x0F) == 0x0F and n_value >= text_base_vm and strx < strsize) {
                        const srest = bytes[@as(usize, stroff) + strx .. @as(usize, stroff) + strsize];
                        const nul = std.mem.indexOfScalar(u8, srest, 0) orelse srest.len;
                        if (nul > 0) {
                            const rva: u32 = @intCast(@min(n_value - text_base_vm, std.math.maxInt(u32)));
                            const dup_name = try allocator.dupe(u8, srest[0..nul]);
                            errdefer allocator.free(dup_name);
                            try exp_list.append(allocator, .{
                                .name = dup_name,
                                .rva = rva,
                                .ordinal = @truncate(exp_list.items.len),
                                .is_forwarded = false,
                            });
                        }
                    }
                }
            }
        }

        cmd_off += cmdsize;
    }

    if (fn_starts_off != 0 and fn_starts_sz != 0 and @as(usize, fn_starts_off) +| fn_starts_sz <= bytes.len) {
        const fs = bytes[fn_starts_off .. fn_starts_off + fn_starts_sz];
        var pos: usize = 0;
        var cur: u64 = 0;
        var starts = std.ArrayList(u32).empty;
        defer starts.deinit(allocator);
        while (pos < fs.len) {
            const delta = readUleb128(fs, &pos) orelse break;
            if (delta == 0) break;
            cur +|= delta;
            try starts.append(allocator, @truncate(cur));
        }
        for (starts.items, 0..) |st, idx| {
            const end_rva = if (idx + 1 < starts.items.len) starts.items[idx + 1] else @max(st +| 4, text_end_rva);
            try fn_list.append(allocator, .{
                .begin_rva = st,
                .end_rva = end_rva,
                .unwind_rva = 0,
            });
        }
    }

    const size_of_image: u32 = if (max_vm > text_base_vm)
        @intCast(@min(max_vm - text_base_vm, std.math.maxInt(u32)))
    else
        0;

    return .{
        .machine = machine,
        .image_base = text_base_vm,
        .entry_rva = if (fn_list.items.len > 0) fn_list.items[0].begin_rva else 0,
        .size_of_image = size_of_image,
        .has_pac = has_pac,
        .sections = try sec_list.toOwnedSlice(allocator),
        .functions = try fn_list.toOwnedSlice(allocator),
        .exports = try exp_list.toOwnedSlice(allocator),
        .allocator = allocator,
    };
}

test "macho_arm64 parses synthetic 64-bit arm64e Mach-O with LC_FUNCTION_STARTS" {
    var buf: [512]u8 = @splat(0);
    std.mem.writeInt(u32, buf[0..4], MH_MAGIC_64, .little);
    std.mem.writeInt(u32, buf[4..8], CPU_TYPE_ARM64, .little);
    std.mem.writeInt(u32, buf[8..12], CPU_SUBTYPE_ARM64E, .little);
    std.mem.writeInt(u32, buf[16..20], 2, .little); // ncmds = 2
    std.mem.writeInt(u32, buf[20..24], 152 + 16, .little); // sizeofcmds

    // LC_SEGMENT_64 (cmd=0x19, size=72+80=152) at offset 32
    std.mem.writeInt(u32, buf[32..36], LC_SEGMENT_64, .little);
    std.mem.writeInt(u32, buf[36..40], 152, .little);
    @memcpy(buf[40 .. 40 + 6], "__TEXT");
    std.mem.writeInt(u64, buf[56..64], 0x1_0000_0000, .little); // vmaddr
    std.mem.writeInt(u64, buf[64..72], 0x4000, .little); // vmsize
    std.mem.writeInt(u32, buf[88..92], 5, .little); // maxprot
    std.mem.writeInt(u32, buf[96..100], 1, .little); // nsects

    // section_64 "__text" at 104 (size 80)
    @memcpy(buf[104 .. 104 + 6], "__text");
    std.mem.writeInt(u64, buf[104 + 32 ..][0..8], 0x1_0000_1000, .little);
    std.mem.writeInt(u64, buf[104 + 40 ..][0..8], 0x40, .little);
    std.mem.writeInt(u32, buf[104 + 48 ..][0..4], 0x180, .little);
    std.mem.writeInt(u32, buf[104 + 64 ..][0..4], 0x8000_0400, .little);

    // LC_FUNCTION_STARTS at 184 (size 16)
    std.mem.writeInt(u32, buf[184..188], LC_FUNCTION_STARTS, .little);
    std.mem.writeInt(u32, buf[188..192], 16, .little);
    std.mem.writeInt(u32, buf[192..196], 0x1E0, .little);
    std.mem.writeInt(u32, buf[196..200], 4, .little);

    // Function starts ULEB128 at 0x1E0: 0x1000 (= 0x80 0x20), then 0
    buf[0x1E0] = 0x80;
    buf[0x1E1] = 0x20;
    buf[0x1E2] = 0x00;

    var img = try parseMachO(std.testing.allocator, &buf);
    defer img.deinit();

    try std.testing.expectEqual(pe.Machine.arm64, img.machine);
    try std.testing.expect(img.has_pac);
    try std.testing.expectEqual(@as(usize, 1), img.sections.len);
    try std.testing.expectEqual(@as(usize, 1), img.functions.len);
    try std.testing.expectEqual(@as(u32, 0x1000), img.functions[0].begin_rva);
    try std.testing.expectEqual(@as(u32, 0x1040), img.functions[0].end_rva);
}
