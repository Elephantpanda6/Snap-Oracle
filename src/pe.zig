const std = @import("std");

pub const IMAGE_SCN_MEM_SHARED: u32 = 0x1000_0000;
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

pub const Machine = enum(u16) {
    amd64 = 0x8664,
    arm64 = 0xAA64,
    arm64ec = 0xA641,
    _,
};

pub const Section = struct {
    name: [8]u8,
    virtual_size: u32,
    virtual_address: u32,
    raw_size: u32,
    raw_offset: u32,
    characteristics: u32,

    pub fn nameSlice(self: *const Section) []const u8 {
        const end = std.mem.indexOfScalar(u8, &self.name, 0) orelse self.name.len;
        return self.name[0..end];
    }

    pub fn isWritableData(self: *const Section) bool {
        return (self.characteristics & IMAGE_SCN_MEM_WRITE) != 0 and
            (self.characteristics & IMAGE_SCN_MEM_EXECUTE) == 0 and
            (self.characteristics & IMAGE_SCN_MEM_SHARED) == 0;
    }
};

pub const RuntimeFunction = struct {
    begin_rva: u32,
    end_rva: u32,
    unwind_rva: u32,
};

pub const ExportSymbol = struct {
    name: []u8,
    rva: u32,
    ordinal: u16,
    is_forwarded: bool = false,
};

pub const PeImage = struct {
    machine: Machine,
    image_base: u64,
    entry_rva: u32,
    size_of_image: u32,
    file_len: usize = std.math.maxInt(usize),
    export_dir_rva: u32,
    export_dir_size: u32,
    arm64_pac_unwind_fns: usize,
    sections: []Section,
    functions: []RuntimeFunction,
    exports: []ExportSymbol,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *PeImage) void {
        for (self.exports) |exp| {
            self.allocator.free(exp.name);
        }
        self.allocator.free(self.sections);
        self.allocator.free(self.functions);
        self.allocator.free(self.exports);
    }

    pub fn rvaToOffset(self: *const PeImage, rva: u32) ?usize {
        for (self.sections) |sec| {
            const span = @max(sec.virtual_size, sec.raw_size);
            if (rva >= sec.virtual_address and rva < sec.virtual_address +| span) {
                const delta = rva - sec.virtual_address;
                if (delta < sec.raw_size) {
                    const off = @as(usize, sec.raw_offset) +| @as(usize, delta);
                    if (off < self.file_len) return off;
                }
            }
        }
        return null;
    }

    pub fn findSection(self: *const PeImage, name: []const u8) ?Section {
        for (self.sections) |sec| {
            if (std.mem.eql(u8, sec.nameSlice(), name)) return sec;
        }
        return null;
    }

    pub fn findExport(self: *const PeImage, name: []const u8) ?u32 {
        for (self.exports) |exp| {
            if (std.mem.eql(u8, exp.name, name)) return exp.rva;
        }
        return null;
    }

    pub fn writableDataSections(self: *const PeImage, allocator: std.mem.Allocator) ![]Section {
        var list = std.ArrayList(Section).empty;
        errdefer list.deinit(allocator);
        for (self.sections) |sec| {
            if (sec.isWritableData() and sec.virtual_size > 0) {
                try list.append(allocator, sec);
            }
        }
        return list.toOwnedSlice(allocator);
    }
};

fn readU16(bytes: []const u8, off: usize) !u16 {
    if (off + 2 > bytes.len) return error.UnexpectedEof;
    return std.mem.readInt(u16, bytes[off..][0..2], .little);
}

fn readU32(bytes: []const u8, off: usize) !u32 {
    if (off + 4 > bytes.len) return error.UnexpectedEof;
    return std.mem.readInt(u32, bytes[off..][0..4], .little);
}

fn readU64(bytes: []const u8, off: usize) !u64 {
    if (off + 8 > bytes.len) return error.UnexpectedEof;
    return std.mem.readInt(u64, bytes[off..][0..8], .little);
}

pub fn parsePe(allocator: std.mem.Allocator, bytes: []const u8) !PeImage {
    if (bytes.len < 64) return error.InvalidPe;
    if (bytes[0] != 'M' or bytes[1] != 'Z') return error.InvalidPe;

    const pe_off = @as(usize, try readU32(bytes, 0x3C));
    if (pe_off + 24 > bytes.len) return error.InvalidPe;
    if (!std.mem.eql(u8, bytes[pe_off..][0..4], "PE\x00\x00")) return error.InvalidPe;

    const coff_off = pe_off + 4;
    const machine_raw = try readU16(bytes, coff_off);
    const machine: Machine = @enumFromInt(machine_raw);
    const num_sections = try readU16(bytes, coff_off + 2);
    const opt_size = try readU16(bytes, coff_off + 16);
    const opt_off = coff_off + 20;

    if (opt_off + opt_size > bytes.len or opt_size < 112) return error.InvalidPe;
    const magic = try readU16(bytes, opt_off);
    if (magic != 0x020B) return error.NotPe32Plus; // PE32+ (64-bit) only

    const entry_rva = try readU32(bytes, opt_off + 16);
    const image_base = try readU64(bytes, opt_off + 24);
    const size_of_image = try readU32(bytes, opt_off + 56);
    const num_rvas = try readU32(bytes, opt_off + 108);

    const sec_table_off = opt_off + opt_size;
    if (sec_table_off + @as(usize, num_sections) * 40 > bytes.len) return error.InvalidPe;

    const sections = try allocator.alloc(Section, num_sections);

    for (0..num_sections) |i| {
        const s_off = sec_table_off + i * 40;
        var name: [8]u8 = undefined;
        @memcpy(&name, bytes[s_off..][0..8]);
        sections[i] = .{
            .name = name,
            .virtual_size = try readU32(bytes, s_off + 8),
            .virtual_address = try readU32(bytes, s_off + 12),
            .raw_size = try readU32(bytes, s_off + 16),
            .raw_offset = try readU32(bytes, s_off + 20),
            .characteristics = try readU32(bytes, s_off + 36),
        };
    }

    var img = PeImage{
        .machine = machine,
        .image_base = image_base,
        .entry_rva = entry_rva,
        .size_of_image = size_of_image,
        .file_len = bytes.len,
        .export_dir_rva = 0,
        .export_dir_size = 0,
        .arm64_pac_unwind_fns = 0,
        .sections = sections,
        .functions = &[_]RuntimeFunction{},
        .exports = &[_]ExportSymbol{},
        .allocator = allocator,
    };
    errdefer img.deinit();

    // Parse .pdata (DataDirectory[3] = Exception Table)
    if (num_rvas > 3 and opt_off + 112 + 4 * 8 <= bytes.len) {
        const pdata_rva = try readU32(bytes, opt_off + 112 + 3 * 8);
        const pdata_size = try readU32(bytes, opt_off + 112 + 3 * 8 + 4);
        if (pdata_rva != 0) {
            if (img.rvaToOffset(pdata_rva)) |pdata_off| {
                if (pdata_off < bytes.len) {
                    const max_avail = @min(@as(usize, pdata_size), bytes.len - pdata_off);
                    if (machine == .arm64 or machine == .arm64ec) {
                        const count = max_avail / 8;
                        var funcs = try allocator.alloc(RuntimeFunction, count);
                        errdefer allocator.free(funcs);
                        var valid: usize = 0;
                        for (0..count) |i| {
                            const f_off = pdata_off + i * 8;
                            const begin_rva = try readU32(bytes, f_off);
                            const unwind_data = try readU32(bytes, f_off + 4);
                            if (begin_rva == 0 and unwind_data == 0) continue;
                            const flag = unwind_data & 0x3;
                            const fn_len_bytes: u32 = if (flag != 0) blk_packed: {
                                // Packed ARM64 unwind: H=bit 20, CR=bits [22:21] (`2` = PAC-signed LR).
                                const cr = (unwind_data >> 21) & 0x3;
                                if (cr == 2) img.arm64_pac_unwind_fns += 1;
                                break :blk_packed ((unwind_data >> 2) & 0x7FF) * 4;
                            } else blk: {
                                const xdata_rva = unwind_data & 0xFFFF_FFFC;
                                const x_off = img.rvaToOffset(xdata_rva) orelse break :blk 0;
                                const hdr = readU32(bytes, x_off) catch break :blk 0;
                                break :blk (hdr & 0x3FFFF) * 4;
                            };
                            if (fn_len_bytes == 0) continue;
                            funcs[valid] = .{
                                .begin_rva = begin_rva,
                                .end_rva = begin_rva +| fn_len_bytes,
                                .unwind_rva = unwind_data,
                            };
                            valid += 1;
                        }
                        img.functions = try allocator.realloc(funcs, valid);
                    } else if (pdata_size >= 12) {
                        const count = max_avail / 12;
                        var funcs = try allocator.alloc(RuntimeFunction, count);
                        errdefer allocator.free(funcs);
                        for (0..count) |i| {
                            const f_off = pdata_off + i * 12;
                            funcs[i] = .{
                                .begin_rva = try readU32(bytes, f_off),
                                .end_rva = try readU32(bytes, f_off + 4),
                                .unwind_rva = try readU32(bytes, f_off + 8),
                            };
                        }
                        img.functions = funcs;
                    }
                }
            }
        }
    }

    // Parse Export Directory (DataDirectory[0])
    if (num_rvas > 0 and opt_off + 112 + 8 <= bytes.len) {
        const exp_rva = try readU32(bytes, opt_off + 112);
        const exp_size = try readU32(bytes, opt_off + 112 + 4);
        img.export_dir_rva = exp_rva;
        img.export_dir_size = exp_size;
        if (exp_rva != 0) {
            if (img.rvaToOffset(exp_rva)) |exp_off| {
                if (exp_off +| 40 <= bytes.len) {
                    const num_names = try readU32(bytes, exp_off + 24);
                    const funcs_rva = try readU32(bytes, exp_off + 28);
                    const names_rva = try readU32(bytes, exp_off + 32);
                    const ords_rva = try readU32(bytes, exp_off + 36);
                    if (img.rvaToOffset(funcs_rva)) |funcs_off| {
                        if (img.rvaToOffset(names_rva)) |names_off| {
                            if (img.rvaToOffset(ords_rva)) |ords_off| {
                                const max_names = @min(@as(usize, num_names), (bytes.len - names_off) / 4);
                                var exps = try allocator.alloc(ExportSymbol, max_names);
                                var valid: usize = 0;
                                errdefer {
                                    for (exps[0..valid]) |e| allocator.free(e.name);
                                    allocator.free(exps);
                                }
                                for (0..max_names) |i| {
                                    if (names_off + i * 4 + 4 > bytes.len or ords_off + i * 2 + 2 > bytes.len) break;
                                    const n_rva = try readU32(bytes, names_off + i * 4);
                                    const ord = try readU16(bytes, ords_off + i * 2);
                                    if (funcs_off +| @as(usize, ord) * 4 +| 4 > bytes.len) continue;
                                    const fn_rva = try readU32(bytes, funcs_off + @as(usize, ord) * 4);
                                    if (img.rvaToOffset(n_rva)) |n_off| {
                                        if (n_off >= bytes.len) continue;
                                        const rest = bytes[n_off..];
                                        const nul = std.mem.indexOfScalar(u8, rest, 0) orelse continue;
                                        const forwarded = exp_size > 0 and fn_rva >= exp_rva and fn_rva < exp_rva +| exp_size;
                                        exps[valid] = .{
                                            .name = try allocator.dupe(u8, rest[0..nul]),
                                            .rva = fn_rva,
                                            .ordinal = ord,
                                            .is_forwarded = forwarded,
                                        };
                                        valid += 1;
                                    }
                                }
                                img.exports = try allocator.realloc(exps, valid);
                            }
                        }
                    }
                }
            }
        }
    }

    return img;
}

test "pe parses synthetic ARM64 PE32+ with .pdata, writable .data, and owned export names" {
    var raw: [1280]u8 = @splat(0);
    // DOS header
    raw[0] = 'M';
    raw[1] = 'Z';
    std.mem.writeInt(u32, raw[0x3C..][0..4], 0x80, .little);
    // PE header at 0x80
    @memcpy(raw[0x80..0x84], "PE\x00\x00");
    // COFF: machine = 0xAA64, sections = 3, opt_size = 240
    std.mem.writeInt(u16, raw[0x84..][0..2], 0xAA64, .little);
    std.mem.writeInt(u16, raw[0x86..][0..2], 3, .little);
    std.mem.writeInt(u16, raw[0x94..][0..2], 240, .little);
    // Optional header at 0x98
    std.mem.writeInt(u16, raw[0x98..][0..2], 0x020B, .little); // PE32+
    std.mem.writeInt(u32, raw[0x98 + 16 ..][0..4], 0x1000, .little); // entry RVA
    std.mem.writeInt(u64, raw[0x98 + 24 ..][0..8], 0x1_8000_0000, .little); // image base
    std.mem.writeInt(u32, raw[0x98 + 56 ..][0..4], 0x4000, .little); // SizeOfImage
    std.mem.writeInt(u32, raw[0x98 + 108 ..][0..4], 16, .little); // NumberOfRvaAndSizes
    // DataDirectory[0] (Export): RVA=0x2000, Size=64
    std.mem.writeInt(u32, raw[0x98 + 112 ..][0..4], 0x2000, .little);
    std.mem.writeInt(u32, raw[0x98 + 116 ..][0..4], 64, .little);
    // DataDirectory[3] (Exception/.pdata): RVA=0x2100, Size=8
    std.mem.writeInt(u32, raw[0x98 + 112 + 24 ..][0..4], 0x2100, .little);
    std.mem.writeInt(u32, raw[0x98 + 116 + 24 ..][0..4], 8, .little);

    // Section table at 0x98 + 240 = 0x188
    // 0: .text (RVA=0x1000, raw_off=0x200, size=0x100)
    @memcpy(raw[0x188 .. 0x188 + 5], ".text");
    std.mem.writeInt(u32, raw[0x188 + 8 ..][0..4], 0x100, .little);
    std.mem.writeInt(u32, raw[0x188 + 12 ..][0..4], 0x1000, .little);
    std.mem.writeInt(u32, raw[0x188 + 16 ..][0..4], 0x100, .little);
    std.mem.writeInt(u32, raw[0x188 + 20 ..][0..4], 0x200, .little);
    std.mem.writeInt(u32, raw[0x188 + 36 ..][0..4], IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE, .little);

    // 1: .rdata (RVA=0x2000, raw_off=0x300, size=0x180)
    const s1 = 0x188 + 40;
    @memcpy(raw[s1 .. s1 + 6], ".rdata");
    std.mem.writeInt(u32, raw[s1 + 8 ..][0..4], 0x180, .little);
    std.mem.writeInt(u32, raw[s1 + 12 ..][0..4], 0x2000, .little);
    std.mem.writeInt(u32, raw[s1 + 16 ..][0..4], 0x180, .little);
    std.mem.writeInt(u32, raw[s1 + 20 ..][0..4], 0x300, .little);
    std.mem.writeInt(u32, raw[s1 + 36 ..][0..4], IMAGE_SCN_MEM_READ, .little);

    // 2: .data (RVA=0x3000, raw_off=0x480, size=0x80)
    const s2 = s1 + 40;
    @memcpy(raw[s2 .. s2 + 5], ".data");
    std.mem.writeInt(u32, raw[s2 + 8 ..][0..4], 0x80, .little);
    std.mem.writeInt(u32, raw[s2 + 12 ..][0..4], 0x3000, .little);
    std.mem.writeInt(u32, raw[s2 + 16 ..][0..4], 0x80, .little);
    std.mem.writeInt(u32, raw[s2 + 20 ..][0..4], 0x480, .little);
    std.mem.writeInt(u32, raw[s2 + 36 ..][0..4], IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE, .little);

    // Export directory at raw 0x300 (RVA 0x2000)
    std.mem.writeInt(u32, raw[0x300 + 24 ..][0..4], 1, .little); // NumberOfNames
    std.mem.writeInt(u32, raw[0x300 + 28 ..][0..4], 0x2028, .little); // AddressOfFunctions
    std.mem.writeInt(u32, raw[0x300 + 32 ..][0..4], 0x202C, .little); // AddressOfNames
    std.mem.writeInt(u32, raw[0x300 + 36 ..][0..4], 0x2030, .little); // AddressOfNameOrdinals
    std.mem.writeInt(u32, raw[0x328..][0..4], 0x1000, .little); // func RVA
    std.mem.writeInt(u32, raw[0x32C..][0..4], 0x2034, .little); // name RVA
    std.mem.writeInt(u16, raw[0x330..][0..2], 0, .little); // ordinal
    @memcpy(raw[0x334 .. 0x334 + 10], "arm_fn\x00\x00\x00\x00");

    // .pdata at raw 0x400 (RVA 0x2100): BeginRVA=0x1000, packed flag=1, len=8 words (32B), CR=2 (PAC, bits 22:21)
    std.mem.writeInt(u32, raw[0x400..][0..4], 0x1000, .little);
    const unwind: u32 = 1 | (8 << 2) | (2 << 21);
    std.mem.writeInt(u32, raw[0x404..][0..4], unwind, .little);

    const copy = try std.testing.allocator.dupe(u8, &raw);
    var img = try parsePe(std.testing.allocator, copy);
    defer img.deinit();
    // Overwrite and free source buffer immediately to prove owned export strings!
    @memset(copy, 0);
    std.testing.allocator.free(copy);

    try std.testing.expectEqual(Machine.arm64, img.machine);
    try std.testing.expectEqual(@as(u32, 0x4000), img.size_of_image);
    try std.testing.expectEqual(@as(usize, 1), img.functions.len);
    try std.testing.expectEqual(@as(u32, 0x1020), img.functions[0].end_rva);
    try std.testing.expectEqual(@as(usize, 1), img.arm64_pac_unwind_fns);
    try std.testing.expectEqual(@as(u32, 0x1000), img.findExport("arm_fn").?);

    const wsecs = try img.writableDataSections(std.testing.allocator);
    defer std.testing.allocator.free(wsecs);
    try std.testing.expectEqual(@as(usize, 1), wsecs.len);
    try std.testing.expectEqualStrings(".data", wsecs[0].nameSlice());
}
