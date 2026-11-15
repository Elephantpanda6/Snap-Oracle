const std = @import("std");

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
};

pub const RuntimeFunction = struct {
    begin_rva: u32,
    end_rva: u32,
    unwind_rva: u32,
};

pub const ExportSymbol = struct {
    name: []const u8,
    rva: u32,
    ordinal: u16,
};

pub const PeImage = struct {
    machine: Machine,
    image_base: u64,
    entry_rva: u32,
    sections: []Section,
    functions: []RuntimeFunction,
    exports: []ExportSymbol,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *PeImage) void {
        self.allocator.free(self.sections);
        self.allocator.free(self.functions);
        self.allocator.free(self.exports);
    }

    pub fn rvaToOffset(self: *const PeImage, rva: u32) ?usize {
        for (self.sections) |sec| {
            const span = @max(sec.virtual_size, sec.raw_size);
            if (rva >= sec.virtual_address and rva < sec.virtual_address + span) {
                const delta = rva - sec.virtual_address;
                if (delta < sec.raw_size) {
                    return @as(usize, sec.raw_offset) + @as(usize, delta);
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
    const num_rvas = try readU32(bytes, opt_off + 108);

    const sec_table_off = opt_off + opt_size;
    if (sec_table_off + @as(usize, num_sections) * 40 > bytes.len) return error.InvalidPe;

    var sections = try allocator.alloc(Section, num_sections);
    errdefer allocator.free(sections);

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
        .sections = sections,
        .functions = &[_]RuntimeFunction{},
        .exports = &[_]ExportSymbol{},
        .allocator = allocator,
    };

    // Parse .pdata (DataDirectory[3] = Exception Table)
    if (num_rvas > 3 and opt_off + 112 + 4 * 8 <= bytes.len) {
        const pdata_rva = try readU32(bytes, opt_off + 112 + 3 * 8);
        const pdata_size = try readU32(bytes, opt_off + 112 + 3 * 8 + 4);
        if (pdata_rva != 0 and pdata_size >= 12) {
            if (img.rvaToOffset(pdata_rva)) |pdata_off| {
                const max_avail = @min(@as(usize, pdata_size), bytes.len - pdata_off);
                const count = max_avail / 12;
                var funcs = try allocator.alloc(RuntimeFunction, count);
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

    // Parse Export Directory (DataDirectory[0])
    if (num_rvas > 0 and opt_off + 112 + 8 <= bytes.len) {
        const exp_rva = try readU32(bytes, opt_off + 112);
        if (exp_rva != 0) {
            if (img.rvaToOffset(exp_rva)) |exp_off| {
                if (exp_off + 40 <= bytes.len) {
                    const num_names = try readU32(bytes, exp_off + 24);
                    const funcs_rva = try readU32(bytes, exp_off + 28);
                    const names_rva = try readU32(bytes, exp_off + 32);
                    const ords_rva = try readU32(bytes, exp_off + 36);
                    if (img.rvaToOffset(funcs_rva)) |funcs_off| {
                        if (img.rvaToOffset(names_rva)) |names_off| {
                            if (img.rvaToOffset(ords_rva)) |ords_off| {
                                var exps = try allocator.alloc(ExportSymbol, num_names);
                                var valid: usize = 0;
                                for (0..num_names) |i| {
                                    if (names_off + i * 4 + 4 > bytes.len or ords_off + i * 2 + 2 > bytes.len) break;
                                    const n_rva = try readU32(bytes, names_off + i * 4);
                                    const ord = try readU16(bytes, ords_off + i * 2);
                                    if (funcs_off + @as(usize, ord) * 4 + 4 > bytes.len) continue;
                                    const fn_rva = try readU32(bytes, funcs_off + @as(usize, ord) * 4);
                                    if (img.rvaToOffset(n_rva)) |n_off| {
                                        const rest = bytes[n_off..];
                                        const nul = std.mem.indexOfScalar(u8, rest, 0) orelse continue;
                                        exps[valid] = .{
                                            .name = rest[0..nul],
                                            .rva = fn_rva,
                                            .ordinal = ord,
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
