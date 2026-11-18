const std = @import("std");
const pe = @import("pe.zig");
const elf = @import("elf_arm64.zig");
const macho = @import("macho_arm64.zig");

pub const BinaryFormat = enum {
    pe32plus,
    elf64,
    macho64,
};

pub const BinaryImage = struct {
    format: BinaryFormat,
    machine: pe.Machine,
    image_base: u64,
    entry_rva: u32,
    size_of_image: u32,
    sections: []pe.Section,
    functions: []pe.RuntimeFunction,
    exports: []pe.ExportSymbol,
    has_pac: bool,
    has_bti: bool,
    is_arm64ec: bool,
    min_segment_align: u32,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *BinaryImage) void {
        for (self.exports) |exp| {
            self.allocator.free(exp.name);
        }
        self.allocator.free(self.sections);
        self.allocator.free(self.functions);
        self.allocator.free(self.exports);
    }

    pub fn isArm64(self: *const BinaryImage) bool {
        return self.machine == .arm64 or self.machine == .arm64ec;
    }

    pub fn findSection(self: *const BinaryImage, name: []const u8) ?pe.Section {
        for (self.sections) |sec| {
            if (std.mem.eql(u8, sec.nameSlice(), name)) return sec;
        }
        return null;
    }

    pub fn findCodeSection(self: *const BinaryImage) ?pe.Section {
        return self.findSection(".text") orelse self.findSection("__text") orelse blk: {
            for (self.sections) |sec| {
                if ((sec.characteristics & pe.IMAGE_SCN_MEM_EXECUTE) != 0) break :blk sec;
            }
            break :blk null;
        };
    }

    pub fn rvaToOffset(self: *const BinaryImage, rva: u32) ?usize {
        for (self.sections) |sec| {
            const span = @max(sec.virtual_size, sec.raw_size);
            if (rva >= sec.virtual_address and rva < sec.virtual_address +| span) {
                const delta = rva - sec.virtual_address;
                if (delta < sec.raw_size) {
                    return @as(usize, sec.raw_offset) +| @as(usize, delta);
                }
            }
        }
        return null;
    }

    pub fn findExport(self: *const BinaryImage, name: []const u8) ?u32 {
        for (self.exports) |exp| {
            if (std.mem.eql(u8, exp.name, name)) return exp.rva;
        }
        return null;
    }

    pub fn writableDataSections(self: *const BinaryImage, allocator: std.mem.Allocator) ![]pe.Section {
        var list = std.ArrayList(pe.Section).empty;
        errdefer list.deinit(allocator);
        for (self.sections) |sec| {
            if (sec.isWritableData() and sec.virtual_size > 0) {
                try list.append(allocator, sec);
            }
        }
        return list.toOwnedSlice(allocator);
    }
};

/// Auto-detect PE32+, ELF64, or 64-bit Mach-O binary headers and normalize into `BinaryImage`.
pub fn parseBinary(allocator: std.mem.Allocator, bytes: []const u8) !BinaryImage {
    if (bytes.len >= 4 and std.mem.eql(u8, bytes[0..4], "\x7fELF")) {
        const e = try elf.parseElf(allocator, bytes);
        return .{
            .format = .elf64,
            .machine = e.machine,
            .image_base = e.image_base,
            .entry_rva = e.entry_rva,
            .size_of_image = e.size_of_image,
            .sections = e.sections,
            .functions = e.functions,
            .exports = e.exports,
            .has_pac = e.has_pac,
            .has_bti = e.has_bti,
            .is_arm64ec = false,
            .min_segment_align = e.min_segment_align,
            .allocator = e.allocator,
        };
    }

    if (bytes.len >= 4 and std.mem.readInt(u32, bytes[0..4], .little) == 0xFEED_FACF) {
        const m = try macho.parseMachO(allocator, bytes);
        return .{
            .format = .macho64,
            .machine = m.machine,
            .image_base = m.image_base,
            .entry_rva = m.entry_rva,
            .size_of_image = m.size_of_image,
            .sections = m.sections,
            .functions = m.functions,
            .exports = m.exports,
            .has_pac = m.has_pac,
            .has_bti = false,
            .is_arm64ec = false,
            .min_segment_align = 16384,
            .allocator = m.allocator,
        };
    }

    const p = try pe.parsePe(allocator, bytes);
    return .{
        .format = .pe32plus,
        .machine = p.machine,
        .image_base = p.image_base,
        .entry_rva = p.entry_rva,
        .size_of_image = p.size_of_image,
        .sections = p.sections,
        .functions = p.functions,
        .exports = p.exports,
        .has_pac = p.arm64_pac_unwind_fns > 0,
        .has_bti = false,
        .is_arm64ec = p.machine == .arm64ec,
        .min_segment_align = 4096,
        .allocator = p.allocator,
    };
}

test "binary auto-detects PE32+, ELF64, and Mach-O ARM64 images" {
    // Minimal ELF64 AArch64 header
    var elf_buf: [64]u8 = @splat(0);
    @memcpy(elf_buf[0..4], "\x7fELF");
    elf_buf[4] = 2;
    elf_buf[5] = 1;
    std.mem.writeInt(u16, elf_buf[18..20], elf.EM_AARCH64, .little);
    var bi_elf = try parseBinary(std.testing.allocator, &elf_buf);
    defer bi_elf.deinit();
    try std.testing.expectEqual(BinaryFormat.elf64, bi_elf.format);
    try std.testing.expect(bi_elf.isArm64());

    // Minimal Mach-O ARM64 header
    var mac_buf: [64]u8 = @splat(0);
    std.mem.writeInt(u32, mac_buf[0..4], 0xFEED_FACF, .little);
    std.mem.writeInt(u32, mac_buf[4..8], 0x0100_000C, .little);
    var bi_mac = try parseBinary(std.testing.allocator, &mac_buf);
    defer bi_mac.deinit();
    try std.testing.expectEqual(BinaryFormat.macho64, bi_mac.format);
    try std.testing.expect(bi_mac.isArm64());
}
