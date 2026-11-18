const std = @import("std");
const pe = @import("pe.zig");

pub const EM_X86_64: u16 = 62;
pub const EM_AARCH64: u16 = 183;

const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_NOTE: u32 = 7;
const SHT_NOBITS: u32 = 8;
const SHT_DYNSYM: u32 = 11;

const SHF_WRITE: u64 = 0x1;
const SHF_ALLOC: u64 = 0x2;
const SHF_EXECINSTR: u64 = 0x4;
const SHF_TLS: u64 = 0x400;

const STT_FUNC: u8 = 2;
const STB_GLOBAL: u8 = 1;
const STB_WEAK: u8 = 2;

const NT_GNU_PROPERTY_TYPE_0: u32 = 5;
const GNU_PROPERTY_AARCH64_FEATURE_1_AND: u32 = 0xc000_0000;
const GNU_PROPERTY_AARCH64_FEATURE_1_BTI: u32 = 1;
const GNU_PROPERTY_AARCH64_FEATURE_1_PAC: u32 = 2;

pub const ElfImage = struct {
    machine: pe.Machine,
    image_base: u64,
    entry_rva: u32,
    size_of_image: u32,
    min_segment_align: u32,
    has_bti: bool,
    has_pac: bool,
    sections: []pe.Section,
    functions: []pe.RuntimeFunction,
    exports: []pe.ExportSymbol,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *ElfImage) void {
        for (self.exports) |exp| {
            self.allocator.free(exp.name);
        }
        self.allocator.free(self.sections);
        self.allocator.free(self.functions);
        self.allocator.free(self.exports);
    }
};

fn readU16(b: []const u8, off: usize) !u16 {
    if (off + 2 > b.len) return error.UnexpectedEof;
    return std.mem.readInt(u16, b[off..][0..2], .little);
}

fn readU32(b: []const u8, off: usize) !u32 {
    if (off + 4 > b.len) return error.UnexpectedEof;
    return std.mem.readInt(u32, b[off..][0..4], .little);
}

fn readU64(b: []const u8, off: usize) !u64 {
    if (off + 8 > b.len) return error.UnexpectedEof;
    return std.mem.readInt(u64, b[off..][0..8], .little);
}

pub fn parseElf(allocator: std.mem.Allocator, bytes: []const u8) !ElfImage {
    if (bytes.len < 64) return error.InvalidElf;
    if (!std.mem.eql(u8, bytes[0..4], "\x7fELF")) return error.InvalidElf;
    if (bytes[4] != 2 or bytes[5] != 1) return error.UnsupportedElfClassOrEndian; // ELF64 LE

    const e_machine = try readU16(bytes, 18);
    const machine: pe.Machine = switch (e_machine) {
        EM_AARCH64 => .arm64,
        EM_X86_64 => .amd64,
        else => @enumFromInt(e_machine),
    };

    const e_entry = try readU64(bytes, 24);
    const e_phoff = try readU64(bytes, 32);
    const e_shoff = try readU64(bytes, 40);
    const e_phentsize = try readU16(bytes, 54);
    const e_phnum = try readU16(bytes, 56);
    const e_shentsize = try readU16(bytes, 58);
    const e_shnum = try readU16(bytes, 60);
    const e_shstrndx = try readU16(bytes, 62);

    var base_vaddr: u64 = std.math.maxInt(u64);
    var max_vaddr: u64 = 0;
    var min_align: u32 = 4096;
    var found_load = false;

    if (e_phoff != 0 and e_phentsize >= 56 and e_phoff <= bytes.len) {
        const ph_base: usize = @intCast(e_phoff);
        var pi: usize = 0;
        while (pi < e_phnum) : (pi += 1) {
            const off = ph_base +| (pi *| e_phentsize);
            if (off +| 56 > bytes.len) break;
            const p_type = try readU32(bytes, off);
            if (p_type == 1) { // PT_LOAD
                const p_vaddr = try readU64(bytes, off + 16);
                const p_memsz = try readU64(bytes, off + 40);
                const p_align = try readU64(bytes, off + 48);
                if (!found_load or p_vaddr < base_vaddr) base_vaddr = p_vaddr;
                max_vaddr = @max(max_vaddr, p_vaddr +| p_memsz);
                if (p_align >= 4096 and p_align <= 1024 * 1024) {
                    const a32: u32 = @intCast(p_align);
                    if (!found_load or a32 < min_align) min_align = a32;
                }
                found_load = true;
            }
        }
    }
    if (!found_load) base_vaddr = 0;

    const image_size: u32 = if (max_vaddr > base_vaddr)
        @intCast(@min(max_vaddr - base_vaddr, std.math.maxInt(u32)))
    else
        0;

    var sec_list = std.ArrayList(pe.Section).empty;
    errdefer sec_list.deinit(allocator);
    var fn_list = std.ArrayList(pe.RuntimeFunction).empty;
    errdefer fn_list.deinit(allocator);
    var exp_list = std.ArrayList(pe.ExportSymbol).empty;
    errdefer {
        for (exp_list.items) |e| allocator.free(e.name);
        exp_list.deinit(allocator);
    }
    var seen_fn_rvas = std.AutoHashMap(u32, void).init(allocator);
    defer seen_fn_rvas.deinit();
    var seen_exp_names = std.StringHashMap(void).init(allocator);
    defer seen_exp_names.deinit();

    var has_bti = false;
    var has_pac = false;

    var shstr_off: usize = 0;
    var shstr_size: usize = 0;
    if (e_shoff != 0 and e_shentsize >= 64 and e_shoff <= bytes.len and e_shstrndx < e_shnum) {
        const sh_base: usize = @intCast(e_shoff);
        const str_hdr = sh_base +| (@as(usize, e_shstrndx) *| e_shentsize);
        if (str_hdr +| 64 <= bytes.len) {
            const raw_shstr_off = try readU64(bytes, str_hdr + 24);
            const raw_shstr_sz = try readU64(bytes, str_hdr + 32);
            if (raw_shstr_off <= bytes.len and raw_shstr_sz <= bytes.len) {
                shstr_off = @intCast(raw_shstr_off);
                shstr_size = @intCast(raw_shstr_sz);
            }
        }
    }

    if (e_shoff != 0 and e_shentsize >= 64 and e_shoff <= bytes.len) {
        const sh_base: usize = @intCast(e_shoff);
        var si: usize = 0;
        while (si < e_shnum) : (si += 1) {
            const sh_off = sh_base +| (si *| e_shentsize);
            if (sh_off +| 64 > bytes.len) break;
            const sh_name_idx = try readU32(bytes, sh_off);
            const sh_type = try readU32(bytes, sh_off + 4);
            const sh_flags = try readU64(bytes, sh_off + 8);
            const sh_addr = try readU64(bytes, sh_off + 16);
            const sh_offset = try readU64(bytes, sh_off + 24);
            const sh_size = try readU64(bytes, sh_off + 32);
            const sh_link = try readU32(bytes, sh_off + 40);

            var sec_name: [8]u8 = @splat(0);
            if (sh_name_idx < shstr_size and shstr_off +| sh_name_idx < bytes.len) {
                const start = shstr_off + sh_name_idx;
                const end = @min(bytes.len, shstr_off +| shstr_size);
                if (start < end) {
                    const rest = bytes[start..end];
                    const nul = std.mem.indexOfScalar(u8, rest, 0) orelse rest.len;
                    const copy_len = @min(nul, 8);
                    @memcpy(sec_name[0..copy_len], rest[0..copy_len]);
                }
            }

            if ((sh_flags & SHF_ALLOC) != 0 and sh_size > 0) {
                var chars: u32 = pe.IMAGE_SCN_MEM_READ;
                if ((sh_flags & SHF_WRITE) != 0 and (sh_flags & SHF_TLS) == 0) chars |= pe.IMAGE_SCN_MEM_WRITE;
                if ((sh_flags & SHF_EXECINSTR) != 0) chars |= pe.IMAGE_SCN_MEM_EXECUTE;
                const rva: u32 = if (sh_addr >= base_vaddr)
                    @intCast(@min(sh_addr - base_vaddr, std.math.maxInt(u32)))
                else
                    @truncate(sh_addr);
                try sec_list.append(allocator, .{
                    .name = sec_name,
                    .virtual_size = @intCast(@min(sh_size, std.math.maxInt(u32))),
                    .virtual_address = rva,
                    .raw_size = if (sh_type == SHT_NOBITS) 0 else @intCast(@min(sh_size, std.math.maxInt(u32))),
                    .raw_offset = @intCast(@min(sh_offset, std.math.maxInt(u32))),
                    .characteristics = chars,
                });
            }

            // Parse GNU note properties for BTI/PAC flags
            if (sh_type == SHT_NOTE and sh_offset <= bytes.len and sh_size <= bytes.len - sh_offset) {
                const note_start: usize = @intCast(sh_offset);
                const note_len: usize = @intCast(sh_size);
                const note_slice = bytes[note_start .. note_start + note_len];
                var npos: usize = 0;
                while (npos +| 12 <= note_slice.len) {
                    const namesz = std.mem.readInt(u32, note_slice[npos..][0..4], .little);
                    const descsz = std.mem.readInt(u32, note_slice[npos + 4 ..][0..4], .little);
                    const ntype = std.mem.readInt(u32, note_slice[npos + 8 ..][0..4], .little);
                    const name_aligned = std.mem.alignForward(usize, namesz, 4);
                    const desc_off = npos +| 12 +| name_aligned;
                    const desc_aligned = std.mem.alignForward(usize, descsz, 4);
                    if (desc_off +| descsz > note_slice.len) break;
                    if (ntype == NT_GNU_PROPERTY_TYPE_0) {
                        var ppos: usize = desc_off;
                        while (ppos +| 8 <= desc_off + descsz) {
                            const pr_type = std.mem.readInt(u32, note_slice[ppos..][0..4], .little);
                            const pr_datasz = std.mem.readInt(u32, note_slice[ppos + 4 ..][0..4], .little);
                            if (ppos +| 8 +| pr_datasz > desc_off + descsz) break;
                            if (pr_type == GNU_PROPERTY_AARCH64_FEATURE_1_AND and pr_datasz >= 4) {
                                const feat = std.mem.readInt(u32, note_slice[ppos + 8 ..][0..4], .little);
                                if ((feat & GNU_PROPERTY_AARCH64_FEATURE_1_BTI) != 0) has_bti = true;
                                if ((feat & GNU_PROPERTY_AARCH64_FEATURE_1_PAC) != 0) has_pac = true;
                            }
                            ppos +|= 8 +| std.mem.alignForward(usize, pr_datasz, 8);
                        }
                    }
                    npos = desc_off +| desc_aligned;
                }
            }

            // Parse symbol table for STT_FUNC entries (deduplicated across .dynsym & .symtab)
            if ((sh_type == SHT_SYMTAB or sh_type == SHT_DYNSYM) and sh_link < e_shnum and sh_offset <= bytes.len and sh_size <= bytes.len - sh_offset) {
                const strtab_hdr = sh_base +| (@as(usize, sh_link) *| e_shentsize);
                if (strtab_hdr +| 64 <= bytes.len) {
                    const raw_str_off = try readU64(bytes, strtab_hdr + 24);
                    const raw_str_sz = try readU64(bytes, strtab_hdr + 32);
                    if (raw_str_off <= bytes.len and raw_str_sz <= bytes.len - raw_str_off) {
                        const str_off: usize = @intCast(raw_str_off);
                        const str_sz: usize = @intCast(raw_str_sz);
                        const num_syms: usize = @intCast(sh_size / 24);
                        const sym_base: usize = @intCast(sh_offset);
                        for (0..num_syms) |sym_i| {
                            const sym_off = sym_base + sym_i * 24;
                            const st_name = try readU32(bytes, sym_off);
                            const st_info = bytes[sym_off + 4];
                            const st_shndx = try readU16(bytes, sym_off + 6);
                            const st_value = try readU64(bytes, sym_off + 8);
                            const st_size = try readU64(bytes, sym_off + 16);
                            const sym_type = st_info & 0xF;
                            const sym_bind = st_info >> 4;
                            if (sym_type == STT_FUNC and st_shndx != 0 and st_size > 0 and st_value >= base_vaddr) {
                                const begin_rva: u32 = @intCast(@min(st_value - base_vaddr, std.math.maxInt(u32)));
                                const sz32: u32 = @intCast(@min(st_size, std.math.maxInt(u32)));
                                if (!seen_fn_rvas.contains(begin_rva)) {
                                    try seen_fn_rvas.put(begin_rva, {});
                                    try fn_list.append(allocator, .{
                                        .begin_rva = begin_rva,
                                        .end_rva = begin_rva +| sz32,
                                        .unwind_rva = 0,
                                    });
                                }
                                if ((sym_bind == STB_GLOBAL or sym_bind == STB_WEAK) and st_name < str_sz) {
                                    const srest = bytes[str_off + st_name .. str_off + str_sz];
                                    const nul = std.mem.indexOfScalar(u8, srest, 0) orelse srest.len;
                                    if (nul > 0 and !seen_exp_names.contains(srest[0..nul])) {
                                        const dup_name = try allocator.dupe(u8, srest[0..nul]);
                                        errdefer allocator.free(dup_name);
                                        try exp_list.append(allocator, .{
                                            .name = dup_name,
                                            .rva = begin_rva,
                                            .ordinal = @truncate(exp_list.items.len),
                                            .is_forwarded = false,
                                        });
                                        try seen_exp_names.put(dup_name, {});
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    const entry_rva: u32 = if (e_entry >= base_vaddr)
        @intCast(@min(e_entry - base_vaddr, std.math.maxInt(u32)))
    else
        @truncate(e_entry);

    return .{
        .machine = machine,
        .image_base = base_vaddr,
        .entry_rva = entry_rva,
        .size_of_image = image_size,
        .min_segment_align = min_align,
        .has_bti = has_bti,
        .has_pac = has_pac,
        .sections = try sec_list.toOwnedSlice(allocator),
        .functions = try fn_list.toOwnedSlice(allocator),
        .exports = try exp_list.toOwnedSlice(allocator),
        .allocator = allocator,
    };
}

test "elf_arm64 parses synthetic ELF64 EM_AARCH64 with BTI/PAC note and 16KB align" {
    var buf: [512]u8 = @splat(0);
    // ELF64 LE header
    @memcpy(buf[0..4], "\x7fELF");
    buf[4] = 2; // ELFCLASS64
    buf[5] = 1; // ELFDATA2LSB
    buf[6] = 1;
    std.mem.writeInt(u16, buf[16..18], 3, .little); // ET_DYN
    std.mem.writeInt(u16, buf[18..20], EM_AARCH64, .little);
    std.mem.writeInt(u64, buf[24..32], 0x1000, .little); // e_entry
    std.mem.writeInt(u64, buf[32..40], 64, .little); // e_phoff
    std.mem.writeInt(u64, buf[40..48], 128, .little); // e_shoff
    std.mem.writeInt(u16, buf[54..56], 56, .little); // e_phentsize
    std.mem.writeInt(u16, buf[56..58], 1, .little); // e_phnum
    std.mem.writeInt(u16, buf[58..60], 64, .little); // e_shentsize
    std.mem.writeInt(u16, buf[60..62], 3, .little); // e_shnum
    std.mem.writeInt(u16, buf[62..64], 1, .little); // e_shstrndx

    // PHDR[0] at 64: PT_LOAD with 16KB p_align
    std.mem.writeInt(u32, buf[64..68], 1, .little);
    std.mem.writeInt(u64, buf[64 + 16 ..][0..8], 0, .little);
    std.mem.writeInt(u64, buf[64 + 40 ..][0..8], 0x4000, .little);
    std.mem.writeInt(u64, buf[64 + 48 ..][0..8], 16384, .little);

    // SHDR[0] at 128: .text
    std.mem.writeInt(u32, buf[128..132], 1, .little); // sh_name -> ".text"
    std.mem.writeInt(u32, buf[128 + 4 ..][0..4], 1, .little); // SHT_PROGBITS
    std.mem.writeInt(u64, buf[128 + 8 ..][0..8], SHF_ALLOC | SHF_EXECINSTR, .little);
    std.mem.writeInt(u64, buf[128 + 16 ..][0..8], 0x1000, .little);
    std.mem.writeInt(u64, buf[128 + 24 ..][0..8], 0x1A0, .little);
    std.mem.writeInt(u64, buf[128 + 32 ..][0..8], 0x20, .little);

    // SHDR[1] at 192: shstrtab at 0x160
    std.mem.writeInt(u32, buf[192 + 4 ..][0..4], SHT_STRTAB, .little);
    std.mem.writeInt(u64, buf[192 + 24 ..][0..8], 0x160, .little);
    std.mem.writeInt(u64, buf[192 + 32 ..][0..8], 16, .little);
    @memcpy(buf[0x160 .. 0x160 + 7], "\x00.text\x00");

    // SHDR[2] at 256: SHT_NOTE at 0x180
    std.mem.writeInt(u32, buf[256 + 4 ..][0..4], SHT_NOTE, .little);
    std.mem.writeInt(u64, buf[256 + 24 ..][0..8], 0x180, .little);
    std.mem.writeInt(u64, buf[256 + 32 ..][0..8], 32, .little);
    // Note header + GNU_PROPERTY_AARCH64_FEATURE_1_AND (BTI | PAC)
    std.mem.writeInt(u32, buf[0x180..0x184], 4, .little); // namesz
    std.mem.writeInt(u32, buf[0x184..0x188], 16, .little); // descsz
    std.mem.writeInt(u32, buf[0x188..0x18C], NT_GNU_PROPERTY_TYPE_0, .little);
    @memcpy(buf[0x18C..0x190], "GNU\x00");
    std.mem.writeInt(u32, buf[0x190..0x194], GNU_PROPERTY_AARCH64_FEATURE_1_AND, .little);
    std.mem.writeInt(u32, buf[0x194..0x198], 4, .little);
    std.mem.writeInt(u32, buf[0x198..0x19C], GNU_PROPERTY_AARCH64_FEATURE_1_BTI | GNU_PROPERTY_AARCH64_FEATURE_1_PAC, .little);

    var elf = try parseElf(std.testing.allocator, &buf);
    defer elf.deinit();

    try std.testing.expectEqual(pe.Machine.arm64, elf.machine);
    try std.testing.expectEqual(@as(u32, 16384), elf.min_segment_align);
    try std.testing.expect(elf.has_bti);
    try std.testing.expect(elf.has_pac);
    try std.testing.expectEqual(@as(usize, 1), elf.sections.len);
    try std.testing.expectEqualStrings(".text", elf.sections[0].nameSlice());
}
