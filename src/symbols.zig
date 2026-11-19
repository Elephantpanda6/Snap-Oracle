const std = @import("std");
const binary = @import("binary.zig");
const macho = @import("macho_arm64.zig");
const finding = @import("finding.zig");
const pe = @import("pe.zig");

pub const SymbolEntry = struct {
    rva: u32,
    size: u32,
    name: []const u8,
};

pub const ResolvedSymbol = struct {
    name: []const u8,
    offset: u32,
    found: bool,
};

pub const SymbolTable = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    entries: []SymbolEntry,

    pub fn deinit(self: *SymbolTable) void {
        self.allocator.free(self.entries);
        self.arena.deinit();
    }

    pub fn build(allocator: std.mem.Allocator, img: *const binary.BinaryImage, raw_bytes: ?[]const u8, do_demangle: bool) !SymbolTable {
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();
        const aa = arena.allocator();

        var by_rva = std.AutoHashMap(u32, SymbolEntry).init(allocator);
        defer by_rva.deinit();

        // 1. Function ranges from BinaryImage (.pdata / ELF .symtab / Mach-O LC_FUNCTION_STARTS)
        for (img.functions) |fn_entry| {
            const sz = if (fn_entry.end_rva > fn_entry.begin_rva) fn_entry.end_rva - fn_entry.begin_rva else 4;
            const auto_name = try std.fmt.allocPrint(aa, "sub_{x}", .{fn_entry.begin_rva});
            try by_rva.put(fn_entry.begin_rva, .{
                .rva = fn_entry.begin_rva,
                .size = sz,
                .name = auto_name,
            });
        }

        // 2. Named exports (override synthetic sub_<rva> names and preserve function sizes)
        for (img.exports) |exp| {
            if (exp.is_forwarded or exp.rva == 0 or exp.name.len == 0) continue;
            const display = if (do_demangle) try demangle(aa, exp.name) else try aa.dupe(u8, exp.name);
            if (by_rva.getPtr(exp.rva)) |existing| {
                existing.name = display;
            } else {
                try by_rva.put(exp.rva, .{
                    .rva = exp.rva,
                    .size = 0,
                    .name = display,
                });
            }
        }

        // 3. Optional COFF symbol table for unstripped MinGW/LLVM PE binaries
        if (raw_bytes) |rb| {
            const bytes = macho.unwrapFatSlice(rb);
            if (img.format == .pe32plus) {
                try appendPeCoffSymbols(aa, bytes, img, do_demangle, &by_rva);
            }
        }

        var list = std.ArrayList(SymbolEntry).empty;
        errdefer list.deinit(allocator);

        var it = by_rva.valueIterator();
        while (it.next()) |entry| {
            try list.append(allocator, entry.*);
        }

        const owned = try list.toOwnedSlice(allocator);
        std.mem.sort(SymbolEntry, owned, {}, struct {
            fn lessThan(_: void, a: SymbolEntry, b: SymbolEntry) bool {
                return a.rva < b.rva;
            }
        }.lessThan);

        // Fill unknown sizes using distance to next symbol (capped sensibly)
        for (owned, 0..) |*sym, idx| {
            if (sym.size == 0 and idx + 1 < owned.len) {
                const delta = owned[idx + 1].rva - sym.rva;
                sym.size = @min(delta, 0x10000);
            }
        }

        return .{
            .allocator = allocator,
            .arena = arena,
            .entries = owned,
        };
    }

    pub fn resolve(self: *const SymbolTable, rva: u32) ResolvedSymbol {
        if (self.entries.len == 0) {
            return .{ .name = "<unknown>", .offset = rva, .found = false };
        }

        // Binary search for greatest sym.rva <= rva
        var lo: usize = 0;
        var hi: usize = self.entries.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (self.entries[mid].rva <= rva) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }

        if (lo == 0) {
            return .{ .name = "<image_header>", .offset = rva, .found = false };
        }

        const cand = self.entries[lo - 1];
        const delta = rva - cand.rva;
        if (cand.size > 0 and delta >= cand.size) {
            return .{ .name = "<unmapped_gap>", .offset = rva, .found = false };
        }
        return .{ .name = cand.name, .offset = delta, .found = true };
    }
};

fn appendPeCoffSymbols(
    aa: std.mem.Allocator,
    bytes: []const u8,
    img: *const binary.BinaryImage,
    do_demangle: bool,
    by_rva: *std.AutoHashMap(u32, SymbolEntry),
) !void {
    if (bytes.len < 0x40) return;
    const e_lfanew = std.mem.readInt(u32, bytes[0x3C..][0..4], .little);
    const coff_off = @as(u64, e_lfanew) + 4;
    if (coff_off + 20 > bytes.len) return;

    const ptr_symtab = std.mem.readInt(u32, bytes[@as(usize, @intCast(coff_off + 8))..][0..4], .little);
    const num_syms = std.mem.readInt(u32, bytes[@as(usize, @intCast(coff_off + 12))..][0..4], .little);
    if (ptr_symtab == 0 or num_syms == 0 or num_syms > 200_000) return;

    const symtab_bytes = @as(u64, num_syms) * 18;
    const strtab_off = @as(u64, ptr_symtab) + symtab_bytes;
    if (strtab_off + 4 > bytes.len) return;
    const strtab_sz = std.mem.readInt(u32, bytes[@as(usize, @intCast(strtab_off))..][0..4], .little);
    if (strtab_off + strtab_sz > bytes.len) return;
    const strtab = bytes[@as(usize, @intCast(strtab_off))..@as(usize, @intCast(strtab_off + strtab_sz))];

    var i: u32 = 0;
    while (i < num_syms) {
        const off = @as(usize, ptr_symtab) + @as(usize, i) * 18;
        if (off + 18 > bytes.len) break;
        const rec = bytes[off..][0..18];
        const value = std.mem.readInt(u32, rec[8..12], .little);
        const sec_num = std.mem.readInt(i16, rec[12..14], .little);
        const aux_cnt = rec[17];
        i += 1 + @as(u32, aux_cnt);

        if (sec_num <= 0) continue;
        const sec_idx: usize = @intCast(sec_num - 1);
        if (sec_idx >= img.sections.len) continue;
        const sec = img.sections[sec_idx];
        if ((sec.characteristics & pe.IMAGE_SCN_MEM_EXECUTE) == 0) continue;

        const rva = sec.virtual_address +| value;
        var raw_name: []const u8 = "";
        const zeroes = std.mem.readInt(u32, rec[0..4], .little);
        if (zeroes == 0) {
            const str_off = std.mem.readInt(u32, rec[4..8], .little);
            if (str_off >= 4 and str_off < strtab.len) {
                const tail = strtab[str_off..];
                const end = std.mem.indexOfScalar(u8, tail, 0) orelse tail.len;
                raw_name = tail[0..end];
            }
        } else {
            const end = std.mem.indexOfScalar(u8, rec[0..8], 0) orelse 8;
            raw_name = rec[0..end];
        }

        if (raw_name.len == 0 or raw_name[0] == '.') continue;
        const clean = if (do_demangle) try demangle(aa, raw_name) else try aa.dupe(u8, raw_name);
        if (by_rva.getPtr(rva)) |existing| {
            if (std.mem.startsWith(u8, existing.name, "sub_")) {
                existing.name = clean;
            }
        } else {
            try by_rva.put(rva, .{ .rva = rva, .size = 0, .name = clean });
        }
    }
}

/// Best-effort pure-Zig demangler for Itanium C++ (`_Z...`) and MSVC C++ (`?...@@...`).
/// Falls back cleanly to returning a duplicate of `raw` for C or unrecognized names.
pub fn demangle(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    if (raw.len == 0) return allocator.dupe(u8, raw);

    // Strip leading underscore on macOS Mach-O / 32-bit COFF aliases if followed by _Z or ?
    const s = if (raw.len >= 3 and raw[0] == '_' and raw[1] == '_' and raw[2] == 'Z')
        raw[1..]
    else
        raw;

    if (std.mem.startsWith(u8, s, "_Z")) {
        if (try demangleItanium(allocator, s[2..])) |res| return res;
    } else if (s[0] == '?' and s.len > 2) {
        if (try demangleMsvc(allocator, s[1..])) |res| return res;
    }

    return allocator.dupe(u8, raw);
}

fn readItaniumLenIdent(rest: *[]const u8) ?[]const u8 {
    if (rest.*.len == 0 or !std.ascii.isDigit(rest.*[0])) return null;
    var n: usize = 0;
    var i: usize = 0;
    while (i < rest.*.len and std.ascii.isDigit(rest.*[i])) : (i += 1) {
        n = n * 10 + (rest.*[i] - '0');
        if (n > 4096) return null;
    }
    if (i + n > rest.*.len or n == 0) return null;
    const ident = rest.*[i .. i + n];
    rest.* = rest.*[i + n ..];
    return ident;
}

fn demangleItanium(allocator: std.mem.Allocator, body: []const u8) !?[]u8 {
    var cur = body;
    var parts = std.ArrayList([]const u8).empty;
    defer parts.deinit(allocator);

    if (cur.len == 0) return null;

    if (cur[0] == 'N') {
        cur = cur[1..];
        // Optional cv/ref qualifiers on member function
        while (cur.len > 0 and (cur[0] == 'K' or cur[0] == 'V' or cur[0] == 'R' or cur[0] == 'O')) {
            cur = cur[1..];
        }
        while (cur.len > 0 and cur[0] != 'E') {
            if (std.mem.startsWith(u8, cur, "St")) {
                try parts.append(allocator, "std");
                cur = cur[2..];
            } else if (std.mem.startsWith(u8, cur, "Sa")) {
                try parts.append(allocator, "std::allocator");
                cur = cur[2..];
            } else if (std.mem.startsWith(u8, cur, "Ss")) {
                try parts.append(allocator, "std::string");
                cur = cur[2..];
            } else if (std.mem.startsWith(u8, cur, "C1") or std.mem.startsWith(u8, cur, "C2")) {
                if (parts.items.len > 0) try parts.append(allocator, parts.items[parts.items.len - 1]);
                cur = cur[2..];
            } else if (std.mem.startsWith(u8, cur, "D1") or std.mem.startsWith(u8, cur, "D2") or std.mem.startsWith(u8, cur, "D0")) {
                try parts.append(allocator, "~dtor");
                cur = cur[2..];
            } else if (readItaniumLenIdent(&cur)) |ident| {
                try parts.append(allocator, ident);
            } else {
                break;
            }
        }
    } else if (std.mem.startsWith(u8, cur, "St")) {
        try parts.append(allocator, "std");
        cur = cur[2..];
        if (readItaniumLenIdent(&cur)) |ident| {
            try parts.append(allocator, ident);
        } else {
            return null;
        }
    } else if (readItaniumLenIdent(&cur)) |ident| {
        try parts.append(allocator, ident);
    } else {
        return null;
    }

    if (parts.items.len == 0) return null;

    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);
    for (parts.items, 0..) |p, idx| {
        if (idx > 0) try out.appendSlice(allocator, "::");
        try out.appendSlice(allocator, p);
    }
    try out.appendSlice(allocator, "(...)");
    return try out.toOwnedSlice(allocator);
}

fn demangleMsvc(allocator: std.mem.Allocator, body: []const u8) !?[]u8 {
    // Format: ?name@scope1@scope2@@...
    const term = std.mem.indexOf(u8, body, "@@") orelse return null;
    const header = body[0..term];
    if (header.len == 0) return null;

    var scopes = std.ArrayList([]const u8).empty;
    defer scopes.deinit(allocator);

    var it = std.mem.splitScalar(u8, header, '@');
    while (it.next()) |seg| {
        if (seg.len == 0) continue;
        if (std.mem.eql(u8, seg, "?0")) {
            try scopes.append(allocator, "{ctor}");
        } else if (std.mem.eql(u8, seg, "?1")) {
            try scopes.append(allocator, "{dtor}");
        } else {
            try scopes.append(allocator, seg);
        }
    }
    if (scopes.items.len == 0) return null;

    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);
    // MSVC puts innermost name first and outer namespaces afterwards
    var idx: usize = scopes.items.len;
    var first = true;
    while (idx > 1) {
        idx -= 1;
        if (!first) try out.appendSlice(allocator, "::");
        try out.appendSlice(allocator, scopes.items[idx]);
        first = false;
    }
    if (!first) try out.appendSlice(allocator, "::");
    try out.appendSlice(allocator, scopes.items[0]);
    try out.appendSlice(allocator, "(...)");
    return try out.toOwnedSlice(allocator);
}

/// Extract source file names referenced inside a DWARF v2-v4 `.debug_line` section if present.
pub fn extractDwarfSourceFiles(
    allocator: std.mem.Allocator,
    raw_bytes_in: []const u8,
    img: *const binary.BinaryImage,
) ![][]u8 {
    const raw_bytes = macho.unwrapFatSlice(raw_bytes_in);
    const sec = img.findSection(".debug_line") orelse img.findSection("__debug_line") orelse return try allocator.alloc([]u8, 0);
    const sec_end = @as(u64, sec.raw_offset) + @as(u64, sec.raw_size);
    if (sec_end > raw_bytes.len) return try allocator.alloc([]u8, 0);
    const data = raw_bytes[@as(usize, sec.raw_offset)..@as(usize, @intCast(sec_end))];

    var files = std.ArrayList([]u8).empty;
    errdefer {
        for (files.items) |f| allocator.free(f);
        files.deinit(allocator);
    }

    var seen = std.StringHashMap(void).init(allocator);
    defer seen.deinit();

    var off: usize = 0;
    var cu_guard: usize = 0;
    while (off + 12 <= data.len and cu_guard < 512) : (cu_guard += 1) {
        const unit_len32 = std.mem.readInt(u32, data[off..][0..4], .little);
        if (unit_len32 == 0 or unit_len32 == 0xFFFF_FFFF) break;
        const unit_end_u64 = @as(u64, off) + 4 + @as(u64, unit_len32);
        if (unit_end_u64 > data.len or @as(u64, off) + 15 > unit_end_u64) break;
        const unit_end: usize = @intCast(unit_end_u64);

        const version = std.mem.readInt(u16, data[off + 4 ..][0..2], .little);
        if (version < 2 or version > 4) {
            off = unit_end;
            continue;
        }
        const header_len = std.mem.readInt(u32, data[off + 6 ..][0..4], .little);
        var p: usize = off + 10;
        const hdr_end_u64 = @min(@as(u64, unit_end), @as(u64, p) + @as(u64, header_len));
        const hdr_end: usize = @intCast(hdr_end_u64);
        // Skip min_insn_len (1), max_ops (if v4: 1), default_is_stmt (1), line_base (1), line_range (1), opcode_base (1)
        const fixed_sz: usize = if (version >= 4) 6 else 5;
        if (p + fixed_sz > hdr_end) {
            off = unit_end;
            continue;
        }
        const opcode_base = data[p + fixed_sz - 1];
        p += fixed_sz;
        const std_opcode_cnt: usize = if (opcode_base > 0) opcode_base - 1 else 0;
        if (p + std_opcode_cnt > hdr_end) {
            off = unit_end;
            continue;
        }
        p += std_opcode_cnt;

        // Skip include directories list (null-terminated strings ending in empty string)
        var found_dir_term = false;
        var dir_guard: usize = 0;
        while (p < hdr_end and dir_guard < 256) : (dir_guard += 1) {
            if (data[p] == 0) {
                p += 1;
                found_dir_term = true;
                break;
            }
            const z = std.mem.indexOfScalarPos(u8, data[0..hdr_end], p, 0) orelse break;
            p = z + 1;
        }
        if (!found_dir_term) {
            off = unit_end;
            continue;
        }

        // Read file_names entries: name (null-terminated) + 3x ULEB128
        var file_guard: usize = 0;
        while (p < hdr_end and data[p] != 0 and file_guard < 512) : (file_guard += 1) {
            const z = std.mem.indexOfScalarPos(u8, data[0..hdr_end], p, 0) orelse break;
            const fname = data[p..z];
            p = z + 1;
            // Skip 3 ULEB128 integers (dir index, mtime, size)
            for (0..3) |_| {
                while (p < hdr_end and (data[p] & 0x80) != 0) p += 1;
                if (p < hdr_end) p += 1;
            }
            if (fname.len > 0 and !seen.contains(fname)) {
                const duped = try allocator.dupe(u8, fname);
                errdefer allocator.free(duped);
                try seen.put(duped, {});
                try files.append(allocator, duped);
            }
        }

        off = unit_end;
    }

    return files.toOwnedSlice(allocator);
}

pub fn runSymCommand(io: std.Io, allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len == 0) {
        std.debug.print("Usage: snap-oracle sym <binary> [rva_hex...] [--demangle] [--dwarf-files]\n", .{});
        return;
    }

    var bin_path: ?[]const u8 = null;
    var do_demangle = true;
    var show_dwarf = false;
    var queries = std.ArrayList(u32).empty;
    defer queries.deinit(allocator);

    for (args) |a| {
        if (std.mem.eql(u8, a, "--no-demangle")) {
            do_demangle = false;
        } else if (std.mem.eql(u8, a, "--demangle")) {
            do_demangle = true;
        } else if (std.mem.eql(u8, a, "--dwarf-files")) {
            show_dwarf = true;
        } else if (bin_path == null and a.len > 0 and a[0] != '-') {
            bin_path = a;
        } else if (a.len > 0 and a[0] != '-') {
            const cleaned = if (std.mem.startsWith(u8, a, "0x") or std.mem.startsWith(u8, a, "0X")) a[2..] else a;
            if (std.fmt.parseInt(u32, cleaned, 16)) |v| {
                try queries.append(allocator, v);
            } else |_| {}
        }
    }

    const path = bin_path orelse {
        std.debug.print("Usage: snap-oracle sym <binary> [rva_hex...] [--demangle] [--dwarf-files]\n", .{});
        return;
    };

    const raw = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(128 * 1024 * 1024));
    defer allocator.free(raw);

    var img = try binary.parseBinary(allocator, raw);
    defer img.deinit();

    var symtab = try SymbolTable.build(allocator, &img, raw, do_demangle);
    defer symtab.deinit();

    std.debug.print("=== Symbol Table: {s} ({s}/{s}, {d} symbols) ===\n", .{
        finding.basename(path),
        @tagName(img.format),
        @tagName(img.machine),
        symtab.entries.len,
    });

    if (queries.items.len > 0) {
        for (queries.items) |q| {
            const res = symtab.resolve(q);
            std.debug.print("  0x{x:0>8} -> {s}+0x{x}\n", .{ q, res.name, res.offset });
        }
    } else {
        const limit = @min(symtab.entries.len, 40);
        for (symtab.entries[0..limit]) |sym| {
            std.debug.print("  0x{x:0>8}  size={d:<6} {s}\n", .{ sym.rva, sym.size, sym.name });
        }
        if (symtab.entries.len > limit) {
            std.debug.print("  ... ({d} more symbols omitted; pass RVA hex args to resolve)\n", .{symtab.entries.len - limit});
        }
    }

    if (show_dwarf) {
        const srcs = try extractDwarfSourceFiles(allocator, raw, &img);
        defer {
            for (srcs) |s| allocator.free(s);
            allocator.free(srcs);
        }
        std.debug.print("DWARF .debug_line source files ({d}):\n", .{srcs.len});
        for (srcs[0..@min(srcs.len, 25)]) |s| {
            std.debug.print("  - {s}\n", .{s});
        }
    }
}
