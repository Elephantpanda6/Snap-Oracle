const std = @import("std");
const pe = @import("pe.zig");
const binary = @import("binary.zig");
const finding = @import("finding.zig");
const report = @import("report.zig");

pub const ImportedSymbol = struct {
    name: ?[]const u8,
    ordinal: ?u16,
    is_arm64ec_decorated: bool = false,
};

pub const ImportedModule = struct {
    name: []const u8,
    delay_loaded: bool = false,
    is_system: bool = false,
    symbols: []ImportedSymbol = &.{},
};

pub const MachoFatSlice = struct {
    cputype: u32,
    cpusubtype: u32,
    offset: u32,
    size: u32,
};

pub const ImportAnalysis = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    format: binary.BinaryFormat,
    machine: pe.Machine,
    is_arm64ec: bool,
    is_arm64x_hybrid: bool,
    has_chpe_metadata: bool,
    soname: ?[]const u8,
    rpaths: [][]const u8,
    modules: []ImportedModule,
    fat_slices: []MachoFatSlice,

    pub fn deinit(self: *ImportAnalysis) void {
        self.arena.deinit();
    }
};

pub fn isKnownSystemLib(name: []const u8) bool {
    const base = finding.basename(name);
    const sys_prefixes = [_][]const u8{
        "api-ms-win-",
        "ext-ms-win-",
        "/usr/lib/",
        "/system/library/",
        "@rpath/libswift",
        "ld-linux-",
        "libc.so",
        "libm.so",
        "libpthread.so",
        "libdl.so",
        "librt.so",
        "libstdc++.so",
        "libgcc_s.so",
        "libsystem.b.dylib",
    };
    for (sys_prefixes) |pfx| {
        if (name.len >= pfx.len and finding.eqlIgnoreCase(name[0..pfx.len], pfx)) return true;
        if (base.len >= pfx.len and finding.eqlIgnoreCase(base[0..pfx.len], pfx)) return true;
    }

    const win_sys = [_][]const u8{
        "kernel32.dll",
        "kernelbase.dll",
        "ntdll.dll",
        "user32.dll",
        "gdi32.dll",
        "advapi32.dll",
        "shell32.dll",
        "ole32.dll",
        "oleaut32.dll",
        "ws2_32.dll",
        "bcrypt.dll",
        "crypt32.dll",
        "ucrtbase.dll",
        "msvcrt.dll",
        "vcruntime140.dll",
        "vcruntime140_1.dll",
        "msvcp140.dll",
        "secur32.dll",
        "rpcrt4.dll",
        "shlwapi.dll",
        "winhttp.dll",
        "comctl32.dll",
    };
    for (win_sys) |dll| {
        if (finding.eqlIgnoreCase(base, dll)) return true;
    }
    return false;
}

fn readCStringBounded(slice: []const u8, max_len: usize) []const u8 {
    const bound = @min(slice.len, max_len);
    const end = std.mem.indexOfScalar(u8, slice[0..bound], 0) orelse bound;
    return slice[0..end];
}

pub fn analyzeImports(allocator: std.mem.Allocator, bytes: []const u8) !ImportAnalysis {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const aa = arena.allocator();

    // Handle Universal Mach-O Fat container upfront (32-bit 0xCAFEBABE and 64-bit 0xCAFEBABF)
    var fat_list = std.ArrayList(MachoFatSlice).empty;
    var active_bytes = bytes;
    if (bytes.len >= 8) {
        const be_magic = std.mem.readInt(u32, bytes[0..4], .big);
        if (be_magic == 0xCAFE_BABE or be_magic == 0xCAFE_BABF) {
            const is_64 = (be_magic == 0xCAFE_BABF);
            const entry_sz: usize = if (is_64) 32 else 20;
            const nfat = std.mem.readInt(u32, bytes[4..8], .big);
            const count = @min(nfat, 16);
            var arm64_slice: ?[]const u8 = null;
            var first_slice: ?[]const u8 = null;
            var i: u32 = 0;
            while (i < count) : (i += 1) {
                const off = 8 + @as(usize, i) * entry_sz;
                if (off + entry_sz > bytes.len) break;
                const cputype = std.mem.readInt(u32, bytes[off..][0..4], .big);
                const cpusubtype = std.mem.readInt(u32, bytes[off + 4 ..][0..4], .big);
                const slice_off: u64 = if (is_64)
                    std.mem.readInt(u64, bytes[off + 8 ..][0..8], .big)
                else
                    std.mem.readInt(u32, bytes[off + 8 ..][0..4], .big);
                const slice_sz: u64 = if (is_64)
                    std.mem.readInt(u64, bytes[off + 16 ..][0..8], .big)
                else
                    std.mem.readInt(u32, bytes[off + 12 ..][0..4], .big);
                try fat_list.append(aa, .{
                    .cputype = cputype,
                    .cpusubtype = cpusubtype,
                    .offset = @intCast(@min(slice_off, std.math.maxInt(u32))),
                    .size = @intCast(@min(slice_sz, std.math.maxInt(u32))),
                });
                if (slice_off >= 8 and slice_sz > 0) {
                    const slice_end = std.math.add(u64, slice_off, slice_sz) catch continue;
                    if (slice_end <= bytes.len) {
                        const sub = bytes[@intCast(slice_off)..@intCast(slice_end)];
                        if (first_slice == null) first_slice = sub;
                        if (cputype == 0x0100_000C and arm64_slice == null) arm64_slice = sub;
                    }
                }
            }
            if (arm64_slice orelse first_slice) |sel| {
                active_bytes = sel;
            }
        }
    }

    var img = try binary.parseBinary(allocator, active_bytes);
    defer img.deinit();

    var mod_list = std.ArrayList(ImportedModule).empty;
    var rpath_list = std.ArrayList([]const u8).empty;
    var soname: ?[]const u8 = null;
    var has_chpe = false;
    var is_hybrid = img.findSection(".a64xrm") != null;

    switch (img.format) {
        .pe32plus => {
            try parsePeImports(aa, active_bytes, &img, &mod_list, &has_chpe, &is_hybrid);
        },
        .elf64 => {
            try parseElfDynamics(aa, active_bytes, &img, &mod_list, &rpath_list, &soname);
        },
        .macho64 => {
            try parseMachoDylibs(aa, active_bytes, &mod_list, &rpath_list, &soname);
        },
    }

    const rpaths_owned = try rpath_list.toOwnedSlice(aa);
    const mods_owned = try mod_list.toOwnedSlice(aa);
    const fat_owned = try fat_list.toOwnedSlice(aa);

    return .{
        .allocator = allocator,
        .arena = arena,
        .format = img.format,
        .machine = img.machine,
        .is_arm64ec = img.is_arm64ec,
        .is_arm64x_hybrid = is_hybrid or (img.is_arm64ec and has_chpe),
        .has_chpe_metadata = has_chpe,
        .soname = soname,
        .rpaths = rpaths_owned,
        .modules = mods_owned,
        .fat_slices = fat_owned,
    };
}

fn parsePeImports(
    aa: std.mem.Allocator,
    bytes: []const u8,
    img: *const binary.BinaryImage,
    mods: *std.ArrayList(ImportedModule),
    has_chpe: *bool,
    is_hybrid: *bool,
) !void {
    if (bytes.len < 0x40) return;
    const e_lfanew = std.mem.readInt(u32, bytes[0x3C..][0..4], .little);
    const opt_off = @as(u64, e_lfanew) + 24;
    if (opt_off + 112 > bytes.len) return;
    const opt = bytes[@as(usize, @intCast(opt_off))..];
    const magic = std.mem.readInt(u16, opt[0..2], .little);
    if (magic != 0x20B) return; // PE32+
    const num_rvas = @min(std.mem.readInt(u32, opt[108..112], .little), 16);

    // DataDirectory[1]: Import Table
    if (num_rvas > 1 and opt.len >= 112 + 2 * 8) {
        const imp_rva = std.mem.readInt(u32, opt[112 + 8 ..][0..4], .little);
        if (imp_rva != 0) {
            if (img.rvaToOffset(imp_rva)) |imp_off| {
                var idx: usize = 0;
                while (idx < 4096) : (idx += 1) {
                    const desc_off = imp_off + idx * 20;
                    if (desc_off + 20 > bytes.len) break;
                    const ilt_rva = std.mem.readInt(u32, bytes[desc_off..][0..4], .little);
                    const name_rva = std.mem.readInt(u32, bytes[desc_off + 12 ..][0..4], .little);
                    const iat_rva = std.mem.readInt(u32, bytes[desc_off + 16 ..][0..4], .little);
                    if (ilt_rva == 0 and name_rva == 0 and iat_rva == 0) break;

                    const name_off = img.rvaToOffset(name_rva) orelse continue;
                    const dll_name = try aa.dupe(u8, readCStringBounded(bytes[name_off..], 256));
                    if (dll_name.len == 0) continue;

                    const thunk_rva = if (ilt_rva != 0) ilt_rva else iat_rva;
                    const syms = try parsePeThunks(aa, bytes, img, thunk_rva);
                    try mods.append(aa, .{
                        .name = dll_name,
                        .delay_loaded = false,
                        .is_system = isKnownSystemLib(dll_name),
                        .symbols = syms,
                    });
                }
            }
        }
    }

    // DataDirectory[13]: Delay-Load Imports
    if (num_rvas > 13 and opt.len >= 112 + 14 * 8) {
        const delay_rva = std.mem.readInt(u32, opt[112 + 13 * 8 ..][0..4], .little);
        if (delay_rva != 0) {
            if (img.rvaToOffset(delay_rva)) |d_off| {
                var idx: usize = 0;
                while (idx < 1024) : (idx += 1) {
                    const entry_off = d_off + idx * 32;
                    if (entry_off + 32 > bytes.len) break;
                    const attrs = std.mem.readInt(u32, bytes[entry_off..][0..4], .little);
                    const name_rva = std.mem.readInt(u32, bytes[entry_off + 4 ..][0..4], .little);
                    const int_rva = std.mem.readInt(u32, bytes[entry_off + 16 ..][0..4], .little);
                    if (name_rva == 0 and int_rva == 0) break;
                    if ((attrs & 1) == 0) continue; // non-RVA legacy format

                    const name_off = img.rvaToOffset(name_rva) orelse continue;
                    const dll_name = try aa.dupe(u8, readCStringBounded(bytes[name_off..], 256));
                    if (dll_name.len == 0) continue;
                    const syms = try parsePeThunks(aa, bytes, img, int_rva);
                    try mods.append(aa, .{
                        .name = dll_name,
                        .delay_loaded = true,
                        .is_system = isKnownSystemLib(dll_name),
                        .symbols = syms,
                    });
                }
            }
        }
    }

    // DataDirectory[10]: Load Config CHPEMetadataPointer (offset +200 in 64-bit LoadConfig)
    if (num_rvas > 10 and opt.len >= 112 + 11 * 8) {
        const lc_rva = std.mem.readInt(u32, opt[112 + 10 * 8 ..][0..4], .little);
        if (lc_rva != 0) {
            if (img.rvaToOffset(lc_rva)) |lc_off| {
                if (lc_off + 208 <= bytes.len) {
                    const lc_size = std.mem.readInt(u32, bytes[lc_off..][0..4], .little);
                    if (lc_size >= 208) {
                        const chpe_ptr = std.mem.readInt(u64, bytes[lc_off + 200 ..][0..8], .little);
                        if (chpe_ptr != 0) {
                            has_chpe.* = true;
                            is_hybrid.* = true;
                        }
                    }
                }
            }
        }
    }
}

fn parsePeThunks(
    aa: std.mem.Allocator,
    bytes: []const u8,
    img: *const binary.BinaryImage,
    thunk_rva: u32,
) ![]ImportedSymbol {
    var syms = std.ArrayList(ImportedSymbol).empty;
    if (thunk_rva == 0) return try syms.toOwnedSlice(aa);
    const base_off = img.rvaToOffset(thunk_rva) orelse return try syms.toOwnedSlice(aa);

    var i: usize = 0;
    while (i < 65536) : (i += 1) {
        const off = base_off + i * 8;
        if (off + 8 > bytes.len) break;
        const val = std.mem.readInt(u64, bytes[off..][0..8], .little);
        if (val == 0) break;

        if ((val & 0x8000_0000_0000_0000) != 0) {
            try syms.append(aa, .{
                .name = null,
                .ordinal = @truncate(val & 0xFFFF),
            });
        } else {
            const hint_rva: u32 = @truncate(val & 0x7FFF_FFFF);
            if (img.rvaToOffset(hint_rva)) |hint_off| {
                if (hint_off + 3 <= bytes.len) {
                    const raw_name = readCStringBounded(bytes[hint_off + 2 ..], 256);
                    const name = try aa.dupe(u8, raw_name);
                    try syms.append(aa, .{
                        .name = name,
                        .ordinal = null,
                        .is_arm64ec_decorated = name.len > 0 and name[0] == '#',
                    });
                }
            }
        }
    }
    return try syms.toOwnedSlice(aa);
}

fn parseElfDynamics(
    aa: std.mem.Allocator,
    bytes: []const u8,
    img: *const binary.BinaryImage,
    mods: *std.ArrayList(ImportedModule),
    rpaths: *std.ArrayList([]const u8),
    soname: *?[]const u8,
) !void {
    if (bytes.len < 64) return;
    const e_phoff = std.mem.readInt(u64, bytes[32..40], .little);
    const e_phentsize = std.mem.readInt(u16, bytes[54..56], .little);
    const e_phnum = std.mem.readInt(u16, bytes[56..58], .little);
    if (e_phoff == 0 or e_phentsize < 56 or e_phnum == 0) return;

    var dyn_off: usize = 0;
    var dyn_sz: usize = 0;
    const count = @min(e_phnum, 256);
    var i: u16 = 0;
    while (i < count) : (i += 1) {
        const ph_off = std.math.add(u64, e_phoff, @as(u64, i) * e_phentsize) catch break;
        const ph_end = std.math.add(u64, ph_off, 56) catch break;
        if (ph_end > bytes.len) break;
        const p_type = std.mem.readInt(u32, bytes[@as(usize, @intCast(ph_off))..][0..4], .little);
        if (p_type == 2) { // PT_DYNAMIC
            const p_offset = std.mem.readInt(u64, bytes[@as(usize, @intCast(ph_off + 8))..][0..8], .little);
            const p_filesz = std.mem.readInt(u64, bytes[@as(usize, @intCast(ph_off + 32))..][0..8], .little);
            const p_end = std.math.add(u64, p_offset, p_filesz) catch break;
            if (p_end <= bytes.len) {
                dyn_off = @intCast(p_offset);
                dyn_sz = @intCast(p_filesz);
            }
            break;
        }
    }
    if (dyn_off == 0 or dyn_sz < 16) return;

    // Resolve DT_STRTAB string table either via matching .dynstr section or DT_STRTAB vaddr
    var strtab: []const u8 = &.{};
    if (img.findSection(".dynstr")) |ds| {
        const ds_end = std.math.add(u64, ds.raw_offset, ds.raw_size) catch 0;
        if (ds.raw_size > 0 and ds_end <= bytes.len) {
            strtab = bytes[@as(usize, ds.raw_offset)..@as(usize, @intCast(ds_end))];
        }
    }

    var strtab_vaddr: u64 = 0;
    var strsz: u64 = 0;
    const max_ents = @min(dyn_sz / 16, 4096);
    var idx: usize = 0;
    while (idx < max_ents) : (idx += 1) {
        const off = dyn_off + idx * 16;
        const tag = std.mem.readInt(i64, bytes[off..][0..8], .little);
        const val = std.mem.readInt(u64, bytes[off + 8 ..][0..8], .little);
        if (tag == 0) break; // DT_NULL
        if (tag == 5) strtab_vaddr = val; // DT_STRTAB
        if (tag == 10) strsz = val; // DT_STRSZ
    }

    if (strtab.len == 0 and strtab_vaddr != 0) {
        const rel_u64 = strtab_vaddr -| img.image_base;
        if (rel_u64 <= std.math.maxInt(u32)) {
            const rel: u32 = @intCast(rel_u64);
            if (img.rvaToOffset(rel)) |so| {
                if (so < bytes.len) {
                    const end = @min(bytes.len, so + @as(usize, @intCast(@min(strsz, bytes.len - so))));
                    strtab = bytes[so..end];
                }
            }
        }
    }
    if (strtab.len == 0) return;

    idx = 0;
    while (idx < max_ents) : (idx += 1) {
        const off = dyn_off + idx * 16;
        const tag = std.mem.readInt(i64, bytes[off..][0..8], .little);
        const val = std.mem.readInt(u64, bytes[off + 8 ..][0..8], .little);
        if (tag == 0) break;
        if (val >= strtab.len) continue;
        const str = try aa.dupe(u8, readCStringBounded(strtab[@intCast(val)..], 256));
        if (str.len == 0) continue;

        switch (tag) {
            1 => { // DT_NEEDED
                try mods.append(aa, .{
                    .name = str,
                    .delay_loaded = false,
                    .is_system = isKnownSystemLib(str),
                });
            },
            14 => soname.* = str, // DT_SONAME
            15, 29 => try rpaths.append(aa, str), // DT_RPATH / DT_RUNPATH
            else => {},
        }
    }
}

fn parseMachoDylibs(
    aa: std.mem.Allocator,
    bytes: []const u8,
    mods: *std.ArrayList(ImportedModule),
    rpaths: *std.ArrayList([]const u8),
    soname: *?[]const u8,
) !void {
    if (bytes.len < 32) return;
    const magic = std.mem.readInt(u32, bytes[0..4], .little);
    if (magic != 0xFEED_FACF) return;
    const ncmds = @min(std.mem.readInt(u32, bytes[16..20], .little), 4096);
    var off: usize = 32;
    var i: u32 = 0;
    while (i < ncmds) : (i += 1) {
        if (off + 8 > bytes.len) break;
        const cmd = std.mem.readInt(u32, bytes[off..][0..4], .little);
        const cmdsize = std.mem.readInt(u32, bytes[off + 4 ..][0..4], .little);
        if (cmdsize < 8 or cmdsize > bytes.len - off) break;

        switch (cmd) {
            0x0C, 0x8000_0018, 0x8000_001F, 0x20 => { // LC_LOAD_*_DYLIB / LC_REEXPORT_DYLIB
                if (cmdsize >= 24) {
                    const str_off = std.mem.readInt(u32, bytes[off + 8 ..][0..4], .little);
                    if (str_off < cmdsize) {
                        const s = try aa.dupe(u8, readCStringBounded(bytes[off + str_off .. off + cmdsize], 512));
                        if (s.len > 0) {
                            try mods.append(aa, .{
                                .name = s,
                                .delay_loaded = (cmd == 0x20 or cmd == 0x8000_0018),
                                .is_system = isKnownSystemLib(s),
                            });
                        }
                    }
                }
            },
            0x0D => { // LC_ID_DYLIB
                if (cmdsize >= 24) {
                    const str_off = std.mem.readInt(u32, bytes[off + 8 ..][0..4], .little);
                    if (str_off < cmdsize) {
                        soname.* = try aa.dupe(u8, readCStringBounded(bytes[off + str_off .. off + cmdsize], 512));
                    }
                }
            },
            0x8000_001C => { // LC_RPATH
                if (cmdsize >= 12) {
                    const str_off = std.mem.readInt(u32, bytes[off + 8 ..][0..4], .little);
                    if (str_off < cmdsize) {
                        const s = try aa.dupe(u8, readCStringBounded(bytes[off + str_off .. off + cmdsize], 512));
                        if (s.len > 0) try rpaths.append(aa, s);
                    }
                }
            },
            else => {},
        }
        off += cmdsize;
    }
}

pub const CompatStatus = enum {
    ok,
    ec_bridge_ok,
    ec_mixed_warn,
    machine_mismatch,
};

pub fn checkArchCompatibility(
    parent_machine: pe.Machine,
    parent_ec: bool,
    child_machine: pe.Machine,
    child_ec: bool,
) CompatStatus {
    if (parent_ec) {
        // ARM64EC process can load ARM64EC and x64 DLLs directly via ABI thunks
        if (child_ec or child_machine == .amd64 or child_machine == .arm64ec) return .ec_bridge_ok;
        if (child_machine == .arm64) return .ec_mixed_warn;
        return .machine_mismatch;
    }
    if (parent_machine == .arm64) {
        if (child_machine == .arm64 and !child_ec) return .ok;
        if (child_ec or child_machine == .arm64ec) return .ec_mixed_warn;
        return .machine_mismatch;
    }
    if (parent_machine == child_machine) return .ok;
    return .machine_mismatch;
}

fn lowerBase(aa: std.mem.Allocator, name: []const u8) ![]u8 {
    const base = finding.basename(name);
    const out = try aa.alloc(u8, base.len);
    for (base, 0..) |c, i| out[i] = std.ascii.toLower(c);
    return out;
}

pub fn auditDependencies(
    io: std.Io,
    allocator: std.mem.Allocator,
    path: []const u8,
    bytes: []const u8,
    search_root: ?[]const u8,
    recursive: bool,
    out_fs: *finding.FindingSet,
) !ImportAnalysis {
    var analysis = try analyzeImports(allocator, bytes);
    errdefer analysis.deinit();

    const parent_dir = std.Io.Dir.path.dirname(path) orelse ".";
    const root_base = finding.basename(path);

    var bfs_arena = std.heap.ArenaAllocator.init(allocator);
    defer bfs_arena.deinit();
    const baa = bfs_arena.allocator();

    var visited = std.StringHashMap(void).init(allocator);
    defer visited.deinit();
    try visited.put(try lowerBase(baa, path), {});

    const QueueItem = struct {
        parent_name: []const u8,
        mod_name: []const u8,
        parent_machine: pe.Machine,
        parent_ec: bool,
        is_direct: bool,
    };
    var queue = std.ArrayList(QueueItem).empty;

    for (analysis.modules) |mod| {
        // Check ordinal-only PE imports
        var ordinal_cnt: usize = 0;
        for (mod.symbols) |s| {
            if (s.ordinal != null and s.name == null) ordinal_cnt += 1;
        }
        if (ordinal_cnt > 0) {
            const detail = try std.fmt.allocPrint(allocator, "{s} imports {d} ordinal-only function(s) from {s}", .{
                root_base,
                ordinal_cnt,
                mod.name,
            });
            defer allocator.free(detail);
            try out_fs.add(.{
                .rule_id = "SO-DEP-004",
                .artifact = path,
                .detail = detail,
                .func_name = mod.name,
            });
        }

        if (mod.is_system) continue;
        if (recursive and visited.count() >= 64) continue;

        const key = try lowerBase(baa, mod.name);
        if (visited.contains(key)) continue;
        try visited.put(key, {});
        try queue.append(baa, .{
            .parent_name = root_base,
            .mod_name = try baa.dupe(u8, mod.name),
            .parent_machine = analysis.machine,
            .parent_ec = analysis.is_arm64ec,
            .is_direct = true,
        });
    }

    var q_idx: usize = 0;
    while (q_idx < queue.items.len) : (q_idx += 1) {
        const item = queue.items[q_idx];

        const child_bytes = tryResolveDepFile(io, allocator, item.mod_name, parent_dir, search_root) catch |err| switch (err) {
            error.FileNotFound => {
                const detail = if (item.is_direct)
                    try std.fmt.allocPrint(allocator, "Non-system dependency '{s}' imported by '{s}' not found in parent dir or --root", .{
                        item.mod_name,
                        item.parent_name,
                    })
                else
                    try std.fmt.allocPrint(allocator, "Transitive non-system dependency '{s}' imported by '{s}' not found in parent dir or --root", .{
                        item.mod_name,
                        item.parent_name,
                    });
                defer allocator.free(detail);
                try out_fs.add(.{
                    .rule_id = "SO-DEP-003",
                    .artifact = path,
                    .detail = detail,
                    .func_name = item.mod_name,
                });
                continue;
            },
            else => continue,
        };
        defer allocator.free(child_bytes);

        if (!recursive) {
            var child_img = binary.parseBinary(allocator, child_bytes) catch continue;
            defer child_img.deinit();

            const compat = checkArchCompatibility(item.parent_machine, item.parent_ec, child_img.machine, child_img.is_arm64ec);
            switch (compat) {
                .machine_mismatch => {
                    const detail = try std.fmt.allocPrint(allocator, "{s} ({s}) cannot load incompatible {s} ({s})", .{
                        item.parent_name,
                        @tagName(item.parent_machine),
                        item.mod_name,
                        @tagName(child_img.machine),
                    });
                    defer allocator.free(detail);
                    try out_fs.add(.{
                        .rule_id = "SO-DEP-001",
                        .artifact = path,
                        .detail = detail,
                        .func_name = item.mod_name,
                    });
                },
                .ec_mixed_warn => {
                    const detail = try std.fmt.allocPrint(allocator, "ARM64EC / native ARM64 transition between {s} and {s}; verify ARM64X pure forwarders", .{
                        item.parent_name,
                        item.mod_name,
                    });
                    defer allocator.free(detail);
                    try out_fs.add(.{
                        .rule_id = "SO-DEP-002",
                        .artifact = path,
                        .detail = detail,
                        .func_name = item.mod_name,
                    });
                },
                .ok, .ec_bridge_ok => {},
            }
            continue;
        }

        var sub_analysis = analyzeImports(allocator, child_bytes) catch continue;
        defer sub_analysis.deinit();

        const compat = checkArchCompatibility(item.parent_machine, item.parent_ec, sub_analysis.machine, sub_analysis.is_arm64ec);
        switch (compat) {
            .machine_mismatch => {
                const detail = if (item.is_direct)
                    try std.fmt.allocPrint(allocator, "{s} ({s}) cannot load incompatible {s} ({s})", .{
                        item.parent_name,
                        @tagName(item.parent_machine),
                        item.mod_name,
                        @tagName(sub_analysis.machine),
                    })
                else
                    try std.fmt.allocPrint(allocator, "Transitive mismatch: {s} -> {s} ({s}) -> {s} ({s})", .{
                        root_base,
                        item.parent_name,
                        @tagName(item.parent_machine),
                        item.mod_name,
                        @tagName(sub_analysis.machine),
                    });
                defer allocator.free(detail);
                try out_fs.add(.{
                    .rule_id = "SO-DEP-001",
                    .artifact = path,
                    .detail = detail,
                    .func_name = item.mod_name,
                });
            },
            .ec_mixed_warn => {
                const detail = try std.fmt.allocPrint(allocator, "ARM64EC / native ARM64 transition between {s} and {s}; verify ARM64X pure forwarders", .{
                    item.parent_name,
                    item.mod_name,
                });
                defer allocator.free(detail);
                try out_fs.add(.{
                    .rule_id = "SO-DEP-002",
                    .artifact = path,
                    .detail = detail,
                    .func_name = item.mod_name,
                });
            },
            .ok, .ec_bridge_ok => {},
        }

        for (sub_analysis.modules) |sub_mod| {
            if (sub_mod.is_system) continue;
            if (visited.count() >= 64) break;
            const sub_key = try lowerBase(baa, sub_mod.name);
            if (visited.contains(sub_key)) continue;
            try visited.put(sub_key, {});
            try queue.append(baa, .{
                .parent_name = item.mod_name,
                .mod_name = try baa.dupe(u8, sub_mod.name),
                .parent_machine = sub_analysis.machine,
                .parent_ec = sub_analysis.is_arm64ec,
                .is_direct = false,
            });
        }
    }

    return analysis;
}

fn tryResolveDepFile(
    io: std.Io,
    allocator: std.mem.Allocator,
    dep_name: []const u8,
    parent_dir: []const u8,
    search_root: ?[]const u8,
) ![]u8 {
    const base = finding.basename(dep_name);
    const p1 = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ parent_dir, base });
    defer allocator.free(p1);
    if (std.Io.Dir.cwd().readFileAlloc(io, p1, allocator, .limited(64 * 1024 * 1024))) |bytes| {
        return bytes;
    } else |_| {}

    if (search_root) |root| {
        const p2 = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ root, base });
        defer allocator.free(p2);
        if (std.Io.Dir.cwd().readFileAlloc(io, p2, allocator, .limited(64 * 1024 * 1024))) |bytes| {
            return bytes;
        } else |_| {}
    }

    return error.FileNotFound;
}

pub fn runDepsCommand(io: std.Io, allocator: std.mem.Allocator, args: []const []const u8) !u8 {
    if (args.len == 0) {
        std.debug.print("Usage: snap-oracle deps <binary> [--root <dir>] [--recursive] [--format text|json|sarif|junit|gha] [--out <file>] [--fail-on <sev>]\n", .{});
        return 2;
    }

    var path: ?[]const u8 = null;
    var root: ?[]const u8 = null;
    var recursive = false;
    var fmt: report.ReportFormat = .text;
    var out_path: ?[]const u8 = null;
    var fail_on: finding.Severity = .high;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--root") and i + 1 < args.len) {
            i += 1;
            root = args[i];
        } else if (std.mem.eql(u8, a, "--recursive")) {
            recursive = true;
        } else if (std.mem.eql(u8, a, "--format") and i + 1 < args.len) {
            i += 1;
            fmt = report.ReportFormat.fromString(args[i]) orelse .text;
        } else if (std.mem.eql(u8, a, "--out") and i + 1 < args.len) {
            i += 1;
            out_path = args[i];
        } else if (std.mem.eql(u8, a, "--fail-on") and i + 1 < args.len) {
            i += 1;
            fail_on = finding.Severity.fromString(args[i]) orelse .high;
        } else if (path == null and a.len > 0 and a[0] != '-') {
            path = a;
        }
    }

    const bin_path = path orelse {
        std.debug.print("Usage: snap-oracle deps <binary> [--root <dir>] [--recursive]\n", .{});
        return 2;
    };

    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, bin_path, allocator, .limited(128 * 1024 * 1024));
    defer allocator.free(bytes);

    var fs = finding.FindingSet.init(allocator);
    defer fs.deinit();

    var analysis = try auditDependencies(io, allocator, bin_path, bytes, root, recursive, &fs);
    defer analysis.deinit();

    if (fmt == .text) {
        std.debug.print(
            \\=== Dependency & Mixed-Arch ABI Analysis: {s} ===
            \\Format: {s} | Arch: {s} | ARM64EC: {any} | ARM64X Hybrid: {any} | CHPE: {any}
            \\Imported Modules ({d}):
            \\
        , .{
            finding.basename(bin_path),
            @tagName(analysis.format),
            @tagName(analysis.machine),
            analysis.is_arm64ec,
            analysis.is_arm64x_hybrid,
            analysis.has_chpe_metadata,
            analysis.modules.len,
        });
        for (analysis.modules) |m| {
            std.debug.print("  - {s:<32} syms={d:<4} {s}{s}\n", .{
                m.name,
                m.symbols.len,
                if (m.is_system) "[system] " else "[local]  ",
                if (m.delay_loaded) "[delay-load]" else "",
            });
        }
        if (analysis.fat_slices.len > 0) {
            std.debug.print("Mach-O Universal Fat Slices ({d}):\n", .{analysis.fat_slices.len});
            for (analysis.fat_slices) |s| {
                std.debug.print("  - cputype=0x{x:0>8} offset=0x{x} size={d}\n", .{ s.cputype, s.offset, s.size });
            }
        }
        std.debug.print("\n", .{});
    }

    try report.emitOrPrint(io, allocator, &fs, fmt, out_path, bytes);
    return fs.exitCode(fail_on);
}
