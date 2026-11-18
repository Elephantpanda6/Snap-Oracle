const std = @import("std");
const binary = @import("binary.zig");
const pe = @import("pe.zig");
const imports = @import("imports.zig");
const finding = @import("finding.zig");

pub const SbomFormat = enum {
    cyclonedx,
    spdx,
    text,

    pub fn fromString(s: []const u8) ?SbomFormat {
        if (finding.eqlIgnoreCase(s, "cyclonedx") or finding.eqlIgnoreCase(s, "cdx")) return .cyclonedx;
        if (finding.eqlIgnoreCase(s, "spdx")) return .spdx;
        if (finding.eqlIgnoreCase(s, "text")) return .text;
        return null;
    }
};

pub const ComponentKind = enum {
    embedded_library,
    dynamic_dependency,
};

pub const SbomComponent = struct {
    name: []const u8,
    purl_name: []const u8,
    version: []const u8,
    kind: ComponentKind,
    evidence: []const u8,
    file_offset: ?u32 = null,
};

pub const Provenance = struct {
    build_id: ?[]const u8 = null,
    pdb_path: ?[]const u8 = null,
    compiler_comment: ?[]const u8 = null,
    pe_timestamp: ?u32 = null,
    rich_entries: usize = 0,
    macho_minos: ?[]const u8 = null,
};

pub const SbomReport = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    artifact_name: []const u8,
    sha256_hex: [64]u8,
    format: binary.BinaryFormat,
    machine: pe.Machine,
    provenance: Provenance,
    components: []SbomComponent,

    pub fn deinit(self: *SbomReport) void {
        self.arena.deinit();
    }
};

const SignatureDef = struct {
    display_name: []const u8,
    purl_name: []const u8,
    needle: []const u8,
};

const COMPONENT_SIGS = [_]SignatureDef{
    .{ .display_name = "OpenSSL", .purl_name = "openssl", .needle = "OpenSSL " },
    .{ .display_name = "BoringSSL", .purl_name = "boringssl", .needle = "BoringSSL" },
    .{ .display_name = "zlib", .purl_name = "zlib", .needle = "inflate 1." },
    .{ .display_name = "zlib", .purl_name = "zlib", .needle = "deflate 1." },
    .{ .display_name = "zstd", .purl_name = "zstd", .needle = "ZSTD_" },
    .{ .display_name = "SQLite", .purl_name = "sqlite", .needle = "SQLite format 3" },
    .{ .display_name = "libpng", .purl_name = "libpng", .needle = "libpng version " },
    .{ .display_name = "libjpeg-turbo", .purl_name = "libjpeg-turbo", .needle = "libjpeg-turbo" },
    .{ .display_name = "libcurl", .purl_name = "curl", .needle = "libcurl/" },
    .{ .display_name = "FreeType", .purl_name = "freetype", .needle = "FreeType" },
    .{ .display_name = "ONNX Runtime", .purl_name = "onnxruntime", .needle = "ONNX Runtime" },
    .{ .display_name = "llama.cpp", .purl_name = "llama.cpp", .needle = "llama_model_load" },
    .{ .display_name = "ggml", .purl_name = "ggml", .needle = "ggml_" },
    .{ .display_name = "Protobuf", .purl_name = "protobuf", .needle = "google.protobuf." },
    .{ .display_name = "PCRE2", .purl_name = "pcre2", .needle = "pcre2_" },
    .{ .display_name = "mbedTLS", .purl_name = "mbedtls", .needle = "mbed TLS " },
};

fn extractVersionAfter(haystack: []const u8, start: usize) []const u8 {
    var i = start;
    const scan_limit = @min(haystack.len, start + 32);
    // Advance until first ASCII digit if close
    while (i < scan_limit and !std.ascii.isDigit(haystack[i])) : (i += 1) {
        if (haystack[i] == 0 or haystack[i] == '\n') return "unknown";
    }
    if (i >= scan_limit) return "unknown";
    const v_start = i;
    var dots: usize = 0;
    while (i < scan_limit) : (i += 1) {
        const c = haystack[i];
        if (std.ascii.isDigit(c)) continue;
        if (c == '.') {
            dots += 1;
            continue;
        }
        if (std.ascii.isAlphabetic(c) and dots >= 1 and i > v_start) {
            i += 1;
        }
        break;
    }
    if (dots == 0 or i <= v_start) return "unknown";
    const cand = haystack[v_start..i];
    if (cand[cand.len - 1] == '.') return "unknown";
    return cand;
}

pub fn buildSbom(allocator: std.mem.Allocator, path: []const u8, bytes: []const u8) !SbomReport {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const aa = arena.allocator();

    var img = try binary.parseBinary(allocator, bytes);
    defer img.deinit();

    var prov = Provenance{};
    switch (img.format) {
        .pe32plus => try extractPeProvenance(aa, bytes, &img, &prov),
        .elf64 => try extractElfProvenance(aa, bytes, &img, &prov),
        .macho64 => try extractMachoProvenance(aa, bytes, &prov),
    }

    var comp_list = std.ArrayList(SbomComponent).empty;
    var seen_keys = std.StringHashMap(void).init(allocator);
    defer seen_keys.deinit();

    // 1. Fingerprint embedded native libraries
    for (COMPONENT_SIGS) |sig| {
        if (seen_keys.contains(sig.purl_name)) continue;
        if (std.mem.indexOf(u8, bytes, sig.needle)) |pos| {
            const ver_raw = extractVersionAfter(bytes, pos + sig.needle.len);
            const ver = try aa.dupe(u8, ver_raw);
            try seen_keys.put(sig.purl_name, {});
            try comp_list.append(aa, .{
                .name = sig.display_name,
                .purl_name = sig.purl_name,
                .version = ver,
                .kind = .embedded_library,
                .evidence = sig.needle,
                .file_offset = @intCast(@min(pos, std.math.maxInt(u32))),
            });
        }
    }

    // 2. Include dynamic shared library imports
    var imp_analysis = try imports.analyzeImports(allocator, bytes);
    defer imp_analysis.deinit();
    for (imp_analysis.modules) |mod| {
        const clean_base = finding.basename(mod.name);
        if (seen_keys.contains(clean_base)) continue;
        const name_dup = try aa.dupe(u8, clean_base);
        const lower = try aa.alloc(u8, clean_base.len);
        for (clean_base, 0..) |c, i| lower[i] = std.ascii.toLower(c);
        try seen_keys.put(name_dup, {});
        try comp_list.append(aa, .{
            .name = name_dup,
            .purl_name = lower,
            .version = if (mod.is_system) "os-runtime" else "unspecified",
            .kind = .dynamic_dependency,
            .evidence = if (mod.delay_loaded) "delay-import" else "dynamic-import",
        });
    }

    const owned = try comp_list.toOwnedSlice(aa);
    std.mem.sort(SbomComponent, owned, {}, struct {
        fn lessThan(_: void, a: SbomComponent, b: SbomComponent) bool {
            return std.mem.lessThan(u8, a.purl_name, b.purl_name);
        }
    }.lessThan);

    return .{
        .allocator = allocator,
        .arena = arena,
        .artifact_name = try aa.dupe(u8, finding.basename(path)),
        .sha256_hex = finding.sha256Hex(bytes),
        .format = img.format,
        .machine = img.machine,
        .provenance = prov,
        .components = owned,
    };
}

fn extractPeProvenance(aa: std.mem.Allocator, bytes: []const u8, img: *const binary.BinaryImage, prov: *Provenance) !void {
    if (bytes.len < 0x40) return;
    const e_lfanew = std.mem.readInt(u32, bytes[0x3C..][0..4], .little);
    const coff_off = @as(u64, e_lfanew) + 4;
    if (coff_off + 20 > bytes.len) return;
    prov.pe_timestamp = std.mem.readInt(u32, bytes[@intCast(coff_off + 4)..][0..4], .little);

    // Rich Header XOR scan inside DOS stub
    if (e_lfanew > 0x80 and e_lfanew <= bytes.len) {
        const stub = bytes[0x40..e_lfanew];
        if (std.mem.indexOf(u8, stub, "Rich")) |rich_pos| {
            if (rich_pos + 8 <= stub.len) {
                const key = std.mem.readInt(u32, stub[rich_pos + 4 ..][0..4], .little);
                var p: usize = 0;
                while (p + 16 <= rich_pos) : (p += 4) {
                    const dec = std.mem.readInt(u32, stub[p..][0..4], .little) ^ key;
                    if (dec == 0x536E_6144) { // "DanS"
                        const body_len = rich_pos - (p + 16);
                        prov.rich_entries = body_len / 8;
                        break;
                    }
                }
            }
        }
    }

    // DataDirectory[6]: Debug Directory -> RSDS PDB + GUID
    const opt_off = @as(u64, e_lfanew) + 24;
    if (opt_off + 112 + 7 * 8 <= bytes.len) {
        const opt = bytes[@intCast(opt_off)..];
        const num_rvas = std.mem.readInt(u32, opt[108..112], .little);
        if (num_rvas > 6) {
            const dbg_rva = std.mem.readInt(u32, opt[112 + 6 * 8 ..][0..4], .little);
            const dbg_sz = std.mem.readInt(u32, opt[112 + 6 * 8 + 4 ..][0..4], .little);
            if (dbg_rva != 0 and dbg_sz >= 28) {
                if (img.rvaToOffset(dbg_rva)) |d_off| {
                    const cnt = @min(dbg_sz / 28, 32);
                    var k: usize = 0;
                    while (k < cnt) : (k += 1) {
                        const ent = d_off + k * 28;
                        if (ent + 28 > bytes.len) break;
                        const dbg_type = std.mem.readInt(u32, bytes[ent + 12 ..][0..4], .little);
                        const ptr_raw = std.mem.readInt(u32, bytes[ent + 24 ..][0..4], .little);
                        const sz_data = std.mem.readInt(u32, bytes[ent + 16 ..][0..4], .little);
                        if (dbg_type == 2 and sz_data >= 25 and @as(u64, ptr_raw) + sz_data <= bytes.len) {
                            const cv = bytes[ptr_raw .. ptr_raw + sz_data];
                            if (std.mem.eql(u8, cv[0..4], "RSDS")) {
                                const tail = cv[24..];
                                const z = std.mem.indexOfScalar(u8, tail, 0) orelse tail.len;
                                prov.pdb_path = try aa.dupe(u8, tail[0..z]);
                                const hex = "0123456789abcdef";
                                var guid_hex: [32]u8 = undefined;
                                for (cv[4..20], 0..) |b, gi| {
                                    guid_hex[gi * 2] = hex[b >> 4];
                                    guid_hex[gi * 2 + 1] = hex[b & 0xF];
                                }
                                prov.build_id = try aa.dupe(u8, &guid_hex);
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
}

fn extractElfProvenance(aa: std.mem.Allocator, bytes: []const u8, img: *const binary.BinaryImage, prov: *Provenance) !void {
    if (img.findSection(".note.gnu.build-id")) |sec| {
        if (@as(u64, sec.raw_offset) + sec.raw_size <= bytes.len and sec.raw_size >= 16) {
            const note = bytes[sec.raw_offset .. sec.raw_offset + sec.raw_size];
            const namesz = std.mem.readInt(u32, note[0..4], .little);
            const descsz = std.mem.readInt(u32, note[4..8], .little);
            const ntype = std.mem.readInt(u32, note[8..12], .little);
            const desc_off = 12 + ((namesz + 3) & ~@as(u32, 3));
            if (ntype == 3 and @as(u64, desc_off) + descsz <= note.len and descsz <= 64) {
                const raw_id = note[desc_off .. desc_off + descsz];
                const hex = "0123456789abcdef";
                const out = try aa.alloc(u8, raw_id.len * 2);
                for (raw_id, 0..) |b, idx| {
                    out[idx * 2] = hex[b >> 4];
                    out[idx * 2 + 1] = hex[b & 0xF];
                }
                prov.build_id = out;
            }
        }
    }
    if (img.findSection(".comment")) |sec| {
        if (@as(u64, sec.raw_offset) + sec.raw_size <= bytes.len and sec.raw_size > 0) {
            const raw_c = bytes[sec.raw_offset .. sec.raw_offset + sec.raw_size];
            const z = std.mem.indexOfScalar(u8, raw_c, 0) orelse @min(raw_c.len, 160);
            if (z > 0) prov.compiler_comment = try aa.dupe(u8, raw_c[0..@min(z, 160)]);
        }
    }
}

fn extractMachoProvenance(aa: std.mem.Allocator, bytes: []const u8, prov: *Provenance) !void {
    if (bytes.len < 32 or std.mem.readInt(u32, bytes[0..4], .little) != 0xFEED_FACF) return;
    const ncmds = @min(std.mem.readInt(u32, bytes[16..20], .little), 4096);
    var off: usize = 32;
    var i: u32 = 0;
    while (i < ncmds) : (i += 1) {
        if (off + 8 > bytes.len) break;
        const cmd = std.mem.readInt(u32, bytes[off..][0..4], .little);
        const cmdsize = std.mem.readInt(u32, bytes[off + 4 ..][0..4], .little);
        if (cmdsize < 8 or off + cmdsize > bytes.len) break;
        if (cmd == 0x1B and cmdsize >= 24) { // LC_UUID
            const hex = "0123456789abcdef";
            const out = try aa.alloc(u8, 32);
            for (bytes[off + 8 .. off + 24], 0..) |b, idx| {
                out[idx * 2] = hex[b >> 4];
                out[idx * 2 + 1] = hex[b & 0xF];
            }
            prov.build_id = out;
        } else if (cmd == 0x32 and cmdsize >= 24) { // LC_BUILD_VERSION
            const minos = std.mem.readInt(u32, bytes[off + 12 ..][0..4], .little);
            prov.macho_minos = try std.fmt.allocPrint(aa, "{d}.{d}.{d}", .{
                (minos >> 16) & 0xFFFF,
                (minos >> 8) & 0xFF,
                minos & 0xFF,
            });
        }
        off += cmdsize;
    }
}

pub fn renderSbom(allocator: std.mem.Allocator, sbom: *const SbomReport, fmt: SbomFormat) ![]u8 {
    return switch (fmt) {
        .cyclonedx => renderCycloneDx(allocator, sbom),
        .spdx => renderSpdx(allocator, sbom),
        .text => renderText(allocator, sbom),
    };
}

fn renderText(allocator: std.mem.Allocator, sbom: *const SbomReport) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);
    const hdr = try std.fmt.allocPrint(allocator,
        \\=== ARM64 Binary SBOM & Build Provenance: {s} ===
        \\Format: {s} ({s}) | SHA-256: {s}
        \\Build ID: {s} | PDB: {s} | Compiler: {s} | Rich Entries: {d}
        \\Components Detected ({d}):
        \\
    , .{
        sbom.artifact_name,
        @tagName(sbom.format),
        @tagName(sbom.machine),
        sbom.sha256_hex,
        sbom.provenance.build_id orelse "none",
        sbom.provenance.pdb_path orelse "none",
        sbom.provenance.compiler_comment orelse (sbom.provenance.macho_minos orelse "none"),
        sbom.provenance.rich_entries,
        sbom.components.len,
    });
    defer allocator.free(hdr);
    try out.appendSlice(allocator, hdr);

    for (sbom.components) |c| {
        const line = try std.fmt.allocPrint(allocator, "  - {s:<18} ver={s:<14} kind={s:<18} purl=pkg:generic/{s}@{s}\n", .{
            c.name,
            c.version,
            @tagName(c.kind),
            c.purl_name,
            c.version,
        });
        defer allocator.free(line);
        try out.appendSlice(allocator, line);
    }
    return out.toOwnedSlice(allocator);
}

fn renderCycloneDx(allocator: std.mem.Allocator, sbom: *const SbomReport) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);

    const h = sbom.sha256_hex;
    const serial = try std.fmt.allocPrint(allocator, "urn:uuid:{s}-{s}-4{s}-8{s}-{s}", .{
        h[0..8],
        h[8..12],
        h[13..16],
        h[17..20],
        h[20..32],
    });
    defer allocator.free(serial);

    try out.appendSlice(allocator, "{\n  \"bomFormat\": \"CycloneDX\",\n  \"specVersion\": \"1.5\",\n  \"serialNumber\": ");
    try finding.appendJsonEscaped(&out, allocator, serial);
    try out.appendSlice(allocator, ",\n  \"version\": 1,\n  \"metadata\": {\n    \"tools\": [{ \"name\": ");
    try finding.appendJsonEscaped(&out, allocator, finding.TOOL_NAME);
    try out.appendSlice(allocator, ", \"version\": ");
    try finding.appendJsonEscaped(&out, allocator, finding.TOOL_VERSION);
    try out.appendSlice(allocator, " }],\n    \"component\": {\n      \"type\": \"application\",\n      \"bom-ref\": \"root-artifact\",\n      \"name\": ");
    try finding.appendJsonEscaped(&out, allocator, sbom.artifact_name);
    try out.appendSlice(allocator, ",\n      \"hashes\": [{ \"alg\": \"SHA-256\", \"content\": ");
    try finding.appendJsonEscaped(&out, allocator, &sbom.sha256_hex);
    try out.appendSlice(allocator, " }]");
    if (sbom.provenance.build_id) |bid| {
        try out.appendSlice(allocator, ",\n      \"properties\": [{ \"name\": \"snap-oracle:build-id\", \"value\": ");
        try finding.appendJsonEscaped(&out, allocator, bid);
        try out.appendSlice(allocator, " }]");
    }
    try out.appendSlice(allocator, "\n    }\n  },\n  \"components\": [\n");

    for (sbom.components, 0..) |c, i| {
        if (i > 0) try out.appendSlice(allocator, ",\n");
        const purl = try std.fmt.allocPrint(allocator, "pkg:generic/{s}@{s}", .{ c.purl_name, c.version });
        defer allocator.free(purl);
        try out.appendSlice(allocator, "    {\n      \"type\": \"library\",\n      \"bom-ref\": ");
        try finding.appendJsonEscaped(&out, allocator, purl);
        try out.appendSlice(allocator, ",\n      \"name\": ");
        try finding.appendJsonEscaped(&out, allocator, c.name);
        try out.appendSlice(allocator, ",\n      \"version\": ");
        try finding.appendJsonEscaped(&out, allocator, c.version);
        try out.appendSlice(allocator, ",\n      \"purl\": ");
        try finding.appendJsonEscaped(&out, allocator, purl);
        try out.appendSlice(allocator, "\n    }");
    }
    try out.appendSlice(allocator, "\n  ],\n  \"dependencies\": [{\n    \"ref\": \"root-artifact\",\n    \"dependsOn\": [");
    for (sbom.components, 0..) |c, i| {
        if (i > 0) try out.appendSlice(allocator, ", ");
        const purl = try std.fmt.allocPrint(allocator, "pkg:generic/{s}@{s}", .{ c.purl_name, c.version });
        defer allocator.free(purl);
        try finding.appendJsonEscaped(&out, allocator, purl);
    }
    try out.appendSlice(allocator, "]\n  }]\n}\n");
    return out.toOwnedSlice(allocator);
}

fn renderSpdx(allocator: std.mem.Allocator, sbom: *const SbomReport) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);

    try out.appendSlice(allocator, "{\n  \"spdxVersion\": \"SPDX-2.3\",\n  \"dataLicense\": \"CC0-1.0\",\n  \"SPDXID\": \"SPDXRef-DOCUMENT\",\n  \"name\": ");
    try finding.appendJsonEscaped(&out, allocator, sbom.artifact_name);
    const ns = try std.fmt.allocPrint(allocator, "https://snap-oracle.local/spdx/{s}", .{sbom.sha256_hex[0..16]});
    defer allocator.free(ns);
    try out.appendSlice(allocator, ",\n  \"documentNamespace\": ");
    try finding.appendJsonEscaped(&out, allocator, ns);
    try out.appendSlice(allocator, ",\n  \"packages\": [\n    {\n      \"SPDXID\": \"SPDXRef-Package-Root\",\n      \"name\": ");
    try finding.appendJsonEscaped(&out, allocator, sbom.artifact_name);
    try out.appendSlice(allocator, ",\n      \"downloadLocation\": \"NOASSERTION\",\n      \"checksums\": [{ \"algorithm\": \"SHA256\", \"checksumValue\": ");
    try finding.appendJsonEscaped(&out, allocator, &sbom.sha256_hex);
    try out.appendSlice(allocator, " }]\n    }");

    for (sbom.components, 0..) |c, i| {
        const spdx_id = try std.fmt.allocPrint(allocator, "SPDXRef-Comp-{d}", .{i});
        defer allocator.free(spdx_id);
        try out.appendSlice(allocator, ",\n    {\n      \"SPDXID\": ");
        try finding.appendJsonEscaped(&out, allocator, spdx_id);
        try out.appendSlice(allocator, ",\n      \"name\": ");
        try finding.appendJsonEscaped(&out, allocator, c.name);
        try out.appendSlice(allocator, ",\n      \"versionInfo\": ");
        try finding.appendJsonEscaped(&out, allocator, c.version);
        try out.appendSlice(allocator, ",\n      \"downloadLocation\": \"NOASSERTION\"\n    }");
    }
    try out.appendSlice(allocator, "\n  ]\n}\n");
    return out.toOwnedSlice(allocator);
}

pub fn runSbomCommand(io: std.Io, allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len == 0) {
        std.debug.print("Usage: snap-oracle sbom <binary> [--format cyclonedx|spdx|text] [--out <file>]\n", .{});
        return;
    }

    var bin_path: ?[]const u8 = null;
    var fmt: SbomFormat = .text;
    var out_path: ?[]const u8 = null;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--format") and i + 1 < args.len) {
            i += 1;
            fmt = SbomFormat.fromString(args[i]) orelse .text;
        } else if (std.mem.eql(u8, a, "--out") and i + 1 < args.len) {
            i += 1;
            out_path = args[i];
        } else if (bin_path == null and a.len > 0 and a[0] != '-') {
            bin_path = a;
        }
    }

    const path = bin_path orelse {
        std.debug.print("Usage: snap-oracle sbom <binary> [--format cyclonedx|spdx|text] [--out <file>]\n", .{});
        return;
    };

    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(128 * 1024 * 1024));
    defer allocator.free(bytes);

    var sbom = try buildSbom(allocator, path, bytes);
    defer sbom.deinit();

    const rendered = try renderSbom(allocator, &sbom, fmt);
    defer allocator.free(rendered);

    if (out_path) |p| {
        try finding.writeOutputFile(io, p, rendered);
        std.debug.print("[sbom] wrote {s} SBOM ({d} components) to {s}\n", .{ @tagName(fmt), sbom.components.len, p });
    } else {
        finding.writeStdout(io, rendered);
    }
}
