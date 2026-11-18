const std = @import("std");
const binary = @import("binary.zig");
const cfg = @import("cfg.zig");
const coverage = @import("coverage.zig");
const l1 = @import("l1_engine.zig");
const dll_snapshot = @import("dll_snapshot.zig");
const runner = @import("runner.zig");
const veh = @import("veh.zig");
const symbols = @import("symbols.zig");
const finding = @import("finding.zig");

pub const CovFormat = enum {
    html,
    json,
    lcov,
    drcov,

    pub fn fromString(s: []const u8) ?CovFormat {
        if (finding.eqlIgnoreCase(s, "html")) return .html;
        if (finding.eqlIgnoreCase(s, "json")) return .json;
        if (finding.eqlIgnoreCase(s, "lcov")) return .lcov;
        if (finding.eqlIgnoreCase(s, "drcov")) return .drcov;
        return null;
    }
};

pub const BlockRecord = struct {
    rva: u32,
    size: u16,
    func_rva: u32,
    hits: u32,
};

pub const FuncCov = struct {
    name: []const u8,
    rva: u32,
    total_blocks: usize,
    hit_blocks: usize,
};

pub const CovReport = struct {
    allocator: std.mem.Allocator,
    artifact: []const u8,
    image_base: u64,
    size_of_image: u32,
    entry_rva: u32,
    seeds_executed: usize,
    blocks: []BlockRecord,
    functions: []FuncCov,

    pub fn deinit(self: *CovReport) void {
        for (self.functions) |f| self.allocator.free(f.name);
        self.allocator.free(self.blocks);
        self.allocator.free(self.functions);
    }

    pub fn hitBlockCount(self: *const CovReport) usize {
        var n: usize = 0;
        for (self.blocks) |b| if (b.hits > 0) {
            n += 1;
        };
        return n;
    }
};

pub fn buildCoverageReport(
    allocator: std.mem.Allocator,
    path: []const u8,
    image_bytes: []const u8,
    img: *const binary.BinaryImage,
    blocks: []const cfg.BasicBlock,
    hits: []const u32,
    seeds_executed: usize,
) !CovReport {
    var symtab = try symbols.SymbolTable.build(allocator, img, image_bytes, true);
    defer symtab.deinit();

    // Sort indices by RVA so block sizes match sequential gaps inside functions
    const idx_buf = try allocator.alloc(usize, blocks.len);
    defer allocator.free(idx_buf);
    for (idx_buf, 0..) |*slot, i| slot.* = i;
    std.mem.sort(usize, idx_buf, blocks, struct {
        fn less(ctx: []const cfg.BasicBlock, a: usize, b: usize) bool {
            return ctx[a].rva < ctx[b].rva;
        }
    }.less);

    var recs = try allocator.alloc(BlockRecord, blocks.len);
    errdefer allocator.free(recs);

    var fn_map = std.AutoHashMap(u32, struct { total: usize, hit: usize }).init(allocator);
    defer fn_map.deinit();

    for (idx_buf, 0..) |orig_i, pos| {
        const bb = blocks[orig_i];
        const hit_cnt = if (orig_i < hits.len) hits[orig_i] else 0;
        var bsz: u16 = 4;
        if (pos + 1 < idx_buf.len) {
            const next_bb = blocks[idx_buf[pos + 1]];
            if (next_bb.func_rva == bb.func_rva and next_bb.rva > bb.rva) {
                bsz = @intCast(@min(next_bb.rva - bb.rva, 4096));
            }
        }
        recs[pos] = .{
            .rva = bb.rva,
            .size = bsz,
            .func_rva = bb.func_rva,
            .hits = hit_cnt,
        };

        const gop = try fn_map.getOrPut(bb.func_rva);
        if (!gop.found_existing) gop.value_ptr.* = .{ .total = 0, .hit = 0 };
        gop.value_ptr.total += 1;
        if (hit_cnt > 0) gop.value_ptr.hit += 1;
    }

    var fn_list = std.ArrayList(FuncCov).empty;
    errdefer {
        for (fn_list.items) |f| allocator.free(f.name);
        fn_list.deinit(allocator);
    }

    var fit = fn_map.iterator();
    while (fit.next()) |e| {
        const rs = symtab.resolve(e.key_ptr.*);
        try fn_list.append(allocator, .{
            .name = try allocator.dupe(u8, rs.name),
            .rva = e.key_ptr.*,
            .total_blocks = e.value_ptr.total,
            .hit_blocks = e.value_ptr.hit,
        });
    }

    const owned_fns = try fn_list.toOwnedSlice(allocator);
    std.mem.sort(FuncCov, owned_fns, {}, struct {
        fn less(_: void, a: FuncCov, b: FuncCov) bool {
            const a_uncov = a.total_blocks - a.hit_blocks;
            const b_uncov = b.total_blocks - b.hit_blocks;
            if (a_uncov != b_uncov) return a_uncov > b_uncov;
            return a.rva < b.rva;
        }
    }.less);

    return .{
        .allocator = allocator,
        .artifact = path,
        .image_base = img.image_base,
        .size_of_image = img.size_of_image,
        .entry_rva = img.entry_rva,
        .seeds_executed = seeds_executed,
        .blocks = recs,
        .functions = owned_fns,
    };
}

pub fn renderCoverage(allocator: std.mem.Allocator, rep: *const CovReport, fmt: CovFormat) ![]u8 {
    return switch (fmt) {
        .drcov => renderDrCov(allocator, rep),
        .lcov => renderLcov(allocator, rep),
        .json => renderJson(allocator, rep),
        .html => renderHtml(allocator, rep),
    };
}

fn renderDrCov(allocator: std.mem.Allocator, rep: *const CovReport) ![]u8 {
    var covered_cnt: usize = 0;
    for (rep.blocks) |b| if (b.hits > 0) {
        covered_cnt += 1;
    };

    const end_addr = rep.image_base +| rep.size_of_image;
    const entry_addr = rep.image_base +| rep.entry_rva;

    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);

    const hdr = try std.fmt.allocPrint(allocator,
        "DRCOV VERSION: 2\nDRCOV FLAVOR: snap-oracle\nModule Table: version 2, count 1\nColumns: id, base, end, entry, checksum, timestamp, path\n0, 0x{x}, 0x{x}, 0x{x}, 0x0, 0x0, {s}\nBB Table: {d} bbs\n",
        .{ rep.image_base, end_addr, entry_addr, rep.artifact, covered_cnt },
    );
    defer allocator.free(hdr);
    try out.appendSlice(allocator, hdr);

    for (rep.blocks) |b| {
        if (b.hits == 0) continue;
        var entry: [8]u8 = undefined;
        std.mem.writeInt(u32, entry[0..4], b.rva, .little);
        std.mem.writeInt(u16, entry[4..6], b.size, .little);
        std.mem.writeInt(u16, entry[6..8], 0, .little);
        try out.appendSlice(allocator, &entry);
    }

    return out.toOwnedSlice(allocator);
}

fn renderLcov(allocator: std.mem.Allocator, rep: *const CovReport) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);

    const sf = try std.fmt.allocPrint(allocator, "TN:snap-oracle\nSF:{s}\n", .{rep.artifact});
    defer allocator.free(sf);
    try out.appendSlice(allocator, sf);

    var fn_hit: usize = 0;
    for (rep.functions, 1..) |f, ord| {
        const fn_line = try std.fmt.allocPrint(allocator, "FN:{d},{s}\n", .{ ord, f.name });
        defer allocator.free(fn_line);
        try out.appendSlice(allocator, fn_line);
        if (f.hit_blocks > 0) fn_hit += 1;
    }
    for (rep.functions) |f| {
        const fnda = try std.fmt.allocPrint(allocator, "FNDA:{d},{s}\n", .{ f.hit_blocks, f.name });
        defer allocator.free(fnda);
        try out.appendSlice(allocator, fnda);
    }
    const fsum = try std.fmt.allocPrint(allocator, "FNF:{d}\nFNH:{d}\n", .{ rep.functions.len, fn_hit });
    defer allocator.free(fsum);
    try out.appendSlice(allocator, fsum);

    var da_hit: usize = 0;
    for (rep.blocks, 1..) |b, ord| {
        const da = try std.fmt.allocPrint(allocator, "DA:{d},{d}\n", .{ ord, b.hits });
        defer allocator.free(da);
        try out.appendSlice(allocator, da);
        if (b.hits > 0) da_hit += 1;
    }
    const end_rec = try std.fmt.allocPrint(allocator, "LF:{d}\nLH:{d}\nend_of_record\n", .{ rep.blocks.len, da_hit });
    defer allocator.free(end_rec);
    try out.appendSlice(allocator, end_rec);
    return out.toOwnedSlice(allocator);
}

fn renderJson(allocator: std.mem.Allocator, rep: *const CovReport) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);

    try out.appendSlice(allocator, "{\n  \"artifact\": ");
    try finding.appendJsonEscaped(&out, allocator, rep.artifact);
    const meta = try std.fmt.allocPrint(allocator,
        ",\n  \"total_blocks\": {d},\n  \"hit_blocks\": {d},\n  \"seeds_executed\": {d},\n  \"functions\": [\n",
        .{ rep.blocks.len, rep.hitBlockCount(), rep.seeds_executed },
    );
    defer allocator.free(meta);
    try out.appendSlice(allocator, meta);

    for (rep.functions, 0..) |f, i| {
        if (i > 0) try out.appendSlice(allocator, ",\n");
        try out.appendSlice(allocator, "    { \"name\": ");
        try finding.appendJsonEscaped(&out, allocator, f.name);
        const fvals = try std.fmt.allocPrint(allocator, ", \"rva\": {d}, \"total\": {d}, \"hit\": {d} }}", .{
            f.rva,
            f.total_blocks,
            f.hit_blocks,
        });
        defer allocator.free(fvals);
        try out.appendSlice(allocator, fvals);
    }

    try out.appendSlice(allocator, "\n  ],\n  \"blocks\": [\n");
    for (rep.blocks, 0..) |b, i| {
        if (i > 0) try out.appendSlice(allocator, ",\n");
        const line = try std.fmt.allocPrint(allocator, "    {{ \"rva\": {d}, \"size\": {d}, \"hits\": {d} }}", .{
            b.rva,
            b.size,
            b.hits,
        });
        defer allocator.free(line);
        try out.appendSlice(allocator, line);
    }
    try out.appendSlice(allocator, "\n  ]\n}\n");
    return out.toOwnedSlice(allocator);
}

fn renderHtml(allocator: std.mem.Allocator, rep: *const CovReport) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);

    const hit_cnt = rep.hitBlockCount();
    const pct: usize = if (rep.blocks.len > 0) (hit_cnt * 100) / rep.blocks.len else 0;

    const head = try std.fmt.allocPrint(allocator,
        \\<!DOCTYPE html>
        \\<html lang="en"><head><meta charset="utf-8"><title>Snap-Oracle ARM64 Coverage</title>
        \\<style>
        \\body{{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;margin:2rem;}}
        \\.card{{background:#1e293b;border-radius:10px;padding:1.25rem;margin-bottom:1.5rem;border:1px solid #334155;}}
        \\.bar{{height:16px;background:#334155;border-radius:8px;overflow:hidden;}}
        \\.fill{{height:100%;background:#10b981;width:{d}%;}}
        \\table{{width:100%;border-collapse:collapse;font-size:0.9rem;}}
        \\th,td{{padding:0.5rem 0.75rem;border-bottom:1px solid #334155;text-align:left;}}
        \\th{{color:#94a3b8;}}
        \\.grid{{display:grid;grid-template-columns:repeat(32,12px);gap:3px;}}
        \\.cell{{width:12px;height:12px;border-radius:2px;}}
        \\.hit{{background:#10b981;}} .miss{{background:#ef4444;opacity:0.45;}}
        \\</style></head><body>
        \\<h1>Snap-Oracle ARM64 Binary Coverage Report</h1>
        \\<div class="card">
        \\<p><strong>Artifact:</strong> 
    , .{pct});
    defer allocator.free(head);
    try out.appendSlice(allocator, head);
    try finding.appendHtmlEscaped(&out, allocator, rep.artifact);

    const stats = try std.fmt.allocPrint(allocator,
        \\ | <strong>Coverage:</strong> {d}/{d} basic blocks ({d}%) | <strong>Seeds:</strong> {d}</p>
        \\<div class="bar"><div class="fill"></div></div></div>
        \\<div class="card"><h2>Function Coverage</h2><table><thead><tr><th>Function</th><th>RVA</th><th>Blocks Hit</th><th>Total</th><th>%</th></tr></thead><tbody>
        \\
    , .{ hit_cnt, rep.blocks.len, pct, rep.seeds_executed });
    defer allocator.free(stats);
    try out.appendSlice(allocator, stats);

    for (rep.functions) |f| {
        const fpct: usize = if (f.total_blocks > 0) (f.hit_blocks * 100) / f.total_blocks else 0;
        try out.appendSlice(allocator, "<tr><td>");
        try finding.appendHtmlEscaped(&out, allocator, f.name);
        const row = try std.fmt.allocPrint(allocator, "</td><td>0x{x}</td><td>{d}</td><td>{d}</td><td>{d}%</td></tr>\n", .{
            f.rva,
            f.hit_blocks,
            f.total_blocks,
            fpct,
        });
        defer allocator.free(row);
        try out.appendSlice(allocator, row);
    }

    try out.appendSlice(allocator, "</tbody></table></div>\n<div class=\"card\"><h2>Basic-Block Hit Map (first 1024 blocks)</h2><div class=\"grid\">\n");
    for (rep.blocks[0..@min(rep.blocks.len, 1024)]) |b| {
        const cell = try std.fmt.allocPrint(allocator, "<div class=\"cell {s}\" title=\"0x{x} hits={d}\"></div>", .{
            if (b.hits > 0) "hit" else "miss",
            b.rva,
            b.hits,
        });
        defer allocator.free(cell);
        try out.appendSlice(allocator, cell);
    }
    try out.appendSlice(allocator, "</div></div></body></html>\n");
    return out.toOwnedSlice(allocator);
}

const JsonBlockDto = struct {
    rva: u32,
    hits: u32,
};

const JsonCovDto = struct {
    blocks: []const JsonBlockDto = &.{},
};

pub fn compareJsonCoverage(io: std.Io, allocator: std.mem.Allocator, old_path: []const u8, new_path: []const u8) !void {
    const old_raw = try std.Io.Dir.cwd().readFileAlloc(io, old_path, allocator, .limited(64 * 1024 * 1024));
    defer allocator.free(old_raw);
    const new_raw = try std.Io.Dir.cwd().readFileAlloc(io, new_path, allocator, .limited(64 * 1024 * 1024));
    defer allocator.free(new_raw);

    const p_old = try std.json.parseFromSlice(JsonCovDto, allocator, old_raw, .{ .ignore_unknown_fields = true });
    defer p_old.deinit();
    const p_new = try std.json.parseFromSlice(JsonCovDto, allocator, new_raw, .{ .ignore_unknown_fields = true });
    defer p_new.deinit();

    var old_hit = std.AutoHashMap(u32, void).init(allocator);
    defer old_hit.deinit();
    var new_hit = std.AutoHashMap(u32, void).init(allocator);
    defer new_hit.deinit();

    for (p_old.value.blocks) |b| if (b.hits > 0) try old_hit.put(b.rva, {});
    for (p_new.value.blocks) |b| if (b.hits > 0) try new_hit.put(b.rva, {});

    var gained: usize = 0;
    var lost: usize = 0;
    var nit = new_hit.keyIterator();
    while (nit.next()) |k| if (!old_hit.contains(k.*)) {
        gained += 1;
    };
    var oit = old_hit.keyIterator();
    while (oit.next()) |k| if (!new_hit.contains(k.*)) {
        lost += 1;
    };

    std.debug.print("[cov --compare] old_hit={d} new_hit={d} | gained=+{d} lost=-{d}\n", .{
        old_hit.count(),
        new_hit.count(),
        gained,
        lost,
    });
}

pub fn runCovCommand(io: std.Io, allocator: std.mem.Allocator, args: []const []const u8) !void {
    var target_path: ?[]const u8 = null;
    var entry_name: []const u8 = "fuzz_entry";
    var corpus_dir: ?[]const u8 = null;
    var fmt: CovFormat = .json;
    var out_path: ?[]const u8 = null;
    var cmp_old: ?[]const u8 = null;
    var cmp_new: ?[]const u8 = null;
    var bti_safe = false;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--target") and i + 1 < args.len) {
            i += 1;
            target_path = args[i];
        } else if (std.mem.eql(u8, a, "--entry") and i + 1 < args.len) {
            i += 1;
            entry_name = args[i];
        } else if (std.mem.eql(u8, a, "--corpus") and i + 1 < args.len) {
            i += 1;
            corpus_dir = args[i];
        } else if (std.mem.eql(u8, a, "--format") and i + 1 < args.len) {
            i += 1;
            fmt = CovFormat.fromString(args[i]) orelse .json;
        } else if (std.mem.eql(u8, a, "--out") and i + 1 < args.len) {
            i += 1;
            out_path = args[i];
        } else if (std.mem.eql(u8, a, "--bti-safe")) {
            bti_safe = true;
        } else if (std.mem.eql(u8, a, "--compare") and i + 2 < args.len) {
            cmp_old = args[i + 1];
            cmp_new = args[i + 2];
            i += 2;
        }
    }

    if (cmp_old != null and cmp_new != null) {
        try compareJsonCoverage(io, allocator, cmp_old.?, cmp_new.?);
        return;
    }

    const bin = target_path orelse {
        std.debug.print("Usage: snap-oracle cov --target <dll/bin> [--corpus <dir>] [--entry fn] [--format html|json|lcov|drcov] [--out <file>]\n", .{});
        return;
    };

    const image_bytes = try std.Io.Dir.cwd().readFileAlloc(io, bin, allocator, .limited(256 * 1024 * 1024));
    defer allocator.free(image_bytes);
    var img = try binary.parseBinary(allocator, image_bytes);
    defer img.deinit();

    const blocks = try cfg.decodeAllTextBasicBlocksEx(allocator, image_bytes, bti_safe);
    defer allocator.free(blocks);

    const hits = try allocator.alloc(u32, blocks.len);
    defer allocator.free(hits);
    @memset(hits, 0);

    var seeds_run: usize = 0;
    if (corpus_dir) |cdir| {
        var loaded = try runner.LoadedTarget.load(allocator, bin, entry_name);
        defer loaded.unload();
        var guard = veh.Guard.init();
        defer guard.deinit();
        veh.setTargetModuleBounds(loaded.base_addr, img.size_of_image);
        defer veh.setTargetModuleBounds(0, 0);

        var arena = try l1.SnapshotArena.init(allocator, 64 * 1024);
        defer arena.deinit();
        arena.takeSnapshot();
        var mod_snap = try dll_snapshot.ModuleDataSnapshot.init(allocator, loaded.base_addr, &img);
        defer mod_snap.deinit();

        const armed = try allocator.alloc(bool, blocks.len);
        defer allocator.free(armed);

        var dir = try std.Io.Dir.cwd().openDir(io, cdir, .{ .iterate = true });
        defer dir.close(io);
        var it = dir.iterate();
        while (it.next(io) catch null) |ent| {
            if (ent.kind != .file) continue;
            const data = dir.readFileAlloc(io, ent.name, allocator, .limited(64 * 1024)) catch continue;
            defer allocator.free(data);

            var bitmap = l1.CoverageBitmap{};
            var bp_table = try coverage.BreakpointTable.init(allocator, loaded.base_addr, img.machine, blocks, &bitmap);
            defer bp_table.deinit();
            for (blocks, 0..) |bb, bi| {
                armed[bi] = bp_table.orig_bytes.contains(loaded.base_addr + @as(usize, bb.rva));
            }
            veh.setBreakpointTable(&bp_table);
            @memcpy(arena.live_ptr[0..data.len], data);
            _ = veh.runProtected(loaded.entry, arena.live_ptr, data.len);
            _ = arena.restoreDirtyPages() catch 0;
            _ = mod_snap.restore();

            for (blocks, 0..) |bb, bi| {
                if (armed[bi] and !bp_table.orig_bytes.contains(loaded.base_addr + @as(usize, bb.rva))) {
                    hits[bi] += 1;
                }
            }
            seeds_run += 1;
        }
    }

    var rep = try buildCoverageReport(allocator, bin, image_bytes, &img, blocks, hits, seeds_run);
    defer rep.deinit();

    const rendered = try renderCoverage(allocator, &rep, fmt);
    defer allocator.free(rendered);

    if (out_path) |op| {
        try finding.writeOutputFile(io, op, rendered);
        std.debug.print("[cov] wrote {s} ({d}/{d} blocks hit, {d} seeds) -> {s}\n", .{
            @tagName(fmt),
            rep.hitBlockCount(),
            rep.blocks.len,
            seeds_run,
            op,
        });
    } else if (fmt == .drcov) {
        std.debug.print("[cov] binary drcov format requires --out <file>\n", .{});
    } else {
        finding.writeStdout(io, rendered);
    }
}
