const std = @import("std");
const pe = @import("pe.zig");
const cfg = @import("cfg.zig");
const arch = @import("arch.zig");
const l1 = @import("l1_engine.zig");
const mutator = @import("mutator.zig");
const runner = @import("runner.zig");

fn getFlag(args: []const []const u8, name: []const u8) ?[]const u8 {
    var i: usize = 0;
    while (i + 1 < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], name)) return args[i + 1];
    }
    return null;
}

fn hasFlag(args: []const []const u8, name: []const u8) bool {
    for (args) |a| {
        if (std.mem.eql(u8, a, name)) return true;
    }
    return false;
}

fn printUsage() void {
    std.debug.print(
        \\snap-oracle (win-x64 / win-arm64) - Binary-Only Differential Snapshot Fuzzer
        \\
        \\Usage:
        \\  snap-oracle inspect <target.exe|dll>       Parse PE/.pdata functions, exports & basic blocks
        \\  snap-oracle fuzz    --target <bin> --entry <fn> [--iters N] [--corpus <dir>]
        \\  snap-oracle diff    --x64 <bin> --arm64 <bin> --entry <fn>
        \\  snap-oracle replay  --target <bin> --entry <fn> --input <file> [--minimize]
        \\
    , .{});
}

fn cmdInspect(io: std.Io, allocator: std.mem.Allocator, path: []const u8) !void {
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(128 * 1024 * 1024));
    defer allocator.free(bytes);

    var img = try pe.parsePe(allocator, bytes);
    defer img.deinit();

    std.debug.print("File:       {s}\n", .{path});
    std.debug.print("Machine:    {s} (0x{x:0>4})\n", .{ @tagName(img.machine), @intFromEnum(img.machine) });
    std.debug.print("ImageBase:  0x{x}\n", .{img.image_base});
    std.debug.print("EntryRVA:   0x{x}\n", .{img.entry_rva});
    std.debug.print("Sections:   {d}\n", .{img.sections.len});
    std.debug.print(".pdata fns: {d}\n", .{img.functions.len});
    std.debug.print("Exports:    {d}\n", .{img.exports.len});

    if (img.findSection(".text")) |text_sec| {
        if (img.rvaToOffset(text_sec.virtual_address)) |t_off| {
            const avail = @min(@as(usize, text_sec.raw_size), bytes.len - t_off);
            const code = bytes[t_off .. t_off + avail];
            var total_bb: usize = 0;
            const sample_fns = @min(img.functions.len, 64);
            for (img.functions[0..sample_fns]) |f| {
                if (f.begin_rva < text_sec.virtual_address or f.end_rva > text_sec.virtual_address + text_sec.raw_size) continue;
                const bbs = switch (img.machine) {
                    .arm64, .arm64ec => try cfg.decodeArm64BasicBlocks(allocator, code, text_sec.virtual_address, f.begin_rva, f.end_rva),
                    .amd64 => try cfg.decodeX64BasicBlocks(allocator, code, text_sec.virtual_address, f.begin_rva, f.end_rva),
                    else => continue,
                };
                defer allocator.free(bbs);
                total_bb += bbs.len;
            }
            std.debug.print("Decoded BBs (first {d} .pdata funcs): {d}\n", .{ sample_fns, total_bb });
        }
    }
}

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.c_allocator;

    var args_list = std.ArrayList([]const u8).empty;
    defer args_list.deinit(allocator);
    var it = try init.minimal.args.iterateAllocator(allocator);
    defer it.deinit();
    while (it.next()) |arg| {
        try args_list.append(allocator, arg);
    }
    const args = args_list.items;

    if (args.len < 2) {
        printUsage();
        return;
    }

    const sub = args[1];
    if (std.mem.eql(u8, sub, "inspect") and args.len >= 3) {
        try cmdInspect(init.io, allocator, args[2]);
    } else if (std.mem.eql(u8, sub, "fuzz")) {
        const target = getFlag(args[2..], "--target") orelse {
            printUsage();
            return;
        };
        const entry = getFlag(args[2..], "--entry") orelse "fuzz_entry";
        const iters_str = getFlag(args[2..], "--iters") orelse "1000";
        const iters = std.fmt.parseInt(usize, iters_str, 10) catch 1000;
        const corpus_dir = getFlag(args[2..], "--corpus");
        try runner.runFuzz(init.io, allocator, target, entry, iters, corpus_dir);
    } else if (std.mem.eql(u8, sub, "diff")) {
        const x64_bin = getFlag(args[2..], "--x64") orelse {
            printUsage();
            return;
        };
        const arm64_bin = getFlag(args[2..], "--arm64") orelse {
            printUsage();
            return;
        };
        const entry = getFlag(args[2..], "--entry") orelse "fuzz_entry";
        const iters_str = getFlag(args[2..], "--iters") orelse "1000";
        const iters = std.fmt.parseInt(usize, iters_str, 10) catch 1000;
        try runner.runDiff(allocator, x64_bin, arm64_bin, entry, iters);
    } else if (std.mem.eql(u8, sub, "replay")) {
        const target = getFlag(args[2..], "--target") orelse {
            printUsage();
            return;
        };
        const entry = getFlag(args[2..], "--entry") orelse "fuzz_entry";
        const input = getFlag(args[2..], "--input") orelse {
            printUsage();
            return;
        };
        const minimize = hasFlag(args[2..], "--minimize");
        try runner.runReplay(init.io, allocator, target, entry, input, minimize);
    } else {
        printUsage();
    }
}
