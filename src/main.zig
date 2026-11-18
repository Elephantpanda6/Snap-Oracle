const std = @import("std");
const binary = @import("binary.zig");
const cfg = @import("cfg.zig");
const runner = @import("runner.zig");
const audit = @import("audit.zig");
const arm_laptops = @import("arm_laptops.zig");
const worker = @import("worker.zig");
const pool = @import("pool.zig");

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
        \\snap-oracle (ARM64-First Cross-OS Snapshot Fuzzer & Binary Auditor)
        \\
        \\Usage:
        \\  snap-oracle inspect  <binary>                 Parse PE32+/ELF64/Mach-O headers, functions & BBs
        \\  snap-oracle audit    <binary>                 ARM64 readiness, PAC/BTI/LSE, laptop matrix & exports
        \\  snap-oracle hwinfo                            Probe live host ARM64 ISA/page-size/laptop profile
        \\  snap-oracle profiles                          List all supported ARM64 laptop & workstation profiles
        \\  snap-oracle fuzz     --target <bin> [--entry <fn>] [--iters N] [--corpus <dir>]
        \\                       [--max-input N] [--seed N] [--dict <file>] [--laptop <id>]
        \\                       [--jobs N] [--bti-safe]
        \\  snap-oracle diff     [--a <bin1> --b <bin2> | --x64 <bin1> --arm64 <bin2>] [--entry <fn>] [--iters N]
        \\  snap-oracle replay   --target <bin> [--entry <fn>] --input <file> [--minimize]
        \\  snap-oracle worker   --target <bin> [--entry <fn>] [--bti-safe]
        \\
    , .{});
}

fn cmdInspect(io: std.Io, allocator: std.mem.Allocator, path: []const u8) !void {
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(128 * 1024 * 1024));
    defer allocator.free(bytes);

    var img = try binary.parseBinary(allocator, bytes);
    defer img.deinit();

    std.debug.print("File:       {s}\n", .{path});
    std.debug.print("Format:     {s}\n", .{@tagName(img.format)});
    std.debug.print("Machine:    {s} (0x{x:0>4})\n", .{ @tagName(img.machine), @intFromEnum(img.machine) });
    std.debug.print("ImageBase:  0x{x}\n", .{img.image_base});
    std.debug.print("ImageSize:  {d} bytes (min_align={d})\n", .{ img.size_of_image, img.min_segment_align });
    std.debug.print("EntryRVA:   0x{x}\n", .{img.entry_rva});
    std.debug.print("Sections:   {d}\n", .{img.sections.len});
    std.debug.print("Functions:  {d}\n", .{img.functions.len});
    std.debug.print("Exports:    {d}\n", .{img.exports.len});

    if (img.findCodeSection()) |text_sec| {
        if (text_sec.raw_offset < bytes.len and text_sec.raw_size > 0) {
            const avail = @min(@as(usize, text_sec.raw_size), bytes.len - text_sec.raw_offset);
            const code = bytes[text_sec.raw_offset .. text_sec.raw_offset + avail];
            var total_bb: usize = 0;
            const sample_fns = @min(img.functions.len, 64);
            for (img.functions[0..sample_fns]) |f| {
                if (f.begin_rva < text_sec.virtual_address or f.end_rva > text_sec.virtual_address + text_sec.raw_size) continue;
                const bbs = switch (img.machine) {
                    .arm64, .arm64ec => try cfg.decodeArm64BasicBlocksEx(allocator, code, text_sec.virtual_address, f.begin_rva, f.end_rva, true),
                    .amd64 => try cfg.decodeX64BasicBlocksFull(allocator, code, text_sec.virtual_address, f.begin_rva, f.end_rva),
                    else => continue,
                };
                defer allocator.free(bbs);
                total_bb += bbs.len;
            }
            std.debug.print("Decoded BBs (first {d} funcs): {d}\n", .{ sample_fns, total_bb });
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
    } else if (std.mem.eql(u8, sub, "audit") and args.len >= 3) {
        try audit.runAuditCommand(init.io, allocator, args[2]);
    } else if (std.mem.eql(u8, sub, "hwinfo")) {
        arm_laptops.printHostInfo();
    } else if (std.mem.eql(u8, sub, "profiles")) {
        arm_laptops.printAllProfiles();
    } else if (std.mem.eql(u8, sub, "fuzz")) {
        const target = getFlag(args[2..], "--target") orelse {
            printUsage();
            return;
        };
        const entry = getFlag(args[2..], "--entry") orelse "fuzz_entry";
        const iters_str = getFlag(args[2..], "--iters") orelse "1000";
        const iters = std.fmt.parseInt(usize, iters_str, 10) catch 1000;
        const corpus_dir = getFlag(args[2..], "--corpus");
        const dict_path = getFlag(args[2..], "--dict");
        const max_in_str = getFlag(args[2..], "--max-input") orelse "4096";
        const max_input = std.fmt.parseInt(usize, max_in_str, 10) catch 4096;
        const seed_opt: ?u64 = if (getFlag(args[2..], "--seed")) |s|
            std.fmt.parseInt(u64, s, 0) catch null
        else
            null;
        const jobs_str = getFlag(args[2..], "--jobs") orelse "1";
        const jobs = std.fmt.parseInt(usize, jobs_str, 10) catch 1;
        const laptop_profile = getFlag(args[2..], "--laptop");
        const bti_safe = hasFlag(args[2..], "--bti-safe");

        if (jobs > 1) {
            try pool.runPoolFuzz(
                init.io,
                allocator,
                args[0],
                target,
                entry,
                iters,
                jobs,
                corpus_dir,
                dict_path,
                max_input,
                laptop_profile,
                bti_safe,
            );
        } else {
            try runner.runFuzzEx(init.io, allocator, .{
                .target_path = target,
                .entry_name = entry,
                .iters = iters,
                .corpus_dir = corpus_dir,
                .dict_path = dict_path,
                .max_input = max_input,
                .seed = seed_opt,
                .laptop_profile = laptop_profile,
                .bti_safe = bti_safe,
            });
        }
    } else if (std.mem.eql(u8, sub, "diff")) {
        const bin_a = getFlag(args[2..], "--a") orelse getFlag(args[2..], "--x64") orelse {
            printUsage();
            return;
        };
        const bin_b = getFlag(args[2..], "--b") orelse getFlag(args[2..], "--arm64") orelse {
            printUsage();
            return;
        };
        const entry = getFlag(args[2..], "--entry") orelse "fuzz_entry";
        const iters_str = getFlag(args[2..], "--iters") orelse "1000";
        const iters = std.fmt.parseInt(usize, iters_str, 10) catch 1000;
        try runner.runDiff(init.io, allocator, bin_a, bin_b, entry, iters);
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
    } else if (std.mem.eql(u8, sub, "worker")) {
        const target = getFlag(args[2..], "--target") orelse {
            printUsage();
            return;
        };
        const entry = getFlag(args[2..], "--entry") orelse "fuzz_entry";
        const bti_safe = hasFlag(args[2..], "--bti-safe");
        try worker.runWorkerStdio(init.io, allocator, target, entry, bti_safe);
    } else {
        printUsage();
    }
}
