const std = @import("std");
const binary = @import("binary.zig");
const macho = @import("macho_arm64.zig");
const pe = @import("pe.zig");
const cfg = @import("cfg.zig");
const arm64_isa = @import("arm64_isa.zig");
const arm_laptops = @import("arm_laptops.zig");
const symbols = @import("symbols.zig");
const finding = @import("finding.zig");
const report = @import("report.zig");

pub const FuncPerfStats = struct {
    rva: u32,
    name: []const u8,
    total_insns: usize = 0,
    neon_insns: usize = 0,
    sve_insns: usize = 0,
    fp_scalar_insns: usize = 0,
    ll_sc_insns: usize = 0,
    lse_insns: usize = 0,
    barrier_insns: usize = 0,
    back_edges: usize = 0,
    dotprod_insns: usize = 0,
    i8mm_insns: usize = 0,
    bf16_insns: usize = 0,
    crypto_insns: usize = 0,
};

pub const PerfReport = struct {
    allocator: std.mem.Allocator,
    format: binary.BinaryFormat,
    machine: pe.Machine,
    profile_name: []const u8,
    profile_has_lse: bool,
    profile_has_dotprod: bool,
    profile_has_sve: bool,
    total_insns: usize = 0,
    total_neon: usize = 0,
    total_sve: usize = 0,
    total_fp_scalar: usize = 0,
    total_ll_sc: usize = 0,
    total_lse: usize = 0,
    total_dotprod: usize = 0,
    total_i8mm: usize = 0,
    total_bf16: usize = 0,
    total_crypto: usize = 0,
    x64_sse_cnt: usize = 0,
    x64_vex_avx_cnt: usize = 0,
    x64_evex_avx512_cnt: usize = 0,
    hot_funcs: []FuncPerfStats,

    pub fn deinit(self: *PerfReport) void {
        for (self.hot_funcs) |hf| {
            self.allocator.free(hf.name);
        }
        self.allocator.free(self.hot_funcs);
    }
};

fn isMlComputeSymbol(name: []const u8) bool {
    const patterns = [_][]const u8{
        "gemm",
        "matmul",
        "conv2d",
        "dequant",
        "quantize",
        "softmax",
        "attention",
        "flash_attn",
        "qgemm",
        "vec_dot",
    };
    for (patterns) |p| {
        if (finding.containsIgnoreCase(name, p)) return true;
    }
    return false;
}

pub fn analyzePerformance(
    allocator: std.mem.Allocator,
    path: []const u8,
    raw_bytes: []const u8,
    profile_query: ?[]const u8,
    out_fs: *finding.FindingSet,
) !PerfReport {
    const bytes = macho.unwrapFatSlice(raw_bytes);
    var img = try binary.parseBinary(allocator, bytes);
    defer img.deinit();

    var symtab = try symbols.SymbolTable.build(allocator, &img, bytes, true);
    defer symtab.deinit();

    const prof: arm_laptops.LaptopProfile = if (profile_query) |q|
        (arm_laptops.findProfile(q) orelse arm_laptops.ALL_PROFILES[0])
    else
        arm_laptops.ALL_PROFILES[0];

    var rep = PerfReport{
        .allocator = allocator,
        .format = img.format,
        .machine = img.machine,
        .profile_name = prof.id,
        .profile_has_lse = prof.has_lse,
        .profile_has_dotprod = true,
        .profile_has_sve = prof.has_sve2,
        .hot_funcs = &.{},
    };

    if (img.is_arm64ec) {
        try out_fs.add(.{
            .rule_id = "SO-PERF-004",
            .severity = .medium,
            .confidence = .high,
            .artifact = path,
            .detail = "Binary is ARM64EC hybrid; verify x64-emulated entrypoints are minimized for native throughput",
        });
    }

    const text_sec = img.findCodeSection() orelse {
        return rep;
    };
    const sec_end = @as(u64, text_sec.raw_offset) + @as(u64, text_sec.raw_size);
    if (sec_end > bytes.len or text_sec.raw_size == 0) {
        return rep;
    }
    const code = bytes[@as(usize, text_sec.raw_offset)..@as(usize, @intCast(sec_end))];
    const base_rva = text_sec.virtual_address;
    const end_rva = base_rva +| @as(u32, @intCast(code.len));

    var func_stats = std.ArrayList(FuncPerfStats).empty;
    errdefer {
        for (func_stats.items) |hf| allocator.free(hf.name);
        func_stats.deinit(allocator);
    }

    if (img.isArm64()) {
        var fallback: [1]pe.RuntimeFunction = undefined;
        const fn_list: []const pe.RuntimeFunction = if (img.functions.len > 0)
            img.functions
        else blk: {
            fallback[0] = .{ .begin_rva = base_rva, .end_rva = end_rva, .unwind_rva = 0 };
            break :blk &fallback;
        };

        for (fn_list) |f| {
            if (f.begin_rva < base_rva or f.end_rva <= f.begin_rva or f.begin_rva >= end_rva) continue;
            const start_off = f.begin_rva - base_rva;
            const clamped_end = @min(f.end_rva, end_rva) - base_rva;
            const res = symtab.resolve(f.begin_rva);

            var st = FuncPerfStats{
                .rva = f.begin_rva,
                .name = res.name,
            };

            var off: usize = start_off;
            while (off + 4 <= clamped_end) : (off += 4) {
                const insn = std.mem.readInt(u32, code[off..][0..4], .little);
                const d = arm64_isa.decode(insn);
                const ce = arm64_isa.classifyComputeExt(insn);

                st.total_insns += 1;
                switch (d.class) {
                    .neon_simd => st.neon_insns += 1,
                    .sve => st.sve_insns += 1,
                    .fp_scalar => st.fp_scalar_insns += 1,
                    .ldxr, .stxr => st.ll_sc_insns += 1,
                    .lse_atomic => st.lse_insns += 1,
                    .barrier => st.barrier_insns += 1,
                    .b, .b_cond, .cbz, .cbnz, .tbz, .tbnz => {
                        if (d.target_delta) |delta| {
                            if (delta < 0) st.back_edges += 1;
                        }
                    },
                    else => {},
                }
                switch (ce) {
                    .dotprod => st.dotprod_insns += 1,
                    .i8mm => st.i8mm_insns += 1,
                    .bf16 => st.bf16_insns += 1,
                    .crypto_aes, .crypto_sha, .crc32 => st.crypto_insns += 1,
                    else => {},
                }
            }

            rep.total_insns += st.total_insns;
            rep.total_neon += st.neon_insns;
            rep.total_sve += st.sve_insns;
            rep.total_fp_scalar += st.fp_scalar_insns;
            rep.total_ll_sc += st.ll_sc_insns;
            rep.total_lse += st.lse_insns;
            rep.total_dotprod += st.dotprod_insns;
            rep.total_i8mm += st.i8mm_insns;
            rep.total_bf16 += st.bf16_insns;
            rep.total_crypto += st.crypto_insns;

            if (st.back_edges > 0 and st.fp_scalar_insns >= 10 and st.neon_insns == 0 and st.sve_insns == 0) {
                const detail = try std.fmt.allocPrint(allocator, "Function {s} has {d} loop back-edges and {d} scalar FP instructions with 0 NEON/SVE vector instructions", .{
                    st.name,
                    st.back_edges,
                    st.fp_scalar_insns,
                });
                defer allocator.free(detail);
                try out_fs.add(.{
                    .rule_id = "SO-PERF-001",
                    .artifact = path,
                    .rva = st.rva,
                    .func_name = st.name,
                    .detail = detail,
                });
            }

            if (prof.has_lse and st.ll_sc_insns >= 4 and st.lse_insns == 0) {
                const detail = try std.fmt.allocPrint(allocator, "Function {s} uses {d} LL/SC (LDXR/STXR) atomics without LSE while targeting {s}", .{
                    st.name,
                    st.ll_sc_insns,
                    prof.name,
                });
                defer allocator.free(detail);
                try out_fs.add(.{
                    .rule_id = "SO-PERF-002",
                    .artifact = path,
                    .rva = st.rva,
                    .func_name = st.name,
                    .detail = detail,
                });
            }

            if (isMlComputeSymbol(st.name) and st.dotprod_insns == 0 and st.i8mm_insns == 0 and st.bf16_insns == 0) {
                const detail = try std.fmt.allocPrint(allocator, "ML/compute symbol '{s}' emits 0 SDOT/SMMLA/BFDOT instructions (missing ARMv8.2+ AI kernel acceleration)", .{st.name});
                defer allocator.free(detail);
                try out_fs.add(.{
                    .rule_id = "SO-PERF-003",
                    .artifact = path,
                    .rva = st.rva,
                    .func_name = st.name,
                    .detail = detail,
                });
            }

            if (st.total_insns > 0) {
                st.name = try allocator.dupe(u8, res.name);
                errdefer allocator.free(st.name);
                try func_stats.append(allocator, st);
            }
        }
    } else if (img.machine == .amd64) {
        try out_fs.add(.{
            .rule_id = "SO-PERF-004",
            .artifact = path,
            .detail = "Binary targets x86_64/AMD64 and executes via Prism/Rosetta emulation on ARM64 laptops (estimated heuristic 20-40% overhead)",
        });

        var off: usize = 0;
        const limit = @min(code.len, 2 * 1024 * 1024);
        while (off < limit) {
            const insn = cfg.decodeX64Insn(code[off..]) orelse {
                off += 1;
                continue;
            };
            rep.total_insns += 1;
            const raw = code[off .. off + insn.len];
            if (raw.len >= 2 and (raw[0] == 0xC4 or raw[0] == 0xC5)) {
                rep.x64_vex_avx_cnt += 1;
            } else if (raw.len >= 4 and raw[0] == 0x62) {
                rep.x64_evex_avx512_cnt += 1;
            } else if (raw.len >= 3 and (raw[0] == 0x66 or raw[0] == 0xF2 or raw[0] == 0xF3) and raw[1] == 0x0F) {
                rep.x64_sse_cnt += 1;
            }
            off += insn.len;
        }

        if (rep.x64_vex_avx_cnt + rep.x64_evex_avx512_cnt + rep.x64_sse_cnt > 0) {
            const detail = try std.fmt.allocPrint(allocator, "Detected {d} SSE, {d} AVX/AVX2 (VEX), and {d} AVX-512 (EVEX) instructions needing NEON/SVE2 port", .{
                rep.x64_sse_cnt,
                rep.x64_vex_avx_cnt,
                rep.x64_evex_avx512_cnt,
            });
            defer allocator.free(detail);
            try out_fs.add(.{
                .rule_id = "SO-PERF-005",
                .artifact = path,
                .detail = detail,
            });
        }
    }

    const owned = try func_stats.toOwnedSlice(allocator);
    std.mem.sort(FuncPerfStats, owned, {}, struct {
        fn desc(_: void, a: FuncPerfStats, b: FuncPerfStats) bool {
            return a.total_insns > b.total_insns;
        }
    }.desc);
    rep.hot_funcs = owned;
    return rep;
}

pub fn runPerfAdviseCommand(io: std.Io, allocator: std.mem.Allocator, args: []const []const u8) !u8 {
    if (args.len == 0) {
        std.debug.print("Usage: snap-oracle perf-advise <binary> [--profile <name>] [--format text|json|sarif|junit|gha] [--out <file>] [--fail-on <sev>]\n", .{});
        return 2;
    }

    var bin_path: ?[]const u8 = null;
    var profile: ?[]const u8 = null;
    var fmt: report.ReportFormat = .text;
    var out_path: ?[]const u8 = null;
    var fail_on: finding.Severity = .critical;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--profile") and i + 1 < args.len) {
            i += 1;
            profile = args[i];
        } else if (std.mem.eql(u8, a, "--format") and i + 1 < args.len) {
            i += 1;
            fmt = report.ReportFormat.fromString(args[i]) orelse .text;
        } else if (std.mem.eql(u8, a, "--out") and i + 1 < args.len) {
            i += 1;
            out_path = args[i];
        } else if (std.mem.eql(u8, a, "--fail-on") and i + 1 < args.len) {
            i += 1;
            fail_on = finding.Severity.fromString(args[i]) orelse .critical;
        } else if (bin_path == null and a.len > 0 and a[0] != '-') {
            bin_path = a;
        }
    }

    const path = bin_path orelse {
        std.debug.print("Usage: snap-oracle perf-advise <binary> [--profile <name>]\n", .{});
        return 2;
    };

    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(128 * 1024 * 1024));
    defer allocator.free(bytes);

    var fs = finding.FindingSet.init(allocator);
    defer fs.deinit();

    var rep = try analyzePerformance(allocator, path, bytes, profile, &fs);
    defer rep.deinit();

    if (fmt == .text) {
        std.debug.print(
            \\=== ARM64 Performance & Vectorization Migration Advisor: {s} ===
            \\Target Profile: {s} (LSE={any}, SVE={any}) | Binary Arch: {s}
            \\Insns: {d} | NEON={d} SVE={d} ScalarFP={d} | DotProd={d} I8MM={d} BF16={d} Crypto={d} | LSE={d} LL/SC={d}
            \\
        , .{
            finding.basename(path),
            rep.profile_name,
            rep.profile_has_lse,
            rep.profile_has_sve,
            @tagName(rep.machine),
            rep.total_insns,
            rep.total_neon,
            rep.total_sve,
            rep.total_fp_scalar,
            rep.total_dotprod,
            rep.total_i8mm,
            rep.total_bf16,
            rep.total_crypto,
            rep.total_lse,
            rep.total_ll_sc,
        });
        if (rep.hot_funcs.len > 0) {
            std.debug.print("Top Analyzed Functions:\n", .{});
            for (rep.hot_funcs[0..@min(rep.hot_funcs.len, 10)]) |hf| {
                std.debug.print("  0x{x:0>8} {s:<28} insns={d:<5} neon={d:<4} fp_scalar={d:<4} backedges={d}\n", .{
                    hf.rva,
                    hf.name[0..@min(hf.name.len, 28)],
                    hf.total_insns,
                    hf.neon_insns,
                    hf.fp_scalar_insns,
                    hf.back_edges,
                });
            }
        }
        std.debug.print("\n", .{});
    }

    try report.emitOrPrint(io, allocator, &fs, fmt, out_path, bytes);
    return fs.exitCode(fail_on);
}
