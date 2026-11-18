const std = @import("std");
const builtin = @import("builtin");

const arch = @import("arch.zig");
const arm64_isa = @import("arm64_isa.zig");
const pe = @import("pe.zig");
const elf_arm64 = @import("elf_arm64.zig");
const macho_arm64 = @import("macho_arm64.zig");
const binary = @import("binary.zig");
const cfg = @import("cfg.zig");
const dict_extract = @import("dict_extract.zig");
const mutator = @import("mutator.zig");
const l1 = @import("l1_engine.zig");
const dll_snapshot = @import("dll_snapshot.zig");
const veh = @import("veh.zig");
const coverage = @import("coverage.zig");
const corpus = @import("corpus.zig");
const minimizer = @import("minimizer.zig");
const arm_laptops = @import("arm_laptops.zig");
const audit = @import("audit.zig");
const diff_protocol = @import("diff_protocol.zig");
const runner = @import("runner.zig");
const worker = @import("worker.zig");
const pool = @import("pool.zig");
const test_target = @import("test_target.zig");
const finding = @import("finding.zig");
const report = @import("report.zig");
const symbols = @import("symbols.zig");
const license = @import("license.zig");
const imports = @import("imports.zig");
const pagesize = @import("pagesize.zig");
const hardening = @import("hardening.zig");
const sbom = @import("sbom.zig");
const perfadvisor = @import("perfadvisor.zig");
const portscan = @import("portscan.zig");
const crash_triage = @import("crash_triage.zig");
const harnessgen = @import("harnessgen.zig");
const cmin = @import("cmin.zig");
const covreport = @import("covreport.zig");
const bench = @import("bench.zig");
const crashdb = @import("crashdb.zig");
const ci_gate = @import("ci_gate.zig");

comptime {
    _ = arch;
    _ = arm64_isa;
    _ = pe;
    _ = elf_arm64;
    _ = macho_arm64;
    _ = binary;
    _ = cfg;
    _ = dict_extract;
    _ = mutator;
    _ = l1;
    _ = dll_snapshot;
    _ = veh;
    _ = coverage;
    _ = corpus;
    _ = minimizer;
    _ = arm_laptops;
    _ = audit;
    _ = diff_protocol;
    _ = runner;
    _ = worker;
    _ = pool;
    _ = test_target;
    _ = finding;
    _ = report;
    _ = symbols;
    _ = license;
    _ = imports;
    _ = pagesize;
    _ = hardening;
    _ = sbom;
    _ = perfadvisor;
    _ = portscan;
    _ = crash_triage;
    _ = harnessgen;
    _ = cmin;
    _ = covreport;
    _ = bench;
    _ = crashdb;
    _ = ci_gate;
}

test "arm64 basic-block decoder" {
    const alloc = std.testing.allocator;
    // NOP; B.EQ +8; NOP; RET
    const code = [_]u8{
        0x1F, 0x20, 0x03, 0xD5, // 0x1000: nop
        0x40, 0x00, 0x00, 0x54, // 0x1004: b.eq +8 -> 0x100C
        0x1F, 0x20, 0x03, 0xD5, // 0x1008: nop
        0xC0, 0x03, 0x5F, 0xD6, // 0x100C: ret
    };
    const bbs = try cfg.decodeArm64BasicBlocks(alloc, &code, 0x1000, 0x1000, 0x1010);
    defer alloc.free(bbs);
    try std.testing.expectEqual(@as(usize, 3), bbs.len);
}

test "x64 basic-block decoder" {
    const alloc = std.testing.allocator;
    const code = [_]u8{ 0x90, 0x74, 0x02, 0x90, 0x90, 0xC3 };
    const bbs = try cfg.decodeX64BasicBlocks(alloc, &code, 0x1000, 0x1000, 0x1006);
    defer alloc.free(bbs);
    try std.testing.expectEqual(@as(usize, 2), bbs.len);
}

test "mutator & coverage bitmap" {
    var rng = mutator.Rng.init(42);
    var buf = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const new_len = mutator.mutateHavoc(&rng, &buf, buf.len);
    try std.testing.expect(new_len > 0 and new_len <= buf.len);

    var bm = l1.CoverageBitmap{};
    try std.testing.expect(bm.recordEdge(0x140001000));
    try std.testing.expectEqual(@as(usize, 1), bm.unique_edges);
}

test "SnapshotArena dirty-page reset (MEM_WRITE_WATCH on Windows / page compare on POSIX)" {
    const alloc = std.testing.allocator;
    var arena = try l1.SnapshotArena.init(alloc, 32 * 1024);
    defer arena.deinit();

    arena.live_ptr[0] = 0xAA;
    arena.takeSnapshot();

    arena.live_ptr[0] = 0x55;
    arena.live_ptr[arena.page_size] = 0x77;
    const restored = try arena.restoreDirtyPages();
    try std.testing.expectEqual(@as(usize, 2), restored);
    try std.testing.expectEqual(@as(u8, 0xAA), arena.live_ptr[0]);
    try std.testing.expectEqual(@as(u8, 0x00), arena.live_ptr[arena.page_size]);
}

fn testTargetFn(ptr: [*]const u8, len: usize) callconv(.c) u64 {
    if (len >= 4 and ptr[0] == 'B' and ptr[1] == 'O' and ptr[2] == 'O' and ptr[3] == 'M') {
        const bad: *volatile u8 = @ptrFromInt(0xDEAD);
        bad.* = 1;
    }
    return @as(u64, len);
}

test "VEH / POSIX signal protected execution, fault_rva, & crash recovery" {
    var guard = veh.Guard.init();
    defer guard.deinit();

    const ok_input = "SAFE";
    const ok_res = veh.runProtected(testTargetFn, ok_input.ptr, ok_input.len);
    try std.testing.expect(!ok_res.crashed);
    try std.testing.expectEqual(@as(u64, 4), ok_res.ret_val);

    const boom_input = "BOOM";
    const crash_res = veh.runProtected(testTargetFn, boom_input.ptr, boom_input.len);
    try std.testing.expect(crash_res.crashed);
    try std.testing.expectEqual(@as(u32, 0xC0000005), crash_res.exception_code);
    try std.testing.expect(crash_res.exception_addr != 0);
}

const MEM_COMMIT_TEST: u32 = 0x1000;
const MEM_RESERVE_TEST: u32 = 0x2000;
const MEM_RELEASE_TEST: u32 = 0x8000;
const PAGE_EXECUTE_READWRITE_TEST: u32 = 0x40;

const WinTestMem = if (builtin.os.tag == .windows) struct {
    extern "kernel32" fn VirtualAlloc(?*anyopaque, usize, u32, u32) callconv(.winapi) ?*anyopaque;
    extern "kernel32" fn VirtualFree(*anyopaque, usize, u32) callconv(.winapi) c_int;
} else struct {};

test "end-to-end decodeX64BasicBlocksFull + BreakpointTable + VEH one-shot coverage" {
    if (builtin.cpu.arch != .x86_64 or builtin.os.tag != .windows) return error.SkipZigTest;

    const mem: [*]u8 = @ptrCast(WinTestMem.VirtualAlloc(null, 4096, MEM_RESERVE_TEST | MEM_COMMIT_TEST, PAGE_EXECUTE_READWRITE_TEST) orelse return error.SkipZigTest);
    defer _ = WinTestMem.VirtualFree(mem, 0, MEM_RELEASE_TEST);

    const code = [_]u8{
        0x48, 0x83, 0xFA, 0x04,
        0x72, 0x06,
        0xB8, 0x01, 0x00, 0x00, 0x00,
        0xC3,
        0x31, 0xC0,
        0xC3,
    };
    @memcpy(mem[0..code.len], &code);

    const blocks = try cfg.decodeX64BasicBlocksFull(std.testing.allocator, mem[0..code.len], 0, 0, code.len);
    defer std.testing.allocator.free(blocks);
    try std.testing.expectEqual(@as(usize, 3), blocks.len);

    var bitmap = l1.CoverageBitmap{};
    var table = try coverage.BreakpointTable.init(std.testing.allocator, @intFromPtr(mem), .amd64, blocks, &bitmap);
    defer table.deinit();
    try std.testing.expectEqual(@as(usize, 3), table.totalCount());

    var guard = veh.Guard.init();
    defer guard.deinit();
    veh.setBreakpointTable(&table);

    const f: veh.TargetFn = @ptrCast(@alignCast(mem));
    const long_in = "ABCD";
    const res1 = veh.runProtected(f, long_in.ptr, long_in.len);
    try std.testing.expect(!res1.crashed);
    try std.testing.expectEqual(@as(u64, 1), res1.ret_val);
    try std.testing.expectEqual(@as(usize, 2), table.hitCount());
    try std.testing.expectEqual(@as(usize, 2), bitmap.unique_edges);

    const res2 = veh.runProtected(f, long_in.ptr, long_in.len);
    try std.testing.expect(!res2.crashed);
    try std.testing.expectEqual(@as(u64, 1), res2.ret_val);
    try std.testing.expectEqual(@as(usize, 2), table.hitCount());

    const short_in = "A";
    const res3 = veh.runProtected(f, short_in.ptr, short_in.len);
    try std.testing.expect(!res3.crashed);
    try std.testing.expectEqual(@as(u64, 0), res3.ret_val);
    try std.testing.expectEqual(@as(usize, 3), table.hitCount());
    try std.testing.expectEqual(@as(usize, 3), bitmap.unique_edges);
}

test "end-to-end decodeArm64BasicBlocks + BreakpointTable + VEH one-shot coverage" {
    if (builtin.cpu.arch != .aarch64 or builtin.os.tag != .windows) return error.SkipZigTest;

    const mem: [*]u8 = @ptrCast(WinTestMem.VirtualAlloc(null, 4096, MEM_RESERVE_TEST | MEM_COMMIT_TEST, PAGE_EXECUTE_READWRITE_TEST) orelse return error.SkipZigTest);
    defer _ = WinTestMem.VirtualFree(mem, 0, MEM_RELEASE_TEST);

    // ARM64 ABI (x0=ptr, x1=len):
    // 0x00: cmp x1, #4       (F100103F)
    // 0x04: b.lo +12 -> 0x10 (54000063)
    // 0x08: movz w0, #1      (52800020)
    // 0x0C: ret              (D65F03C0)
    // 0x10: movz w0, #0      (52800000)
    // 0x14: ret              (D65F03C0)
    const code = [_]u8{
        0x3F, 0x10, 0x00, 0xF1,
        0x63, 0x00, 0x00, 0x54,
        0x20, 0x00, 0x80, 0x52,
        0xC0, 0x03, 0x5F, 0xD6,
        0x00, 0x00, 0x80, 0x52,
        0xC0, 0x03, 0x5F, 0xD6,
    };
    @memcpy(mem[0..code.len], &code);
    l1.flushCodeRange(mem, code.len);

    const blocks = try cfg.decodeArm64BasicBlocks(std.testing.allocator, mem[0..code.len], 0, 0, code.len);
    defer std.testing.allocator.free(blocks);
    try std.testing.expectEqual(@as(usize, 3), blocks.len);

    var bitmap = l1.CoverageBitmap{};
    var table = try coverage.BreakpointTable.init(std.testing.allocator, @intFromPtr(mem), .arm64, blocks, &bitmap);
    defer table.deinit();
    try std.testing.expectEqual(@as(usize, 3), table.totalCount());

    var guard = veh.Guard.init();
    defer guard.deinit();
    veh.setBreakpointTable(&table);

    const f: veh.TargetFn = @ptrCast(@alignCast(mem));
    const long_in = "ABCD";
    const res1 = veh.runProtected(f, long_in.ptr, long_in.len);
    try std.testing.expect(!res1.crashed);
    try std.testing.expectEqual(@as(u64, 1), res1.ret_val);
    try std.testing.expectEqual(@as(usize, 2), table.hitCount());

    const short_in = "A";
    const res2 = veh.runProtected(f, short_in.ptr, short_in.len);
    try std.testing.expect(!res2.crashed);
    try std.testing.expectEqual(@as(u64, 0), res2.ret_val);
    try std.testing.expectEqual(@as(usize, 3), table.hitCount());
}

test "arm64_isa compute extensions & 4K hardcoded constant detector" {
    try std.testing.expectEqual(arm64_isa.ComputeExt.dotprod, arm64_isa.classifyComputeExt(0x4E80_9400)); // sdot
    try std.testing.expectEqual(arm64_isa.ComputeExt.i8mm, arm64_isa.classifyComputeExt(0x4E80_A400)); // smmla
    try std.testing.expectEqual(arm64_isa.ComputeExt.crypto_aes, arm64_isa.classifyComputeExt(0x4E28_4800)); // aese
    try std.testing.expectEqual(arm64_isa.ComputeExt.crc32, arm64_isa.classifyComputeExt(0x1AC0_4000)); // crc32b
    try std.testing.expect(arm64_isa.isHardcoded4kPageImm(0xD282_0000)); // mov x0, #0x1000
    try std.testing.expect(arm64_isa.isHardcoded4kPageImm(0x9274_CC00)); // and x0, x0, #~0xfff
    try std.testing.expect(!arm64_isa.isHardcoded4kPageImm(0xD503_201F)); // nop
}

test "finding + SARIF 2.1.0 / JUnit / JSON roundtrip" {
    const alloc = std.testing.allocator;
    var fs = finding.FindingSet.init(alloc);
    defer fs.deinit();

    try fs.add(.{
        .rule_id = "SO-HARDEN-003",
        .artifact = "C:/bins/demo_arm64.dll",
        .rva = 0x1200,
        .func_name = "parse_header",
        .detail = "Control Flow Guard \"missing\" in <demo>",
    });

    const json_bytes = try report.renderFindingSet(alloc, &fs, .json, "PAYLOAD");
    defer alloc.free(json_bytes);
    try std.testing.expect(std.mem.indexOf(u8, json_bytes, "\"SO-HARDEN-003\"") != null);

    var reparsed = finding.FindingSet.init(alloc);
    defer reparsed.deinit();
    try report.parseJsonReportIntoFindingSet(alloc, json_bytes, &reparsed);
    try std.testing.expectEqual(@as(usize, 1), reparsed.items.items.len);
    try std.testing.expectEqualStrings("SO-HARDEN-003", reparsed.items.items[0].rule_id);

    const sarif = try report.renderFindingSet(alloc, &fs, .sarif, "PAYLOAD");
    defer alloc.free(sarif);
    try std.testing.expect(std.mem.indexOf(u8, sarif, "\"version\": \"2.1.0\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, sarif, "\"security-severity\"") != null);

    const junit = try report.renderFindingSet(alloc, &fs, .junit, null);
    defer alloc.free(junit);
    try std.testing.expect(std.mem.indexOf(u8, junit, "&lt;demo&gt;") != null);
    try std.testing.expect(std.mem.indexOf(u8, junit, "<failure ") != null);
}

test "symbols demangler (Itanium and MSVC)" {
    const alloc = std.testing.allocator;
    const it = try symbols.demangle(alloc, "_ZN4snap6Oracle4initEv");
    defer alloc.free(it);
    try std.testing.expect(std.mem.startsWith(u8, it, "snap::Oracle::init"));

    const msvc = try symbols.demangle(alloc, "?parseHeader@Parser@snap@@QEAAXXZ");
    defer alloc.free(msvc);
    try std.testing.expect(std.mem.startsWith(u8, msvc, "snap::Parser::parseHeader"));
}

test "Ed25519 offline commercial license verification" {
    const alloc = std.testing.allocator;
    const seed: [32]u8 = @splat(0x5A);
    const tok_json = try license.generateDemoSignedTokenJson(
        std.testing.io,
        alloc,
        "ArmEnterpriseInc",
        .enterprise_commercial,
        50,
        "2027-12-31",
        seed,
    );
    defer alloc.free(tok_json);

    const ok = try license.verifyTokenJson(alloc, tok_json, null, 20261119);
    try std.testing.expect(ok.valid);
    try std.testing.expectEqual(license.LicenseTier.enterprise_commercial, ok.tier);

    const expired = try license.verifyTokenJson(alloc, tok_json, null, 20280101);
    try std.testing.expect(!expired.valid);

    const wrong_pk_buf: [64]u8 = @splat('0');
    const wrong_pk = try license.verifyTokenJson(alloc, tok_json, &wrong_pk_buf, 20261119);
    try std.testing.expect(!wrong_pk.valid);
}

test "imports compatibility matrix & synthetic SBOM embedded component detection" {
    try std.testing.expectEqual(imports.CompatStatus.ok, imports.checkArchCompatibility(.arm64, false, .arm64, false));
    try std.testing.expectEqual(imports.CompatStatus.machine_mismatch, imports.checkArchCompatibility(.arm64, false, .amd64, false));
    try std.testing.expectEqual(imports.CompatStatus.ec_bridge_ok, imports.checkArchCompatibility(.arm64, true, .amd64, false));

    // Minimal valid PE32+ ARM64 buffer embedding an OpenSSL string
    const alloc = std.testing.allocator;
    var raw: [1024]u8 = @splat(0);
    raw[0] = 'M';
    raw[1] = 'Z';
    std.mem.writeInt(u32, raw[0x3C..][0..4], 0x80, .little);
    @memcpy(raw[0x80..0x84], "PE\x00\x00");
    std.mem.writeInt(u16, raw[0x84..][0..2], 0xAA64, .little);
    std.mem.writeInt(u16, raw[0x86..][0..2], 1, .little);
    std.mem.writeInt(u16, raw[0x94..][0..2], 240, .little);
    std.mem.writeInt(u16, raw[0x98..][0..2], 0x020B, .little);
    std.mem.writeInt(u32, raw[0xD0..][0..4], 0x1000, .little);
    @memcpy(raw[0x300..0x30E], "OpenSSL 3.0.13");

    var bom = try sbom.buildSbom(alloc, "demo_arm64.dll", &raw);
    defer bom.deinit();
    try std.testing.expect(bom.components.len >= 1);
    try std.testing.expectEqualStrings("OpenSSL", bom.components[0].name);
    try std.testing.expectEqualStrings("3.0.13", bom.components[0].version);

    const cdx = try sbom.renderSbom(alloc, &bom, .cyclonedx);
    defer alloc.free(cdx);
    try std.testing.expect(std.mem.indexOf(u8, cdx, "pkg:generic/openssl@3.0.13") != null);
}

test "pagesize readiness catches 4K ELF failure on 16K kernels & portscan catches x64 hazards" {
    const alloc = std.testing.allocator;
    // Build minimal ELF64 AArch64 with 1 PT_LOAD (p_align = 4096 -> fail 16K!)
    var elf: [256]u8 = @splat(0);
    @memcpy(elf[0..4], "\x7fELF");
    elf[4] = 2; // ELF64
    elf[5] = 1; // LE
    elf[6] = 1;
    std.mem.writeInt(u16, elf[16..18], 3, .little); // ET_DYN
    std.mem.writeInt(u16, elf[18..20], 183, .little); // EM_AARCH64
    std.mem.writeInt(u64, elf[32..40], 64, .little); // e_phoff
    std.mem.writeInt(u16, elf[54..56], 56, .little); // e_phentsize
    std.mem.writeInt(u16, elf[56..58], 1, .little); // e_phnum
    // PT_LOAD at offset 64: p_type=1, p_flags=5 (RX), p_offset=0, p_vaddr=0, memsz=256, align=4096
    std.mem.writeInt(u32, elf[64..68], 1, .little);
    std.mem.writeInt(u32, elf[68..72], 5, .little);
    std.mem.writeInt(u64, elf[96..104], 256, .little);
    std.mem.writeInt(u64, elf[104..112], 256, .little);
    std.mem.writeInt(u64, elf[112..120], 4096, .little);

    var fs = finding.FindingSet.init(alloc);
    defer fs.deinit();
    const ps_rep = try pagesize.auditPageSize(alloc, "libfoo.so", &elf, &fs);
    try std.testing.expectEqual(pagesize.PageVerdict.pass, ps_rep.targets[0].verdict); // 4K pass
    try std.testing.expectEqual(pagesize.PageVerdict.fail, ps_rep.targets[1].verdict); // 16K fail

    // Source portscan ignores comments and flags real intrinsics
    var src_fs = finding.FindingSet.init(alloc);
    defer src_fs.deinit();
    const sample_src =
        \\// comment mentioning _mm_add_ps should be ignored
        \\#ifdef _M_X64
        \\uint64_t t = __rdtsc();
        \\__m128i v = _mm_setzero_si128();
        \\#endif
        \\volatile int ready_flag = 0;
        \\
    ;
    _ = try portscan.scanSourceText(alloc, "fast.c", sample_src, &src_fs);
    try std.testing.expect(src_fs.items.items.len >= 3);
}

test "crash_triage classification, harnessgen, cmin set-cover, baseline diff & expiring waivers" {
    const alloc = std.testing.allocator;

    const pac_res = veh.RunResult{
        .crashed = true,
        .exception_code = 0xC000_0005,
        .exception_addr = 0x1000,
        .fault_rva = 0x200,
        .fault_addr = 0x2000_0000_DEAD_BEEF,
        .access_type = 1,
        .ret_val = 0,
    };
    const v_pac = crash_triage.classifyCrash(pac_res, "ABCD", null, null, null);
    try std.testing.expectEqual(crash_triage.CrashClass.pac_auth_fail, v_pac.class);

    var write_in: [8]u8 = undefined;
    std.mem.writeInt(u64, &write_in, 0x0000_0000_4142_4344, .little);
    const taint_res = veh.RunResult{
        .crashed = true,
        .exception_code = 0xC000_0005,
        .exception_addr = 0x1000,
        .fault_rva = 0x204,
        .fault_addr = 0x4142_4344,
        .access_type = 2,
        .ret_val = 0,
    };
    const v_write = crash_triage.classifyCrash(taint_res, &write_in, null, null, null);
    try std.testing.expectEqual(crash_triage.CrashClass.wild_write, v_write.class);
    try std.testing.expect(v_write.input_tainted_addr);

    const c_rep = try harnessgen.generateRepro(alloc, .c, "target.dll", "fuzz_entry", "STAT");
    defer alloc.free(c_rep);
    try std.testing.expect(std.mem.indexOf(u8, c_rep, "CRASH_INPUT") != null);

    // cmin greedy set-cover picks 2 seeds covering {0,1,2,3} skipping redundant seed #2
    const traces = [_]cmin.SeedTrace{
        .{ .name = "s0", .bytes = "AAAA", .crashed = false, .hit_blocks = &.{ 0, 1 } },
        .{ .name = "s1", .bytes = "BBBBBBBB", .crashed = false, .hit_blocks = &.{ 2, 3 } },
        .{ .name = "s2", .bytes = "CCCCCCCCCCCC", .crashed = false, .hit_blocks = &.{ 0, 2 } },
    };
    const picked = try cmin.selectMinimalSeeds(alloc, 4, &traces);
    defer alloc.free(picked);
    try std.testing.expectEqual(@as(usize, 2), picked.len);

    // CI Gate baseline + expiring waiver
    var fs = finding.FindingSet.init(alloc);
    defer fs.deinit();
    try fs.add(.{ .rule_id = "SO-HARDEN-003", .artifact = "app.dll", .detail = "missing CFG" });
    const rep_json = try report.renderFindingSet(alloc, &fs, .json, null);
    defer alloc.free(rep_json);

    const waiver_active =
        \\{ "waivers": [{ "rule_id": "SO-HARDEN-003", "artifact": "app.dll", "expires": "2027-01-01" }] }
    ;
    var active1 = finding.FindingSet.init(alloc);
    defer active1.deinit();
    const g1 = try ci_gate.evaluateGate(alloc, rep_json, null, waiver_active, .high, 20261119, &active1);
    try std.testing.expect(g1.passed);
    try std.testing.expectEqual(@as(usize, 1), g1.waived);

    const waiver_expired =
        \\{ "waivers": [{ "rule_id": "SO-HARDEN-003", "artifact": "app.dll", "expires": "2026-01-01" }] }
    ;
    var active2 = finding.FindingSet.init(alloc);
    defer active2.deinit();
    const g2 = try ci_gate.evaluateGate(alloc, rep_json, null, waiver_expired, .high, 20261119, &active2);
    try std.testing.expect(!g2.passed);
    try std.testing.expectEqual(@as(usize, 1), g2.expired_waivers);
}

test "hostile malformed binary input resilience across enterprise static parsers" {
    const alloc = std.testing.allocator;
    var rng = mutator.Rng.init(0xCAFE_BABE_1337_0001);
    var buf: [512]u8 = @splat(0);
    for (0..32) |_| {
        buf[0] = 'M';
        buf[1] = 'Z';
        const len = mutator.mutateHavoc(&rng, &buf, 256);
        const slice = buf[0..len];

        if (imports.analyzeImports(alloc, slice)) |*ia| {
            var tmp = ia.*;
            tmp.deinit();
        } else |_| {}

        var fs = finding.FindingSet.init(alloc);
        defer fs.deinit();
        _ = pagesize.auditPageSize(alloc, "fuzz.bin", slice, &fs) catch {};
        _ = hardening.auditHardening(alloc, "fuzz.bin", slice, .baseline, &fs) catch {};
        if (sbom.buildSbom(alloc, "fuzz.bin", slice)) |*s| {
            var tmp = s.*;
            tmp.deinit();
        } else |_| {}
    }
}
