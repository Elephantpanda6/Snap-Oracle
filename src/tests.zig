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

test "Ed25519 offline license verification" {
    const alloc = std.testing.allocator;
    const seed: [32]u8 = @splat(0x5A);
    const tok_json = try license.generateDemoSignedTokenJson(
        std.testing.io,
        alloc,
        "ArmSampleOrg",
        .organization,
        50,
        "2027-12-31",
        seed,
    );
    defer alloc.free(tok_json);

    const ok = try license.verifyTokenJson(alloc, tok_json, null, 20261119);
    try std.testing.expect(ok.valid);
    try std.testing.expectEqual(license.LicenseTier.organization, ok.tier);

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

test "hostile malformed binary input resilience across static parsers" {
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

fn buildTestPeWithImports(
    alloc: std.mem.Allocator,
    machine: pe.Machine,
    dll_names: []const []const u8,
) ![]u8 {
    // 4096-byte PE32+ with .text (RVA 0x1000) and .rdata (RVA 0x2000, raw 0x400) containing IAT/ILT + descriptors
    const buf = try alloc.alloc(u8, 4096);
    @memset(buf, 0);
    buf[0] = 'M';
    buf[1] = 'Z';
    std.mem.writeInt(u32, buf[0x3C..][0..4], 0x80, .little);
    @memcpy(buf[0x80..0x84], "PE\x00\x00");
    std.mem.writeInt(u16, buf[0x84..][0..2], @intFromEnum(machine), .little);
    std.mem.writeInt(u16, buf[0x86..][0..2], 2, .little); // 2 sections
    std.mem.writeInt(u16, buf[0x94..][0..2], 240, .little);
    std.mem.writeInt(u16, buf[0x98..][0..2], 0x020B, .little); // PE32+
    std.mem.writeInt(u32, buf[0x98 + 56 ..][0..4], 0x3000, .little); // SizeOfImage
    std.mem.writeInt(u32, buf[0x98 + 108 ..][0..4], 16, .little); // NumberOfRvaAndSizes
    // DataDirectory[1] (Import): RVA 0x2000
    std.mem.writeInt(u32, buf[0x98 + 112 + 8 ..][0..4], 0x2000, .little);
    std.mem.writeInt(u32, buf[0x98 + 112 + 12 ..][0..4], 256, .little);

    // Section 0: .text (RVA 0x1000, raw 0x200, size 0x100)
    @memcpy(buf[0x188 .. 0x188 + 5], ".text");
    std.mem.writeInt(u32, buf[0x188 + 8 ..][0..4], 0x100, .little);
    std.mem.writeInt(u32, buf[0x188 + 12 ..][0..4], 0x1000, .little);
    std.mem.writeInt(u32, buf[0x188 + 16 ..][0..4], 0x100, .little);
    std.mem.writeInt(u32, buf[0x188 + 20 ..][0..4], 0x200, .little);
    std.mem.writeInt(u32, buf[0x188 + 36 ..][0..4], pe.IMAGE_SCN_MEM_READ | pe.IMAGE_SCN_MEM_EXECUTE, .little);

    // Section 1: .rdata (RVA 0x2000, raw 0x400, size 0x800)
    const s1 = 0x188 + 40;
    @memcpy(buf[s1 .. s1 + 6], ".rdata");
    std.mem.writeInt(u32, buf[s1 + 8 ..][0..4], 0x800, .little);
    std.mem.writeInt(u32, buf[s1 + 12 ..][0..4], 0x2000, .little);
    std.mem.writeInt(u32, buf[s1 + 16 ..][0..4], 0x800, .little);
    std.mem.writeInt(u32, buf[s1 + 20 ..][0..4], 0x400, .little);
    std.mem.writeInt(u32, buf[s1 + 36 ..][0..4], pe.IMAGE_SCN_MEM_READ, .little);

    var str_off: usize = 0x600;
    for (dll_names, 0..) |dll, idx| {
        const desc_off = 0x400 + idx * 20;
        const name_rva: u32 = 0x2000 + @as(u32, @intCast(str_off - 0x400));
        std.mem.writeInt(u32, buf[desc_off + 12 ..][0..4], name_rva, .little);
        @memcpy(buf[str_off .. str_off + dll.len], dll);
        str_off += dll.len + 1;
    }
    return buf;
}

fn buildMinimalArm64MachoSlice(alloc: std.mem.Allocator, cputype: u32, filetype: u32, flags: u32, seg_vmaddr: u64, seg_fileoff: u64) ![]u8 {
    const buf = try alloc.alloc(u8, 512);
    @memset(buf, 0);
    std.mem.writeInt(u32, buf[0..4], 0xFEED_FACF, .little);
    std.mem.writeInt(u32, buf[4..8], cputype, .little);
    std.mem.writeInt(u32, buf[12..16], filetype, .little);
    std.mem.writeInt(u32, buf[16..20], 1, .little); // ncmds = 1
    std.mem.writeInt(u32, buf[20..24], 152, .little); // sizeofcmds
    std.mem.writeInt(u32, buf[24..28], flags, .little);

    // LC_SEGMENT_64 (72 + 80 = 152) at offset 32
    std.mem.writeInt(u32, buf[32..36], 0x19, .little);
    std.mem.writeInt(u32, buf[36..40], 152, .little);
    @memcpy(buf[40 .. 40 + 6], "__TEXT");
    std.mem.writeInt(u64, buf[56..64], seg_vmaddr, .little);
    std.mem.writeInt(u64, buf[64..72], 0x4000, .little);
    std.mem.writeInt(u64, buf[72..80], seg_fileoff, .little);
    std.mem.writeInt(u64, buf[80..88], 0x200, .little);
    std.mem.writeInt(u32, buf[92..96], 5, .little); // initprot RX
    std.mem.writeInt(u32, buf[96..100], 1, .little); // nsects

    // section_64 __text at 104
    @memcpy(buf[104 .. 104 + 6], "__text");
    std.mem.writeInt(u64, buf[104 + 32 ..][0..8], seg_vmaddr + 0x100, .little);
    std.mem.writeInt(u64, buf[104 + 40 ..][0..8], 16, .little);
    std.mem.writeInt(u32, buf[104 + 48 ..][0..4], 0x100, .little);
    std.mem.writeInt(u32, buf[104 + 64 ..][0..4], 0x8000_0400, .little);
    std.mem.writeInt(u32, buf[0x100..0x104], 0xD503_201F, .little); // nop
    std.mem.writeInt(u32, buf[0x104..0x108], 0xD65F_03C0, .little); // ret
    return buf;
}

test "regression: license UAF, parseYmd calendar, delimiter injection, and unpinned warning" {
    const alloc = std.testing.allocator;
    const seed: [32]u8 = @splat(0x3C);

    // Date validation
    try std.testing.expectEqual(@as(?u32, 20240229), license.parseYmd("2024-02-29"));
    try std.testing.expectEqual(@as(?u32, 20000229), license.parseYmd("2000-02-29"));
    try std.testing.expectEqual(@as(?u32, 20261119), license.parseYmd("20261119"));
    try std.testing.expect(license.parseYmd("20269999") == null);
    try std.testing.expect(license.parseYmd("1969-12-31") == null);
    try std.testing.expect(license.parseYmd("2025-02-29") == null);
    try std.testing.expect(license.parseYmd("2100-02-29") == null);
    try std.testing.expect(license.parseYmd("2026-04-31") == null);
    try std.testing.expect(license.parseYmd("2026_119") == null);

    // Reject delimiter injection & invalid dates
    try std.testing.expectError(error.InvalidLicenseOrg, license.canonicalMessage(alloc, "Bad|Org", .team, 5, "2027-12-31", 1));
    try std.testing.expectError(error.InvalidExpiryDate, license.generateDemoSignedTokenJson(std.testing.io, alloc, "SafeOrg", .team, 5, "20269999", seed));

    const tok_json = try license.generateDemoSignedTokenJson(std.testing.io, alloc, "SafeOrg", .organization, 10, "2027-12-31", seed);
    defer alloc.free(tok_json);

    // Unpinned pubkey must NOT claim "Valid offline Ed25519-signed license"
    const unpinned = try license.verifyTokenJson(alloc, tok_json, null, 20261119);
    try std.testing.expect(unpinned.valid);
    try std.testing.expectEqualStrings("SafeOrg", unpinned.org());
    try std.testing.expect(std.mem.indexOf(u8, unpinned.reason, "Valid offline Ed25519-signed license") == null);

    // Pinned pubkey claims "Valid offline Ed25519-signed license"
    const parsed_tok = try std.json.parseFromSlice(license.LicenseToken, alloc, tok_json, .{ .ignore_unknown_fields = true });
    defer parsed_tok.deinit();
    const pinned = try license.verifyTokenJson(alloc, tok_json, parsed_tok.value.pubkey_hex, 20261119);
    try std.testing.expect(pinned.valid);
    try std.testing.expectEqualStrings("SafeOrg", pinned.org());
    try std.testing.expectEqualStrings("Valid offline Ed25519-signed license", pinned.reason);
}

test "regression: perfadvisor owns hot_funcs[].name after symtab.deinit" {
    const alloc = std.testing.allocator;
    var raw: [1280]u8 = @splat(0);
    raw[0] = 'M';
    raw[1] = 'Z';
    std.mem.writeInt(u32, raw[0x3C..][0..4], 0x80, .little);
    @memcpy(raw[0x80..0x84], "PE\x00\x00");
    std.mem.writeInt(u16, raw[0x84..][0..2], 0xAA64, .little);
    std.mem.writeInt(u16, raw[0x86..][0..2], 2, .little);
    std.mem.writeInt(u16, raw[0x94..][0..2], 240, .little);
    std.mem.writeInt(u16, raw[0x98..][0..2], 0x020B, .little);
    std.mem.writeInt(u32, raw[0x98 + 56 ..][0..4], 0x4000, .little);
    std.mem.writeInt(u32, raw[0x98 + 108 ..][0..4], 16, .little);
    std.mem.writeInt(u32, raw[0x98 + 112 ..][0..4], 0x2000, .little);
    std.mem.writeInt(u32, raw[0x98 + 116 ..][0..4], 64, .little);
    std.mem.writeInt(u32, raw[0x98 + 112 + 24 ..][0..4], 0x2100, .little);
    std.mem.writeInt(u32, raw[0x98 + 116 + 24 ..][0..4], 8, .little);

    @memcpy(raw[0x188 .. 0x188 + 5], ".text");
    std.mem.writeInt(u32, raw[0x188 + 8 ..][0..4], 0x100, .little);
    std.mem.writeInt(u32, raw[0x188 + 12 ..][0..4], 0x1000, .little);
    std.mem.writeInt(u32, raw[0x188 + 16 ..][0..4], 0x100, .little);
    std.mem.writeInt(u32, raw[0x188 + 20 ..][0..4], 0x200, .little);
    std.mem.writeInt(u32, raw[0x188 + 36 ..][0..4], pe.IMAGE_SCN_MEM_READ | pe.IMAGE_SCN_MEM_EXECUTE, .little);

    const s1 = 0x188 + 40;
    @memcpy(raw[s1 .. s1 + 6], ".rdata");
    std.mem.writeInt(u32, raw[s1 + 8 ..][0..4], 0x200, .little);
    std.mem.writeInt(u32, raw[s1 + 12 ..][0..4], 0x2000, .little);
    std.mem.writeInt(u32, raw[s1 + 16 ..][0..4], 0x200, .little);
    std.mem.writeInt(u32, raw[s1 + 20 ..][0..4], 0x300, .little);
    std.mem.writeInt(u32, raw[s1 + 36 ..][0..4], pe.IMAGE_SCN_MEM_READ, .little);

    std.mem.writeInt(u32, raw[0x200..][0..4], 0xD503_201F, .little);
    std.mem.writeInt(u32, raw[0x204..][0..4], 0xD65F_03C0, .little);
    std.mem.writeInt(u32, raw[0x300 + 24 ..][0..4], 1, .little);
    std.mem.writeInt(u32, raw[0x300 + 28 ..][0..4], 0x2028, .little);
    std.mem.writeInt(u32, raw[0x300 + 32 ..][0..4], 0x202C, .little);
    std.mem.writeInt(u32, raw[0x300 + 36 ..][0..4], 0x2030, .little);
    std.mem.writeInt(u32, raw[0x328..][0..4], 0x1000, .little);
    std.mem.writeInt(u32, raw[0x32C..][0..4], 0x2034, .little);
    @memcpy(raw[0x334 .. 0x334 + 9], "hot_gemm\x00");
    std.mem.writeInt(u32, raw[0x400..][0..4], 0x1000, .little);
    std.mem.writeInt(u32, raw[0x404..][0..4], 1 | (2 << 2), .little);

    var fs = finding.FindingSet.init(alloc);
    defer fs.deinit();
    var rep = try perfadvisor.analyzePerformance(alloc, "hot.dll", &raw, null, &fs);
    defer rep.deinit();

    try std.testing.expectEqual(@as(usize, 1), rep.hot_funcs.len);
    try std.testing.expectEqualStrings("hot_gemm", rep.hot_funcs[0].name);
}

test "regression: finding line fingerprints, UTF-8/ctrl JSON escaping, SARIF startLine, GHA escaping, catalog fallback" {
    const alloc = std.testing.allocator;
    var fs = finding.FindingSet.init(alloc);
    defer fs.deinit();

    try fs.add(.{
        .rule_id = "SO-PORT-001",
        .artifact = "dir/a:b,c%d\ne.rs",
        .line = 12,
        .detail = "line12\x08\x0C\x7F valid: café \xFF\xE2\x82\xC0\xAF\xED\xA0\x80\nnext",
    });
    try fs.add(.{
        .rule_id = "SO-PORT-001",
        .artifact = "dir/a:b,c%d\ne.rs",
        .line = 99,
        .detail = "line12\x08\x0C\x7F valid: café \xFF\xE2\x82\xC0\xAF\xED\xA0\x80\nnext",
    });
    try fs.add(.{
        .rule_id = "SO-HARDEN-002",
        .artifact = "libfoo.so",
        .detail = "missing PT_GNU_STACK",
    });
    try fs.add(.{
        .rule_id = "SO-HARDEN-002",
        .artifact = "libfoo.so",
        .detail = "W+X segment",
    });

    try std.testing.expect(fs.items.items[0].fingerprint != fs.items.items[1].fingerprint);
    try std.testing.expect(fs.items.items[2].fingerprint != fs.items.items[3].fingerprint);

    const json_bytes = try report.renderFindingSet(alloc, &fs, .json, null);
    defer alloc.free(json_bytes);
    try std.testing.expect(std.mem.indexOf(u8, json_bytes, "\\b\\f\\u007f") != null);
    try std.testing.expect(std.mem.indexOf(u8, json_bytes, "\\uFFFD") != null);

    // Must parse cleanly as valid JSON
    const parsed = try std.json.parseFromSlice(report.JsonReportDto, alloc, json_bytes, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    try std.testing.expectEqual(@as(?u32, 12), parsed.value.findings[0].line);

    // Empty remediation in JSON restores catalog default remediation
    const empty_rem_json =
        \\{"findings":[{"rule_id":"SO-PORT-001","severity":"high","title":"x","detail":"d","artifact":"f.c","line":7,"remediation":""}]}
    ;
    var reparsed = finding.FindingSet.init(alloc);
    defer reparsed.deinit();
    try report.parseJsonReportIntoFindingSet(alloc, empty_rem_json, &reparsed);
    try std.testing.expectEqual(@as(?u32, 7), reparsed.items.items[0].line);
    try std.testing.expect(reparsed.items.items[0].remediation.len > 10);

    const sarif = try report.renderFindingSet(alloc, &fs, .sarif, null);
    defer alloc.free(sarif);
    try std.testing.expect(std.mem.indexOf(u8, sarif, "\"startLine\": 12") != null);

    const gha = try report.renderFindingSet(alloc, &fs, .gha, null);
    defer alloc.free(gha);
    try std.testing.expect(std.mem.indexOf(u8, gha, "file=a%3Ab%2Cc%25d%0Ae.rs,line=12,title=SO-PORT-001") != null);
    try std.testing.expect(std.mem.indexOf(u8, gha, "%0Anext") != null);
}

test "regression: symbols _ZSt demangling, DWARF unterminated dir-table, and integer overflow hardening" {
    const alloc = std.testing.allocator;
    const dem = try symbols.demangle(alloc, "_ZSt9terminatev");
    defer alloc.free(dem);
    try std.testing.expectEqualStrings("std::terminate(...)", dem);

    // ELF64 with .debug_line CU whose include-dir table has no terminating 0 byte (must abort CU cleanly)
    var elf: [512]u8 = @splat(0);
    @memcpy(elf[0..4], "\x7fELF");
    elf[4] = 2;
    elf[5] = 1;
    std.mem.writeInt(u16, elf[18..20], 183, .little);
    std.mem.writeInt(u64, elf[40..48], 64, .little); // e_shoff
    std.mem.writeInt(u16, elf[58..60], 64, .little); // e_shentsize
    std.mem.writeInt(u16, elf[60..62], 2, .little); // e_shnum
    std.mem.writeInt(u16, elf[62..64], 0, .little); // e_shstrndx

    // SHDR[0]: .shstrtab at 0x100
    std.mem.writeInt(u32, elf[64 + 4 ..][0..4], 3, .little);
    std.mem.writeInt(u64, elf[64 + 24 ..][0..8], 0x100, .little);
    std.mem.writeInt(u64, elf[64 + 32 ..][0..8], 32, .little);
    @memcpy(elf[0x100 .. 0x100 + 13], "\x00.debug_line\x00");

    // SHDR[1]: .debug_line at 0x140 (size 32)
    std.mem.writeInt(u32, elf[128..132], 1, .little);
    std.mem.writeInt(u32, elf[128 + 4 ..][0..4], 1, .little);
    std.mem.writeInt(u64, elf[128 + 8 ..][0..8], 2, .little); // SHF_ALLOC
    std.mem.writeInt(u64, elf[128 + 24 ..][0..8], 0x140, .little);
    std.mem.writeInt(u64, elf[128 + 32 ..][0..8], 32, .little);

    // Malformed DWARF v3 CU: unit_len=28, version=3, header_len=18, opcode_base=1, dir="unterminated_dir" (no trailing empty string)
    std.mem.writeInt(u32, elf[0x140..0x144], 28, .little);
    std.mem.writeInt(u16, elf[0x144..0x146], 3, .little);
    std.mem.writeInt(u32, elf[0x146..0x14A], 18, .little);
    elf[0x14E] = 1; // opcode_base = 1 (0 std opcodes)
    @memcpy(elf[0x14F .. 0x14F + 17], "bad_unterm_dir_xx"); // fills up to hdr_end without 0

    var img = try binary.parseBinary(alloc, &elf);
    defer img.deinit();
    const files = try symbols.extractDwarfSourceFiles(alloc, &elf, &img);
    defer {
        for (files) |f| alloc.free(f);
        alloc.free(files);
    }
    try std.testing.expectEqual(@as(usize, 0), files.len);

    // Overflowing .debug_line section raw_offset + raw_size returns empty without panic/leak
    std.mem.writeInt(u64, elf[128 + 24 ..][0..8], 0xFFFF_FFF0, .little);
    std.mem.writeInt(u64, elf[128 + 32 ..][0..8], 0x20, .little);
    var img_ovf = try binary.parseBinary(alloc, &elf);
    defer img_ovf.deinit();
    const files_ovf = try symbols.extractDwarfSourceFiles(alloc, &elf, &img_ovf);
    defer alloc.free(files_ovf);
    try std.testing.expectEqual(@as(usize, 0), files_ovf.len);

    // Hostile overflow values across ELF/Fat parsers must not panic or leak
    var bad_elf: [128]u8 = @splat(0);
    @memcpy(bad_elf[0..4], "\x7fELF");
    bad_elf[4] = 2;
    bad_elf[5] = 1;
    std.mem.writeInt(u16, bad_elf[18..20], 183, .little);
    std.mem.writeInt(u64, bad_elf[32..40], 0xFFFF_FFFF_FFFF_FFF0, .little); // overflowing e_phoff
    std.mem.writeInt(u16, bad_elf[54..56], 56, .little);
    std.mem.writeInt(u16, bad_elf[56..58], 4, .little);

    var fs = finding.FindingSet.init(alloc);
    defer fs.deinit();
    if (imports.analyzeImports(alloc, &bad_elf)) |*ia| {
        var tmp = ia.*;
        tmp.deinit();
    } else |_| {}
    _ = try pagesize.auditPageSize(alloc, "bad.so", &bad_elf, &fs);
    _ = try hardening.auditHardening(alloc, "bad.so", &bad_elf, .baseline, &fs);
    if (sbom.buildSbom(alloc, "bad.so", &bad_elf)) |*sb| {
        var tmp = sb.*;
        tmp.deinit();
    } else |_| {}
    var pr = try perfadvisor.analyzePerformance(alloc, "bad.so", &bad_elf, null, &fs);
    pr.deinit();
    try portscan.scanBinaryPortability(alloc, "bad.so", &bad_elf, &fs);
}

test "regression: imports true case-insensitive BFS transitive dependency resolver" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const dir_path = try std.fmt.allocPrint(alloc, ".zig-cache/tmp/{s}", .{&tmp.sub_path});
    defer alloc.free(dir_path);

    const root_pe = try buildTestPeWithImports(alloc, .arm64, &.{"Mid.dll"});
    defer alloc.free(root_pe);
    const mid_pe = try buildTestPeWithImports(alloc, .arm64, &.{ "Leaf.dll", "MID.DLL" });
    defer alloc.free(mid_pe);
    const leaf_pe = try buildTestPeWithImports(alloc, .arm64, &.{ "BadX64.dll", "mid.dll" });
    defer alloc.free(leaf_pe);
    const bad_pe = try buildTestPeWithImports(alloc, .amd64, &.{});
    defer alloc.free(bad_pe);

    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "root.dll", .data = root_pe });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "Mid.dll", .data = mid_pe });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "Leaf.dll", .data = leaf_pe });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "BadX64.dll", .data = bad_pe });

    const root_full = try std.fmt.allocPrint(alloc, "{s}/root.dll", .{dir_path});
    defer alloc.free(root_full);

    var fs = finding.FindingSet.init(alloc);
    defer fs.deinit();
    var ia = try imports.auditDependencies(std.testing.io, alloc, root_full, root_pe, null, true, &fs);
    defer ia.deinit();

    var dep001_cnt: usize = 0;
    for (fs.items.items) |f| {
        if (std.mem.eql(u8, f.rule_id, "SO-DEP-001")) {
            dep001_cnt += 1;
            try std.testing.expect(std.mem.indexOf(u8, f.detail, "BadX64.dll") != null);
        }
    }
    try std.testing.expectEqual(@as(usize, 1), dep001_cnt);
}

test "regression: hardening Mach-O dylib/bundle, strict PAC/BTI despite note, PE GuardFlags, ELF PT_GNU_STACK" {
    const alloc = std.testing.allocator;

    // 1. Mach-O MH_DYLIB (6) and MH_BUNDLE (8) are ASLR/PIE without MH_PIE flag
    const dylib = try buildMinimalArm64MachoSlice(alloc, 0x0100_000C, 6, 0, 0x1_0000_0000, 0);
    defer alloc.free(dylib);
    var fs_dy = finding.FindingSet.init(alloc);
    defer fs_dy.deinit();
    const sum_dy = try hardening.auditHardening(alloc, "libdemo.dylib", dylib, .baseline, &fs_dy);
    try std.testing.expect(sum_dy.aslr_pie);

    const bundle = try buildMinimalArm64MachoSlice(alloc, 0x0100_000C, 8, 0, 0x1_0000_0000, 0);
    defer alloc.free(bundle);
    var fs_bu = finding.FindingSet.init(alloc);
    defer fs_bu.deinit();
    const sum_bu = try hardening.auditHardening(alloc, "demo.bundle", bundle, .baseline, &fs_bu);
    try std.testing.expect(sum_bu.aslr_pie);

    // 2. ELF with PAC+BTI note & 8 functions lacking PAC/BTI prologues -> strict mode emits SO-PAC-001 & SO-BTI-001; missing PT_GNU_STACK sets nx_stack=false
    var elf: [1024]u8 = @splat(0);
    @memcpy(elf[0..4], "\x7fELF");
    elf[4] = 2;
    elf[5] = 1;
    std.mem.writeInt(u16, elf[16..18], 3, .little);
    std.mem.writeInt(u16, elf[18..20], 183, .little);
    std.mem.writeInt(u64, elf[40..48], 64, .little); // e_shoff
    std.mem.writeInt(u16, elf[58..60], 64, .little); // e_shentsize
    std.mem.writeInt(u16, elf[60..62], 5, .little); // e_shnum
    std.mem.writeInt(u16, elf[62..64], 1, .little); // e_shstrndx
    // SHDR[0] .text at 0x200
    std.mem.writeInt(u32, elf[64..68], 1, .little);
    std.mem.writeInt(u32, elf[68..72], 1, .little);
    std.mem.writeInt(u64, elf[72..80], 6, .little); // SHF_ALLOC | SHF_EXECINSTR
    std.mem.writeInt(u64, elf[80..88], 0x1000, .little);
    std.mem.writeInt(u64, elf[88..96], 0x200, .little);
    std.mem.writeInt(u64, elf[96..104], 0x40, .little);
    for (0..16) |k| std.mem.writeInt(u32, elf[0x200 + k * 4 ..][0..4], 0xD503_201F, .little);
    // SHDR[1] .shstrtab at 0x250
    std.mem.writeInt(u32, elf[128 + 4 ..][0..4], 3, .little);
    std.mem.writeInt(u64, elf[128 + 24 ..][0..8], 0x250, .little);
    std.mem.writeInt(u64, elf[128 + 32 ..][0..8], 32, .little);
    @memcpy(elf[0x250 .. 0x250 + 7], "\x00.text\x00");
    // SHDR[2] SHT_NOTE at 0x280 with PAC|BTI
    std.mem.writeInt(u32, elf[192 + 4 ..][0..4], 7, .little);
    std.mem.writeInt(u64, elf[192 + 24 ..][0..8], 0x280, .little);
    std.mem.writeInt(u64, elf[192 + 32 ..][0..8], 32, .little);
    std.mem.writeInt(u32, elf[0x280..0x284], 4, .little);
    std.mem.writeInt(u32, elf[0x284..0x288], 16, .little);
    std.mem.writeInt(u32, elf[0x288..0x28C], 5, .little);
    @memcpy(elf[0x28C..0x290], "GNU\x00");
    std.mem.writeInt(u32, elf[0x290..0x294], 0xC000_0000, .little);
    std.mem.writeInt(u32, elf[0x294..0x298], 4, .little);
    std.mem.writeInt(u32, elf[0x298..0x29C], 3, .little); // BTI | PAC
    // SHDR[3] .strtab at 0x2B0, SHDR[4] .symtab at 0x2D0 (8 STT_FUNC symbols)
    std.mem.writeInt(u32, elf[256 + 4 ..][0..4], 3, .little);
    std.mem.writeInt(u64, elf[256 + 24 ..][0..8], 0x2B0, .little);
    std.mem.writeInt(u64, elf[256 + 32 ..][0..8], 16, .little);
    std.mem.writeInt(u32, elf[320 + 4 ..][0..4], 2, .little);
    std.mem.writeInt(u64, elf[320 + 24 ..][0..8], 0x2D0, .little);
    std.mem.writeInt(u64, elf[320 + 32 ..][0..8], 8 * 24, .little);
    std.mem.writeInt(u32, elf[320 + 40 ..][0..4], 3, .little);
    for (0..8) |fi| {
        const soff = 0x2D0 + fi * 24;
        elf[soff + 4] = 2; // STT_FUNC
        std.mem.writeInt(u16, elf[soff + 6 ..][0..2], 1, .little);
        std.mem.writeInt(u64, elf[soff + 8 ..][0..8], 0x1000 + fi * 8, .little);
        std.mem.writeInt(u64, elf[soff + 16 ..][0..8], 8, .little);
    }

    var fs_strict = finding.FindingSet.init(alloc);
    defer fs_strict.deinit();
    const sum_elf = try hardening.auditHardening(alloc, "strict.so", &elf, .strict, &fs_strict);
    try std.testing.expect(!sum_elf.nx_stack);
    var saw_pac = false;
    var saw_bti = false;
    for (fs_strict.items.items) |f| {
        if (std.mem.eql(u8, f.rule_id, "SO-PAC-001")) saw_pac = true;
        if (std.mem.eql(u8, f.rule_id, "SO-BTI-001")) saw_bti = true;
    }
    try std.testing.expect(saw_pac and saw_bti);

    // 3. PE Load Config GuardFlags verification
    var pe_buf: [1536]u8 = @splat(0);
    pe_buf[0] = 'M';
    pe_buf[1] = 'Z';
    std.mem.writeInt(u32, pe_buf[0x3C..][0..4], 0x80, .little);
    @memcpy(pe_buf[0x80..0x84], "PE\x00\x00");
    std.mem.writeInt(u16, pe_buf[0x84..][0..2], 0xAA64, .little);
    std.mem.writeInt(u16, pe_buf[0x86..][0..2], 1, .little);
    std.mem.writeInt(u16, pe_buf[0x94..][0..2], 240, .little);
    std.mem.writeInt(u16, pe_buf[0x98..][0..2], 0x020B, .little);
    std.mem.writeInt(u32, pe_buf[0x98 + 56 ..][0..4], 0x2000, .little);
    std.mem.writeInt(u16, pe_buf[0x98 + 70 ..][0..2], 0x4140, .little); // DYNAMICBASE | NX_COMPAT | GUARD_CF
    std.mem.writeInt(u32, pe_buf[0x98 + 108 ..][0..4], 16, .little);
    std.mem.writeInt(u32, pe_buf[0x98 + 112 + 10 * 8 ..][0..4], 0x1000, .little); // DataDirectory[10] LoadConfig
    std.mem.writeInt(u32, pe_buf[0x98 + 112 + 10 * 8 + 4 ..][0..4], 256, .little);
    @memcpy(pe_buf[0x188 .. 0x188 + 6], ".rdata");
    std.mem.writeInt(u32, pe_buf[0x188 + 8 ..][0..4], 0x200, .little);
    std.mem.writeInt(u32, pe_buf[0x188 + 12 ..][0..4], 0x1000, .little);
    std.mem.writeInt(u32, pe_buf[0x188 + 16 ..][0..4], 0x200, .little);
    std.mem.writeInt(u32, pe_buf[0x188 + 20 ..][0..4], 0x200, .little);
    std.mem.writeInt(u32, pe_buf[0x188 + 36 ..][0..4], pe.IMAGE_SCN_MEM_READ, .little);
    std.mem.writeInt(u32, pe_buf[0x200..][0..4], 256, .little); // LoadConfig Size
    // GuardFlags at +144 = 0 -> fails CFG check!
    var fs_pe1 = finding.FindingSet.init(alloc);
    defer fs_pe1.deinit();
    const sum_pe1 = try hardening.auditHardening(alloc, "nocfg.dll", &pe_buf, .baseline, &fs_pe1);
    try std.testing.expect(!sum_pe1.cfg_or_full_relro);
    // Set IMAGE_GUARD_CF_INSTRUMENTED (0x100) at +144 -> passes CFG check!
    std.mem.writeInt(u32, pe_buf[0x200 + 144 ..][0..4], 0x100, .little);
    var fs_pe2 = finding.FindingSet.init(alloc);
    defer fs_pe2.deinit();
    const sum_pe2 = try hardening.auditHardening(alloc, "cfg.dll", &pe_buf, .baseline, &fs_pe2);
    try std.testing.expect(sum_pe2.cfg_or_full_relro);
}

test "regression: pagesize --targets 16k,64k, Mach-O 64K alignment, zero-memsz W^X, and Mach-O Fat unwrap" {
    const alloc = std.testing.allocator;

    // 1. Mach-O 64K-aligned vs 16K-aligned
    const m64k = try buildMinimalArm64MachoSlice(alloc, 0x0100_000C, 2, 0x0020_0000, 0x1_0000_0000, 0);
    defer alloc.free(m64k);
    var fs1 = finding.FindingSet.init(alloc);
    defer fs1.deinit();
    const rep64 = try pagesize.auditPageSizeEx(alloc, "aligned64.macho", m64k, pagesize.TargetMask.parse("16k,64k").?, &fs1);
    try std.testing.expectEqual(pagesize.PageVerdict.pass, rep64.targets[1].verdict);
    try std.testing.expectEqual(pagesize.PageVerdict.pass, rep64.targets[2].verdict);

    const m16k = try buildMinimalArm64MachoSlice(alloc, 0x0100_000C, 2, 0x0020_0000, 0x1_0000_4000, 0x4000);
    defer alloc.free(m16k);
    var fs2 = finding.FindingSet.init(alloc);
    defer fs2.deinit();
    const rep16 = try pagesize.auditPageSizeEx(alloc, "aligned16.macho", m16k, pagesize.TargetMask.parse("16k,64k").?, &fs2);
    try std.testing.expectEqual(pagesize.PageVerdict.pass, rep16.targets[1].verdict);
    try std.testing.expectEqual(pagesize.PageVerdict.fail, rep16.targets[2].verdict);
    try std.testing.expect(fs2.items.items.len >= 1);

    // 2. ELF zero-memsz W/X segment does not trigger W^X overlap
    var elf: [256]u8 = @splat(0);
    @memcpy(elf[0..4], "\x7fELF");
    elf[4] = 2;
    elf[5] = 1;
    std.mem.writeInt(u16, elf[16..18], 3, .little);
    std.mem.writeInt(u16, elf[18..20], 183, .little);
    std.mem.writeInt(u64, elf[32..40], 64, .little);
    std.mem.writeInt(u16, elf[54..56], 56, .little);
    std.mem.writeInt(u16, elf[56..58], 2, .little);
    // PHDR 0: RX memsz=256, align=65536
    std.mem.writeInt(u32, elf[64..68], 1, .little);
    std.mem.writeInt(u32, elf[68..72], 5, .little);
    std.mem.writeInt(u64, elf[96..104], 256, .little);
    std.mem.writeInt(u64, elf[104..112], 256, .little);
    std.mem.writeInt(u64, elf[112..120], 65536, .little);
    // PHDR 1: RW memsz=0 at vaddr=0x200, align=65536
    std.mem.writeInt(u32, elf[120..124], 1, .little);
    std.mem.writeInt(u32, elf[124..128], 6, .little);
    std.mem.writeInt(u64, elf[136..144], 0x200, .little);
    std.mem.writeInt(u64, elf[160..168], 0, .little);
    std.mem.writeInt(u64, elf[168..176], 65536, .little);
    var fs3 = finding.FindingSet.init(alloc);
    defer fs3.deinit();
    const rep_zero = try pagesize.auditPageSizeEx(alloc, "zero_memsz.so", &elf, pagesize.TargetMask.parse("16k,64k").?, &fs3);
    try std.testing.expectEqual(@as(usize, 0), rep_zero.targets[1].wx_overlaps);
    try std.testing.expectEqual(@as(usize, 0), rep_zero.targets[2].wx_overlaps);

    // 3. Universal Fat container (x64 slice first, ARM64 slice second, truncated 3rd slice)
    const x64_slice = try buildMinimalArm64MachoSlice(alloc, 0x0100_0007, 2, 0x0020_0000, 0x1_0000_0000, 0);
    defer alloc.free(x64_slice);
    const fat = try alloc.alloc(u8, 128 + x64_slice.len + m64k.len);
    defer alloc.free(fat);
    @memset(fat, 0);
    std.mem.writeInt(u32, fat[0..4], 0xCAFE_BABE, .big);
    std.mem.writeInt(u32, fat[4..8], 3, .big); // 3 slices (3rd truncated!)
    // Slice 0: x86_64
    std.mem.writeInt(u32, fat[8..12], 0x0100_0007, .big);
    std.mem.writeInt(u32, fat[16..20], 128, .big);
    std.mem.writeInt(u32, fat[20..24], @intCast(x64_slice.len), .big);
    // Slice 1: arm64
    const arm_off: u32 = @intCast(128 + x64_slice.len);
    std.mem.writeInt(u32, fat[28..32], 0x0100_000C, .big);
    std.mem.writeInt(u32, fat[36..40], arm_off, .big);
    std.mem.writeInt(u32, fat[40..44], @intCast(m64k.len), .big);
    // Slice 2: truncated / huge size
    std.mem.writeInt(u32, fat[48..52], 0x0100_000C, .big);
    std.mem.writeInt(u32, fat[56..60], 0xFFFF_FFF0, .big);
    std.mem.writeInt(u32, fat[60..64], 0x2000, .big);
    @memcpy(fat[128 .. 128 + x64_slice.len], x64_slice);
    @memcpy(fat[arm_off .. arm_off + m64k.len], m64k);

    const unwrapped = macho_arm64.unwrapFatSlice(fat);
    try std.testing.expectEqual(m64k.len, unwrapped.len);
    var bi = try binary.parseBinary(alloc, fat);
    defer bi.deinit();
    try std.testing.expectEqual(pe.Machine.arm64, bi.machine);
    var fs_fat = finding.FindingSet.init(alloc);
    defer fs_fat.deinit();
    const h_fat = try hardening.auditHardening(alloc, "universal.bin", fat, .baseline, &fs_fat);
    try std.testing.expectEqual(pe.Machine.arm64, h_fat.machine);
    const p_fat = try pagesize.auditPageSize(alloc, "universal.bin", fat, &fs_fat);
    try std.testing.expectEqual(pe.Machine.arm64, p_fat.machine);
    var sb_fat = try sbom.buildSbom(alloc, "universal.bin", fat);
    defer sb_fat.deinit();
    try std.testing.expectEqual(pe.Machine.arm64, sb_fat.machine);
}

test "regression: sbom lowercase deduplication, PE RSDS GUID endianness, and SPDX 2.3 fields" {
    const alloc = std.testing.allocator;
    const raw = try buildTestPeWithImports(alloc, .arm64, &.{ "KERNEL32.dll", "kernel32.dll" });
    defer alloc.free(raw);

    // Add Debug Directory DataDirectory[6] at RVA 0x2200 (raw 0x600? buildTestPeWithImports uses 0x600 for strings, put Debug at 0x700 -> RVA 0x2300)
    std.mem.writeInt(u32, raw[0x98 + 112 + 6 * 8 ..][0..4], 0x2300, .little);
    std.mem.writeInt(u32, raw[0x98 + 112 + 6 * 8 + 4 ..][0..4], 28, .little);
    // IMAGE_DEBUG_DIRECTORY at raw 0x700: Type=2 (CodeView), SizeOfData=32, PointerToRawData=0x740
    std.mem.writeInt(u32, raw[0x700 + 12 ..][0..4], 2, .little);
    std.mem.writeInt(u32, raw[0x700 + 16 ..][0..4], 32, .little);
    std.mem.writeInt(u32, raw[0x700 + 24 ..][0..4], 0x740, .little);
    // RSDS at 0x740
    @memcpy(raw[0x740..0x744], "RSDS");
    std.mem.writeInt(u32, raw[0x744..0x748], 0x1234_5678, .little); // Data1
    std.mem.writeInt(u16, raw[0x748..0x74A], 0x9ABC, .little); // Data2
    std.mem.writeInt(u16, raw[0x74A..0x74C], 0xDEF0, .little); // Data3
    const d4 = [_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
    @memcpy(raw[0x74C..0x754], &d4);
    @memcpy(raw[0x758..0x760], "app.pdb\x00");

    var bom = try sbom.buildSbom(alloc, "app.dll", raw);
    defer bom.deinit();

    // Case-insensitive deduplication: only 1 kernel32.dll component
    try std.testing.expectEqual(@as(usize, 1), bom.components.len);
    try std.testing.expectEqualStrings("kernel32.dll", bom.components[0].purl_name);
    // Proper RSDS GUID byte order
    try std.testing.expectEqualStrings("123456789abcdef01122334455667788", bom.provenance.build_id.?);

    const spdx = try sbom.renderSbom(alloc, &bom, .spdx);
    defer alloc.free(spdx);
    try std.testing.expect(std.mem.indexOf(u8, spdx, "\"creationInfo\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, spdx, "\"creators\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, spdx, "\"relationships\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, spdx, "\"DESCRIBES\"") != null);
}

test "regression: crash_triage fault_rva==0 CRT read vs null_deref vs wild_exec/pc_corrupt" {
    const crt_read = veh.RunResult{
        .crashed = true,
        .exception_code = 0xC000_0005,
        .exception_addr = 0x7FF8_1234_5678,
        .fault_rva = 0,
        .fault_addr = 0x1234_5678,
        .access_type = 1,
        .ret_val = 0,
    };
    try std.testing.expectEqual(crash_triage.CrashClass.heap_oob_read, crash_triage.classifyCrash(crt_read, "ABCD", null, null, null).class);

    const null_read = veh.RunResult{
        .crashed = true,
        .exception_code = 0xC000_0005,
        .exception_addr = 0x1000,
        .fault_rva = 0,
        .fault_addr = 0,
        .access_type = 1,
        .ret_val = 0,
    };
    try std.testing.expectEqual(crash_triage.CrashClass.null_deref, crash_triage.classifyCrash(null_read, "ABCD", null, null, null).class);

    const null_write = veh.RunResult{
        .crashed = true,
        .exception_code = 0xC000_0005,
        .exception_addr = 0,
        .fault_rva = 0,
        .fault_addr = 0,
        .access_type = 2,
        .ret_val = 0,
    };
    try std.testing.expectEqual(crash_triage.CrashClass.null_deref, crash_triage.classifyCrash(null_write, "ABCD", null, null, null).class);

    const exec_hijack = veh.RunResult{
        .crashed = true,
        .exception_code = 0xC000_0005,
        .exception_addr = 0x4141_4141,
        .fault_rva = 0,
        .fault_addr = 0x4141_4141,
        .access_type = 8,
        .ret_val = 0,
    };
    try std.testing.expectEqual(crash_triage.CrashClass.wild_exec, crash_triage.classifyCrash(exec_hijack, "ABCD", null, null, null).class);

    const null_jump = veh.RunResult{
        .crashed = true,
        .exception_code = 0xC000_0005,
        .exception_addr = 0,
        .fault_rva = 0,
        .fault_addr = 0,
        .access_type = 8,
        .ret_val = 0,
    };
    try std.testing.expectEqual(crash_triage.CrashClass.pc_corrupt, crash_triage.classifyCrash(null_jump, "ABCD", null, null, null).class);
}

test "regression: cmin deduplicates hit_blocks & covreport last-block size, DrCov hex, LCOV sanitize" {
    const alloc = std.testing.allocator;

    // cmin: duplicate block 0 five times must NOT beat unique {0, 1}
    const traces = [_]cmin.SeedTrace{
        .{ .name = "dup", .bytes = "AAAAAAAAAA", .crashed = false, .hit_blocks = &.{ 0, 0, 0, 0, 0 } },
        .{ .name = "uniq", .bytes = "BBBBBBBBBB", .crashed = false, .hit_blocks = &.{ 0, 1 } },
    };
    const picked = try cmin.selectMinimalSeeds(alloc, 2, &traces);
    defer alloc.free(picked);
    try std.testing.expectEqual(@as(usize, 1), picked.len);
    try std.testing.expectEqual(@as(usize, 1), picked[0]);

    // covreport: last block of function gets true size (32) from img.functions
    var raw: [1024]u8 = @splat(0);
    raw[0] = 'M';
    raw[1] = 'Z';
    std.mem.writeInt(u32, raw[0x3C..][0..4], 0x80, .little);
    @memcpy(raw[0x80..0x84], "PE\x00\x00");
    std.mem.writeInt(u16, raw[0x84..][0..2], 0xAA64, .little);
    std.mem.writeInt(u16, raw[0x86..][0..2], 1, .little);
    std.mem.writeInt(u16, raw[0x94..][0..2], 240, .little);
    std.mem.writeInt(u16, raw[0x98..][0..2], 0x020B, .little);
    std.mem.writeInt(u32, raw[0x98 + 16 ..][0..4], 0x1000, .little);
    std.mem.writeInt(u64, raw[0x98 + 24 ..][0..8], 0x1_8000_0000, .little);
    std.mem.writeInt(u32, raw[0x98 + 56 ..][0..4], 0x2000, .little);
    std.mem.writeInt(u32, raw[0x98 + 108 ..][0..4], 16, .little);
    std.mem.writeInt(u32, raw[0x98 + 112 + 24 ..][0..4], 0x1100, .little);
    std.mem.writeInt(u32, raw[0x98 + 116 + 24 ..][0..4], 8, .little);
    @memcpy(raw[0x188 .. 0x188 + 5], ".text");
    std.mem.writeInt(u32, raw[0x188 + 8 ..][0..4], 0x200, .little);
    std.mem.writeInt(u32, raw[0x188 + 12 ..][0..4], 0x1000, .little);
    std.mem.writeInt(u32, raw[0x188 + 16 ..][0..4], 0x200, .little);
    std.mem.writeInt(u32, raw[0x188 + 20 ..][0..4], 0x200, .little);
    std.mem.writeInt(u32, raw[0x188 + 36 ..][0..4], pe.IMAGE_SCN_MEM_READ | pe.IMAGE_SCN_MEM_EXECUTE, .little);
    // .pdata at raw 0x300 (RVA 0x1100): fn 0x1000..0x1024 (size 36 bytes)
    std.mem.writeInt(u32, raw[0x300..][0..4], 0x1000, .little);
    std.mem.writeInt(u32, raw[0x304..][0..4], 1 | (9 << 2), .little);
    // Export with comma in name via parsed BinaryImage
    var img = try binary.parseBinary(alloc, &raw);
    defer img.deinit();
    const blocks = [_]cfg.BasicBlock{
        .{ .rva = 0x1000, .func_rva = 0x1000 },
        .{ .rva = 0x1004, .func_rva = 0x1000 }, // last block -> 0x1024 - 0x1004 = 32
    };
    const hits = [_]u32{ 1, 2 };
    var rep = try covreport.buildCoverageReport(alloc, "cov.dll", &raw, &img, &blocks, &hits, 1);
    defer rep.deinit();
    try std.testing.expectEqual(@as(u16, 4), rep.blocks[0].size);
    try std.testing.expectEqual(@as(u16, 32), rep.blocks[1].size);

    const drcov = try covreport.renderCoverage(alloc, &rep, .drcov);
    defer alloc.free(drcov);
    try std.testing.expect(std.mem.indexOf(u8, drcov, "0x0000000180000000, 0x0000000180002000, 0x0000000180001000") != null);

    // Replace function name with comma/newline to verify LCOV sanitization
    alloc.free(rep.functions[0].name);
    rep.functions[0].name = try alloc.dupe(u8, "fn(a, b)\nnext");
    const lcov = try covreport.renderCoverage(alloc, &rep, .lcov);
    defer alloc.free(lcov);
    try std.testing.expect(std.mem.indexOf(u8, lcov, "FN:1,fn(a_ b)_next\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, lcov, "FNDA:2,fn(a_ b)_next\n") != null);
}

test "regression: harnessgen escaping, Zig args.deinit, C guards, truncation note" {
    const alloc = std.testing.allocator;
    const c_h = try harnessgen.generateHarness(alloc, .c, "dir/a\"c.dll", "fn\\x\"y");
    defer alloc.free(c_h);
    try std.testing.expect(std.mem.indexOf(u8, c_h, "\"a\\\"c.dll\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, c_h, "\"fn\\\\x\\\"y\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, c_h, "n < 0") != null);
    try std.testing.expect(std.mem.indexOf(u8, c_h, "if (!buf)") != null);

    const z_h = try harnessgen.generateHarness(alloc, .zig, "dir/a\"c.dll", "fn\\x\"y");
    defer alloc.free(z_h);
    try std.testing.expect(std.mem.indexOf(u8, z_h, "defer args.deinit();") != null);
    try std.testing.expect(std.mem.indexOf(u8, z_h, "\"a\\\"c.dll\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, z_h, "\"fn\\\\x\\\"y\"") != null);

    const big = try alloc.alloc(u8, 65540);
    defer alloc.free(big);
    @memset(big, 0x41);
    const repro = try harnessgen.generateRepro(alloc, .c, "target.dll", "fuzz_entry", big);
    defer alloc.free(repro);
    try std.testing.expect(std.mem.indexOf(u8, repro, "WARNING: input truncated from 65540 to 65536 bytes") != null);
}

test "regression: portscan Rust lifetimes, comment stripping order, unsigned char, and .line" {
    const alloc = std.testing.allocator;
    var fs = finding.FindingSet.init(alloc);
    defer fs.deinit();

    const rust_and_c =
        \\// TODO: __aarch64__ and std::atomic and __asm
        \\fn foo<'a, 'static>(s: &'a [u8]) { unsafe { _mm_pause(); } }
        \\const char *msg = "_mm_add_ps"; // __asm
        \\#ifdef _M_X64
        \\volatile int ready = 0;
        \\#endif
        \\unsigned char uc = 1; if (uc < 0) {}
        \\
    ;
    _ = try portscan.scanSourceText(alloc, "lib.rs", rust_and_c, &fs);

    var saw_simd = false;
    var saw_guard = false;
    var saw_vol = false;
    var saw_char = false;
    for (fs.items.items) |f| {
        if (std.mem.eql(u8, f.rule_id, "SO-PORT-001")) {
            saw_simd = true;
            try std.testing.expectEqual(@as(?u32, 2), f.line);
        }
        if (std.mem.eql(u8, f.rule_id, "SO-PORT-004")) saw_guard = true;
        if (std.mem.eql(u8, f.rule_id, "SO-PORT-005")) saw_vol = true;
        if (std.mem.eql(u8, f.rule_id, "SO-PORT-006")) saw_char = true;
    }
    try std.testing.expect(saw_simd);
    try std.testing.expect(saw_guard);
    try std.testing.expect(saw_vol);
    try std.testing.expect(!saw_char);
}

test "regression: bench --suite exec without --target returns 2, ci_gate YAML/UTC/fail-closed, crashdb CRC/atomic/case" {
    const alloc = std.testing.allocator;
    try std.testing.expectEqual(@as(u8, 2), try bench.runBenchCommand(std.testing.io, alloc, &.{ "--suite", "exec" }));

    const gha_tpl = ci_gate.renderPipelineTemplate(.github);
    try std.testing.expect(std.mem.indexOf(u8, gha_tpl, "mlugg/setup-zig@v2") != null);
    try std.testing.expect(std.mem.indexOf(u8, gha_tpl, "fuzz --target ") != null);
    try std.testing.expect(ci_gate.currentUtcYmd(std.testing.io) >= 20260101);

    var fs = finding.FindingSet.init(alloc);
    defer fs.deinit();
    try fs.add(.{ .rule_id = "SO-HARDEN-003", .artifact = "app.dll", .detail = "missing CFG" });
    const rep_json = try report.renderFindingSet(alloc, &fs, .json, null);
    defer alloc.free(rep_json);

    // Malformed waiver expiry must fail closed (NOT waive!)
    const bad_waiver =
        \\{ "waivers": [{ "rule_id": "SO-HARDEN-003", "artifact": "app.dll", "expires": "20269999" }] }
    ;
    var active = finding.FindingSet.init(alloc);
    defer active.deinit();
    const ev = try ci_gate.evaluateGate(alloc, rep_json, null, bad_waiver, .high, 20261119, &active);
    try std.testing.expect(!ev.passed);
    try std.testing.expectEqual(@as(usize, 0), ev.waived);

    // crashdb: computeRecordCrc depends on count, rejects crc32 == 0, baseline matches uppercase hex
    const r1 = crashdb.DbRecord{ .fingerprint = "0011223344556677", .rule_id = "R1", .severity = "high", .artifact = "a.dll", .title = "t", .count = 1, .status = "new" };
    const r2 = crashdb.DbRecord{ .fingerprint = "0011223344556677", .rule_id = "R1", .severity = "high", .artifact = "a.dll", .title = "t", .count = 2, .status = "new" };
    try std.testing.expect(crashdb.computeRecordCrc(r1) != crashdb.computeRecordCrc(r2));

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "db.jsonl",
        .data = "{\"fingerprint\":\"0011\",\"rule_id\":\"R\",\"severity\":\"high\",\"artifact\":\"a\",\"title\":\"t\",\"count\":1,\"status\":\"new\",\"crc32\":0}\n",
    });
    const db_path = try std.fmt.allocPrint(alloc, ".zig-cache/tmp/{s}/db.jsonl", .{&tmp.sub_path});
    defer alloc.free(db_path);
    var loaded_recs = try crashdb.loadDbRecords(std.testing.io, alloc, db_path, true);
    defer crashdb.freeDbRecords(alloc, &loaded_recs);
    try std.testing.expectEqual(@as(usize, 0), loaded_recs.items.len);

    // writeFileAtomic via `crashdb init` on an existing file leaves no `.tmp` file behind
    try crashdb.runCrashDbCommand(std.testing.io, alloc, &.{ "init", "--db", db_path });
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "db.jsonl.tmp", .{}));

    var fp_buf: [16]u8 = undefined;
    const fp_lower = try std.fmt.bufPrint(&fp_buf, "{x:0>16}", .{fs.items.items[0].fingerprint});
    var fp_upper: [16]u8 = undefined;
    for (fp_lower, 0..) |c, i| fp_upper[i] = std.ascii.toUpper(c);
    const base_json = try std.fmt.allocPrint(alloc, "{{\"schema_version\":\"1.0\",\"fingerprints\":[\"{s}\"]}}", .{fp_upper});
    defer alloc.free(base_json);
    var out_new = finding.FindingSet.init(alloc);
    defer out_new.deinit();
    const supp = try crashdb.filterFindingsAgainstBaseline(alloc, &fs, base_json, &out_new);
    try std.testing.expectEqual(@as(usize, 1), supp);
    try std.testing.expectEqual(@as(usize, 0), out_new.items.items.len);
}

test "regression: arm64_isa tightened crypto_sha and isHardcoded4kPageImm masks" {
    // .crypto_sha: valid SHA1C vs invalid op=7 vs unrelated 0x5E40_0000
    try std.testing.expectEqual(arm64_isa.ComputeExt.crypto_sha, arm64_isa.classifyComputeExt(0x5E02_0020));
    try std.testing.expectEqual(arm64_isa.ComputeExt.none, arm64_isa.classifyComputeExt(0x5E02_7020));
    try std.testing.expectEqual(arm64_isa.ComputeExt.none, arm64_isa.classifyComputeExt(0x5E40_0000));

    // isHardcoded4kPageImm: valid MOVZ hw=0, ADD #1 lsl #12, AND 32-bit sf=0 n=0
    try std.testing.expect(arm64_isa.isHardcoded4kPageImm(0x5282_0000)); // mov w0, #0x1000
    try std.testing.expect(arm64_isa.isHardcoded4kPageImm(0x9140_0420)); // add x0, x1, #1, lsl #12
    try std.testing.expect(arm64_isa.isHardcoded4kPageImm(0x1200_2C00)); // and w0, w0, #0xfff

    // Reject MOVZ hw!=0, MOVK, MOVN, MTE ADDG/SUBG, and sf!=n logical immediates
    try std.testing.expect(!arm64_isa.isHardcoded4kPageImm(0xD2A2_0000)); // movz x0, #0x1000, lsl #16
    try std.testing.expect(!arm64_isa.isHardcoded4kPageImm(0xF282_0000)); // movk x0, #0x1000
    try std.testing.expect(!arm64_isa.isHardcoded4kPageImm(0x9282_0000)); // movn x0, #0x1000
    try std.testing.expect(!arm64_isa.isHardcoded4kPageImm(0x9180_0420)); // addg (MTE)
    try std.testing.expect(!arm64_isa.isHardcoded4kPageImm(0xD180_0420)); // subg (MTE)
    try std.testing.expect(!arm64_isa.isHardcoded4kPageImm(0x9200_2C00)); // and x0, x0, #0x00000fff00000fff (sf=1, N=0)
    try std.testing.expect(!arm64_isa.isHardcoded4kPageImm(0x1240_2C00)); // unallocated (sf=0, N=1)
}
