const std = @import("std");
const builtin = @import("builtin");
const pe = @import("pe.zig");
const cfg = @import("cfg.zig");
const l1 = @import("l1_engine.zig");
const arch = @import("arch.zig");

const win = std.os.windows;

pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;

extern "kernel32" fn VirtualProtect(
    lpAddress: *anyopaque,
    dwSize: usize,
    flNewProtect: u32,
    lpflOldProtect: *u32,
) callconv(.winapi) c_int;

pub const SavedSite = struct {
    /// Original instruction bytes (1 byte on amd64, 4 on arm64).
    orig: [4]u8,
    /// 1 or 4.
    len: u8,
    /// Page protection of the site before the breakpoint was installed.
    orig_protect: u32,
};

/// Write `bytes` over executable memory at `addr`, then restore the page protection and flush
/// the instruction cache. Returns the protection that was in force before the write.
fn patchCode(addr: usize, bytes: []const u8) ?u32 {
    const p: *anyopaque = @ptrFromInt(addr);
    var old: u32 = 0;
    if (VirtualProtect(p, bytes.len, PAGE_EXECUTE_READWRITE, &old) == 0) return null;
    const dst: [*]u8 = @ptrFromInt(addr);
    @memcpy(dst[0..bytes.len], bytes);
    var tmp: u32 = 0;
    _ = VirtualProtect(p, bytes.len, old, &tmp);
    l1.flushCodeRange(p, bytes.len);
    return old;
}

pub const BreakpointTable = struct {
    allocator: std.mem.Allocator,
    module_base: usize,
    machine: pe.Machine,
    bitmap: *l1.CoverageBitmap,
    /// Absolute address -> saved original instruction bytes. Entries are removed when hit.
    orig_bytes: std.AutoHashMap(usize, SavedSite),
    total: usize = 0,

    fn isArm(machine: pe.Machine) bool {
        return machine == .arm64 or machine == .arm64ec;
    }

    pub fn init(
        allocator: std.mem.Allocator,
        module_base: usize,
        machine: pe.Machine,
        blocks: []const cfg.BasicBlock,
        bitmap: *l1.CoverageBitmap,
    ) !BreakpointTable {
        var self = BreakpointTable{
            .allocator = allocator,
            .module_base = module_base,
            .machine = machine,
            .bitmap = bitmap,
            .orig_bytes = std.AutoHashMap(usize, SavedSite).init(allocator),
        };
        errdefer self.deinit();

        const arm = isArm(machine);
        if (!arm and machine != .amd64) return self; // unsupported: no-op table

        try self.orig_bytes.ensureTotalCapacity(@intCast(blocks.len));

        for (blocks) |bb| {
            const addr = module_base + @as(usize, bb.rva);
            if (self.orig_bytes.contains(addr)) continue; // duplicate RVA
            if (arm and (addr & 3) != 0) continue;

            const len: usize = if (arm) 4 else 1;
            const p: *anyopaque = @ptrFromInt(addr);
            var old: u32 = 0;
            // Probe + unprotect. Failure means the address is not mapped: skip the site.
            if (VirtualProtect(p, len, PAGE_EXECUTE_READWRITE, &old) == 0) continue;

            const src: [*]const u8 = @ptrFromInt(addr);
            var site = SavedSite{ .orig = .{ 0, 0, 0, 0 }, .len = @intCast(len), .orig_protect = old };
            @memcpy(site.orig[0..len], src[0..len]);

            // Never patch a site that already holds our trap pattern (padding / foreign int3).
            const already = if (arm)
                std.mem.readInt(u32, site.orig[0..4], .little) == arch.ARM64_BRK_0
            else
                site.orig[0] == arch.X64_INT3;
            if (already) {
                var tmp: u32 = 0;
                _ = VirtualProtect(p, len, old, &tmp);
                continue;
            }

            const dst: [*]u8 = @ptrFromInt(addr);
            if (arm) {
                std.mem.writeInt(u32, dst[0..4], arch.ARM64_BRK_0, .little);
            } else {
                dst[0] = arch.X64_INT3;
            }
            var tmp: u32 = 0;
            _ = VirtualProtect(p, len, old, &tmp);
            l1.flushCodeRange(p, len);

            self.orig_bytes.putAssumeCapacity(addr, site);
        }
        self.total = self.orig_bytes.count();
        return self;
    }

    fn restoreSite(addr: usize, site: SavedSite) void {
        _ = patchCode(addr, site.orig[0..site.len]);
    }

    /// One-shot: if `addr` is an armed breakpoint, restore the original instruction, record the
    /// coverage edge, and return true (caller should resume at `addr`).
    pub fn handleBreakpoint(self: *BreakpointTable, addr: usize) bool {
        const key: usize = if (isArm(self.machine)) @intCast(arch.stripPac(addr)) else addr;
        const kv = self.orig_bytes.fetchRemove(key) orelse return false;
        restoreSite(key, kv.value);
        _ = self.bitmap.recordEdge(key);
        return true;
    }

    pub fn hitCount(self: *const BreakpointTable) usize {
        return self.total - self.orig_bytes.count();
    }

    pub fn totalCount(self: *const BreakpointTable) usize {
        return self.total;
    }

    /// Restores every breakpoint that was never hit, then frees the table.
    pub fn deinit(self: *BreakpointTable) void {
        var it = self.orig_bytes.iterator();
        while (it.next()) |e| restoreSite(e.key_ptr.*, e.value_ptr.*);
        self.orig_bytes.deinit();
        self.total = 0;
    }
};

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_RELEASE: u32 = 0x8000;

extern "kernel32" fn VirtualAlloc(?*anyopaque, usize, u32, u32) callconv(.winapi) ?*anyopaque;
extern "kernel32" fn VirtualFree(*anyopaque, usize, u32) callconv(.winapi) c_int;

test "BreakpointTable patches, hits once via VEH, and restores" {
    if (builtin.cpu.arch != .x86_64 or builtin.os.tag != .windows) return error.SkipZigTest;
    const veh = @import("veh.zig");

    const mem: [*]u8 = @ptrCast(VirtualAlloc(null, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE) orelse return error.SkipZigTest);
    defer _ = VirtualFree(mem, 0, MEM_RELEASE);

    // 0: mov eax, 7        (B8 07 00 00 00)
    // 5: test eax, eax     (85 C0)
    // 7: jz +1             (74 01)   -> 0xA
    // 9: nop               (90)
    // A: ret               (C3)
    const code = [_]u8{ 0xB8, 7, 0, 0, 0, 0x85, 0xC0, 0x74, 0x01, 0x90, 0xC3 };
    @memcpy(mem[0..code.len], &code);

    const base = @intFromPtr(mem);
    const blocks = try cfg.decodeX64BasicBlocksFull(std.testing.allocator, mem[0..code.len], 0, 0, code.len);
    defer std.testing.allocator.free(blocks);
    // entry 0, jz target 0xA, fall-through 9
    try std.testing.expectEqual(@as(usize, 3), blocks.len);

    // Include a duplicate RVA to verify dedup.
    var with_dup: [4]cfg.BasicBlock = undefined;
    @memcpy(with_dup[0..3], blocks);
    with_dup[3] = blocks[0];

    var bitmap = l1.CoverageBitmap{};
    var table = try BreakpointTable.init(std.testing.allocator, base, .amd64, &with_dup, &bitmap);
    try std.testing.expectEqual(@as(usize, 3), table.totalCount());
    try std.testing.expectEqual(@as(usize, 0), table.hitCount());
    try std.testing.expectEqual(@as(u8, 0xCC), mem[0]);
    try std.testing.expectEqual(@as(u8, 0xCC), mem[0xA]);

    var guard = veh.Guard.init();
    defer guard.deinit();
    veh.setBreakpointTable(&table);
    defer veh.setBreakpointTable(null);

    const f: veh.TargetFn = @ptrCast(mem);
    const dummy = "x";
    const res = veh.runProtected(f, dummy.ptr, dummy.len);
    try std.testing.expect(!res.crashed);
    try std.testing.expectEqual(@as(u64, 7), res.ret_val);
    // jz not taken (eax=7): entry, fall-through 9 and ret block 0xA all trapped once.
    try std.testing.expectEqual(@as(usize, 3), table.hitCount());
    try std.testing.expectEqual(@as(u8, 0xB8), mem[0]);
    try std.testing.expectEqual(@as(u8, 0x90), mem[9]);
    try std.testing.expectEqual(@as(u8, 0xC3), mem[0xA]);
    try std.testing.expectEqual(@as(usize, 3), bitmap.unique_edges);

    // Second run: breakpoints are one-shot, no further traps.
    const res2 = veh.runProtected(f, dummy.ptr, dummy.len);
    try std.testing.expect(!res2.crashed);
    try std.testing.expectEqual(@as(usize, 3), table.hitCount());
    table.deinit();

    // Unhit breakpoints are restored by deinit.
    var bitmap2 = l1.CoverageBitmap{};
    var table2 = try BreakpointTable.init(std.testing.allocator, base, .amd64, blocks, &bitmap2);
    try std.testing.expectEqual(@as(u8, 0xCC), mem[0]);
    try std.testing.expect(!table2.handleBreakpoint(base + 5)); // not an armed site
    table2.deinit();
    try std.testing.expectEqual(@as(u8, 0xB8), mem[0]);
    try std.testing.expectEqual(@as(u8, 0xC3), mem[0xA]);
}