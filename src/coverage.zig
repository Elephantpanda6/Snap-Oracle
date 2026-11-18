const std = @import("std");
const builtin = @import("builtin");
const pe = @import("pe.zig");
const cfg = @import("cfg.zig");
const l1 = @import("l1_engine.zig");
const arch = @import("arch.zig");
const veh = @import("veh.zig");

pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;

const WinMem = if (builtin.os.tag == .windows) struct {
    extern "kernel32" fn VirtualProtect(
        lpAddress: *anyopaque,
        dwSize: usize,
        flNewProtect: u32,
        lpflOldProtect: *u32,
    ) callconv(.winapi) c_int;

    extern "kernel32" fn VirtualAlloc(?*anyopaque, usize, u32, u32) callconv(.winapi) ?*anyopaque;
    extern "kernel32" fn VirtualFree(*anyopaque, usize, u32) callconv(.winapi) c_int;
} else struct {};

pub const SavedSite = struct {
    /// Original instruction bytes (1 byte on amd64, 4 on arm64).
    orig: [4]u8,
    /// 1 or 4.
    len: u8,
    /// Page protection of the site before the breakpoint was installed.
    orig_protect: u32,
};

fn posixPageAlign(addr: usize, len: usize) struct { base: [*]align(std.heap.page_size_min) u8, span: usize } {
    const psize = std.heap.pageSize();
    const page_start = addr & ~(psize - 1);
    const page_end = std.mem.alignForward(usize, addr + len, psize);
    return .{
        .base = @ptrFromInt(page_start),
        .span = page_end - page_start,
    };
}

/// Write `bytes` over executable memory at `addr`, then restore the page protection and flush
/// the instruction cache.
fn patchCode(addr: usize, bytes: []const u8, restore_prot: u32) bool {
    if (builtin.os.tag == .windows) {
        const p: *anyopaque = @ptrFromInt(addr);
        var old: u32 = 0;
        if (WinMem.VirtualProtect(p, bytes.len, PAGE_EXECUTE_READWRITE, &old) == 0) return false;
        const dst: [*]u8 = @ptrFromInt(addr);
        @memcpy(dst[0..bytes.len], bytes);
        var tmp: u32 = 0;
        _ = WinMem.VirtualProtect(p, bytes.len, if (restore_prot != 0) restore_prot else old, &tmp);
        l1.flushCodeRange(p, bytes.len);
        return true;
    } else {
        const seg = posixPageAlign(addr, bytes.len);
        if (std.c.mprotect(seg.base, seg.span, .{ .READ = true, .WRITE = true, .EXEC = true }) != 0) return false;
        const dst: [*]u8 = @ptrFromInt(addr);
        @memcpy(dst[0..bytes.len], bytes);
        _ = std.c.mprotect(seg.base, seg.span, .{ .READ = true, .EXEC = true });
        l1.flushCodeRange(@ptrFromInt(addr), bytes.len);
        return true;
    }
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
        if (!arm and machine != .amd64) return self;

        try self.orig_bytes.ensureTotalCapacity(@intCast(blocks.len));
        const brk_insn = arch.arm64BreakpointInsn();

        for (blocks) |bb| {
            const addr = module_base + @as(usize, bb.rva);
            if (self.orig_bytes.contains(addr)) continue;
            if (arm and (addr & 3) != 0) continue;

            const len: usize = if (arm) 4 else 1;
            var old: u32 = 0;

            if (builtin.os.tag == .windows) {
                const p: *anyopaque = @ptrFromInt(addr);
                if (WinMem.VirtualProtect(p, len, PAGE_EXECUTE_READWRITE, &old) == 0) continue;
                const src: [*]const u8 = @ptrFromInt(addr);
                var site = SavedSite{ .orig = .{ 0, 0, 0, 0 }, .len = @intCast(len), .orig_protect = old };
                @memcpy(site.orig[0..len], src[0..len]);

                const already = if (arm)
                    std.mem.readInt(u32, site.orig[0..4], .little) == brk_insn
                else
                    site.orig[0] == arch.X64_INT3;
                if (already) {
                    var tmp: u32 = 0;
                    _ = WinMem.VirtualProtect(p, len, old, &tmp);
                    continue;
                }

                const dst: [*]u8 = @ptrFromInt(addr);
                if (arm) {
                    std.mem.writeInt(u32, dst[0..4], brk_insn, .little);
                } else {
                    dst[0] = arch.X64_INT3;
                }
                var tmp: u32 = 0;
                _ = WinMem.VirtualProtect(p, len, old, &tmp);
                l1.flushCodeRange(p, len);

                self.orig_bytes.putAssumeCapacity(addr, site);
            } else {
                const seg = posixPageAlign(addr, len);
                if (std.c.mprotect(seg.base, seg.span, .{ .READ = true, .WRITE = true, .EXEC = true }) != 0) continue;
                const src: [*]const u8 = @ptrFromInt(addr);
                var site = SavedSite{ .orig = .{ 0, 0, 0, 0 }, .len = @intCast(len), .orig_protect = 5 };
                @memcpy(site.orig[0..len], src[0..len]);

                const already = if (arm)
                    std.mem.readInt(u32, site.orig[0..4], .little) == brk_insn
                else
                    site.orig[0] == arch.X64_INT3;
                if (already) {
                    _ = std.c.mprotect(seg.base, seg.span, .{ .READ = true, .EXEC = true });
                    continue;
                }

                const dst: [*]u8 = @ptrFromInt(addr);
                if (arm) {
                    std.mem.writeInt(u32, dst[0..4], brk_insn, .little);
                } else {
                    dst[0] = arch.X64_INT3;
                }
                _ = std.c.mprotect(seg.base, seg.span, .{ .READ = true, .EXEC = true });
                l1.flushCodeRange(@ptrFromInt(addr), len);

                self.orig_bytes.putAssumeCapacity(addr, site);
            }
        }
        self.total = self.orig_bytes.count();
        return self;
    }

    fn restoreSite(addr: usize, site: SavedSite) bool {
        return patchCode(addr, site.orig[0..site.len], site.orig_protect);
    }

    /// One-shot: if `addr` is an armed breakpoint, restore the original instruction, record the
    /// coverage edge, and return true (caller should resume at `addr`).
    pub fn handleBreakpoint(self: *BreakpointTable, addr: usize) bool {
        const key: usize = if (isArm(self.machine)) @intCast(arch.stripPac(addr)) else addr;
        const site = self.orig_bytes.get(key) orelse return false;
        if (!restoreSite(key, site)) return false;
        _ = self.orig_bytes.remove(key);
        _ = self.bitmap.recordEdge(key);
        return true;
    }

    pub fn hitCount(self: *const BreakpointTable) usize {
        return self.total - self.orig_bytes.count();
    }

    pub fn totalCount(self: *const BreakpointTable) usize {
        return self.total;
    }

    /// Safely detaches from VEH/signal handler first (preventing UAF regardless of defer order),
    /// restores every unhit breakpoint, then frees the map.
    pub fn deinit(self: *BreakpointTable) void {
        veh.clearBreakpointTableIf(self);
        var it = self.orig_bytes.iterator();
        while (it.next()) |e| _ = restoreSite(e.key_ptr.*, e.value_ptr.*);
        self.orig_bytes.deinit();
        self.total = 0;
    }
};

const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_RELEASE: u32 = 0x8000;

test "BreakpointTable patches, hits once via VEH, and detaches safely on deinit" {
    if (builtin.cpu.arch != .x86_64 or builtin.os.tag != .windows) return error.SkipZigTest;

    const mem: [*]u8 = @ptrCast(WinMem.VirtualAlloc(null, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE) orelse return error.SkipZigTest);
    defer _ = WinMem.VirtualFree(mem, 0, MEM_RELEASE);

    const code = [_]u8{ 0xB8, 7, 0, 0, 0, 0x85, 0xC0, 0x74, 0x01, 0x90, 0xC3 };
    @memcpy(mem[0..code.len], &code);

    const base = @intFromPtr(mem);
    const blocks = try cfg.decodeX64BasicBlocksFull(std.testing.allocator, mem[0..code.len], 0, 0, code.len);
    defer std.testing.allocator.free(blocks);
    try std.testing.expectEqual(@as(usize, 3), blocks.len);

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

    const f: veh.TargetFn = @ptrCast(mem);
    const dummy = "x";
    const res = veh.runProtected(f, dummy.ptr, dummy.len);
    try std.testing.expect(!res.crashed);
    try std.testing.expectEqual(@as(u64, 7), res.ret_val);
    try std.testing.expectEqual(@as(usize, 3), table.hitCount());
    try std.testing.expectEqual(@as(u8, 0xB8), mem[0]);
    try std.testing.expectEqual(@as(u8, 0x90), mem[9]);
    try std.testing.expectEqual(@as(u8, 0xC3), mem[0xA]);
    try std.testing.expectEqual(@as(usize, 3), bitmap.unique_edges);

    const res2 = veh.runProtected(f, dummy.ptr, dummy.len);
    try std.testing.expect(!res2.crashed);
    try std.testing.expectEqual(@as(usize, 3), table.hitCount());
    table.deinit();

    var bitmap2 = l1.CoverageBitmap{};
    var table2 = try BreakpointTable.init(std.testing.allocator, base, .amd64, blocks, &bitmap2);
    try std.testing.expectEqual(@as(u8, 0xCC), mem[0]);
    try std.testing.expect(!table2.handleBreakpoint(base + 5));
    table2.deinit();
    try std.testing.expectEqual(@as(u8, 0xB8), mem[0]);
    try std.testing.expectEqual(@as(u8, 0xC3), mem[0xA]);
}
