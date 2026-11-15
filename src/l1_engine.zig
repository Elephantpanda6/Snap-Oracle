const std = @import("std");
const builtin = @import("builtin");
const arch = @import("arch.zig");

const win = std.os.windows;

pub const MEM_COMMIT: u32 = 0x0000_1000;
pub const MEM_RESERVE: u32 = 0x0000_2000;
pub const MEM_RELEASE: u32 = 0x0000_8000;
pub const PAGE_READWRITE: u32 = 0x04;
pub const MEM_WRITE_WATCH: u32 = 0x0020_0000;
pub const WRITE_WATCH_FLAG_RESET: u32 = 0x01;
pub const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
pub const EXCEPTION_CONTINUE_SEARCH: i32 = 0;
pub const EXCEPTION_BREAKPOINT: u32 = 0x8000_0003;
pub const EXCEPTION_ACCESS_VIOLATION: u32 = 0xC000_0005;

extern "kernel32" fn VirtualAlloc(
    lpAddress: ?*anyopaque,
    dwSize: usize,
    flAllocationType: u32,
    flProtect: u32,
) callconv(.winapi) ?*anyopaque;

extern "kernel32" fn VirtualFree(
    lpAddress: *anyopaque,
    dwSize: usize,
    dwFreeType: u32,
) callconv(.winapi) win.BOOL;

extern "kernel32" fn GetWriteWatch(
    dwFlags: u32,
    lpBaseAddress: *anyopaque,
    dwRegionSize: usize,
    lpAddresses: [*]?*anyopaque,
    lpdwCount: *usize,
    lpdwGranularity: *u32,
) callconv(.winapi) u32;

extern "kernel32" fn ResetWriteWatch(
    lpBaseAddress: *anyopaque,
    dwRegionSize: usize,
) callconv(.winapi) u32;

extern "kernel32" fn FlushInstructionCache(
    hProcess: win.HANDLE,
    lpBaseAddress: ?*const anyopaque,
    dwSize: usize,
) callconv(.winapi) win.BOOL;

extern "kernel32" fn GetCurrentProcess() callconv(.winapi) win.HANDLE;

pub const CoverageBitmap = struct {
    bits: [65536]u8 = @splat(0),
    prev_loc: u16 = 0,
    unique_edges: usize = 0,

    pub fn recordEdge(self: *CoverageBitmap, pc: u64) bool {
        const cur: u16 = @truncate((pc >> 2) ^ (pc >> 16));
        const idx = self.prev_loc ^ cur;
        self.prev_loc = cur >> 1;
        if (self.bits[idx] == 0) {
            self.bits[idx] = 1;
            self.unique_edges += 1;
            return true;
        }
        if (self.bits[idx] < 255) self.bits[idx] += 1;
        return false;
    }
};

pub const SnapshotArena = struct {
    live_ptr: [*]u8,
    clean_ptr: [*]u8,
    size: usize,
    page_size: u32,
    dirty_addrs: []?*anyopaque,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, size: usize) !SnapshotArena {
        const aligned_size = std.mem.alignForward(usize, size, 4096);
        const live_raw = VirtualAlloc(
            null,
            aligned_size,
            MEM_RESERVE | MEM_COMMIT | MEM_WRITE_WATCH,
            PAGE_READWRITE,
        ) orelse return error.VirtualAllocFailed;

        const clean_raw = VirtualAlloc(
            null,
            aligned_size,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        ) orelse {
            _ = VirtualFree(live_raw, 0, MEM_RELEASE);
            return error.VirtualAllocFailed;
        };

        const max_pages = aligned_size / 4096;
        const dirty_addrs = try allocator.alloc(?*anyopaque, max_pages);

        return .{
            .live_ptr = @ptrCast(live_raw),
            .clean_ptr = @ptrCast(clean_raw),
            .size = aligned_size,
            .page_size = 4096,
            .dirty_addrs = dirty_addrs,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *SnapshotArena) void {
        _ = VirtualFree(self.live_ptr, 0, MEM_RELEASE);
        _ = VirtualFree(self.clean_ptr, 0, MEM_RELEASE);
        self.allocator.free(self.dirty_addrs);
    }

    pub fn takeSnapshot(self: *SnapshotArena) void {
        @memcpy(self.clean_ptr[0..self.size], self.live_ptr[0..self.size]);
        _ = ResetWriteWatch(self.live_ptr, self.size);
    }

    pub fn restoreDirtyPages(self: *SnapshotArena) usize {
        var count: usize = self.dirty_addrs.len;
        var gran: u32 = 4096;
        const rc = GetWriteWatch(
            WRITE_WATCH_FLAG_RESET,
            self.live_ptr,
            self.size,
            self.dirty_addrs.ptr,
            &count,
            &gran,
        );
        if (rc != 0) return 0;

        const base_addr = @intFromPtr(self.live_ptr);
        for (self.dirty_addrs[0..count]) |maybe_addr| {
            const addr = @intFromPtr(maybe_addr orelse continue);
            if (addr < base_addr or addr + 4096 > base_addr + self.size) continue;
            const off = addr - base_addr;
            arch.fastRestorePage4K(self.live_ptr + off, self.clean_ptr + off);
        }
        return count;
    }
};

pub fn flushCodeRange(addr: *const anyopaque, len: usize) void {
    _ = FlushInstructionCache(GetCurrentProcess(), addr, len);
    arch.flushIcacheAddr(@intFromPtr(addr));
}
