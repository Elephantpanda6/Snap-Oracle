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

const WinExports = if (builtin.os.tag == .windows) struct {
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
} else struct {};

const DarwinExports = if (builtin.os.tag == .macos) struct {
    extern "c" fn sys_icache_invalidate(start: *const anyopaque, len: usize) callconv(.c) void;
} else struct {};

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
    page_size: usize,
    dirty_addrs: []?*anyopaque,
    posix_live_len: usize = 0,
    posix_clean_len: usize = 0,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, size: usize) !SnapshotArena {
        const psize = std.heap.pageSize();
        const aligned_size = std.mem.alignForward(usize, @max(size, psize), psize);

        if (builtin.os.tag == .windows) {
            const live_raw = WinExports.VirtualAlloc(
                null,
                aligned_size,
                MEM_RESERVE | MEM_COMMIT | MEM_WRITE_WATCH,
                PAGE_READWRITE,
            ) orelse return error.VirtualAllocFailed;

            const clean_raw = WinExports.VirtualAlloc(
                null,
                aligned_size,
                MEM_RESERVE | MEM_COMMIT,
                PAGE_READWRITE,
            ) orelse {
                _ = WinExports.VirtualFree(live_raw, 0, MEM_RELEASE);
                return error.VirtualAllocFailed;
            };

            const max_pages = aligned_size / psize;
            const dirty_addrs = try allocator.alloc(?*anyopaque, max_pages);

            return .{
                .live_ptr = @ptrCast(live_raw),
                .clean_ptr = @ptrCast(clean_raw),
                .size = aligned_size,
                .page_size = psize,
                .dirty_addrs = dirty_addrs,
                .allocator = allocator,
            };
        } else {
            const live_slice = std.posix.mmap(
                null,
                aligned_size,
                .{ .READ = true, .WRITE = true },
                .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
                -1,
                0,
            ) catch return error.MmapFailed;
            errdefer std.posix.munmap(live_slice);

            const clean_slice = std.posix.mmap(
                null,
                aligned_size,
                .{ .READ = true, .WRITE = true },
                .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
                -1,
                0,
            ) catch return error.MmapFailed;

            const max_pages = aligned_size / psize;
            const dirty_addrs = try allocator.alloc(?*anyopaque, max_pages);

            return .{
                .live_ptr = live_slice.ptr,
                .clean_ptr = clean_slice.ptr,
                .size = aligned_size,
                .page_size = psize,
                .dirty_addrs = dirty_addrs,
                .posix_live_len = live_slice.len,
                .posix_clean_len = clean_slice.len,
                .allocator = allocator,
            };
        }
    }

    pub fn deinit(self: *SnapshotArena) void {
        if (builtin.os.tag == .windows) {
            _ = WinExports.VirtualFree(self.live_ptr, 0, MEM_RELEASE);
            _ = WinExports.VirtualFree(self.clean_ptr, 0, MEM_RELEASE);
        } else {
            const live_aligned: [*]align(std.heap.page_size_min) const u8 = @alignCast(self.live_ptr);
            const clean_aligned: [*]align(std.heap.page_size_min) const u8 = @alignCast(self.clean_ptr);
            std.posix.munmap(live_aligned[0..self.posix_live_len]);
            std.posix.munmap(clean_aligned[0..self.posix_clean_len]);
        }
        self.allocator.free(self.dirty_addrs);
    }

    pub fn maxCapacity(self: *const SnapshotArena) usize {
        return self.size;
    }

    pub fn takeSnapshot(self: *SnapshotArena) void {
        @memcpy(self.clean_ptr[0..self.size], self.live_ptr[0..self.size]);
        if (builtin.os.tag == .windows) {
            _ = WinExports.ResetWriteWatch(self.live_ptr, self.size);
        }
    }

    pub fn restoreDirtyPages(self: *SnapshotArena) error{GetWriteWatchFailed}!usize {
        if (builtin.os.tag == .windows) {
            var count: usize = self.dirty_addrs.len;
            var gran: u32 = @intCast(self.page_size);
            const rc = WinExports.GetWriteWatch(
                WRITE_WATCH_FLAG_RESET,
                self.live_ptr,
                self.size,
                self.dirty_addrs.ptr,
                &count,
                &gran,
            );
            if (rc != 0) return error.GetWriteWatchFailed;

            const base_addr = @intFromPtr(self.live_ptr);
            for (self.dirty_addrs[0..count]) |maybe_addr| {
                const addr = @intFromPtr(maybe_addr orelse continue);
                if (addr < base_addr or addr + self.page_size > base_addr + self.size) continue;
                const off = addr - base_addr;
                arch.fastRestorePage(self.live_ptr + off, self.clean_ptr + off, self.page_size);
            }
            return count;
        } else {
            var count: usize = 0;
            var off: usize = 0;
            while (off + self.page_size <= self.size) : (off += self.page_size) {
                if (!std.mem.eql(u8, self.live_ptr[off .. off + self.page_size], self.clean_ptr[off .. off + self.page_size])) {
                    arch.fastRestorePage(self.live_ptr + off, self.clean_ptr + off, self.page_size);
                    count += 1;
                }
            }
            return count;
        }
    }
};

pub fn flushCodeRange(addr: *const anyopaque, len: usize) void {
    if (builtin.os.tag == .windows) {
        _ = WinExports.FlushInstructionCache(WinExports.GetCurrentProcess(), addr, len);
        arch.flushIcacheAddr(@intFromPtr(addr));
    } else if (builtin.os.tag == .macos) {
        DarwinExports.sys_icache_invalidate(addr, len);
    } else if (builtin.cpu.arch == .aarch64) {
        const start = @intFromPtr(addr);
        const end = start + len;
        var p = start & ~@as(usize, 63);
        while (p < end) : (p += 64) {
            asm volatile ("dc cvau, %[p]"
                :
                : [p] "r" (p),
            );
        }
        asm volatile ("dsb ish");
        p = start & ~@as(usize, 63);
        while (p < end) : (p += 64) {
            asm volatile ("ic ivau, %[p]"
                :
                : [p] "r" (p),
            );
        }
        asm volatile ("dsb ish\nisb");
    }
}
