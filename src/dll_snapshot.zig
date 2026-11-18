const std = @import("std");
const builtin = @import("builtin");
const binary = @import("binary.zig");
const pe = @import("pe.zig");

const WinQuery = if (builtin.os.tag == .windows) struct {
    pub const MEM_COMMIT: u32 = 0x1000;
    pub const PAGE_READWRITE: u32 = 0x04;
    pub const PAGE_WRITECOPY: u32 = 0x08;
    pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    pub const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
    pub const PAGE_GUARD: u32 = 0x100;

    pub const MEMORY_BASIC_INFORMATION = extern struct {
        BaseAddress: ?*anyopaque,
        AllocationBase: ?*anyopaque,
        AllocationProtect: u32,
        PartitionId: u16,
        RegionSize: usize,
        State: u32,
        Protect: u32,
        Type: u32,
    };

    extern "kernel32" fn VirtualQuery(
        lpAddress: ?*const anyopaque,
        lpBuffer: *MEMORY_BASIC_INFORMATION,
        dwLength: usize,
    ) callconv(.winapi) usize;

    fn isWritableProtect(prot: u32) bool {
        if ((prot & PAGE_GUARD) != 0) return false;
        const base = prot & 0xFF;
        return base == PAGE_READWRITE or base == PAGE_WRITECOPY or base == PAGE_EXECUTE_READWRITE or base == PAGE_EXECUTE_WRITECOPY;
    }
} else struct {};

pub const SnapshotSpan = struct {
    live_addr: usize,
    clean_offset: usize,
    len: usize,
};

/// Captures and restores modified writable non-shared data sections (`.data`, `.bss`, `__data`)
/// inside a loaded target DLL/SO/Dylib so global state resets deterministically across iterations.
pub const ModuleDataSnapshot = struct {
    spans: []SnapshotSpan,
    clean_buf: []u8,
    chunk_size: usize,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, module_base: usize, bin: *const binary.BinaryImage) !ModuleDataSnapshot {
        const wsecs = try bin.writableDataSections(allocator);
        defer allocator.free(wsecs);

        return initFromSections(allocator, module_base, wsecs);
    }

    pub fn initFromSections(allocator: std.mem.Allocator, module_base: usize, wsecs: []const pe.Section) !ModuleDataSnapshot {
        var spans = std.ArrayList(SnapshotSpan).empty;
        errdefer spans.deinit(allocator);

        var total_bytes: usize = 0;

        for (wsecs) |sec| {
            if (sec.virtual_size == 0) continue;
            const sec_start = module_base + @as(usize, sec.virtual_address);
            const sec_end = sec_start + @as(usize, sec.virtual_size);

            if (builtin.os.tag == .windows) {
                var cur = sec_start;
                while (cur < sec_end) {
                    var mbi: WinQuery.MEMORY_BASIC_INFORMATION = undefined;
                    const q = WinQuery.VirtualQuery(@ptrFromInt(cur), &mbi, @sizeOf(WinQuery.MEMORY_BASIC_INFORMATION));
                    if (q == 0 or mbi.RegionSize == 0) break;
                    const reg_start = @intFromPtr(mbi.BaseAddress orelse break);
                    const reg_end = reg_start +| mbi.RegionSize;
                    const overlap_start = @max(cur, reg_start);
                    const overlap_end = @min(sec_end, reg_end);
                    if (overlap_end > overlap_start and mbi.State == WinQuery.MEM_COMMIT and WinQuery.isWritableProtect(mbi.Protect)) {
                        const span_len = overlap_end - overlap_start;
                        try spans.append(allocator, .{
                            .live_addr = overlap_start,
                            .clean_offset = total_bytes,
                            .len = span_len,
                        });
                        total_bytes += span_len;
                    }
                    if (reg_end <= cur) break;
                    cur = reg_end;
                }
            } else {
                const span_len = @as(usize, sec.virtual_size);
                try spans.append(allocator, .{
                    .live_addr = sec_start,
                    .clean_offset = total_bytes,
                    .len = span_len,
                });
                total_bytes += span_len;
            }
        }

        const clean_buf = try allocator.alloc(u8, total_bytes);
        errdefer allocator.free(clean_buf);

        for (spans.items) |sp| {
            const live: [*]const u8 = @ptrFromInt(sp.live_addr);
            @memcpy(clean_buf[sp.clean_offset .. sp.clean_offset + sp.len], live[0..sp.len]);
        }

        return .{
            .spans = try spans.toOwnedSlice(allocator),
            .clean_buf = clean_buf,
            .chunk_size = std.heap.pageSize(),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ModuleDataSnapshot) void {
        self.allocator.free(self.spans);
        self.allocator.free(self.clean_buf);
    }

    /// Re-captures current clean state as baseline.
    pub fn recapture(self: *ModuleDataSnapshot) void {
        for (self.spans) |sp| {
            const live: [*]const u8 = @ptrFromInt(sp.live_addr);
            @memcpy(self.clean_buf[sp.clean_offset .. sp.clean_offset + sp.len], live[0..sp.len]);
        }
    }

    /// Scans writable module pages and restores only chunks whose bytes differ from the clean baseline.
    /// Returns the number of restored chunks.
    pub fn restore(self: *ModuleDataSnapshot) usize {
        var restored: usize = 0;
        for (self.spans) |sp| {
            const live: [*]u8 = @ptrFromInt(sp.live_addr);
            const clean = self.clean_buf[sp.clean_offset .. sp.clean_offset + sp.len];
            var off: usize = 0;
            while (off < sp.len) {
                const clen = @min(self.chunk_size, sp.len - off);
                const live_slice = live[off .. off + clen];
                const clean_slice = clean[off .. off + clen];
                if (!std.mem.eql(u8, live_slice, clean_slice)) {
                    @memcpy(live_slice, clean_slice);
                    restored += 1;
                }
                off += clen;
            }
        }
        return restored;
    }

    pub fn totalBytes(self: *const ModuleDataSnapshot) usize {
        return self.clean_buf.len;
    }
};

test "dll_snapshot restores only dirty writable pages" {
    var mock_mem: [8192]u8 align(4096) = @splat(0x11);
    const sec = pe.Section{
        .name = .{ '.', 'd', 'a', 't', 'a', 0, 0, 0 },
        .virtual_size = 8192,
        .virtual_address = 0,
        .raw_size = 8192,
        .raw_offset = 0,
        .characteristics = pe.IMAGE_SCN_MEM_READ | pe.IMAGE_SCN_MEM_WRITE,
    };
    const secs = [_]pe.Section{sec};
    var snap = try ModuleDataSnapshot.initFromSections(std.testing.allocator, @intFromPtr(&mock_mem), &secs);
    defer snap.deinit();

    try std.testing.expectEqual(@as(usize, 8192), snap.totalBytes());
    try std.testing.expectEqual(@as(usize, 0), snap.restore());

    mock_mem[12] = 0xFE;
    mock_mem[5000] = 0xCA;
    const restored = snap.restore();
    try std.testing.expect(restored >= 1);
    try std.testing.expectEqual(@as(u8, 0x11), mock_mem[12]);
    try std.testing.expectEqual(@as(u8, 0x11), mock_mem[5000]);
}
