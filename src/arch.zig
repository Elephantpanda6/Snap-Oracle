const std = @import("std");
const builtin = @import("builtin");

pub const X64_INT3: u8 = 0xCC;
/// Canonical Windows on ARM64 breakpoint (`brk #0xF000` -> `STATUS_BREAKPOINT` 0x80000003).
pub const ARM64_BRK_0: u32 = 0xD43E_0000;
/// POSIX (Linux / macOS / BSD) AArch64 software breakpoint (`brk #0` -> `SIGTRAP`).
pub const ARM64_POSIX_BRK_0: u32 = 0xD420_0000;

/// Windows `_CONTEXT` / `_ARM64_NT_CONTEXT` register offsets from `winnt.h`.
pub const X64_CTX_RIP_OFFSET: usize = 0xF8;
pub const ARM64_CTX_FP_OFFSET: usize = 0xF0;
pub const ARM64_CTX_LR_OFFSET: usize = 0xF8;
pub const ARM64_CTX_SP_OFFSET: usize = 0x100;
pub const ARM64_CTX_PC_OFFSET: usize = 0x108;

/// Returns the canonical AArch64 trap instruction encoding for the active OS.
pub inline fn arm64BreakpointInsn() u32 {
    return if (builtin.os.tag == .windows) ARM64_BRK_0 else ARM64_POSIX_BRK_0;
}

/// Cycle-exact hardware timestamp counter.
pub inline fn readCycleCounter() u64 {
    return switch (builtin.cpu.arch) {
        .aarch64 => asm volatile ("mrs %[ret], cntvct_el0"
            : [ret] "=r" (-> u64),
        ),
        .x86_64 => blk: {
            var lo: u32 = 0;
            var hi: u32 = 0;
            asm volatile ("rdtsc"
                : [lo] "={eax}" (lo),
                  [hi] "={edx}" (hi),
            );
            break :blk (@as(u64, hi) << 32) | @as(u64, lo);
        },
        else => 0,
    };
}

/// Read AArch64 architectural timer frequency (`cntfrq_el0`), or nominal 1 GHz fallback.
pub inline fn readCounterFreq() u64 {
    return switch (builtin.cpu.arch) {
        .aarch64 => asm volatile ("mrs %[ret], cntfrq_el0"
            : [ret] "=r" (-> u64),
        ),
        else => 1_000_000_000,
    };
}

/// Strip Pointer Authentication (PAC) and Top-Byte-Ignore (TBI) metadata bits from an ARM64
/// pointer, preserving canonical user/kernel bit-55 sign extension when needed.
pub inline fn stripPac(addr: u64) u64 {
    return switch (builtin.cpu.arch) {
        .aarch64 => stripPacAlways(addr),
        else => addr,
    };
}

/// Unconditional ARM64 PAC/TBI bit stripping helper (usable during cross-arch analysis on x64).
pub inline fn stripPacAlways(addr: u64) u64 {
    // Bit 55 distinguishes TTBR0 user addresses (0) from TTBR1 kernel addresses (1).
    if ((addr & (@as(u64, 1) << 55)) != 0) {
        return addr | 0xFFFF_0000_0000_0000;
    }
    return addr & 0x0000_FFFF_FFFF_FFFF;
}

/// Normalize an exception address against a loaded module range `[module_base, module_base + module_size)`
/// into an ASLR-invariant RVA. Falls back to truncated address if outside module bounds.
pub fn computeFaultRva(exc_addr: usize, module_base: usize, module_size: usize) u32 {
    if (module_base != 0 and exc_addr >= module_base) {
        const delta = exc_addr - module_base;
        if (delta < module_size and delta <= std.math.maxInt(u32)) {
            return @intCast(delta);
        }
    }
    return @truncate(exc_addr);
}

/// Flush instruction cache after patching/restoring a breakpoint.
/// On Windows, `l1.flushCodeRange` calls `FlushInstructionCache(GetCurrentProcess(), ...)`,
/// which performs safe kernel-coordinated D-cache/I-cache coherency even in VMs where
/// EL0 `dc cvau` / `ic ivau` (`SCTLR_EL1.UCI == 0`) is trapped.
pub inline fn flushIcacheAddr(_: usize) void {}

/// Fast 4KB page restore from clean snapshot to dirty target page.
pub fn fastRestorePage4K(dst: [*]u8, src: [*]const u8) void {
    const d: *[4096]u8 = @ptrCast(dst);
    const s: *const [4096]u8 = @ptrCast(src);
    @memcpy(d, s);
}

/// Fast page restore supporting both 4 KB (Windows/Linux) and 16 KB (Apple Silicon) pages.
pub fn fastRestorePage(dst: [*]u8, src: [*]const u8, page_size: usize) void {
    switch (page_size) {
        4096 => fastRestorePage4K(dst, src),
        16384 => {
            const d: *[16384]u8 = @ptrCast(dst);
            const s: *const [16384]u8 = @ptrCast(src);
            @memcpy(d, s);
        },
        else => @memcpy(dst[0..page_size], src[0..page_size]),
    }
}

test "arch stripPacAlways strips PAC/TBI tags cleanly" {
    const tagged_user: u64 = 0x002B_0000_7FF6_1234;
    try std.testing.expectEqual(@as(u64, 0x0000_7FF6_1234), stripPacAlways(tagged_user));
    const tagged_kern: u64 = 0x809A_FFFF_8000_ABCD;
    try std.testing.expectEqual(@as(u64, 0xFFFF_FFFF_8000_ABCD), stripPacAlways(tagged_kern));
}

test "arch computeFaultRva normalizes ASLR addresses" {
    try std.testing.expectEqual(@as(u32, 0x1234), computeFaultRva(0x7FF8_0000_1234, 0x7FF8_0000_0000, 0x10000));
    try std.testing.expectEqual(@as(u32, 0xDEAD_BEEF), computeFaultRva(0x1_DEAD_BEEF, 0x7FF8_0000_0000, 0x10000));
    try std.testing.expectEqual(@as(u32, 0x5678), computeFaultRva(0x5678, 0, 0));
}

test "arch fastRestorePage restores 4K and 16K pages" {
    var src4: [4096]u8 = @splat(0x5A);
    var dst4: [4096]u8 = @splat(0x00);
    fastRestorePage4K(&dst4, &src4);
    try std.testing.expectEqualSlices(u8, &src4, &dst4);

    var src16: [16384]u8 = @splat(0xA5);
    var dst16: [16384]u8 = @splat(0x11);
    fastRestorePage(&dst16, &src16, 16384);
    try std.testing.expectEqualSlices(u8, &src16, &dst16);
}
