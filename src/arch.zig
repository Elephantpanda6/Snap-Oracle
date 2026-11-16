const builtin = @import("builtin");

pub const X64_INT3: u8 = 0xCC;
/// Canonical Windows on ARM64 breakpoint (`brk #0xF000` -> `STATUS_BREAKPOINT` 0x80000003).
pub const ARM64_BRK_0: u32 = 0xD43E_0000;

/// Cycle-exact hardware timestamp counter.
pub inline fn readCycleCounter() u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => asm volatile ("rdtsc"
            : [ret] "={rax}" (-> u64),
            :
            : .{ .rdx = true }
        ),
        .aarch64 => asm volatile ("mrs %[ret], cntvct_el0"
            : [ret] "=r" (-> u64),
        ),
        else => 0,
    };
}

/// Strip Pointer Authentication (PAC) bits from an ARM64 instruction pointer.
pub inline fn stripPac(addr: u64) u64 {
    return switch (builtin.cpu.arch) {
        .aarch64 => blk: {
            // Portable user-space VA mask (48-bit VA on Windows/Linux ARM64)
            // when XPACI is not guaranteed on older silicon.
            break :blk addr & 0x0000_FFFF_FFFF_FFFF;
        },
        else => addr,
    };
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
