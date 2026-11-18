const std = @import("std");
const builtin = @import("builtin");
const arch = @import("arch.zig");
const coverage = @import("coverage.zig");

const EXCEPTION_CONTINUE_SEARCH: c_long = 0;
const EXCEPTION_CONTINUE_EXECUTION: c_long = -1;

pub const EXCEPTION_RECORD = extern struct {
    ExceptionCode: u32,
    ExceptionFlags: u32,
    ExceptionRecord: ?*EXCEPTION_RECORD,
    ExceptionAddress: ?*anyopaque,
    NumberParameters: u32,
    ExceptionInformation: [15]usize,
};

pub const EXCEPTION_POINTERS = extern struct {
    ExceptionRecord: *EXCEPTION_RECORD,
    ContextRecord: *anyopaque,
};

const PVECTORED_EXCEPTION_HANDLER = *const fn (*EXCEPTION_POINTERS) callconv(.winapi) c_long;

const WinApi = if (builtin.os.tag == .windows) struct {
    extern "kernel32" fn AddVectoredExceptionHandler(first: u32, handler: PVECTORED_EXCEPTION_HANDLER) callconv(.winapi) ?*anyopaque;
    extern "kernel32" fn RemoveVectoredExceptionHandler(handle: *anyopaque) callconv(.winapi) u32;
    extern "kernel32" fn RtlCaptureContext(context_record: *align(16) [2048]u8) callconv(.winapi) void;
    extern "kernel32" fn RtlRestoreContext(context_record: *align(16) [2048]u8, exception_record: ?*EXCEPTION_RECORD) callconv(.winapi) noreturn;
} else struct {};

threadlocal var g_active: bool = false;
threadlocal var g_caught: bool = false;
threadlocal var g_exc_code: u32 = 0;
threadlocal var g_exc_addr: usize = 0;
threadlocal var g_bp_table: ?*coverage.BreakpointTable = null;
threadlocal var g_mod_base: usize = 0;
threadlocal var g_mod_size: usize = 0;
threadlocal var g_return_ctx: [2048]u8 align(16) = undefined;

const PosixCtx = extern struct {
    sp: u64 = 0,
    fp: u64 = 0,
    pc: u64 = 0,
};
threadlocal var g_posix_ctx: PosixCtx = .{};

pub const RunResult = struct {
    crashed: bool,
    exception_code: u32,
    exception_addr: usize,
    fault_rva: u32 = 0,
    ret_val: u64,
};

/// Install (or clear with null) the one-shot breakpoint table consulted for breakpoint hits
/// on the current thread.
pub fn setBreakpointTable(bp: ?*coverage.BreakpointTable) void {
    g_bp_table = bp;
}

/// Detach `g_bp_table` only if it matches `bp` (prevents dangling VEH/signal pointers on teardown).
pub fn clearBreakpointTableIf(bp: *const coverage.BreakpointTable) void {
    if (g_bp_table) |cur| {
        if (cur == bp) g_bp_table = null;
    }
}

/// Set loaded target module `[base, base + size)` so caught exceptions report ASLR-invariant `fault_rva`.
pub fn setTargetModuleBounds(base: usize, size: usize) void {
    g_mod_base = base;
    g_mod_size = size;
}

/// x64 `int3` traps report RIP = address+1, and Windows ARM64 `brk #0xF000` may report
/// PC = address or address+4; explicitly restore IP/PC to `ExceptionAddress` so the
/// restored original instruction executes cleanly on both architectures.
fn rewindToException(ep: *EXCEPTION_POINTERS) void {
    if (builtin.cpu.arch == .x86_64) {
        const rip: *align(1) u64 = @ptrFromInt(@intFromPtr(ep.ContextRecord) + arch.X64_CTX_RIP_OFFSET);
        rip.* = @intFromPtr(ep.ExceptionRecord.ExceptionAddress);
    } else if (builtin.cpu.arch == .aarch64) {
        const pc: *align(1) u64 = @ptrFromInt(@intFromPtr(ep.ContextRecord) + arch.ARM64_CTX_PC_OFFSET);
        pc.* = @intFromPtr(ep.ExceptionRecord.ExceptionAddress);
    }
}

fn vehHandler(ep: *EXCEPTION_POINTERS) callconv(.winapi) c_long {
    if (ep.ExceptionRecord.ExceptionCode == 0x80000003) {
        if (g_bp_table) |bp| {
            if (bp.handleBreakpoint(@intFromPtr(ep.ExceptionRecord.ExceptionAddress))) {
                rewindToException(ep);
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
    }
    if (!g_active) return EXCEPTION_CONTINUE_SEARCH;

    const code = ep.ExceptionRecord.ExceptionCode;
    switch (code) {
        0xC0000005, // ACCESS_VIOLATION
        0xC000001D, // ILLEGAL_INSTRUCTION
        0xC0000094, // INTEGER_DIVIDE_BY_ZERO
        0xC0000095, // INTEGER_OVERFLOW
        0xC00000FD, // STACK_OVERFLOW
        0x80000003, // BREAKPOINT
        => {
            g_caught = true;
            g_exc_code = code;
            g_exc_addr = @intFromPtr(ep.ExceptionRecord.ExceptionAddress);
            g_active = false;
            WinApi.RtlRestoreContext(&g_return_ctx, null);
        },
        else => return EXCEPTION_CONTINUE_SEARCH,
    }
}

// POSIX Signal Context layouts matching `std/debug/cpu_context.zig`
const PosixUcontext = if (builtin.os.tag == .linux) switch (builtin.cpu.arch) {
    .aarch64 => extern struct {
        _flags: usize,
        _link: ?*anyopaque,
        _stack: std.os.linux.stack_t,
        _sigmask: std.os.linux.sigset_t,
        _unused: [120]u8,
        mcontext: extern struct {
            _fault_address: u64 align(16),
            x: [30]u64,
            lr: u64,
            sp: u64,
            pc: u64,
        },
    },
    .x86_64 => extern struct {
        _flags: usize,
        _link: ?*anyopaque,
        _stack: std.os.linux.stack_t,
        mcontext: extern struct {
            r8: u64,
            r9: u64,
            r10: u64,
            r11: u64,
            r12: u64,
            r13: u64,
            r14: u64,
            r15: u64,
            rdi: u64,
            rsi: u64,
            rbp: u64,
            rbx: u64,
            rdx: u64,
            rax: u64,
            rcx: u64,
            rsp: u64,
            rip: u64,
        },
    },
    else => void,
} else if (builtin.os.tag.isDarwin()) switch (builtin.cpu.arch) {
    .aarch64 => extern struct {
        _onstack: i32,
        _sigmask: std.c.sigset_t,
        _stack: std.c.stack_t,
        _link: ?*anyopaque,
        _mcsize: u64,
        mcontext: *extern struct {
            _far: u64 align(16),
            _esr: u64,
            x: [30]u64,
            lr: u64,
            sp: u64,
            pc: u64,
        },
    },
    .x86_64 => extern struct {
        _onstack: i32,
        _sigmask: std.c.sigset_t,
        _stack: std.c.stack_t,
        _link: ?*anyopaque,
        _mcsize: u64,
        mcontext: *extern struct {
            _trapno: u16,
            _cpu: u16,
            _err: u32,
            _faultvaddr: u64,
            rax: u64,
            rbx: u64,
            rcx: u64,
            rdx: u64,
            rdi: u64,
            rsi: u64,
            rbp: u64,
            rsp: u64,
            r8: u64,
            r9: u64,
            r10: u64,
            r11: u64,
            r12: u64,
            r13: u64,
            r14: u64,
            r15: u64,
            rip: u64,
        },
    },
    else => void,
} else void;

fn mapPosixSignalToWinCode(sig: std.posix.SIG) u32 {
    return switch (sig) {
        .TRAP => 0x80000003,
        .ILL => 0xC000001D,
        .FPE => 0xC0000094,
        else => 0xC0000005, // SEGV / BUS -> ACCESS_VIOLATION
    };
}

fn posixSignalHandler(sig: std.posix.SIG, _: *const std.posix.siginfo_t, ctx_ptr: ?*anyopaque) callconv(.c) void {
    if (PosixUcontext == void or ctx_ptr == null) {
        std.process.abort();
    }
    const uc: *PosixUcontext = @ptrCast(@alignCast(ctx_ptr.?));

    const pc_val: u64 = if (builtin.cpu.arch == .aarch64) uc.mcontext.pc else uc.mcontext.rip;
    if (sig == .TRAP) {
        if (g_bp_table) |bp| {
            const site_addr: usize = if (builtin.cpu.arch == .x86_64) @intCast(pc_val - 1) else @intCast(pc_val);
            if (bp.handleBreakpoint(site_addr)) {
                if (builtin.cpu.arch == .x86_64) {
                    uc.mcontext.rip = @intCast(site_addr);
                } else if (builtin.cpu.arch == .aarch64) {
                    uc.mcontext.pc = @intCast(site_addr);
                }
                return;
            }
        }
    }

    if (!g_active) {
        std.process.abort();
    }

    g_caught = true;
    g_exc_code = mapPosixSignalToWinCode(sig);
    g_exc_addr = @intCast(pc_val);
    g_active = false;

    if (builtin.cpu.arch == .aarch64) {
        uc.mcontext.sp = g_posix_ctx.sp;
        uc.mcontext.x[29] = g_posix_ctx.fp;
        uc.mcontext.pc = g_posix_ctx.pc;
    } else if (builtin.cpu.arch == .x86_64) {
        uc.mcontext.rsp = g_posix_ctx.sp;
        uc.mcontext.rbp = g_posix_ctx.fp;
        uc.mcontext.rip = g_posix_ctx.pc;
    }
}

pub const Guard = struct {
    handle: ?*anyopaque = null,
    prev_trap: if (builtin.os.tag != .windows) std.posix.Sigaction else void = undefined,
    prev_segv: if (builtin.os.tag != .windows) std.posix.Sigaction else void = undefined,
    prev_bus: if (builtin.os.tag != .windows) std.posix.Sigaction else void = undefined,
    prev_ill: if (builtin.os.tag != .windows) std.posix.Sigaction else void = undefined,
    prev_fpe: if (builtin.os.tag != .windows) std.posix.Sigaction else void = undefined,
    installed: bool = false,

    pub fn init() Guard {
        if (builtin.os.tag == .windows) {
            return .{ .handle = WinApi.AddVectoredExceptionHandler(1, vehHandler), .installed = true };
        } else {
            var g = Guard{};
            const act = std.posix.Sigaction{
                .handler = .{ .sigaction = posixSignalHandler },
                .mask = std.posix.sigemptyset(),
                .flags = std.posix.SA.SIGINFO | std.posix.SA.NODEFER,
            };
            std.posix.sigaction(.TRAP, &act, &g.prev_trap);
            std.posix.sigaction(.SEGV, &act, &g.prev_segv);
            std.posix.sigaction(.BUS, &act, &g.prev_bus);
            std.posix.sigaction(.ILL, &act, &g.prev_ill);
            std.posix.sigaction(.FPE, &act, &g.prev_fpe);
            g.installed = true;
            return g;
        }
    }

    pub fn deinit(self: *Guard) void {
        if (builtin.os.tag == .windows) {
            if (self.handle) |h| {
                _ = WinApi.RemoveVectoredExceptionHandler(h);
                self.handle = null;
            }
        } else if (self.installed) {
            std.posix.sigaction(.TRAP, &self.prev_trap, null);
            std.posix.sigaction(.SEGV, &self.prev_segv, null);
            std.posix.sigaction(.BUS, &self.prev_bus, null);
            std.posix.sigaction(.ILL, &self.prev_ill, null);
            std.posix.sigaction(.FPE, &self.prev_fpe, null);
            self.installed = false;
        }
    }
};

pub const TargetFn = *const fn ([*]const u8, usize) callconv(.c) u64;

/// Execute `func(data, len)` under hardware exception/signal isolation.
/// Marked `noinline` so LLVM preserves a dedicated stack frame across non-local `RtlRestoreContext`/signal unwind.
pub noinline fn runProtected(func: TargetFn, data: [*]const u8, len: usize) RunResult {
    g_caught = false;
    g_exc_code = 0;
    g_exc_addr = 0;

    if (builtin.os.tag == .windows) {
        WinApi.RtlCaptureContext(&g_return_ctx);
        if (@as(*const volatile bool, &g_caught).*) {
            g_active = false;
            const clean_addr: usize = if (builtin.cpu.arch == .aarch64)
                @intCast(arch.stripPac(g_exc_addr))
            else
                g_exc_addr;
            return .{
                .crashed = true,
                .exception_code = g_exc_code,
                .exception_addr = clean_addr,
                .fault_rva = arch.computeFaultRva(clean_addr, g_mod_base, g_mod_size),
                .ret_val = 0,
            };
        }
    } else {
        switch (builtin.cpu.arch) {
            .aarch64 => asm volatile (
                \\ mov x0, sp
                \\ adr x1, 0f
                \\ stp x0, fp, [x2]
                \\ str x1, [x2, #16]
                \\0:
                :
                : [ctx] "{x2}" (&g_posix_ctx),
                : .{
                  .x0 = true,
                  .x1 = true,
                  .x3 = true,
                  .x4 = true,
                  .x5 = true,
                  .x6 = true,
                  .x7 = true,
                  .x8 = true,
                  .x9 = true,
                  .x10 = true,
                  .x11 = true,
                  .x12 = true,
                  .x13 = true,
                  .x14 = true,
                  .x15 = true,
                  .x16 = true,
                  .x17 = true,
                  .x19 = true,
                  .x20 = true,
                  .x21 = true,
                  .x22 = true,
                  .x23 = true,
                  .x24 = true,
                  .x25 = true,
                  .x26 = true,
                  .x27 = true,
                  .x28 = true,
                  .x30 = true,
                  .memory = true,
                }),
            .x86_64 => asm volatile (
                \\ leaq 0f(%%rip), %%rax
                \\ movq %%rsp, 0(%%rdi)
                \\ movq %%rbp, 8(%%rdi)
                \\ movq %%rax, 16(%%rdi)
                \\0:
                :
                : [ctx] "{rdi}" (&g_posix_ctx),
                : .{
                  .rax = true,
                  .rcx = true,
                  .rdx = true,
                  .rbx = true,
                  .rsi = true,
                  .r8 = true,
                  .r9 = true,
                  .r10 = true,
                  .r11 = true,
                  .r12 = true,
                  .r13 = true,
                  .r14 = true,
                  .r15 = true,
                  .memory = true,
                }),
            else => {},
        }
        if (@as(*const volatile bool, &g_caught).*) {
            g_active = false;
            const clean_addr: usize = if (builtin.cpu.arch == .aarch64)
                @intCast(arch.stripPac(g_exc_addr))
            else
                g_exc_addr;
            return .{
                .crashed = true,
                .exception_code = g_exc_code,
                .exception_addr = clean_addr,
                .fault_rva = arch.computeFaultRva(clean_addr, g_mod_base, g_mod_size),
                .ret_val = 0,
            };
        }
    }

    @as(*volatile bool, &g_active).* = true;
    const ret = func(data, len);
    @as(*volatile bool, &g_active).* = false;
    return .{
        .crashed = false,
        .exception_code = 0,
        .exception_addr = 0,
        .fault_rva = 0,
        .ret_val = ret,
    };
}
