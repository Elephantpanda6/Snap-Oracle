const std = @import("std");
const builtin = @import("builtin");
const windows = std.os.windows;
const coverage = @import("coverage.zig");

const EXCEPTION_CONTINUE_SEARCH: c_long = 0;
const EXCEPTION_EXECUTE_HANDLER: c_long = 1;
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

extern "kernel32" fn AddVectoredExceptionHandler(first: u32, handler: PVECTORED_EXCEPTION_HANDLER) callconv(.winapi) ?*anyopaque;
extern "kernel32" fn RemoveVectoredExceptionHandler(handle: *anyopaque) callconv(.winapi) u32;
extern "kernel32" fn RtlCaptureContext(context_record: *align(16) [2048]u8) callconv(.winapi) void;
extern "kernel32" fn RtlRestoreContext(context_record: *align(16) [2048]u8, exception_record: ?*EXCEPTION_RECORD) callconv(.winapi) noreturn;

threadlocal var g_active: bool = false;
threadlocal var g_caught: bool = false;
threadlocal var g_exc_code: u32 = 0;
threadlocal var g_exc_addr: usize = 0;
threadlocal var g_bp_table: ?*coverage.BreakpointTable = null;
threadlocal var g_return_ctx: [2048]u8 align(16) = undefined;

pub const RunResult = struct {
    crashed: bool,
    exception_code: u32,
    exception_addr: usize,
    ret_val: u64,
};

/// Install (or clear with null) the one-shot breakpoint table consulted for `0x80000003` hits
/// on the current thread.
pub fn setBreakpointTable(bp: ?*coverage.BreakpointTable) void {
    g_bp_table = bp;
}

/// x64 `int3` traps report RIP = address+1, and Windows ARM64 `brk #0xF000` may report
/// PC = address or address+4; explicitly restore IP/PC to `ExceptionAddress` so the
/// restored original instruction executes cleanly on both architectures.
fn rewindToException(ep: *EXCEPTION_POINTERS) void {
    if (builtin.cpu.arch == .x86_64) {
        const rip: *align(1) u64 = @ptrFromInt(@intFromPtr(ep.ContextRecord) + 0xF8);
        rip.* = @intFromPtr(ep.ExceptionRecord.ExceptionAddress);
    } else if (builtin.cpu.arch == .aarch64) {
        // `_ARM64_NT_CONTEXT::Pc` is at offset 0x108 in `winnt.h`.
        const pc: *align(1) u64 = @ptrFromInt(@intFromPtr(ep.ContextRecord) + 0x108);
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
            RtlRestoreContext(&g_return_ctx, null);
        },
        else => return EXCEPTION_CONTINUE_SEARCH,
    }
}

pub const Guard = struct {
    handle: ?*anyopaque,

    pub fn init() Guard {
        return .{ .handle = AddVectoredExceptionHandler(1, vehHandler) };
    }

    pub fn deinit(self: *Guard) void {
        if (self.handle) |h| {
            _ = RemoveVectoredExceptionHandler(h);
            self.handle = null;
        }
    }
};

pub const TargetFn = *const fn ([*]const u8, usize) callconv(.c) u64;

pub inline fn runProtected(func: TargetFn, data: [*]const u8, len: usize) RunResult {
    g_caught = false;
    g_exc_code = 0;
    g_exc_addr = 0;

    RtlCaptureContext(&g_return_ctx);
    if (g_caught) {
        g_active = false;
        return .{
            .crashed = true,
            .exception_code = g_exc_code,
            .exception_addr = g_exc_addr,
            .ret_val = 0,
        };
    }

    g_active = true;
    const ret = func(data, len);
    g_active = false;
    return .{
        .crashed = false,
        .exception_code = 0,
        .exception_addr = 0,
        .ret_val = ret,
    };
}
