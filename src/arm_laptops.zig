const std = @import("std");
const builtin = @import("builtin");

pub const LaptopProfile = struct {
    id: []const u8,
    name: []const u8,
    soc_microarch: []const u8,
    representative_laptops: []const u8,
    isa_level: []const u8,
    total_cores: u8,
    p_cores: u8,
    e_cores: u8,
    p_core_affinity_mask: u64,
    native_page_size: u32,
    cache_line_bytes: u16,
    has_lse: bool,
    has_pac: bool,
    has_bti: bool,
    has_mte: bool,
    has_sve2: bool,
    has_sme: bool,
    has_bf16_i8mm: bool,
    npu_tops: u16,
    recommended_arena_kb: u32,
    recommended_workers: u8,
    vm_uci_trap_note: []const u8,
};

pub const ALL_PROFILES = [_]LaptopProfile{
    .{
        .id = "snapdragon-x-elite",
        .name = "Qualcomm Snapdragon X Elite (X1E-78/80/84)",
        .soc_microarch = "12x Qualcomm Oryon Gen 1 (ARMv8.7-A)",
        .representative_laptops = "Surface Laptop 7, Surface Pro 11, Lenovo Yoga Slim 7x, ASUS Vivobook S 15, Dell XPS 13 9345, HP Omnibook X",
        .isa_level = "ARMv8.7-A",
        .total_cores = 12,
        .p_cores = 12,
        .e_cores = 0,
        .p_core_affinity_mask = 0x0FFF,
        .native_page_size = 4096,
        .cache_line_bytes = 64,
        .has_lse = true,
        .has_pac = true,
        .has_bti = false,
        .has_mte = false,
        .has_sve2 = false,
        .has_sme = false,
        .has_bf16_i8mm = true,
        .npu_tops = 45,
        .recommended_arena_kb = 64,
        .recommended_workers = 10,
        .vm_uci_trap_note = "Windows Hyper-V VMs may trap EL0 dc cvau/ic ivau; use FlushInstructionCache.",
    },
    .{
        .id = "snapdragon-x-plus",
        .name = "Qualcomm Snapdragon X Plus / X (X1P-42/64)",
        .soc_microarch = "8x-10x Qualcomm Oryon Gen 1 (ARMv8.7-A)",
        .representative_laptops = "Surface Laptop 13, Lenovo IdeaPad Slim 5x, Acer Swift Go 14 AI, HP OmniBook 5",
        .isa_level = "ARMv8.7-A",
        .total_cores = 8,
        .p_cores = 8,
        .e_cores = 0,
        .p_core_affinity_mask = 0x00FF,
        .native_page_size = 4096,
        .cache_line_bytes = 64,
        .has_lse = true,
        .has_pac = true,
        .has_bti = false,
        .has_mte = false,
        .has_sve2 = false,
        .has_sme = false,
        .has_bf16_i8mm = true,
        .npu_tops = 45,
        .recommended_arena_kb = 64,
        .recommended_workers = 6,
        .vm_uci_trap_note = "Use FlushInstructionCache on Windows; 8-core thermal envelope favors 6 workers.",
    },
    .{
        .id = "snapdragon-x2-elite",
        .name = "Qualcomm Snapdragon X2 Elite / Extreme",
        .soc_microarch = "12x-18x Qualcomm Oryon Gen 2/3 (ARMv9.2-A)",
        .representative_laptops = "2025/2026 Windows Copilot+ ARM64 workstations (ARMv9 + SME/SVE2)",
        .isa_level = "ARMv9.2-A",
        .total_cores = 18,
        .p_cores = 12,
        .e_cores = 6,
        .p_core_affinity_mask = 0x0FFF,
        .native_page_size = 4096,
        .cache_line_bytes = 64,
        .has_lse = true,
        .has_pac = true,
        .has_bti = true,
        .has_mte = true,
        .has_sve2 = true,
        .has_sme = true,
        .has_bf16_i8mm = true,
        .npu_tops = 80,
        .recommended_arena_kb = 128,
        .recommended_workers = 12,
        .vm_uci_trap_note = "Pin fuzzers to 12 prime/performance Oryon cores (0x0FFF) and enable --bti-safe.",
    },
    .{
        .id = "nvidia-n1x-spark",
        .name = "NVIDIA N1X / Grace-Blackwell ARM64 Laptop (RTX Spark)",
        .soc_microarch = "10x Cortex-X925 + 10x Cortex-A725 (ARMv9.2-A) + Blackwell UMA",
        .representative_laptops = "NVIDIA N1X / RTX Spark 128GB LPDDR5X Unified-Memory AI Laptops",
        .isa_level = "ARMv9.2-A",
        .total_cores = 20,
        .p_cores = 10,
        .e_cores = 10,
        .p_core_affinity_mask = 0x03FF,
        .native_page_size = 4096,
        .cache_line_bytes = 64,
        .has_lse = true,
        .has_pac = true,
        .has_bti = true,
        .has_mte = true,
        .has_sve2 = true,
        .has_sme = false,
        .has_bf16_i8mm = true,
        .npu_tops = 100,
        .recommended_arena_kb = 256,
        .recommended_workers = 10,
        .vm_uci_trap_note = "128GB UMA ideal for fuzzing full GGUF/ONNX parsers + CUDA/Vulkan drivers on Cortex-X925 P-cores.",
    },
    .{
        .id = "apple-m1-m2",
        .name = "Apple Silicon M1 / M2 (macOS / Asahi Linux / Parallels WoA)",
        .soc_microarch = "Apple Firestorm/Avalanche + Icestorm/Blizzard (ARMv8.5-A)",
        .representative_laptops = "MacBook Air/Pro M1, M2, M1 Pro/Max, M2 Pro/Max",
        .isa_level = "ARMv8.5-A",
        .total_cores = 8,
        .p_cores = 4,
        .e_cores = 4,
        .p_core_affinity_mask = 0x00F0,
        .native_page_size = 16384,
        .cache_line_bytes = 128,
        .has_lse = true,
        .has_pac = true,
        .has_bti = false,
        .has_mte = false,
        .has_sve2 = false,
        .has_sme = false,
        .has_bf16_i8mm = true,
        .npu_tops = 15,
        .recommended_arena_kb = 128,
        .recommended_workers = 4,
        .vm_uci_trap_note = "macOS & Asahi Linux use 16KB OS pages (128B cache lines); Parallels Windows VM runs 4KB pages.",
    },
    .{
        .id = "apple-m3-m4",
        .name = "Apple Silicon M3 / M4 (macOS / Asahi / Virtualization)",
        .soc_microarch = "Apple M3/M4 P+E Cores (ARMv8.6-A + SME on M4)",
        .representative_laptops = "MacBook Air/Pro M3, M4, M4 Pro, M4 Max",
        .isa_level = "ARMv9.2-A / SME (M4)",
        .total_cores = 14,
        .p_cores = 10,
        .e_cores = 4,
        .p_core_affinity_mask = 0x3FF0,
        .native_page_size = 16384,
        .cache_line_bytes = 128,
        .has_lse = true,
        .has_pac = true,
        .has_bti = true,
        .has_mte = false,
        .has_sve2 = false,
        .has_sme = true,
        .has_bf16_i8mm = true,
        .npu_tops = 38,
        .recommended_arena_kb = 128,
        .recommended_workers = 8,
        .vm_uci_trap_note = "16KB pages natively on macOS; M4 supports SME streaming matrix instructions.",
    },
    .{
        .id = "mediatek-kompanio-ultra",
        .name = "MediaTek Kompanio / Dimensity Chromebook & Linux ARM64 Laptop",
        .soc_microarch = "ARM Cortex-X925/X4 + A720/A520 (ARMv9.2-A)",
        .representative_laptops = "Lenovo Chromebook Plus ARM64, Linux ARM64 ultrabooks",
        .isa_level = "ARMv9.2-A",
        .total_cores = 8,
        .p_cores = 4,
        .e_cores = 4,
        .p_core_affinity_mask = 0x00F0,
        .native_page_size = 4096,
        .cache_line_bytes = 64,
        .has_lse = true,
        .has_pac = true,
        .has_bti = true,
        .has_mte = true,
        .has_sve2 = true,
        .has_sme = false,
        .has_bf16_i8mm = true,
        .npu_tops = 50,
        .recommended_arena_kb = 64,
        .recommended_workers = 4,
        .vm_uci_trap_note = "Enable --bti-safe for Linux distros built with -mbranch-protection=standard.",
    },
    .{
        .id = "ampere-neoverse-cloud",
        .name = "Ampere Altra / AWS Graviton / Windows-11-ARM Cloud Runner",
        .soc_microarch = "Arm Neoverse N1 / N2 / V2",
        .representative_laptops = "GitHub Actions windows-11-arm, AWS Graviton3/4, Azure Cobalt 100",
        .isa_level = "ARMv8.2-A / ARMv9.0-A",
        .total_cores = 16,
        .p_cores = 16,
        .e_cores = 0,
        .p_core_affinity_mask = 0xFFFF,
        .native_page_size = 4096,
        .cache_line_bytes = 64,
        .has_lse = true,
        .has_pac = true,
        .has_bti = true,
        .has_mte = false,
        .has_sve2 = true,
        .has_sme = false,
        .has_bf16_i8mm = true,
        .npu_tops = 0,
        .recommended_arena_kb = 64,
        .recommended_workers = 8,
        .vm_uci_trap_note = "Virtualization traps EL0 icache ops when UCI=0; FlushInstructionCache / Linux kernel path safe.",
    },
};

fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0 or needle.len > haystack.len) return false;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[i .. i + needle.len], needle)) return true;
    }
    return false;
}

pub fn findProfile(query: []const u8) ?LaptopProfile {
    if (query.len == 0) return null;
    for (ALL_PROFILES) |p| {
        if (std.ascii.eqlIgnoreCase(p.id, query)) return p;
    }
    for (ALL_PROFILES) |p| {
        if (containsIgnoreCase(p.id, query) or containsIgnoreCase(p.name, query)) return p;
    }
    return null;
}

const WinProbe = if (builtin.os.tag == .windows) struct {
    const SYSTEM_INFO = extern struct {
        wProcessorArchitecture: u16,
        wReserved: u16,
        dwPageSize: u32,
        lpMinimumApplicationAddress: ?*anyopaque,
        lpMaximumApplicationAddress: ?*anyopaque,
        dwActiveProcessorMask: usize,
        dwNumberOfProcessors: u32,
        dwProcessorType: u32,
        dwAllocationGranularity: u32,
        wProcessorLevel: u16,
        wProcessorRevision: u16,
    };

    extern "kernel32" fn IsProcessorFeaturePresent(ProcessorFeature: u32) callconv(.winapi) i32;
    extern "kernel32" fn GetSystemInfo(lpSystemInfo: *SYSTEM_INFO) callconv(.winapi) void;
    extern "kernel32" fn SetProcessAffinityMask(hProcess: std.os.windows.HANDLE, dwProcessAffinityMask: usize) callconv(.winapi) i32;
    extern "kernel32" fn GetCurrentProcess() callconv(.winapi) std.os.windows.HANDLE;

    const PF_ARM_V8_INSTRUCTIONS_AVAILABLE: u32 = 29;
    const PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE: u32 = 30;
    const PF_ARM_V8_CRC32_INSTRUCTIONS_AVAILABLE: u32 = 31;
    const PF_ARM_V81_ATOMIC_INSTRUCTIONS_AVAILABLE: u32 = 34;
    const PF_ARM_V82_DP_INSTRUCTIONS_AVAILABLE: u32 = 43;
    const PF_ARM_V83_JSCVT_INSTRUCTIONS_AVAILABLE: u32 = 44;
    const PF_ARM_V83_LRCPC_INSTRUCTIONS_AVAILABLE: u32 = 45;
    const PF_ARM_SVE_INSTRUCTIONS_AVAILABLE: u32 = 46;
} else struct {};

pub const HostArm64Capabilities = struct {
    arch_name: []const u8,
    os_name: []const u8,
    is_native_arm64: bool,
    page_size: u32,
    logical_cpus: u32,
    feat_neon: bool,
    feat_crc32: bool,
    feat_crypto: bool,
    feat_lse: bool,
    feat_dotprod: bool,
    feat_jscvt: bool,
    feat_lrcpc: bool,
    feat_pac: bool,
    feat_bti: bool,
    feat_sve: bool,
    matched_profile_id: []const u8,
};

pub fn probeHostCapabilities() HostArm64Capabilities {
    const is_arm = builtin.cpu.arch == .aarch64;
    const psize: u32 = @intCast(std.heap.pageSize());
    var cpus: u32 = @intCast(std.Thread.getCpuCount() catch 4);

    if (builtin.os.tag == .windows) {
        var si: WinProbe.SYSTEM_INFO = undefined;
        WinProbe.GetSystemInfo(&si);
        if (si.dwNumberOfProcessors > 0) cpus = si.dwNumberOfProcessors;

        const neon = is_arm and WinProbe.IsProcessorFeaturePresent(WinProbe.PF_ARM_V8_INSTRUCTIONS_AVAILABLE) != 0;
        const crypto = is_arm and WinProbe.IsProcessorFeaturePresent(WinProbe.PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE) != 0;
        const crc = is_arm and WinProbe.IsProcessorFeaturePresent(WinProbe.PF_ARM_V8_CRC32_INSTRUCTIONS_AVAILABLE) != 0;
        const lse = is_arm and WinProbe.IsProcessorFeaturePresent(WinProbe.PF_ARM_V81_ATOMIC_INSTRUCTIONS_AVAILABLE) != 0;
        const dp = is_arm and WinProbe.IsProcessorFeaturePresent(WinProbe.PF_ARM_V82_DP_INSTRUCTIONS_AVAILABLE) != 0;
        const jscvt = is_arm and WinProbe.IsProcessorFeaturePresent(WinProbe.PF_ARM_V83_JSCVT_INSTRUCTIONS_AVAILABLE) != 0;
        const lrcpc = is_arm and WinProbe.IsProcessorFeaturePresent(WinProbe.PF_ARM_V83_LRCPC_INSTRUCTIONS_AVAILABLE) != 0;
        const sve = is_arm and WinProbe.IsProcessorFeaturePresent(WinProbe.PF_ARM_SVE_INSTRUCTIONS_AVAILABLE) != 0;

        const profile_id: []const u8 = if (!is_arm)
            "x64-cross-host"
        else if (sve and cpus >= 18)
            "nvidia-n1x-spark"
        else if (sve)
            "snapdragon-x2-elite"
        else if (cpus >= 12 and lrcpc)
            "snapdragon-x-elite"
        else if (cpus >= 8 and lrcpc)
            "snapdragon-x-plus"
        else
            "ampere-neoverse-cloud";

        return .{
            .arch_name = @tagName(builtin.cpu.arch),
            .os_name = @tagName(builtin.os.tag),
            .is_native_arm64 = is_arm,
            .page_size = if (si.dwPageSize > 0) si.dwPageSize else psize,
            .logical_cpus = cpus,
            .feat_neon = neon,
            .feat_crc32 = crc,
            .feat_crypto = crypto,
            .feat_lse = lse,
            .feat_dotprod = dp,
            .feat_jscvt = jscvt,
            .feat_lrcpc = lrcpc,
            .feat_pac = is_arm and lrcpc,
            .feat_bti = is_arm and sve,
            .feat_sve = sve,
            .matched_profile_id = profile_id,
        };
    } else {
        const has_lse = is_arm and builtin.cpu.has(.aarch64, .lse);
        const has_pac = is_arm and builtin.cpu.has(.aarch64, .pauth);
        const has_bti = is_arm and builtin.cpu.has(.aarch64, .bti);
        const has_sve = is_arm and builtin.cpu.has(.aarch64, .sve);

        const profile_id: []const u8 = if (!is_arm)
            "x64-cross-host"
        else if (builtin.os.tag == .macos or psize == 16384)
            "apple-m3-m4"
        else if (cpus >= 18)
            "nvidia-n1x-spark"
        else
            "ampere-neoverse-cloud";

        return .{
            .arch_name = @tagName(builtin.cpu.arch),
            .os_name = @tagName(builtin.os.tag),
            .is_native_arm64 = is_arm,
            .page_size = psize,
            .logical_cpus = cpus,
            .feat_neon = is_arm,
            .feat_crc32 = is_arm and builtin.cpu.has(.aarch64, .crc),
            .feat_crypto = is_arm and builtin.cpu.has(.aarch64, .aes),
            .feat_lse = has_lse,
            .feat_dotprod = is_arm and builtin.cpu.has(.aarch64, .dotprod),
            .feat_jscvt = is_arm,
            .feat_lrcpc = is_arm and builtin.cpu.has(.aarch64, .rcpc),
            .feat_pac = has_pac,
            .feat_bti = has_bti,
            .feat_sve = has_sve,
            .matched_profile_id = profile_id,
        };
    }
}

/// Optionally pin the current worker process to the P-core affinity mask of a named ARM64 laptop profile.
pub fn applyProfileAffinity(profile: LaptopProfile) bool {
    if (builtin.os.tag == .windows) {
        const mask: usize = @truncate(profile.p_core_affinity_mask);
        if (mask == 0) return false;
        return WinProbe.SetProcessAffinityMask(WinProbe.GetCurrentProcess(), mask) != 0;
    }
    return false;
}

pub fn printHostInfo() void {
    const caps = probeHostCapabilities();
    std.debug.print(
        \\Snap-Oracle Host ARM64 Capability Probe
        \\  Arch / OS:       {s} / {s} (native_arm64={any})
        \\  Page Size:       {d} bytes
        \\  Logical CPUs:    {d}
        \\  Matched Profile: {s}
        \\  ISA Features:    NEON={any} CRC32={any} CRYPTO={any} LSE={any} DotProd={any} LRCPC={any} PAC={any} BTI={any} SVE={any}
        \\
    , .{
        caps.arch_name,
        caps.os_name,
        caps.is_native_arm64,
        caps.page_size,
        caps.logical_cpus,
        caps.matched_profile_id,
        caps.feat_neon,
        caps.feat_crc32,
        caps.feat_crypto,
        caps.feat_lse,
        caps.feat_dotprod,
        caps.feat_lrcpc,
        caps.feat_pac,
        caps.feat_bti,
        caps.feat_sve,
    });
}

pub fn printAllProfiles() void {
    std.debug.print("Supported ARM64 Laptop & Workstation Profiles ({d}):\n", .{ALL_PROFILES.len});
    for (ALL_PROFILES) |p| {
        std.debug.print(
            \\  - {s}
            \\      SoC:        {s} ({s})
            \\      Cores:      {d} total ({d}P + {d}E, P-mask=0x{x}) | Page={d}B | CacheLine={d}B | NPU={d} TOPS
            \\      Extensions: LSE={any} PAC={any} BTI={any} MTE={any} SVE2={any} SME={any} BF16/I8MM={any}
            \\      Tuning:     arena={d} KiB | workers={d}
            \\      Note:       {s}
            \\
        , .{
            p.id,
            p.name,
            p.soc_microarch,
            p.total_cores,
            p.p_cores,
            p.e_cores,
            p.p_core_affinity_mask,
            p.native_page_size,
            p.cache_line_bytes,
            p.npu_tops,
            p.has_lse,
            p.has_pac,
            p.has_bti,
            p.has_mte,
            p.has_sve2,
            p.has_sme,
            p.has_bf16_i8mm,
            p.recommended_arena_kb,
            p.recommended_workers,
            p.vm_uci_trap_note,
        });
    }
}

test "arm_laptops profiles lookup and host probe" {
    const snap = findProfile("snapdragon-x-elite").?;
    try std.testing.expectEqual(@as(u8, 12), snap.total_cores);
    try std.testing.expectEqual(@as(u32, 4096), snap.native_page_size);

    const n1x = findProfile("nvidia-n1x-spark").?;
    try std.testing.expectEqual(@as(u8, 20), n1x.total_cores);
    try std.testing.expect(n1x.has_bti and n1x.has_sve2);

    const apple = findProfile("apple-m3-m4").?;
    try std.testing.expectEqual(@as(u32, 16384), apple.native_page_size);
    try std.testing.expect(apple.has_sme);

    const host = probeHostCapabilities();
    try std.testing.expect(host.page_size >= 4096);
    try std.testing.expect(host.logical_cpus >= 1);
}
