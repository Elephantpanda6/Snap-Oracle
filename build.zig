const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    const exe = b.addExecutable(.{
        .name = "snap-oracle",
        .root_module = exe_mod,
    });
    b.installArtifact(exe);

    const test_target_mod = b.createModule(.{
        .root_source_file = b.path("src/test_target.zig"),
        .target = target,
        .optimize = optimize,
    });
    const test_target_dll = b.addLibrary(.{
        .name = "test_target",
        .linkage = .dynamic,
        .root_module = test_target_mod,
    });
    b.installArtifact(test_target_dll);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    const run_step = b.step("run", "Run snap-oracle");
    run_step.dependOn(&run_cmd.step);

    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/tests.zig"),
        .target = target,
        .optimize = optimize,
    });
    const unit_tests = b.addTest(.{
        .root_module = test_mod,
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);
}
